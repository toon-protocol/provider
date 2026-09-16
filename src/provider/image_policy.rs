// Image policy and resolution: what this provider refuses to run, and how
// an image named by a spawn is resolved to the manifest that would actually
// run (spec §6.2 step 5, §6.4, §8.4, §9).
//
// Two things are deliberately separate:
// - `ImagePolicy` holds the provider's configured rules (a deny list of
//   digests, a cheap deny list of reference prefixes, a size cap) and needs
//   no network access to apply the parts that don't.
// - `check` resolves the image — through the upstream registry for the
//   `reference` form, through its Image Registry entry for the
//   `registry_entry` form — fetching only what resolution needs (an index,
//   the manifest for the listing's arch, its config; never a layer), and
//   applies the policy to what it found.
//
// `check` is the one entry point both `availability` and a paid spawn call,
// so a tenant never sees a spawn refused for a reason `availability` would
// not have reported the same way. Every byte it reads comes through
// `fetcher`, which verifies it against its digest first; a source that
// cannot be reached, answers badly or serves the wrong bytes is
// `refused_image`, never a distinct "registry down" code — the spec has no
// code for a transient outage, and anything but a refusal would let a
// tenant's check hang or retry against a provider that has already decided
// not to run the image right now.

use serde_json::Value;

use super::config::{ImagePolicyConfig, Listing};
use super::fetcher::{BlobFetcher, Candidate};
use super::oci::{parse_reference, OciEndpoint};
use crate::directory::Directory;
use crate::nostr::image_events::{ImageEntry, SpawnImage};
use crate::nostr::wire::{ErrorCode, ErrorResponse, RegistryEntryRef};

/// What a provider says to `{ digest }` alone until it looks Blob Records
/// up on its Relay Set (§8.4 step 3). `refused_image`, not
/// `invalid_request`: the request is well-formed and the spec allows it —
/// this provider simply cannot find those bytes yet, and a tenant must learn
/// that from `availability` before it pays rather than from a lease it
/// cannot use.
pub const IMAGE_DIGEST_ONLY_NOT_RESOLVED: &str =
    "image: this provider does not yet look up Blob Records on its Relay Set, so it cannot \
     fetch an image named by digest alone; name its Image Registry entry (`registry_entry`) \
     or an upstream `reference` as well";

/// What a paid spawn says to `{ digest, registry_entry }` until the provider
/// can run what it resolved: `availability` answers for such an image
/// exactly as a spawn will once it can, but a spawn today would take the
/// tenant's money for a workload it cannot start.
pub const IMAGE_REGISTRY_NOT_RUNNABLE: &str =
    "image: this provider resolves an Image Registry entry on `availability` but cannot yet \
     run an image fetched through one; name the image with an upstream `reference` to spawn it";

fn refused(message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::RefusedImage, message)
}

/// The provider's configured image policy, built once from
/// `ProviderConfig::image_policy`.
#[derive(Debug, Clone, Default)]
pub struct ImagePolicy {
    deny_digests: std::collections::HashSet<String>,
    deny_references: Vec<String>,
    max_image_bytes: Option<u64>,
}

impl ImagePolicy {
    pub fn from_config(config: &ImagePolicyConfig) -> Self {
        Self {
            deny_digests: config.deny_digests.iter().cloned().collect(),
            deny_references: config.deny_references.clone(),
            max_image_bytes: config.max_image_bytes,
        }
    }

    fn digest_denied(&self, digest: &str) -> bool {
        self.deny_digests.contains(digest)
    }

    /// A trailing `*` on a configured entry matches any suffix; otherwise the
    /// whole reference must match. No real glob engine: the ticket calls
    /// this "cheap", and a prefix is enough to block a repository or a whole
    /// registry (`ghcr.io/*`).
    fn reference_denied(&self, reference: &str) -> bool {
        self.deny_references
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => reference.starts_with(prefix),
                None => reference == pattern,
            })
    }
}

/// An image resolved to the manifest that would actually run: enough for
/// the policy to judge it now, and for a spawn to fetch the rest of it.
#[derive(Debug, Clone)]
pub struct ResolvedImage {
    /// The digest of the concrete (single-platform) manifest: the requested
    /// digest itself, or the entry an index resolved to for the listing's
    /// arch.
    pub manifest_digest: String,
    /// The config blob plus every layer, in the manifest's own `size`
    /// fields — the same quantity a backend pulls.
    pub size_bytes: u64,
    /// The manifest itself, already verified against `manifest_digest`.
    pub manifest: Value,
    /// The Image Registry entry the image was resolved through, when it was
    /// named by one: the source of every blob a spawn still has to fetch.
    pub entry: Option<ImageEntry>,
}

/// Which sources may serve a blob of the image being resolved, by digest.
/// `Err` when the image's own description does not account for the blob —
/// an entry that omits a blob its manifest needs is incomplete (§8.1), and
/// a provider with nothing else to consult refuses it.
type Sources<'a> = dyn Fn(&str) -> Result<Vec<Candidate>, ErrorResponse> + Sync + 'a;

/// Apply the provider's image policy to a spawn's (or availability's)
/// image, resolving it exactly as a spawn's step 5 would. Called by both
/// `availability` and `spawn` so a positive `availability` answer and a
/// spawn's actual behaviour never disagree.
///
/// Order: the cheap, network-free checks (denied digest, denied reference)
/// first, then resolution — the entry, the index, the manifest for the
/// listing's `arch` (`no_matching_arch`), its config — then the size cap
/// against the resolved manifest, which may itself be a digest this
/// provider denies, if an index was named and its per-arch manifest (rather
/// than the index digest) is on the deny list.
pub async fn check(
    fetcher: &BlobFetcher,
    directory: &dyn Directory,
    policy: &ImagePolicy,
    listing: &Listing,
    image: &SpawnImage,
) -> Result<ResolvedImage, ErrorResponse> {
    let digest = image.digest();
    if policy.digest_denied(digest) {
        return Err(refused(format!(
            "image digest {} is denied by this provider's image policy",
            digest
        )));
    }

    let resolved = match image {
        SpawnImage::Upstream { reference, .. } => {
            if policy.reference_denied(reference) {
                return Err(refused(format!(
                    "image reference {} is denied by this provider's image policy",
                    reference
                )));
            }
            let (registry, repository) = parse_reference(reference);
            // Milestone 1's form: the registry serves every manifest, and
            // the layers are the backend's to pull once the image passes.
            let sources = move |_: &str| {
                Ok(vec![Candidate::Oci {
                    registry: registry.clone(),
                    repository: repository.clone(),
                    endpoint: OciEndpoint::Manifests,
                }])
            };
            let (manifest_digest, size_bytes, manifest) =
                resolve(fetcher, digest, &listing.arch, &sources).await?;
            ResolvedImage {
                manifest_digest,
                size_bytes,
                manifest,
                entry: None,
            }
        }
        SpawnImage::Registry { entry, .. } => {
            let entry = load_entry(directory, entry).await?;
            if entry.content.digest != digest {
                return Err(refused(format!(
                    "the Image Registry entry {}:{} names image {}, not {}",
                    entry.name, entry.tag, entry.content.digest, digest
                )));
            }
            let sources = |wanted: &str| entry_sources(&entry, wanted);
            let (manifest_digest, size_bytes, manifest) =
                resolve(fetcher, digest, &listing.arch, &sources).await?;
            // The entry MUST list every blob reachable from the image
            // (§8.1); one it omits could never be fetched, so the image is
            // refused now rather than after a tenant has paid.
            for blob in manifest_blob_digests(&manifest) {
                sources(blob)?;
            }
            // The config is the one blob short enough to fetch for free and
            // long enough to prove the entry's sources serve: it goes
            // through the same chain a spawn will send every layer down.
            if let Some(config_digest) = manifest_config_digest(&manifest) {
                fetcher
                    .fetch(config_digest, &sources(config_digest)?)
                    .await?;
            }
            ResolvedImage {
                manifest_digest,
                size_bytes,
                manifest,
                entry: Some(entry),
            }
        }
        SpawnImage::Digest { .. } => return Err(refused(IMAGE_DIGEST_ONLY_NOT_RESOLVED)),
    };

    if policy.digest_denied(&resolved.manifest_digest) {
        return Err(refused(format!(
            "image digest {} is denied by this provider's image policy",
            resolved.manifest_digest
        )));
    }
    if let Some(max) = policy.max_image_bytes {
        if resolved.size_bytes > max {
            return Err(refused(format!(
                "image size {} bytes exceeds this provider's max_image_bytes {}",
                resolved.size_bytes, max
            )));
        }
    }
    Ok(resolved)
}

/// Resolve `digest` (an index or a manifest) to the manifest that would
/// actually run: itself if it is already a single-platform manifest, or the
/// entry of an index matching `arch`. Answers the manifest's digest, its
/// size and its parsed JSON.
async fn resolve(
    fetcher: &BlobFetcher,
    digest: &str,
    arch: &str,
    sources: &Sources<'_>,
) -> Result<(String, u64, Value), ErrorResponse> {
    let value = fetch_json(fetcher, digest, sources).await?;

    if let Some(manifests) = value.get("manifests").and_then(Value::as_array) {
        let chosen = manifests.iter().find(|m| {
            m.get("platform")
                .and_then(|p| p.get("architecture"))
                .and_then(Value::as_str)
                == Some(arch)
        });
        let chosen = chosen.ok_or_else(|| {
            ErrorResponse::new(
                ErrorCode::NoMatchingArch,
                format!("image index {} has no manifest for arch {:?}", digest, arch),
            )
        })?;
        let child_digest = chosen
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                refused(format!(
                    "image index {} entry for arch {:?} has no digest",
                    digest, arch
                ))
            })?;
        // A nested index is refused rather than recursed into forever.
        let leaf = fetch_json(fetcher, child_digest, sources).await?;
        if leaf.get("manifests").is_some() {
            return Err(refused(format!(
                "image index {} resolves to another index; nested indexes are not supported",
                digest
            )));
        }
        return Ok((child_digest.to_string(), manifest_size(&leaf), leaf));
    }

    Ok((digest.to_string(), manifest_size(&value), value))
}

async fn fetch_json(
    fetcher: &BlobFetcher,
    digest: &str,
    sources: &Sources<'_>,
) -> Result<Value, ErrorResponse> {
    let bytes = fetcher.fetch(digest, &sources(digest)?).await?;
    serde_json::from_slice(&bytes).map_err(|e| {
        refused(format!(
            "image manifest {} is not valid JSON: {}",
            digest, e
        ))
    })
}

fn manifest_config_digest(manifest: &Value) -> Option<&str> {
    manifest
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(Value::as_str)
}

/// The digests a manifest's own blobs carry: its config first, then every
/// layer in order.
fn manifest_blob_digests(manifest: &Value) -> Vec<&str> {
    let config = manifest_config_digest(manifest);
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|l| l.get("digest").and_then(Value::as_str));
    config.into_iter().chain(layers).collect()
}

/// Size of the manifest the provider would run: the config blob plus every
/// layer, in the media type's own `size` fields.
fn manifest_size(manifest: &Value) -> u64 {
    let config_size = manifest
        .get("config")
        .and_then(|c| c.get("size"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let layers_size: u64 = manifest
        .get("layers")
        .and_then(Value::as_array)
        .map(|layers| {
            layers
                .iter()
                .filter_map(|l| l.get("size").and_then(Value::as_u64))
                .sum()
        })
        .unwrap_or(0);
    config_size + layers_size
}

/// Where an entry says one of its blobs lives — the one source the entry
/// names for it (§8.4 step 2).
fn entry_sources(entry: &ImageEntry, digest: &str) -> Result<Vec<Candidate>, ErrorResponse> {
    entry
        .content
        .blobs
        .iter()
        .find(|blob| blob.digest == digest)
        .map(|blob| vec![Candidate::from_entry_source(&blob.source, &blob.media_type)])
        .ok_or_else(|| {
            refused(format!(
                "the Image Registry entry {}:{} does not list blob {}, which the image needs",
                entry.name, entry.tag, digest
            ))
        })
}

/// The Image Registry entry a spawn named, read from the relay it hinted
/// at and checked to be the entry that was named: the address is the
/// signer's, so an event from another signer or under another `d` is not
/// it, whatever the relay served.
async fn load_entry(
    directory: &dyn Directory,
    entry: &RegistryEntryRef,
) -> Result<ImageEntry, ErrorResponse> {
    // `SpawnImage::parse` already refused any address that is not
    // `30434:<pubkey>:<d>`.
    let mut parts = entry.address.splitn(3, ':');
    let (_kind, pubkey, d) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let event = directory
        .get_image_entry(&entry.address, &entry.relay)
        .await
        .map_err(|e| {
            refused(format!(
                "could not read the Image Registry entry {} from {}: {:#}",
                entry.address, entry.relay, e
            ))
        })?
        .ok_or_else(|| {
            refused(format!(
                "no Image Registry entry {} on {}",
                entry.address, entry.relay
            ))
        })?;
    if event.pubkey.to_hex() != pubkey {
        return Err(refused(format!(
            "the relay {} served an event signed by {} for the Image Registry entry {}",
            entry.relay,
            event.pubkey.to_hex(),
            entry.address
        )));
    }
    if event.verify().is_err() {
        return Err(refused(format!(
            "the Image Registry entry {} served by {} is not validly signed",
            entry.address, entry.relay
        )));
    }
    let parsed = ImageEntry::from_event(&event).map_err(|e| {
        refused(format!(
            "the Image Registry entry {} is not readable: {:#}",
            entry.address, e
        ))
    })?;
    if format!("{}:{}", parsed.name, parsed.tag) != d {
        return Err(refused(format!(
            "the relay {} served the entry {}:{} for the Image Registry address {}",
            entry.relay, parsed.name, parsed.tag, entry.address
        )));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_star_denies_a_prefix_and_a_bare_entry_denies_exactly() {
        let policy = ImagePolicy {
            deny_digests: Default::default(),
            deny_references: vec![
                "ghcr.io/evil/*".to_string(),
                "docker.io/library/bad".to_string(),
            ],
            max_image_bytes: None,
        };
        assert!(policy.reference_denied("ghcr.io/evil/anything"));
        assert!(!policy.reference_denied("ghcr.io/fine/anything"));
        assert!(policy.reference_denied("docker.io/library/bad"));
        assert!(!policy.reference_denied("docker.io/library/badder"));
    }

    #[test]
    fn a_manifests_blobs_are_its_config_then_its_layers_in_order() {
        let manifest = serde_json::json!({
            "config": { "digest": "sha256:c", "size": 1 },
            "layers": [
                { "digest": "sha256:l1", "size": 2 },
                { "digest": "sha256:l2", "size": 3 }
            ]
        });
        assert_eq!(
            manifest_blob_digests(&manifest),
            vec!["sha256:c", "sha256:l1", "sha256:l2"]
        );
        assert_eq!(manifest_size(&manifest), 6);
        assert!(manifest_blob_digests(&serde_json::json!({})).is_empty());
    }
}
