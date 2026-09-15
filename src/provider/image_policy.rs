// Image policy: what this provider refuses to run, and the OCI registry
// client that resolves an image reference/digest into the facts the policy
// needs (spec §6.2 step 5, §6.4, §9; ADR — image policy in issue #1).
//
// Two things are deliberately separate:
// - `ImagePolicy` holds the provider's configured rules (a deny list of
//   digests, a cheap deny list of reference prefixes, a size cap) and needs
//   no network access to apply the parts that don't.
// - `OciRegistry` fetches and verifies manifests/indexes by digest from the
//   upstream registry named in the reference, over plain HTTP(S), so it can
//   report an image's size and its per-architecture manifests.
//
// `check` is the one entry point both `availability` and a paid spawn call,
// so a tenant never sees a spawn refused for a reason `availability` would
// not have reported the same way.
//
// Caching: only verified manifest bytes are cached, in memory, keyed by
// digest (`OciRegistry::cache`). Issue #1 asks for "verified blobs cached
// across leases"; a manifest is the only blob this milestone ever fetches
// (layers are the backend's problem once it pulls the image), so a small
// in-memory manifest cache is the whole of that requirement here. It is not
// persisted and does not survive a restart.
//
// Unreachable registry: a registry that cannot be reached, answers with a
// non-success status, or serves bytes that don't hash to the requested
// digest is `refused_image`, not a distinct "registry down" code. The spec
// has no code for a transient registry outage, and treating it as anything
// but a refusal would let a tenant's availability check or spawn silently
// hang or retry against a provider that has already decided not to run the
// image right now.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::header::{HeaderValue, ACCEPT, WWW_AUTHENTICATE};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::config::{ImagePolicyConfig, Listing};
use crate::nostr::wire::{ErrorCode, ErrorResponse, ImageRef};

/// Every OCI/Docker media type this milestone reads: an index (OCI or the
/// older Docker manifest list) or a single-platform manifest.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

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

/// Size of the manifest the provider would run: the config blob plus every
/// layer, in the media type's own `size` fields — the same quantity the
/// backend will pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedManifest {
    /// The digest of the concrete (single-platform) manifest that was sized:
    /// the requested digest itself, or the entry an index resolved to.
    pub digest: String,
    pub size_bytes: u64,
}

/// One provider-wide client for fetching and verifying OCI manifests. Cheap
/// to construct; holds only an HTTP client and a manifest cache, so one
/// instance is shared by `availability` and every spawn (`AppState`).
pub struct OciRegistry {
    client: reqwest::Client,
    /// When set, every registry request goes to this base URL
    /// (`scheme://host[:port]`) instead of the host named in the reference.
    /// Tests point it at a `wiremock` server.
    base_url_override: Option<String>,
    /// Verified manifest bytes, keyed by the digest they were fetched and
    /// checked against. Never evicted in this milestone; a manifest is a few
    /// KB and a provider's whole catalogue of distinct images is small.
    cache: Mutex<HashMap<String, bytes::Bytes>>,
}

impl OciRegistry {
    pub fn new(base_url_override: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client with a timeout builds"),
            base_url_override,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `digest` (an index or a manifest) for `reference`, returning
    /// the manifest that would actually run: itself if it is already a
    /// single-platform manifest, or the entry of an index matching `arch`.
    pub async fn resolve(
        &self,
        reference: &str,
        digest: &str,
        arch: &str,
    ) -> Result<ResolvedManifest, ErrorResponse> {
        let bytes = self.verified_manifest(reference, digest).await?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
            refused(format!(
                "image manifest {} is not valid JSON: {}",
                digest, e
            ))
        })?;

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
            return self.resolve_leaf(reference, child_digest).await;
        }

        manifest_size(digest, &value)
    }

    /// Fetch and verify `digest` assuming it names a single-platform
    /// manifest, refusing a nested index rather than recursing forever.
    async fn resolve_leaf(
        &self,
        reference: &str,
        digest: &str,
    ) -> Result<ResolvedManifest, ErrorResponse> {
        let bytes = self.verified_manifest(reference, digest).await?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
            refused(format!(
                "image manifest {} is not valid JSON: {}",
                digest, e
            ))
        })?;
        if value.get("manifests").is_some() {
            return Err(refused(format!(
                "image index {} resolves to another index; nested indexes are not supported",
                digest
            )));
        }
        manifest_size(digest, &value)
    }

    /// Bytes of `digest`, from the cache or freshly fetched and checked
    /// against it. Only bytes that hash to `digest` are ever cached or
    /// returned.
    async fn verified_manifest(
        &self,
        reference: &str,
        digest: &str,
    ) -> Result<bytes::Bytes, ErrorResponse> {
        if let Some(cached) = self.cache.lock().unwrap().get(digest).cloned() {
            return Ok(cached);
        }
        let bytes = self.fetch_manifest(reference, digest).await?;
        verify_digest(&bytes, digest)?;
        self.cache
            .lock()
            .unwrap()
            .insert(digest.to_string(), bytes.clone());
        Ok(bytes)
    }

    async fn fetch_manifest(
        &self,
        reference: &str,
        digest: &str,
    ) -> Result<bytes::Bytes, ErrorResponse> {
        let (registry_host, repository) = parse_reference(reference);
        let pull_host = if registry_host == "docker.io" {
            "registry-1.docker.io"
        } else {
            &registry_host
        };
        let base = self
            .base_url_override
            .clone()
            .unwrap_or_else(|| format!("https://{}", pull_host));
        let url = format!("{}/v2/{}/manifests/{}", base, repository, digest);

        let send = |bearer: Option<&str>| {
            let mut req = self.client.get(&url).header(ACCEPT, MANIFEST_ACCEPT);
            if let Some(token) = bearer {
                req = req.bearer_auth(token);
            }
            req.send()
        };

        let response = send(None).await.map_err(|e| {
            refused(format!(
                "could not reach registry for {} ({}): {}",
                reference, digest, e
            ))
        })?;

        let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            // The generic bearer challenge flow (docker distribution spec):
            // the 401 names a token endpoint in `Www-Authenticate`, and an
            // anonymous pull token from it is usually enough for a public
            // image. `docker.io` itself always challenges this way; other
            // registries are tried anonymously first and only challenged if
            // they answer 401.
            match response.headers().get(WWW_AUTHENTICATE) {
                Some(challenge) => {
                    let token = self.bearer_token(challenge, &repository).await?;
                    send(Some(&token)).await.map_err(|e| {
                        refused(format!(
                            "could not reach registry for {} ({}) after authenticating: {}",
                            reference, digest, e
                        ))
                    })?
                }
                None => response,
            }
        } else {
            response
        };

        if !response.status().is_success() {
            return Err(refused(format!(
                "registry refused to serve manifest {} for {}: HTTP {}",
                digest,
                reference,
                response.status()
            )));
        }
        response.bytes().await.map_err(|e| {
            refused(format!(
                "could not read manifest body for {} ({}): {}",
                reference, digest, e
            ))
        })
    }

    /// Exchange a `WWW-Authenticate: Bearer ...` challenge for an anonymous
    /// pull token, the way every OCI-distribution registry's public images
    /// are fetched without credentials.
    async fn bearer_token(
        &self,
        challenge: &HeaderValue,
        repository: &str,
    ) -> Result<String, ErrorResponse> {
        let challenge = challenge
            .to_str()
            .map_err(|_| refused("registry sent a non-UTF-8 Www-Authenticate challenge"))?;
        let params = parse_bearer_challenge(challenge).ok_or_else(|| {
            refused(format!(
                "unsupported Www-Authenticate challenge: {}",
                challenge
            ))
        })?;
        let realm = params
            .get("realm")
            .ok_or_else(|| refused("bearer challenge has no realm"))?;

        let mut url = reqwest::Url::parse(realm).map_err(|e| {
            refused(format!(
                "bearer challenge realm {:?} is not a URL: {}",
                realm, e
            ))
        })?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(service) = params.get("service") {
                query.append_pair("service", service);
            }
            let scope = params
                .get("scope")
                .cloned()
                .unwrap_or_else(|| format!("repository:{}:pull", repository));
            query.append_pair("scope", &scope);
        }

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| refused(format!("could not reach token endpoint: {}", e)))?;
        if !response.status().is_success() {
            return Err(refused(format!(
                "token endpoint refused an anonymous pull token: HTTP {}",
                response.status()
            )));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|e| refused(format!("token endpoint response is not JSON: {}", e)))?;
        body.get("token")
            .or_else(|| body.get("access_token"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| refused("token endpoint response has no token"))
    }
}

/// `Bearer realm="...",service="...",scope="..."` into its key/value pairs.
/// `None` if the challenge isn't the `Bearer` scheme this flow handles.
fn parse_bearer_challenge(challenge: &str) -> Option<HashMap<String, String>> {
    let rest = challenge.trim().strip_prefix("Bearer")?.trim_start();
    let mut params = HashMap::new();
    for part in split_challenge_params(rest) {
        let (key, value) = part.split_once('=')?;
        let value = value.trim().trim_matches('"');
        params.insert(key.trim().to_string(), value.to_string());
    }
    Some(params)
}

/// Split on commas that are outside a quoted value, since a scope
/// (`repository:a/b:pull`) never itself contains a comma but the header as a
/// whole is comma-separated `key="value"` pairs.
fn split_challenge_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

/// `registry.docker.io`-style scheme: everything up to the first `/` is a
/// registry host only if it looks like one (has a `.` or `:`, or is
/// `localhost`); otherwise the whole reference is a Docker Hub repository
/// (bare `alpine` means `library/alpine`), matching what
/// `spawn::looks_like_repository` already accepts.
fn parse_reference(reference: &str) -> (String, String) {
    let mut parts = reference.splitn(2, '/');
    let first = parts.next().unwrap_or("");
    let rest = parts.next();
    let looks_like_host = first.contains('.') || first.contains(':') || first == "localhost";
    if looks_like_host {
        (first.to_string(), rest.unwrap_or("").to_string())
    } else {
        match rest {
            Some(_) => ("docker.io".to_string(), reference.to_string()),
            None => ("docker.io".to_string(), format!("library/{}", reference)),
        }
    }
}

fn verify_digest(bytes: &[u8], digest: &str) -> Result<(), ErrorResponse> {
    let want = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| refused(format!("digest {:?} is not sha256:<hex>", digest)))?;
    let got = hex_sha256(bytes);
    if !got.eq_ignore_ascii_case(want) {
        return Err(refused(format!(
            "digest mismatch: requested {} but the fetched bytes hash to sha256:{}",
            digest, got
        )));
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn manifest_size(digest: &str, value: &Value) -> Result<ResolvedManifest, ErrorResponse> {
    let config_size = value
        .get("config")
        .and_then(|c| c.get("size"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let layers_size: u64 = value
        .get("layers")
        .and_then(Value::as_array)
        .map(|layers| {
            layers
                .iter()
                .filter_map(|l| l.get("size").and_then(Value::as_u64))
                .sum()
        })
        .unwrap_or(0);
    Ok(ResolvedManifest {
        digest: digest.to_string(),
        size_bytes: config_size + layers_size,
    })
}

/// Apply the provider's image policy to a spawn's (or availability's) image,
/// resolving it against the upstream registry exactly as a spawn's step 5
/// would. Called by both `availability` and `spawn` so a positive
/// `availability` answer and a spawn's actual behaviour never disagree.
///
/// Order: the cheap, network-free checks (denied digest, denied reference)
/// first, then resolution against the registry (`no_matching_arch`), then
/// the size cap against the resolved manifest — which may itself be a
/// digest this provider denies, if an index was named and its per-arch
/// manifest (rather than the index digest) is on the deny list.
pub async fn check(
    registry: &OciRegistry,
    policy: &ImagePolicy,
    listing: &Listing,
    image: &ImageRef,
) -> Result<(), ErrorResponse> {
    if policy.digest_denied(&image.digest) {
        return Err(refused(format!(
            "image digest {} is denied by this provider's image policy",
            image.digest
        )));
    }
    if policy.reference_denied(&image.reference) {
        return Err(refused(format!(
            "image reference {} is denied by this provider's image policy",
            image.reference
        )));
    }

    let resolved = registry
        .resolve(&image.reference, &image.digest, &listing.arch)
        .await?;

    if policy.digest_denied(&resolved.digest) {
        return Err(refused(format!(
            "image digest {} is denied by this provider's image policy",
            resolved.digest
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_hub_references_normalise_to_docker_io() {
        assert_eq!(
            parse_reference("alpine"),
            ("docker.io".to_string(), "library/alpine".to_string())
        );
        assert_eq!(
            parse_reference("library/alpine"),
            ("docker.io".to_string(), "library/alpine".to_string())
        );
        assert_eq!(
            parse_reference("myuser/myapp"),
            ("docker.io".to_string(), "myuser/myapp".to_string())
        );
    }

    #[test]
    fn hosted_references_keep_their_registry() {
        assert_eq!(
            parse_reference("lscr.io/linuxserver/openssh-server"),
            (
                "lscr.io".to_string(),
                "linuxserver/openssh-server".to_string()
            )
        );
        assert_eq!(
            parse_reference("localhost:5000/team/app"),
            ("localhost:5000".to_string(), "team/app".to_string())
        );
    }

    #[test]
    fn digest_verification_catches_a_mismatch() {
        let bytes = b"not the bytes you expected";
        let real = format!("sha256:{}", hex_sha256(bytes));
        assert!(verify_digest(bytes, &real).is_ok());
        assert!(verify_digest(bytes, "sha256:00").is_err());
    }

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
    fn bearer_challenge_parses_realm_service_and_scope() {
        let params = parse_bearer_challenge(
            "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/alpine:pull\"",
        )
        .unwrap();
        assert_eq!(params["realm"], "https://auth.docker.io/token");
        assert_eq!(params["service"], "registry.docker.io");
        assert_eq!(params["scope"], "repository:library/alpine:pull");
    }

    #[test]
    fn a_non_bearer_challenge_is_not_parsed() {
        assert!(parse_bearer_challenge("Basic realm=\"x\"").is_none());
    }
}
