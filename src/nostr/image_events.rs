// The Image Registry entry, the Blob Record and the Template (spec §8), and
// the three forms a spawn's `image` may take (spec §6.2).
//
// None of these three events is signed by a PROVIDER. A publisher signs an
// Image Registry entry and a Blob Record; a template author signs a
// Template. So this module has no `ProviderConfig` and no provider keys in
// it: it is the wire shape plus a builder and a parser per event, usable by
// whoever holds the key — the publisher tool in the sandbox harness as much
// as the provider that reads what it published.
//
// They are still DIRECTORY events in the sense §4 means: each carries
// `["L", "toon.network"]`, so one relay filter finds every TOON Network
// event whatever its kind. Everything a relay should search on is a tag
// (`d`, `x`, `L`); only the numbers and the lists live in content, the same
// rule `directory_events` follows.
//
// Parsing is deliberately strict:
// - the kind must be the one the shape belongs to;
// - an `x` tag must agree with the digest in content, so a relay's `#x`
//   filter cannot be made to serve a record describing a different blob;
// - unknown fields are refused, never dropped (ADR 0004's rule, applied to
//   published events too: a field this provider does not know is a claim it
//   must not silently ignore).

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use nostr_sdk::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, Timestamp};
use serde::{Deserialize, Serialize};

use super::kinds::{K_BLOB, K_IMAGE, K_TEMPLATE, TOON_LABEL};
use super::wire::{
    is_lower_hex, ErrorCode, ErrorResponse, ImageRef, PortRequest, RegistryEntryRef, Resources,
};

// ── Image Registry entry (spec §8.1) ─────────────────────────────────────────

/// Where one blob's bytes can be fetched from.
///
/// `toon-store` names the Blob Record that lists the blob's parts, by the
/// transaction id of the record's own upload (ADR 0006) — not by the parts
/// themselves, so an entry stays small however large the blob is. `oci`
/// names an upstream repository, for a base layer that already exists there
/// and that a publisher should not pay to store twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BlobSource {
    ToonStore {
        blob_record_txid: String,
    },
    Oci {
        registry: String,
        repository: String,
    },
}

/// One blob an Image Registry entry lists: enough to fetch it, verify it and
/// know what it is before any of its bytes are read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryBlob {
    /// `sha256:<64 hex>`.
    pub digest: String,
    pub size: u64,
    pub media_type: String,
    pub source: BlobSource,
}

/// The content of an Image Registry entry (`K_IMAGE`, addressable), spec
/// §8.1. The `d` tag carries `<name>:<tag>`, so neither is repeated here.
///
/// `blobs` MUST list EVERY blob reachable from `digest` — the index, the
/// manifests, the configs and the layers — because a provider fetching the
/// image from this entry alone has nothing else to consult.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageEntryContent {
    /// The image's content address: `sha256:<64 hex>` naming an OCI index or
    /// a single-platform manifest.
    pub digest: String,
    pub media_type: String,
    pub blobs: Vec<EntryBlob>,
}

/// An Image Registry entry as it arrives from a relay: who signed it, the
/// `<name>:<tag>` its `d` tag carries, and its parsed content.
///
/// The canonical name of the image is `<publisher npub>/<name>:<tag>`
/// (spec §8.1): the publisher is part of the name, so it is kept here rather
/// than left for the caller to remember.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageEntry {
    pub publisher: PublicKey,
    pub name: String,
    pub tag: String,
    pub content: ImageEntryContent,
}

impl ImageEntry {
    /// Read an Image Registry entry from a signed event, checking its kind,
    /// its `d` tag's `<name>:<tag>` shape and that its `x` tag names the
    /// digest the content describes.
    pub fn from_event(event: &Event) -> Result<Self> {
        let content: ImageEntryContent = parse_content(event, K_IMAGE, "an Image Registry entry")?;
        check_x_tag(event, &content.digest)?;
        let d = identifier(event)?;
        let (name, tag) = d.rsplit_once(':').with_context(|| {
            format!(
                "an Image Registry entry's `d` is `<name>:<tag>`, not {:?}",
                d
            )
        })?;
        if name.is_empty() || tag.is_empty() {
            bail!(
                "an Image Registry entry's `d` is `<name>:<tag>`, not {:?}",
                d
            );
        }
        Ok(Self {
            publisher: event.pubkey,
            name: name.to_string(),
            tag: tag.to_string(),
            content,
        })
    }
}

/// Build an Image Registry entry for `<name>:<tag>`, signed by its
/// publisher. Addressable, so re-publishing the same `d` MOVES the tag
/// (spec §8.1) rather than adding a second entry.
pub fn image_entry_event(
    name: &str,
    tag: &str,
    content: &ImageEntryContent,
    keys: &Keys,
    now: u64,
) -> Result<Event> {
    Ok(
        EventBuilder::new(Kind::Custom(K_IMAGE), serde_json::to_string(content)?)
            .tags([
                Tag::identifier(format!("{}:{}", name, tag)),
                digest_tag(&content.digest)?,
                label_tag()?,
            ])
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(keys)?,
    )
}

// ── Blob Record (spec §8.2) ──────────────────────────────────────────────────

/// One part of a blob: a single TOON store upload, its hash and its length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPart {
    /// The TOON store transaction id this part was uploaded as.
    pub txid: String,
    /// The part's own SHA-256, as bare hex — a part is not content-addressed
    /// the way a blob is, so it carries no `sha256:` prefix.
    pub sha256: String,
    pub size: u64,
}

/// The content of a Blob Record (`K_BLOB`, addressable), spec §8.2: how one
/// blob's bytes are split into ordered parts in the TOON store.
///
/// `parts` is ORDERED: a reader concatenates them as they appear and checks
/// the result against `digest`. `part_size` is the size every part but the
/// last has, kept so a reader can tell a truncated list from a complete one
/// without fetching anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRecordContent {
    /// `sha256:<64 hex>` of the whole blob; also the `d` tag.
    pub digest: String,
    pub size: u64,
    pub part_size: u64,
    pub parts: Vec<BlobPart>,
}

/// A Blob Record as it arrives from a relay. Its `d` is its content's
/// `digest`, so there is nothing in the address the content does not already
/// say — only the signer is new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRecord {
    /// Whoever uploaded the parts. Not trusted: the parts and the blob are
    /// verified by hash, so a record from any signer is usable or discarded
    /// on its bytes alone (spec §8.4).
    pub publisher: PublicKey,
    pub content: BlobRecordContent,
}

impl BlobRecord {
    /// Read a Blob Record from a signed event, checking its kind and that
    /// its `d` and `x` tags both name the digest its content describes.
    pub fn from_event(event: &Event) -> Result<Self> {
        let content: BlobRecordContent = parse_content(event, K_BLOB, "a Blob Record")?;
        check_x_tag(event, &content.digest)?;
        let d = identifier(event)?;
        if d != content.digest {
            bail!(
                "a Blob Record's `d` is its digest: `d` says {:?}, content says {:?}",
                d,
                content.digest
            );
        }
        Ok(Self {
            publisher: event.pubkey,
            content,
        })
    }
}

/// Build a Blob Record, signed by whoever uploaded the parts.
pub fn blob_record_event(content: &BlobRecordContent, keys: &Keys, now: u64) -> Result<Event> {
    Ok(
        EventBuilder::new(Kind::Custom(K_BLOB), serde_json::to_string(content)?)
            .tags([
                Tag::identifier(content.digest.clone()),
                digest_tag(&content.digest)?,
                label_tag()?,
            ])
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(keys)?,
    )
}

// ── Template (spec §8.3) ─────────────────────────────────────────────────────

/// The image a Template names: by content address, with the Image Registry
/// entry that lists its blobs when there is one. Never a mutable tag — a
/// Template that could be repointed by someone else's `:latest` would be a
/// Template that grants what its author never wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateImage {
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_entry: Option<RegistryEntryRef>,
}

/// The content of a Template (`K_TEMPLATE`, addressable), spec §8.3. The `d`
/// tag carries the template name.
///
/// A Template GRANTS NOTHING (ADR 0004): there is no capability field here
/// and there never will be, because only a provider's own Listing decides
/// what privileges a workload gets. It is also expanded by the TENANT — the
/// provider never reads one, and a spawn's `template` field is informational
/// (spec §8.3, §11 item 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateContent {
    pub version: u32,
    pub image: TemplateImage,
    pub ports: Vec<PortRequest>,
    /// Where the workload keeps state, when it keeps any. A tenant expanding
    /// this into a spawn turns it into `volume_gb`; the path itself is the
    /// provider's (`spawn::VOLUME_MOUNT_PATH`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_path: Option<String>,
    /// Settings the author fixed. A `BTreeMap` so two publications of the
    /// same Template differ only where the values do.
    pub env_fixed: BTreeMap<String, String>,
    /// Names of the settings a tenant may supply.
    pub env_tenant: Vec<String>,
    /// The smallest tier this Template expects to run on, for a tenant
    /// choosing a Listing. Advice to the tenant, not a rule on any provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_resources: Option<Resources>,
}

/// A Template as it arrives from a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub publisher: PublicKey,
    pub name: String,
    pub content: TemplateContent,
}

impl Template {
    /// Read a Template from a signed event, checking its kind and that it
    /// has a name.
    pub fn from_event(event: &Event) -> Result<Self> {
        let content: TemplateContent = parse_content(event, K_TEMPLATE, "a Template")?;
        let name = identifier(event)?;
        if name.is_empty() {
            bail!("a Template's `d` is its name, which may not be empty");
        }
        Ok(Self {
            publisher: event.pubkey,
            name,
            content,
        })
    }
}

/// Build a Template, signed by its author. No `x` tag: a Template is found
/// by its name, and the digest it names is the image's, not its own.
pub fn template_event(
    name: &str,
    content: &TemplateContent,
    keys: &Keys,
    now: u64,
) -> Result<Event> {
    Ok(
        EventBuilder::new(Kind::Custom(K_TEMPLATE), serde_json::to_string(content)?)
            .tags([Tag::identifier(name.to_string()), label_tag()?])
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(keys)?,
    )
}

// ── the three forms of a spawn's image (spec §6.2) ───────────────────────────

/// What a spawn's (or an availability's) `image` object actually names, once
/// the three forms spec §6.2 allows are told apart.
///
/// This enum is the ONE place the forms are distinguished. Everything
/// downstream — the image policy, the fetcher, the backend — takes a
/// `SpawnImage` rather than re-reading the optional fields of `ImageRef`, so
/// there is a single answer to "which form is this?" and a single place a
/// fourth shape is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnImage {
    /// `{ reference, digest }`: pull `reference@digest` from an upstream OCI
    /// registry. The only form with a source that needs no TOON Network
    /// lookup at all, and the only one Milestone 1 spoke.
    Upstream { reference: String, digest: String },
    /// `{ digest, registry_entry }`: the Image Registry entry at `address`
    /// lists every blob and where its bytes are (spec §8.4 step 2).
    Registry {
        digest: String,
        entry: RegistryEntryRef,
    },
    /// `{ digest }` alone: the blobs are found by Blob Record lookup on the
    /// provider's own Relay Set (spec §8.4 step 3). Anyone who knows a
    /// digest someone already uploaded can spawn it.
    Digest { digest: String },
}

/// What a provider says when it is handed an Image Registry form it cannot
/// yet resolve. `refused_image`, not `invalid_request`: the request is
/// well-formed and the spec allows it — this provider simply cannot fetch
/// those bytes yet, and a tenant must learn that from `availability` before
/// it pays rather than from a lease it cannot use.
pub const IMAGE_REGISTRY_NOT_RESOLVED: &str =
    "image: this provider does not yet resolve the Image Registry, so it cannot fetch an image \
     named by digest alone or by a registry entry; name it with an upstream `reference` as well";

impl SpawnImage {
    /// Tell the three forms apart, refusing any fourth shape as
    /// `invalid_request` (spec §6.2 step 5).
    pub fn parse(image: &ImageRef) -> Result<Self, ErrorResponse> {
        if !is_sha256_digest(&image.digest) {
            return Err(invalid("image.digest must be `sha256:<64 lowercase hex>`"));
        }
        let digest = image.digest.clone();
        match (&image.reference, &image.registry_entry) {
            (Some(_), Some(_)) => Err(invalid(
                "image: `reference` and `registry_entry` name two different sources; \
                 give one or neither",
            )),
            (Some(reference), None) => {
                if !looks_like_repository(reference) {
                    return Err(invalid(
                        "image.reference must be an OCI repository (`registry/repo`), with no \
                         tag or digest",
                    ));
                }
                Ok(Self::Upstream {
                    reference: reference.clone(),
                    digest,
                })
            }
            (None, Some(entry)) => {
                check_entry_address(&entry.address)?;
                if entry.relay.is_empty() {
                    return Err(invalid("image.registry_entry.relay must name a relay"));
                }
                Ok(Self::Registry {
                    digest,
                    entry: entry.clone(),
                })
            }
            (None, None) => Ok(Self::Digest { digest }),
        }
    }

    /// The image's content address, whichever form named it.
    pub fn digest(&self) -> &str {
        match self {
            Self::Upstream { digest, .. }
            | Self::Registry { digest, .. }
            | Self::Digest { digest } => digest,
        }
    }

    /// `<reference>@<digest>` for the one form that names an upstream
    /// repository to pull from; `None` for the Image Registry forms, whose
    /// bytes come from §8.4's resolution instead.
    pub fn upstream_pull(&self) -> Option<String> {
        match self {
            Self::Upstream { reference, digest } => Some(format!("{}@{}", reference, digest)),
            _ => None,
        }
    }

    /// The upstream repository this form names, for the checks that are
    /// about the repository rather than the bytes (an image policy's deny
    /// list, the registry host to fetch a manifest from).
    pub fn upstream_reference(&self) -> Option<&str> {
        match self {
            Self::Upstream { reference, .. } => Some(reference),
            _ => None,
        }
    }
}

fn invalid(message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::InvalidRequest, message)
}

/// `30434:<64 hex pubkey>:<d>` — the NIP-01 coordinate of an Image Registry
/// entry. Checked here so a spawn that names a Listing, a Template or a
/// nonsense string is refused at the request rather than after a relay
/// lookup finds nothing.
fn check_entry_address(address: &str) -> Result<(), ErrorResponse> {
    let mut parts = address.splitn(3, ':');
    let (Some(kind), Some(pubkey), Some(d)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid(
            "image.registry_entry.address must be `<kind>:<pubkey>:<d>`",
        ));
    };
    if kind.parse::<u16>() != Ok(K_IMAGE) {
        return Err(invalid(format!(
            "image.registry_entry.address must name an Image Registry entry (kind {}), not kind {:?}",
            K_IMAGE, kind
        )));
    }
    if !is_lower_hex(pubkey, 64) {
        return Err(invalid(
            "image.registry_entry.address must carry the publisher's 32-byte pubkey as hex",
        ));
    }
    if d.is_empty() {
        return Err(invalid(
            "image.registry_entry.address must end in the entry's `<name>:<tag>`",
        ));
    }
    Ok(())
}

/// `sha256:` followed by exactly 64 lowercase hex characters. The one shape
/// a digest may have anywhere in this protocol.
pub fn is_sha256_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| is_lower_hex(hex, 64))
}

/// `[registry[:port]/]repo[/path…]` in the character set OCI references
/// allow, with no `@digest` and no `:tag` on the last segment.
fn looks_like_repository(reference: &str) -> bool {
    if reference.is_empty()
        || reference.contains('@')
        || !reference.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '/' | ':')
        })
    {
        return false;
    }
    let mut segments = reference.split('/');
    let first = segments.next().unwrap_or("");
    let rest: Vec<&str> = segments.collect();
    // A colon is only legal in the first segment as a registry port, and
    // never in the last segment (that would be a tag).
    let colon_ok = |seg: &str| match seg.split_once(':') {
        None => true,
        Some((_, port)) => !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()),
    };
    if rest.is_empty() {
        return !first.contains(':') && !first.is_empty();
    }
    colon_ok(first) && rest.iter().all(|s| !s.is_empty() && !s.contains(':'))
}

// ── shared event plumbing ────────────────────────────────────────────────────

/// The `["L", "toon.network"]` every TOON Network event carries.
fn label_tag() -> Result<Tag> {
    Ok(Tag::parse(["L", TOON_LABEL])?)
}

/// `["x", "<digest hex>"]`: the digest WITHOUT its `sha256:` prefix, so a
/// relay's `#x` filter is over the hex the spec writes (§8.1, §8.2).
fn digest_tag(digest: &str) -> Result<Tag> {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    Ok(Tag::parse(["x", hex])?)
}

fn parse_content<T: serde::de::DeserializeOwned>(
    event: &Event,
    kind: u16,
    what: &str,
) -> Result<T> {
    if event.kind.as_u16() != kind {
        bail!("{} is kind {}, not {}", what, kind, event.kind.as_u16());
    }
    serde_json::from_str(&event.content).with_context(|| format!("the content of {}", what))
}

fn identifier(event: &Event) -> Result<String> {
    event
        .tags
        .find(TagKind::d())
        .and_then(|t| t.content())
        .map(str::to_string)
        .context("an addressable event carries a `d` tag")
}

/// The `x` tag MUST be the content's digest hex. Without this a publisher
/// could tag a record with someone else's digest and have a relay serve it
/// to every `#x` filter for that blob.
fn check_x_tag(event: &Event, digest: &str) -> Result<()> {
    let x = event
        .tags
        .find(TagKind::custom("x"))
        .and_then(|t| t.content())
        .context("this event carries an `x` tag of its digest")?;
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    if x != hex {
        bail!(
            "the `x` tag {:?} does not name the digest in content ({:?})",
            x,
            digest
        );
    }
    Ok(())
}
