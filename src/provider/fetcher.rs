// Fetching image bytes: one blob at a time, from an ordered chain of
// sources, verified before anything reads them (spec §8.4, ADR 0006).
//
// The rule is the same for every blob whatever it is — an index, a
// manifest, a config, a layer — and wherever it lives:
//
// 1. the local cache;
// 2. the source the IMAGE'S OWN DESCRIPTION names for that blob — the
//    spawn's Image Registry entry, or Milestone 1's upstream reference;
// 3. the Blob Records the provider's Relay Set holds for the digest, found
//    by `#x` whoever signed them (`Directory::find_blob_records`);
// 4. exhaustion is `refused_image`.
//
// It stops at the first source whose bytes hash to the digest that was
// asked for; a source that fails — unreachable, a part that does not hash
// to its recorded sha256, a whole blob that does not hash to its digest —
// is logged and the next is tried. Fallthrough is PER BLOB: a gateway that
// is down for one layer costs that layer its source, not the spawn, and a
// blob already verified is never fetched again.
//
// Step 3 is taken LAZILY, and only for the blob that needs it: an image
// whose blobs are all cached contacts no relay and no gateway, and one
// whose entry describes every blob never asks the Relay Set at all.
//
// A `toon-store` source is a Blob Record: fetched by the txid of the
// record's own upload from the gateway URL pattern the provider is
// configured with, then each part from the same pattern, each part checked
// against its recorded sha256 and size, concatenated in order. An `oci`
// source is a pull by digest from an upstream registry (`oci`). Who signed
// a Blob Record is never trusted: the parts and the blob are checked by
// hash, so a record from any signer is usable or discarded on its bytes
// alone.
//
// The cache is `BlobCache`: verified bytes on disk, keyed by digest,
// outliving every lease and every restart, so a popular layer is fetched
// once. A blob that cannot be kept because the disk (or the configured cap)
// is full is `no_capacity`, the spec's word for a provider that has run out
// of room.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use nostr_sdk::Event;
use sha2::{Digest, Sha256};
use tracing::warn;

use super::blob_cache::{BlobCache, CacheError};
use super::oci::{OciClient, OciEndpoint};
use crate::directory::Directory;
use crate::nostr::image_events::{BlobPart, BlobRecord, BlobRecordContent, BlobSource, ImageEntry};
use crate::nostr::wire::{ErrorCode, ErrorResponse};
use crate::outbound_guard::OutboundGuard;
use crate::outbound_proxy::{guarded_http_client, OutboundProxy};

/// The placeholder a `gateway_url_pattern` must contain, replaced by the
/// transaction id of the part or record being read.
pub const TXID_PLACEHOLDER: &str = "{txid}";

/// The bound on a whole blob — a Blob Record's declared `size`, and the
/// up-front allocation `assemble` reserves for it — when this provider's
/// `max_image_bytes` is not configured (spec §8.4, TOON_Network#79).
/// Generous enough for a real image layer; small enough that a hostile
/// record's `size` alone cannot make a provider commit memory before a
/// single byte of it is verified.
const DEFAULT_MAX_BLOB_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// How large a Blob Record's own upload, or one of its pages, may be before
/// a fetch gives up on it — the JSON a record or a page carries, never the
/// blob's own bytes, so this bound has nothing to do with `max_image_bytes`
/// and is not itself declared anywhere. It is the "fixed page ceiling,
/// chosen by the implementation and not normative" spec §8.4 and §11 item 2
/// call for: about a hundred times a real record or page's own size (a
/// record at the ~700-part threshold that switches a publisher to `pages`,
/// §8.2, is itself only ~100 KB), so an honest upload is never close to it.
const GATEWAY_JSON_CEILING_BYTES: u64 = 16 * 1024 * 1024;

/// One place a blob's bytes may come from. A fetch is handed these in the
/// order §8.4 tries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    /// A Blob Record in the TOON store, by the txid of the record's own
    /// upload — an Image Registry entry's `toon-store` source (ADR 0006).
    ToonStoreRecord { blob_record_txid: String },
    /// A Blob Record already in hand, as one found on the Relay Set by
    /// `#x` arrives (§8.4 step 3).
    BlobRecord(BlobRecordContent),
    /// An upstream OCI repository — an entry's `oci` source, or the
    /// registry Milestone 1's `reference` form names.
    Oci {
        registry: String,
        repository: String,
        endpoint: OciEndpoint,
        /// The blob's own declared size, when one is known (an entry's
        /// `EntryBlob.size`, §8.1) — bounds a `Blobs` read at that size
        /// rather than this provider's whole-blob fallback, the same way a
        /// Blob Record part's own `size` bounds its read (TOON_Network#79).
        /// `None` for the top-level digest Milestone 1's `reference` form
        /// pulls, which nothing describes a size for; unused for
        /// `Manifests`, which is always bounded by a fixed JSON ceiling
        /// instead.
        size_hint: Option<u64>,
    },
}

impl Candidate {
    /// The candidate an Image Registry entry's source becomes, for a blob
    /// of `media_type` and declared `size`.
    pub fn from_entry_source(source: &BlobSource, media_type: &str, size: u64) -> Self {
        match source {
            BlobSource::ToonStore { blob_record_txid } => Self::ToonStoreRecord {
                blob_record_txid: blob_record_txid.clone(),
            },
            BlobSource::Oci {
                registry,
                repository,
            } => Self::Oci {
                registry: registry.clone(),
                repository: repository.clone(),
                endpoint: OciEndpoint::for_media_type(media_type),
                size_hint: Some(size),
            },
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::ToonStoreRecord { blob_record_txid } => {
                format!("toon-store Blob Record {}", blob_record_txid)
            }
            Self::BlobRecord(record) => match (&record.parts, &record.pages) {
                (Some(parts), _) => format!("Blob Record with {} part(s)", parts.len()),
                (None, Some(pages)) => format!("Blob Record with {} page(s)", pages.len()),
                (None, None) => "Blob Record with neither parts nor pages".to_string(),
            },
            Self::Oci {
                registry,
                repository,
                ..
            } => format!("oci {}/{}", registry, repository),
        }
    }
}

/// The §8.4 source chain for the blobs of ONE image: what the image's own
/// description names for a blob (step 2), and the Blob Records the Relay
/// Set holds for it (step 3). The cache — step 1 — is the fetcher's, since
/// it is shared by every image.
///
/// The two steps are separate methods rather than one list because step 3
/// costs a relay round trip: `named` is free and answered from memory,
/// `discovered` is only awaited once everything cheaper has failed. Within
/// one image a digest is looked up at most once however many times it is
/// asked for, so resolving an image and then fetching its layers does not
/// ask the Relay Set twice for the same blob.
///
/// Cloning is cheap and SHARES the memo: a clone handed to a spawn's fetch
/// of the layers reuses what resolution already found.
#[derive(Clone)]
pub struct BlobSources {
    describes: Description,
    /// The Relay Set to search for Blob Records — `None` when §8.4 step 3
    /// does not apply to this image at all: Milestone 1's `reference` form,
    /// which §6.2 gives "No Image Registry lookup at all", and an image
    /// nothing describes and no relay is asked about.
    directory: Option<Arc<dyn Directory>>,
    /// Blob Records found on the Relay Set, by digest. Absent for a digest
    /// nobody has asked about yet.
    found: Arc<Mutex<HashMap<String, Vec<Candidate>>>>,
}

impl std::fmt::Debug for BlobSources {
    /// Written by hand only because `Arc<dyn Directory>` has none, and
    /// `ResolvedImage` — which carries one of these — derives `Debug`. What
    /// it prints is the part a reader would want: which form named the
    /// image, not the port behind it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.describes {
            Description::Upstream {
                registry,
                repository,
            } => write!(f, "BlobSources(upstream {}/{})", registry, repository),
            Description::Entry(entry) => {
                write!(f, "BlobSources(entry {}:{})", entry.name, entry.tag)
            }
            Description::Nothing => write!(f, "BlobSources(Relay Set only)"),
        }
    }
}

/// What the image's own description says, which is one of the three forms
/// §6.2 allows.
#[derive(Clone)]
enum Description {
    /// `{ reference, digest }`: the repository the tenant named serves the
    /// image's manifests. Its layers are the backend's to pull.
    Upstream {
        registry: String,
        repository: String,
    },
    /// `{ digest, registry_entry }`: the entry names one source per blob
    /// (§8.1). A blob it does not list is not an error here — the Relay Set
    /// is asked for it next, like any other blob nothing nearer serves.
    Entry(Box<ImageEntry>),
    /// `{ digest }` alone: nothing is named, so every blob is found by `#x`
    /// on the Relay Set.
    Nothing,
}

impl BlobSources {
    /// Milestone 1's form: one upstream repository for the whole image, and
    /// NO Relay Set. That is §6.2's own word for it — "No Image Registry
    /// lookup at all" — so a registry that will not serve a blob of it is
    /// the end of the chain, not the start of a search for someone else's
    /// copy.
    pub fn upstream(registry: impl Into<String>, repository: impl Into<String>) -> Self {
        Self::with(
            Description::Upstream {
                registry: registry.into(),
                repository: repository.into(),
            },
            None,
        )
    }

    /// The form that names an Image Registry entry.
    pub fn entry(entry: ImageEntry, directory: Arc<dyn Directory>) -> Self {
        Self::with(Description::Entry(Box::new(entry)), Some(directory))
    }

    /// `{ digest }` alone: the Relay Set is the only source.
    pub fn relay_set(directory: Arc<dyn Directory>) -> Self {
        Self::with(Description::Nothing, Some(directory))
    }

    /// Sources for an image nothing describes and no relay is asked about:
    /// what a caller that only reads the cache hands in.
    pub fn nowhere() -> Self {
        Self::with(Description::Nothing, None)
    }

    fn with(describes: Description, directory: Option<Arc<dyn Directory>>) -> Self {
        Self {
            describes,
            directory,
            found: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// §8.4 step 2: what the image's own description names for `digest`.
    /// Empty when it names nothing for it — a bare digest, or an entry that
    /// does not list the blob.
    pub fn named(&self, digest: &str) -> Vec<Candidate> {
        match &self.describes {
            Description::Upstream {
                registry,
                repository,
            } => vec![Candidate::Oci {
                registry: registry.clone(),
                repository: repository.clone(),
                endpoint: OciEndpoint::Manifests,
                // Nothing describes a size for the top-level digest this
                // form pulls — and `Manifests` bounds by a fixed JSON
                // ceiling regardless, so this is never consulted anyway.
                size_hint: None,
            }],
            Description::Entry(entry) => entry
                .content
                .blobs
                .iter()
                .find(|blob| blob.digest == digest)
                .map(|blob| {
                    vec![Candidate::from_entry_source(
                        &blob.source,
                        &blob.media_type,
                        blob.size,
                    )]
                })
                .unwrap_or_default(),
            Description::Nothing => Vec::new(),
        }
    }

    /// Why nothing could serve `digest`, in the terms of the form that
    /// named the image: an entry that should have listed the blob (§8.1) is
    /// a different mistake from a bare digest nobody has uploaded every
    /// blob of, and a tenant can only act on the difference.
    pub fn no_source_message(&self, digest: &str) -> String {
        let why = match &self.describes {
            Description::Upstream {
                registry,
                repository,
            } => format!("{}/{} does not serve it", registry, repository),
            Description::Entry(entry) => format!(
                "the Image Registry entry {}:{} does not list it",
                entry.name, entry.tag
            ),
            Description::Nothing => {
                "the image was named by digest alone, so nothing names a source for it".to_string()
            }
        };
        let relay_set = match &self.directory {
            Some(_) => ", and this provider's Relay Set holds no Blob Record for it",
            None => "",
        };
        format!(
            "no source is known for blob {}: {}{}",
            digest, why, relay_set
        )
    }

    /// §8.4 step 3: the Blob Records the Relay Set holds for `digest`, as
    /// candidates. Looked up once per digest per image; a relay that cannot
    /// be reached is logged and counts as "none", because a source that
    /// cannot answer is a source that did not serve.
    ///
    /// A record whose content describes another blob is dropped here rather
    /// than tried: a relay is free to answer an `#x` filter with anything,
    /// and `BlobRecord::from_event` only proves the record is
    /// self-consistent, not that it is about the blob that was asked for.
    /// Nothing else about a record is judged — not its signer, not its
    /// publisher — because the parts and the blob are checked by hash.
    pub async fn discovered(&self, digest: &str) -> Vec<Candidate> {
        let Some(directory) = &self.directory else {
            return Vec::new();
        };
        if let Some(found) = self.found.lock().unwrap().get(digest) {
            return found.clone();
        }
        let events = match directory.find_blob_records(digest).await {
            Ok(events) => events,
            Err(e) => {
                warn!(
                    "the Relay Set could not be searched for Blob Records of {}: {:#}",
                    digest, e
                );
                Vec::new()
            }
        };
        let candidates: Vec<Candidate> = events
            .iter()
            .filter_map(|event| match BlobRecord::from_event(event) {
                Ok(record) if record.content.digest == digest => {
                    Some(Candidate::BlobRecord(record.content))
                }
                Ok(record) => {
                    warn!(
                        "a Blob Record found for {} describes {} instead",
                        digest, record.content.digest
                    );
                    None
                }
                Err(e) => {
                    warn!(
                        "an event found for {} is not a readable Blob Record: {:#}",
                        digest, e
                    );
                    None
                }
            })
            .collect();
        self.found
            .lock()
            .unwrap()
            .insert(digest.to_string(), candidates.clone());
        candidates
    }
}

/// How long one image fetch may take: a gateway read, a registry pull, or the
/// token exchange between them.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// One provider-wide fetcher, shared by `availability` and every spawn
/// (`AppState`). Holds the HTTP client, the registry client, the gateway
/// pattern and the cache of verified blobs.
pub struct BlobFetcher {
    http: reqwest::Client,
    oci: OciClient,
    /// `gateway_url_pattern` from the config, e.g.
    /// `http://envoy:3000/raw/{txid}`. `None` means this provider has no
    /// gateway and every `toon-store` source fails — refused, not a panic,
    /// so an operator sees why in the answer.
    gateway_url_pattern: Option<String>,
    /// The provider's `image_policy.max_image_bytes`, reused here as the
    /// bound on any ONE blob's declared `size` — `None` falls back to
    /// `DEFAULT_MAX_BLOB_BYTES` (spec §8.4, TOON_Network#79). A single blob
    /// can never exceed the whole image's cap anyway, so the same number
    /// serves both without a second config key.
    max_blob_bytes: Option<u64>,
    /// Where a fetch may go (TOON_Network#105): held so that `with_proxy`,
    /// which rebuilds the client, cannot rebuild it without the guard.
    guard: Arc<OutboundGuard>,
    /// Verified bytes on disk, keyed by digest. Only bytes that hashed to
    /// their digest are ever put here, so a cache hit skips every source
    /// and every check.
    cache: BlobCache,
}

impl BlobFetcher {
    /// `exempt_registries` is `image_policy.exempt_registries`: the hosts
    /// and CIDRs an operator has declared theirs, exempt from the rule that
    /// an image is never fetched from an address that is not publicly
    /// routable (TOON_Network#105). Empty is the default and the strict
    /// case. The two URLs an OPERATOR configures — `registry_url_override`
    /// and `gateway_url_pattern` — are exempt without being listed: they are
    /// not tenant values, and a store gateway on a compose network is the
    /// normal case.
    pub fn new(
        gateway_url_pattern: Option<String>,
        registry_url_override: Option<String>,
        exempt_registries: &[String],
        max_blob_bytes: Option<u64>,
        cache: BlobCache,
    ) -> Result<Self> {
        let guard = Arc::new(
            OutboundGuard::new(exempt_registries)?
                .exempting(registry_url_override.as_deref())
                .exempting(gateway_url_pattern.as_deref()),
        );
        let http = guarded_http_client(None, FETCH_TIMEOUT, "image fetches", &guard)?;
        Ok(Self {
            oci: OciClient::new(http.clone(), registry_url_override, Arc::clone(&guard)),
            http,
            gateway_url_pattern,
            max_blob_bytes,
            guard,
            cache,
        })
    }

    /// `max_blob_bytes`, or the fixed ceiling when this provider configures
    /// none.
    fn blob_byte_limit(&self) -> u64 {
        self.max_blob_bytes.unwrap_or(DEFAULT_MAX_BLOB_BYTES)
    }

    /// The same fetcher, with every byte it pulls leaving through `proxy`:
    /// the TOON store gateway, the upstream OCI registries, and the
    /// anonymous pull-token exchange a registry challenges with — which is a
    /// request to a THIRD host (the registry's auth realm) and would
    /// otherwise be the one image fetch that named this provider (spec §10).
    ///
    /// One client for all three, so no source can be added later that
    /// quietly goes direct. `socks5h`, so the registry's and the realm's
    /// names are resolved by the proxy.
    pub fn with_proxy(mut self, proxy: &OutboundProxy) -> Result<Self> {
        let http = guarded_http_client(Some(proxy), FETCH_TIMEOUT, "image fetches", &self.guard)?;
        self.oci = self.oci.with_client(http.clone());
        self.http = http;
        Ok(self)
    }

    /// The cache every verified blob lands in — where a spawn reads them
    /// back from to assemble an image.
    pub fn cache(&self) -> &BlobCache {
        &self.cache
    }

    /// The verified bytes of `digest`, down the whole of §8.4: the cache,
    /// then the source the image's description names, then the Relay Set's
    /// Blob Records — stopping at the first whose bytes hash to `digest`,
    /// which are then cached. `refused_image` when none does, naming every
    /// source that was tried and why it failed; `no_capacity` when the
    /// bytes were found but the cache has no room for them.
    ///
    /// The Relay Set is only asked once the cache and the named source have
    /// failed, so a blob already on disk costs no network at all.
    pub async fn fetch(&self, digest: &str, sources: &BlobSources) -> Result<Bytes, ErrorResponse> {
        if let Some(cached) = self.cache.get(digest).await {
            return Ok(cached);
        }
        let mut failures = Vec::new();
        for candidate in sources.named(digest) {
            if let Some(bytes) = self
                .try_candidate(digest, &candidate, &mut failures)
                .await?
            {
                return Ok(bytes);
            }
        }
        for candidate in sources.discovered(digest).await {
            if let Some(bytes) = self
                .try_candidate(digest, &candidate, &mut failures)
                .await?
            {
                return Ok(bytes);
            }
        }
        Err(ErrorResponse::new(
            ErrorCode::RefusedImage,
            if failures.is_empty() {
                sources.no_source_message(digest)
            } else {
                format!(
                    "no source could serve blob {} ({})",
                    digest,
                    failures.join("; ")
                )
            },
        ))
    }

    /// Whether some source could serve `digest`, WITHOUT fetching it: it is
    /// in the cache, or the image names a source for it, or the Relay Set
    /// holds a Blob Record for it.
    ///
    /// This is what lets `availability` refuse an image with a layer
    /// nothing can serve for free (§6.4) instead of leaving a tenant to buy
    /// the discovery. It is the same chain in the same order, so it asks
    /// the Relay Set only about blobs the cache and the image's own
    /// description do not account for — and the answer is memoised, so the
    /// paid fetch that follows does not ask again.
    pub async fn can_serve(&self, digest: &str, sources: &BlobSources) -> bool {
        self.cache.contains(digest)
            || !sources.named(digest).is_empty()
            || !sources.discovered(digest).await.is_empty()
    }

    /// One candidate: `Some(bytes)` if it served, `None` (with the failure
    /// recorded) if it did not, and `Err` only for a failure that is not
    /// the candidate's fault — a cache with no room, which no other source
    /// would fix.
    async fn try_candidate(
        &self,
        digest: &str,
        candidate: &Candidate,
        failures: &mut Vec<String>,
    ) -> Result<Option<Bytes>, ErrorResponse> {
        match self.fetch_from(digest, candidate).await {
            Ok(bytes) => {
                self.keep(digest, &bytes).await?;
                Ok(Some(bytes))
            }
            Err(e) => {
                warn!(
                    "blob {} could not be served by {}: {:#}",
                    digest,
                    candidate.describe(),
                    e
                );
                failures.push(format!("{}: {:#}", candidate.describe(), e));
                Ok(None)
            }
        }
    }

    /// Cache verified bytes. A cache that cannot take them is an answer,
    /// not a warning: the next spawn would fetch the same blob again and
    /// fail the same way, and a layer that is not on disk cannot be
    /// assembled into an image — so the spawn is `no_capacity`, which is
    /// what the spec says a full disk is.
    async fn keep(&self, digest: &str, bytes: &[u8]) -> Result<(), ErrorResponse> {
        match self.cache.put(digest, bytes).await {
            Ok(()) => Ok(()),
            Err(CacheError::NoSpace(why)) => Err(ErrorResponse::new(ErrorCode::NoCapacity, why)),
            Err(CacheError::Io(e)) => Err(ErrorResponse::new(
                ErrorCode::NoCapacity,
                format!("blob {} could not be kept in the cache: {:#}", digest, e),
            )),
        }
    }

    /// Bytes from one candidate, verified against `digest` before they are
    /// returned; every failure is an `Err` the chain moves past.
    async fn fetch_from(&self, digest: &str, candidate: &Candidate) -> Result<Bytes> {
        let bytes = match candidate {
            Candidate::ToonStoreRecord { blob_record_txid } => {
                let record = self.blob_record(blob_record_txid).await?;
                self.assemble(digest, &record).await?
            }
            Candidate::BlobRecord(record) => self.assemble(digest, record).await?,
            Candidate::Oci {
                registry,
                repository,
                endpoint,
                size_hint,
            } => {
                self.oci
                    .fetch(
                        registry,
                        repository,
                        *endpoint,
                        digest,
                        *size_hint,
                        self.blob_byte_limit(),
                    )
                    .await?
            }
        };
        verify_digest(&bytes, digest)?;
        Ok(bytes)
    }

    /// A Blob Record from its own upload in the TOON store: the signed
    /// event JSON the publisher uploaded beside publishing it to relays
    /// (ADR 0006).
    async fn blob_record(&self, txid: &str) -> Result<BlobRecordContent> {
        let bytes = self.gateway_read(txid, GATEWAY_JSON_CEILING_BYTES).await?;
        let event: Event = serde_json::from_slice(&bytes)
            .with_context(|| format!("the upload {} is not a Nostr event", txid))?;
        event
            .verify()
            .with_context(|| format!("the upload {} is not a validly signed event", txid))?;
        let record = BlobRecord::from_event(&event)
            .with_context(|| format!("the upload {} is not a Blob Record", txid))?;
        Ok(record.content)
    }

    /// The whole blob from a Blob Record's parts: each read from the
    /// gateway, checked against its recorded size and sha256, and
    /// concatenated in the record's order. The parts themselves come either
    /// straight from the record (`parts`) or through its `pages` (§8.2, §11
    /// item 2) — `resolve_parts` tells them apart, and everything after it
    /// is unchanged either way.
    ///
    /// Nothing here trusts `record.size` before it is verified
    /// (TOON_Network#79): it is checked against the recorded parts' own
    /// sizes, and against this provider's limit, BEFORE a single part is
    /// fetched or a single byte is reserved for the blob — so a record that
    /// lies about either fails cheaply, without the large allocation a
    /// `size` near `u64::MAX` would otherwise cause.
    async fn assemble(&self, digest: &str, record: &BlobRecordContent) -> Result<Bytes> {
        if record.digest != digest {
            bail!(
                "the Blob Record describes {}, not {}",
                record.digest,
                digest
            );
        }
        let limit = self.blob_byte_limit();
        if record.size > limit {
            bail!(
                "the Blob Record's size {} exceeds this provider's limit of {} bytes",
                record.size,
                limit
            );
        }
        let parts = self.resolve_parts(record).await?;
        let declared_total: u64 = parts.iter().fold(0u64, |sum, p| sum.saturating_add(p.size));
        if declared_total != record.size {
            bail!(
                "the Blob Record declares size {} but its {} part(s) total {}",
                record.size,
                parts.len(),
                declared_total
            );
        }
        let mut blob = BytesMut::with_capacity(usize::try_from(record.size).unwrap_or(0));
        for (index, part) in parts.iter().enumerate() {
            let bytes = self.gateway_read(&part.txid, part.size).await?;
            if bytes.len() as u64 != part.size {
                bail!(
                    "part {} ({}) is {} bytes, not the {} recorded",
                    index,
                    part.txid,
                    bytes.len(),
                    part.size
                );
            }
            let got = hex_sha256(&bytes);
            if !got.eq_ignore_ascii_case(&part.sha256) {
                bail!(
                    "part {} ({}) hashes to {}, not the {} recorded",
                    index,
                    part.txid,
                    got,
                    part.sha256
                );
            }
            blob.extend_from_slice(&bytes);
        }
        if blob.len() as u64 != record.size {
            bail!(
                "the parts total {} bytes, not the {} the Blob Record says",
                blob.len(),
                record.size
            );
        }
        Ok(blob.freeze())
    }

    /// The record's ordered parts, however they are carried (§8.2, §11 item
    /// 2). Inline `parts` is returned as is, once its length is checked
    /// against what `size`/`part_size` imply; `pages` is bounded by those
    /// same numbers BEFORE a single page is fetched — TOON_Network#79, so a
    /// record cannot make a provider read an unbounded number of pages by
    /// simply listing more of them — and then fetched page by page, each
    /// page's OWN bytes verified against its `sha256` — and its part count
    /// against `parts` — BEFORE any part inside it is trusted, then
    /// concatenated in page order. A page that cannot be fetched or fails
    /// its digest fails the whole record here, which is what sends the
    /// caller's source (§8.4's chain) on to the next one.
    async fn resolve_parts(&self, record: &BlobRecordContent) -> Result<Vec<BlobPart>> {
        record.check_one_of()?;
        let expected_parts = expected_part_count(record.size, record.part_size)?;
        match (&record.parts, &record.pages) {
            (Some(parts), None) => {
                if parts.len() as u64 != expected_parts {
                    bail!(
                        "the Blob Record's size {} and part_size {} imply {} part(s), but it \
                         lists {}",
                        record.size,
                        record.part_size,
                        expected_parts,
                        parts.len()
                    );
                }
                Ok(parts.clone())
            }
            (None, Some(pages)) => {
                if pages.len() as u64 > expected_parts {
                    bail!(
                        "the Blob Record lists {} page(s), more than the {} part(s) its size {} \
                         and part_size {} imply",
                        pages.len(),
                        expected_parts,
                        record.size,
                        record.part_size
                    );
                }
                let mut declared_parts_total: u64 = 0;
                for (index, page) in pages.iter().enumerate() {
                    if page.parts == 0 {
                        bail!("page {} ({}) declares 0 parts", index, page.txid);
                    }
                    declared_parts_total = declared_parts_total.saturating_add(page.parts);
                }
                if declared_parts_total != expected_parts {
                    bail!(
                        "the Blob Record's pages declare {} part(s) total, not the {} its size \
                         {} and part_size {} imply",
                        declared_parts_total,
                        expected_parts,
                        record.size,
                        record.part_size
                    );
                }
                let mut all = Vec::new();
                for (index, page) in pages.iter().enumerate() {
                    let bytes = self
                        .gateway_read(&page.txid, GATEWAY_JSON_CEILING_BYTES)
                        .await
                        .with_context(|| {
                            format!("page {} ({}) could not be read", index, page.txid)
                        })?;
                    let got = hex_sha256(&bytes);
                    if !got.eq_ignore_ascii_case(&page.sha256) {
                        bail!(
                            "page {} ({}) hashes to {}, not the {} recorded",
                            index,
                            page.txid,
                            got,
                            page.sha256
                        );
                    }
                    let page_parts: Vec<BlobPart> =
                        serde_json::from_slice(&bytes).with_context(|| {
                            format!(
                                "page {} ({}) is not a JSON array of parts",
                                index, page.txid
                            )
                        })?;
                    if page_parts.len() as u64 != page.parts {
                        bail!(
                            "page {} ({}) lists {} part(s), not the {} recorded",
                            index,
                            page.txid,
                            page_parts.len(),
                            page.parts
                        );
                    }
                    all.extend(page_parts);
                }
                Ok(all)
            }
            _ => unreachable!("check_one_of already refused both or neither"),
        }
    }

    /// `GET` one upload from the gateway, by txid, streamed chunk by chunk
    /// and cut off the instant it exceeds `limit` — never buffering more
    /// than `limit` bytes of a body, however large a hostile or merely
    /// broken gateway sends (spec §8.4, TOON_Network#79). A body that is
    /// shorter than `limit` is unaffected: this only ever stops something
    /// that was already too long.
    async fn gateway_read(&self, txid: &str, limit: u64) -> Result<Bytes> {
        let url = self.gateway_url(txid)?;
        let mut response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("could not reach the gateway at {}", url))?;
        if !response.status().is_success() {
            bail!(
                "the gateway answered HTTP {} for {}",
                response.status(),
                url
            );
        }
        let mut body = BytesMut::with_capacity(usize::try_from(limit).unwrap_or(0));
        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("could not read the body of {}", url))?
        {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > limit {
                bail!(
                    "the body of {} is longer than the {} bytes allowed for it",
                    url,
                    limit
                );
            }
        }
        Ok(body.freeze())
    }

    fn gateway_url(&self, txid: &str) -> Result<String> {
        let pattern = self.gateway_url_pattern.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "this provider has no gateway_url_pattern configured, so it cannot read the \
                 TOON store"
            )
        })?;
        Ok(pattern.replace(TXID_PLACEHOLDER, txid))
    }
}

/// The number of parts a Blob Record's own `size` and `part_size` imply
/// (§8.2: `part_size` "is the size every part but the last has... the
/// parts' sizes MUST sum to `size`") — `ceil(size / part_size)`. Computed
/// from numbers the record already carries, so this costs no network call:
/// used to bound a paged record's page count and per-page `parts`, and an
/// inline record's `parts` length, before a single page or part is fetched
/// (TOON_Network#79).
fn expected_part_count(size: u64, part_size: u64) -> Result<u64> {
    if part_size == 0 {
        bail!("the Blob Record's part_size is 0, which cannot split its size into parts");
    }
    let whole = size / part_size;
    Ok(if size.is_multiple_of(part_size) {
        whole
    } else {
        whole + 1
    })
}

/// The bytes hash to `digest`, or why not.
pub fn verify_digest(bytes: &[u8], digest: &str) -> Result<()> {
    let want = digest
        .strip_prefix("sha256:")
        .with_context(|| format!("digest {:?} is not sha256:<hex>", digest))?;
    let got = hex_sha256(bytes);
    if !got.eq_ignore_ascii_case(want) {
        bail!(
            "digest mismatch: requested {} but the fetched bytes hash to sha256:{}",
            digest,
            got
        );
    }
    Ok(())
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_verification_catches_a_mismatch() {
        let bytes = b"not the bytes you expected";
        let real = format!("sha256:{}", hex_sha256(bytes));
        assert!(verify_digest(bytes, &real).is_ok());
        assert!(verify_digest(bytes, "sha256:00").is_err());
        assert!(verify_digest(bytes, "md5:00").is_err());
    }

    fn cache() -> BlobCache {
        BlobCache::open(tempfile::tempdir().unwrap().keep(), None).unwrap()
    }

    #[test]
    fn the_gateway_pattern_is_filled_with_the_txid() {
        let fetcher = BlobFetcher::new(
            Some("http://gw:3000/raw/{txid}".to_string()),
            None,
            &[],
            None,
            cache(),
        )
        .unwrap();
        assert_eq!(
            fetcher.gateway_url("abc").unwrap(),
            "http://gw:3000/raw/abc"
        );
        let none = BlobFetcher::new(None, None, &[], None, cache()).unwrap();
        assert!(none
            .gateway_url("abc")
            .unwrap_err()
            .to_string()
            .contains("gateway_url_pattern"));
    }

    #[test]
    fn an_entry_source_becomes_the_candidate_for_its_media_type() {
        let toon = BlobSource::ToonStore {
            blob_record_txid: "tx".to_string(),
        };
        assert_eq!(
            Candidate::from_entry_source(&toon, "application/vnd.oci.image.layer.v1.tar+gzip", 5),
            Candidate::ToonStoreRecord {
                blob_record_txid: "tx".to_string()
            }
        );
        let oci = BlobSource::Oci {
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
        };
        assert_eq!(
            Candidate::from_entry_source(&oci, "application/vnd.oci.image.manifest.v1+json", 5),
            Candidate::Oci {
                registry: "docker.io".to_string(),
                repository: "library/alpine".to_string(),
                endpoint: OciEndpoint::Manifests,
                size_hint: Some(5),
            }
        );
        assert_eq!(
            Candidate::from_entry_source(&oci, "application/vnd.oci.image.config.v1+json", 5),
            Candidate::Oci {
                registry: "docker.io".to_string(),
                repository: "library/alpine".to_string(),
                endpoint: OciEndpoint::Blobs,
                size_hint: Some(5),
            }
        );
    }
}
