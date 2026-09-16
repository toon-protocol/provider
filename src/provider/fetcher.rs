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
use crate::directory::{Directory, NullDirectory};
use crate::nostr::image_events::{BlobRecord, BlobRecordContent, BlobSource, ImageEntry};
use crate::nostr::wire::{ErrorCode, ErrorResponse};

/// The placeholder a `gateway_url_pattern` must contain, replaced by the
/// transaction id of the part or record being read.
pub const TXID_PLACEHOLDER: &str = "{txid}";

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
    },
}

impl Candidate {
    /// The candidate an Image Registry entry's source becomes, for a blob
    /// of `media_type`.
    pub fn from_entry_source(source: &BlobSource, media_type: &str) -> Self {
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
            },
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::ToonStoreRecord { blob_record_txid } => {
                format!("toon-store Blob Record {}", blob_record_txid)
            }
            Self::BlobRecord(record) => {
                format!("Blob Record with {} part(s)", record.parts.len())
            }
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
    named: Named,
    directory: Arc<dyn Directory>,
    /// Blob Records found on the Relay Set, by digest. `None` for a digest
    /// nobody has asked about yet.
    found: Arc<Mutex<HashMap<String, Vec<Candidate>>>>,
}

impl std::fmt::Debug for BlobSources {
    /// Written by hand: `Arc<dyn Directory>` has no `Debug`, and what a
    /// reader of a log line wants is which form named the image, not the
    /// port behind it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.named {
            Named::Upstream {
                registry,
                repository,
            } => write!(f, "BlobSources(upstream {}/{})", registry, repository),
            Named::Entry(entry) => {
                write!(f, "BlobSources(entry {}:{})", entry.name, entry.tag)
            }
            Named::Nothing => write!(f, "BlobSources(Relay Set only)"),
        }
    }
}

/// What the image's own description says, which is one of the three forms
/// §6.2 allows.
#[derive(Clone)]
enum Named {
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
    /// Milestone 1's form: one upstream repository for the whole image.
    pub fn upstream(
        registry: impl Into<String>,
        repository: impl Into<String>,
        directory: Arc<dyn Directory>,
    ) -> Self {
        Self::with(
            Named::Upstream {
                registry: registry.into(),
                repository: repository.into(),
            },
            directory,
        )
    }

    /// The form that names an Image Registry entry.
    pub fn entry(entry: ImageEntry, directory: Arc<dyn Directory>) -> Self {
        Self::with(Named::Entry(Box::new(entry)), directory)
    }

    /// `{ digest }` alone: the Relay Set is the only source.
    pub fn relay_set(directory: Arc<dyn Directory>) -> Self {
        Self::with(Named::Nothing, directory)
    }

    /// Sources for an image nothing describes and no relay is asked about:
    /// what a caller that only reads the cache (the layout writer, a unit
    /// test) hands in.
    pub fn nowhere() -> Self {
        Self::with(Named::Nothing, Arc::new(NullDirectory))
    }

    fn with(named: Named, directory: Arc<dyn Directory>) -> Self {
        Self {
            named,
            directory,
            found: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// §8.4 step 2: what the image's own description names for `digest`.
    /// Empty when it names nothing for it — a bare digest, or an entry that
    /// does not list the blob.
    pub fn named(&self, digest: &str) -> Vec<Candidate> {
        match &self.named {
            Named::Upstream {
                registry,
                repository,
            } => vec![Candidate::Oci {
                registry: registry.clone(),
                repository: repository.clone(),
                endpoint: OciEndpoint::Manifests,
            }],
            Named::Entry(entry) => entry
                .content
                .blobs
                .iter()
                .find(|blob| blob.digest == digest)
                .map(|blob| vec![Candidate::from_entry_source(&blob.source, &blob.media_type)])
                .unwrap_or_default(),
            Named::Nothing => Vec::new(),
        }
    }

    /// Why nothing could serve `digest`, in the terms of the form that
    /// named the image: an entry that should have listed the blob (§8.1) is
    /// a different mistake from a bare digest nobody has uploaded every
    /// blob of, and a tenant can only act on the difference.
    pub fn no_source_message(&self, digest: &str) -> String {
        let why = match &self.named {
            Named::Upstream {
                registry,
                repository,
            } => format!("{}/{} does not serve it", registry, repository),
            Named::Entry(entry) => format!(
                "the Image Registry entry {}:{} does not list it",
                entry.name, entry.tag
            ),
            Named::Nothing => "the image was named by digest alone, so nothing names a source \
                 for it"
                .to_string(),
        };
        format!(
            "no source is known for blob {}: {}, and this provider's Relay Set holds no Blob \
             Record for it",
            digest, why
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
        if let Some(found) = self.found.lock().unwrap().get(digest) {
            return found.clone();
        }
        let events = match self.directory.find_blob_records(digest).await {
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
    /// Verified bytes on disk, keyed by digest. Only bytes that hashed to
    /// their digest are ever put here, so a cache hit skips every source
    /// and every check.
    cache: BlobCache,
}

impl BlobFetcher {
    pub fn new(
        gateway_url_pattern: Option<String>,
        registry_url_override: Option<String>,
        cache: BlobCache,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client with a timeout builds");
        Self {
            oci: OciClient::new(http.clone(), registry_url_override),
            http,
            gateway_url_pattern,
            cache,
        }
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
            } => {
                self.oci
                    .fetch(registry, repository, *endpoint, digest)
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
        let bytes = self.gateway_read(txid).await?;
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
    /// concatenated in the record's order.
    async fn assemble(&self, digest: &str, record: &BlobRecordContent) -> Result<Bytes> {
        if record.digest != digest {
            bail!(
                "the Blob Record describes {}, not {}",
                record.digest,
                digest
            );
        }
        let mut blob = BytesMut::with_capacity(usize::try_from(record.size).unwrap_or(0));
        for (index, part) in record.parts.iter().enumerate() {
            let bytes = self.gateway_read(&part.txid).await?;
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

    /// `GET` one upload from the gateway, by txid.
    async fn gateway_read(&self, txid: &str) -> Result<Bytes> {
        let url = self.gateway_url(txid)?;
        let response = self
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
        response
            .bytes()
            .await
            .with_context(|| format!("could not read the body of {}", url))
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
        let fetcher =
            BlobFetcher::new(Some("http://gw:3000/raw/{txid}".to_string()), None, cache());
        assert_eq!(
            fetcher.gateway_url("abc").unwrap(),
            "http://gw:3000/raw/abc"
        );
        let none = BlobFetcher::new(None, None, cache());
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
            Candidate::from_entry_source(&toon, "application/vnd.oci.image.layer.v1.tar+gzip"),
            Candidate::ToonStoreRecord {
                blob_record_txid: "tx".to_string()
            }
        );
        let oci = BlobSource::Oci {
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
        };
        assert_eq!(
            Candidate::from_entry_source(&oci, "application/vnd.oci.image.manifest.v1+json"),
            Candidate::Oci {
                registry: "docker.io".to_string(),
                repository: "library/alpine".to_string(),
                endpoint: OciEndpoint::Manifests,
            }
        );
        assert_eq!(
            Candidate::from_entry_source(&oci, "application/vnd.oci.image.config.v1+json"),
            Candidate::Oci {
                registry: "docker.io".to_string(),
                repository: "library/alpine".to_string(),
                endpoint: OciEndpoint::Blobs,
            }
        );
    }
}
