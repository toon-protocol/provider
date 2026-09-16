// Fetching image bytes: one blob at a time, from an ordered chain of
// sources, verified before anything reads them (spec §8.4, ADR 0006).
//
// The rule is the same for every blob whatever it is — an index, a
// manifest, a config, a layer — and wherever it lives:
//
// 1. the local cache;
// 2. each candidate source in order, stopping at the first whose bytes hash
//    to the digest that was asked for; a source that fails — unreachable,
//    a part that does not hash to its recorded sha256, a whole blob that
//    does not hash to its digest — is logged and the next is tried;
// 3. exhaustion is `refused_image`.
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
// of room. What this leaves for the next ticket is the Relay Set lookup
// that supplies `Candidate::BlobRecord`s for a bare digest.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use nostr_sdk::Event;
use sha2::{Digest, Sha256};
use tracing::warn;

use super::blob_cache::{BlobCache, CacheError};
use super::oci::{OciClient, OciEndpoint};
use crate::nostr::image_events::{BlobRecord, BlobRecordContent, BlobSource};
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

    /// The verified bytes of `digest`: from the cache, or from the first
    /// candidate whose bytes hash to it, which are then cached.
    /// `refused_image` when none does, naming every source that was tried
    /// and why it failed; `no_capacity` when the bytes were found but the
    /// cache has no room for them.
    pub async fn fetch(
        &self,
        digest: &str,
        candidates: &[Candidate],
    ) -> Result<Bytes, ErrorResponse> {
        if let Some(cached) = self.cache.get(digest).await {
            return Ok(cached);
        }
        let mut failures = Vec::new();
        for candidate in candidates {
            match self.fetch_from(digest, candidate).await {
                Ok(bytes) => {
                    self.keep(digest, &bytes).await?;
                    return Ok(bytes);
                }
                Err(e) => {
                    warn!(
                        "blob {} could not be served by {}: {:#}",
                        digest,
                        candidate.describe(),
                        e
                    );
                    failures.push(format!("{}: {:#}", candidate.describe(), e));
                }
            }
        }
        Err(ErrorResponse::new(
            ErrorCode::RefusedImage,
            if failures.is_empty() {
                format!("no source is known for blob {}", digest)
            } else {
                format!(
                    "no source could serve blob {} ({})",
                    digest,
                    failures.join("; ")
                )
            },
        ))
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
