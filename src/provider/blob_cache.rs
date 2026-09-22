// The blob cache: verified image bytes on disk, keyed by digest, outliving
// every lease and every restart (spec §8.4: "verified blobs SHOULD be cached
// across leases").
//
// Only bytes that hashed to their digest are ever written here, and a read
// hashes them again before handing them out — a file that rotted on disk is
// dropped and fetched afresh rather than run. So a cache hit is exactly as
// trustworthy as a fresh fetch, and the fetcher can skip every source for
// it.
//
// The layout is `<dir>/sha256/<hex>`, one file per blob, written to a
// temporary name and renamed into place so a crash mid-write leaves no
// half-blob a later read could mistake for a whole one. There is no
// eviction: an operator who wants a bound sets `blob_cache_max_bytes`, and
// a blob that would cross it is `NoSpace` — the same answer a full disk
// gives, and what a spawn turns into `no_capacity`.
//
// `path_of` is where every lookup ultimately joins a digest onto this
// directory, so it is the one place that MUST refuse a digest that is not
// `sha256:<64 lowercase hex>` — a caller that skipped its own shape check
// (TOON_Network#104) still cannot turn `..` in a digest into a path outside
// `<dir>/sha256/`. A malformed digest is a miss: `get` and `contains` never
// read, probe or delete a path built from one, and `put` refuses to write
// one.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bytes::Bytes;
use tracing::warn;

use crate::nostr::image_events::is_sha256_digest;

use super::fetcher::{hex_sha256, verify_digest};

/// Why a blob could not be kept.
#[derive(Debug)]
pub enum CacheError {
    /// The disk is full, or the configured cap would be crossed. A spawn
    /// answers this `no_capacity`.
    NoSpace(String),
    /// Anything else the filesystem refused.
    Io(anyhow::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSpace(why) => write!(f, "{}", why),
            Self::Io(e) => write!(f, "{:#}", e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlobCache {
    dir: PathBuf,
    max_bytes: Option<u64>,
}

impl BlobCache {
    /// Open (creating if needed) the cache at `dir`. `max_bytes` bounds
    /// what it may hold; `None` leaves it to the disk.
    pub fn open(dir: impl Into<PathBuf>, max_bytes: Option<u64>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(dir.join("sha256"))
            .with_context(|| format!("could not create the blob cache at {}", dir.display()))?;
        std::fs::create_dir_all(dir.join("tmp"))
            .with_context(|| format!("could not create the blob cache at {}", dir.display()))?;
        Ok(Self { dir, max_bytes })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A scratch directory beside the blobs, on the same filesystem, for
    /// what is assembled out of them (an image layout on its way to the
    /// backend).
    pub fn scratch_dir(&self) -> PathBuf {
        self.dir.join("tmp")
    }

    /// Where `digest` lives if it is cached, or `None` if `digest` is not
    /// `sha256:<64 lowercase hex>` — the one shape this cache ever joins
    /// onto its directory, so nothing else a digest might contain (`..`, a
    /// `/`, anything shorter or longer than 64 hex characters) is ever
    /// turned into a path. The path is answered whether or not the file
    /// exists; `contains` says which.
    pub fn path_of(&self, digest: &str) -> Option<PathBuf> {
        if !is_sha256_digest(digest) {
            return None;
        }
        let hex = digest
            .strip_prefix("sha256:")
            .expect("is_sha256_digest just checked the prefix");
        Some(self.dir.join("sha256").join(hex))
    }

    /// A malformed digest is never cached, so this is `false` for one
    /// without probing the filesystem at all.
    pub fn contains(&self, digest: &str) -> bool {
        self.path_of(digest).is_some_and(|path| path.is_file())
    }

    /// The verified bytes of `digest`, or `None` if it is not cached — which
    /// includes a malformed digest, for which no path is ever read. A
    /// cached file that no longer hashes to its name is removed and reported
    /// as absent, so a fetch replaces it.
    pub async fn get(&self, digest: &str) -> Option<Bytes> {
        let path = self.path_of(digest)?;
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => Bytes::from(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                warn!("could not read cached blob {}: {}", path.display(), e);
                return None;
            }
        };
        if let Err(e) = verify_digest(&bytes, digest) {
            warn!(
                "cached blob {} is corrupt and was dropped: {:#}",
                path.display(),
                e
            );
            let _ = tokio::fs::remove_file(&path).await;
            return None;
        }
        Some(bytes)
    }

    /// Keep `bytes` as `digest`. The caller has verified them — this is the
    /// one place that trust is taken on faith, so the fetcher is the only
    /// caller. Idempotent: a blob already present is left as it is. A
    /// malformed digest is refused rather than written anywhere: the
    /// fetcher only ever calls this once `verify_digest` has already
    /// confirmed the bytes hash to `digest`, so this only fires if a future
    /// caller skips that.
    pub async fn put(&self, digest: &str, bytes: &[u8]) -> Result<(), CacheError> {
        let path = self.path_of(digest).ok_or_else(|| {
            CacheError::Io(anyhow::anyhow!(
                "blob digest {:?} is not `sha256:<64 lowercase hex>`, refusing to cache it",
                digest
            ))
        })?;
        if path.is_file() {
            return Ok(());
        }
        if let Some(max) = self.max_bytes {
            let used = self.used_bytes().await.map_err(CacheError::Io)?;
            let after = used.saturating_add(bytes.len() as u64);
            if after > max {
                return Err(CacheError::NoSpace(format!(
                    "the blob cache at {} holds {} bytes and blob {} ({} bytes) would take it \
                     past blob_cache_max_bytes {}",
                    self.dir.display(),
                    used,
                    digest,
                    bytes.len(),
                    max
                )));
            }
        }
        let tmp = self.scratch_dir().join(format!(
            "{}.{}.part",
            hex_sha256(digest.as_bytes()),
            std::process::id()
        ));
        let write = async {
            tokio::fs::write(&tmp, bytes).await?;
            tokio::fs::rename(&tmp, &path).await
        };
        match write.await {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                if e.kind() == std::io::ErrorKind::StorageFull {
                    Err(CacheError::NoSpace(format!(
                        "the disk holding the blob cache at {} is full ({} bytes for blob {}): {}",
                        self.dir.display(),
                        bytes.len(),
                        digest,
                        e
                    )))
                } else {
                    Err(CacheError::Io(anyhow::Error::new(e).context(format!(
                        "could not write blob {} to the cache",
                        digest
                    ))))
                }
            }
        }
    }

    /// Bytes held by every cached blob.
    pub async fn used_bytes(&self) -> Result<u64> {
        let dir = self.dir.join("sha256");
        let mut entries = tokio::fs::read_dir(&dir)
            .await
            .with_context(|| format!("could not list the blob cache at {}", dir.display()))?;
        let mut total = 0u64;
        while let Some(entry) = entries.next_entry().await? {
            total = total.saturating_add(entry.metadata().await?.len());
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex_sha256(bytes))
    }

    #[tokio::test]
    async fn a_blob_put_is_read_back_by_digest_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(dir.path(), None).unwrap();
        let bytes = b"layer bytes";
        let digest = digest_of(bytes);

        assert!(cache.get(&digest).await.is_none());
        cache.put(&digest, bytes).await.unwrap();
        assert_eq!(cache.get(&digest).await.unwrap().as_ref(), bytes);
        assert!(cache.contains(&digest));

        let reopened = BlobCache::open(dir.path(), None).unwrap();
        assert_eq!(reopened.get(&digest).await.unwrap().as_ref(), bytes);
        assert_eq!(reopened.used_bytes().await.unwrap(), bytes.len() as u64);
    }

    #[tokio::test]
    async fn a_cached_file_that_no_longer_hashes_to_its_name_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(dir.path(), None).unwrap();
        let digest = digest_of(b"the real bytes");
        std::fs::write(cache.path_of(&digest).unwrap(), b"rotted").unwrap();

        assert!(cache.get(&digest).await.is_none());
        assert!(!cache.contains(&digest), "the corrupt file is gone");
    }

    /// TOON_Network#104: a digest that is not `sha256:<64 lowercase hex>`
    /// never becomes a path, at every one of the cache's own entry points —
    /// so no future caller can reintroduce the traversal even if it skips
    /// its own shape check.
    #[tokio::test]
    async fn a_malformed_digest_is_refused_at_every_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(dir.path(), None).unwrap();

        // A file that a traversal digest would reach if `path_of` ever
        // built a path from one: beside the cache directory itself.
        let canary = dir.path().join("canary.txt");
        std::fs::write(&canary, b"do not touch me").unwrap();

        let malformed = [
            "sha256:../../canary.txt",
            "sha256:../canary.txt",
            "../../canary.txt",
            "canary.txt",
            "",
            "sha256:",
            "sha256:00",                            // too short
            &format!("sha256:{}0", "a".repeat(64)), // too long
            &format!("SHA256:{}", "a".repeat(64)),  // wrong case prefix
            &format!("sha256:{}", "A".repeat(64)),  // uppercase hex
            &format!("sha256:{}", "g".repeat(64)),  // not hex
            &format!("md5:{}", "a".repeat(32)),
        ];
        for digest in malformed {
            assert!(
                cache.path_of(digest).is_none(),
                "{:?} must not become a path",
                digest
            );
            assert!(
                !cache.contains(digest),
                "{:?} must be a miss, not a probe",
                digest
            );
            assert!(
                cache.get(digest).await.is_none(),
                "{:?} must be a miss, not a read",
                digest
            );
            let err = cache.put(digest, b"whatever").await.unwrap_err();
            assert!(matches!(err, CacheError::Io(_)), "{}", err);
        }

        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"do not touch me",
            "the file beside the cache directory was never read, probed or deleted"
        );
    }

    #[tokio::test]
    async fn a_blob_past_the_cap_is_no_space_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(dir.path(), Some(20)).unwrap();
        let small = b"ten bytes!";
        cache.put(&digest_of(small), small).await.unwrap();

        let big = b"eleven bytes";
        let err = cache.put(&digest_of(big), big).await.unwrap_err();
        assert!(matches!(err, CacheError::NoSpace(_)), "{}", err);
        assert!(err.to_string().contains("blob_cache_max_bytes"));
        assert!(!cache.contains(&digest_of(big)));
        assert_eq!(cache.used_bytes().await.unwrap(), 10);
        assert!(
            std::fs::read_dir(cache.scratch_dir())
                .unwrap()
                .next()
                .is_none(),
            "no temporary file is left behind"
        );

        // The same blob again is not counted twice.
        cache.put(&digest_of(small), small).await.unwrap();
        assert_eq!(cache.used_bytes().await.unwrap(), 10);
    }
}
