// The image a Docker backend loads: every verified blob of a resolved
// image, laid out as the OCI image layout (`oci-layout`, `index.json`,
// `blobs/sha256/<hex>`) in one tar the backend reads with `docker load`.
//
// Nothing is copied: every blob is streamed straight out of the blob cache,
// where the fetcher put it after checking it against its digest. The index
// names the one manifest that was resolved for the listing's arch, and no
// tag: what comes out of the load is an image id, and the workload runs by
// that id (spec §8.4, ADR 0006 — bytes are verified by digest wherever they
// are stored, and a name is never what selects them).

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use super::blob_cache::BlobCache;
use super::image_policy::ResolvedImage;

const OCI_LAYOUT: &str = r#"{"imageLayoutVersion":"1.0.0"}"#;

fn hex_of(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

/// Write `image` as an OCI layout tar at `out`, from blobs already in
/// `cache`: the manifest, its config and every layer. Blocking file I/O,
/// so a caller on the async runtime should `spawn_blocking` it.
pub fn write_layout_tar(cache: &BlobCache, image: &ResolvedImage, out: &Path) -> Result<()> {
    let file = std::fs::File::create(out)
        .with_context(|| format!("could not create the image layout at {}", out.display()))?;
    let mut tar = tar::Builder::new(file);

    // Every digest here already went down §8.4's chain — resolution fetched
    // and verified each one before this ran — so `path_of` refusing it
    // would mean a digest reached this far without that, which is a bug
    // upstream, not something this layout can route around.
    let manifest_path = cache.path_of(&image.manifest_digest).with_context(|| {
        format!(
            "manifest digest {:?} is not `sha256:<64 lowercase hex>`",
            image.manifest_digest
        )
    })?;
    let manifest_size = std::fs::metadata(&manifest_path)
        .with_context(|| {
            format!(
                "manifest {} is not in the blob cache",
                image.manifest_digest
            )
        })?
        .len();
    let index = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": image.manifest_media_type(),
            "digest": image.manifest_digest,
            "size": manifest_size,
        }],
    })
    .to_string();

    append_data(&mut tar, "oci-layout", OCI_LAYOUT.as_bytes())?;
    append_data(&mut tar, "index.json", index.as_bytes())?;

    let mut blobs: Vec<&str> = vec![image.manifest_digest.as_str()];
    blobs.extend(image.config_digest());
    blobs.extend(image.layer_digests());
    for digest in blobs {
        let path = cache.path_of(digest).with_context(|| {
            format!(
                "blob digest {:?} is not `sha256:<64 lowercase hex>`",
                digest
            )
        })?;
        tar.append_path_with_name(&path, format!("blobs/sha256/{}", hex_of(digest)))
            .with_context(|| format!("blob {} is not in the blob cache", digest))?;
    }
    tar.finish()
        .with_context(|| format!("could not finish the image layout at {}", out.display()))
}

fn append_data<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    name: &str,
    data: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(&mut header, name, data)
        .with_context(|| format!("could not write {} into the image layout", name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::fetcher::{hex_sha256, BlobSources};
    use std::collections::BTreeMap;
    use std::io::Read;

    fn digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", hex_sha256(bytes))
    }

    #[tokio::test]
    async fn the_layout_holds_the_index_the_manifest_and_every_blob_from_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(dir.path().join("blobs"), None).unwrap();
        let config = br#"{"architecture":"amd64","os":"linux"}"#;
        let layer = b"not really a tar";
        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "digest": digest_of(config), "size": config.len() },
            "layers": [{ "digest": digest_of(layer), "size": layer.len() }],
        });
        let manifest_bytes = manifest.to_string().into_bytes();
        for (digest, bytes) in [
            (digest_of(config), config.as_slice()),
            (digest_of(layer), layer.as_slice()),
            (digest_of(&manifest_bytes), manifest_bytes.as_slice()),
        ] {
            cache.put(&digest, bytes).await.unwrap();
        }
        let image = ResolvedImage {
            manifest_digest: digest_of(&manifest_bytes),
            size_bytes: 0,
            manifest,
            sources: BlobSources::nowhere(),
        };
        let out = dir.path().join("image.tar");

        write_layout_tar(&cache, &image, &out).unwrap();

        let mut entries = BTreeMap::new();
        for entry in tar::Archive::new(std::fs::File::open(&out).unwrap())
            .entries()
            .unwrap()
        {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            entries.insert(name, bytes);
        }
        assert_eq!(entries["oci-layout"], OCI_LAYOUT.as_bytes());
        let index: serde_json::Value = serde_json::from_slice(&entries["index.json"]).unwrap();
        assert_eq!(index["manifests"][0]["digest"], digest_of(&manifest_bytes));
        assert_eq!(index["manifests"][0]["size"], manifest_bytes.len());
        assert_eq!(
            index["manifests"][0]["mediaType"],
            "application/vnd.oci.image.manifest.v1+json"
        );
        for (digest, bytes) in [
            (digest_of(config), config.as_slice()),
            (digest_of(layer), layer.as_slice()),
            (digest_of(&manifest_bytes), manifest_bytes.as_slice()),
        ] {
            assert_eq!(entries[&format!("blobs/sha256/{}", hex_of(&digest))], bytes);
        }
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn a_blob_missing_from_the_cache_fails_the_layout() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(dir.path().join("blobs"), None).unwrap();
        let image = ResolvedImage {
            manifest_digest: digest_of(b"never cached"),
            size_bytes: 0,
            manifest: json!({}),
            sources: BlobSources::nowhere(),
        };
        let err = write_layout_tar(&cache, &image, &dir.path().join("image.tar")).unwrap_err();
        assert!(
            err.to_string().contains("not in the blob cache"),
            "{:#}",
            err
        );
    }
}
