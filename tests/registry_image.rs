//! An image named `{ digest, registry_entry }` (spec §6.2), resolved through
//! its Image Registry entry (§8.1, §8.4) on the free `availability` route.
//!
//! The world is `common::store`'s: a faked `Directory` holding the entry, a
//! `wiremock` gateway serving Blob Records and parts at `/raw/<txid>` (the
//! TOON store as a provider reads it), and a `wiremock` upstream registry.
//! Every assertion is on the HTTP answer and on the requests those two
//! servers saw: never on the provider's state. What a paid spawn does with
//! such an image is `tests/registry_spawn.rs`.

mod common;

use std::collections::BTreeSet;

use serde_json::json;

use common::harness::listing;
use common::store::*;
use common::{FakeBackend, FakeClock, FakeDirectory};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::{router, ProviderConfig, ProviderService};

// ── availability through the entry ─────────────────────────────────────────

#[tokio::test]
async fn availability_resolves_an_all_store_image_fetching_only_what_resolution_needs() {
    let mut w = World::new().await;
    let (index, manifest, config, layer) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&index, INDEX));

    let body = availability(&h, registry_image(&w, &index)).await;

    assert_eq!(body, json!({ "would_run": true }));
    // The index, the manifest and the config came from the store — each as
    // its record plus every part — and the layer was never touched.
    let mut expected = BTreeSet::new();
    expected.extend(w.raw_paths(&index));
    expected.extend(w.raw_paths(&manifest));
    expected.extend(w.raw_paths(&config));
    assert_eq!(w.gateway_paths().await, expected);
    assert!(
        !w.gateway_paths()
            .await
            .iter()
            .any(|p| p.contains(&layer.strip_prefix("sha256:").unwrap()[..12])),
        "a layer is never fetched for availability"
    );
    assert!(
        w.registry_paths().await.is_empty(),
        "no upstream was needed"
    );
    assert_eq!(
        h.directory.entry_lookups(),
        vec![(w.address(), RELAY.to_string())],
        "the entry was read from the relay the spawn hinted at"
    );
    assert!(h.backend.calls().is_empty(), "availability starts nothing");
}

#[tokio::test]
async fn a_repeated_availability_is_served_from_the_cache() {
    let mut w = World::new().await;
    let (index, ..) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&index, INDEX));

    availability(&h, registry_image(&w, &index)).await;
    let after_first = w.gateway_request_count().await;
    let body = availability(&h, registry_image(&w, &index)).await;

    assert_eq!(body, json!({ "would_run": true }));
    assert_eq!(
        w.gateway_request_count().await,
        after_first,
        "verified blobs are cached; the second check reads nothing from the store"
    );
}

#[tokio::test]
async fn an_oci_sourced_manifest_is_fetched_by_digest_from_the_upstream_registry() {
    let mut w = World::new().await;
    let config = config_bytes();
    let layer = layer_bytes(3);
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer_digest = w.store(&layer, LAYER, 1024).await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest, layer.len())],
    );
    // The manifest is public upstream: the entry says so, and the provider
    // pulls it by digest from the registry the entry names.
    let manifest_digest = w.upstream(&manifest, MANIFEST).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    let body = availability(&h, registry_image(&w, &manifest_digest)).await;

    assert_eq!(body, json!({ "would_run": true }));
    assert_eq!(
        w.registry_paths().await,
        vec![format!("/v2/{}/manifests/{}", REPOSITORY, manifest_digest)]
    );
    let expected: BTreeSet<String> = w.raw_paths(&config_digest).into_iter().collect();
    assert_eq!(
        w.gateway_paths().await,
        expected,
        "only the config came from the store"
    );
}

#[tokio::test]
async fn an_oversize_oci_blob_body_is_cut_off_and_the_provider_keeps_serving() {
    // The registry serves far more than the entry's own declared size for
    // the config blob (TOON_Network#79) — a fetch MUST stop reading at
    // that size rather than buffer all of it.
    let mut w = World::new().await;
    let config = layer_bytes(210);
    let config_digest = w.upstream_oversize(&config, CONFIG, 8 * 1024 * 1024).await;
    let layer = layer_bytes(3);
    let layer_digest = w.store(&layer, LAYER, 1024).await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest, layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    let body = availability(&h, registry_image(&w, &manifest_digest)).await;

    assert_refused(&body, "longer than");

    // The provider survived reading a body far larger than the descriptor
    // it was told to expect, and keeps answering: an honest image resolves
    // normally right after, on the very same process.
    let (good_index, ..) = store_whole_image(&mut w).await;
    seed_blob_records(&w, &h.directory);
    assert_eq!(
        availability(&h, bare_image(&good_index)).await,
        json!({ "would_run": true }),
        "an oversize registry body cost the provider nothing it cannot recover from"
    );
}

#[tokio::test]
async fn an_oversize_oci_manifest_body_is_cut_off_and_the_provider_keeps_serving() {
    // Nothing describes a size for a manifest or an index ahead of
    // fetching it, so this is bounded by a fixed JSON ceiling rather than
    // a declared size (TOON_Network#79) — the registry here serves a body
    // far longer than that ceiling.
    let mut w = World::new().await;
    let config = layer_bytes(211);
    let config_digest = digest_of(&config);
    let layer = layer_bytes(4);
    let layer_digest = digest_of(&layer);
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest, layer.len())],
    );
    let manifest_digest = w
        .upstream_oversize(&manifest, MANIFEST, 17 * 1024 * 1024)
        .await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    let body = availability(&h, registry_image(&w, &manifest_digest)).await;

    assert_refused(&body, "longer than");
    assert!(
        w.gateway_paths().await.is_empty(),
        "the manifest fetch failed before any blob it names was ever reached: {:?}",
        w.gateway_paths().await
    );

    let (good_index, ..) = store_whole_image(&mut w).await;
    seed_blob_records(&w, &h.directory);
    assert_eq!(
        availability(&h, bare_image(&good_index)).await,
        json!({ "would_run": true }),
        "an oversize registry body cost the provider nothing it cannot recover from"
    );
}

#[tokio::test]
async fn a_part_that_does_not_hash_to_its_record_is_refused_image() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = digest_of(&config);
    w.store_as(&config_digest, &config, CONFIG, 64, Tamper::CorruptPart(1))
        .await;
    let layer = layer_bytes(5);
    let layer_digest = w.store(&layer, LAYER, 1024).await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest, layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    let body = availability(&h, registry_image(&w, &manifest_digest)).await;

    assert_refused(&body, "hashes to");
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_part_whose_size_differs_from_its_record_is_refused_image() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = digest_of(&config);
    w.store_as(
        &config_digest,
        &config,
        CONFIG,
        64,
        Tamper::WrongPartSize(0),
    )
    .await;
    let layer = layer_bytes(5);
    let layer_digest = w.store(&layer, LAYER, 1024).await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest, layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    let body = availability(&h, registry_image(&w, &manifest_digest)).await;

    // A part's declared size one byte off throws the record's own declared
    // `size` and its parts' total out of agreement — caught by that upfront
    // check (TOON_Network#79) before any part is fetched, rather than by
    // comparing a fetched part's length afterwards.
    assert_refused(&body, "declares size");
}

#[tokio::test]
async fn a_reassembled_blob_that_does_not_hash_to_its_digest_is_refused_image() {
    // Every part is exactly what the record says, and the record still
    // lies: the whole does not hash to the digest the entry (and the
    // record) claim. The blob is discarded on the whole-blob check.
    let mut w = World::new().await;
    let real_config = config_bytes();
    let claimed = digest_of(b"a config that was never uploaded");
    w.store_as(&claimed, &real_config, CONFIG, 64, Tamper::None)
        .await;
    let layer = layer_bytes(5);
    let layer_digest = w.store(&layer, LAYER, 1024).await;
    let manifest = manifest_bytes(
        (&claimed, real_config.len()),
        &[(layer_digest, layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    let body = availability(&h, registry_image(&w, &manifest_digest)).await;

    assert_refused(&body, "digest mismatch");
}

#[tokio::test]
async fn an_index_with_no_manifest_for_the_listings_arch_is_no_matching_arch() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let manifest = manifest_bytes((&config_digest, config.len()), &[]);
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let index = index_bytes(&[("arm64", &manifest_digest, manifest.len())]);
    let index_digest = w.store(&index, INDEX, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&index_digest, INDEX));

    let body = availability(&h, registry_image(&w, &index_digest)).await;

    assert_eq!(body["would_run"], false);
    assert_eq!(body["error"], "no_matching_arch", "{}", body);
    // Only the index was needed to know.
    let expected: BTreeSet<String> = w.raw_paths(&index_digest).into_iter().collect();
    assert_eq!(w.gateway_paths().await, expected);
}

#[tokio::test]
async fn an_entry_that_omits_a_blob_the_manifest_needs_is_refused_image() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    // The layer exists nowhere at all: the manifest names it, the entry
    // does not list it (§8.1 says it must) and no relay in this provider's
    // Relay Set holds a Blob Record for it either. Refused on the free
    // route, before a tenant pays to find out.
    let layer = layer_bytes(9);
    let layer_digest = digest_of(&layer);
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    let body = availability(&h, registry_image(&w, &manifest_digest)).await;

    assert_refused(
        &body,
        &format!("no source is known for blob {}", layer_digest),
    );
    assert_refused(&body, "the Image Registry entry web:1.0 does not list it");
    assert_eq!(
        h.directory.blob_record_lookups(),
        vec![layer_digest],
        "the entry named no source for it, so the Relay Set was asked — and had none"
    );
}

#[tokio::test]
async fn a_relay_hint_that_holds_no_entry_is_refused_image() {
    let mut w = World::new().await;
    let (index, ..) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    // Nothing seeded: the relay the spawn named has never seen the entry.

    let body = availability(&h, registry_image(&w, &index)).await;

    assert_refused(&body, "no Image Registry entry");
    assert_eq!(
        h.directory.entry_lookups(),
        vec![(w.address(), RELAY.to_string())]
    );
    assert_eq!(
        w.gateway_request_count().await,
        0,
        "nothing was fetched without an entry"
    );
}

#[tokio::test]
async fn an_entry_naming_a_different_image_is_refused_image() {
    let mut w = World::new().await;
    let (index, manifest, ..) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    // The entry at the address is for the index; the spawn names the
    // manifest with it. The entry is not a description of that image.
    h.directory.seed_image_entry(w.entry(&index, INDEX));

    let body = availability(&h, registry_image(&w, &manifest)).await;

    assert_refused(&body, &format!("names image {}, not {}", index, manifest));
    assert_eq!(w.gateway_request_count().await, 0);
}

#[tokio::test]
async fn the_image_policy_applies_to_what_the_entry_resolved() {
    let mut w = World::new().await;
    let (index, manifest, ..) = store_whole_image(&mut w).await;
    // The same harness with a policy denying the per-arch manifest the
    // index resolves to, and a size cap smaller than the layer.
    let mut config = ProviderConfig {
        image_policy: ImagePolicyConfig {
            deny_digests: vec![manifest.clone()],
            registry_url_override: Some(w.registry.uri()),
            ..Default::default()
        },
        ..store_config(&w, vec![listing("basic", 1, 2)])
    };
    let directory = FakeDirectory::new();
    directory.seed_image_entry(w.entry(&index, INDEX));
    let app = |config: ProviderConfig| {
        router(
            ProviderService::with_backend_clock_and_directory(
                config,
                FakeBackend::new(),
                FakeClock::at(NOW),
                directory.clone(),
            )
            .unwrap()
            .app_state(),
        )
    };

    let (_, body) = post(
        &app(config.clone()),
        "/availability",
        json!({ "listing": "basic", "version": 1, "image": registry_image(&w, &index) }),
    )
    .await;
    assert_refused(&body, "denied by this provider's image policy");

    config.image_policy.deny_digests.clear();
    config.image_policy.max_image_bytes = Some(1000);
    let (_, body) = post(
        &app(config),
        "/availability",
        json!({ "listing": "basic", "version": 1, "image": registry_image(&w, &index) }),
    )
    .await;
    assert_refused(&body, "max_image_bytes");
}

// ── TOON_Network#104: a manifest's own digests are checked too ──────────────

#[tokio::test]
async fn a_manifests_config_digest_naming_a_traversal_is_refused_through_the_entry_too() {
    // The same attack as the bare-digest form's proof
    // (`tests/bare_digest.rs`), but through an Image Registry entry: the
    // entry itself is honest (it lists only the manifest's own, real
    // digest), and the traversal lives inside the manifest bytes it
    // points to — bytes a publisher fully controls. Before this ticket,
    // this manifest's config digest would have been handed straight to
    // `BlobCache::path_of`; now the manifest read itself refuses it.
    //
    // The cache lives at `<dir>/blobs`, one blob per file at
    // `<dir>/blobs/sha256/<hex>` — so `../../canary.txt`, stripped of its
    // `sha256:` prefix and joined there, walks back up through `sha256/`
    // and `blobs/` to `<dir>/canary.txt` exactly: not a made-up path, the
    // real one `BlobCache::path_of` used to build unchecked.
    let mut w = World::new().await;
    let traversal = "sha256:../../canary.txt";
    let manifest = manifest_bytes((traversal, 4), &[]);
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    // The file the traversal digest above resolves to: beside the cache
    // directory itself, not inside it.
    let canary = h
        .config
        .blob_cache_dir()
        .parent()
        .unwrap()
        .join("canary.txt")
        .to_path_buf();
    std::fs::write(&canary, b"do not touch me").unwrap();

    let body = availability(&h, registry_image(&w, &manifest_digest)).await;

    assert_refused(&body, "sha256:<64 lowercase hex>");
    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"do not touch me",
        "the file beside the cache directory was never read, probed or deleted"
    );
}
