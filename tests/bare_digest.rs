//! An image named `{ digest }` alone (spec §6.2's third form), and the
//! fallthrough between sources that makes it work (§8.4, ADR 0006).
//!
//! A bare digest names no registry, no entry and no signer: every blob is
//! found by asking the provider's own Relay Set for the Blob Records tagged
//! `#x = <hex>`, whoever published them. That is safe because nothing is
//! trusted — each part is checked against its recorded sha256 and size and
//! each blob against the digest that was asked for — so a wrong record is
//! discarded and the next one tried.
//!
//! The order is the same for every blob whichever form named the image:
//! the local cache, then the source the image's own description names, then
//! the Relay Set. These tests drive it through the HTTP surface over
//! `common::store`'s world — `wiremock` gateway and registry, a faked
//! `Directory` holding the entries and the Blob Records — and assert on the
//! answers, on what the two servers were asked for and on what the
//! `Directory` was asked. Never on the provider's state.

mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use serde_json::json;

use common::harness::listing;
use common::store::*;
use common::{sha256_hex, BackendCall};
use toon_provider::nostr::image_events::{
    blob_record_event, BlobPage, BlobPart, BlobRecordContent,
};
use toon_provider::nostr::wire::ImageRef;

// ── the bare-digest form runs ───────────────────────────────────────────────

#[tokio::test]
async fn a_bare_digest_runs_from_blob_records_with_no_entry_and_no_reference() {
    let mut w = World::new().await;
    let (index, manifest, config, layer) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    // Nothing is seeded but the Blob Records: there is no Image Registry
    // entry for this image anywhere, and the spawn names no relay.
    seed_blob_records(&w, &h.directory);

    assert_eq!(
        availability(&h, bare_image(&index)).await,
        json!({ "would_run": true })
    );
    let (status, body, _) = spawn(&h, 0x11, ImageRef::by_digest(index.clone())).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], "11".repeat(32));
    assert_eq!(body["access"]["ports"][0]["container_port"], 443);
    // Every blob came from the store: the index, the manifest the index
    // chose for `amd64`, the config and the layer, each as its parts. Their
    // records are not read from the gateway at all — the Relay Set handed
    // them over as signed events, which is the whole of what step 3 buys.
    let mut expected = BTreeSet::new();
    for digest in [&index, &manifest, &config, &layer] {
        expected.extend(w.part_paths(digest));
    }
    assert_eq!(w.gateway_paths().await, expected);
    assert!(
        w.registry_paths().await.is_empty(),
        "a bare digest pulls from no upstream registry"
    );
    // The Relay Set was asked for each of them, and no relay was asked for
    // an Image Registry entry: there is none to ask for.
    let looked_up: BTreeSet<String> = h.directory.blob_record_lookups().into_iter().collect();
    assert_eq!(
        looked_up,
        BTreeSet::from([index.clone(), manifest.clone(), config, layer])
    );
    assert!(h.directory.entry_lookups().is_empty());
    // And it ran, exactly as the entry form does: the layout named after
    // the manifest the index chose was loaded, and the workload was started
    // by the id that load produced and by nothing else.
    let tar = format!("{}.oci.tar", manifest.strip_prefix("sha256:").unwrap());
    assert_eq!(
        h.backend.calls(),
        vec![
            BackendCall::LoadImage(tar.clone()),
            BackendCall::Create(1000),
            BackendCall::Start(1000)
        ]
    );
    assert_eq!(
        h.started_images(),
        vec![common::loaded_image_id(std::path::Path::new(&tar))]
    );
}

#[tokio::test]
async fn a_bare_digest_with_no_record_for_one_blob_is_refused_image_on_both_routes() {
    let mut w = World::new().await;
    let (index, manifest, config, layer) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    // Everything but the layer is on the Relay Set: the image can be
    // resolved and still can never be run.
    for digest in [&index, &manifest, &config] {
        h.directory.seed_blob_record(w.record(digest));
    }

    let body = availability(&h, bare_image(&index)).await;

    assert_refused(&body, &format!("no source is known for blob {}", layer));
    assert_refused(&body, "Relay Set holds no Blob Record for it");

    let (status, body, _) = spawn(&h, 0x21, ImageRef::by_digest(index)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"].as_str().unwrap().contains(&layer),
        "the refusal names the blob nothing can serve: {}",
        body
    );
    assert!(
        h.backend.calls().is_empty(),
        "nothing was loaded or started"
    );
    assert!(live_containers(&h.backend).await.is_empty());
}

// ── fallthrough between sources ─────────────────────────────────────────────

/// An image whose layer is stored TWICE: once as the upload the entry
/// cites, and once more under `label`, however each upload misbehaves.
/// Answers `(manifest digest, layer digest, the second record)`.
async fn image_with_a_second_record(
    w: &mut World,
    cited: Tamper,
    label: &str,
    second: Tamper,
) -> (String, String, nostr_sdk::Event) {
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    w.store_as(&layer_digest, &layer, LAYER, 1024, cited).await;
    let record = w
        .another_record(label, &layer_digest, &layer, 1024, second)
        .await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    (manifest_digest, layer_digest, record)
}

#[tokio::test]
async fn an_entry_record_whose_parts_fail_falls_through_to_one_on_the_relay_set() {
    let mut w = World::new().await;
    // The entry cites an upload whose third part does not hash to what the
    // record says; someone else published an honest record for the same
    // blob.
    let (manifest, layer, second) =
        image_with_a_second_record(&mut w, Tamper::CorruptPart(2), "second", Tamper::None).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&manifest, MANIFEST));
    h.directory.seed_blob_record(second);

    let (status, body, _) = spawn(
        &h,
        0x31,
        ImageRef::from_registry(manifest.clone(), w.address(), RELAY),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    // Both were tried, in §8.4's order: the entry's upload first, and the
    // Relay Set's only once that one failed.
    let paths = w.gateway_paths().await;
    assert!(
        paths.contains(&w.record_path(&layer)),
        "the entry's source was tried first, record and all: {:?}",
        paths
    );
    assert!(
        paths.is_superset(&w.part_paths_of("second").into_iter().collect()),
        "and the Relay Set's record served it: {:?}",
        paths
    );
    assert_eq!(
        h.directory.blob_record_lookups(),
        vec![layer],
        "only the blob the entry could not serve was looked up"
    );
    assert!(matches!(
        h.backend.calls().as_slice(),
        [
            BackendCall::LoadImage(_),
            BackendCall::Create(1000),
            BackendCall::Start(1000)
        ]
    ));
}

#[tokio::test]
async fn the_first_record_that_verifies_wins_and_the_second_is_never_fetched() {
    let mut w = World::new().await;
    // Two honest records for the layer on the Relay Set, and no entry: the
    // first the relay answers with is the one that serves.
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    let first = w
        .another_record("first", &layer_digest, &layer, 1024, Tamper::None)
        .await;
    let second = w
        .another_record("second", &layer_digest, &layer, 1024, Tamper::None)
        .await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_blob_record(w.record(&manifest_digest));
    h.directory.seed_blob_record(w.record(&config_digest));
    h.directory.seed_blob_record(first);
    h.directory.seed_blob_record(second);

    let (status, body, _) = spawn(&h, 0x41, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    let paths = w.gateway_paths().await;
    assert!(
        paths.is_superset(&w.part_paths_of("first").into_iter().collect()),
        "the first record served the blob: {:?}",
        paths
    );
    assert!(
        !paths.iter().any(|p| p.contains("second")),
        "the second was never read: {:?}",
        paths
    );
}

#[tokio::test]
async fn a_gateway_5xx_on_one_part_moves_that_blob_on_and_leaves_the_others_alone() {
    let mut w = World::new().await;
    // The record the entry cites is honest; the gateway simply will not
    // serve its second part.
    let (manifest, layer, second) =
        image_with_a_second_record(&mut w, Tamper::GatewayError(1), "second", Tamper::None).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&manifest, MANIFEST));
    h.directory.seed_blob_record(second);
    let config = w.blobs[0].digest.clone();

    let (status, body, _) = spawn(
        &h,
        0x51,
        ImageRef::from_registry(manifest.clone(), w.address(), RELAY),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    let requested = w.gateway_path_list().await;
    // The manifest and the config verified at the first source and were
    // never asked for again: the fallthrough is the failing blob's alone.
    for verified in [&manifest, &config] {
        for path in w.raw_paths(verified) {
            assert_eq!(
                requested.iter().filter(|p| **p == path).count(),
                1,
                "{} was fetched more than once: {:?}",
                path,
                requested
            );
        }
    }
    // The layer's failing source was tried and abandoned at the part the
    // gateway would not serve, and the next source served the whole blob.
    assert!(requested.contains(&w.part_path(&layer, 1)));
    assert!(
        !requested.contains(&w.part_path(&layer, 2)),
        "the failing source was abandoned at the part that failed: {:?}",
        requested
    );
    assert!(w
        .part_paths_of("second")
        .iter()
        .all(|p| requested.contains(p)));
}

// ── resolution order ────────────────────────────────────────────────────────

#[tokio::test]
async fn an_image_already_cached_contacts_neither_the_relay_nor_a_gateway() {
    let mut w = World::new().await;
    let (index, ..) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    seed_blob_records(&w, &h.directory);
    let (status, body, _) = spawn(&h, 0x61, ImageRef::by_digest(index.clone())).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let gateway_before = w.gateway_request_count().await;
    let lookups_before = h.directory.blob_record_lookups().len();

    // A second spawn of the same image, and an availability check of it.
    assert_eq!(
        availability(&h, bare_image(&index)).await,
        json!({ "would_run": true })
    );
    let (status, body, _) = spawn(&h, 0x62, ImageRef::by_digest(index)).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        w.gateway_request_count().await,
        gateway_before,
        "every blob was in the cache: no gateway read"
    );
    assert_eq!(
        h.directory.blob_record_lookups().len(),
        lookups_before,
        "and the Relay Set was not asked either"
    );
    assert_eq!(h.started_images().len(), 2, "both workloads run");
}

#[tokio::test]
async fn the_entrys_source_is_used_and_the_relay_set_is_never_asked() {
    let mut w = World::new().await;
    // The image is fully described by its entry AND fully on the Relay Set:
    // either could serve it, and §8.4 says the entry's source comes first.
    let (manifest, ..) = {
        let config = config_bytes();
        let config_digest = w.store(&config, CONFIG, 64).await;
        let layer = layer_bytes(7);
        let layer_digest = w.store(&layer, LAYER, 1024).await;
        let manifest = manifest_bytes(
            (&config_digest, config.len()),
            &[(layer_digest.clone(), layer.len())],
        );
        let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
        (manifest_digest, config_digest, layer_digest)
    };
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&manifest, MANIFEST));
    seed_blob_records(&w, &h.directory);

    let (status, body, _) = spawn(
        &h,
        0x71,
        ImageRef::from_registry(manifest, w.address(), RELAY),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        h.directory.blob_record_lookups(),
        Vec::<String>::new(),
        "the entry named a source for every blob, so step 3 was never reached"
    );
    assert_eq!(
        h.directory.entry_lookups(),
        vec![(w.address(), RELAY.to_string())]
    );
}

#[tokio::test]
async fn a_relay_record_whose_parts_fail_falls_through_to_the_next_relay_record() {
    let mut w = World::new().await;
    // Two records for the layer on the Relay Set and no entry at all: the
    // first one the relay answers with lies about its second part, and the
    // second is honest. Fallthrough WITHIN step 3, which is what makes a
    // wrong record from any signer harmless (ADR 0006).
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    let lying = w
        .another_record("lying", &layer_digest, &layer, 1024, Tamper::CorruptPart(1))
        .await;
    let honest = w
        .another_record("honest", &layer_digest, &layer, 1024, Tamper::None)
        .await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_blob_record(w.record(&manifest_digest));
    h.directory.seed_blob_record(w.record(&config_digest));
    h.directory.seed_blob_record(lying);
    h.directory.seed_blob_record(honest);

    let (status, body, _) = spawn(&h, 0x81, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    let paths = w.gateway_paths().await;
    assert!(
        paths.contains("/raw/lying-part1"),
        "the lying record was tried and failed at its bad part: {:?}",
        paths
    );
    assert!(
        paths.is_superset(&w.part_paths_of("honest").into_iter().collect()),
        "and the next record on the Relay Set served the blob: {:?}",
        paths
    );
}

#[tokio::test]
async fn an_upstream_registry_that_refuses_falls_through_to_the_relay_set() {
    let mut w = World::new().await;
    // The entry says the layer is public upstream. The registry has never
    // heard of it — and a Blob Record on the Relay Set has.
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    w.list_unserved_upstream(&layer_digest, layer.len() as u64, LAYER);
    let rescue = w
        .another_record("rescue", &layer_digest, &layer, 1024, Tamper::None)
        .await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));
    h.directory.seed_blob_record(rescue);

    let (status, body, _) = spawn(
        &h,
        0x91,
        ImageRef::from_registry(manifest_digest, w.address(), RELAY),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        w.registry_paths().await,
        vec![format!("/v2/{}/blobs/{}", REPOSITORY, layer_digest)],
        "the entry's `oci` source was tried, by digest"
    );
    assert!(
        w.gateway_paths()
            .await
            .is_superset(&w.part_paths_of("rescue").into_iter().collect()),
        "and the Relay Set served what upstream would not"
    );
}

#[tokio::test]
async fn an_upstream_reference_never_reaches_the_relay_set() {
    // §6.2's `{ reference, digest }` is "No Image Registry lookup at all",
    // so a registry that will not serve the image is the end of the chain:
    // this provider does not go looking for someone else's copy of it, even
    // with a Relay Set to look in. `refused_image`, and no Directory read.
    let mut w = World::new().await;
    let (_, manifest, ..) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    seed_blob_records(&w, &h.directory);

    let body = availability(
        &h,
        json!({ "reference": "docker.io/library/alpine", "digest": manifest }),
    )
    .await;

    assert_refused(&body, "no source could serve blob");
    assert!(
        h.directory.blob_record_lookups().is_empty(),
        "the Relay Set was searched for an upstream reference: {:?}",
        h.directory.blob_record_lookups()
    );
    assert!(h.directory.reads().is_empty());
}

// ── paged Blob Records (§8.2, §11 item 2) ───────────────────────────────────

#[tokio::test]
async fn a_paged_layer_resolves_to_the_same_bytes_as_inline_parts() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    // Five parts at 1024 bytes, grouped two at a time into three pages.
    let layer_digest = w.store_paged(&layer, LAYER, 1024, 2).await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    seed_blob_records(&w, &h.directory);

    assert_eq!(
        availability(&h, bare_image(&manifest_digest)).await,
        json!({ "would_run": true })
    );
    let (status, body, _) = spawn(&h, 0xb1, ImageRef::by_digest(manifest_digest.clone())).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    // Every page was fetched and digest-checked, and every part a page
    // named was fetched after it — the same bytes an inline record would
    // have taken, one level of indirection deeper. No record was fetched
    // from the gateway at all: like an inline record found this way, the
    // Relay Set handed it over as a signed event (§8.4 step 3).
    let mut expected = BTreeSet::new();
    expected.extend(w.page_paths(&layer_digest));
    expected.extend(w.part_paths(&layer_digest));
    expected.extend(w.part_paths(&config_digest));
    expected.extend(w.part_paths(&manifest_digest));
    assert_eq!(w.gateway_paths().await, expected);
}

#[tokio::test]
async fn a_page_that_does_not_hash_to_its_record_is_refused_image() {
    // A layer's bytes are not fetched for `availability` at all (only
    // checked for a CANDIDATE, spec §6.4) — so a bad page is caught only
    // once something actually asks to run it, exactly as a bad PART is
    // (`tests/registry_image.rs` corrupts a part of the CONFIG instead, for
    // the same reason: config is what `availability` really fetches).
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(5);
    let layer_digest = digest_of(&layer);
    w.store_paged_as(
        &layer_digest,
        &layer,
        LAYER,
        1024,
        2,
        Tamper::CorruptPage(0),
    )
    .await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    seed_blob_records(&w, &h.directory);

    let (status, body, _) = spawn(&h, 0xb5, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"].as_str().unwrap().contains("hashes to"),
        "{}",
        body
    );
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_page_that_cannot_be_fetched_falls_through_to_the_next_relay_record() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    // The first record's second page is a store that will not serve it; a
    // second, honest, inline record for the same blob is on the Relay Set
    // too.
    let lying = w
        .another_paged_record(
            "lying",
            &layer_digest,
            &layer,
            1024,
            2,
            Tamper::PageGatewayError(1),
        )
        .await;
    let honest = w
        .another_record("honest", &layer_digest, &layer, 1024, Tamper::None)
        .await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_blob_record(w.record(&manifest_digest));
    h.directory.seed_blob_record(w.record(&config_digest));
    h.directory.seed_blob_record(lying);
    h.directory.seed_blob_record(honest);

    let (status, body, _) = spawn(&h, 0xb2, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    let paths = w.gateway_paths().await;
    assert!(
        paths.contains("/raw/lying-page0"),
        "the first page of the failing record was tried: {:?}",
        paths
    );
    assert!(
        !paths.iter().any(|p| p.contains("lying-part")),
        "no part was ever fetched on the failing record's account: {:?}",
        paths
    );
    assert!(
        paths.is_superset(&w.part_paths_of("honest").into_iter().collect()),
        "and the next record on the Relay Set served the blob: {:?}",
        paths
    );
}

#[tokio::test]
async fn a_relay_record_with_both_parts_and_pages_fails_that_source_and_the_chain_continues() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    let honest = w
        .another_record("honest", &layer_digest, &layer, 1024, Tamper::None)
        .await;
    // A second record for the same blob carrying BOTH `parts` and `pages`
    // (spec §8.2, §11 item 2's one-of rule): unreadable, so it never
    // becomes a candidate at all and its own txids are never fetched.
    let both_forms = BlobRecordContent {
        digest: layer_digest.clone(),
        size: layer.len() as u64,
        part_size: 1024,
        parts: Some(vec![BlobPart {
            txid: "both-forms-unused-part".to_string(),
            sha256: sha256_hex(&layer),
            size: layer.len() as u64,
        }]),
        pages: Some(vec![BlobPage {
            txid: "both-forms-unused-page".to_string(),
            sha256: sha256_hex(&layer),
            parts: 1,
        }]),
    };
    let both_forms_event = blob_record_event(&both_forms, &w.publisher, NOW).unwrap();
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_blob_record(w.record(&manifest_digest));
    h.directory.seed_blob_record(w.record(&config_digest));
    h.directory.seed_blob_record(both_forms_event);
    h.directory.seed_blob_record(honest);

    let (status, body, _) = spawn(&h, 0xb3, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert!(
        w.gateway_paths()
            .await
            .iter()
            .all(|p| !p.contains("both-forms")),
        "the invalid record's own txids were never fetched: {:?}",
        w.gateway_paths().await
    );
}

#[tokio::test]
async fn a_relay_record_with_neither_parts_nor_pages_fails_that_source_and_the_chain_continues() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    let honest = w
        .another_record("honest", &layer_digest, &layer, 1024, Tamper::None)
        .await;
    // A second record for the same blob carrying NEITHER `parts` nor
    // `pages`: just as unreadable as carrying both.
    let neither = BlobRecordContent {
        digest: layer_digest.clone(),
        size: layer.len() as u64,
        part_size: 1024,
        parts: None,
        pages: None,
    };
    let neither_event = blob_record_event(&neither, &w.publisher, NOW).unwrap();
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_blob_record(w.record(&manifest_digest));
    h.directory.seed_blob_record(w.record(&config_digest));
    h.directory.seed_blob_record(neither_event);
    h.directory.seed_blob_record(honest);

    let (status, body, _) = spawn(&h, 0xb4, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
}

// ── bounded fetches: a malicious Blob Record cannot crash a provider or
// exhaust its memory (§8.4, TOON_Network#79) ────────────────────────────────

#[tokio::test]
async fn a_records_size_that_disagrees_with_its_parts_total_fails_before_any_part_is_fetched() {
    // The record's own `size` is honest; a single part's recorded size
    // lies by one byte, so the two no longer agree. `availability` fetches
    // CONFIG for free (spec §6.4), the same reachability
    // `tests/registry_image.rs`'s part-size tests use.
    let mut w = World::new().await;
    let bad_config = config_bytes();
    let bad_config_digest = digest_of(&bad_config);
    w.store_as(
        &bad_config_digest,
        &bad_config,
        CONFIG,
        64,
        Tamper::WrongPartSize(0),
    )
    .await;
    let layer = layer_bytes(3);
    let layer_digest = w.store(&layer, LAYER, 1024).await;
    let manifest = manifest_bytes(
        (&bad_config_digest, bad_config.len()),
        &[(layer_digest, layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    seed_blob_records(&w, &h.directory);

    let body = availability(&h, bare_image(&manifest_digest)).await;

    assert_refused(&body, "declares size");
    let requested = w.gateway_paths().await;
    for part_path in w.part_paths(&bad_config_digest) {
        assert!(
            !requested.contains(&part_path),
            "a part was fetched despite the record's own size disagreeing with its parts: {:?}",
            requested
        );
    }
}

#[tokio::test]
async fn a_records_absurd_size_is_refused_without_a_large_allocation_and_the_provider_keeps_serving(
) {
    // The record's `size` alone is a lie — far beyond any real image and
    // beyond this provider's (unconfigured, so default) limit. The parts
    // it lists are entirely honest and never need to be fetched to catch
    // this. Its own bytes are distinct from `store_whole_image`'s fixed
    // config, so the honest record that call stores later cannot collide
    // with — and silently overwrite — this one's digest.
    let mut w = World::new().await;
    let bad_config = layer_bytes(201);
    let bad_config_digest = digest_of(&bad_config);
    w.store_as(
        &bad_config_digest,
        &bad_config,
        CONFIG,
        64,
        Tamper::AbsurdSize,
    )
    .await;
    let bad_layer = layer_bytes(3);
    let bad_layer_digest = w.store(&bad_layer, LAYER, 1024).await;
    let bad_manifest = manifest_bytes(
        (&bad_config_digest, bad_config.len()),
        &[(bad_layer_digest, bad_layer.len())],
    );
    let bad_manifest_digest = w.store(&bad_manifest, MANIFEST, 100).await;
    // An honest image, stored on the same world, so a request for it right
    // after the malicious one proves the provider is still answering.
    let (good_index, ..) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    seed_blob_records(&w, &h.directory);

    let body = availability(&h, bare_image(&bad_manifest_digest)).await;

    assert_refused(&body, "exceeds this provider's limit");
    assert_eq!(
        availability(&h, bare_image(&good_index)).await,
        json!({ "would_run": true }),
        "an absurd `size` cost the provider nothing it cannot recover from"
    );
    let (status, body, _) = spawn(&h, 0xc1, ImageRef::by_digest(good_index)).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

#[tokio::test]
async fn an_oversize_part_body_is_cut_off_and_the_provider_keeps_serving() {
    // The store (or something in front of it) serves far more than the
    // CONFIG part's own recorded size. A fetch MUST stop reading at that
    // size rather than buffer all of it. Distinct bytes from
    // `store_whole_image`'s fixed config, for the same reason as above.
    let mut w = World::new().await;
    let bad_config = layer_bytes(202);
    let bad_config_digest = digest_of(&bad_config);
    w.store_as(
        &bad_config_digest,
        &bad_config,
        CONFIG,
        64,
        Tamper::OversizePart(0),
    )
    .await;
    let bad_layer = layer_bytes(3);
    let bad_layer_digest = w.store(&bad_layer, LAYER, 1024).await;
    let bad_manifest = manifest_bytes(
        (&bad_config_digest, bad_config.len()),
        &[(bad_layer_digest, bad_layer.len())],
    );
    let bad_manifest_digest = w.store(&bad_manifest, MANIFEST, 100).await;
    let (good_index, ..) = store_whole_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    seed_blob_records(&w, &h.directory);

    let body = availability(&h, bare_image(&bad_manifest_digest)).await;

    assert_refused(&body, "longer than");
    assert_eq!(
        availability(&h, bare_image(&good_index)).await,
        json!({ "would_run": true }),
        "an oversize body cost the provider nothing it cannot recover from"
    );
}

#[tokio::test]
async fn a_paged_page_body_over_the_ceiling_is_cut_off_and_the_source_fails() {
    // A layer's bytes are not fetched for `availability` (only checked for
    // a candidate, spec §6.4), so — like a bad page's hash
    // (`a_page_that_does_not_hash_to_its_record_is_refused_image` above) —
    // this is only caught once something actually asks to run it.
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(5);
    let layer_digest = digest_of(&layer);
    w.store_paged_as(
        &layer_digest,
        &layer,
        LAYER,
        1024,
        2,
        Tamper::OversizePage(0),
    )
    .await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    seed_blob_records(&w, &h.directory);

    let (status, body, _) = spawn(&h, 0xc2, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"].as_str().unwrap().contains("longer than"),
        "{}",
        body
    );
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_paged_records_page_count_beyond_what_size_and_part_size_imply_is_refused_before_any_page_is_fetched(
) {
    // 5000 bytes at part_size 1024 is 5 real parts (§8.2: `part_size` is
    // every part's size but the last's). A record claiming SIX pages,
    // however small each looks, cannot be honest — and that is knowable
    // from the record's own numbers, with no page fetched (TOON_Network
    // #79).
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(11);
    let layer_digest = digest_of(&layer);
    let lying = BlobRecordContent {
        digest: layer_digest.clone(),
        size: layer.len() as u64,
        part_size: 1024,
        parts: None,
        pages: Some(
            (0..6)
                .map(|i| BlobPage {
                    txid: format!("unused-page{}", i),
                    sha256: "0".repeat(64),
                    parts: 1,
                })
                .collect(),
        ),
    };
    let lying_event = blob_record_event(&lying, &w.publisher, NOW).unwrap();
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_blob_record(w.record(&manifest_digest));
    h.directory.seed_blob_record(w.record(&config_digest));
    h.directory.seed_blob_record(lying_event);

    let (status, body, _) = spawn(&h, 0xc3, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"].as_str().unwrap().contains("more than"),
        "{}",
        body
    );
    assert!(
        !w.gateway_paths()
            .await
            .iter()
            .any(|p| p.contains("unused-page")),
        "no page of the lying record was ever fetched: {:?}",
        w.gateway_paths().await
    );
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_page_declaring_zero_parts_is_refused_before_any_page_is_fetched() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(13);
    let layer_digest = digest_of(&layer);
    let lying = BlobRecordContent {
        digest: layer_digest.clone(),
        size: layer.len() as u64,
        part_size: 1024,
        parts: None,
        pages: Some(vec![BlobPage {
            txid: "unused-page0".to_string(),
            sha256: "0".repeat(64),
            parts: 0,
        }]),
    };
    let lying_event = blob_record_event(&lying, &w.publisher, NOW).unwrap();
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_blob_record(w.record(&manifest_digest));
    h.directory.seed_blob_record(w.record(&config_digest));
    h.directory.seed_blob_record(lying_event);

    let (status, body, _) = spawn(&h, 0xc4, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("declares 0 parts"),
        "{}",
        body
    );
    assert!(
        !w.gateway_paths()
            .await
            .iter()
            .any(|p| p.contains("unused-page")),
        "no page of the lying record was ever fetched: {:?}",
        w.gateway_paths().await
    );
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn an_inline_records_part_count_disagreeing_with_size_and_part_size_is_refused_before_any_part_is_fetched(
) {
    // The record's `size` and `part_size` imply 5 parts (5000 bytes at
    // 1024); an extra, entirely honest-looking part is appended anyway —
    // caught by count alone, before any part (including the honest ones)
    // is fetched.
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(17);
    let layer_digest = digest_of(&layer);
    let lying = BlobRecordContent {
        digest: layer_digest.clone(),
        size: layer.len() as u64,
        part_size: 1024,
        parts: Some(vec![BlobPart {
            txid: "unused-part-extra".to_string(),
            sha256: "0".repeat(64),
            size: 0,
        }]),
        pages: None,
    };
    let lying_event = blob_record_event(&lying, &w.publisher, NOW).unwrap();
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_blob_record(w.record(&manifest_digest));
    h.directory.seed_blob_record(w.record(&config_digest));
    h.directory.seed_blob_record(lying_event);

    let (status, body, _) = spawn(&h, 0xc5, ImageRef::by_digest(manifest_digest)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"].as_str().unwrap().contains("imply"),
        "{}",
        body
    );
    assert!(
        !w.gateway_paths()
            .await
            .iter()
            .any(|p| p.contains("unused-part")),
        "no part of the lying record was ever fetched: {:?}",
        w.gateway_paths().await
    );
    assert!(h.backend.calls().is_empty());
}
