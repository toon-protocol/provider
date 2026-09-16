//! A paid spawn of an image named `{ digest, registry_entry }` (spec §6.2):
//! every layer fetched through the entry's sources, verified, cached on
//! disk across leases and restarts, assembled into an OCI layout and loaded
//! into the backend, and the workload run by the id the load produced —
//! never by a tag (§8.4, ADR 0006).
//!
//! Over `common::store`'s world — a gateway and a registry stubbed with
//! `wiremock`, a faked `Directory` holding the entry — and a faked backend
//! that records what it was told to load and run. Assertions are on the
//! HTTP answers, on the requests the two servers saw and on what the
//! backend was asked; never on the provider's state. The same spawn
//! against a real Docker daemon is `tests/registry_spawn_docker.rs`.

mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use nostr_sdk::Keys;
use serde_json::{json, Value};

use common::harness::{listing, INTERVAL};
use common::store::*;
use common::{loaded_image_id, BackendCall};
use toon_provider::nostr::wire::ImageRef;
use toon_provider::Clock;

/// An image whose layers are one `toon-store` blob and one `oci` blob, with
/// its config and manifest in the store. Answers `(manifest digest,
/// stored layer digest, upstream layer digest)`.
async fn store_mixed_image(w: &mut World) -> (String, String, String) {
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let stored = layer_bytes(7);
    let stored_digest = w.store(&stored, LAYER, 1024).await;
    let upstream = layer_bytes(11);
    let upstream_digest = w.upstream(&upstream, LAYER).await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[
            (stored_digest.clone(), stored.len()),
            (upstream_digest.clone(), upstream.len()),
        ],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    (manifest_digest, stored_digest, upstream_digest)
}

fn image(w: &World, digest: &str) -> ImageRef {
    ImageRef::from_registry(digest.to_string(), w.address(), RELAY)
}

fn layout_name(manifest_digest: &str) -> String {
    format!(
        "{}.oci.tar",
        manifest_digest.strip_prefix("sha256:").unwrap()
    )
}

fn assert_ok_spawn(status: StatusCode, body: &Value, seed: u8) {
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], format!("{:02x}", seed).repeat(32));
    assert_eq!(body["role"], "standalone");
    assert_eq!(body["expires_at"], NOW + INTERVAL);
    assert_eq!(body["access"]["host"], "203.0.113.7");
    assert!(body["access"]["ssh_port"].is_u64(), "{}", body);
    assert_eq!(body["access"]["ports"][0]["container_port"], 443);
}

#[tokio::test]
async fn a_paid_spawn_fetches_every_layer_through_the_entry_and_runs_the_loaded_image() {
    let mut w = World::new().await;
    let (manifest, stored, upstream) = store_mixed_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&manifest, MANIFEST));
    assert_eq!(
        availability(&h, registry_image(&w, &manifest)).await,
        json!({ "would_run": true })
    );

    let (status, body) = spawn(&h, 0x11, image(&w, &manifest)).await;

    assert_ok_spawn(status, &body, 0x11);
    // Every blob came from where the entry said: the manifest, the config
    // and one layer from the store (record + parts each), the other layer
    // from the upstream registry, by digest.
    let mut expected = BTreeSet::new();
    expected.extend(w.raw_paths(&manifest));
    expected.extend(w.raw_paths(&w.blobs[0].digest.clone()));
    expected.extend(w.raw_paths(&stored));
    assert_eq!(w.gateway_paths().await, expected);
    assert_eq!(
        w.registry_paths().await,
        vec![format!("/v2/{}/blobs/{}", REPOSITORY, upstream)]
    );
    // The backend loaded the layout named after the manifest, then ran the
    // image by the id the load produced — and by nothing else.
    let tar = layout_name(&manifest);
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
        vec![loaded_image_id(std::path::Path::new(&tar))]
    );
    assert!(
        !std::path::Path::new(&h.config.blob_cache_dir())
            .join("tmp")
            .join(&tar)
            .exists(),
        "the layout tar is removed once loaded"
    );
}

#[tokio::test]
async fn a_second_spawn_of_the_same_image_makes_no_gateway_or_registry_request() {
    let mut w = World::new().await;
    let (manifest, ..) = store_mixed_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&manifest, MANIFEST));
    let (status, body) = spawn(&h, 0x21, image(&w, &manifest)).await;
    assert_ok_spawn(status, &body, 0x21);
    let gateway_before = w.gateway_request_count().await;
    let registry_before = w.registry_paths().await.len();

    let (status, body) = spawn(&h, 0x22, image(&w, &manifest)).await;

    assert_ok_spawn(status, &body, 0x22);
    assert_eq!(w.gateway_request_count().await, gateway_before);
    assert_eq!(w.registry_paths().await.len(), registry_before);
    assert_eq!(
        h.started_images().len(),
        2,
        "both workloads run, the second from the cache"
    );
}

#[tokio::test]
async fn a_spawn_of_an_image_sharing_a_layer_fetches_only_the_new_layer() {
    let mut w = World::new().await;
    let (first_manifest, shared, _) = store_mixed_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 4)]).await;
    h.directory
        .seed_image_entry(w.entry_named("web", "1.0", &first_manifest, MANIFEST));
    let (status, body) = spawn(&h, 0x31, image(&w, &first_manifest)).await;
    assert_ok_spawn(status, &body, 0x31);
    let fetched_before = w.gateway_paths().await;

    // A second image: the same config and the shared layer, plus one new
    // layer, under a manifest of its own.
    let config_digest = w.blobs[0].digest.clone();
    let config_len = w.blobs[0].size as usize;
    let new_layer = layer_bytes(13);
    let new_digest = w.store(&new_layer, LAYER, 1024).await;
    let manifest = manifest_bytes(
        (&config_digest, config_len),
        &[
            (shared.clone(), layer_bytes(7).len()),
            (new_digest.clone(), new_layer.len()),
        ],
    );
    let second_manifest = w.store(&manifest, MANIFEST, 100).await;
    h.directory
        .seed_image_entry(w.entry_named("web", "2.0", &second_manifest, MANIFEST));

    let (status, body) = spawn(
        &h,
        0x32,
        ImageRef::from_registry(second_manifest.clone(), w.address_of("web", "2.0"), RELAY),
    )
    .await;

    assert_ok_spawn(status, &body, 0x32);
    let fetched_now: BTreeSet<String> = w
        .gateway_paths()
        .await
        .difference(&fetched_before)
        .cloned()
        .collect();
    let mut expected = BTreeSet::new();
    expected.extend(w.raw_paths(&second_manifest));
    expected.extend(w.raw_paths(&new_digest));
    assert_eq!(
        fetched_now, expected,
        "only the new manifest and the new layer were fetched"
    );
    assert!(
        !fetched_now.iter().any(|p| p.contains(&shared[7..19])),
        "the shared layer was served from the cache"
    );
}

#[tokio::test]
async fn a_layer_whose_parts_fail_verification_is_refused_image_with_no_container() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    w.store_as(&layer_digest, &layer, LAYER, 1024, Tamper::CorruptPart(2))
        .await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    // One slot, so the refusal's release of it is visible afterwards.
    let h = harness(&w, vec![listing("basic", 1, 1)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));
    // Availability fetches no layer, so it cannot know: the layer's
    // corruption is only found out on the paid fetch.
    assert_eq!(
        availability(&h, registry_image(&w, &manifest_digest)).await,
        json!({ "would_run": true })
    );

    let (status, body) = spawn(&h, 0x41, image(&w, &manifest_digest)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"].as_str().unwrap().contains("hashes to"),
        "{}",
        body
    );
    assert!(
        h.backend.calls().is_empty(),
        "nothing was loaded or started"
    );
    assert!(live_containers(&h.backend).await.is_empty());
    // The slot was given back: the same listing still has room.
    assert_eq!(
        availability(&h, registry_image(&w, &manifest_digest)).await,
        json!({ "would_run": true })
    );
    let (status, body) = post(
        &h.app,
        "/status",
        json!({ "request": signed(&h, "status", json!({ "workload_id": "41".repeat(32) }), None) }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(
        body["error"], "unknown_workload",
        "no lease was left behind"
    );
}

#[tokio::test]
async fn a_layer_no_source_serves_is_refused_image_with_no_container() {
    let mut w = World::new().await;
    let config = config_bytes();
    let config_digest = w.store(&config, CONFIG, 64).await;
    // The entry lists the layer with a Blob Record the gateway never had.
    let layer = layer_bytes(7);
    let layer_digest = digest_of(&layer);
    w.list_unserved(&layer_digest, layer.len() as u64, LAYER);
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory
        .seed_image_entry(w.entry(&manifest_digest, MANIFEST));

    let (status, body) = spawn(&h, 0x51, image(&w, &manifest_digest)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains(&format!("no source could serve blob {}", layer_digest)),
        "{}",
        body
    );
    assert!(h.backend.calls().is_empty());
    assert!(live_containers(&h.backend).await.is_empty());
}

#[tokio::test]
async fn a_cache_with_no_room_for_the_image_is_no_capacity() {
    let mut w = World::new().await;
    let (manifest, ..) = store_mixed_image(&mut w).await;
    // Room for the manifest and the config (a few hundred bytes), not for a
    // 5000-byte layer: availability passes, the paid fetch runs out of room.
    let config = toon_provider::ProviderConfig {
        blob_cache_max_bytes: Some(2000),
        ..store_config(&w, vec![listing("basic", 1, 2)])
    };
    let h = harness_with_config(config).await;
    h.directory.seed_image_entry(w.entry(&manifest, MANIFEST));
    assert_eq!(
        availability(&h, registry_image(&w, &manifest)).await,
        json!({ "would_run": true })
    );

    let (status, body) = spawn(&h, 0x61, image(&w, &manifest)).await;

    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(body["error"], "no_capacity", "{}", body);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("blob_cache_max_bytes"),
        "{}",
        body
    );
    assert!(h.backend.calls().is_empty());
    assert!(live_containers(&h.backend).await.is_empty());
}

#[tokio::test]
async fn the_blob_cache_survives_a_provider_restart() {
    let mut w = World::new().await;
    let (manifest, ..) = store_mixed_image(&mut w).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&manifest, MANIFEST));
    let (status, body) = spawn(&h, 0x71, image(&w, &manifest)).await;
    assert_ok_spawn(status, &body, 0x71);
    let gateway_before = w.gateway_request_count().await;
    let registry_before = w.registry_paths().await.len();

    let h = h.restart().await;

    // The first lease came back with the process...
    let (status, body) = post(
        &h.app,
        "/status",
        json!({ "request": signed(&h, "status", json!({ "workload_id": "71".repeat(32) }), None) }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(
        body["error"], "not_tenant",
        "the lease is still held (by its tenant)"
    );
    // ...and so did every verified blob: a new spawn fetches nothing.
    let (status, body) = spawn(&h, 0x72, image(&w, &manifest)).await;
    assert_ok_spawn(status, &body, 0x72);
    assert_eq!(w.gateway_request_count().await, gateway_before);
    assert_eq!(w.registry_paths().await.len(), registry_before);
}

/// Everything after the spawn, for one lease: status, extension, status
/// again, termination, status after. What a tenant sees of a lease once it
/// runs, with nothing that names the image in it.
async fn lifecycle(h: &StoreHarness, tenant: &Keys, workload_id: &str) -> Vec<Value> {
    let tenant = || Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap();
    let about = json!({ "workload_id": workload_id });
    let mut seen = Vec::new();
    let status = |h: &StoreHarness, ttl: u64| {
        let about = about.clone();
        let tenant = tenant();
        let provider = h.provider;
        let now = h.clock.now();
        let app = h.app.clone();
        async move {
            let request = common::harness::RequestSpec {
                tenant,
                provider,
                op: "status",
                content: about,
                created_at: now,
                expiration: Some(now + ttl),
                kind: toon_provider::nostr::kinds::K_LEASE_REQUEST,
            }
            .sign();
            post(&app, "/status", json!({ "request": request })).await
        }
    };
    seen.push(status(h, 60).await.1);
    seen.push(
        post(&h.app, "/listings/basic/v1/extend", about.clone())
            .await
            .1,
    );
    seen.push(status(h, 61).await.1);
    let request = common::harness::RequestSpec {
        tenant: tenant(),
        provider: h.provider,
        op: "terminate",
        content: about.clone(),
        created_at: h.clock.now(),
        expiration: Some(h.clock.now() + 60),
        kind: toon_provider::nostr::kinds::K_LEASE_REQUEST,
    }
    .sign();
    seen.push(
        post(&h.app, "/terminate", json!({ "request": request }))
            .await
            .1,
    );
    seen.push(status(h, 62).await.1);
    seen
}

#[tokio::test]
async fn the_lease_lifecycle_is_the_same_for_a_registry_entry_image_as_for_a_reference() {
    let mut w = World::new().await;
    let (manifest, ..) = store_mixed_image(&mut w).await;
    // The Milestone 1 form resolves against the stubbed registry too.
    common::mount_default_manifest(&w.registry).await;
    let h = harness(&w, vec![listing("basic", 1, 2)]).await;
    h.directory.seed_image_entry(w.entry(&manifest, MANIFEST));

    let by_reference = Keys::generate();
    let (status, body) = spawn_as(
        &h,
        0x81,
        ImageRef::upstream("docker.io/library/alpine", common::valid_digest()),
        Keys::parse(&by_reference.secret_key().to_secret_hex()).unwrap(),
    )
    .await;
    assert_ok_spawn(status, &body, 0x81);
    let by_entry = Keys::generate();
    let (status, body) = spawn_as(
        &h,
        0x82,
        image(&w, &manifest),
        Keys::parse(&by_entry.secret_key().to_secret_hex()).unwrap(),
    )
    .await;
    assert_ok_spawn(status, &body, 0x82);

    let reference = lifecycle(&h, &by_reference, &"81".repeat(32)).await;
    let entry = lifecycle(&h, &by_entry, &"82".repeat(32)).await;

    // The two leases differ only in what names them and what ports they
    // got; every state, expiry and ending is the same.
    let strip = |mut v: Value| {
        v.as_object_mut().map(|o| {
            o.remove("workload_id");
            o.remove("access")
        });
        v
    };
    assert_eq!(
        reference.iter().cloned().map(strip).collect::<Vec<_>>(),
        entry.iter().cloned().map(strip).collect::<Vec<_>>()
    );
    assert_eq!(entry[0]["state"], "running");
    assert_eq!(entry[1]["expires_at"], NOW + 2 * INTERVAL, "{}", entry[1]);
    assert_eq!(entry[3]["state"], json!({ "ended": "termination" }));
    assert!(entry[4]["access"].is_null());
    assert_eq!(
        h.backend
            .calls()
            .iter()
            .filter(|c| matches!(c, BackendCall::Delete(_)))
            .count(),
        2,
        "both workloads were destroyed"
    );

    // And expiry: a third lease of each kind, left to run out, is reaped
    // by the same sweep.
    let (status, _) = spawn(
        &h,
        0x83,
        ImageRef::upstream("docker.io/library/alpine", common::valid_digest()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = spawn(&h, 0x84, image(&w, &manifest)).await;
    assert_eq!(status, StatusCode::OK);
    h.clock.advance(INTERVAL + 1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert!(
        live_containers(&h.backend).await.is_empty(),
        "both expired workloads are gone"
    );
}
