//! An image named `{ digest, registry_entry }` (spec §6.2), resolved through
//! its Image Registry entry (§8.1, §8.4) on the free `availability` route —
//! and refused on a paid spawn until the provider can run what it resolves.
//!
//! The world is a faked `Directory` holding the entry, a `wiremock` gateway
//! serving Blob Records and parts at `/raw/<txid>` (the TOON store as a
//! provider reads it), and a `wiremock` upstream registry. Every assertion
//! is on the HTTP answer and on the requests those two servers saw: never
//! on the provider's state.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nostr_sdk::{Event, Keys};
use serde_json::{json, Value};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::harness::{listing, RequestSpec, SSH_KEY};
use common::{sha256_hex, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::image_events::{
    blob_record_event, image_entry_event, BlobPart, BlobRecordContent, BlobSource, EntryBlob,
    ImageEntryContent,
};
use toon_provider::nostr::kinds::{K_IMAGE, K_LEASE_REQUEST};
use toon_provider::nostr::wire::{ImageRef, PortRequest, Protocol, SpawnContent};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::{router, Clock, Listing, ProviderConfig, ProviderService};

const NOW: u64 = 1_700_000_000;
const RELAY: &str = "wss://relay.example";
const INDEX: &str = "application/vnd.oci.image.index.v1+json";
const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const REPOSITORY: &str = "library/alpine";

// ── the world: a gateway, a registry, a publisher, and the blobs it lists ──

/// How a stored blob's record may lie about it.
#[derive(Clone, Copy)]
enum Tamper {
    None,
    /// The bytes served for part `n` are not the ones its sha256 records.
    CorruptPart(usize),
    /// The record's size for part `n` is one byte off.
    WrongPartSize(usize),
}

struct World {
    gateway: MockServer,
    registry: MockServer,
    publisher: Keys,
    /// Every blob the entry will list, in the order they were added.
    blobs: Vec<EntryBlob>,
    /// How many parts each stored blob was split into, by digest.
    parts: HashMap<String, usize>,
}

impl World {
    async fn new() -> Self {
        Self {
            gateway: MockServer::start().await,
            registry: MockServer::start().await,
            publisher: Keys::generate(),
            blobs: Vec::new(),
            parts: HashMap::new(),
        }
    }

    /// Store `bytes` in the TOON store as parts of `part_size`, with a Blob
    /// Record at `/raw/<record txid>`, and list it as a `toon-store` blob.
    /// Answers the blob's digest.
    async fn store(&mut self, bytes: &[u8], media_type: &str, part_size: usize) -> String {
        let digest = digest_of(bytes);
        self.store_as(&digest, bytes, media_type, part_size, Tamper::None)
            .await;
        digest
    }

    /// Like `store`, but the record (and the entry) claim the bytes are
    /// `claimed` — a lying publisher, or an honest one's mistake.
    async fn store_as(
        &mut self,
        claimed: &str,
        bytes: &[u8],
        media_type: &str,
        part_size: usize,
        tamper: Tamper,
    ) {
        let hex = claimed.strip_prefix("sha256:").unwrap();
        let mut parts = Vec::new();
        for (i, chunk) in bytes.chunks(part_size).enumerate() {
            let txid = format!("{}-part{}", &hex[..12], i);
            let served: Vec<u8> = match tamper {
                Tamper::CorruptPart(n) if n == i => chunk.iter().map(|b| b ^ 0xff).collect(),
                _ => chunk.to_vec(),
            };
            let size = match tamper {
                Tamper::WrongPartSize(n) if n == i => chunk.len() as u64 + 1,
                _ => chunk.len() as u64,
            };
            mount_raw(&self.gateway, &txid, served).await;
            parts.push(BlobPart {
                txid,
                sha256: sha256_hex(chunk),
                size,
            });
        }
        let record = BlobRecordContent {
            digest: claimed.to_string(),
            size: bytes.len() as u64,
            part_size: part_size as u64,
            parts,
        };
        self.parts.insert(claimed.to_string(), record.parts.len());
        let event = blob_record_event(&record, &self.publisher, NOW).unwrap();
        let record_txid = format!("{}-record", &hex[..12]);
        mount_raw(
            &self.gateway,
            &record_txid,
            serde_json::to_vec(&event).unwrap(),
        )
        .await;
        self.blobs.push(EntryBlob {
            digest: claimed.to_string(),
            size: bytes.len() as u64,
            media_type: media_type.to_string(),
            source: BlobSource::ToonStore {
                blob_record_txid: record_txid,
            },
        });
    }

    /// Serve `bytes` from the upstream registry and list it as an `oci`
    /// blob. Answers the blob's digest.
    async fn upstream(&mut self, bytes: &[u8], media_type: &str) -> String {
        let digest = digest_of(bytes);
        let endpoint = if media_type == MANIFEST || media_type == INDEX {
            "manifests"
        } else {
            "blobs"
        };
        Mock::given(method("GET"))
            .and(path(format!("/v2/{}/{}/{}", REPOSITORY, endpoint, digest)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
            .mount(&self.registry)
            .await;
        self.blobs.push(EntryBlob {
            digest: digest.clone(),
            size: bytes.len() as u64,
            media_type: media_type.to_string(),
            source: BlobSource::Oci {
                registry: "docker.io".to_string(),
                repository: REPOSITORY.to_string(),
            },
        });
        digest
    }

    /// The entry `web:1.0` for `digest`, listing every blob added so far.
    fn entry(&self, digest: &str, media_type: &str) -> Event {
        let content = ImageEntryContent {
            digest: digest.to_string(),
            media_type: media_type.to_string(),
            blobs: self.blobs.clone(),
        };
        image_entry_event("web", "1.0", &content, &self.publisher, NOW).unwrap()
    }

    fn address(&self) -> String {
        format!(
            "{}:{}:web:1.0",
            K_IMAGE,
            self.publisher.public_key().to_hex()
        )
    }

    /// The `/raw/` paths a stored blob's record and parts live at.
    fn raw_paths(&self, digest: &str) -> Vec<String> {
        let hex = &digest.strip_prefix("sha256:").unwrap()[..12];
        let mut paths = vec![format!("/raw/{}-record", hex)];
        paths.extend((0..self.parts[digest]).map(|i| format!("/raw/{}-part{}", hex, i)));
        paths
    }

    /// Every path the gateway was asked for, as a set.
    async fn gateway_paths(&self) -> BTreeSet<String> {
        self.gateway
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    async fn gateway_request_count(&self) -> usize {
        self.gateway.received_requests().await.unwrap().len()
    }

    async fn registry_paths(&self) -> Vec<String> {
        self.registry
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }
}

async fn mount_raw(gateway: &MockServer, txid: &str, bytes: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(format!("/raw/{}", txid)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(gateway)
        .await;
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

// ── image bytes ─────────────────────────────────────────────────────────────

fn config_bytes() -> Vec<u8> {
    json!({
        "architecture": "amd64",
        "os": "linux",
        "config": { "Cmd": ["/bin/sh"] },
        "rootfs": { "type": "layers", "diff_ids": [] }
    })
    .to_string()
    .into_bytes()
}

fn layer_bytes(seed: u8) -> Vec<u8> {
    (0..5000u32).map(|i| (i as u8).wrapping_mul(seed)).collect()
}

fn manifest_bytes(config: (&str, usize), layers: &[(String, usize)]) -> Vec<u8> {
    json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": { "mediaType": CONFIG, "digest": config.0, "size": config.1 },
        "layers": layers.iter().map(|(digest, size)| json!({
            "mediaType": LAYER, "digest": digest, "size": size
        })).collect::<Vec<_>>()
    })
    .to_string()
    .into_bytes()
}

fn index_bytes(manifests: &[(&str, &str, usize)]) -> Vec<u8> {
    json!({
        "schemaVersion": 2,
        "mediaType": INDEX,
        "manifests": manifests.iter().map(|(arch, digest, size)| json!({
            "mediaType": MANIFEST, "digest": digest, "size": size,
            "platform": { "architecture": arch, "os": "linux" }
        })).collect::<Vec<_>>()
    })
    .to_string()
    .into_bytes()
}

/// A whole image in the TOON store: config, one layer, a manifest and an
/// index for `amd64`. Answers `(index digest, manifest digest, config
/// digest, layer digest)`.
async fn store_whole_image(w: &mut World) -> (String, String, String, String) {
    let config = config_bytes();
    let layer = layer_bytes(7);
    let config_digest = w.store(&config, CONFIG, 64).await;
    let layer_digest = w.store(&layer, LAYER, 1024).await;
    let manifest = manifest_bytes(
        (&config_digest, config.len()),
        &[(layer_digest.clone(), layer.len())],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 100).await;
    let index = index_bytes(&[("amd64", &manifest_digest, manifest.len())]);
    let index_digest = w.store(&index, INDEX, 100).await;
    (index_digest, manifest_digest, config_digest, layer_digest)
}

// ── the provider ────────────────────────────────────────────────────────────

struct Harness {
    app: axum::Router,
    backend: Arc<FakeBackend>,
    directory: Arc<FakeDirectory>,
    provider: nostr_sdk::PublicKey,
    clock: Arc<FakeClock>,
}

async fn harness(w: &World, listings: Vec<Listing>) -> Harness {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let config = ProviderConfig {
        public_ip: "203.0.113.7".to_string(),
        nostr_private_key: keys.secret_key().to_secret_hex(),
        listings,
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: dir
            .keep()
            .join("leases.json")
            .to_string_lossy()
            .into_owned(),
        image_policy: ImagePolicyConfig {
            registry_url_override: Some(w.registry.uri()),
            ..Default::default()
        },
        gateway_url_pattern: Some(format!("{}/raw/{{txid}}", w.gateway.uri())),
        ..ProviderConfig::default()
    };
    let backend = FakeBackend::new();
    let clock = FakeClock::at(NOW);
    let directory = FakeDirectory::new();
    let service = ProviderService::with_backend_clock_and_directory(
        config,
        backend.clone(),
        clock.clone(),
        directory.clone(),
    )
    .unwrap();
    Harness {
        app: router(service.app_state()),
        backend,
        directory,
        provider: keys.public_key(),
        clock,
    }
}

async fn post(app: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn availability(h: &Harness, image: Value) -> Value {
    let (status, body) = post(
        &h.app,
        "/availability",
        json!({ "listing": "basic", "version": 1, "image": image }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    body
}

fn registry_image(w: &World, digest: &str) -> Value {
    json!({
        "digest": digest,
        "registry_entry": { "address": w.address(), "relay": RELAY },
    })
}

fn assert_refused(body: &Value, containing: &str) {
    assert_eq!(body["would_run"], false, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"].as_str().unwrap().contains(containing),
        "expected the message to mention {:?}: {}",
        containing,
        body
    );
}

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

    assert_refused(&body, "bytes, not the");
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
    // The layer exists nowhere the entry knows of: the manifest names it
    // and the entry does not list it.
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

    assert_refused(&body, &format!("does not list blob {}", layer_digest));
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
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    // The same harness with a policy denying the per-arch manifest the
    // index resolves to, and a size cap smaller than the layer.
    let mut config = ProviderConfig {
        public_ip: "203.0.113.7".to_string(),
        nostr_private_key: keys.secret_key().to_secret_hex(),
        listings: vec![listing("basic", 1, 2)],
        lease_state_path: dir
            .keep()
            .join("leases.json")
            .to_string_lossy()
            .into_owned(),
        image_policy: ImagePolicyConfig {
            deny_digests: vec![manifest.clone()],
            registry_url_override: Some(w.registry.uri()),
            ..Default::default()
        },
        gateway_url_pattern: Some(format!("{}/raw/{{txid}}", w.gateway.uri())),
        ..ProviderConfig::default()
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

// ── a paid spawn ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_paid_spawn_of_a_registry_entry_image_is_refused_before_capacity_with_no_container() {
    let mut w = World::new().await;
    let (index, ..) = store_whole_image(&mut w).await;
    // A one-slot listing whose slot is already taken by a Milestone 1
    // spawn, so a runnable image would be `no_capacity` here.
    common::mount_default_manifest(&w.registry).await;
    let h = harness(&w, vec![listing("basic", 1, 1)]).await;
    h.directory.seed_image_entry(w.entry(&index, INDEX));
    let taken = spawn(
        &h,
        0x51,
        ImageRef::upstream("docker.io/library/alpine", common::valid_digest()),
    )
    .await;
    assert_eq!(taken.0, StatusCode::OK, "{}", taken.1);
    let calls_before = h.backend.calls();
    let gateway_before = w.gateway_request_count().await;

    let (status, body) = spawn(
        &h,
        0x52,
        ImageRef::from_registry(index.clone(), w.address(), RELAY),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("cannot yet run an image fetched through one"));
    assert_eq!(h.backend.calls(), calls_before, "no container was created");
    assert_eq!(
        w.gateway_request_count().await,
        gateway_before,
        "nothing was fetched for a spawn that was going to be refused"
    );
    assert!(h.directory.entry_lookups().is_empty());

    // And `availability` for the same image is honest about the slot:
    // resolution passes, and it is capacity that answers.
    let body = availability(&h, registry_image(&w, &index)).await;
    assert_eq!(body["error"], "no_capacity", "{}", body);
}

async fn spawn(h: &Harness, seed: u8, image: ImageRef) -> (StatusCode, Value) {
    let content = SpawnContent {
        workload_id: format!("{:02x}", seed).repeat(32),
        image,
        env: Default::default(),
        ports: vec![PortRequest {
            container_port: 443,
            protocol: Protocol::Tcp,
        }],
        volume_gb: None,
        ssh_public_key: SSH_KEY.to_string(),
        entrypoint: None,
        args: None,
        standby_set: None,
        template: None,
    };
    let spec = RequestSpec {
        tenant: Keys::generate(),
        provider: h.provider,
        op: "spawn",
        content: serde_json::to_value(&content).unwrap(),
        created_at: h.clock.now(),
        expiration: Some(h.clock.now() + 60),
        kind: K_LEASE_REQUEST,
    };
    post(
        &h.app,
        "/listings/basic/v1/spawn",
        json!({ "request": spec.sign() }),
    )
    .await
}
