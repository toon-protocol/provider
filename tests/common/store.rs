//! The world an image lives in when its bytes are in the TOON store: a
//! `wiremock` gateway serving Blob Records and parts at `/raw/<txid>`, a
//! `wiremock` upstream registry, a publisher, and the Image Registry entry
//! listing where each blob is — plus a provider over faked I/O to drive
//! against it. Shared by the registry-image tests (`tests/registry_image.rs`,
//! `tests/registry_spawn.rs`, the Docker one), which assert on HTTP answers
//! and on the requests the two servers saw, never on the provider's state.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nostr_sdk::{Event, Keys};
use serde_json::{json, Value};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::harness::{RequestSpec, SSH_KEY};
use super::{sha256_hex, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::compute::ComputeBackend;
use toon_provider::nostr::image_events::{
    blob_record_event, image_entry_event, BlobPart, BlobRecordContent, BlobSource, EntryBlob,
    ImageEntryContent,
};
use toon_provider::nostr::kinds::{K_IMAGE, K_LEASE_REQUEST};
use toon_provider::nostr::wire::{ImageRef, PortRequest, Protocol, SpawnContent};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::{router, Clock, Listing, ProviderConfig, ProviderService};

pub const NOW: u64 = 1_700_000_000;
pub const RELAY: &str = "wss://relay.example";
pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const REPOSITORY: &str = "library/alpine";

// ── the world: a gateway, a registry, a publisher, and the blobs it lists ──

/// How a stored blob's record may lie about it.
#[derive(Clone, Copy)]
pub enum Tamper {
    None,
    /// The bytes served for part `n` are not the ones its sha256 records.
    CorruptPart(usize),
    /// The record's size for part `n` is one byte off.
    WrongPartSize(usize),
    /// The gateway answers 5xx for part `n`. The record is honest and the
    /// bytes exist; the store is simply not serving them right now.
    GatewayError(usize),
}

pub struct World {
    pub gateway: MockServer,
    pub registry: MockServer,
    pub publisher: Keys,
    /// Every blob the entry will list, in the order they were added.
    pub blobs: Vec<EntryBlob>,
    /// How many parts each upload was split into, by the txid prefix its
    /// parts were mounted under.
    parts: HashMap<String, usize>,
    /// The signed Blob Record of each stored blob, by digest — what an
    /// entry's `toon-store` source cites AND what a Relay Set would answer
    /// a `#x` lookup with. Seed it into a `FakeDirectory` to put the blob
    /// on the Relay Set (`seed_blob_records`).
    records: HashMap<String, Event>,
}

impl World {
    pub async fn new() -> Self {
        Self {
            gateway: MockServer::start().await,
            registry: MockServer::start().await,
            publisher: Keys::generate(),
            blobs: Vec::new(),
            parts: HashMap::new(),
            records: HashMap::new(),
        }
    }

    /// Store `bytes` in the TOON store as parts of `part_size`, with a Blob
    /// Record at `/raw/<record txid>`, and list it as a `toon-store` blob.
    /// Answers the blob's digest.
    pub async fn store(&mut self, bytes: &[u8], media_type: &str, part_size: usize) -> String {
        let digest = digest_of(bytes);
        self.store_as(&digest, bytes, media_type, part_size, Tamper::None)
            .await;
        digest
    }

    /// Like `store`, but the record (and the entry) claim the bytes are
    /// `claimed` — a lying publisher, or an honest one's mistake.
    pub async fn store_as(
        &mut self,
        claimed: &str,
        bytes: &[u8],
        media_type: &str,
        part_size: usize,
        tamper: Tamper,
    ) {
        let hex = claimed.strip_prefix("sha256:").unwrap();
        let (event, record_txid) = self
            .upload(&hex[..12], claimed, bytes, part_size, tamper)
            .await;
        self.records.insert(claimed.to_string(), event);
        self.blobs.push(EntryBlob {
            digest: claimed.to_string(),
            size: bytes.len() as u64,
            media_type: media_type.to_string(),
            source: BlobSource::ToonStore {
                blob_record_txid: record_txid,
            },
        });
    }

    /// A SECOND upload of `claimed`, under txids prefixed with `label`: a
    /// Blob Record someone else published for the same blob. Mounted on the
    /// gateway and answered as an event, but listed in no entry — this is a
    /// record a provider finds by `#x` on its Relay Set, not one an entry
    /// cites. Answers the signed record.
    pub async fn another_record(
        &mut self,
        label: &str,
        claimed: &str,
        bytes: &[u8],
        part_size: usize,
        tamper: Tamper,
    ) -> Event {
        self.upload(label, claimed, bytes, part_size, tamper)
            .await
            .0
    }

    /// Upload `bytes` as parts under `<label>-part<n>` and the signed Blob
    /// Record describing them as `<label>-record`, however the `tamper`
    /// says this upload misbehaves. Answers the record and its own txid.
    async fn upload(
        &mut self,
        label: &str,
        claimed: &str,
        bytes: &[u8],
        part_size: usize,
        tamper: Tamper,
    ) -> (Event, String) {
        let mut parts = Vec::new();
        for (i, chunk) in bytes.chunks(part_size).enumerate() {
            let txid = format!("{}-part{}", label, i);
            let served: Vec<u8> = match tamper {
                Tamper::CorruptPart(n) if n == i => chunk.iter().map(|b| b ^ 0xff).collect(),
                _ => chunk.to_vec(),
            };
            let size = match tamper {
                Tamper::WrongPartSize(n) if n == i => chunk.len() as u64 + 1,
                _ => chunk.len() as u64,
            };
            match tamper {
                Tamper::GatewayError(n) if n == i => {
                    mount_raw_status(&self.gateway, &txid, 503).await
                }
                _ => mount_raw(&self.gateway, &txid, served).await,
            }
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
        self.parts.insert(label.to_string(), record.parts.len());
        let event = blob_record_event(&record, &self.publisher, NOW).unwrap();
        let record_txid = format!("{}-record", label);
        mount_raw(
            &self.gateway,
            &record_txid,
            serde_json::to_vec(&event).unwrap(),
        )
        .await;
        (event, record_txid)
    }

    /// The signed Blob Record of a stored blob: what the Relay Set would
    /// answer a `#x` lookup for it with.
    pub fn record(&self, digest: &str) -> Event {
        self.records
            .get(digest)
            .unwrap_or_else(|| panic!("{} was never stored", digest))
            .clone()
    }

    /// List `digest` as a `toon-store` blob whose Blob Record the gateway
    /// does not have: a source that cannot serve.
    pub fn list_unserved(&mut self, digest: &str, size: u64, media_type: &str) {
        let hex = digest.strip_prefix("sha256:").unwrap();
        self.blobs.push(EntryBlob {
            digest: digest.to_string(),
            size,
            media_type: media_type.to_string(),
            source: BlobSource::ToonStore {
                blob_record_txid: format!("{}-missing", &hex[..12]),
            },
        });
    }

    /// List `digest` as an `oci` blob in a repository the registry will not
    /// serve it from: an upstream that refuses, which §8.4 moves past like
    /// any other source that cannot serve.
    pub fn list_unserved_upstream(&mut self, digest: &str, size: u64, media_type: &str) {
        self.blobs.push(EntryBlob {
            digest: digest.to_string(),
            size,
            media_type: media_type.to_string(),
            source: BlobSource::Oci {
                registry: "docker.io".to_string(),
                repository: REPOSITORY.to_string(),
            },
        });
    }

    /// Serve `bytes` from the upstream registry and list it as an `oci`
    /// blob. Answers the blob's digest.
    pub async fn upstream(&mut self, bytes: &[u8], media_type: &str) -> String {
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
    pub fn entry(&self, digest: &str, media_type: &str) -> Event {
        self.entry_named("web", "1.0", digest, media_type)
    }

    /// An entry under another name, listing every blob added so far: a
    /// second image in the same world.
    pub fn entry_named(&self, name: &str, tag: &str, digest: &str, media_type: &str) -> Event {
        let content = ImageEntryContent {
            digest: digest.to_string(),
            media_type: media_type.to_string(),
            blobs: self.blobs.clone(),
        };
        image_entry_event(name, tag, &content, &self.publisher, NOW).unwrap()
    }

    pub fn address(&self) -> String {
        self.address_of("web", "1.0")
    }

    pub fn address_of(&self, name: &str, tag: &str) -> String {
        format!(
            "{}:{}:{}:{}",
            K_IMAGE,
            self.publisher.public_key().to_hex(),
            name,
            tag
        )
    }

    /// The `/raw/` paths a stored blob's record and parts live at.
    pub fn raw_paths(&self, digest: &str) -> Vec<String> {
        self.raw_paths_of(&digest.strip_prefix("sha256:").unwrap()[..12])
    }

    /// The `/raw/` paths of one upload, by the label its txids carry —
    /// a stored blob's digest prefix, or the label `another_record` used.
    pub fn raw_paths_of(&self, label: &str) -> Vec<String> {
        let mut paths = vec![format!("/raw/{}-record", label)];
        paths.extend(self.part_paths_of(label));
        paths
    }

    /// The `/raw/` paths of one upload's PARTS, without its record: what a
    /// provider reads when it already holds the record — because the Relay
    /// Set handed it over as an event, rather than the store as bytes.
    pub fn part_paths_of(&self, label: &str) -> Vec<String> {
        (0..self.parts[label])
            .map(|i| format!("/raw/{}-part{}", label, i))
            .collect()
    }

    /// The `/raw/` paths of a stored blob's parts, without its record.
    pub fn part_paths(&self, digest: &str) -> Vec<String> {
        self.part_paths_of(&digest.strip_prefix("sha256:").unwrap()[..12])
    }

    /// The `/raw/` path of one part of a stored blob — so a test names a
    /// part the way this world does rather than re-deriving the txid rule.
    pub fn part_path(&self, digest: &str, index: usize) -> String {
        format!(
            "/raw/{}-part{}",
            &digest.strip_prefix("sha256:").unwrap()[..12],
            index
        )
    }

    /// The `/raw/` path of a stored blob's own Blob Record upload.
    pub fn record_path(&self, digest: &str) -> String {
        format!(
            "/raw/{}-record",
            &digest.strip_prefix("sha256:").unwrap()[..12]
        )
    }

    /// Every path the gateway was asked for, as a set.
    pub async fn gateway_paths(&self) -> BTreeSet<String> {
        self.gateway
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    /// Every path the gateway was asked for, in order and with repeats —
    /// so a test can say a blob was fetched ONCE.
    pub async fn gateway_path_list(&self) -> Vec<String> {
        self.gateway
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    /// The signed Blob Record of every blob stored so far.
    pub fn records(&self) -> Vec<Event> {
        self.records.values().cloned().collect()
    }

    pub async fn gateway_request_count(&self) -> usize {
        self.gateway.received_requests().await.unwrap().len()
    }

    pub async fn registry_paths(&self) -> Vec<String> {
        self.registry
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    /// Whether any request to the gateway or the registry named `digest`
    /// (by its 12-hex-digit prefix, the way this world names uploads).
    pub async fn was_fetched(&self, digest: &str) -> bool {
        let short = &digest.strip_prefix("sha256:").unwrap()[..12];
        self.gateway_paths().await.iter().any(|p| p.contains(short))
            || self
                .registry_paths()
                .await
                .iter()
                .any(|p| p.contains(digest))
    }
}

/// The gateway answers `status` for this upload and serves no bytes: a
/// store that is down, a gateway that has lost the data item.
pub async fn mount_raw_status(gateway: &MockServer, txid: &str, status: u16) {
    Mock::given(method("GET"))
        .and(path(format!("/raw/{}", txid)))
        .respond_with(ResponseTemplate::new(status))
        .mount(gateway)
        .await;
}

pub async fn mount_raw(gateway: &MockServer, txid: &str, bytes: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(format!("/raw/{}", txid)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(gateway)
        .await;
}

pub fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

// ── image bytes ─────────────────────────────────────────────────────────────

pub fn config_bytes() -> Vec<u8> {
    json!({
        "architecture": "amd64",
        "os": "linux",
        "config": { "Cmd": ["/bin/sh"] },
        "rootfs": { "type": "layers", "diff_ids": [] }
    })
    .to_string()
    .into_bytes()
}

pub fn layer_bytes(seed: u8) -> Vec<u8> {
    (0..5000u32).map(|i| (i as u8).wrapping_mul(seed)).collect()
}

pub fn manifest_bytes(config: (&str, usize), layers: &[(String, usize)]) -> Vec<u8> {
    let layers: Vec<(String, usize, &str)> = layers
        .iter()
        .map(|(digest, size)| (digest.clone(), *size, LAYER))
        .collect();
    manifest_with_layers(config, &layers)
}

/// A manifest whose layers each carry their own media type (an
/// uncompressed `…layer.v1.tar` beside a gzipped one, say).
pub fn manifest_with_layers(config: (&str, usize), layers: &[(String, usize, &str)]) -> Vec<u8> {
    json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": { "mediaType": CONFIG, "digest": config.0, "size": config.1 },
        "layers": layers.iter().map(|(digest, size, media_type)| json!({
            "mediaType": media_type, "digest": digest, "size": size
        })).collect::<Vec<_>>()
    })
    .to_string()
    .into_bytes()
}

pub fn index_bytes(manifests: &[(&str, &str, usize)]) -> Vec<u8> {
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
pub async fn store_whole_image(w: &mut World) -> (String, String, String, String) {
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

pub struct StoreHarness {
    pub app: axum::Router,
    pub service: ProviderService,
    pub backend: Arc<FakeBackend>,
    pub directory: Arc<FakeDirectory>,
    pub provider: nostr_sdk::PublicKey,
    pub clock: Arc<FakeClock>,
    /// The config the provider runs on, kept so `restart` can start the
    /// process again over the same lease table and blob cache.
    pub config: ProviderConfig,
}

/// The provider's configuration in this world: images resolve against
/// `w.registry` and the TOON store is read at `w.gateway`; the lease table
/// and the blob cache live in a fresh temporary directory.
pub fn store_config(w: &World, listings: Vec<Listing>) -> ProviderConfig {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap().keep();
    ProviderConfig {
        public_ip: "203.0.113.7".to_string(),
        nostr_private_key: keys.secret_key().to_secret_hex(),
        listings,
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: dir.join("leases.json").to_string_lossy().into_owned(),
        image_policy: ImagePolicyConfig {
            registry_url_override: Some(w.registry.uri()),
            ..Default::default()
        },
        gateway_url_pattern: Some(format!("{}/raw/{{txid}}", w.gateway.uri())),
        ..ProviderConfig::default()
    }
}

pub async fn harness(w: &World, listings: Vec<Listing>) -> StoreHarness {
    harness_with_config(store_config(w, listings)).await
}

pub async fn harness_with_config(config: ProviderConfig) -> StoreHarness {
    let backend = FakeBackend::new();
    let clock = FakeClock::at(NOW);
    let directory = FakeDirectory::new();
    start(config, backend, clock, directory).await
}

async fn start(
    config: ProviderConfig,
    backend: Arc<FakeBackend>,
    clock: Arc<FakeClock>,
    directory: Arc<FakeDirectory>,
) -> StoreHarness {
    let service = ProviderService::with_backend_clock_and_directory(
        config.clone(),
        backend.clone(),
        clock.clone(),
        directory.clone(),
    )
    .unwrap();
    service.restore_leases().await;
    StoreHarness {
        app: router(service.app_state()),
        provider: Keys::parse(&config.nostr_private_key).unwrap().public_key(),
        service,
        backend,
        directory,
        clock,
        config,
    }
}

impl StoreHarness {
    /// The provider process started again over the same lease table, blob
    /// cache, backend, clock and relay — a restart. Every workload the old
    /// process left running is still running on the backend.
    pub async fn restart(self) -> StoreHarness {
        start(self.config, self.backend, self.clock, self.directory).await
    }

    /// The `ContainerConfig` every workload was started with, in order.
    pub fn started_images(&self) -> Vec<String> {
        self.backend
            .created()
            .into_iter()
            .map(|c| c.image)
            .collect()
    }
}

pub async fn post(app: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
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

pub async fn availability(h: &StoreHarness, image: Value) -> Value {
    let (status, body) = post(
        &h.app,
        "/availability",
        json!({ "listing": "basic", "version": 1, "image": image }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    body
}

/// Put every blob stored so far on the provider's Relay Set, as the Blob
/// Records their publisher would have published beside uploading the parts
/// — what a `#x` lookup for any of them finds.
pub fn seed_blob_records(w: &World, directory: &FakeDirectory) {
    for record in w.records() {
        directory.seed_blob_record(record);
    }
}

/// The `{ digest }` form: no reference and no entry, so every blob is found
/// by Blob Record lookup on the provider's Relay Set (spec §8.4 step 3).
pub fn bare_image(digest: &str) -> Value {
    json!({ "digest": digest })
}

pub fn registry_image(w: &World, digest: &str) -> Value {
    json!({
        "digest": digest,
        "registry_entry": { "address": w.address(), "relay": RELAY },
    })
}

pub fn assert_refused(body: &Value, containing: &str) {
    assert_eq!(body["would_run"], false, "{}", body);
    assert_eq!(body["error"], "refused_image", "{}", body);
    assert!(
        body["message"].as_str().unwrap().contains(containing),
        "expected the message to mention {:?}: {}",
        containing,
        body
    );
}

pub fn spawn_content(seed: u8, image: ImageRef) -> SpawnContent {
    SpawnContent {
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
    }
}

/// A tenant-signed request for `op` about `content`, as the tenant's tooling
/// would send it. `tenant` is a fresh key unless given.
pub fn signed(h: &StoreHarness, op: &'static str, content: Value, tenant: Option<Keys>) -> Value {
    RequestSpec {
        tenant: tenant.unwrap_or_else(Keys::generate),
        providers: vec![h.provider],
        op,
        content,
        created_at: h.clock.now(),
        expiration: Some(h.clock.now() + 60),
        kind: K_LEASE_REQUEST,
    }
    .sign()
}

/// Pay a spawn of `image` on `basic` v1 as a fresh tenant.
pub async fn spawn(h: &StoreHarness, seed: u8, image: ImageRef) -> (StatusCode, Value) {
    spawn_as(h, seed, image, Keys::generate()).await
}

pub async fn spawn_as(
    h: &StoreHarness,
    seed: u8,
    image: ImageRef,
    tenant: Keys,
) -> (StatusCode, Value) {
    let content = serde_json::to_value(spawn_content(seed, image)).unwrap();
    post(
        &h.app,
        "/listings/basic/v1/spawn",
        json!({ "request": signed(h, "spawn", content, Some(tenant)) }),
    )
    .await
}

/// Whether the backend has a container for `id` at all.
pub fn container_exists(backend: &FakeBackend, id: u32) -> bool {
    backend.status_of(id) != toon_provider::compute::ContainerStatus::Absent
}

/// Every id the fake backend knows, so a test can say "no container at all".
pub async fn live_containers(backend: &FakeBackend) -> Vec<u32> {
    let mut ids = Vec::new();
    for id in 1000..=1003 {
        if backend.get_container_status(id).await.unwrap()
            != toon_provider::compute::ContainerStatus::Absent
        {
            ids.push(id);
        }
    }
    ids
}
