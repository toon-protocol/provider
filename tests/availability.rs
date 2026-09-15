//! The free `availability` route, driven the way the provider's connector
//! drives it: an unsigned POST in, JSON out. It applies spec §6.2 steps 2, 5
//! and 6 — the same listing lookup, image policy and capacity spawn uses —
//! and must never touch the compute backend (§6.4: "a positive answer is
//! advice, not a reservation").

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{sha256_hex, valid_digest, valid_manifest_bytes, FakeBackend};
use toon_provider::nostr::wire::{Resources, Role};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::{router, Listing, ProviderConfig, ProviderService};
use toon_provider::{LeaseRecord, LeaseState};

const NOW: u64 = 1_700_000_000;
const INTERVAL: u64 = 3600;
const PUBLIC_IP: &str = "203.0.113.7";
const REFERENCE: &str = "docker.io/library/alpine";

fn listing(name: &str, version: u32, capacity: u32, arch: &str) -> Listing {
    Listing {
        name: name.to_string(),
        version,
        resources: Resources {
            cpu_millicores: 500,
            memory_mb: 256,
            storage_gb: 4,
            gpu: None,
        },
        arch: arch.to_string(),
        lease_interval_s: INTERVAL,
        price: 1000,
        capabilities: vec![],
        capacity,
    }
}

struct Harness {
    app: axum::Router,
    service: ProviderService,
    backend: Arc<FakeBackend>,
    /// Kept alive so the stubbed registry keeps answering for the harness's
    /// lifetime; never read otherwise.
    _registry: MockServer,
}

/// A harness whose lease table starts from `state_path` (empty unless the
/// caller pre-populates it — see `a_full_listing_is_no_capacity`) and whose
/// image fetches all go to `registry`.
async fn harness_over(
    listings: Vec<Listing>,
    image_policy: ImagePolicyConfig,
    registry: MockServer,
    state_path: String,
) -> Harness {
    let backend = FakeBackend::new();
    let config = ProviderConfig {
        public_ip: PUBLIC_IP.to_string(),
        nostr_private_key: nostr_sdk::Keys::generate().secret_key().to_secret_hex(),
        listings,
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: state_path,
        image_policy: ImagePolicyConfig {
            registry_url_override: Some(registry.uri()),
            ..image_policy
        },
        ..ProviderConfig::default()
    };
    let service = ProviderService::with_backend(config, backend.clone()).unwrap();
    Harness {
        app: router(service.app_state()),
        service,
        backend,
        _registry: registry,
    }
}

async fn harness(
    listings: Vec<Listing>,
    image_policy: ImagePolicyConfig,
    registry: MockServer,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    harness_over(listings, image_policy, registry, state_path).await
}

fn image_body(listing: &str, version: u32, reference: &str, digest: &str) -> Value {
    json!({
        "listing": listing,
        "version": version,
        "image": { "reference": reference, "digest": digest }
    })
}

async fn post(app: &axum::Router, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/availability")
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

/// An OCI index naming one manifest per `(arch, digest)` pair.
fn index_bytes(entries: &[(&str, &str)]) -> Vec<u8> {
    let manifests: Vec<Value> = entries
        .iter()
        .map(|(arch, digest)| {
            json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": digest,
                "size": 123,
                "platform": { "architecture": arch, "os": "linux" }
            })
        })
        .collect();
    json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": manifests
    })
    .to_string()
    .into_bytes()
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn manifest_with_layer_size(size: u64) -> Vec<u8> {
    json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 100,
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "size": size,
            "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }]
    })
    .to_string()
    .into_bytes()
}

async fn mount(server: &MockServer, digest: &str, bytes: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(format!("/v2/library/alpine/manifests/{}", digest)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(server)
        .await;
}

fn lease(id: u32, listing: &str, version: u32) -> LeaseRecord {
    LeaseRecord {
        id,
        workload_id: format!("{:02x}", id % 256).repeat(32),
        tenant: "ee6afe4b4a6e4fe49d6c35359d1161a6fd26fbe5d6eefcbab1c9c147731bf08a".to_string(),
        listing: listing.to_string(),
        listing_version: version,
        role: Role::Standalone,
        state: LeaseState::Running,
        created_at: NOW - 600,
        expires_at: NOW + 600,
        ssh_port: 40000,
        ports: vec![],
    }
}

fn state_file(dir: &std::path::Path, leases: &[LeaseRecord]) -> String {
    let path = dir.join("leases.json");
    let table: HashMap<u32, &LeaseRecord> = leases.iter().map(|l| (l.id, l)).collect();
    std::fs::write(&path, serde_json::to_vec_pretty(&table).unwrap()).unwrap();
    path.to_string_lossy().into_owned()
}

#[tokio::test]
async fn a_runnable_spawn_answers_would_run_true() {
    let registry = common::stub_registry().await;
    let h = harness(
        vec![listing("basic", 1, 2, "amd64")],
        ImagePolicyConfig::default(),
        registry,
    )
    .await;

    let (status, body) = post(&h.app, image_body("basic", 1, REFERENCE, &valid_digest())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "would_run": true }));
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn an_unknown_listing_version_is_wrong_listing_version() {
    let registry = common::stub_registry().await;
    let h = harness(
        vec![listing("basic", 1, 2, "amd64")],
        ImagePolicyConfig::default(),
        registry,
    )
    .await;

    let (status, body) = post(&h.app, image_body("basic", 2, REFERENCE, &valid_digest())).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "availability answers 200 either way"
    );
    assert_eq!(body["would_run"], false);
    assert_eq!(body["error"], "wrong_listing_version");
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_denied_digest_is_refused_image() {
    let registry = common::stub_registry().await;
    let digest = valid_digest();
    let policy = ImagePolicyConfig {
        deny_digests: vec![digest.clone()],
        ..Default::default()
    };
    let h = harness(vec![listing("basic", 1, 2, "amd64")], policy, registry).await;

    let (status, body) = post(&h.app, image_body("basic", 1, REFERENCE, &digest)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["would_run"], false);
    assert_eq!(body["error"], "refused_image");
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn an_oversized_image_is_refused_image() {
    let registry = MockServer::start().await;
    let bytes = manifest_with_layer_size(10_000_000_000);
    let digest = digest_of(&bytes);
    mount(&registry, &digest, bytes).await;

    let policy = ImagePolicyConfig {
        max_image_bytes: Some(1_000_000),
        ..Default::default()
    };
    let h = harness(vec![listing("basic", 1, 2, "amd64")], policy, registry).await;

    let (status, body) = post(&h.app, image_body("basic", 1, REFERENCE, &digest)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["would_run"], false);
    assert_eq!(body["error"], "refused_image");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("max_image_bytes"));
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn an_index_without_the_listings_arch_is_no_matching_arch() {
    let registry = MockServer::start().await;
    let other_arch_digest = format!("sha256:{}", "c".repeat(64));
    let index = index_bytes(&[("arm64", &other_arch_digest)]);
    let index_digest = digest_of(&index);
    mount(&registry, &index_digest, index).await;

    let h = harness(
        vec![listing("basic", 1, 2, "amd64")],
        ImagePolicyConfig::default(),
        registry,
    )
    .await;

    let (status, body) = post(&h.app, image_body("basic", 1, REFERENCE, &index_digest)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["would_run"], false);
    assert_eq!(body["error"], "no_matching_arch");
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn an_index_with_the_listings_arch_resolves_and_would_run() {
    let registry = MockServer::start().await;
    let leaf = valid_manifest_bytes();
    let leaf_digest = digest_of(&leaf);
    let index = index_bytes(&[("amd64", &leaf_digest)]);
    let index_digest = digest_of(&index);
    mount(&registry, &index_digest, index).await;
    mount(&registry, &leaf_digest, leaf).await;

    let h = harness(
        vec![listing("basic", 1, 2, "amd64")],
        ImagePolicyConfig::default(),
        registry,
    )
    .await;

    let (status, body) = post(&h.app, image_body("basic", 1, REFERENCE, &index_digest)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "would_run": true }));
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_full_listing_is_no_capacity() {
    let registry = common::stub_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let state_path = state_file(dir.path(), &[lease(1000, "basic", 1)]);
    let h = harness_over(
        vec![listing("basic", 1, 1, "amd64")],
        ImagePolicyConfig::default(),
        registry,
        state_path,
    )
    .await;
    // `restore_leases` only keeps a persisted lease if the backend agrees
    // the workload still exists, so the backend must be seeded first.
    h.backend.seed_running(1000);
    h.service.restore_leases().await;

    let (status, body) = post(&h.app, image_body("basic", 1, REFERENCE, &valid_digest())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["would_run"], false);
    assert_eq!(body["error"], "no_capacity");
    assert!(h.backend.calls().is_empty(), "availability starts nothing");
}

#[tokio::test]
async fn an_unknown_body_field_is_invalid_request() {
    let registry = common::stub_registry().await;
    let h = harness(
        vec![listing("basic", 1, 2, "amd64")],
        ImagePolicyConfig::default(),
        registry,
    )
    .await;

    // The spec draft's own `image_digest` shape is also an unknown field
    // here: the ticket's `{ image: { reference, digest } }` shape is the
    // only one this route accepts.
    let mut body = image_body("basic", 1, REFERENCE, &valid_digest());
    body["image_digest"] = json!("sha256:aaaa");
    let (status, resp) = post(&h.app, body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["would_run"], false);
    assert_eq!(resp["error"], "invalid_request");
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn availability_never_calls_the_backend_across_every_outcome() {
    // Belt and braces alongside the per-test assertions above: one request
    // per code path, none of which may ever touch the backend.
    let registry = common::stub_registry().await;
    let h = harness(
        vec![listing("basic", 1, 1, "amd64")],
        ImagePolicyConfig::default(),
        registry,
    )
    .await;

    let _ = post(&h.app, image_body("basic", 1, REFERENCE, &valid_digest())).await;
    let _ = post(&h.app, image_body("basic", 9, REFERENCE, &valid_digest())).await;
    let _ = post(&h.app, json!({ "not": "a valid body" })).await;

    assert!(h.backend.calls().is_empty());
}
