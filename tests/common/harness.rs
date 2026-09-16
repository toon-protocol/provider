//! The provider process as a test drives it: an HTTP request in, JSON out,
//! over a faked `ComputeBackend` and a clock the test moves by hand.
//!
//! Lifted out of `tests/spawn.rs` when the extend, status and terminate
//! routes needed the same fixtures. Nothing here reaches into the provider:
//! a test asserts on the answer and on what the backend was asked to do.
//!
//! Every spawn resolves its image against a registry, because the image
//! policy applies to every spawn — so a harness starts a `wiremock` stub of
//! one (`common::stub_registry`) and points the provider's
//! `image_policy.registry_url_override` at it. That makes building a harness
//! `async`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nostr_sdk::{EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, Timestamp};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::kinds::K_LEASE_REQUEST;
use toon_provider::nostr::wire::{ImageRef, PortRequest, Protocol, Resources, SpawnContent};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::{router, Clock, Listing, ProviderConfig, ProviderService};
use wiremock::MockServer;

pub const NOW: u64 = 1_700_000_000;
pub const INTERVAL: u64 = 3600;
pub const PUBLIC_IP: &str = "203.0.113.7";
pub const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdlbm91Z2hmb3JhdGVzdGtleQ tenant@example";

/// The digest every spawn in these tests names: whatever
/// `common::stub_registry` answers a manifest fetch with. It cannot be an
/// arbitrary constant — the registry client verifies the bytes it fetched
/// against the digest that was asked for.
pub fn digest() -> String {
    super::valid_digest()
}

pub struct Harness {
    pub app: axum::Router,
    pub service: ProviderService,
    pub backend: Arc<FakeBackend>,
    pub clock: Arc<FakeClock>,
    /// So a test can read back what the provider published — an Eviction
    /// Notice, chiefly — without paying a relay.
    pub directory: Arc<FakeDirectory>,
    pub provider: PublicKey,
    pub state_path: String,
    pub provider_key: String,
    /// Kept alive only so the stubbed registry keeps answering for as long
    /// as this harness's app might still call it; never read otherwise.
    pub _registry: MockServer,
}

pub fn listing(name: &str, version: u32, capacity: u32) -> Listing {
    Listing {
        name: name.to_string(),
        version,
        resources: Resources {
            cpu_millicores: 500,
            memory_mb: 256,
            storage_gb: 4,
            gpu: None,
        },
        arch: "amd64".to_string(),
        lease_interval_s: INTERVAL,
        price: 1000,
        standby_price: None,
        capabilities: vec![],
        capacity,
    }
}

pub async fn harness_with(listings: Vec<Listing>) -> Harness {
    harness_with_policy(listings, ImagePolicyConfig::default()).await
}

/// Like `harness_with`, but with a caller-chosen image policy — for tests
/// that check the policy itself, rather than just needing *a* runnable
/// image.
pub async fn harness_with_policy(
    listings: Vec<Listing>,
    image_policy: ImagePolicyConfig,
) -> Harness {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    restart(
        listings,
        keys.secret_key().to_secret_hex(),
        state_path,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        super::stub_registry().await,
        image_policy,
    )
    .await
}

/// The provider process, (re)started over a lease table on disk, resolving
/// images against `registry` (a fresh `common::stub_registry` server unless
/// the caller wants a specific one, e.g. to reuse a policy mounted on it).
#[allow(clippy::too_many_arguments)]
pub async fn restart(
    listings: Vec<Listing>,
    provider_key: String,
    state_path: String,
    backend: Arc<FakeBackend>,
    clock: Arc<FakeClock>,
    directory: Arc<FakeDirectory>,
    registry: MockServer,
    image_policy: ImagePolicyConfig,
) -> Harness {
    let config = ProviderConfig {
        public_ip: PUBLIC_IP.to_string(),
        nostr_private_key: provider_key.clone(),
        listings,
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: state_path.clone(),
        image_policy: ImagePolicyConfig {
            registry_url_override: Some(registry.uri()),
            ..image_policy
        },
        ..ProviderConfig::default()
    };
    let service = ProviderService::with_backend_clock_and_directory(
        config,
        backend.clone(),
        clock.clone(),
        directory.clone(),
    )
    .unwrap();
    let provider = Keys::parse(&provider_key).unwrap().public_key();
    Harness {
        app: router(service.app_state()),
        service,
        backend,
        clock,
        directory,
        provider,
        state_path,
        provider_key,
        _registry: registry,
    }
}

pub async fn harness() -> Harness {
    harness_with(vec![listing("basic", 1, 2)]).await
}

pub fn workload_id(seed: u8) -> String {
    format!("{:02x}", seed).repeat(32)
}

pub fn spawn_content(seed: u8) -> SpawnContent {
    SpawnContent {
        workload_id: workload_id(seed),
        image: ImageRef::upstream("docker.io/library/alpine".to_string(), digest()),
        env: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
        ports: vec![PortRequest {
            container_port: 443,
            protocol: Protocol::Tcp,
        }],
        volume_gb: Some(2),
        ssh_public_key: SSH_KEY.to_string(),
        entrypoint: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), "sleep 300".to_string()]),
        standby_set: None,
        template: None,
    }
}

/// A Lease Request as a tenant's tooling would sign it.
pub struct RequestSpec {
    pub tenant: Keys,
    pub provider: PublicKey,
    pub op: &'static str,
    pub content: Value,
    pub created_at: u64,
    pub expiration: Option<u64>,
    pub kind: u16,
}

impl RequestSpec {
    /// A fresh request for `op`, signed by a tenant nobody has seen before.
    /// Override `tenant` to sign as a tenant that already holds a lease.
    pub fn op(h: &Harness, op: &'static str, content: Value) -> Self {
        Self {
            tenant: Keys::generate(),
            provider: h.provider,
            op,
            content,
            created_at: h.clock.now(),
            expiration: Some(h.clock.now() + 60),
            kind: K_LEASE_REQUEST,
        }
    }

    pub fn spawn(h: &Harness, content: &SpawnContent) -> Self {
        Self::op(h, "spawn", serde_json::to_value(content).unwrap())
    }

    /// `op = status` or `op = terminate`: the content is just the workload id.
    pub fn about(h: &Harness, op: &'static str, workload_id: &str) -> Self {
        Self::op(h, op, json!({ "workload_id": workload_id }))
    }

    pub fn sign(&self) -> Value {
        let mut tags = vec![
            Tag::public_key(self.provider),
            Tag::custom(TagKind::custom("op"), [self.op]),
        ];
        if let Some(t) = self.expiration {
            tags.push(Tag::expiration(Timestamp::from(t)));
        }
        let event = EventBuilder::new(Kind::Custom(self.kind), self.content.to_string())
            .tags(tags)
            .custom_created_at(Timestamp::from(self.created_at))
            .sign_with_keys(&self.tenant)
            .unwrap();
        serde_json::to_value(event).unwrap()
    }
}

pub async fn post(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
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
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

pub async fn spawn(h: &Harness, event: Value) -> (StatusCode, Value) {
    post(
        &h.app,
        "/listings/basic/v1/spawn",
        json!({ "request": event }),
    )
    .await
}

pub fn error_of(body: &Value) -> &str {
    body["error"].as_str().unwrap_or("<no error field>")
}
