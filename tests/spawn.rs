//! The spawn route, driven the way the provider's connector drives it: a
//! POST with a tenant-signed Lease Request in, JSON out. Assertions are on
//! the answer and on what the faked `ComputeBackend` was asked to run —
//! never on the provider's internal state.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nostr_sdk::{EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, Timestamp};
use serde_json::{json, Value};
use tower::ServiceExt;

use common::{BackendCall, FakeBackend, FakeClock};
use toon_provider::compute::PortMapping;
use toon_provider::nostr::kinds::K_LEASE_REQUEST;
use toon_provider::nostr::wire::{ImageRef, PortRequest, Protocol, Resources, SpawnContent};
use toon_provider::{router, AppState, Listing, ProviderConfig};

const NOW: u64 = 1_700_000_000;
const INTERVAL: u64 = 3600;
const PUBLIC_IP: &str = "203.0.113.7";
const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdlbm91Z2hmb3JhdGVzdGtleQ tenant@example";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Harness {
    app: axum::Router,
    backend: Arc<FakeBackend>,
    clock: Arc<FakeClock>,
    provider: PublicKey,
}

fn listing(name: &str, version: u32, capacity: u32) -> Listing {
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
        capabilities: vec![],
        capacity,
    }
}

fn harness_with(listings: Vec<Listing>) -> Harness {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let config = ProviderConfig {
        public_ip: PUBLIC_IP.to_string(),
        nostr_private_key: keys.secret_key().to_secret_hex(),
        listings,
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: dir
            .into_path()
            .join("leases.json")
            .to_string_lossy()
            .into_owned(),
        ..ProviderConfig::default()
    };
    let backend = FakeBackend::new();
    let clock = FakeClock::at(NOW);
    let state = AppState::new(config, backend.clone(), clock.clone()).unwrap();
    Harness {
        app: router(state),
        backend,
        clock,
        provider: keys.public_key(),
    }
}

fn harness() -> Harness {
    harness_with(vec![listing("basic", 1, 2)])
}

fn workload_id(seed: u8) -> String {
    format!("{:02x}", seed).repeat(32)
}

fn spawn_content(seed: u8) -> SpawnContent {
    SpawnContent {
        workload_id: workload_id(seed),
        image: ImageRef {
            reference: "docker.io/library/alpine".to_string(),
            digest: DIGEST.to_string(),
            registry_entry: None,
        },
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
struct RequestSpec {
    tenant: Keys,
    provider: PublicKey,
    op: &'static str,
    content: Value,
    created_at: u64,
    expiration: Option<u64>,
    kind: u16,
}

impl RequestSpec {
    fn spawn(h: &Harness, content: &SpawnContent) -> Self {
        Self {
            tenant: Keys::generate(),
            provider: h.provider,
            op: "spawn",
            content: serde_json::to_value(content).unwrap(),
            created_at: NOW,
            expiration: Some(NOW + 60),
            kind: K_LEASE_REQUEST,
        }
    }

    fn sign(&self) -> Value {
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

async fn post(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
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

async fn spawn(h: &Harness, event: Value) -> (StatusCode, Value) {
    post(
        &h.app,
        "/listings/basic/v1/spawn",
        json!({ "request": event }),
    )
    .await
}

// ── success ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_spawn_starts_the_workload_and_answers_the_access_details() {
    let h = harness();
    let content = spawn_content(1);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], workload_id(1));
    assert_eq!(body["role"], "standalone");
    assert_eq!(
        body["expires_at"],
        NOW + INTERVAL,
        "one payment buys one Lease Interval"
    );
    assert_eq!(body["access"]["host"], PUBLIC_IP);
    assert_eq!(body["access"]["ssh_port"], 40000);
    assert_eq!(
        body["access"]["ports"],
        json!([{ "container_port": 443, "host_port": 41000 }])
    );

    assert_eq!(
        h.backend.calls(),
        vec![BackendCall::Create(1000), BackendCall::Start(1000)]
    );
    let created = &h.backend.created()[0];
    assert_eq!(
        created.image,
        format!("docker.io/library/alpine@{}", DIGEST),
        "pulled by reference@digest so the daemon verifies the bytes"
    );
    assert_eq!(created.ssh_key.as_deref(), Some(SSH_KEY));
    assert_eq!(created.host_port, Some(40000), "the SSH forward");
    assert_eq!(
        created.ports,
        vec![PortMapping {
            host_port: 41000,
            container_port: 443,
            protocol: "tcp".to_string()
        }]
    );
    assert_eq!(created.env.get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(created.entrypoint.as_deref(), Some("/bin/sh"));
    assert_eq!(
        created.args,
        vec!["-c".to_string(), "sleep 300".to_string()]
    );
    assert_eq!(created.cpu_millicores, 500);
    assert_eq!(created.memory_mb, 256);
    assert!(
        created.data_path.is_some(),
        "volume_gb asked for a persistent volume"
    );
}
