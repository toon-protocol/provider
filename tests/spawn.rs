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
use toon_provider::{router, Clock, Listing, ProviderConfig, ProviderService};

const NOW: u64 = 1_700_000_000;
const INTERVAL: u64 = 3600;
const PUBLIC_IP: &str = "203.0.113.7";
const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdlbm91Z2hmb3JhdGVzdGtleQ tenant@example";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Harness {
    app: axum::Router,
    service: ProviderService,
    backend: Arc<FakeBackend>,
    clock: Arc<FakeClock>,
    provider: PublicKey,
    state_path: String,
    provider_key: String,
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
    )
}

/// The provider process, (re)started over a lease table on disk.
fn restart(
    listings: Vec<Listing>,
    provider_key: String,
    state_path: String,
    backend: Arc<FakeBackend>,
    clock: Arc<FakeClock>,
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
        ..ProviderConfig::default()
    };
    let service =
        ProviderService::with_backend_and_clock(config, backend.clone(), clock.clone()).unwrap();
    let provider = Keys::parse(&provider_key).unwrap().public_key();
    Harness {
        app: router(service.app_state()),
        service,
        backend,
        clock,
        provider,
        state_path,
        provider_key,
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
            created_at: h.clock.now(),
            expiration: Some(h.clock.now() + 60),
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

// ── refusals, in the spec's order ───────────────────────────────────────

fn error_of(body: &Value) -> &str {
    body["error"].as_str().unwrap_or("<no error field>")
}

#[tokio::test]
async fn a_tampered_request_is_bad_signature() {
    let h = harness();
    let mut event = RequestSpec::spawn(&h, &spawn_content(1)).sign();
    // Same signature, different content: the id no longer matches.
    event["content"] = Value::String(serde_json::to_string(&spawn_content(2)).unwrap());
    let (status, body) = spawn(&h, event).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_of(&body), "bad_signature");
    assert!(h.backend.calls().is_empty(), "nothing was started");
}

#[tokio::test]
async fn a_forged_signature_is_bad_signature() {
    let h = harness();
    let mut event = RequestSpec::spawn(&h, &spawn_content(1)).sign();
    event["sig"] = Value::String("00".repeat(64));
    let (_, body) = spawn(&h, event).await;
    assert_eq!(error_of(&body), "bad_signature");
}

#[tokio::test]
async fn an_expired_request_is_stale() {
    let h = harness();
    let spec = RequestSpec {
        created_at: NOW - 100,
        expiration: Some(NOW - 1),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (status, body) = spawn(&h, spec.sign()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "stale_request");
}

#[tokio::test]
async fn a_request_valid_for_more_than_300_seconds_is_stale() {
    let h = harness();
    let spec = RequestSpec {
        created_at: NOW - 400,
        expiration: Some(NOW + 10), // 410 s window
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (_, body) = spawn(&h, spec.sign()).await;
    assert_eq!(error_of(&body), "stale_request");

    // Exactly 300 s is fine.
    let spec = RequestSpec {
        created_at: NOW - 290,
        expiration: Some(NOW + 10),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (status, body) = spawn(&h, spec.sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

#[tokio::test]
async fn a_request_with_no_expiration_is_invalid() {
    let h = harness();
    let spec = RequestSpec {
        expiration: None,
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (_, body) = spawn(&h, spec.sign()).await;
    assert_eq!(error_of(&body), "invalid_request");
}

#[tokio::test]
async fn a_request_addressed_to_another_provider_is_refused() {
    let h = harness();
    let spec = RequestSpec {
        provider: Keys::generate().public_key(),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (status, body) = spawn(&h, spec.sign()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "invalid_request");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("another provider"));
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_request_for_another_op_or_kind_is_invalid() {
    let h = harness();
    let spec = RequestSpec {
        op: "status",
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (_, body) = spawn(&h, spec.sign()).await;
    assert_eq!(error_of(&body), "invalid_request");

    let spec = RequestSpec {
        kind: 1,
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (_, body) = spawn(&h, spec.sign()).await;
    assert_eq!(error_of(&body), "invalid_request");
}

#[tokio::test]
async fn a_body_that_is_not_an_envelope_is_invalid() {
    let h = harness();
    let (status, body) = post(&h.app, "/listings/basic/v1/spawn", json!({ "hello": 1 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "invalid_request");
}

#[tokio::test]
async fn runtime_flags_host_mounts_devices_and_capabilities_are_invalid() {
    // ADR 0004: privileges come from the listing, never from the spawn.
    let h = harness();
    for (field, value) in [
        ("privileged", json!(true)),
        ("runtime_flags", json!(["--privileged"])),
        ("mounts", json!([{ "host": "/", "container": "/host" }])),
        ("devices", json!(["/dev/kvm"])),
        ("capabilities", json!(["SYS_ADMIN"])),
    ] {
        let mut content = serde_json::to_value(spawn_content(1)).unwrap();
        content[field] = value;
        let spec = RequestSpec {
            content,
            ..RequestSpec::spawn(&h, &spawn_content(1))
        };
        let (status, body) = spawn(&h, spec.sign()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {}", field, body);
        assert_eq!(error_of(&body), "invalid_request", "{}", field);
    }
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_standby_set_is_refused_this_milestone() {
    let h = harness();
    let content = SpawnContent {
        standby_set: Some(vec![h.provider.to_hex(), "bb".repeat(32)]),
        ..spawn_content(1)
    };
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
    assert_eq!(error_of(&body), "invalid_request");
    assert!(body["message"].as_str().unwrap().contains("standby_set"));
}

#[tokio::test]
async fn a_registry_entry_is_refused_this_milestone() {
    let h = harness();
    let mut content = spawn_content(1);
    content.image.registry_entry = Some(json!({ "address": "x", "relay": "wss://r" }));
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
    assert_eq!(error_of(&body), "invalid_request");
    assert!(body["message"].as_str().unwrap().contains("registry_entry"));
}

#[tokio::test]
async fn malformed_ids_keys_images_and_ports_are_invalid() {
    let h = harness();
    let cases: Vec<(&str, SpawnContent)> = vec![
        (
            "short workload id",
            SpawnContent {
                workload_id: "abcd".to_string(),
                ..spawn_content(1)
            },
        ),
        (
            "no ssh key",
            SpawnContent {
                ssh_public_key: "".to_string(),
                ..spawn_content(1)
            },
        ),
        (
            "a tag instead of a digest",
            SpawnContent {
                image: ImageRef {
                    reference: "docker.io/library/alpine:latest".to_string(),
                    digest: DIGEST.to_string(),
                    registry_entry: None,
                },
                ..spawn_content(1)
            },
        ),
        (
            "a digest that is not sha256:<64 hex>",
            SpawnContent {
                image: ImageRef {
                    reference: "docker.io/library/alpine".to_string(),
                    digest: "sha256:abc".to_string(),
                    registry_entry: None,
                },
                ..spawn_content(1)
            },
        ),
        (
            "port 0",
            SpawnContent {
                ports: vec![PortRequest {
                    container_port: 0,
                    protocol: Protocol::Tcp,
                }],
                ..spawn_content(1)
            },
        ),
        (
            "a volume bigger than the listing's storage",
            SpawnContent {
                volume_gb: Some(5),
                ..spawn_content(1)
            },
        ),
    ];
    for (label, content) in cases {
        let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {}", label, body);
        assert_eq!(error_of(&body), "invalid_request", "{}", label);
    }
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_listing_version_this_provider_does_not_sell_is_wrong_listing_version() {
    let h = harness();
    for path in [
        "/listings/basic/v2/spawn",
        "/listings/gpu/v1/spawn",
        "/listings/basic/latest/spawn",
    ] {
        let event = RequestSpec::spawn(&h, &spawn_content(1)).sign();
        let (status, body) = post(&h.app, path, json!({ "request": event })).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}: {}", path, body);
        assert_eq!(error_of(&body), "wrong_listing_version", "{}", path);
    }
}

#[tokio::test]
async fn a_workload_id_held_by_another_tenant_is_taken() {
    let h = harness();
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK);

    // A different tenant, the same id.
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&body), "workload_id_taken");
    assert_eq!(
        h.backend.calls().len(),
        2,
        "only the first spawn touched the backend"
    );
}

#[tokio::test]
async fn the_same_tenant_respawning_an_id_it_holds_is_taken_too() {
    let h = harness();
    let tenant = Keys::generate();
    let first = RequestSpec {
        tenant: Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (status, _) = spawn(&h, first.sign()).await;
    assert_eq!(status, StatusCode::OK);
    // A second later, so this is a new request and not a replay of the first.
    h.clock.advance(1);
    let again = RequestSpec {
        tenant,
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (_, body) = spawn(&h, again.sign()).await;
    assert_eq!(error_of(&body), "workload_id_taken");
}

#[tokio::test]
async fn a_full_listing_is_no_capacity() {
    let h = harness_with(vec![listing("basic", 1, 1)]);
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(2)).sign()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&body), "no_capacity");
    assert_eq!(h.backend.calls().len(), 2);
}

#[tokio::test]
async fn capacity_is_per_listing_name_across_versions() {
    let h = harness_with(vec![listing("basic", 1, 1), listing("basic", 2, 1)]);
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK);
    let event = RequestSpec::spawn(&h, &spawn_content(2)).sign();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v2/spawn",
        json!({ "request": event }),
    )
    .await;
    assert_eq!(
        error_of(&body),
        "no_capacity",
        "v2 sells the same hardware as v1"
    );
}

#[tokio::test]
async fn a_replayed_lease_request_is_refused() {
    let h = harness();
    let event = RequestSpec::spawn(&h, &spawn_content(1)).sign();
    let (status, _) = spawn(&h, event.clone()).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = spawn(&h, event).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "stale_request");
    assert_eq!(h.backend.calls().len(), 2, "the replay started nothing");
}

#[tokio::test]
async fn a_request_refused_after_acceptance_cannot_be_resent_either() {
    // The id is remembered once the signed request was accepted as
    // authentic, so a captured refusal cannot be replayed onto the right
    // route later. A tenant signs a new request instead.
    let h = harness();
    let event = RequestSpec::spawn(&h, &spawn_content(1)).sign();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v2/spawn",
        json!({ "request": event.clone() }),
    )
    .await;
    assert_eq!(error_of(&body), "wrong_listing_version");
    let (_, body) = spawn(&h, event).await;
    assert_eq!(error_of(&body), "stale_request");
}

#[tokio::test]
async fn the_first_failing_step_is_the_one_reported() {
    // Every later fault present, one earlier fault added per case.
    let h = harness_with(vec![listing("basic", 1, 1)]);
    // Fill the listing and take an id, so steps 4 and 6 would fail.
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK);

    // 1 before 2: a stale request on an unsold version is stale.
    let stale = RequestSpec {
        expiration: Some(NOW - 1),
        created_at: NOW - 10,
        ..RequestSpec::spawn(&h, &spawn_content(1))
    }
    .sign();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v9/spawn",
        json!({ "request": stale }),
    )
    .await;
    assert_eq!(error_of(&body), "stale_request");

    // invalid content before 2: a runtime flag on an unsold version.
    let mut content = serde_json::to_value(spawn_content(1)).unwrap();
    content["privileged"] = json!(true);
    let flagged = RequestSpec {
        content,
        ..RequestSpec::spawn(&h, &spawn_content(1))
    }
    .sign();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v9/spawn",
        json!({ "request": flagged }),
    )
    .await;
    assert_eq!(error_of(&body), "invalid_request");

    // 2 before 3/4/6: unsold version, with a standby set, a taken id, full.
    let content = SpawnContent {
        standby_set: Some(vec![h.provider.to_hex()]),
        ..spawn_content(1)
    };
    let event = RequestSpec::spawn(&h, &content).sign();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v9/spawn",
        json!({ "request": event }),
    )
    .await;
    assert_eq!(error_of(&body), "wrong_listing_version");

    // 3 before 4/6.
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
    assert_eq!(error_of(&body), "invalid_request");

    // 4 before 6: a taken id on a full listing is taken.
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(error_of(&body), "workload_id_taken");

    // 6 on its own.
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(2)).sign()).await;
    assert_eq!(error_of(&body), "no_capacity");
}

#[tokio::test]
async fn a_workload_that_fails_to_start_is_no_capacity_and_releases_its_slot() {
    let h = harness_with(vec![listing("basic", 1, 1)]);
    h.backend.fail_next_create("pull failed: manifest unknown");
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "no_capacity");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("manifest unknown"));

    // The slot and the id are free again: the tenant's next try succeeds.
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

#[tokio::test]
async fn payment_headers_are_never_read() {
    // ADR 0005: a packet through a hop carries no X-TOON-* headers, so a
    // request that carries them must be served exactly as one that does not.
    let h = harness();
    let event = RequestSpec::spawn(&h, &spawn_content(1)).sign();
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listings/basic/v1/spawn")
                .header("content-type", "application/json")
                .header("x-toon-payer", "solana:nobody")
                .header("x-toon-amount", "0")
                .header("x-toon-chain", "solana")
                .body(Body::from(json!({ "request": event }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ── after the spawn ─────────────────────────────────────────────────────

#[tokio::test]
async fn an_unpaid_lease_expires_and_its_workload_id_is_free_again() {
    let h = harness_with(vec![listing("basic", 1, 1)]);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK);
    let expires_at = body["expires_at"].as_u64().unwrap();

    h.clock.set(expires_at - 1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(
        h.backend.calls().len(),
        2,
        "still paid for: nothing destroyed"
    );

    h.clock.set(expires_at);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(
        h.backend.calls()[2..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)],
        "no grace period"
    );

    // The id and the slot are free: the same tenant-chosen id spawns again.
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

#[tokio::test]
async fn a_spawned_lease_survives_a_restart() {
    let h = harness();
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let expires_at = body["expires_at"].as_u64().unwrap();

    // A new process over the same lease table, with the workload still
    // running on the backend.
    let backend = FakeBackend::new();
    backend.seed_running(1000);
    let restarted = restart(
        vec![listing("basic", 1, 2)],
        h.provider_key.clone(),
        h.state_path.clone(),
        backend.clone(),
        FakeClock::at(NOW + 10),
    );
    restarted.service.restore_leases().await;

    // It still holds its workload id...
    let (_, body) = spawn(
        &restarted,
        RequestSpec::spawn(&restarted, &spawn_content(1)).sign(),
    )
    .await;
    assert_eq!(error_of(&body), "workload_id_taken");
    // ...and it still expires when it was going to.
    restarted.service.sweep_expired_leases(expires_at).await;
    assert_eq!(
        backend.calls(),
        vec![BackendCall::Stop(1000), BackendCall::Delete(1000)]
    );
}

#[tokio::test]
async fn a_workload_that_vanished_keeps_its_id_until_its_lease_ends() {
    // The daemon no longer has toon-1000, but its lease is still paid for:
    // the next spawn must take the next id, not refuse, and not reuse 1000.
    let h = harness();
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK);
    h.backend.vanish(1000);

    h.clock.advance(1);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(2)).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["access"]["ssh_port"], 40001, "the second id, 1001");
    assert_eq!(h.backend.calls()[2], BackendCall::Create(1001));
}

#[tokio::test]
async fn a_request_created_in_the_future_is_stale() {
    // Otherwise a created_at far ahead of the clock would stretch the 300 s
    // window past what it is meant to bound.
    let h = harness();
    let spec = RequestSpec {
        created_at: NOW + 1000,
        expiration: Some(NOW + 1300),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (_, body) = spawn(&h, spec.sign()).await;
    assert_eq!(error_of(&body), "stale_request");
}

#[tokio::test]
async fn a_request_naming_a_second_provider_is_refused() {
    let h = harness();
    let mut event = RequestSpec::spawn(&h, &spawn_content(1)).sign();
    // Re-sign with an extra `p` for someone else.
    let tenant = Keys::generate();
    let content = event["content"].as_str().unwrap().to_string();
    event = serde_json::to_value(
        EventBuilder::new(Kind::Custom(K_LEASE_REQUEST), content)
            .tags([
                Tag::public_key(h.provider),
                Tag::public_key(Keys::generate().public_key()),
                Tag::custom(TagKind::custom("op"), ["spawn"]),
                Tag::expiration(Timestamp::from(NOW + 60)),
            ])
            .custom_created_at(Timestamp::from(NOW))
            .sign_with_keys(&tenant)
            .unwrap(),
    )
    .unwrap();
    let (_, body) = spawn(&h, event).await;
    assert_eq!(error_of(&body), "invalid_request");
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn ports_are_checked_against_the_listing_not_before_it() {
    // §6.2 step 2: the listing version first, then whether the ports fit.
    let h = harness();
    let content = SpawnContent {
        ports: (1..=17)
            .map(|p| PortRequest {
                container_port: p,
                protocol: Protocol::Tcp,
            })
            .collect(),
        ..spawn_content(1)
    };
    let event = RequestSpec::spawn(&h, &content).sign();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v9/spawn",
        json!({ "request": event }),
    )
    .await;
    assert_eq!(error_of(&body), "wrong_listing_version");
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
    assert_eq!(error_of(&body), "invalid_request");
}
