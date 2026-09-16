//! Golden wire fixtures for tenant implementations (TOON_Network #16).
//!
//! Every file under `tests/fixtures/wire/` is generated HERE, from the real
//! HTTP surface (`router`) and the real event builders, over fixed test keys,
//! a fixed clock and BIP-340 signatures whose auxiliary randomness is all
//! zeros — so the bytes are reproducible and a tenant can re-derive every
//! id and signature. Nothing in a fixture is typed by hand: a request body is
//! what this suite sent, a response is what the app answered, an event is
//! what the provider published.
//!
//! By default the suite VERIFIES each file byte-for-byte and fails on drift,
//! so a wire change that is not reflected in the fixtures fails CI.
//! `TOON_UPDATE_FIXTURES=1` rewrites them instead (`make fixtures`). The
//! spec repository carries a copy under `docs/spec/fixtures/wire/`;
//! `make fixtures TOON_SPEC_DIR=<path to TOON_Network>` regenerates and
//! syncs it in one go.
//!
//! The keys below are TEST-ONLY. They are published in the fixtures on
//! purpose; never fund or trust them.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use nostr_sdk::secp256k1::rand::{CryptoRng, RngCore};
use nostr_sdk::secp256k1::SECP256K1;
use nostr_sdk::{
    Event, EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, Timestamp, UnsignedEvent,
};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::harness::post;
use common::{sha256_hex, stub_registry, valid_digest, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::directory_events::Settlement;
use toon_provider::nostr::kinds::{
    K_EVICTION, K_LEASE_REQUEST, K_LISTING, K_LIVENESS, K_PROFILE, TOON_LABEL,
};
use toon_provider::nostr::wire::{
    ErrorCode, ErrorResponse, EvictionReason, ImageRef, PortRequest, Protocol, Resources,
    SpawnContent,
};
use toon_provider::provider::{evict, route_table, ImagePolicyConfig};
use toon_provider::provider_http::refuse;
use toon_provider::{router, Listing, ProviderConfig, ProviderService};

// ── the fixed world every fixture is generated in ────────────────────────────

/// The instant the fixture clock is stopped at (2023-11-14T22:13:20Z), and
/// the `created_at` of every event.
const NOW: u64 = 1_700_000_000;
const INTERVAL: u64 = 3600;
/// How far past `created_at` a fixture Lease Request expires, well inside
/// `lease_request::MAX_REQUEST_WINDOW_SECS`.
const TTL: u64 = 60;

/// TEST-ONLY secret keys, chosen to be obviously synthetic.
const TENANT_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PROVIDER_SECRET: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const OTHER_TENANT_SECRET: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";

const PROVIDER_NAME: &str = "Fixture Provider";
const ILP_ADDRESS: &str = "g.fixture";
const PUBLIC_IP: &str = "203.0.113.7";
const CONNECTOR_URL: &str = "http://connector.fixture.example:3300/ilp";
/// The shape a connector reports at `/ilp/identity`: an uncompressed
/// secp256k1 key, `0x`-prefixed, copied verbatim (`provider.example.toml`).
const CONNECTOR_SEAL_KEY: &str = "0x04325b06f4bcb438204ab86a36a715fdf409552da5cdc7cd28301b08088ce7c3a1bf4289f62ba89a707ed8d7db66b03cb2881ea5934e35f2d600c4cd7067ed0188";
const RELAY: &str = "ws://relay.fixture.example:7100";
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const GEOHASH: &str = "u4pruydqqvj";
const LIVENESS_CADENCE_S: u64 = 60;

const REFERENCE: &str = "docker.io/library/alpine";
const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdlbm91Z2hmb3JhdGVzdGtleQ tenant@fixture";

const GENERATOR: &str = "toon-provider tests/wire_fixtures.rs";

// ── reproducible signatures ──────────────────────────────────────────────────

/// An RNG that yields only zeros. `secp256k1::sign_schnorr_with_rng` draws
/// exactly the 32 bytes of BIP-340 auxiliary randomness from it, so signing
/// with this is BIP-340 with `aux_rand = 0x00 × 32`: fully deterministic, and
/// reproducible by any BIP-340 implementation that lets the caller supply
/// `aux_rand`. Only for fixtures — a real signer wants fresh randomness.
struct ZeroAux;

impl RngCore for ZeroAux {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), nostr_sdk::secp256k1::rand::Error> {
        dest.fill(0);
        Ok(())
    }
}

impl CryptoRng for ZeroAux {}

fn sign_reproducibly(unsigned: UnsignedEvent, keys: &Keys) -> Event {
    unsigned
        .sign_with_ctx(SECP256K1, &mut ZeroAux, keys)
        .expect("a well-formed unsigned event signs")
}

/// The provider signs what it publishes with fresh randomness
/// (`EventBuilder::sign_with_keys` uses `OsRng`), so its `sig` differs on
/// every run. For the fixture, re-sign the SAME event — same id, pubkey,
/// created_at, kind, tags and content — with zero aux randomness. Every
/// field but the 64 signature bytes is exactly what the provider produced,
/// and the id is checked against the fields on the way through.
fn with_reproducible_sig(event: &Event, keys: &Keys) -> Event {
    event
        .verify()
        .expect("the provider's own signature verifies");
    assert_eq!(
        event.pubkey,
        keys.public_key(),
        "signed by the fixture provider"
    );
    let unsigned = UnsignedEvent {
        id: Some(event.id),
        pubkey: event.pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags.clone(),
        content: event.content.clone(),
    };
    let signed = sign_reproducibly(unsigned, keys);
    assert_eq!(signed.id, event.id, "re-signing keeps the NIP-01 id");
    signed
}

// ── golden files ─────────────────────────────────────────────────────────────

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wire")
}

/// Render `value` as pretty JSON (object keys sorted — `serde_json::Value`
/// is a `BTreeMap`) with a trailing newline, then either write it
/// (`TOON_UPDATE_FIXTURES` set) or require the file on disk to match it
/// byte-for-byte.
fn golden(name: &str, value: Value) {
    let path = fixture_dir().join(name);
    let mut rendered = serde_json::to_string_pretty(&value).expect("fixtures are JSON");
    rendered.push('\n');

    if std::env::var_os("TOON_UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, rendered).unwrap_or_else(|e| panic!("writing {:?}: {}", path, e));
        return;
    }

    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "fixture {} is missing ({}). The wire tests generate it: run `make fixtures` \
             (TOON_UPDATE_FIXTURES=1 cargo test --test wire_fixtures) and commit the result.",
            name, e
        )
    });
    if on_disk != rendered {
        let first_diff = on_disk
            .lines()
            .zip(rendered.lines())
            .position(|(a, b)| a != b)
            .map(|i| i + 1)
            .unwrap_or_else(|| on_disk.lines().count().min(rendered.lines().count()) + 1);
        panic!(
            "fixture {} has drifted from the code (first difference at line {}).\n\
             If the wire change is intended, regenerate with `make fixtures`, review the \
             diff, commit it, and sync the spec repository's copy \
             (`make fixtures TOON_SPEC_DIR=...`).\n\n--- on disk ---\n{}\n--- generated now ---\n{}",
            name, first_diff, on_disk, rendered
        );
    }
}

fn header(surface: &str, case: &str, description: &str) -> Value {
    json!({
        "surface": surface,
        "case": case,
        "description": description,
        "generated_by": GENERATOR,
    })
}

// ── NIP-01 ───────────────────────────────────────────────────────────────────

/// The exact UTF-8 string whose SHA-256 is the event id (NIP-01):
/// `[0, <pubkey>, <created_at>, <kind>, <tags>, <content>]` with no
/// whitespace. Asserted against the id before it goes into a fixture.
fn nip01_serialization(event: &Event) -> String {
    let serialization = json!([
        0,
        event.pubkey.to_hex(),
        event.created_at.as_u64(),
        event.kind.as_u16(),
        event.tags,
        event.content,
    ])
    .to_string();
    assert_eq!(
        sha256_hex(serialization.as_bytes()),
        event.id.to_hex(),
        "the NIP-01 serialization hashes to the event id"
    );
    serialization
}

fn event_json(event: &Event) -> Value {
    serde_json::to_value(event).expect("an event serialises")
}

/// A fixture holding one signed event: the event as a relay or a request
/// body carries it, its content parsed for reading, and the NIP-01 string a
/// tenant must reproduce to get the same id.
fn event_fixture(
    surface: &str,
    case: &str,
    description: &str,
    kind_name: &str,
    event: &Event,
) -> Value {
    let content: Value =
        serde_json::from_str(&event.content).expect("every fixture event has JSON content");
    json!({
        "fixture": header(surface, case, description),
        "kind_name": kind_name,
        "event": event_json(event),
        "content": content,
        "nip01_serialization": nip01_serialization(event),
    })
}

// ── the tenant's side: Lease Requests ────────────────────────────────────────

fn keys(secret: &str) -> Keys {
    Keys::parse(secret).expect("a fixture secret key parses")
}

fn workload_id(seed: u8) -> String {
    format!("{:02x}", seed).repeat(32)
}

fn spawn_content(seed: u8) -> Value {
    serde_json::to_value(SpawnContent {
        workload_id: workload_id(seed),
        image: ImageRef {
            reference: REFERENCE.to_string(),
            digest: valid_digest(),
            registry_entry: None,
        },
        env: BTreeMap::from([("GREETING".to_string(), "hello".to_string())]),
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
    })
    .unwrap()
}

/// A Lease Request exactly as spec §6.1 has a tenant sign it: kind
/// `K_LEASE_REQUEST`, tags `p` (the provider), `op` and `expiration`, the
/// op's content object as the JSON `content` string.
fn lease_request(
    tenant: &Keys,
    provider: PublicKey,
    op: &str,
    content: &Value,
    created_at: u64,
    expiration: u64,
) -> Event {
    let unsigned = EventBuilder::new(Kind::Custom(K_LEASE_REQUEST), content.to_string())
        .tags([
            Tag::public_key(provider),
            Tag::custom(TagKind::custom("op"), [op]),
            Tag::expiration(Timestamp::from(expiration)),
        ])
        .custom_created_at(Timestamp::from(created_at))
        .build(tenant.public_key());
    sign_reproducibly(unsigned, tenant)
}

/// The body of every signed route: the event under the single key
/// `request`, nothing else (`nostr::wire::LeaseRequestEnvelope`).
fn envelope(event: &Event) -> Value {
    json!({ "request": event_json(event) })
}

fn about(seed: u8) -> Value {
    json!({ "workload_id": workload_id(seed) })
}

// ── the provider's side: a fixed configuration over faked I/O ────────────────

fn listing(
    name: &str,
    version: u32,
    capacity: u32,
    gpu: Option<&str>,
    capabilities: &[&str],
) -> Listing {
    Listing {
        name: name.to_string(),
        version,
        resources: Resources {
            cpu_millicores: 500,
            memory_mb: 256,
            storage_gb: 4,
            gpu: gpu.map(str::to_string),
        },
        arch: "amd64".to_string(),
        lease_interval_s: INTERVAL,
        price: 1000,
        capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        capacity,
    }
}

fn config(
    state_path: String,
    registry_url: Option<String>,
    policy: ImagePolicyConfig,
) -> ProviderConfig {
    ProviderConfig {
        provider_name: PROVIDER_NAME.to_string(),
        ilp_address: ILP_ADDRESS.to_string(),
        public_ip: PUBLIC_IP.to_string(),
        nostr_private_key: PROVIDER_SECRET.to_string(),
        relay_set: vec![RELAY.to_string()],
        connector_url: CONNECTOR_URL.to_string(),
        connector_seal_key: CONNECTOR_SEAL_KEY.to_string(),
        settlement: vec![Settlement {
            chain: "solana".to_string(),
            token: USDC_MINT.to_string(),
            decimals: 6,
        }],
        isolation: "shared-kernel".to_string(),
        liveness_cadence_s: LIVENESS_CADENCE_S,
        geohash: Some(GEOHASH.to_string()),
        capabilities: vec!["x-fixture".to_string()],
        listings: vec![
            listing("basic", 1, 2, None, &["x-fixture"]),
            listing("gpu", 1, 1, Some("rtx-4090"), &[]),
        ],
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: state_path,
        image_policy: ImagePolicyConfig {
            registry_url_override: registry_url,
            ..policy
        },
        ..ProviderConfig::default()
    }
}

struct Fixture {
    app: axum::Router,
    service: ProviderService,
    directory: Arc<FakeDirectory>,
    provider: Keys,
    tenant: Keys,
    other_tenant: Keys,
    /// Keeps the stubbed registry answering while the app may still ask it.
    _registry: MockServer,
}

impl Fixture {
    fn provider_pubkey(&self) -> PublicKey {
        self.provider.public_key()
    }

    fn spawn_request(&self, seed: u8, ttl: u64) -> Event {
        lease_request(
            &self.tenant,
            self.provider_pubkey(),
            "spawn",
            &spawn_content(seed),
            NOW,
            NOW + ttl,
        )
    }

    /// `op = status` or `op = terminate` about one workload. `ttl` also makes
    /// two requests about the same workload distinct events, since the
    /// provider refuses a replayed id (§6.1).
    fn about_request(&self, tenant: &Keys, op: &str, seed: u8, ttl: u64) -> Event {
        lease_request(
            tenant,
            self.provider_pubkey(),
            op,
            &about(seed),
            NOW,
            NOW + ttl,
        )
    }
}

async fn fixture_provider(policy: ImagePolicyConfig, registry: MockServer) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let directory = FakeDirectory::new();
    let service = ProviderService::with_backend_clock_and_directory(
        config(state_path, Some(registry.uri()), policy),
        FakeBackend::new(),
        FakeClock::at(NOW),
        directory.clone(),
    )
    .unwrap();
    Fixture {
        app: router(service.app_state()),
        service,
        directory,
        provider: keys(PROVIDER_SECRET),
        tenant: keys(TENANT_SECRET),
        other_tenant: keys(OTHER_TENANT_SECRET),
        _registry: registry,
    }
}

fn route(suffix: &str) -> String {
    format!("{}.{}", ILP_ADDRESS, suffix)
}

/// One request through the real router, captured as a fixture: the ILP route
/// a tenant pays, the HTTP path the connector forwards it to, the exact body
/// sent, and the status and body that came back.
async fn exchange(
    f: &Fixture,
    (surface, case, description): (&str, &str, &str),
    route: &str,
    http_path: &str,
    body: Value,
) -> (StatusCode, Value, Value) {
    let (status, response) = post(&f.app, http_path, body.clone()).await;
    let doc = json!({
        "fixture": header(surface, case, description),
        "route": route,
        "http_path": http_path,
        "request_body": body,
        "response_status": status.as_u16(),
        "response_body": response,
    });
    (status, response, doc)
}

fn error_of(body: &Value) -> &str {
    body["error"].as_str().unwrap_or("<no error field>")
}

/// A refusal fixture also says where it sits in spec §6.2's validation
/// order, since the first failing step is the one a tenant is told about.
fn with_validation_step(mut doc: Value, step: &str) -> Value {
    doc["validation_step"] = json!(step);
    doc
}

// ── fixtures ─────────────────────────────────────────────────────────────────

#[test]
fn constants_and_test_keys() {
    let provider = keys(PROVIDER_SECRET);
    let tenant = keys(TENANT_SECRET);
    let other = keys(OTHER_TENANT_SECRET);
    let key = |k: &Keys| {
        json!({
            "secret_key": k.secret_key().to_secret_hex(),
            "public_key": k.public_key().to_hex(),
        })
    };
    golden(
        "constants.json",
        json!({
            "fixture": header(
                "constants",
                "test_keys",
                "The fixed world every other fixture was generated in: the clock, the \
                 test-only keys, the kind numbers and the signing rule.",
            ),
            "warning": "TEST-ONLY KEYS, published on purpose. Never fund, trust or reuse them.",
            "now": NOW,
            "lease_interval_s": INTERVAL,
            "lease_request_ttl_s": TTL,
            "provider": {
                "name": PROVIDER_NAME,
                "ilp_address": ILP_ADDRESS,
                "secret_key": provider.secret_key().to_secret_hex(),
                "public_key": provider.public_key().to_hex(),
            },
            "tenant": key(&tenant),
            "other_tenant": key(&other),
            "kinds": {
                "K_PROFILE": K_PROFILE,
                "K_LISTING": K_LISTING,
                "K_LIVENESS": K_LIVENESS,
                "K_LEASE_REQUEST": K_LEASE_REQUEST,
                "K_EVICTION": K_EVICTION,
            },
            "label": TOON_LABEL,
            "signing": {
                "id": "sha256 over the NIP-01 serialization [0, pubkey, created_at, kind, tags, content]",
                "sig": "BIP-340 Schnorr over the id, by the event's pubkey",
                "aux_rand": "32 zero bytes, so every fixture signature is reproducible; \
                             real signers use fresh randomness",
            },
        }),
    );
}

#[test]
fn a_lease_request_per_op() {
    let provider = keys(PROVIDER_SECRET).public_key();
    let tenant = keys(TENANT_SECRET);
    let cases = [
        (
            "spawn",
            spawn_content(0xaa),
            "Buys a lease on `<addr>.basic.v1.spawn`. The body of `spawn.ok`.",
        ),
        (
            "status",
            about(0xaa),
            "Asks after the lease on the free `<addr>.status` route. The body of `status.running`.",
        ),
        (
            "terminate",
            about(0xaa),
            "Ends the lease on the free `<addr>.terminate` route. The body of `terminate.ok`.",
        ),
    ];
    for (op, content, description) in cases {
        let event = lease_request(&tenant, provider, op, &content, NOW, NOW + TTL);
        assert!(event.verify().is_ok());
        let mut doc = event_fixture("lease_request", op, description, "K_LEASE_REQUEST", &event);
        doc["packet_body"] = envelope(&event);
        doc["packet_body_encoding"] = json!(
            "The HTTP request body is this JSON object: the signed event, unmodified, as the \
             value of the single key `request`. No other key is allowed. The connector \
             carries the whole HTTP request inside its sealed envelope; the provider app \
             receives this body as plaintext JSON."
        );
        golden(&format!("lease_request.{}.json", op), doc);
    }
}

#[test]
fn the_routes_a_listing_generates() {
    let cfg = config("unused".to_string(), None, ImagePolicyConfig::default());
    let rows: Vec<Value> = route_table(&cfg, &[])
        .into_iter()
        .map(|r| json!({ "prefix": r.prefix, "handler_url": r.handler_url, "price": r.price }))
        .collect();
    golden(
        "routes.listing.json",
        json!({
            "fixture": header(
                "routes",
                "listing",
                "The connector routes this provider's Profile and Listings generate: one paid \
                 `.spawn` and `.extend` per listing version, then the three free provider-wide \
                 routes. `prefix` is what a tenant pays; `handler_url` is the provider's own \
                 HTTP path behind its connector and never leaves the operator's config.",
            ),
            "ilp_address": ILP_ADDRESS,
            "listings": cfg.listings.iter().map(|l| json!({
                "name": l.name, "version": l.version, "price": l.price,
                "lease_interval_s": l.lease_interval_s,
            })).collect::<Vec<_>>(),
            "patterns": {
                "spawn": "<ilp_address>.<listing d tag>.v<content.version>.spawn",
                "extend": "<ilp_address>.<listing d tag>.v<content.version>.extend",
                "availability": "<ilp_address>.availability",
                "status": "<ilp_address>.status",
                "terminate": "<ilp_address>.terminate",
            },
            "routes": rows,
        }),
    );
}

#[tokio::test]
async fn one_directory_event_per_kind() {
    let f = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    f.service.publish_directory().await.unwrap();
    f.service.publish_liveness(NOW).await.unwrap();

    let one = |kind: u16| -> Event {
        let events = f.directory.of_kind(kind);
        assert_eq!(events.len(), 1, "one event of kind {}", kind);
        with_reproducible_sig(&events[0], &f.provider)
    };

    golden(
        "directory.profile.json",
        event_fixture(
            "directory",
            "profile",
            "The Provider Profile (spec §4.1): replaceable, one per provider, tagged \
             `L toon.network`. `connector_seal_key` is what a tenant seals to (ADR 0011).",
            "K_PROFILE",
            &one(K_PROFILE),
        ),
    );

    let listings = f.directory.of_kind(K_LISTING);
    assert_eq!(listings.len(), 2);
    for (event, case, description) in [
        (
            &listings[0],
            "listing",
            "The `basic` Listing (spec §4.2): addressable on `d`, pointing at its Profile \
             through `a`, with one `t` tag per capability (here the experimental `x-fixture`) and \
             `l` labels for isolation and arch. `routes.listing` is what this event generates.",
        ),
        (
            &listings[1],
            "listing.gpu",
            "The `gpu` Listing: as `listing`, plus `resources.gpu` in content and an \
             `l gpu:<model>` label, and no capabilities.",
        ),
    ] {
        golden(
            &format!("directory.{}.json", case),
            event_fixture(
                "directory",
                case,
                description,
                "K_LISTING",
                &with_reproducible_sig(event, &f.provider),
            ),
        );
    }

    golden(
        "directory.liveness.json",
        event_fixture(
            "directory",
            "liveness",
            "Liveness (spec §4.3) published at `now`, before any lease: `available` is each \
             listing's full capacity, and `expiration` is `now + 5 × liveness_cadence_s` \
             (ADR 0007).",
            "K_LIVENESS",
            &one(K_LIVENESS),
        ),
    );

    // An Eviction Notice needs a lease to evict.
    let (status, _) = post(
        &f.app,
        "/listings/basic/v1/spawn",
        envelope(&f.spawn_request(0xbb, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let answer = evict(
        &f.service.app_state(),
        &workload_id(0xbb),
        EvictionReason::Maintenance,
        "host maintenance window",
    )
    .await
    .unwrap();
    assert!(answer.notice_published);
    golden(
        "directory.eviction.json",
        event_fixture(
            "directory",
            "eviction",
            "An Eviction Notice (spec §6.7): a regular event with the workload id in an `x` \
             tag and `{ workload_id, reason, message }` as content. `reason` is this \
             provider's own vocabulary (abuse | policy | maintenance | other).",
            "K_EVICTION",
            &one(K_EVICTION),
        ),
    );
}

#[tokio::test]
async fn a_lease_lifecycle_request_and_response_per_route() {
    let f = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let aa = 0xaa;

    // Availability, before anything runs.
    let image = json!({ "reference": REFERENCE, "digest": valid_digest() });
    let (status, response, doc) = exchange(
        &f,
        (
            "availability",
            "would_run",
            "The free availability route (spec §6.4) for a listing version on sale, a \
             runnable image and free capacity. Unsigned; always HTTP 200.",
        ),
        &route("availability"),
        "/availability",
        json!({ "listing": "basic", "version": 1, "image": image }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["would_run"], true);
    golden("availability.would_run.json", doc);

    let (status, response, doc) = exchange(
        &f,
        (
            "availability",
            "refused",
            "Availability for a listing version this provider does not sell: still HTTP \
             200, with `would_run: false` and the same error code and message a paid spawn \
             on that route would have bought.",
        ),
        &route("availability"),
        "/availability",
        json!({ "listing": "basic", "version": 2, "image": image }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["would_run"], false);
    assert_eq!(error_of(&response), "wrong_listing_version");
    golden("availability.refused.json", doc);

    // Spawn.
    let (status, response, doc) = exchange(
        &f,
        (
            "spawn",
            "ok",
            "A paid spawn (spec §6.2) on `basic` v1 with `lease_request.spawn` as its body. \
             `expires_at = now + lease_interval_s`; `access` is host, the SSH port and one \
             host port per requested port.",
        ),
        &route("basic.v1.spawn"),
        "/listings/basic/v1/spawn",
        envelope(&f.spawn_request(aa, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["expires_at"], NOW + INTERVAL);
    golden("spawn.ok.json", doc);

    // Status while running.
    let (status, response, doc) = exchange(
        &f,
        (
            "status",
            "running",
            "Status (spec §6.5) of the running lease, signed by its tenant, with \
             `lease_request.status` as its body. `state` is the one-word `running`.",
        ),
        &route("status"),
        "/status",
        envelope(&f.about_request(&f.tenant, "status", aa, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["state"], "running");
    golden("status.running.json", doc);

    // Extend.
    let (status, response, doc) = exchange(
        &f,
        (
            "extend",
            "ok",
            "A paid extension (spec §6.3) on the lease's own listing version: unsigned, \
             `{ workload_id }` only, and `expires_at` grows by one lease interval.",
        ),
        &route("basic.v1.extend"),
        "/listings/basic/v1/extend",
        about(aa),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["expires_at"], NOW + 2 * INTERVAL);
    golden("extend.ok.json", doc);

    // Refusals a running lease can produce.
    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "not_tenant",
            "Status signed by a key that is not the lease's tenant (spec §6.5).",
        ),
        &route("status"),
        "/status",
        envelope(&f.about_request(&f.other_tenant, "status", aa, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_of(&response), "not_tenant");
    golden(
        "error.not_tenant.json",
        with_validation_step(doc, "§6.5: the signer MUST be the lease's tenant"),
    );

    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "unknown_workload",
            "Status for a workload id this provider holds no lease for.",
        ),
        &route("status"),
        "/status",
        envelope(&f.about_request(&f.tenant, "status", 0xff, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error_of(&response), "unknown_workload");
    golden(
        "error.unknown_workload.json",
        with_validation_step(doc, "§6.3/§6.5/§6.6: the workload id names no lease here"),
    );

    // Terminate.
    let (status, response, doc) = exchange(
        &f,
        (
            "terminate",
            "ok",
            "Termination (spec §6.6) by the tenant with `lease_request.terminate` as its \
             body. The answer echoes the ended state so no second call is needed.",
        ),
        &route("terminate"),
        "/terminate",
        envelope(&f.about_request(&f.tenant, "terminate", aa, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["state"], json!({ "ended": "termination" }));
    golden("terminate.ok.json", doc);

    let (status, response, doc) = exchange(
        &f,
        (
            "status",
            "ended",
            "Status of the same lease after termination: `state` is the tagged \
             `{ \"ended\": <how> }` and `access` is absent because the workload is gone.",
        ),
        &route("status"),
        "/status",
        envelope(&f.about_request(&f.tenant, "status", aa, TTL + 30)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert!(response.get("access").is_none());
    golden("status.ended.json", doc);

    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "expired",
            "An extension paid for a lease that is over (here: terminated). `expired` is \
             the spec's code for every ending (§6.3); the message says which.",
        ),
        &route("basic.v1.extend"),
        "/listings/basic/v1/extend",
        about(aa),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&response), "expired");
    golden(
        "error.expired.json",
        with_validation_step(doc, "§6.3: the lease MUST be running"),
    );
}

#[tokio::test]
async fn one_refusal_per_spawn_validation_step() {
    let f = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let spawn_route = route("basic.v1.spawn");
    let spawn_path = "/listings/basic/v1/spawn";

    // Step 1: the signature.
    let mut tampered = event_json(&f.spawn_request(0xaa, TTL));
    let sig = tampered["sig"].as_str().unwrap().to_string();
    let flipped = format!(
        "{}{}",
        if sig.starts_with('0') { "1" } else { "0" },
        &sig[1..]
    );
    tampered["sig"] = json!(flipped);
    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "bad_signature",
            "`lease_request.spawn` with one hex digit of `sig` changed. The id still \
             matches the fields; the signature does not verify.",
        ),
        &spawn_route,
        spawn_path,
        json!({ "request": tampered }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_of(&response), "bad_signature");
    golden(
        "error.bad_signature.json",
        with_validation_step(doc, "§6.2 step 1: the signature is valid"),
    );

    // Step 1: freshness.
    let stale = lease_request(
        &f.tenant,
        f.provider_pubkey(),
        "spawn",
        &spawn_content(0xaa),
        NOW - 400,
        NOW - 100,
    );
    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "stale_request",
            "A correctly signed Lease Request whose `expiration` is in the past \
             (`now > t`, spec §6.1). The same code answers a window over 300 s and a \
             replayed id.",
        ),
        &spawn_route,
        spawn_path,
        envelope(&stale),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "stale_request");
    golden(
        "error.stale_request.json",
        with_validation_step(doc, "§6.2 step 1: the request is not expired or replayed"),
    );

    // Step 1: the content's shape (ADR 0004).
    let mut privileged = spawn_content(0xaa);
    privileged["privileged"] = json!(true);
    let event = lease_request(
        &f.tenant,
        f.provider_pubkey(),
        "spawn",
        &privileged,
        NOW,
        NOW + TTL,
    );
    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "invalid_request",
            "A spawn whose content carries a field the spec does not name (`privileged`). \
             Unknown fields are refused, never dropped: a runtime flag, host mount, device \
             or capability in a spawn is not silently ignored (ADR 0004).",
        ),
        &spawn_route,
        spawn_path,
        envelope(&event),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response), "invalid_request");
    golden(
        "error.invalid_request.json",
        with_validation_step(doc, "§6.2 step 1: the content parses as the op's shape"),
    );

    // Step 2: the listing version.
    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "wrong_listing_version",
            "A valid spawn paid on a `basic` version this provider does not sell (v2; it \
             sells v1). Still billed (ADR 0003).",
        ),
        &route("basic.v2.spawn"),
        "/listings/basic/v2/spawn",
        envelope(&f.spawn_request(0xbb, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error_of(&response), "wrong_listing_version");
    golden(
        "error.wrong_listing_version.json",
        with_validation_step(doc, "§6.2 step 2: the route's listing version exists"),
    );

    // Step 4: the workload id. Spawn `aa`, then spawn `aa` again with a
    // distinct event (a longer TTL) so the refusal is about the id, not a
    // replay.
    let (status, response) = post(&f.app, spawn_path, envelope(&f.spawn_request(0xaa, TTL))).await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "workload_id_taken",
            "A second spawn naming a workload id this provider already holds a live lease \
             for — here by the same tenant, which is refused too: a spawn buys a NEW lease.",
        ),
        &spawn_route,
        spawn_path,
        envelope(&f.spawn_request(0xaa, TTL + 1)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&response), "workload_id_taken");
    golden(
        "error.workload_id_taken.json",
        with_validation_step(doc, "§6.2 step 4: workload_id is not held here"),
    );

    // Step 6: capacity. `basic` sells 2; `aa` and `bb` fill it. The `bb`
    // request paid on the v2 route above was booked against replay before it
    // was refused (§6.1), so this is a fresh event about the same workload.
    let (status, response) = post(
        &f.app,
        spawn_path,
        envelope(&f.spawn_request(0xbb, TTL + 1)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    let (status, response, doc) = exchange(
        &f,
        (
            "error",
            "no_capacity",
            "A valid spawn when every slot of the listing is taken (`basic` has capacity 2 \
             and two leases run).",
        ),
        &spawn_route,
        spawn_path,
        envelope(&f.spawn_request(0xcc, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&response), "no_capacity");
    golden(
        "error.no_capacity.json",
        with_validation_step(doc, "§6.2 step 6: capacity is available"),
    );

    // Step 5: the image, on providers configured to refuse it.
    let denying = fixture_provider(
        ImagePolicyConfig {
            deny_digests: vec![valid_digest()],
            ..ImagePolicyConfig::default()
        },
        stub_registry().await,
    )
    .await;
    let (status, response, doc) = exchange(
        &denying,
        (
            "error",
            "refused_image",
            "A valid spawn on a provider whose image policy denies the named digest \
             (spec §9). `availability` answers the same refusal for free first.",
        ),
        &spawn_route,
        spawn_path,
        envelope(&denying.spawn_request(0xaa, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_of(&response), "refused_image");
    golden(
        "error.refused_image.json",
        with_validation_step(doc, "§6.2 step 5: the provider's image policy"),
    );

    // An OCI index with no manifest for the listing's arch (amd64).
    let registry = MockServer::start().await;
    let index = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{}", "c".repeat(64)),
            "size": 123,
            "platform": { "architecture": "arm64", "os": "linux" }
        }]
    })
    .to_string()
    .into_bytes();
    let index_digest = format!("sha256:{}", sha256_hex(&index));
    Mock::given(method("GET"))
        .and(path(format!(
            "/v2/library/alpine/manifests/{}",
            index_digest
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(index))
        .mount(&registry)
        .await;
    let arm_only = fixture_provider(ImagePolicyConfig::default(), registry).await;
    let mut content = spawn_content(0xaa);
    content["image"]["digest"] = json!(index_digest);
    let event = lease_request(
        &arm_only.tenant,
        arm_only.provider_pubkey(),
        "spawn",
        &content,
        NOW,
        NOW + TTL,
    );
    let (status, response, doc) = exchange(
        &arm_only,
        (
            "error",
            "no_matching_arch",
            "A spawn naming an OCI index that has no manifest for the listing's `arch` \
             (the index lists arm64 only; `basic` is amd64).",
        ),
        &spawn_route,
        spawn_path,
        envelope(&event),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_of(&response), "no_matching_arch");
    golden(
        "error.no_matching_arch.json",
        with_validation_step(doc, "§6.2 step 5: pick the manifest for the listing's arch"),
    );

    // `not_standby` has no route to produce it until Milestone 3 sells Warm
    // Standbys, so its fixture is the error shape as `provider_http::refuse`
    // renders it — the same serialiser and status mapping every other
    // refusal above went through — with no request to show.
    let rendered = refuse(ErrorResponse::new(
        ErrorCode::NotStandby,
        "this lease is not a Warm Standby; extend it on .extend",
    ));
    let status = rendered.status();
    let bytes = axum::body::to_bytes(rendered.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&body), "not_standby");
    golden(
        "error.not_standby.json",
        json!({
            "fixture": header(
                "error",
                "not_standby",
                "The `not_standby` refusal as this provider renders it. No Milestone 1 \
                 route can produce it: it belongs to `.standby.extend` (spec §6.3), which \
                 arrives with Warm Standby in Milestone 3. Shape and status only.",
            ),
            "route": Value::Null,
            "http_path": Value::Null,
            "request_body": Value::Null,
            "response_status": status.as_u16(),
            "response_body": body,
            "validation_step": "§6.3: on `.standby.extend` the lease MUST be a standby before Takeover",
        }),
    );
}
