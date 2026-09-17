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

use common::harness::{hidden_config, post, socks_proxy_of, HIDDEN_CONNECTOR_URL};
use common::socks::SocksStub;
use common::{
    sha256_hex, stub_registry, valid_digest, FakeBackend, FakeClock, FakeDirectory,
    FakeHiddenService,
};
use toon_provider::nostr::directory_events::{
    takeover_event, ProfileContent, Settlement, HIDDEN_LABEL,
};
use toon_provider::nostr::image_events::{
    blob_record_event, image_entry_event, template_event, BlobPart, BlobRecordContent, BlobSource,
    EntryBlob, ImageEntryContent, TemplateContent, TemplateImage,
};
use toon_provider::nostr::kinds::{
    K_BLOB, K_EVICTION, K_IMAGE, K_LEASE_REQUEST, K_LISTING, K_LIVENESS, K_PROFILE, K_TAKEOVER,
    K_TEMPLATE, TOON_LABEL,
};
use toon_provider::nostr::wire::{
    EvictionReason, ImageRef, PortRequest, Protocol, RegistryEntryRef, Resources, SpawnContent,
};
use toon_provider::provider::{evict, route_table, ImagePolicyConfig, SELF_STOP_CADENCES};
use toon_provider::{router, Listing, LivenessState, ProviderConfig, ProviderService};

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
/// The PUBLISHER: whoever signs an Image Registry entry, a Blob Record or a
/// Template. Never a provider — spec §8's events are a publisher's, and the
/// provider only reads them — so it gets a key of its own here.
const PUBLISHER_SECRET: &str = "4444444444444444444444444444444444444444444444444444444444444444";
/// The PRIMARY of a Standby Set (spec §7): index 0 of the `standby_set`,
/// another provider entirely. The fixture provider is the STANDBY that
/// watches it, so a Takeover it announces names this key.
const PRIMARY_SECRET: &str = "5555555555555555555555555555555555555555555555555555555555555555";
/// The OTHER Warm Standby of a Standby Set: the peer the fixture provider
/// stands beside when IT is the primary. It signs nothing here either; it is
/// index 1 of the set `spawn.primary` forms.
const STANDBY_SECRET: &str = "6666666666666666666666666666666666666666666666666666666666666666";

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
/// µUSDC per interval for a Warm Standby of the `warm` tier: less than the
/// 1000 a running lease costs, because held capacity is not a running
/// workload.
const STANDBY_PRICE: u64 = 400;

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

/// The workload a Standby Set serves: one id across the primary and every
/// standby (spec §7). The Takeover and the reserved status are about this
/// one, so the two fixtures tell one story.
const STANDBY_SET_WORKLOAD: u8 = 0xa0;

/// The workload of the OTHER set in the fixtures: the one the fixture
/// provider is the primary of (`spawn.primary`). A different id, because it
/// is a different set — membership never changes, so a second set is always a
/// second workload id (spec §7).
const PRIMARY_WORKLOAD: u8 = 0xa1;

fn spawn_content(seed: u8) -> Value {
    serde_json::to_value(SpawnContent {
        workload_id: workload_id(seed),
        image: ImageRef::upstream(REFERENCE.to_string(), valid_digest()),
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

/// The spawn content of a Standby Set (spec §6.2, §7): the same
/// `workload_id` and the same `standby_set`, primary first, at every member.
fn standby_set_content(seed: u8, set: &[PublicKey]) -> Value {
    let mut content = spawn_content(seed);
    content["standby_set"] = json!(set.iter().map(|k| k.to_hex()).collect::<Vec<_>>());
    content
}

/// A Lease Request exactly as spec §6.1 has a tenant sign it: kind
/// `K_LEASE_REQUEST`, one `p` tag per addressee, `op` and `expiration`, the
/// op's content object as the JSON `content` string.
///
/// `providers` is ordinarily one. A spawn that forms a Standby Set names
/// every member of it, because the tenant signs the request ONCE and sends
/// the same bytes to all of them (§6.1, §7); each member then reads its role
/// off its own position and the route it was paid on.
fn lease_request(
    tenant: &Keys,
    providers: &[PublicKey],
    op: &str,
    content: &Value,
    created_at: u64,
    expiration: u64,
) -> Event {
    let mut tags: Vec<Tag> = providers.iter().copied().map(Tag::public_key).collect();
    tags.push(Tag::custom(TagKind::custom("op"), [op]));
    tags.push(Tag::expiration(Timestamp::from(expiration)));
    let unsigned = EventBuilder::new(Kind::Custom(K_LEASE_REQUEST), content.to_string())
        .tags(tags)
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
    standby_price: Option<u64>,
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
        standby_price,
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
        public_ip: Some(PUBLIC_IP.to_string()),
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
            listing("basic", 1, 2, None, &["x-fixture"], None),
            listing("gpu", 1, 1, Some("rtx-4090"), &[], None),
            // The one tier that sells Warm Standbys, so the fixtures show
            // both halves of the rule: a priced listing gets `.standby` and
            // `.standby.extend` rows and publishes `standby_price`, and the
            // two above get neither and publish no such field.
            listing("warm", 1, 1, None, &[], Some(STANDBY_PRICE)),
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
    /// Stopped at `NOW`, and moved only to drive the watchdog through a
    /// Takeover — then set back, so every request is signed at `NOW`.
    clock: Arc<FakeClock>,
    provider: Keys,
    tenant: Keys,
    other_tenant: Keys,
    /// Keeps the stubbed registry answering while the app may still ask it.
    _registry: MockServer,
    /// The TOON store as the provider reads it (`/raw/<txid>`), holding the
    /// Milestone 2 image's records and parts.
    _gateway: MockServer,
}

impl Fixture {
    fn provider_pubkey(&self) -> PublicKey {
        self.provider.public_key()
    }

    fn spawn_request(&self, seed: u8, ttl: u64) -> Event {
        lease_request(
            &self.tenant,
            &[self.provider_pubkey()],
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
            &[self.provider_pubkey()],
            op,
            &about(seed),
            NOW,
            NOW + ttl,
        )
    }
}

async fn fixture_provider(policy: ImagePolicyConfig, registry: MockServer) -> Fixture {
    fixture_provider_configured(policy, registry, |config| config).await
}

/// `fixture_provider` with the config changed on its way in — how the
/// Hidden Provider fixtures are made: the same keys, listings and world,
/// with `hidden = true` and everything spec §10 requires beside it.
async fn fixture_provider_configured(
    policy: ImagePolicyConfig,
    registry: MockServer,
    adjust: impl FnOnce(ProviderConfig) -> ProviderConfig,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    // The relay holds the Milestone 2 entry, and the gateway and registry
    // serve its bytes, whether or not a fixture goes on to ask for them.
    let directory = FakeDirectory::new();
    directory.seed_image_entry(image_entry());
    // And its Relay Set holds a Blob Record for every blob of the image, as
    // `#x` finds them — what `{ digest }` alone is resolved through (§8.4
    // step 3).
    for record in stored_blob_record_events() {
        directory.seed_blob_record(record);
    }
    let gateway = MockServer::start().await;
    mount_image_bytes(&gateway, &registry).await;
    let clock = FakeClock::at(NOW);
    let service = ProviderService::with_backend_clock_and_directory(
        adjust(ProviderConfig {
            gateway_url_pattern: Some(format!("{}/raw/{{txid}}", gateway.uri())),
            ..config(state_path, Some(registry.uri()), policy)
        }),
        FakeBackend::new(),
        clock.clone(),
        directory.clone(),
    )
    .unwrap()
    // Installed on every fixture provider, hidden or not: a hidden one's
    // leases get their `.anyone` addresses from it, and a public one's
    // fixtures show that it was never asked (`spawn.ok` carries an IP).
    .with_hidden_service(FakeHiddenService::new());
    Fixture {
        app: router(service.app_state()),
        service,
        directory,
        clock,
        provider: keys(PROVIDER_SECRET),
        tenant: keys(TENANT_SECRET),
        other_tenant: keys(OTHER_TENANT_SECRET),
        _registry: registry,
        _gateway: gateway,
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
            "publisher": key(&keys(PUBLISHER_SECRET)),
            "primary_provider": key(&keys(PRIMARY_SECRET)),
            "standby_provider": key(&keys(STANDBY_SECRET)),
            "kinds": {
                "K_PROFILE": K_PROFILE,
                "K_LISTING": K_LISTING,
                "K_LIVENESS": K_LIVENESS,
                "K_LEASE_REQUEST": K_LEASE_REQUEST,
                "K_EVICTION": K_EVICTION,
                "K_TAKEOVER": K_TAKEOVER,
                "K_IMAGE": K_IMAGE,
                "K_BLOB": K_BLOB,
                "K_TEMPLATE": K_TEMPLATE,
            },
            "standby_price": STANDBY_PRICE,
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
        let event = lease_request(&tenant, &[provider], op, &content, NOW, NOW + TTL);
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
                 `.spawn` and `.extend` per listing version, a `.standby` and a \
                 `.standby.extend` beside them at the listing's `standby_price` when it sells \
                 Warm Standbys (here `warm` only), then the three free provider-wide routes. A \
                 listing that prices no standby gets neither standby row: a connector must \
                 never terminate a route the provider did not price. `prefix` is what a tenant \
                 pays; `handler_url` is the provider's own HTTP path behind its connector and \
                 never leaves the operator's config.",
            ),
            "ilp_address": ILP_ADDRESS,
            "listings": cfg.listings.iter().map(|l| {
                let mut row = json!({
                    "name": l.name, "version": l.version, "price": l.price,
                    "lease_interval_s": l.lease_interval_s,
                });
                // Absent, never zero, exactly as the Listing event writes it.
                if let Some(standby_price) = l.standby_price {
                    row["standby_price"] = json!(standby_price);
                }
                row
            }).collect::<Vec<_>>(),
            "patterns": {
                "spawn": "<ilp_address>.<listing d tag>.v<content.version>.spawn",
                "extend": "<ilp_address>.<listing d tag>.v<content.version>.extend",
                "standby": "<ilp_address>.<listing d tag>.v<content.version>.standby \
                            (only when content.standby_price is present)",
                "standby.extend": "<ilp_address>.<listing d tag>.v<content.version>.standby.extend \
                                   (only when content.standby_price is present)",
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
    assert_eq!(listings.len(), 3);
    for (event, case, description) in [
        (
            &listings[0],
            "listing",
            "The `basic` Listing (spec §4.2): addressable on `d`, pointing at its Profile \
             through `a`, with one `t` tag per capability (here the experimental `x-fixture`) and \
             `l` labels for isolation and arch. It sells no Warm Standby, so it carries NO \
             `standby_price` field at all — absent, never `0`, which would read as \
             \"standbys are free\". `routes.listing` is what this event generates.",
        ),
        (
            &listings[1],
            "listing.gpu",
            "The `gpu` Listing: as `listing`, plus `resources.gpu` in content and an \
             `l gpu:<model>` label, and no capabilities.",
        ),
        (
            &listings[2],
            "listing.warm",
            "The `warm` Listing: the one tier that sells Warm Standbys (spec §4.2, §7), so \
             its content carries `standby_price` — µUSDC per interval for held capacity with \
             nothing running, less than the `price` of a running lease. It is this field \
             alone that gives the tier its `.standby` and `.standby.extend` routes in \
             `routes.listing`; nothing else about the Listing changes.",
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
             tag, the `L toon.network` label, and `{ workload_id, reason, message }` as \
             content. `reason` is one of §6.7's codes (abuse | policy | maintenance | other).",
            "K_EVICTION",
            &one(K_EVICTION),
        ),
    );

    // A Takeover, which no route produces: a Warm Standby publishes one when
    // the primary it watches has gone silent (spec §7.1 step 2), which
    // `provider::watchdog` decides over a cadence of silent readings that
    // nothing here waits out. The EVENT is built by the same builder the
    // watchdog calls, signed by the fixture provider in its role as the
    // standby; `tests/takeover_watch.rs` drives the watchdog with these
    // keys and checks that what it publishes is this fixture, byte for
    // byte.
    let takeover = with_reproducible_sig(
        &takeover_event(
            &workload_id(STANDBY_SET_WORKLOAD),
            &keys(PRIMARY_SECRET).public_key(),
            &f.provider,
            NOW,
        )
        .unwrap(),
        &f.provider,
    );
    golden(
        "directory.takeover.json",
        event_fixture(
            "directory",
            "takeover",
            "A Takeover (spec §7.1): a Warm Standby's claim on the workload of a primary \
             that went silent, published to the PRIMARY's Relay Set, where every other \
             member of the Standby Set is watching. Addressable on `d` = the workload id \
             the whole set shares, so a second announcement about the same workload \
             replaces the first and the settle query reads one claim per standby rather \
             than a history. `primary` is the pubkey at index 0 of the `standby_set` \
             (`constants.primary_provider`); the signer is the standby that claims the \
             workload — here the fixture provider — and never the primary itself.",
            "K_TAKEOVER",
            &takeover,
        ),
    );
}

/// The Hidden Provider's two directory shapes (spec §4.1, §4.2, §10;
/// TOON_Network #38): the same fixture provider — same key, same listings,
/// same relay — configured with `hidden = true`, its connector at an
/// `.anyone` host and every `[anon]` key the startup gate requires. What
/// changes on the wire is exactly two things: the Profile says `hidden:
/// true` and carries no `host` key at all, and every Listing carries the
/// `hidden:true` label. Nothing else in either event moves.
#[tokio::test]
async fn a_hidden_providers_profile_and_listing() {
    let f = fixture_provider_configured(
        ImagePolicyConfig::default(),
        stub_registry().await,
        hidden_config,
    )
    .await;
    f.service.publish_directory().await.unwrap();

    let profiles = f.directory.of_kind(K_PROFILE);
    assert_eq!(profiles.len(), 1);
    let profile = with_reproducible_sig(&profiles[0], &f.provider);
    let content: ProfileContent = serde_json::from_str(&profile.content).unwrap();
    assert!(content.hidden);
    assert_eq!(content.host, None);
    assert_eq!(content.connector_url, HIDDEN_CONNECTOR_URL);
    golden(
        "directory.profile.hidden.json",
        event_fixture(
            "directory",
            "profile.hidden",
            "The Provider Profile of a HIDDEN PROVIDER (spec §4.1, §10): `hidden: true`, NO \
             `host` key at all, and a `connector_url` at an `.anyone` host — the only way the \
             connector is reached. Everything else is `directory.profile`'s: same key, same \
             sealing key, same Relay Set, same settlement. `hidden` is a self-assertion that \
             nothing verifies, and it hides where the provider is, not that it was paid: \
             payments stay public on chain (ADR 0008).",
            "K_PROFILE",
            &profile,
        ),
    );

    let listings = f.directory.of_kind(K_LISTING);
    assert_eq!(listings.len(), 3);
    for event in &listings {
        assert!(
            event
                .tags
                .iter()
                .any(|t| t.clone().to_vec() == ["l", HIDDEN_LABEL, TOON_LABEL]),
            "every Listing of a hidden provider carries the label"
        );
    }
    golden(
        "directory.listing.hidden.json",
        event_fixture(
            "directory",
            "listing.hidden",
            "The `basic` Listing of the HIDDEN PROVIDER of `directory.profile.hidden` (spec \
             §4.2, §10): `directory.listing` plus one tag, `[\"l\", \"hidden:true\", \
             \"toon.network\"]`, beside the isolation and arch labels, so a tenant can filter \
             for or against hidden compute by tag alone (`#l = hidden:true`). Present on every \
             Listing of a hidden provider and on no Listing of any other; never `hidden:false`. \
             Content is unchanged, and so are the routes it generates.",
            "K_LISTING",
            &with_reproducible_sig(&listings[0], &f.provider),
        ),
    );
}

/// The Hidden Provider's LEASE (spec §6.2, §6.5, §10; TOON_Network #39):
/// the same paid spawn `spawn.ok` shows, on the same listing, for the same
/// workload, bought from the same fixture provider configured with
/// `hidden = true`. One thing changes, and it is the whole point: `access`
/// carries the lease's OWN `.anyone` address in place of the provider's IP,
/// and `status` answers the same one. The ports do not move — a tenant
/// dials `ssh_port` and each `host_port` on the address exactly as it would
/// on an IP — and no IP appears anywhere in either answer.
///
/// The address here is the fake `HiddenService`'s, derived from the
/// workload id so the fixture is reproducible; a real one is 56 base32
/// characters the daemon chooses.
#[tokio::test]
async fn a_hidden_providers_lease_is_reached_at_its_own_anyone_address() {
    // A hidden provider's image fetch leaves through `anon.socks_proxy`
    // (§10), so the stub registry is reached through a SOCKS stub that
    // dials the registry's IP literal as given.
    let socks = SocksStub::start(&[]).await;
    let f = fixture_provider_configured(
        ImagePolicyConfig::default(),
        stub_registry().await,
        |config| socks_proxy_of(hidden_config(config), &socks.url()),
    )
    .await;
    let aa = 0xaa;
    let host = FakeHiddenService::address_for(&workload_id(aa));

    let (status, response, doc) = exchange(
        &f,
        (
            "spawn",
            "ok.hidden",
            "The paid spawn of `spawn.ok`, on a HIDDEN PROVIDER (spec §6.2, §10): the same \
             request, the same listing and the same workload id, answered with the lease's \
             OWN `.anyone` address as `access.host` instead of an IP. The provider published \
             no host (`directory.profile.hidden`), so this address — created for this lease \
             before its workload started, mapping its SSH forward and every port it published \
             — is the only way to reach it; a tenant dials it through a `socks5h://` proxy, on \
             the SAME `ssh_port` and `host_port`s a public provider would have given. It is \
             destroyed when the lease ends, and re-established at the same host if the \
             provider restarts. No IP appears anywhere in the answer.",
        ),
        &route("basic.v1.spawn"),
        "/listings/basic/v1/spawn",
        envelope(&f.spawn_request(aa, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["access"]["host"], host);
    assert!(toon_provider::is_anyone_host(&host));
    // The ports are `spawn.ok`'s, unchanged: hiding moves the host, not the
    // numbers a tenant dials.
    assert_eq!(response["access"]["ssh_port"], 40000);
    assert_eq!(response["access"]["ports"][0]["host_port"], 41000);
    golden("spawn.ok.hidden.json", doc);

    let (status, response, doc) = exchange(
        &f,
        (
            "status",
            "running.hidden",
            "Status of that hidden lease (spec §6.5, §10): `status.running` with the same \
             `.anyone` host its spawn answered. A provider restarted on its lease table \
             re-establishes each live lease's address from the key it stored, so this answer \
             does not change across a restart; a lease whose key was not kept is given a fresh \
             address, and this is where its tenant reads it.",
        ),
        &route("status"),
        "/status",
        envelope(&f.about_request(&f.tenant, "status", aa, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["state"], "running");
    assert_eq!(response["access"]["host"], host);
    golden("status.running.hidden.json", doc);
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
             runnable image and free capacity. Unsigned; always HTTP 200. `image` is the \
             same three-form object a spawn carries (ADR 0015).",
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

    // Availability asked about a Warm Standby rather than a running lease.
    let (status, response, doc) = exchange(
        &f,
        (
            "availability",
            "standby_role",
            "Availability with §6.4's optional `role`, asked about the one tier that sells \
             Warm Standbys: would a standby be RESERVED here? Nothing is reserved by \
             asking, and the answer is `false` with `wrong_listing_version` on a listing \
             that prices no standby, exactly as its `.standby` route would have answered. \
             `role` takes `primary` or `standby` and nothing else — `standalone` is a \
             lease role, not a question, since every spawn with no Standby Set is \
             standalone already — and an unknown value is `invalid_request` like any other \
             shape. Omitting `role` asks the ordinary question, as every other \
             availability fixture here does.",
        ),
        &route("availability"),
        "/availability",
        json!({ "listing": "warm", "version": 1, "image": image, "role": "standby" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["would_run"], true);
    golden("availability.standby_role.json", doc);

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
             body. The answer is `{ workload_id, state }` with the ended state, so no \
             second call is needed.",
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
        &[f.provider_pubkey()],
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
        &[f.provider_pubkey()],
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
        &[arm_only.provider_pubkey()],
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
}

/// Paying a reservation (spec §6.3, TOON_Network #30): `.standby.extend`'s
/// response, and the two refusals that turn on a lease's ROLE rather than on
/// its workload id, its listing version or whether it has ended — those three
/// are the same codes `error.wrong_listing_version`, `error.expired` and
/// `error.unknown_workload` already show, on `.extend`. Each scenario gets
/// its own fixture provider: `warm` sells one slot, and a role refusal must
/// not be confused with a capacity one.
#[tokio::test]
async fn a_standby_extend_response_and_its_role_refusals() {
    let warm_standby_extend_route = route("warm.v1.standby.extend");
    let warm_extend_route = route("warm.v1.extend");

    // ── the response: one lease_interval_s on a reservation ──────────────
    let f = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let seed = 0xb0;
    let set = [keys(PRIMARY_SECRET).public_key(), f.provider_pubkey()];
    let reserve_event = lease_request(
        &f.tenant,
        &set,
        "spawn",
        &standby_set_content(seed, &set),
        NOW,
        NOW + TTL,
    );
    let (status, response) = post(
        &f.app,
        "/listings/warm/v1/standby",
        envelope(&reserve_event),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);

    let (status, response, doc) = exchange(
        &f,
        (
            "standby_extend",
            "ok",
            "A paid extension of a reservation (spec §6.3): unsigned, `{ workload_id }` \
             only, exactly like `.extend`. `expires_at` grows by one lease interval at the \
             listing's `standby_price`, and the fake backend is never asked for anything — \
             a reservation runs nothing to extend.",
        ),
        &warm_standby_extend_route,
        "/listings/warm/v1/standby/extend",
        about(seed),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["expires_at"], NOW + 2 * INTERVAL);
    golden("standby_extend.ok.json", doc);

    // ── `not_standby`: `.standby.extend` meets a RUNNING lease ───────────
    // Bought on `.spawn` rather than `.standby`, so it is running rather than
    // reserved, but still on `warm` — the same listing and version
    // `.standby.extend` is paid on, so the role is the only thing wrong.
    let g = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let running_seed = 0xb1;
    let running_event = g.spawn_request(running_seed, TTL);
    let (status, response) =
        post(&g.app, "/listings/warm/v1/spawn", envelope(&running_event)).await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["role"], "standalone");

    let (status, response, doc) = exchange(
        &g,
        (
            "error",
            "not_standby",
            "`.standby.extend` paid for a RUNNING lease — standalone here, and the same for \
             a Standby Set's primary or a standby after Takeover. It is billed at its own \
             price on `.extend` instead; nothing here is a role a tenant can fix by \
             retrying, so the message points at the route that will take the payment.",
        ),
        &warm_standby_extend_route,
        "/listings/warm/v1/standby/extend",
        about(running_seed),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&response), "not_standby");
    golden(
        "error.not_standby.json",
        with_validation_step(doc, "§6.3: on .standby.extend the lease MUST be Reserved"),
    );

    // ── `not_running`: `.extend` meets a RESERVATION ──────────────────────
    // The mirror refusal, this ticket's own choice of code: none of §6.3's
    // other three named codes fit a lease that is known, on the right
    // version and not yet ended, just not RUNNING.
    let h = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let reserved_seed = 0xb2;
    let reserved_set = [keys(PRIMARY_SECRET).public_key(), h.provider_pubkey()];
    let reserved_event = lease_request(
        &h.tenant,
        &reserved_set,
        "spawn",
        &standby_set_content(reserved_seed, &reserved_set),
        NOW,
        NOW + TTL,
    );
    let (status, response) = post(
        &h.app,
        "/listings/warm/v1/standby",
        envelope(&reserved_event),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);

    let (status, response, doc) = exchange(
        &h,
        (
            "error",
            "not_running",
            "`.extend` paid for a Warm Standby RESERVATION rather than a running lease \
             (spec §6.3). A reservation is billed at `standby_price` on `.standby.extend`; \
             a lease is always billed at the price for what it is doing.",
        ),
        &warm_extend_route,
        "/listings/warm/v1/extend",
        about(reserved_seed),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&response), "not_running");
    golden(
        "error.not_running.json",
        with_validation_step(doc, "§6.3: on .extend the lease MUST be Running"),
    );
}

/// The two roles a Standby Set gives, each as a paid exchange: the same
/// signed spawn reaches every member, and the route it lands on decides what
/// this provider does with it (spec §6.2 step 3, §7) — and what the primary's
/// `status` says once its own relays stop taking its Liveness (§7.1).
///
/// Two fixture providers, because ONE provider can hold only one position in
/// one set: in `spawn.primary` the fixture provider is index 0 of a set whose
/// other member is `constants.standby_provider`, and in `spawn.standby` it is
/// index 1 behind `constants.primary_provider` — the same primary the
/// `directory.takeover` fixture names, for the same workload id, so the two
/// tell one story.
#[tokio::test]
async fn a_spawn_and_a_status_per_standby_set_role() {
    // ── index 0, on `.spawn`: the primary runs the workload ──────────────
    let f = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let primary_set = [f.provider_pubkey(), keys(STANDBY_SECRET).public_key()];
    let content = standby_set_content(PRIMARY_WORKLOAD, &primary_set);
    let event = lease_request(&f.tenant, &primary_set, "spawn", &content, NOW, NOW + TTL);
    let (status, response, doc) = exchange(
        &f,
        (
            "spawn",
            "primary",
            "A paid spawn that forms a Standby Set (spec §6.2, §7), at the member it makes the \
             PRIMARY. The content carries `standby_set` with this provider's key at index 0, and \
             the request carries one `p` tag per member, because the tenant signs it once and \
             sends the same bytes to every member. Index 0 must arrive on `.spawn`, and the lease \
             that follows runs exactly as a standalone one does: `role` is `primary` and `access` \
             is present. The tier is `warm`, the one that prices standbys, because the rest of \
             the set is bought on its `.standby` route at `standby_price`.",
        ),
        &route("warm.v1.spawn"),
        "/listings/warm/v1/spawn",
        envelope(&event),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["role"], "primary");
    assert!(response.get("access").is_some());
    golden("spawn.primary.json", doc);

    let (status, response, doc) = exchange(
        &f,
        (
            "status",
            "primary",
            "Status of that primary (spec §6.5): `role` is `primary` rather than `standalone`, \
             `state` is `running`, and `access` is where the workload actually runs. A tenant \
             asks every member of the set the same question to find out where its workload is.",
        ),
        &route("status"),
        "/status",
        envelope(&f.about_request(&f.tenant, "status", PRIMARY_WORKLOAD, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["role"], "primary");
    assert_eq!(response["state"], "running");
    golden("status.primary.json", doc);

    // ── the same primary, cut off from its own Relay Set ─────────────────
    // Five Liveness publications that no relay of the Relay Set took, which
    // is exactly what spec §7.1 counts: the provider stops its primary's
    // workload rather than keep it running beside a Takeover.
    f.directory.publishes_to(&[RELAY]);
    f.directory.refuse_liveness_on(&[RELAY]);
    for _ in 0..SELF_STOP_CADENCES {
        f.service
            .publish_liveness(NOW)
            .await
            .expect("a Liveness every relay refused is still a report");
    }

    let (status, response, doc) = exchange(
        &f,
        (
            "status",
            "stopped",
            "The same primary after five Liveness cadences that reached no relay of its own \
             Relay Set (spec §7.1, \"Primary self-stop\"): `state` is the one word `stopped` and \
             there is NO `access`, because the workload's container is off. Nothing about the \
             LEASE ended — `role` is still `primary`, `expires_at` is unchanged, and `.extend` \
             still buys another interval — and the workload starts again if the relays come back \
             before any member of the Standby Set has claimed the workload id. The request is \
             the same question as `status.primary`, asked with a longer TTL so that it is a \
             different event (§6.1).",
        ),
        &route("status"),
        "/status",
        envelope(&f.about_request(&f.tenant, "status", PRIMARY_WORKLOAD, TTL + 30)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["role"], "primary");
    assert_eq!(response["state"], "stopped");
    assert!(response.get("access").is_none(), "{}", response);
    golden("status.stopped.json", doc);

    // ── any other index, on `.standby`: a Warm Standby reserves ──────────
    let g = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let standby_set = [keys(PRIMARY_SECRET).public_key(), g.provider_pubkey()];
    let content = standby_set_content(STANDBY_SET_WORKLOAD, &standby_set);
    let event = lease_request(&g.tenant, &standby_set, "spawn", &content, NOW, NOW + TTL);
    let (status, response, doc) = exchange(
        &g,
        (
            "spawn",
            "standby",
            "The same kind of request at the member it makes a WARM STANDBY: this provider's key \
             is at index 1 of the `standby_set`, so the spawn must arrive on `.standby` and is \
             paid at the listing's `standby_price`. The provider reserves capacity and sets \
             `expires_at` the same way a running lease does, and starts NOTHING: `role` is \
             `standby` and there is no `access` at all, because there is nowhere to reach until a \
             Takeover (spec §7.1). Index 0 here is `constants.primary_provider`, the primary \
             whose Liveness this standby watches and whom `directory.takeover` claims the same \
             workload id from.",
        ),
        &route("warm.v1.standby"),
        "/listings/warm/v1/standby",
        envelope(&event),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["role"], "standby");
    assert!(response.get("access").is_none(), "{}", response);
    golden("spawn.standby.json", doc);

    let (status, response, doc) = exchange(
        &g,
        (
            "status",
            "reserved",
            "Status of that Warm Standby before Takeover (spec §6.5, §6.7): `state` is the one \
             word `reserved`, `role` is `standby`, and there is NO `access` — the capacity is \
             held and paid for, and nothing is running to reach. The reservation counts against \
             the listing's capacity exactly as a running lease does, so Liveness `available` and \
             `availability` both subtract it.",
        ),
        &route("status"),
        "/status",
        envelope(&g.about_request(&g.tenant, "status", STANDBY_SET_WORKLOAD, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["state"], "reserved");
    assert_eq!(response["role"], "standby");
    assert!(response.get("access").is_none(), "{}", response);
    golden("status.reserved.json", doc);
}

/// The workload of the set the fixture provider LOSES in: a third id, since
/// a set is a workload id and this set has three members — the primary
/// provider, the fixture provider and the standby provider.
const LOST_WORKLOAD: u8 = 0xa2;

/// The primary provider's Profile, as the relay holds it (spec §4.1): the
/// Relay Set and the cadence the fixture provider watches it by. Never a
/// fixture itself — it is signed by a peer, not by the provider under test.
fn primary_profile() -> Event {
    let content = ProfileContent {
        ilp_address: "g.primary".to_string(),
        connector_url: "http://connector.primary.example:3300/ilp".to_string(),
        connector_seal_key: CONNECTOR_SEAL_KEY.to_string(),
        relays: vec![RELAY.to_string()],
        settlement: vec![],
        isolation: "shared-kernel".to_string(),
        hidden: false,
        host: Some("198.51.100.9".to_string()),
        liveness_cadence_s: LIVENESS_CADENCE_S,
    };
    EventBuilder::new(
        Kind::Custom(K_PROFILE),
        serde_json::to_string(&content).unwrap(),
    )
    .tags([Tag::parse(["L", TOON_LABEL]).unwrap()])
    .custom_created_at(Timestamp::from(NOW - 1000))
    .sign_with_keys(&keys(PRIMARY_SECRET))
    .unwrap()
}

/// Drive `f` through one Takeover of `workload` (spec §7.1): the primary
/// provider is silent on its one relay from a cadence before `NOW`, so the
/// Takeover is announced AT `NOW` — the same event `directory.takeover`
/// shows — and settled two cadences later. The clock ends back at `NOW`.
async fn take_over(f: &Fixture, workload: u8) {
    let primary = keys(PRIMARY_SECRET).public_key();
    f.directory.seed_profile(primary_profile());
    f.directory
        .set_liveness_on(primary, &[RELAY], LivenessState::Absent);
    for at in [NOW - LIVENESS_CADENCE_S, NOW, NOW + 2 * LIVENESS_CADENCE_S] {
        f.clock.set(at);
        f.service.watch_primaries(at).await;
    }
    f.clock.set(NOW);

    let published = f.directory.takeover_publications();
    assert_eq!(published.len(), 1, "one Takeover, at NOW: {published:?}");
    assert_eq!(
        published[0].0.id,
        takeover_event(&workload_id(workload), &primary, &f.provider, NOW)
            .unwrap()
            .id,
        "the claim is the one the Takeover fixture shows, byte for byte"
    );
}

/// The two ways a Takeover settles (spec §7.1 steps 3–5), each as `status`
/// then reports it: the fixture provider WON the race for the set of
/// `spawn.standby` — it was the only claimant — and runs the workload; and
/// it LOST a second set's race to the standby provider, whose claim was
/// earlier, and stays reserved watching the winner.
#[tokio::test]
async fn a_status_per_takeover_outcome() {
    // ── won: the standby of `spawn.standby`, after its primary went silent ──
    let f = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let set = [keys(PRIMARY_SECRET).public_key(), f.provider_pubkey()];
    let content = standby_set_content(STANDBY_SET_WORKLOAD, &set);
    let event = lease_request(&f.tenant, &set, "spawn", &content, NOW, NOW + TTL);
    let (status, response) = post(&f.app, "/listings/warm/v1/standby", envelope(&event)).await;
    assert_eq!(status, StatusCode::OK, "{}", response);

    take_over(&f, STANDBY_SET_WORKLOAD).await;

    let (status, response, doc) = exchange(
        &f,
        (
            "status",
            "won",
            "Status of the Warm Standby of `spawn.standby` after it WON the Takeover of its \
             workload (spec §6.5, §7.1 steps 3–4). The primary provider went silent on its \
             Relay Set; this provider announced `directory.takeover` at `now`, waited the \
             settle window of two cadences, found its own claim the earliest from any \
             member of the `standby_set`, and started the workload from the image exactly \
             as a spawn would, with no state carried over (ADR 0010). `state` is now \
             `running` and `access` is where the workload runs; `role` is still `standby`, \
             because a role is a position in the set and never changes; and `takeover.winner` \
             names this provider. `expires_at` is the reservation's own: winning buys no \
             time, so a full-price `.extend` is due before it or the sweep ends the lease. \
             `.standby.extend` is refused `not_standby` from here on.",
        ),
        &route("status"),
        "/status",
        envelope(&f.about_request(&f.tenant, "status", STANDBY_SET_WORKLOAD, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["state"], "running");
    assert_eq!(response["role"], "standby");
    assert!(response.get("access").is_some(), "{}", response);
    assert_eq!(response["takeover"]["winner"], f.provider_pubkey().to_hex());
    golden("status.won.json", doc);

    // ── lost: a set of three, where the standby provider claimed first ──
    let g = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let winner = keys(STANDBY_SECRET);
    let set = [
        keys(PRIMARY_SECRET).public_key(),
        g.provider_pubkey(),
        winner.public_key(),
    ];
    let content = standby_set_content(LOST_WORKLOAD, &set);
    let event = lease_request(&g.tenant, &set, "spawn", &content, NOW, NOW + TTL);
    let (status, response) = post(&g.app, "/listings/warm/v1/standby", envelope(&event)).await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    // The relay already holds the standby provider's claim, one second
    // earlier than this provider's will be.
    g.directory.seed_takeover(
        takeover_event(
            &workload_id(LOST_WORKLOAD),
            &keys(PRIMARY_SECRET).public_key(),
            &winner,
            NOW - 1,
        )
        .unwrap(),
    );

    take_over(&g, LOST_WORKLOAD).await;

    let (status, response, doc) = exchange(
        &g,
        (
            "status",
            "lost",
            "Status of a Warm Standby that LOST a Takeover (spec §6.5, §7.1 steps 3 and 5). \
             This provider is index 1 of a set of three; the standby provider at index 2 \
             announced one second earlier, so its claim won. The lease stays `reserved` with \
             no `access` — nothing runs here, and `.standby.extend` still pays it while \
             `.extend` is still `not_running` — and `takeover.winner` names the member the \
             workload went to, which is the whole of what a tenant asking THIS member needs \
             to know. From the next watchdog step on, this provider watches the winner's \
             Liveness on the winner's own Relay Set, so the set survives a second failure.",
        ),
        &route("status"),
        "/status",
        envelope(&g.about_request(&g.tenant, "status", LOST_WORKLOAD, TTL)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    assert_eq!(response["state"], "reserved");
    assert_eq!(response["role"], "standby");
    assert!(response.get("access").is_none(), "{}", response);
    assert_eq!(response["takeover"]["winner"], winner.public_key().to_hex());
    golden("status.lost.json", doc);
}

// ── Milestone 2: what a publisher signs, and the three forms of `image` ──────

/// The image the Milestone 2 fixtures publish, `<publisher npub>/web:1.0`:
/// a real, loadable OCI image built here from fixed bytes — a manifest, a
/// config and two layers. The base layer is the kind a publisher leaves
/// upstream (`oci`, "registry-1.docker.io/library/alpine" for the story);
/// the application layer, the config and the manifest exist nowhere else
/// and are in the TOON store, each named by a Blob Record. That is the
/// point of having two source types at all: a publisher pays only for what
/// exists nowhere else (spec §8.1). Because the bytes are real, the
/// `spawn_image.registry_entry` fixture is a spawn that RUNS, fetched
/// through this very entry.
const IMAGE_NAME: &str = "web";
const IMAGE_TAG: &str = "1.0";
const TEMPLATE_NAME: &str = "static-site";
const UPSTREAM_REGISTRY: &str = "registry-1.docker.io";
const UPSTREAM_REPOSITORY: &str = "library/alpine";

const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
/// Uncompressed, so a layer's diff id IS its digest and a reader can check
/// the config's `rootfs.diff_ids` against the manifest by eye.
const LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

/// The TOON store part size the sandbox uses: 102,400 bytes, which fits the
/// free tier's 107,520-byte data item (spec §8.2, Appendix A).
const PART_SIZE: u64 = 102_400;

/// Transaction ids of the uploads, readable on purpose (each is the base64
/// of what it holds). A real txid is 43 characters of Arweave base64url.
const LAYER_RECORD_TXID: &str = "dG9vbi1zdG9yZS1ibG9iLXJlY29yZC10eGlk";
const LAYER_PART_TXIDS: [&str; 3] = [
    "dG9vbi1zdG9yZS1wYXJ0LW9uZQ",
    "dG9vbi1zdG9yZS1wYXJ0LXR3bw",
    "dG9vbi1zdG9yZS1wYXJ0LXRocmVl",
];
const CONFIG_RECORD_TXID: &str = "dG9vbi1zdG9yZS1jb25maWctcmVjb3Jk";
const CONFIG_PART_TXIDS: [&str; 1] = ["dG9vbi1zdG9yZS1jb25maWctcGFydA"];
const MANIFEST_RECORD_TXID: &str = "dG9vbi1zdG9yZS1tYW5pZmVzdC1yZWNvcmQ";
const MANIFEST_PART_TXIDS: [&str; 1] = ["dG9vbi1zdG9yZS1tYW5pZmVzdC1wYXJ0"];
/// The base layer is in the store TOO, though the entry cites its upstream
/// registry instead (§8.1: a publisher pays for what exists nowhere else).
/// Somebody else uploaded it and published the Blob Record, which is what
/// makes the same image spawnable by `{ digest }` alone: §8.4 step 3 needs
/// a record for EVERY blob, base layers included.
const BASE_RECORD_TXID: &str = "dG9vbi1zdG9yZS1iYXNlLXJlY29yZA";
const BASE_PART_TXIDS: [&str; 1] = ["dG9vbi1zdG9yZS1iYXNlLXBhcnQ"];

fn publisher() -> Keys {
    keys(PUBLISHER_SECRET)
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// One file in a tar, with every header field fixed, so the bytes are the
/// same on every run.
fn tar_of(name: &str, content: &[u8]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(&mut header, name, content).unwrap();
    tar.into_inner().unwrap()
}

/// The base layer: what an upstream image would contribute. Tiny.
fn base_layer_bytes() -> Vec<u8> {
    tar_of("etc/motd", b"a base layer, still upstream\n")
}

/// The application layer: long enough to need three parts at `PART_SIZE`
/// — two full and a short last one — so a reader sees that `part_size` is
/// not the last part's size and that the sizes sum to the blob's.
fn app_layer_bytes() -> Vec<u8> {
    let line = b"<p>served from the TOON store</p>\n";
    let content: Vec<u8> = line.iter().cycle().take(233_472).copied().collect();
    tar_of("srv/www/index.html", &content)
}

fn config_bytes() -> Vec<u8> {
    json!({
        "architecture": "amd64",
        "os": "linux",
        "config": { "Cmd": ["/bin/sh"] },
        "rootfs": {
            "type": "layers",
            "diff_ids": [digest_of(&base_layer_bytes()), digest_of(&app_layer_bytes())]
        }
    })
    .to_string()
    .into_bytes()
}

fn manifest_bytes() -> Vec<u8> {
    let base = base_layer_bytes();
    let app = app_layer_bytes();
    let config = config_bytes();
    json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": { "mediaType": CONFIG_MEDIA_TYPE, "digest": digest_of(&config), "size": config.len() },
        "layers": [
            { "mediaType": LAYER_MEDIA_TYPE, "digest": digest_of(&base), "size": base.len() },
            { "mediaType": LAYER_MEDIA_TYPE, "digest": digest_of(&app), "size": app.len() },
        ]
    })
    .to_string()
    .into_bytes()
}

/// The image's content address: its manifest's digest.
fn image_digest() -> String {
    digest_of(&manifest_bytes())
}

/// `30434:<publisher>:<name>:<tag>` — the coordinate a spawn or a Template
/// names an Image Registry entry by.
fn entry_address() -> String {
    format!(
        "{}:{}:{}:{}",
        K_IMAGE,
        publisher().public_key().to_hex(),
        IMAGE_NAME,
        IMAGE_TAG
    )
}

fn registry_entry_ref() -> RegistryEntryRef {
    RegistryEntryRef {
        address: entry_address(),
        relay: RELAY.to_string(),
    }
}

/// A Blob Record for `bytes` split at `PART_SIZE`, its parts uploaded
/// under `part_txids` (one per part, in order).
fn blob_record_for(bytes: &[u8], part_txids: &[&str]) -> BlobRecordContent {
    let chunks: Vec<&[u8]> = bytes.chunks(PART_SIZE as usize).collect();
    assert_eq!(chunks.len(), part_txids.len(), "one txid per part");
    BlobRecordContent {
        digest: digest_of(bytes),
        size: bytes.len() as u64,
        part_size: PART_SIZE,
        parts: chunks
            .iter()
            .zip(part_txids)
            .map(|(chunk, txid)| BlobPart {
                txid: txid.to_string(),
                sha256: sha256_hex(chunk),
                size: chunk.len() as u64,
            })
            .collect(),
    }
}

/// The application layer's Blob Record: the one `registry.blob_record`
/// shows.
fn blob_record_content() -> BlobRecordContent {
    blob_record_for(&app_layer_bytes(), &LAYER_PART_TXIDS)
}

/// Every blob in the TOON store, with the txid of its record's own upload
/// and of each part: what the fixture gateway serves, and what the entry's
/// `toon-store` sources cite.
fn stored_blobs() -> Vec<(BlobRecordContent, &'static str, Vec<u8>)> {
    vec![
        (
            blob_record_for(&manifest_bytes(), &MANIFEST_PART_TXIDS),
            MANIFEST_RECORD_TXID,
            manifest_bytes(),
        ),
        (
            blob_record_for(&config_bytes(), &CONFIG_PART_TXIDS),
            CONFIG_RECORD_TXID,
            config_bytes(),
        ),
        (blob_record_content(), LAYER_RECORD_TXID, app_layer_bytes()),
        (
            blob_record_for(&base_layer_bytes(), &BASE_PART_TXIDS),
            BASE_RECORD_TXID,
            base_layer_bytes(),
        ),
    ]
}

/// Every stored blob's Blob Record as its uploader published it: signed
/// with zero aux randomness, so the one the gateway serves and the one a
/// relay answers an `#x` lookup with are the same bytes.
fn stored_blob_record_events() -> Vec<Event> {
    stored_blobs()
        .iter()
        .map(|(record, ..)| {
            with_reproducible_sig(
                &blob_record_event(record, &publisher(), NOW).unwrap(),
                &publisher(),
            )
        })
        .collect()
}

/// A digest nobody has uploaded: no Blob Record on any relay, no entry
/// listing it, no registry holding it. What `availability.image_unresolved`
/// asks about.
fn unstored_digest() -> String {
    digest_of(b"an image nobody has ever uploaded")
}

fn image_entry_content() -> ImageEntryContent {
    let toon_store = |txid: &str| BlobSource::ToonStore {
        blob_record_txid: txid.to_string(),
    };
    ImageEntryContent {
        digest: image_digest(),
        media_type: MANIFEST_MEDIA_TYPE.to_string(),
        blobs: vec![
            EntryBlob {
                digest: image_digest(),
                size: manifest_bytes().len() as u64,
                media_type: MANIFEST_MEDIA_TYPE.to_string(),
                source: toon_store(MANIFEST_RECORD_TXID),
            },
            EntryBlob {
                digest: digest_of(&config_bytes()),
                size: config_bytes().len() as u64,
                media_type: CONFIG_MEDIA_TYPE.to_string(),
                source: toon_store(CONFIG_RECORD_TXID),
            },
            EntryBlob {
                digest: digest_of(&base_layer_bytes()),
                size: base_layer_bytes().len() as u64,
                media_type: LAYER_MEDIA_TYPE.to_string(),
                source: BlobSource::Oci {
                    registry: UPSTREAM_REGISTRY.to_string(),
                    repository: UPSTREAM_REPOSITORY.to_string(),
                },
            },
            EntryBlob {
                digest: digest_of(&app_layer_bytes()),
                size: app_layer_bytes().len() as u64,
                media_type: LAYER_MEDIA_TYPE.to_string(),
                source: toon_store(LAYER_RECORD_TXID),
            },
        ],
    }
}

/// The entry as published: signed by the publisher with zero aux
/// randomness, so the event in `registry.image_entry` is byte-for-byte the
/// one the fixture provider resolves the spawn through.
fn image_entry() -> Event {
    with_reproducible_sig(
        &image_entry_event(
            IMAGE_NAME,
            IMAGE_TAG,
            &image_entry_content(),
            &publisher(),
            NOW,
        )
        .unwrap(),
        &publisher(),
    )
}

/// The TOON store as the fixture provider reads it: every record and every
/// part at `/raw/<txid>`; and the upstream registry serving the base layer
/// by digest.
async fn mount_image_bytes(gateway: &MockServer, registry: &MockServer) {
    for ((record, record_txid, bytes), event) in
        stored_blobs().into_iter().zip(stored_blob_record_events())
    {
        mount_raw(gateway, record_txid, serde_json::to_vec(&event).unwrap()).await;
        for (part, chunk) in record.parts.iter().zip(bytes.chunks(PART_SIZE as usize)) {
            mount_raw(gateway, &part.txid, chunk.to_vec()).await;
        }
    }
    let base = base_layer_bytes();
    Mock::given(method("GET"))
        .and(path(format!(
            "/v2/{}/blobs/{}",
            UPSTREAM_REPOSITORY,
            digest_of(&base)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(base))
        .mount(registry)
        .await;
}

async fn mount_raw(gateway: &MockServer, txid: &str, bytes: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(format!("/raw/{}", txid)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(gateway)
        .await;
}

fn template_content() -> TemplateContent {
    TemplateContent {
        version: 1,
        image: TemplateImage {
            digest: image_digest(),
            registry_entry: Some(registry_entry_ref()),
        },
        ports: vec![PortRequest {
            container_port: 8080,
            protocol: Protocol::Tcp,
        }],
        data_path: Some("/data".to_string()),
        env_fixed: BTreeMap::from([("MODE".to_string(), "production".to_string())]),
        env_tenant: vec!["SITE_TITLE".to_string()],
        min_resources: Some(Resources {
            cpu_millicores: 500,
            memory_mb: 256,
            storage_gb: 4,
            gpu: None,
        }),
    }
}

/// `30436:<publisher>:<name>` — what a spawn's informational `template`
/// field carries (spec §6.2).
fn template_address() -> String {
    format!(
        "{}:{}:{}",
        K_TEMPLATE,
        publisher().public_key().to_hex(),
        TEMPLATE_NAME
    )
}

#[test]
fn one_publisher_event_per_milestone_2_kind() {
    let publisher = publisher();
    golden(
        "registry.image_entry.json",
        event_fixture(
            "registry",
            "image_entry",
            "An Image Registry entry (spec §8.1), signed by the PUBLISHER and not by any \
             provider: `d` is `<name>:<tag>`, `x` is the image digest's hex, and `blobs` \
             lists EVERY blob reachable from `digest` — the manifest, its config and both \
             layers — with the source of each. Both source types are shown: a base layer \
             still upstream (`oci`) and the manifest, config and application layer in the \
             TOON store (`toon-store`, each naming its Blob Record's own upload). The \
             canonical name of this image is `<publisher npub>/web:1.0`, and its bytes are \
             real: `spawn_image.registry_entry` is a spawn fetched through this entry.",
            "K_IMAGE",
            &image_entry(),
        ),
    );

    let record = with_reproducible_sig(
        &blob_record_event(&blob_record_content(), &publisher, NOW).unwrap(),
        &publisher,
    );
    golden(
        "registry.blob_record.json",
        event_fixture(
            "registry",
            "blob_record",
            "A Blob Record (spec §8.2) for the application layer the entry puts in the TOON \
             store: `d` and `x` both name the blob's digest, and `parts` is the ORDERED \
             list of uploads a reader concatenates and checks against it — each part's \
             `sha256` is the real hash of that slice of the layer. `part_size` is what \
             every part but the last has (102,400 bytes, the sandbox's free-tier size); \
             the last is short, and the sizes sum to `size`.",
            "K_BLOB",
            &record,
        ),
    );

    let template = with_reproducible_sig(
        &template_event(TEMPLATE_NAME, &template_content(), &publisher, NOW).unwrap(),
        &publisher,
    );
    golden(
        "registry.template.json",
        event_fixture(
            "registry",
            "template",
            "A Template (spec §8.3): `d` is the template name, and the content names the \
             image by content address plus the Image Registry entry that lists its blobs. \
             It GRANTS NOTHING — there is no capability field and there never will be \
             (ADR 0004) — and the TENANT expands it into a spawn; a provider never reads \
             one. No `x` tag: a Template is found by name, and the digest it carries is the \
             image's, not its own.",
            "K_TEMPLATE",
            &template,
        ),
    );
}

fn spawn_content_with(seed: u8, image: ImageRef, template: Option<String>) -> Value {
    let mut content = spawn_content(seed);
    content["workload_id"] = json!(workload_id(seed));
    content["image"] = serde_json::to_value(image).unwrap();
    match template {
        Some(t) => content["template"] = json!(t),
        None => {
            content.as_object_mut().unwrap().remove("template");
        }
    }
    content
}

#[tokio::test]
async fn one_spawn_per_image_form() {
    let f = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let spawn_route = route("basic.v1.spawn");
    let spawn_path = "/listings/basic/v1/spawn";

    // Form 1: `{ reference, digest }` — the only form this provider can
    // fetch today, and the one that runs. It also carries the informational
    // `template`, which the provider parses and never acts on.
    let content = spawn_content_with(
        0xd1,
        ImageRef::upstream(REFERENCE, valid_digest()),
        Some(template_address()),
    );
    let event = lease_request(
        &f.tenant,
        &[f.provider_pubkey()],
        "spawn",
        &content,
        NOW,
        NOW + TTL,
    );
    let (status, response, mut doc) = exchange(
        &f,
        (
            "spawn_image",
            "reference",
            "Form 1 of §6.2's `image`: `{ reference, digest }`, pulled as \
             `reference@digest` from an upstream OCI registry. The spawn also carries \
             `template`, the `30436:<pubkey>:<name>` a tenant expanded its values from: the \
             provider parses it, never reads it, and runs exactly what the other fields \
             say (ADR 0004).",
        ),
        &spawn_route,
        spawn_path,
        envelope(&event),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    doc["image"] = content["image"].clone();
    doc["spawn_content"] = content.clone();
    golden("spawn_image.reference.json", doc);

    // Form 2: `{ digest, registry_entry }`, and it RUNS: the entry in
    // `registry.image_entry` is read from the relay, the manifest and the
    // config are resolved through its sources, every layer is fetched and
    // verified, and the image is loaded into the backend and started by
    // its id.
    let content = spawn_content_with(
        0xd2,
        ImageRef::from_registry(image_digest(), entry_address(), RELAY),
        None,
    );
    let event = lease_request(
        &f.tenant,
        &[f.provider_pubkey()],
        "spawn",
        &content,
        NOW,
        NOW + TTL,
    );
    let (status, response, mut doc) = exchange(
        &f,
        (
            "spawn_image",
            "registry_entry",
            "Form 2 of §6.2's `image`: `{ digest, registry_entry }`. The entry at `address` \
             (`registry.image_entry`) lists every blob and where its bytes are (§8.1); \
             `relay` is a hint for finding it, not an authority — the entry is addressed \
             by its signer. The provider resolves the image through the entry (§8.4): the \
             manifest and config for `availability`, then every layer for the paid spawn, \
             each blob fetched from the source the entry names — the Blob Record and its \
             parts from the TOON store, the base layer from the upstream registry by \
             digest — verified against its digest, cached, assembled into an OCI layout, \
             loaded into the backend and run by image id. Same success shape as form 1.",
        ),
        &spawn_route,
        spawn_path,
        envelope(&event),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    doc["image"] = content["image"].clone();
    doc["spawn_content"] = content.clone();
    golden("spawn_image.registry_entry.json", doc);

    // Form 3: `{ digest }` alone, and it RUNS — over a provider of its own,
    // so that nothing is in the blob cache and the image really is resolved
    // through the Relay Set rather than out of what form 2 left behind.
    // The image is the same one; it names neither the entry nor the relay
    // the entry is on.
    let bare = fixture_provider(ImagePolicyConfig::default(), stub_registry().await).await;
    let content = spawn_content_with(0xd3, ImageRef::by_digest(image_digest()), None);
    let event = lease_request(
        &bare.tenant,
        &[bare.provider_pubkey()],
        "spawn",
        &content,
        NOW,
        NOW + TTL,
    );
    let (status, response, mut doc) = exchange(
        &bare,
        (
            "spawn_image",
            "digest_only",
            "Form 3: `{ digest }` alone, and it runs. The image names no entry and no \
             relay, so every blob — the manifest, the config and both layers — is found \
             by asking this provider's own Relay Set for the Blob Records tagged `#x = \
             <hex>`, whoever signed them (§8.4 step 3). Signers are not trusted: each \
             part is checked against its recorded sha256 and size and each blob against \
             the digest that was asked for, so a wrong record is discarded and the next \
             is tried (ADR 0006). Anyone who knows a digest someone has uploaded can \
             spawn it. Same success shape as forms 1 and 2.",
        ),
        &spawn_route,
        spawn_path,
        envelope(&event),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", response);
    doc["image"] = content["image"].clone();
    doc["spawn_content"] = content.clone();
    golden("spawn_image.digest_only.json", doc);

    // What a bare digest is refused for is a blob nothing can serve — and
    // the free route is where a tenant should meet that: `availability`
    // answers it for nothing, a spawn bills for it (ADR 0003).
    let (status, response, doc) = exchange(
        &bare,
        (
            "availability",
            "image_unresolved",
            "Availability for an image named by digest alone that this provider cannot \
             resolve: no relay in its Relay Set holds a Blob Record for the digest, so \
             there is nowhere for its bytes to come from. The free route runs the same \
             §6.2 step 5 a paid spawn does — down the same chain, cache then the image's \
             own sources then the Relay Set — so a tenant learns this BEFORE paying, \
             instead of buying the identical `refused_image`. A digest the Relay Set does \
             know is resolved and runs: `spawn_image.digest_only`.",
        ),
        &route("availability"),
        "/availability",
        json!({
            "listing": "basic",
            "version": 1,
            "image": ImageRef::by_digest(unstored_digest()),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["would_run"], false);
    assert_eq!(error_of(&response), "refused_image");
    golden("availability.image_unresolved.json", doc);
}
