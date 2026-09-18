//! The Provider Directory, driven through the `Directory` port: the provider
//! is asked to publish and the fake reads back what it was handed. Assertions
//! are on the events — kind, tags, content and signature — never on the
//! provider's internal state.
//!
//! The one lease this file spawns goes in through the HTTP router with the
//! faked `ComputeBackend`, exactly as a paying tenant's would, because that is
//! the only honest way to make `available` drop by one. That spawn is checked
//! against the image policy like any other, so the harness points the
//! provider's `image_policy.registry_url_override` at a `wiremock` stub of a
//! registry (`common::stub_registry`) and names the digest that stub answers
//! with (`common::valid_digest`).

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nostr_sdk::{Keys, PublicKey};
use serde_json::{json, Value};
use tower::ServiceExt;

use common::harness::RequestSpec;
use common::{has_tag, stub_registry, valid_digest, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::directory_events::{
    ListingContent, LivenessContent, ProfileContent, Settlement, LIVENESS_EXPIRY_CADENCES,
};
use toon_provider::nostr::kinds::{K_LISTING, K_LIVENESS, K_PROFILE, TOON_LABEL};
use toon_provider::nostr::wire::{ImageRef, PortRequest, Protocol, Resources, SpawnContent};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::{router, Clock, Directory, Listing, ProviderConfig, ProviderService};
use wiremock::MockServer;

const NOW: u64 = 1_700_000_000;
const INTERVAL: u64 = 3600;
const CADENCE: u64 = 30;
const PUBLIC_IP: &str = "203.0.113.7";
// An uncompressed secp256k1 public key, the shape a connector's /ilp
// identity reports, copied verbatim so a tenant's comparison is byte-for-byte.
const SEAL_KEY: &str = "0x04325b06f4bcb438204ab86a36a715fdf409552da5cdc7cd28301b08088ce7c3a1bf4289f62ba89a707ed8d7db66b03cb2881ea5934e35f2d600c4cd7067ed0188";
const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdlbm91Z2hmb3JhdGVzdGtleQ tenant@example";

struct Harness {
    app: axum::Router,
    service: ProviderService,
    directory: Arc<FakeDirectory>,
    clock: Arc<FakeClock>,
    provider: PublicKey,
    /// Kept alive only so the stubbed registry keeps answering for as long as
    /// this harness's app might still resolve an image; never read otherwise.
    _registry: MockServer,
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
        standby_price: None,
        // An `x-` capability, not `docker`: this backend refuses to publish a
        // grant of `docker` or `nesting` at all until it supplies one (spec
        // §4.4, `capabilities::grant_refusal`), and what this file tests is the
        // `t` tag, which is the same either way.
        capabilities: vec!["x-ci-sandbox".to_string()],
        capacity,
    }
}

fn settlement() -> Vec<Settlement> {
    vec![
        Settlement {
            chain: "solana".to_string(),
            token: "H8HSreUF2s8r8hem4qMttE3bWYCpFuh71jbuos5bA77H".to_string(),
            decimals: 6,
        },
        Settlement {
            chain: "evm:31337".to_string(),
            token: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
            decimals: 6,
        },
    ]
}

fn config(listings: Vec<Listing>, provider_key: &str, state_path: String) -> ProviderConfig {
    ProviderConfig {
        public_ip: Some(PUBLIC_IP.to_string()),
        nostr_private_key: provider_key.to_string(),
        ilp_address: "g.acme".to_string(),
        relay_set: vec![
            "ws://relay-one:7100".to_string(),
            "ws://relay-two:7100".to_string(),
        ],
        connector_url: "https://c.acme.example/ilp".to_string(),
        connector_seal_key: SEAL_KEY.to_string(),
        settlement: settlement(),
        isolation: "shared-kernel".to_string(),
        liveness_cadence_s: CADENCE,
        geohash: Some("u4pruy".to_string()),
        listings,
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: state_path,
        ..ProviderConfig::default()
    }
}

async fn harness_with(listings: Vec<Listing>) -> Harness {
    let keys = Keys::generate();
    let provider_key = keys.secret_key().to_secret_hex();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();

    let registry = stub_registry().await;
    let mut cfg = config(listings, &provider_key, state_path);
    cfg.image_policy = ImagePolicyConfig {
        registry_url_override: Some(registry.uri()),
        ..ImagePolicyConfig::default()
    };

    let clock = FakeClock::at(NOW);
    let directory = FakeDirectory::new();
    let service = ProviderService::with_backend_clock_and_directory(
        cfg,
        FakeBackend::new(),
        clock.clone(),
        directory.clone(),
    )
    .unwrap();

    Harness {
        app: router(service.app_state()),
        service,
        directory,
        clock,
        provider: keys.public_key(),
        _registry: registry,
    }
}

async fn harness() -> Harness {
    harness_with(vec![listing("basic", 1, 4)]).await
}

/// Every cell of a tag, as the relay sees it.
fn tag_cells(event: &nostr_sdk::Event) -> Vec<Vec<String>> {
    event.tags.iter().map(|t| t.clone().to_vec()).collect()
}

// ── the Provider Profile ────────────────────────────────────────────────────

#[tokio::test]
async fn the_profile_carries_everything_a_tenant_needs_to_pay_this_provider() {
    let h = harness().await;
    h.service.publish_directory().await.unwrap();

    let profiles = h.directory.of_kind(K_PROFILE);
    assert_eq!(
        profiles.len(),
        1,
        "one Provider Profile, not one per listing"
    );
    let profile = &profiles[0];

    assert_eq!(profile.pubkey, h.provider);
    profile
        .verify()
        .expect("the Profile is signed by the provider's Nostr key");
    assert_eq!(profile.created_at.as_u64(), NOW);

    let content: ProfileContent = serde_json::from_str(&profile.content).unwrap();
    assert_eq!(content.ilp_address, "g.acme");
    assert_eq!(content.connector_url, "https://c.acme.example/ilp");
    assert_eq!(content.connector_seal_key, SEAL_KEY);
    assert_eq!(
        content.relays,
        vec!["ws://relay-one:7100", "ws://relay-two:7100"]
    );
    assert_eq!(content.settlement, settlement());
    assert_eq!(content.isolation, "shared-kernel");
    assert!(!content.hidden, "a provider that did not set hidden = true");
    assert_eq!(content.host.as_deref(), Some(PUBLIC_IP));
    assert_eq!(content.liveness_cadence_s, CADENCE);

    assert!(has_tag(profile, &["L", TOON_LABEL]));
}

// ── Listings ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn one_listing_event_per_configured_listing() {
    let h = harness_with(vec![listing("basic", 1, 4), listing("large", 1, 2)]).await;
    h.service.publish_directory().await.unwrap();

    let names: Vec<String> = h
        .directory
        .of_kind(K_LISTING)
        .iter()
        .map(|e| e.tags.identifier().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["basic", "large"]);
}

#[tokio::test]
async fn a_listing_names_its_tier_its_profile_and_everything_a_relay_filters_on() {
    let mut tier = listing("basic", 3, 4);
    tier.resources.gpu = Some("rtx4090".to_string());
    tier.capabilities = vec!["x-ci-sandbox".to_string(), "x-lxc".to_string()];
    let h = harness_with(vec![tier]).await;
    h.service.publish_directory().await.unwrap();

    let listings = h.directory.of_kind(K_LISTING);
    assert_eq!(listings.len(), 1);
    let event = &listings[0];

    assert_eq!(event.pubkey, h.provider);
    event
        .verify()
        .expect("the Listing is signed by the provider's Nostr key");

    // The `d` tag is the listing NAME, stable across versions: a new version
    // replaces the event rather than accumulating (ADR 0009).
    assert_eq!(event.tags.identifier(), Some("basic"));
    assert!(has_tag(
        event,
        &["a", &format!("{}:{}:", K_PROFILE, h.provider.to_hex())]
    ));
    assert!(has_tag(event, &["L", TOON_LABEL]));
    assert!(has_tag(
        event,
        &["l", "isolation:shared-kernel", TOON_LABEL]
    ));
    assert!(has_tag(event, &["l", "arch:amd64", TOON_LABEL]));
    assert!(has_tag(event, &["l", "gpu:rtx4090", TOON_LABEL]));
    assert!(has_tag(event, &["t", "x-ci-sandbox"]));
    assert!(has_tag(event, &["t", "x-lxc"]));
    assert!(has_tag(event, &["g", "u4pruy"]));

    // Numbers stay in content; a relay cannot filter on them anyway.
    let content: ListingContent = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content.version, 3);
    assert_eq!(content.arch, "amd64");
    assert_eq!(content.lease_interval_s, INTERVAL);
    assert_eq!(content.price, 1000);
    assert_eq!(content.capabilities, vec!["x-ci-sandbox", "x-lxc"]);
    assert_eq!(content.resources.cpu_millicores, 500);
    assert_eq!(content.resources.memory_mb, 256);
    assert_eq!(content.resources.storage_gb, 4);
    assert_eq!(content.resources.gpu.as_deref(), Some("rtx4090"));
    assert_eq!(
        content.standby_price, None,
        "this tier prices no Warm Standby, so it publishes no field at all"
    );
}

#[tokio::test]
async fn a_tier_that_prices_standbys_publishes_its_standby_price() {
    // Spec §4.2: `standby_price` is present only when the listing sells Warm
    // Standbys, and absent — never zero — when it does not, since zero would
    // read as "standbys are free".
    let h = harness_with(vec![Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }])
    .await;
    h.service.publish_directory().await.unwrap();

    let listings = h.directory.of_kind(K_LISTING);
    let content: ListingContent = serde_json::from_str(&listings[0].content).unwrap();
    assert_eq!(content.standby_price, Some(400));
    assert_eq!(content.price, 1000, "the full price is untouched");

    let raw: serde_json::Value = serde_json::from_str(&listings[0].content).unwrap();
    assert_eq!(raw["standby_price"], 400);
}

#[tokio::test]
async fn a_tier_with_no_gpu_publishes_no_gpu_label() {
    let h = harness().await;
    h.service.publish_directory().await.unwrap();

    let listings = h.directory.of_kind(K_LISTING);
    let cells = tag_cells(&listings[0]);
    assert!(
        !cells
            .iter()
            .any(|t| t.get(1).is_some_and(|v| v.starts_with("gpu:"))),
        "a tier with no GPU must not claim one: {cells:?}"
    );
}

#[tokio::test]
async fn a_provider_with_no_geohash_publishes_no_region_tag() {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(
        vec![listing("basic", 1, 4)],
        &keys.secret_key().to_secret_hex(),
        dir.keep()
            .join("leases.json")
            .to_string_lossy()
            .into_owned(),
    );
    cfg.geohash = None;
    let directory = FakeDirectory::new();
    let service = ProviderService::with_backend_clock_and_directory(
        cfg,
        FakeBackend::new(),
        FakeClock::at(NOW),
        directory.clone(),
    )
    .unwrap();
    service.publish_directory().await.unwrap();

    let cells = tag_cells(&directory.of_kind(K_LISTING)[0]);
    assert!(
        !cells.iter().any(|t| t[0] == "g"),
        "region is optional and must be absent when unset: {cells:?}"
    );
}

// ── Liveness ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn liveness_expires_five_cadences_out_and_counts_free_capacity() {
    let h = harness().await;
    h.service.publish_liveness(NOW).await.unwrap();

    let events = h.directory.of_kind(K_LIVENESS);
    assert_eq!(events.len(), 1);
    let event = &events[0];

    assert_eq!(event.pubkey, h.provider);
    event
        .verify()
        .expect("Liveness is signed by the provider's Nostr key");
    assert_eq!(event.created_at.as_u64(), NOW);
    assert!(has_tag(event, &["L", TOON_LABEL]));
    assert!(has_tag(
        event,
        &[
            "expiration",
            &(NOW + LIVENESS_EXPIRY_CADENCES * CADENCE).to_string()
        ]
    ));

    let content: LivenessContent = serde_json::from_str(&event.content).unwrap();
    assert_eq!(
        content.available,
        BTreeMap::from([("basic".to_string(), 4)]),
        "nothing is leased, so the whole capacity could start now"
    );
}

#[tokio::test]
async fn a_running_lease_drops_availability_by_one() {
    let h = harness().await;

    let (status, answer) = spawn_a_lease(&h).await;
    assert_eq!(status, StatusCode::OK, "{answer}");

    h.service.publish_liveness(NOW).await.unwrap();
    let content: LivenessContent =
        serde_json::from_str(&h.directory.of_kind(K_LIVENESS)[0].content).unwrap();
    assert_eq!(
        content.available,
        BTreeMap::from([("basic".to_string(), 3)])
    );
}

#[tokio::test]
async fn availability_returns_when_the_lease_expires() {
    let h = harness().await;
    spawn_a_lease(&h).await;

    h.clock.advance(INTERVAL + 1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    h.service.publish_liveness(h.clock.now()).await.unwrap();

    let liveness = h.directory.of_kind(K_LIVENESS);
    let content: LivenessContent = serde_json::from_str(&liveness.last().unwrap().content).unwrap();
    assert_eq!(
        content.available,
        BTreeMap::from([("basic".to_string(), 4)])
    );
}

#[tokio::test]
async fn every_version_of_a_tier_shares_one_availability_figure() {
    // Capacity is a slice of hardware, not a per-version allowance.
    let h = harness_with(vec![listing("basic", 1, 4), listing("basic", 2, 4)]).await;
    h.service.publish_liveness(NOW).await.unwrap();

    let content: LivenessContent =
        serde_json::from_str(&h.directory.of_kind(K_LIVENESS)[0].content).unwrap();
    assert_eq!(
        content.available,
        BTreeMap::from([("basic".to_string(), 4)])
    );
}

#[tokio::test]
async fn publishing_liveness_reports_which_relays_took_it() {
    // A primary that cannot reach a strict majority of its own Relay Set
    // for five cadences must stop its workload (spec §7.1); the count it
    // keeps is this report, relay by relay.
    let h = harness().await;
    let report = h.service.publish_liveness(NOW).await.unwrap();
    assert!(report.reached_every_relay());
    assert_eq!(report.accepted, vec!["wss://relay.example"]);

    h.directory.relay_always_refuses("ws://relay-two:7100");
    let report = h.service.publish_liveness(NOW + CADENCE).await.unwrap();
    assert_eq!(report.accepted, vec!["wss://relay.example"]);
    assert_eq!(
        report.failed.keys().collect::<Vec<_>>(),
        vec!["ws://relay-two:7100"]
    );
    assert!(!report.reached_every_relay());

    // A publisher that could not be reached asked no relay at all: that is
    // an error, not a report in which every relay happened to refuse.
    h.directory.fail_next_publish("publisher down");
    assert!(h.service.publish_liveness(NOW + 2 * CADENCE).await.is_err());
}

#[tokio::test]
async fn a_relay_that_refuses_a_write_does_not_stop_the_provider() {
    let h = harness().await;
    h.directory
        .fail_next_publish("relay refused: out of credit");

    // The Profile publication fails; the Listing still goes out, and nothing
    // propagates up to the caller — paid leases are running underneath. The
    // answer is `false`, which is what the publication loop retries on.
    let complete = h.service.publish_directory().await.unwrap();

    assert!(
        !complete,
        "an incomplete publication must ask to be retried"
    );
    assert!(h.directory.of_kind(K_PROFILE).is_empty());
    assert_eq!(h.directory.of_kind(K_LISTING).len(), 1);
}

#[tokio::test]
async fn a_relay_set_reached_only_in_part_asks_to_be_retried() {
    // Spec §4: a provider publishes to EVERY relay in its Relay Set. Three of
    // four is not finished.
    let h = harness().await;
    h.directory.relay_always_refuses("wss://relay-two.example");

    assert!(!h.service.publish_directory().await.unwrap());
    assert_eq!(h.directory.of_kind(K_PROFILE).len(), 1, "it still went out");
}

#[tokio::test]
async fn a_publication_every_relay_took_is_not_retried() {
    let h = harness().await;
    assert!(h.service.publish_directory().await.unwrap());
}

// ── a config that would publish nothing usable ──────────────────────────────

#[tokio::test]
async fn a_provider_that_publishes_must_name_a_sealing_key_and_a_settlement() {
    // ADR 0011: a tenant seals only to the key the Profile pins. A Profile
    // that pins nothing cannot be acted on, so the config is refused at load
    // rather than published.
    for break_it in [
        |c: &mut ProviderConfig| c.connector_seal_key = String::new(),
        |c: &mut ProviderConfig| c.connector_url = String::new(),
        |c: &mut ProviderConfig| c.settlement = Vec::new(),
        |c: &mut ProviderConfig| c.relay_set = Vec::new(),
    ] {
        let mut cfg = config(
            vec![listing("basic", 1, 4)],
            &Keys::generate().secret_key().to_secret_hex(),
            "/tmp/unused-leases.json".to_string(),
        );
        cfg.publish_url = Some("http://publisher:8081/publish".to_string());
        break_it(&mut cfg);
        assert!(cfg.validate().is_err());
    }
}

// ── reading Liveness back ───────────────────────────────────────────────────

#[tokio::test]
async fn query_liveness_answers_for_the_provider_that_published_it_and_nobody_else() {
    // The port's other half: a provider is LIVE ON A RELAY while that relay
    // holds an unexpired Liveness from it (spec §4.3). Milestone 3's Takeover
    // is the caller; this pins the contract now.
    let h = harness().await;
    h.service.publish_liveness(NOW).await.unwrap();
    let published = h.directory.of_kind(K_LIVENESS).remove(0);
    h.directory.seed_liveness(published.clone());

    let found = h.directory.query_liveness(h.provider).await.unwrap();
    assert_eq!(found.map(|e| e.id), Some(published.id));

    let stranger = Keys::generate().public_key();
    assert!(h
        .directory
        .query_liveness(stranger)
        .await
        .unwrap()
        .is_none());
}

// ── what must never be published ────────────────────────────────────────────

#[tokio::test]
async fn nothing_a_tenant_sent_is_ever_published() {
    // A Lease Request is not a Nostr event any more (ADR 0016), so there is
    // no tenant-signed thing here to leak — and the lease it bought must not
    // reach a relay by any other route either. Everything published is the
    // PROVIDER's own, carries the label, and says nothing about this lease.
    let h = harness().await;
    spawn_a_lease(&h).await;
    h.service.publish_directory().await.unwrap();
    h.service.publish_liveness(NOW).await.unwrap();

    for event in h.directory.published() {
        assert_eq!(
            event.pubkey, h.provider,
            "a provider publishes only what it signs itself: {:?}",
            event.kind
        );
        assert!(
            has_tag(&event, &["L", TOON_LABEL]),
            "every directory event carries the toon.network label: {:?}",
            event.kind
        );
        assert!(
            !event.content.contains(&"ab".repeat(32)),
            "the workload id of a live lease appears in nothing published: {:?}",
            event.kind
        );
    }
}

// ── driving one real lease in ───────────────────────────────────────────────

async fn spawn_a_lease(h: &Harness) -> (StatusCode, Value) {
    let content = SpawnContent {
        workload_id: "ab".repeat(32),
        image: ImageRef::upstream("docker.io/library/alpine".to_string(), valid_digest()),
        env: BTreeMap::new(),
        ports: vec![PortRequest {
            container_port: 443,
            protocol: Protocol::Tcp,
        }],
        volume_gb: Some(2),
        ssh_public_key: SSH_KEY.to_string(),
        entrypoint: None,
        args: None,
        standby_set: None,
        template: None,
    };

    let request = RequestSpec::new(h.provider, h.clock.now(), "spawn", json!(content)).request();
    let body = json!({ "request": request });
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listings/basic/v1/spawn")
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
