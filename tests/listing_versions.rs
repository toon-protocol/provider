//! Changing a listing's price without repricing the leases already running
//! (spec §4.2, §5, §6.3; ADR 0009).
//!
//! A price or resource change is a NEW listing version. The new version is
//! what is on sale and what the directory advertises; the old one is retired
//! and keeps only enough of itself to serve the leases already on it — its
//! `.extend` route, at the interval and price those leases were sold at —
//! until the last of them ends.
//!
//! The provider is driven the way its connector drives it: an HTTP request
//! per paid route, JSON out, over a faked `ComputeBackend`, a clock the test
//! moves by hand and a faked `Directory`. The "config change and restart"
//! ADR 0009 requires is a real restart here: the provider is built with v1
//! only, sells a lease, and is then rebuilt with v1 + v2 over the same lease
//! table on disk.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use nostr_sdk::Keys;
use serde_json::{json, Value};

use common::harness::{
    digest, error_of, post, restart, spawn_content, Harness, RequestSpec, NOW, PUBLIC_IP,
};
use common::{stub_registry, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::directory_events::ListingContent;
use toon_provider::nostr::kinds::K_LISTING;
use toon_provider::nostr::wire::Resources;
use toon_provider::provider::{persisted_leases, route_table, ImagePolicyConfig};
use toon_provider::{Listing, ProviderConfig, ProviderService};

const PRICE_V1: u64 = 1000;
const INTERVAL_V1: u64 = 100;
const PRICE_V2: u64 = 2000;
const INTERVAL_V2: u64 = 200;
const CAPACITY: u32 = 2;

fn tier(version: u32, price: u64, lease_interval_s: u64) -> Listing {
    Listing {
        name: "basic".to_string(),
        version,
        resources: Resources {
            cpu_millicores: 500,
            memory_mb: 256,
            storage_gb: 4,
            gpu: None,
        },
        arch: "amd64".to_string(),
        lease_interval_s,
        price,
        capabilities: vec![],
        capacity: CAPACITY,
    }
}

fn v1() -> Listing {
    tier(1, PRICE_V1, INTERVAL_V1)
}

fn v2() -> Listing {
    tier(2, PRICE_V2, INTERVAL_V2)
}

/// The provider before the price change: `basic` v1 is the only thing it
/// sells.
async fn before_the_change() -> Harness {
    common::harness::harness_with(vec![v1()]).await
}

/// The same provider after the operator added a `[[listings]]` entry for v2,
/// kept v1, and restarted it — the config-and-restart a listing change
/// requires (ADR 0009, spec §11 item 5). The lease table on disk, the
/// backend, the clock and the Nostr identity all carry over, so the lease
/// sold on v1 is still running underneath.
async fn after_the_change(h: &Harness) -> Harness {
    let restarted = restart(
        vec![v1(), v2()],
        h.provider_key.clone(),
        h.state_path.clone(),
        h.backend.clone(),
        h.clock.clone(),
        stub_registry().await,
        ImagePolicyConfig::default(),
    )
    .await;
    restarted.service.restore_leases().await;
    restarted
}

async fn spawn_on(h: &Harness, version: u32, seed: u8) -> (StatusCode, Value) {
    let content = spawn_content(seed);
    post(
        &h.app,
        &format!("/listings/basic/v{}/spawn", version),
        json!({ "request": RequestSpec::spawn(h, &content).sign() }),
    )
    .await
}

async fn extend_on(h: &Harness, version: u32, workload_id: &str) -> (StatusCode, Value) {
    post(
        &h.app,
        &format!("/listings/basic/v{}/extend", version),
        json!({ "workload_id": workload_id }),
    )
    .await
}

// ── extension keeps the price and interval the lease was sold at ─────────

#[tokio::test]
async fn a_lease_sold_on_the_old_version_still_extends_on_its_own_route() {
    let h = before_the_change().await;
    let (status, body) = spawn_on(&h, 1, 1).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let workload_id = body["workload_id"].as_str().unwrap().to_string();
    let expires_at = body["expires_at"].as_u64().unwrap();
    assert_eq!(expires_at, NOW + INTERVAL_V1);

    let h = after_the_change(&h).await;

    // v1's route is still carried, and one payment there buys v1's interval —
    // not v2's. The lease keeps the price it started at (ADR 0009).
    let (status, body) = extend_on(&h, 1, &workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        expires_at + INTERVAL_V1
    );
}

#[tokio::test]
async fn extending_an_old_versions_lease_on_the_new_versions_route_is_refused() {
    let h = before_the_change().await;
    let (_, body) = spawn_on(&h, 1, 1).await;
    let workload_id = body["workload_id"].as_str().unwrap().to_string();
    let expires_at = body["expires_at"].as_u64().unwrap();

    let h = after_the_change(&h).await;

    // Paying v2's price must not buy time on a v1 lease, and paying v1's
    // price must not buy v2's interval: the route names the deal.
    let (_, body) = extend_on(&h, 2, &workload_id).await;
    assert_eq!(error_of(&body), "wrong_listing_version");

    // ...and the refusal bought nothing (ADR 0003 still billed it).
    let (_, body) = extend_on(&h, 1, &workload_id).await;
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        expires_at + INTERVAL_V1
    );
}

// ── the new version is the only one that sells ───────────────────────────

#[tokio::test]
async fn a_spawn_on_the_new_version_gets_the_new_versions_interval() {
    let h = after_the_change(&before_the_change().await).await;

    let (status, body) = spawn_on(&h, 2, 2).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + INTERVAL_V2);
}

#[tokio::test]
async fn a_spawn_on_a_retired_version_is_refused() {
    let h = after_the_change(&before_the_change().await).await;

    let (_, body) = spawn_on(&h, 1, 2).await;
    assert_eq!(
        error_of(&body),
        "wrong_listing_version",
        "a new version REPLACES the Listing (spec §4.2): v1 sells nothing"
    );
}

#[tokio::test]
async fn a_retired_version_with_no_live_lease_sells_nothing_either() {
    // No lease was ever sold on v1 here, so nothing is holding its route
    // open — and it still refuses, because retirement is about what is on
    // sale, not about what is running.
    let h = common::harness::harness_with(vec![v1(), v2()]).await;

    let (_, body) = spawn_on(&h, 1, 1).await;
    assert_eq!(error_of(&body), "wrong_listing_version");
}

#[tokio::test]
async fn availability_on_a_retired_version_answers_the_same_refusal() {
    let h = common::harness::harness_with(vec![v1(), v2()]).await;

    let (status, body) = post(
        &h.app,
        "/availability",
        json!({
            "listing": "basic",
            "version": 1,
            "image": { "reference": "docker.io/library/alpine", "digest": digest() },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["would_run"], false);
    assert_eq!(error_of(&body), "wrong_listing_version");

    // The version on sale still would.
    let (_, body) = post(
        &h.app,
        "/availability",
        json!({
            "listing": "basic",
            "version": 2,
            "image": { "reference": "docker.io/library/alpine", "digest": digest() },
        }),
    )
    .await;
    assert_eq!(body["would_run"], true, "{}", body);
}

// ── the route table follows the last lease ───────────────────────────────

#[tokio::test]
async fn the_route_table_keeps_a_retired_version_until_its_last_lease_ends() {
    let h = before_the_change().await;
    let (status, body) = spawn_on(&h, 1, 1).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let expires_at = body["expires_at"].as_u64().unwrap();

    let h = after_the_change(&h).await;

    // What `toon-provider routes` prints for the changed config, read off
    // the same lease table on disk the CLI reads.
    let config = ProviderConfig {
        listings: vec![v1(), v2()],
        ..ProviderConfig::default()
    };
    let prefixes = |leases: &[toon_provider::LeaseRecord]| -> Vec<String> {
        route_table(&config, leases)
            .into_iter()
            .map(|row| row.prefix)
            .collect()
    };
    let live = prefixes(&persisted_leases(&h.state_path));
    for wanted in [
        "g.toon.provider.basic.v1.spawn",
        "g.toon.provider.basic.v1.extend",
        "g.toon.provider.basic.v2.spawn",
        "g.toon.provider.basic.v2.extend",
    ] {
        assert!(live.contains(&wanted.to_string()), "missing {}", wanted);
    }

    // The lease runs out and the sweep ends it (spec §6.7).
    h.clock.set(expires_at);
    h.service.sweep_expired_leases(expires_at).await;

    let after = prefixes(&persisted_leases(&h.state_path));
    assert!(
        !after.iter().any(|p| p.contains(".v1.")),
        "v1 has no live lease left; its rows come out of the connector config: {:?}",
        after
    );
    assert!(after.contains(&"g.toon.provider.basic.v2.spawn".to_string()));
    assert!(after.contains(&"g.toon.provider.availability".to_string()));
}

// ── the directory advertises one Listing per name ────────────────────────

/// A provider wired to a `FakeDirectory`, so what it publishes can be read
/// back rather than paid for on a relay (the pattern `tests/directory.rs`
/// uses).
async fn publishing_provider(listings: Vec<Listing>) -> (ProviderService, Arc<FakeDirectory>) {
    publishing_provider_with(listings, FakeDirectory::new()).await
}

/// …over a Directory that has already recorded something, so a test can read
/// back what one provider published before a restart and what the next one
/// published after it, in order.
async fn publishing_provider_with(
    listings: Vec<Listing>,
    directory: Arc<FakeDirectory>,
) -> (ProviderService, Arc<FakeDirectory>) {
    let registry = stub_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let config = ProviderConfig {
        public_ip: PUBLIC_IP.to_string(),
        nostr_private_key: Keys::generate().secret_key().to_secret_hex(),
        listings,
        lease_state_path: dir
            .keep()
            .join("leases.json")
            .to_string_lossy()
            .into_owned(),
        image_policy: ImagePolicyConfig {
            registry_url_override: Some(registry.uri()),
            ..ImagePolicyConfig::default()
        },
        ..ProviderConfig::default()
    };
    let service = ProviderService::with_backend_clock_and_directory(
        config,
        FakeBackend::new(),
        FakeClock::at(NOW),
        directory.clone(),
    )
    .unwrap();
    (service, directory)
}

#[tokio::test]
async fn the_directory_publishes_one_listing_per_name_at_the_newest_version() {
    let (service, directory) = publishing_provider(vec![v1(), v2()]).await;
    service.publish_directory().await.unwrap();

    let listings = directory.of_kind(K_LISTING);
    assert_eq!(
        listings.len(),
        1,
        "the Listing is addressable on `d`, so a new version REPLACES it"
    );
    assert_eq!(listings[0].tags.identifier(), Some("basic"));
    let content: ListingContent = serde_json::from_str(&listings[0].content).unwrap();
    assert_eq!(content.version, 2);
    assert_eq!(content.price, PRICE_V2);
    assert_eq!(content.lease_interval_s, INTERVAL_V2);
}

#[tokio::test]
async fn the_republished_listing_keeps_its_d_and_carries_the_new_version() {
    // Issue #8's acceptance criterion, as the relay sees it across the
    // change: the same provider publishes before and after, and the second
    // event is a REPLACEMENT of the first — same `d`, new `version`.
    let (before, directory) = publishing_provider(vec![v1()]).await;
    before.publish_directory().await.unwrap();
    let first = directory.of_kind(K_LISTING);
    assert_eq!(first.len(), 1);
    let first: ListingContent = serde_json::from_str(&first[0].content).unwrap();
    assert_eq!(first.version, 1);
    assert_eq!(first.price, PRICE_V1);

    // The operator adds v2, keeps v1, and restarts (ADR 0009).
    let (after, directory) = publishing_provider_with(vec![v1(), v2()], directory).await;
    after.publish_directory().await.unwrap();

    let events = directory.of_kind(K_LISTING);
    assert_eq!(events.len(), 2, "one publication before, one after");
    let ds: Vec<Option<&str>> = events.iter().map(|e| e.tags.identifier()).collect();
    assert_eq!(
        ds,
        vec![Some("basic"), Some("basic")],
        "the `d` is the listing NAME and is stable across versions"
    );
    let second: ListingContent = serde_json::from_str(&events[1].content).unwrap();
    assert_eq!(second.version, 2);
    assert_eq!(second.price, PRICE_V2);
}

#[tokio::test]
async fn the_order_of_the_listings_entries_does_not_decide_which_is_published() {
    // The operator appends the new version, but a config edited by hand may
    // put it anywhere: the newest VERSION is what is on sale, not the last
    // entry in the file.
    let (service, directory) = publishing_provider(vec![v2(), v1()]).await;
    service.publish_directory().await.unwrap();

    let listings = directory.of_kind(K_LISTING);
    assert_eq!(listings.len(), 1);
    let content: ListingContent = serde_json::from_str(&listings[0].content).unwrap();
    assert_eq!(content.version, 2);
}
