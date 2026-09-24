//! `GET /operator/status` (ADR 0029, TOON_Network#170): what an operator
//! reads on the box to answer "am I listed, what am I running, what has it
//! billed".
//!
//! Driven the way the operator endpoint is reached — a GET into
//! `operator_router`, JSON out — over the same faked backend, clock and
//! Directory every other route test uses, with the connector's `/identity`
//! stubbed by `wiremock`. Asserts on the document, never on the provider's
//! internals.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nostr_sdk::{Keys, ToBech32};
use serde_json::{json, Value};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::harness::{
    config_for, harness, harness_from, harness_with, hidden_config, listing, mint, post,
    socks_proxy_of, spawn, spawn_content, Harness, RequestSpec, HIDDEN_CONNECTOR_URL, INTERVAL,
    NOW,
};
use common::socks::SocksStub;
use common::{stub_registry, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::continuation::ContinuationToken;
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::{operator_router, Listing, ProviderConfig};

/// What the connector in these tests reports at `/ilp/identity`, and what
/// the provider publishes unless a test says otherwise.
const SEAL_KEY: &str = "0x04325b06f4bcb438204ab86a36a715fdf409552da5cdc7cd28301b08088ce7c3a1bf4289f62ba89a707ed8d7db66b03cb2881ea5934e35f2d600c4cd7067ed0188";
const OTHER_SEAL_KEY: &str = "0x04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RELAY_ONE: &str = "ws://relay-one.example:7100";
const RELAY_TWO: &str = "ws://relay-two.example:7100";

/// `GET /operator/status` on the OPERATOR router, as `curl
/// 127.0.0.1:8090/operator/status` reaches it.
async fn operator_status(h: &Harness) -> Value {
    let (status, body) = get(operator_router(h.service.app_state()), "/operator/status").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    body
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
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

/// A connector whose `/ilp/identity` answers `public_key`.
async fn connector_reporting(public_key: &str) -> MockServer {
    let connector = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ilp/identity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keyId": "connector-key",
            "publicKey": public_key,
        })))
        .mount(&connector)
        .await;
    connector
}

/// A public provider over `listings`, whose connector is at `connector_url`
/// and publishes `seal_key`, with `adjust` applied last.
async fn provider(
    listings: Vec<Listing>,
    connector_url: &str,
    adjust: impl FnOnce(ProviderConfig) -> ProviderConfig,
) -> Harness {
    let registry = stub_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let config = config_for(
        listings,
        &Keys::generate().secret_key().to_secret_hex(),
        &state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    let config = adjust(ProviderConfig {
        connector_url: connector_url.to_string(),
        connector_seal_key: SEAL_KEY.to_string(),
        ..config
    });
    harness_from(
        config,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
    )
}

fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

/// Buy one lease on `<listing>.v1.spawn`, answering the token it was taken
/// with.
async fn spawn_on(h: &Harness, listing: &str, seed: u8) -> (ContinuationToken, SpawnContent) {
    let content = spawn_content(seed);
    let token = mint().continuation_for(&h.provider);
    let spec = RequestSpec::spawn(h, &content).with_token(&token);
    let (status, body) = post(
        &h.app,
        &format!("/listings/{listing}/v1/spawn"),
        json!({ "request": spec.request() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    (token, content)
}

async fn extend(h: &Harness, path: &str, workload_id: &str) {
    let (status, body) = post(&h.app, path, json!({ "workload_id": workload_id })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

fn lease<'a>(status: &'a Value, workload_id: &str) -> &'a Value {
    status["leases"]["leases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["workload_id"] == workload_id)
        .unwrap_or_else(|| panic!("no lease {workload_id} in {status:#}"))
}

// ── the document ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn status_answers_every_section_with_a_version() {
    let h = harness().await;
    let status = operator_status(&h).await;

    assert_eq!(status["version"], 1);
    assert_eq!(status["service"], "provider");
    assert_eq!(status["generated_at"], NOW);
    // When the process started, so `status --check` can tell "not published
    // yet" from "not landing" (TOON_Network#172).
    assert_eq!(status["started_at"], NOW);
    for section in ["identity", "directory", "leases"] {
        assert!(status[section].is_object(), "{section} missing: {status:#}");
    }
    assert_eq!(status["identity"]["npub"], h.provider.to_bech32().unwrap());
    assert_eq!(status["identity"]["pubkey"], h.provider.to_hex());
    assert_eq!(status["identity"]["hidden"], false);
    assert_eq!(
        status["leases"]["listings"]["basic"],
        json!({
            "version": 1,
            "capacity": 2,
            "live": 0,
            "available": 2,
            "price": 1000,
            "standby_price": null,
            "lease_interval_s": INTERVAL,
        })
    );
    assert_eq!(status["leases"]["leases"], json!([]));
}

#[tokio::test]
async fn status_is_not_on_the_tenant_router() {
    // The connector forwards tenant traffic to `router`; the status route
    // lives only on the loopback operator listener.
    let h = harness().await;
    let (status, _) = get(h.app.clone(), "/operator/status").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn status_carries_no_secret() {
    let h = harness().await;
    let (token, _) = spawn_on(&h, "basic", 1).await;

    let rendered = operator_status(&h).await.to_string();
    let token_hex = serde_json::to_value(&token).unwrap();
    let token_hex = token_hex.as_str().unwrap();
    assert!(
        !rendered.contains(token_hex),
        "the Continuation Token leaked: {rendered}"
    );
    let keys = Keys::parse(&h.provider_key).unwrap();
    assert!(!rendered.contains(&keys.secret_key().to_secret_hex()));
    assert!(!rendered.contains(&keys.secret_key().to_bech32().unwrap()));
    // The reserved spawn (with the tenant's env and SSH key) is not there
    // either: the lease summary is chosen field by field.
    assert!(!rendered.contains("ssh-ed25519"), "{rendered}");
    assert!(!rendered.contains("continuation"), "{rendered}");
}

// ── leases and what they billed ──────────────────────────────────────────────

#[tokio::test]
async fn a_spawn_and_its_extensions_are_billed_per_paid_interval() {
    let h = harness().await;
    let (_, content) = spawn_on(&h, "basic", 1).await;
    extend(&h, "/listings/basic/v1/extend", &content.workload_id).await;
    extend(&h, "/listings/basic/v1/extend", &content.workload_id).await;

    let status = operator_status(&h).await;
    let lease = lease(&status, &content.workload_id);
    assert_eq!(lease["listing"], "basic");
    assert_eq!(lease["listing_version"], 1);
    assert_eq!(lease["role"], "standalone");
    assert_eq!(lease["state"], "running");
    assert_eq!(lease["created_at"], NOW);
    assert_eq!(lease["expires_at"], NOW + 3 * INTERVAL);
    assert_eq!(lease["ssh_port"], 40000);
    assert_eq!(
        lease["ports"],
        json!([{ "container_port": 443, "host_port": 41000 }])
    );
    assert_eq!(lease["hidden_address"], Value::Null);
    assert_eq!(
        lease["paid_intervals"],
        json!({ "running": 3, "standby": 0 })
    );
    assert_eq!(lease["billed"], 3000);
    assert_eq!(lease["billed_estimated"], false);

    let basic = &status["leases"]["listings"]["basic"];
    assert_eq!(
        (basic["live"].as_u64(), basic["available"].as_u64()),
        (Some(1), Some(1))
    );
}

#[tokio::test]
async fn a_refused_extension_buys_no_interval() {
    // The connector bills a refusal (ADR 0003), but it buys no Lease
    // Interval, and the count is of intervals.
    let h = harness_with(vec![warm()]).await;
    let (_, content) = spawn_on(&h, "warm", 1).await;
    // A running lease paid on `.standby.extend` is refused `not_standby`.
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby/extend",
        json!({ "workload_id": content.workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);

    let status = operator_status(&h).await;
    let lease = lease(&status, &content.workload_id);
    assert_eq!(
        lease["paid_intervals"],
        json!({ "running": 1, "standby": 0 })
    );
    assert_eq!(lease["billed"], 1000);
}

#[tokio::test]
async fn a_warm_standby_is_billed_at_the_standby_price() {
    let h = harness_with(vec![warm()]).await;
    let content = SpawnContent {
        standby_set: Some(vec![
            Keys::generate().public_key().to_hex(),
            h.provider.to_hex(),
        ]),
        ..spawn_content(2)
    };
    let spec = RequestSpec::standby(&h, &content);
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby",
        json!({ "request": spec.request() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    extend(&h, "/listings/warm/v1/standby/extend", &content.workload_id).await;

    let status = operator_status(&h).await;
    let lease = lease(&status, &content.workload_id);
    assert_eq!(lease["role"], "standby");
    assert_eq!(lease["state"], "reserved");
    assert_eq!(
        lease["paid_intervals"],
        json!({ "running": 0, "standby": 2 })
    );
    assert_eq!(lease["billed"], 800);
    assert_eq!(lease["billed_estimated"], false);
    assert_eq!(status["leases"]["listings"]["warm"]["live"], 1);
    assert_eq!(status["leases"]["listings"]["warm"]["standby_price"], 400);
}

#[tokio::test]
async fn a_lease_from_before_the_count_is_billed_by_estimate() {
    // A leases.json as a provider before TOON_Network#170 wrote it: no
    // `paid_intervals`. It loads, and its billing is derived from its
    // expiry and marked as such.
    let registry = stub_registry().await;
    let dir = tempfile::tempdir().unwrap().keep();
    let state_path = dir.join("leases.json").to_string_lossy().into_owned();
    std::fs::write(
        &state_path,
        json!({ "1000": {
            "id": 1000,
            "workload_id": "aa".repeat(32),
            "continuation": "ee".repeat(32),
            "listing": "basic",
            "listing_version": 1,
            "role": "standalone",
            "state": "running",
            "taken_over": false,
            "created_at": NOW - 100,
            "expires_at": NOW - 100 + 2 * INTERVAL,
            "destroyed": false,
            "ssh_port": 40000,
            "ports": [],
        }})
        .to_string(),
    )
    .unwrap();
    let backend = FakeBackend::new();
    backend.seed_running(1000);
    let config = config_for(
        vec![listing("basic", 1, 2)],
        &Keys::generate().secret_key().to_secret_hex(),
        &state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    let h = harness_from(
        config,
        backend,
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
    );
    h.service.restore_leases().await;
    // An extension of it is counted nowhere: its estimate grows instead.
    extend(&h, "/listings/basic/v1/extend", &"aa".repeat(32)).await;

    let status = operator_status(&h).await;
    let lease = lease(&status, &"aa".repeat(32));
    assert_eq!(
        lease["paid_intervals"],
        json!({ "running": 3, "standby": 0 })
    );
    assert_eq!(lease["billed"], 3000);
    assert_eq!(lease["billed_estimated"], true);

    // And the table on disk has not grown the field.
    let raw: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert!(raw["1000"].get("paid_intervals").is_none(), "{raw:#}");
}

// ── directory, relay by relay ────────────────────────────────────────────────

#[tokio::test]
async fn each_relay_says_what_it_took_and_what_it_refused() {
    let h = provider(
        vec![listing("basic", 1, 2)],
        "http://127.0.0.1:9/ilp",
        |config| ProviderConfig {
            relay_set: vec![RELAY_ONE.to_string(), RELAY_TWO.to_string()],
            ..config
        },
    )
    .await;
    h.directory.publishes_to(&[RELAY_ONE, RELAY_TWO]);

    // Before anything is published every relay is listed, with nothing on it.
    let status = operator_status(&h).await;
    assert_eq!(
        status["directory"]["relays"][RELAY_ONE],
        json!({ "profile": null, "listings": { "basic": null }, "liveness": null })
    );
    assert_eq!(status["directory"]["liveness_expires_at"], Value::Null);

    assert!(h.service.publish_directory().await.unwrap());
    h.service.publish_liveness(NOW).await.unwrap();
    // A cadence later relay two starts refusing the Liveness.
    h.directory.refuse_liveness_on(&[RELAY_TWO]);
    h.clock.set(NOW + 60);
    h.service.publish_liveness(NOW + 60).await.unwrap();

    let status = operator_status(&h).await;
    let relays = &status["directory"]["relays"];
    let took = |at: u64| json!({ "last_accepted_at": at, "last_attempt_at": at, "refusal": null, "kind": null, "expires_at": null });
    assert_eq!(relays[RELAY_ONE]["profile"], took(NOW));
    assert_eq!(relays[RELAY_TWO]["listings"]["basic"], took(NOW));
    let cadence = 60;
    let expiry = |at: u64| at + 5 * cadence;
    assert_eq!(
        relays[RELAY_ONE]["liveness"],
        json!({
            "last_accepted_at": NOW + 60,
            "last_attempt_at": NOW + 60,
            "refusal": null,
            "kind": null,
            "expires_at": expiry(NOW + 60),
        })
    );
    // Relay two refused the latest, and still serves the one before. A
    // relay's own "no" is `kind: "refused"` (TOON_Network#178).
    assert_eq!(
        relays[RELAY_TWO]["liveness"],
        json!({
            "last_accepted_at": NOW,
            "last_attempt_at": NOW + 60,
            "refusal": "relay refused",
            "kind": "refused",
            "expires_at": expiry(NOW),
        })
    );
    assert_eq!(status["directory"]["liveness_expires_at"], expiry(NOW + 60));
}

#[tokio::test]
async fn a_publisher_that_is_down_is_a_refusal_on_every_relay() {
    let h = provider(vec![listing("basic", 1, 2)], "", |config| ProviderConfig {
        relay_set: vec![RELAY_ONE.to_string(), RELAY_TWO.to_string()],
        ..config
    })
    .await;
    h.directory
        .fail_next_publish("the directory publisher could not be reached");
    assert!(h.service.publish_liveness(NOW).await.is_err());

    let status = operator_status(&h).await;
    for relay in [RELAY_ONE, RELAY_TWO] {
        assert_eq!(
            status["directory"]["relays"][relay]["liveness"],
            json!({
                "last_accepted_at": null,
                "last_attempt_at": NOW,
                "refusal": "not attempted: the directory publisher could not be reached",
                // Never reached a relay to be refused — NOT SENT, not
                // REFUSED (TOON_Network#178).
                "kind": "not_sent",
                "expires_at": null,
            })
        );
    }
    assert_eq!(status["directory"]["publishing"], false);
}

// ── identity: the connector's live sealing key ───────────────────────────────

#[tokio::test]
async fn the_connectors_live_key_is_compared_with_the_published_one() {
    let connector = connector_reporting(SEAL_KEY).await;
    let h = provider(
        vec![listing("basic", 1, 2)],
        &format!("{}/ilp", connector.uri()),
        |c| c,
    )
    .await;
    assert_eq!(
        operator_status(&h).await["identity"]["connector_identity"],
        json!({
            "reachable": true,
            "via_proxy": false,
            "live_seal_key": SEAL_KEY,
            "matches": true,
            "error": null,
        })
    );
}

#[tokio::test]
async fn a_rotated_connector_key_is_a_mismatch() {
    let connector = connector_reporting(OTHER_SEAL_KEY).await;
    let h = provider(
        vec![listing("basic", 1, 2)],
        &format!("{}/ilp", connector.uri()),
        |c| c,
    )
    .await;
    let identity = &operator_status(&h).await["identity"];
    assert_eq!(identity["connector_seal_key"], SEAL_KEY);
    assert_eq!(
        identity["connector_identity"]["live_seal_key"],
        OTHER_SEAL_KEY
    );
    assert_eq!(identity["connector_identity"]["matches"], false);
}

#[tokio::test]
async fn a_connector_that_does_not_answer_is_reported_not_fatal() {
    let connector = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&connector)
        .await;
    let url = format!("{}/ilp", connector.uri());
    let h = provider(vec![listing("basic", 1, 2)], &url, |c| c).await;
    spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;

    let status = operator_status(&h).await;
    assert_eq!(
        status["identity"]["connector_identity"],
        json!({
            "reachable": false,
            "via_proxy": false,
            "live_seal_key": null,
            "matches": null,
            "error": format!("GET {url}/identity answered 503 Service Unavailable"),
        })
    );
    // The rest of the document is still there.
    assert_eq!(status["leases"]["leases"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_hidden_provider_asks_its_connector_through_the_socks_proxy() {
    // A Hidden Provider's connector is at an `.anyone` host nothing on this
    // machine resolves: only the proxy knows where it is (spec §10).
    let connector = connector_reporting(SEAL_KEY).await;
    let anyone_host = HIDDEN_CONNECTOR_URL
        .trim_start_matches("http://")
        .trim_end_matches("/ilp");
    let socks = SocksStub::start(&[(anyone_host, *connector.address())]).await;

    let registry = stub_registry().await;
    let dir = tempfile::tempdir().unwrap().keep();
    let config = socks_proxy_of(
        hidden_config(config_for(
            vec![listing("basic", 1, 2)],
            &Keys::generate().secret_key().to_secret_hex(),
            &dir.join("leases.json").to_string_lossy(),
            &registry,
            ImagePolicyConfig::default(),
        )),
        &socks.url(),
    );
    let config = ProviderConfig {
        connector_seal_key: SEAL_KEY.to_string(),
        ..config
    };
    let h = harness_from(
        config,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
    );
    let (_, content) = spawn_on(&h, "basic", 3).await;

    let status = operator_status(&h).await;
    assert_eq!(status["identity"]["hidden"], true);
    assert_eq!(status["identity"]["connector_identity"]["via_proxy"], true);
    assert_eq!(status["identity"]["connector_identity"]["matches"], true);
    assert!(
        socks.asked_for(&format!("{anyone_host}:80")),
        "the probe did not go through the proxy: {:?}",
        socks.destinations()
    );

    // The lease's `.anyone` HOST is reported, and never the key it is
    // derived from.
    let lease = lease(&status, &content.workload_id);
    let host = lease["hidden_address"].as_str().unwrap();
    assert!(host.ends_with(".anyone"), "{host}");
    let rendered = status.to_string();
    assert!(!rendered.contains("ED25519-V3"), "{rendered}");
}
