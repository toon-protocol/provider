//! A tenant's `registry_entry.relay` must not aim this provider's websocket
//! at the operator's own network (TOON_Network#107).
//!
//! The sibling of `registry_address.rs`: the same rule, over the other
//! transport. A spawn's `{ digest, registry_entry: { address, relay } }`
//! carries a relay URL the TENANT chose, and the provider dials it to read
//! the entry (spec §6.2 step 5). Nothing about that URL is the provider's
//! own, and `availability` resolves the image for free — so `ws://127.0.0.1:
//! 9944` would be a free port scan of the operator's host, answered by the
//! difference between "refused" and "nothing there".
//!
//! What makes these tests proof rather than decoration is the trap: a real
//! listener on a loopback port that counts every connection it accepts. The
//! websocket goes through nostr-sdk, which resolves and dials the name
//! itself, so the only proof that the guard runs BEFORE the dial is a count
//! of zero.
//!
//! The operator's own Relay Set is the way back in, and the last two tests
//! walk through it: a hint at a relay this provider already publishes to is
//! dialled, because the operator named that relay themselves.

mod common;

use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use nostr_sdk::{Keys, PublicKey};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

use common::harness::RequestSpec;
use common::relay::StubRelay;
use common::trap::Trap;
use common::{valid_digest, FakeBackend};
use toon_provider::nostr::wire::{ImageRef, PortRequest, Protocol, Resources, SpawnContent};
use toon_provider::{router, Listing, ProviderConfig, ProviderService};

/// A publisher's Image Registry entry address (spec §6.2): kind 30434, a
/// pubkey nobody in these tests holds, `d = web:1.0`.
const ENTRY_ADDRESS: &str =
    "30434:4444444444444444444444444444444444444444444444444444444444444444:web:1.0";

/// A provider with a REAL Directory — `NullDirectory` over `relay_set` —
/// rather than the faked port the other suites drive, because the dial
/// itself is what is under test here.
struct Provider {
    app: axum::Router,
    provider: PublicKey,
    _dir: TempDir,
}

async fn provider_with(relay_set: Vec<String>) -> Provider {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let config = ProviderConfig {
        public_ip: Some("203.0.113.7".to_string()),
        nostr_private_key: keys.secret_key().to_secret_hex(),
        listings: vec![Listing {
            name: "basic".to_string(),
            version: 1,
            resources: Resources {
                cpu_millicores: 500,
                memory_mb: 256,
                storage_gb: 4,
                gpu: None,
            },
            arch: "amd64".to_string(),
            lease_interval_s: 3600,
            price: 1000,
            standby_price: None,
            capabilities: vec![],
            capacity: 2,
        }],
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: dir
            .path()
            .join("leases.json")
            .to_string_lossy()
            .into_owned(),
        relay_set,
        ..ProviderConfig::default()
    };
    let service = ProviderService::with_backend(config, FakeBackend::new()).unwrap();
    Provider {
        app: router(service.app_state()),
        provider: keys.public_key(),
        _dir: dir,
    }
}

async fn post(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            HttpRequest::builder()
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
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// The free route, asking about `{ digest, registry_entry }` hinted at
/// `relay`.
async fn availability(p: &Provider, relay: &str) -> Value {
    let (status, answer) = post(
        &p.app,
        "/availability",
        json!({
            "listing": "basic",
            "version": 1,
            "image": {
                "digest": valid_digest(),
                "registry_entry": { "address": ENTRY_ADDRESS, "relay": relay },
            }
        }),
    )
    .await;
    // The free route always answers 200 with `would_run: false`: a refusal
    // is an answer, not an HTTP error (§6.4).
    assert_eq!(status, StatusCode::OK, "{}", answer);
    answer
}

/// The paid route, for the same image: a tenant who has paid gets the same
/// refusal, not a dial.
async fn spawn(p: &Provider, relay: &str) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let content = SpawnContent {
        workload_id: "11".repeat(32),
        image: ImageRef::from_registry(
            valid_digest(),
            ENTRY_ADDRESS.to_string(),
            relay.to_string(),
        ),
        env: Default::default(),
        ports: vec![PortRequest {
            container_port: 443,
            protocol: Protocol::Tcp,
        }],
        volume_gb: Some(2),
        ssh_public_key: common::harness::SSH_KEY.to_string(),
        entrypoint: None,
        args: None,
        standby_set: None,
        template: None,
    };
    let request = RequestSpec::new(
        p.provider,
        now,
        "spawn",
        serde_json::to_value(&content).unwrap(),
    )
    .request();
    let (_status, answer) = post(
        &p.app,
        "/listings/basic/v1/spawn",
        json!({ "request": request }),
    )
    .await;
    answer
}

// ── the relay hint ──────────────────────────────────────────────────────

/// `relay = "ws://127.0.0.1:<port>"`: an address this provider must not
/// dial, and nothing leaves.
#[tokio::test]
async fn an_availability_whose_relay_hint_is_loopback_is_refused_before_any_connection() {
    let trap = Trap::set().await;
    let p = provider_with(vec![]).await;

    let answer = availability(&p, &trap.relay_url()).await;

    assert_eq!(answer["would_run"], false);
    assert_eq!(answer["error"], "refused_image");
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains(&trap.relay_url()),
        "the refusal names the source: {}",
        answer["message"]
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// The same, by NAME: `localhost` resolves inward, and the check is on what
/// it resolves to — reported as the source the tenant named, never as the
/// address behind it.
#[tokio::test]
async fn a_relay_hint_whose_name_resolves_inward_is_refused_too() {
    let trap = Trap::set().await;
    let p = provider_with(vec![]).await;
    let relay = trap.relay_url_as("localhost");

    let answer = availability(&p, &relay).await;

    assert_eq!(answer["error"], "refused_image");
    let message = answer["message"].as_str().unwrap();
    assert!(
        message.contains(&relay),
        "the refusal names the source: {}",
        message
    );
    assert!(
        !message.contains("127.0.0.1") && !message.contains("::1"),
        "and never the address it resolved to: {}",
        message
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// A paid spawn is refused exactly as the free ask was: `availability` is
/// advice about what a spawn would do, so the two cannot disagree (§6.4).
#[tokio::test]
async fn a_spawn_whose_relay_hint_points_inward_is_refused_before_any_connection() {
    let trap = Trap::set().await;
    let p = provider_with(vec![]).await;

    let answer = spawn(&p, &trap.relay_url()).await;

    assert_eq!(answer["error"], "refused_image", "{}", answer);
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains(&trap.relay_url()),
        "the refusal names the source: {}",
        answer["message"]
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// A scheme that is not `ws` or `wss` is refused before anything is
/// resolved: an Image Registry entry is read over a websocket and nothing
/// else.
#[tokio::test]
async fn a_relay_hint_that_is_not_a_websocket_is_refused() {
    let trap = Trap::set().await;
    let p = provider_with(vec![]).await;

    for written in [
        format!("http://127.0.0.1:{}", trap.addr.port()),
        format!("http://203.0.113.7:{}", trap.addr.port()),
        format!("file:///etc/passwd?{}", trap.addr.port()),
    ] {
        let answer = availability(&p, &written).await;
        assert_eq!(answer["error"], "refused_image", "{}: {}", written, answer);
        let message = answer["message"].as_str().unwrap();
        assert!(
            message.contains("ws") && message.contains(&written),
            "the refusal names the source and says what a relay URL is: {}",
            message
        );
    }
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

// ── the operator's own Relay Set ────────────────────────────────────────

/// A relay the OPERATOR configured is dialled, wherever it is: the sandbox's
/// `ws://relay:7100` on a compose network is the normal case, and a tenant
/// hinting at it asks for nothing the provider does not already do. Proven
/// by the relay seeing the read — the guard is not simply off.
#[tokio::test]
async fn a_hint_at_the_providers_own_relay_is_dialled() {
    let relay = StubRelay::start().await;
    let p = provider_with(vec![relay.url()]).await;

    let answer = availability(&p, &relay.url()).await;

    assert_eq!(answer["would_run"], false);
    assert_eq!(answer["error"], "refused_image");
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains("no Image Registry entry"),
        "the relay was asked and held nothing: {}",
        answer["message"]
    );
    assert!(
        !relay.requests().is_empty(),
        "the provider's own relay was really asked"
    );
}

/// But only THAT relay, on that port: an operator whose relay is at
/// `ws://relay:7100` has not said the rest of their network is fetchable.
#[tokio::test]
async fn another_port_on_the_operators_own_relay_host_is_still_refused() {
    let relay = StubRelay::start().await;
    let trap = Trap::set().await;
    let p = provider_with(vec![relay.url()]).await;

    let answer = availability(&p, &trap.relay_url()).await;

    assert_eq!(answer["error"], "refused_image");
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}
