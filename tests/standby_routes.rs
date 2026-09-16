//! The two Warm Standby routes answer, and refuse.
//!
//! Milestone 3 sells Warm Standbys over several tickets. This one wires the
//! shapes and the routes: `<addr>.<listing>.v<n>.standby` and
//! `.standby.extend` exist on the router, and — until the tickets that
//! reserve and pay a standby land — every request on them, and every spawn
//! carrying a `standby_set`, is refused `invalid_request` with a message
//! that says so. Nobody pays for a role this provider cannot yet hold.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::harness::{
    error_of, harness_with, listing, post, spawn, spawn_content, workload_id, RequestSpec,
};
use common::BackendCall;
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::Listing;

/// A tier that prices standbys, so nothing here is refused merely because
/// the listing sells none: the refusal under test is the milestone's, not
/// the price's.
fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

/// Every refusal names the milestone, so a tenant reading the message knows
/// to come back rather than to change its request.
fn says_standby_sets_land_later(body: &serde_json::Value) {
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Standby Sets") && message.contains("Milestone 3"),
        "message should say Standby Sets land later in Milestone 3, got {:?}",
        message
    );
}

#[tokio::test]
async fn a_spawn_carrying_a_standby_set_is_refused() {
    let h = harness_with(vec![warm()]).await;
    let content = SpawnContent {
        standby_set: Some(vec![h.provider.to_hex(), "bb".repeat(32)]),
        ..spawn_content(1)
    };
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/spawn",
        json!({ "request": RequestSpec::spawn(&h, &content).sign() }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "invalid_request");
    says_standby_sets_land_later(&body);
    assert!(h.backend.calls().is_empty(), "nothing was started");
}

#[tokio::test]
async fn a_standby_spawn_is_refused_on_a_registered_route() {
    let h = harness_with(vec![warm()]).await;
    let content = SpawnContent {
        standby_set: Some(vec!["bb".repeat(32), h.provider.to_hex()]),
        ..spawn_content(2)
    };
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby",
        json!({ "request": RequestSpec::spawn(&h, &content).sign() }),
    )
    .await;

    // Registered, not 404: the connector may already carry the route, and a
    // paid packet must meet the provider's own refusal rather than a hole.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "invalid_request");
    says_standby_sets_land_later(&body);
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_standby_extension_is_refused_on_a_registered_route() {
    let h = harness_with(vec![warm()]).await;
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby/extend",
        json!({ "workload_id": workload_id(3) }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "invalid_request");
    says_standby_sets_land_later(&body);
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_running_lease_is_untouched_by_the_standby_routes() {
    // The refusals are unconditional, so they must not be reachable by
    // accident from an ordinary lease: a standalone spawn still runs, and
    // `.standby.extend` for its workload id changes nothing.
    let h = harness_with(vec![warm()]).await;
    let content = spawn_content(4);
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/spawn",
        json!({ "request": RequestSpec::spawn(&h, &content).sign() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let expires_at = body["expires_at"].as_u64().unwrap();

    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby/extend",
        json!({ "workload_id": content.workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "invalid_request");

    // The lease is exactly where it was: the full-price route still extends
    // it by one interval and no more.
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/extend",
        json!({ "workload_id": content.workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        expires_at + 3600,
        "the standby route bought nothing"
    );
    assert!(matches!(
        h.backend.calls().as_slice(),
        [BackendCall::Create(_), BackendCall::Start(_)]
    ));
}

/// `spawn` on the `basic` harness keeps working exactly as it did: this
/// ticket adds routes, it does not change the ones Milestone 1 sells.
#[tokio::test]
async fn an_ordinary_spawn_is_unaffected() {
    let h = harness_with(vec![listing("basic", 1, 2)]).await;
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(5)).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["role"], "standalone");
}
