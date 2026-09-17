//! Eviction (spec §6.7): a provider ending a lease on its own decision, and
//! publishing a signed Eviction Notice as the public record of it.
//!
//! Driven the way the operator endpoint drives it — a `toon-provider evict`
//! JSON request into `operator_router`, JSON out — asserting on the answer,
//! on what the faked `ComputeBackend` was asked to do, and on the Eviction
//! Notice the faked `Directory` was handed. Never on the provider's internal
//! state. The operator endpoint carries no signature, so unlike every other
//! route here there is no Lease Request to sign.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use common::harness::{
    error_of, harness, post, spawn, spawn_content, workload_id, Harness, RequestSpec,
};
use common::{has_tag, BackendCall};
use toon_provider::nostr::directory_events::EvictionContent;
use toon_provider::nostr::kinds::{K_EVICTION, TOON_LABEL};
use toon_provider::operator_router;

/// A lease that exists, spawned exactly as `tests/lease_lifecycle.rs` does.
async fn spawn_lease(h: &Harness, seed: u8) -> String {
    let content = spawn_content(seed);
    let (status, body) = spawn(h, RequestSpec::spawn(h, &content).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    content.workload_id
}

/// `POST /operator/evict` on the OPERATOR router — a different `Router` from
/// `h.app`, exactly as `main.rs`'s `evict` subcommand reaches it over the
/// wire, on a different port, at runtime.
async fn evict(h: &Harness, body: Value) -> (StatusCode, Value) {
    let response = operator_router(h.service.app_state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operator/evict")
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

async fn evict_for(
    h: &Harness,
    workload_id: &str,
    reason: &str,
    message: &str,
) -> (StatusCode, Value) {
    evict(
        h,
        json!({ "workload_id": workload_id, "reason": reason, "message": message }),
    )
    .await
}

async fn status_of(h: &Harness, tenant: &nostr_sdk::Keys, workload_id: &str) -> Value {
    let spec = RequestSpec {
        tenant: nostr_sdk::Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(h, "status", workload_id)
    };
    let (_, body) = post(&h.app, "/status", json!({ "request": spec.sign() })).await;
    body
}

// ── a live lease is evicted ─────────────────────────────────────────────

#[tokio::test]
async fn evicting_a_running_lease_stops_and_deletes_the_workload() {
    let h = harness().await;
    let workload_id = spawn_lease(&h, 1).await;

    let (status, body) = evict_for(&h, &workload_id, "maintenance", "host going down").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], workload_id);
    assert_eq!(body["state"], json!({ "ended": "eviction" }));
    assert_eq!(body["notice_published"], true);

    assert_eq!(
        h.backend.calls()[2..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)],
        "stopped and deleted now, the same discipline as a termination"
    );
}

#[tokio::test]
async fn eviction_publishes_exactly_one_signed_eviction_notice() {
    let h = harness().await;
    let workload_id = spawn_lease(&h, 1).await;

    evict_for(&h, &workload_id, "abuse", "repeated port scans").await;

    let notices = h.directory.of_kind(K_EVICTION);
    assert_eq!(notices.len(), 1, "exactly one Eviction Notice");
    let notice = &notices[0];

    assert_eq!(notice.pubkey, h.provider);
    notice
        .verify()
        .expect("the Eviction Notice is signed by the provider's Nostr key");
    assert!(has_tag(notice, &["x", &workload_id]));
    assert!(has_tag(notice, &["L", TOON_LABEL]));

    let content: EvictionContent = serde_json::from_str(&notice.content).unwrap();
    assert_eq!(content.workload_id, workload_id);
    assert_eq!(serde_json::to_value(content.reason).unwrap(), "abuse");
    assert_eq!(content.message, "repeated port scans");
}

#[tokio::test]
async fn status_after_eviction_reports_ended_eviction_and_no_access() {
    let h = harness().await;
    let tenant_spec = RequestSpec::spawn(&h, &spawn_content(1));
    let tenant = tenant_spec.tenant.clone();
    let content = spawn_content(1);
    let (status, body) = spawn(&h, tenant_spec.sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let workload_id = content.workload_id;

    evict_for(&h, &workload_id, "policy", "").await;

    let status_body = status_of(&h, &tenant, &workload_id).await;
    assert_eq!(status_body["state"], json!({ "ended": "eviction" }));
    assert!(
        status_body["access"].is_null(),
        "the workload is gone; there is nothing to reach"
    );
}

#[tokio::test]
async fn extending_an_evicted_lease_is_refused_expired() {
    let h = harness().await;
    let workload_id = spawn_lease(&h, 1).await;
    evict_for(&h, &workload_id, "abuse", "").await;

    let (status, body) = post(
        &h.app,
        "/listings/basic/v1/extend",
        json!({ "workload_id": workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");
}

// ── refusals ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn evicting_an_unknown_workload_id_is_unknown_workload_and_publishes_nothing() {
    let h = harness().await;
    let (status, body) = evict_for(&h, &workload_id(9), "abuse", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
    assert!(h.directory.published().is_empty());
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn evicting_an_already_ended_lease_is_unknown_workload() {
    let h = harness().await;
    let workload_id = spawn_lease(&h, 1).await;
    let (status, _) = evict_for(&h, &workload_id, "abuse", "first eviction").await;
    assert_eq!(status, StatusCode::OK);

    let published_before = h.directory.published().len();
    let (status, body) = evict_for(&h, &workload_id, "abuse", "second attempt").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
    assert_eq!(
        h.directory.published().len(),
        published_before,
        "a lease already ended publishes no second notice"
    );
}

#[tokio::test]
async fn an_evict_body_that_is_not_the_operator_shape_is_invalid() {
    let h = harness().await;
    let (status, body) = evict(&h, json!({ "hello": 1 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");
}

#[tokio::test]
async fn an_evict_body_with_an_unknown_field_is_invalid() {
    let h = harness().await;
    let (status, body) = evict(
        &h,
        json!({ "workload_id": workload_id(9), "reason": "abuse", "force": true }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");
}

// ── a relay refusal still ends the lease ────────────────────────────────

#[tokio::test]
async fn a_directory_that_cannot_be_reached_still_ends_the_lease() {
    let h = harness().await;
    let workload_id = spawn_lease(&h, 1).await;
    h.directory
        .fail_next_publish("relay refused: out of credit");

    let (status, body) = evict_for(&h, &workload_id, "maintenance", "").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "eviction" }));
    assert_eq!(
        body["notice_published"], false,
        "the publication failed, and the response says so"
    );
    assert_eq!(
        h.backend.calls()[2..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)],
        "the workload is destroyed regardless of whether the notice landed"
    );
}

#[tokio::test]
async fn a_relay_set_reached_only_in_part_still_ends_the_lease() {
    let h = harness().await;
    let workload_id = spawn_lease(&h, 1).await;
    h.directory.relay_always_refuses("wss://relay-two.example");

    let (status, body) = evict_for(&h, &workload_id, "abuse", "").await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "eviction" }));
    assert_eq!(body["notice_published"], false);
    assert_eq!(
        h.directory.of_kind(K_EVICTION).len(),
        1,
        "it still went out, just not to every relay"
    );
}

// ── the operator endpoint is not a connector route ──────────────────────

#[tokio::test]
async fn the_evict_endpoint_is_not_in_the_connector_route_table() {
    let h = harness().await;
    let rows = toon_provider::provider::route_table(&h.service.app_state().config, &[]);
    assert!(
        rows.iter().all(|r| !r.prefix.contains("evict")),
        "the operator surface must never appear in the connector's route table: {rows:?}"
    );
}

#[tokio::test]
async fn the_main_router_does_not_serve_operator_evict() {
    let h = harness().await;
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operator/evict")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "workload_id": workload_id(9), "reason": "abuse" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the connector-facing router must not serve the operator endpoint"
    );
}
