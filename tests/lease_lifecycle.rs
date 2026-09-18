//! What happens to a lease after the spawn: extension, status, termination
//! and expiry (spec §6.3, §6.5, §6.6, §6.7).
//!
//! Driven the way the provider's connector drives it — an HTTP request in,
//! JSON out — and asserted on the answer, on what the faked `ComputeBackend`
//! was asked to do, and on what a restart over the same lease table restores.

mod common;

use axum::http::StatusCode;
use nostr_sdk::Keys;
use serde_json::{json, Value};

use common::harness::{
    error_of, harness, harness_with, listing, mint, post, spawn, spawn_content, workload_id,
    Harness, RequestSpec, INTERVAL, NOW, PUBLIC_IP,
};
use common::{BackendCall, FakeBackend, FakeClock, FakeDirectory};
use std::sync::Arc;
use toon_provider::nostr::continuation::ContinuationToken;
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::Clock;

/// A lease that exists, and the Continuation Token it was taken with — the
/// whole of what a tenant needs to act on it afterwards (spec §6.1).
struct Lease {
    token: ContinuationToken,
    workload_id: String,
    expires_at: u64,
}

async fn spawn_lease(h: &Harness, seed: u8) -> Lease {
    spawn_lease_from(h, spawn_content(seed)).await
}

async fn spawn_lease_from(h: &Harness, content: SpawnContent) -> Lease {
    let token = mint().continuation_for(&h.provider);
    let spec = RequestSpec::spawn(h, &content).with_token(&token);
    let (status, body) = spawn(h, spec.request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    Lease {
        token,
        workload_id: content.workload_id,
        expires_at: body["expires_at"].as_u64().unwrap(),
    }
}

/// `.extend` as a payer's connector forwards it: no signature, just the id.
async fn extend_on(h: &Harness, path: &str, workload_id: &str) -> (StatusCode, Value) {
    post(&h.app, path, json!({ "workload_id": workload_id })).await
}

async fn extend(h: &Harness, workload_id: &str) -> (StatusCode, Value) {
    extend_on(h, "/listings/basic/v1/extend", workload_id).await
}

// ── extension (spec §6.3) ───────────────────────────────────────────────

#[tokio::test]
async fn an_extension_buys_exactly_one_more_lease_interval() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = extend(&h, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], lease.workload_id);
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL,
        "one payment buys one Lease Interval"
    );
    assert!(
        h.backend
            .calls()
            .iter()
            .all(|c| !matches!(c, BackendCall::Stop(_) | BackendCall::Delete(_))),
        "an extension touches no workload"
    );
}

#[tokio::test]
async fn extensions_stack() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (_, first) = extend(&h, &lease.workload_id).await;
    let (_, second) = extend(&h, &lease.workload_id).await;
    assert_eq!(
        first["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL
    );
    assert_eq!(
        second["expires_at"].as_u64().unwrap(),
        lease.expires_at + 2 * INTERVAL,
        "time is added to the expiry, not to `now`"
    );
}

#[tokio::test]
async fn a_second_payer_may_extend_a_lease_it_did_not_spawn() {
    // ADR 0005: an extension carries no Lease Request and reveals nothing,
    // so a sponsor pays for someone else's lease with its own channel. There
    // is nothing in the request that says who paid.
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = extend(&h, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL
    );
}

/// An extension gained no Continuation Token check, and could not carry one
/// if it wanted to. It only adds time (ADR 0005), so a payer that never
/// learnt the token still buys an interval for the lease — and a body that
/// offers one is an unknown field like any other.
#[tokio::test]
async fn an_extension_takes_no_token_and_refuses_one() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    // No token, from a payer that holds none: accepted.
    let (status, body) = extend(&h, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL
    );

    // The lease's OWN token, offered anyway: `.extend` names no such field.
    let (status, body) = post(
        &h.app,
        "/listings/basic/v1/extend",
        json!({
            "workload_id": lease.workload_id,
            "continuation": lease.token,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");
}

#[tokio::test]
async fn extending_a_lease_this_provider_never_had_is_unknown_workload() {
    let h = harness().await;
    let (status, body) = extend(&h, &workload_id(9)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

#[tokio::test]
async fn extending_an_expired_lease_is_refused() {
    // Money must never buy time on a lease that cannot run.
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    h.clock.set(lease.expires_at);
    h.service.sweep_expired_leases(h.clock.now()).await;

    let (status, body) = extend(&h, &lease.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");
}

#[tokio::test]
async fn an_expiry_the_sweep_has_not_reached_yet_still_refuses_an_extension() {
    // The sweep runs every 30 s, and there is no grace period: a lease is
    // over the instant its expiry passes, not when the sweep notices.
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    h.clock.set(lease.expires_at);
    let (status, body) = extend(&h, &lease.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");

    // And so does a termination: the lease is already over.
    let (status, body) = terminate_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");
}

#[tokio::test]
async fn extending_on_another_listing_version_is_wrong_listing_version() {
    // ADR 0009: a lease keeps the price it started at, so an extension must
    // be bought on the route the lease was spawned on. v2 is the version on
    // sale here, so the lease is bought there and v1 is the retired route it
    // must not be extendable on.
    let h = harness_with(vec![listing("basic", 1, 2), listing("basic", 2, 2)]).await;
    let content = spawn_content(1);
    let (status, body) = post(
        &h.app,
        "/listings/basic/v2/spawn",
        json!({ "request": RequestSpec::spawn(&h, &content).request() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let expires_at = body["expires_at"].as_u64().unwrap();

    let (status, body) = extend_on(&h, "/listings/basic/v1/extend", &content.workload_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "wrong_listing_version");

    // ...and the lease keeps the expiry it had.
    let (_, body) = extend_on(&h, "/listings/basic/v2/extend", &content.workload_id).await;
    assert_eq!(body["expires_at"].as_u64().unwrap(), expires_at + INTERVAL);
}

#[tokio::test]
async fn an_extension_body_that_is_not_a_workload_id_is_invalid() {
    let h = harness().await;
    let (status, body) = post(&h.app, "/listings/basic/v1/extend", json!({ "hello": 1 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");
}

// ── status (spec §6.5) ──────────────────────────────────────────────────

async fn status_with(
    h: &Harness,
    token: &ContinuationToken,
    workload_id: &str,
) -> (StatusCode, Value) {
    let spec = RequestSpec::about(h, "status", workload_id).with_token(token);
    post(&h.app, "/status", json!({ "request": spec.request() })).await
}

#[tokio::test]
async fn status_reports_the_state_the_expiry_and_the_access_details() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], lease.workload_id);
    assert_eq!(body["role"], "standalone");
    assert_eq!(body["state"], "running");
    assert_eq!(body["expires_at"].as_u64().unwrap(), lease.expires_at);
    assert_eq!(body["access"]["host"], PUBLIC_IP);
    assert_eq!(body["access"]["ssh_port"], 40000);
    assert_eq!(
        body["access"]["ports"],
        json!([{ "container_port": 443, "host_port": 41000 }])
    );
}

/// The `30436:<pubkey>:<d>` a tenant that expanded a Template puts in its
/// spawn (spec §6.2). Nothing here reads it — that is the point.
const TEMPLATE: &str =
    "30436:2c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991:static-site";

/// A spawn a tenant made by expanding `TEMPLATE`, rather than by hand.
fn from_template(seed: u8) -> SpawnContent {
    SpawnContent {
        template: Some(TEMPLATE.to_string()),
        ..spawn_content(seed)
    }
}

#[tokio::test]
async fn status_reports_the_template_a_spawn_carried_and_says_nothing_when_it_carried_none() {
    // Spec §6.2, ADR 0004: `template` is INFORMATIONAL. The provider keeps it
    // with the lease and hands it back so tooling can show where a spawn's
    // values came from, and never acts on it.
    let h = harness().await;
    let expanded = spawn_lease_from(&h, from_template(1)).await;
    let by_hand = spawn_lease(&h, 2).await;

    let (status, body) = status_with(&h, &expanded.token, &expanded.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["template"], TEMPLATE);

    let (status, body) = status_with(&h, &by_hand.token, &by_hand.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body.get("template"),
        None,
        "a spawn that named no Template reports none"
    );
}

#[tokio::test]
async fn a_spawns_template_is_never_looked_up() {
    // The provider NEVER reads a Template (spec §8.3): a tenant expands one
    // and signs the result. `Directory` is the provider's whole relay
    // surface — `publish` and `query_liveness`, and nothing else
    // (src/directory.rs) — so a spawn that names a Template leaving both
    // journals empty is the whole of "it looked nothing up". What it RUNS is
    // unchanged too; tests/spawn.rs compares the two container configs.
    let h = harness().await;
    spawn_lease_from(&h, from_template(1)).await;

    assert!(
        h.directory.reads().is_empty(),
        "the Directory was asked {:?}",
        h.directory.reads()
    );
    assert!(h.directory.published().is_empty());
}

#[tokio::test]
async fn a_restart_keeps_the_template_a_lease_was_spawned_from() {
    // It is part of the lease record, so it survives exactly as the tenant,
    // the expiry and the access details do.
    let h = harness().await;
    let lease = spawn_lease_from(&h, from_template(1)).await;

    let backend = FakeBackend::new();
    backend.seed_running(1000);
    let h2 = restarted(&h, NOW + 10, backend).await;
    h2.service.restore_leases().await;

    let (status, body) = status_with(&h2, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["template"], TEMPLATE);
}

#[tokio::test]
async fn status_follows_the_expiry_an_extension_bought() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    extend(&h, &lease.workload_id).await;

    let (_, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL
    );
}

/// A wrong token, no token at all, and a token that belongs to another
/// lease of this same provider: three ways of not being the party that took
/// this lease, and one answer to all three (spec §6.1). An absent token is
/// never read as an unauthenticated success, and none of the three answers
/// says which of them it was.
#[tokio::test]
async fn a_status_with_a_wrong_an_absent_or_another_leases_token_is_not_tenant() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    let other = spawn_lease(&h, 2).await;

    let stranger = mint().continuation_for(&h.provider);
    for spec in [
        RequestSpec::about(&h, "status", &lease.workload_id).with_token(&stranger),
        RequestSpec::about(&h, "status", &lease.workload_id).with_no_token(),
        RequestSpec::about(&h, "status", &lease.workload_id).with_token(&other.token),
    ] {
        let (status, body) = post(&h.app, "/status", json!({ "request": spec.request() })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
        assert_eq!(error_of(&body), "not_tenant");
        assert!(
            !body["message"]
                .as_str()
                .unwrap()
                .contains(&lease.workload_id),
            "a refusal says nothing about the lease: {}",
            body
        );
    }

    // And the lease's own token still reads it.
    let (status, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

/// A Continuation Token reaches no answer a provider sends, refusal or not
/// (spec §6.1.1). The token type makes that hold by construction — it
/// redacts its own `Debug`, has no `Display` and hands its bytes to nobody
/// but serde — and this is the route-level proof: neither the token the
/// request presented nor the token the lease stored is anywhere in what
/// comes back.
#[tokio::test]
async fn no_answer_ever_quotes_a_continuation_token() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    let stranger = mint().continuation_for(&h.provider);
    let quoted = |body: &Value, token: &ContinuationToken| {
        let hex = serde_json::to_value(token).unwrap();
        body.to_string().contains(hex.as_str().unwrap())
    };

    for spec in [
        RequestSpec::about(&h, "status", &lease.workload_id).with_token(&stranger),
        RequestSpec::about(&h, "terminate", &lease.workload_id).with_token(&stranger),
    ] {
        let path = format!("/{}", spec.op);
        let (_, body) = post(&h.app, &path, json!({ "request": spec.request() })).await;
        assert_eq!(error_of(&body), "not_tenant", "{}", body);
        assert!(!quoted(&body, &stranger), "the presented token: {}", body);
        assert!(!quoted(&body, &lease.token), "the stored token: {}", body);
    }

    // Nor does a successful answer, which has every reason to echo the lease
    // and no reason to echo its secret.
    let (_, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert!(!quoted(&body, &lease.token), "{}", body);
}

#[tokio::test]
async fn status_for_a_lease_this_provider_never_had_is_unknown_workload() {
    let h = harness().await;
    let (status, body) =
        status_with(&h, &mint().continuation_for(&h.provider), &workload_id(9)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

#[tokio::test]
async fn a_replayed_status_request_is_refused() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    let spec = RequestSpec::about(&h, "status", &lease.workload_id).with_token(&lease.token);
    let request = spec.request();

    let (status, _) = post(&h.app, "/status", json!({ "request": request.clone() })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(&h.app, "/status", json!({ "request": request })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "stale_request");
}

/// A Lease Request names ONE provider, on every op (§6.1). A request naming
/// somebody else is a request for somebody else, and is never accepted here
/// however good its token is.
#[tokio::test]
async fn a_status_or_terminate_naming_another_provider_is_refused() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    for op in ["status", "terminate"] {
        let spec = RequestSpec::about(&h, op, &lease.workload_id)
            .with_token(&lease.token)
            .addressed_to(Keys::generate().public_key());
        let (status, body) = post(
            &h.app,
            &format!("/{}", op),
            json!({ "request": spec.request() }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
        assert_eq!(error_of(&body), "invalid_request");
    }
    // The lease is untouched: still running, still reachable.
    let (_, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(body["state"], "running", "{}", body);
    assert!(matches!(
        h.backend.calls().as_slice(),
        [BackendCall::Create(_), BackendCall::Start(_)]
    ));
}

#[tokio::test]
async fn a_status_request_signed_for_another_op_is_invalid() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    let spec = RequestSpec::about(&h, "terminate", &lease.workload_id).with_token(&lease.token);
    let (_, body) = post(&h.app, "/status", json!({ "request": spec.request() })).await;
    assert_eq!(error_of(&body), "invalid_request");
}

#[tokio::test]
async fn status_reports_a_lease_that_ended_by_expiry() {
    // §6.7 states are reported after the fact: a tenant that stopped paying
    // must be able to learn that its lease expired rather than that its id is
    // unknown.
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    h.clock.set(lease.expires_at);
    h.service.sweep_expired_leases(h.clock.now()).await;

    let (status, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "expiry" }));
    assert!(
        body["access"].is_null(),
        "the workload is gone; there is nothing to reach"
    );
}

// ── termination (spec §6.6) ─────────────────────────────────────────────

async fn terminate_with(
    h: &Harness,
    token: &ContinuationToken,
    workload_id: &str,
) -> (StatusCode, Value) {
    let spec = RequestSpec::about(h, "terminate", workload_id).with_token(token);
    post(&h.app, "/terminate", json!({ "request": spec.request() })).await
}

#[tokio::test]
async fn terminate_destroys_the_workload_immediately() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = terminate_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], lease.workload_id);
    assert_eq!(body["state"], json!({ "ended": "termination" }));
    assert_eq!(
        h.backend.calls()[2..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)],
        "stopped and deleted now, not at the next sweep"
    );

    let (_, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(body["state"], json!({ "ended": "termination" }));
}

/// The same three refusals `status` gives, on the route that would destroy
/// the workload. Nothing reaches the backend for any of them.
#[tokio::test]
async fn a_terminate_with_a_wrong_an_absent_or_another_leases_token_is_not_tenant() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    let other = spawn_lease(&h, 2).await;

    let stranger = mint().continuation_for(&h.provider);
    for spec in [
        RequestSpec::about(&h, "terminate", &lease.workload_id).with_token(&stranger),
        RequestSpec::about(&h, "terminate", &lease.workload_id).with_no_token(),
        RequestSpec::about(&h, "terminate", &lease.workload_id).with_token(&other.token),
    ] {
        let (status, body) = post(&h.app, "/terminate", json!({ "request": spec.request() })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
        assert_eq!(error_of(&body), "not_tenant");
    }
    assert_eq!(
        h.backend.calls().len(),
        4,
        "two spawns' create and start, and nothing else"
    );
}

#[tokio::test]
async fn terminate_for_a_lease_this_provider_never_had_is_unknown_workload() {
    let h = harness().await;
    let (status, body) =
        terminate_with(&h, &mint().continuation_for(&h.provider), &workload_id(9)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

#[tokio::test]
async fn an_extension_after_a_termination_is_refused() {
    // No refund and no resurrection: the lease is over, so the money would
    // buy time on a workload that no longer exists.
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    terminate_with(&h, &lease.token, &lease.workload_id).await;

    let (status, body) = extend(&h, &lease.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");
}

#[tokio::test]
async fn terminating_an_ended_lease_again_is_refused() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    terminate_with(&h, &lease.token, &lease.workload_id).await;

    // A second later, so this is a new request and not a replay of the first.
    h.clock.advance(1);
    let (status, body) = terminate_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");
    assert_eq!(
        h.backend.calls().len(),
        4,
        "create, start, stop, delete — the workload is destroyed once"
    );
}

// ── expiry (spec §6.7) ──────────────────────────────────────────────────

#[test]
#[allow(clippy::assertions_on_constants, reason = "the constant IS the claim")]
fn the_sweep_runs_at_least_every_thirty_seconds() {
    assert!(
        toon_provider::SWEEP_INTERVAL_SECS <= 30,
        "the spec requires a sweep at least every 30 s"
    );
}

#[tokio::test]
async fn a_lease_whose_expiry_passed_is_destroyed_by_the_next_sweep() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    h.clock.set(lease.expires_at - 1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(h.backend.calls().len(), 2, "still paid for");

    h.clock.set(lease.expires_at);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(
        h.backend.calls()[2..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)],
        "no grace period"
    );
}

#[tokio::test]
async fn a_workload_the_backend_refused_to_delete_is_retried_on_later_sweeps() {
    // The lease is over either way — but a container that is still running
    // must not be left behind, so the sweep keeps asking until the backend
    // confirms it is gone.
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    h.backend.fail_next_delete("daemon is busy");

    h.clock.set(lease.expires_at);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(
        h.backend.calls()[2..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)]
    );
    assert_eq!(
        h.backend.status_of(1000),
        toon_provider::ContainerStatus::Stopped,
        "the delete failed, so the workload is still there"
    );

    h.clock.advance(30);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(
        h.backend.calls()[4..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)],
        "the next sweep tries again"
    );
    assert_eq!(
        h.backend.status_of(1000),
        toon_provider::ContainerStatus::Absent
    );

    // Once it is gone it is not asked for again.
    h.clock.advance(30);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(h.backend.calls().len(), 6);
}

#[tokio::test]
async fn an_ended_lease_is_forgotten_once_its_retention_runs_out() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    terminate_with(&h, &lease.token, &lease.workload_id).await;

    // Still answerable a day after it ENDED, to the second — the expiry it
    // would have had is not what retention counts from.
    h.clock.set(NOW + 86_400 - 1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    let (status, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    // ...and pruned after it.
    h.clock.advance(1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    let (status, body) = status_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

// ── across a restart (spec §6.7) ────────────────────────────────────────

/// A new provider process over the same lease table and a fresh backend —
/// what a restart looks like from here. The caller seeds the backend with
/// whatever survived the restart.
async fn restarted(h: &Harness, at: u64, backend: Arc<FakeBackend>) -> Harness {
    common::harness::restart(
        vec![listing("basic", 1, 2)],
        h.provider_key.clone(),
        h.state_path.clone(),
        backend,
        FakeClock::at(at),
        FakeDirectory::new(),
        common::stub_registry().await,
        toon_provider::provider::ImagePolicyConfig::default(),
    )
    .await
}

#[tokio::test]
async fn a_restart_keeps_a_running_lease_with_its_expiry_token_and_access() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    extend(&h, &lease.workload_id).await;

    let backend = FakeBackend::new();
    backend.seed_running(1000);
    let h2 = restarted(&h, NOW + 10, backend).await;
    h2.service.restore_leases().await;

    let (status, body) = status_with(&h2, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], "running");
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL,
        "the extension it had already bought"
    );
    assert_eq!(body["access"]["ssh_port"], 40000);

    // Its token is still the only one that may ask: the restart restored it
    // with the lease (spec §6.1).
    let (_, body) = status_with(
        &h2,
        &mint().continuation_for(&h2.provider),
        &lease.workload_id,
    )
    .await;
    assert_eq!(error_of(&body), "not_tenant");

    // And it can still be extended on the route it was spawned on.
    let (status, body) = extend(&h2, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + 2 * INTERVAL
    );
}

#[tokio::test]
async fn a_restart_keeps_an_ended_lease_ended() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    terminate_with(&h, &lease.token, &lease.workload_id).await;

    // Nothing is seeded on the new backend: the workload really is gone.
    let backend = FakeBackend::new();
    let h2 = restarted(&h, NOW + 10, backend.clone()).await;
    h2.service.restore_leases().await;

    let (status, body) = status_with(&h2, &lease.token, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["state"],
        json!({ "ended": "termination" }),
        "how a lease ended survives the restart that follows it"
    );
    assert!(
        backend.calls().is_empty(),
        "an ended lease is not re-reaped"
    );
}
