//! A tenant rotates a lease's Continuation Token at one provider (spec §6.8;
//! TOON_Network #70).
//!
//! Rotation is REPLACEMENT: the free `<addr>.rotate` route presents the
//! lease's current token and names the `next` one, and the provider stores
//! `next` in its place and persists the lease before it answers. There is no
//! second value, no grace period and nothing published — so from that moment
//! the old token is `not_tenant`, and every Gateway Grant derived from it is
//! `bad_grant`, because a provider recomputes a grant from whatever token it
//! stores (§6.5.1). That is the whole of revocation (ADR 0018).
//!
//! Everything here is driven through the provider's HTTP surface, the way its
//! connector drives it: a request in, JSON out. Nothing reaches inside, except
//! to assert that a token is ABSENT from the log — which is itself a promise
//! the spec makes on the wire's behalf (§6.1.1).

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::{json, Value};

use common::harness::{
    error_of, harness, harness_with, listing, mint, post, restart, spawn, spawn_content,
    workload_id, Harness, RequestSpec, NOW,
};
use common::{FakeBackend, FakeClock, FakeDirectory};
use nostr_sdk::Keys;
use toon_provider::nostr::continuation::ContinuationToken;
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::{ImagePolicyConfig, Listing};
use toon_provider::Clock;

/// How long past the harness clock a grant in these tests is good for.
const GRANT_TTL: u64 = 3600;

/// A lease that exists, and the Continuation Token it was taken with.
struct Lease {
    token: ContinuationToken,
    workload_id: String,
}

async fn spawn_lease(h: &Harness, seed: u8) -> Lease {
    let content = spawn_content(seed);
    let token = mint().continuation_for(&h.provider);
    let spec = RequestSpec::spawn(h, &content).with_token(&token);
    let (status, body) = spawn(h, spec.request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    Lease {
        token,
        workload_id: content.workload_id,
    }
}

/// The token a tenant rotates to: derived for this provider from a FRESH
/// root secret, as spec §6.8 recommends — the provider cannot tell and does
/// not check, so any 32 bytes other than the current token would do here.
fn fresh_token(h: &Harness) -> ContinuationToken {
    mint().continuation_for(&h.provider)
}

/// The rotate content as spec §6.8 writes it: exactly `workload_id` and
/// `next`.
fn rotate_content(workload_id: &str, next: &ContinuationToken) -> Value {
    json!({ "workload_id": workload_id, "next": next })
}

async fn rotate_raw(h: &Harness, spec: &RequestSpec) -> (StatusCode, Value) {
    post(&h.app, "/rotate", json!({ "request": spec.request() })).await
}

/// `rotate` for `workload_id`, presenting `token` and naming `next`.
async fn rotate(
    h: &Harness,
    token: &ContinuationToken,
    workload_id: &str,
    next: &ContinuationToken,
) -> (StatusCode, Value) {
    let spec = RequestSpec::op(h, "rotate", rotate_content(workload_id, next)).with_token(token);
    rotate_raw(h, &spec).await
}

/// `rotate` with content the caller wrote, presenting `token`.
async fn rotate_with_content(
    h: &Harness,
    token: &ContinuationToken,
    content: Value,
) -> (StatusCode, Value) {
    let spec = RequestSpec::op(h, "rotate", content).with_token(token);
    rotate_raw(h, &spec).await
}

/// `status` for `workload_id`, presenting `token` and asserting the
/// delegation `at` when there is one.
async fn status_with(
    h: &Harness,
    token: &ContinuationToken,
    workload_id: &str,
    at: Option<u64>,
) -> (StatusCode, Value) {
    let mut content = json!({ "workload_id": workload_id });
    if let Some(expires_at) = at {
        content["gateway_expires_at"] = json!(expires_at);
    }
    let spec = RequestSpec::op(h, "status", content).with_token(token);
    post(&h.app, "/status", json!({ "request": spec.request() })).await
}

async fn terminate_with(
    h: &Harness,
    token: &ContinuationToken,
    workload_id: &str,
) -> (StatusCode, Value) {
    let spec = RequestSpec::about(h, "terminate", workload_id).with_token(token);
    post(&h.app, "/terminate", json!({ "request": spec.request() })).await
}

/// The lease's token still reads it: what every refusal test ends with,
/// because a refused rotation must leave the lease exactly as it was.
async fn still_holds(h: &Harness, lease: &Lease) {
    let (status, body) = status_with(h, &lease.token, &lease.workload_id, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a refused rotation leaves the token it found: {}",
        body
    );
}

// ── the rotation itself ──────────────────────────────────────────────────

/// The heart of the ticket: one rotate presenting the current token, and the
/// `next` token is the lease's from then on. The old token is a stranger's,
/// and a grant derived from it delegates nothing — while a grant derived
/// from the NEW token does, so a tenant that keeps its gateway re-derives.
#[tokio::test]
async fn a_rotation_replaces_the_token_and_every_grant_derived_from_it() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let expires_at = h.clock.now() + GRANT_TTL;
    let old_grant = lease.token.gateway_sub(expires_at);
    let (status, body) = status_with(&h, &old_grant, &lease.workload_id, Some(expires_at)).await;
    assert_eq!(status, StatusCode::OK, "the grant reads before: {}", body);

    let next = fresh_token(&h);
    let (status, body) = rotate(&h, &lease.token, &lease.workload_id, &next).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body,
        json!({ "workload_id": lease.workload_id, "rotated": true }),
        "the answer confirms the lease and nothing more"
    );

    let (status, body) = status_with(&h, &next, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], "running", "rotation changes nothing else");

    let (status, body) = status_with(&h, &lease.token, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");

    let (status, body) = status_with(&h, &old_grant, &lease.workload_id, Some(expires_at)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "bad_grant");

    let new_grant = next.gateway_sub(expires_at);
    let (status, body) = status_with(&h, &new_grant, &lease.workload_id, Some(expires_at)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a grant from the new token reads: {}",
        body
    );

    // And every other authority moves with it: the old token cannot end the
    // lease, and the new one can.
    let (_, body) = terminate_with(&h, &lease.token, &lease.workload_id).await;
    assert_eq!(error_of(&body), "not_tenant");
    let (status, body) = terminate_with(&h, &next, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

/// A second rotation presents the token the first one installed. The old one
/// cannot rotate again — which is also how a tenant that lost the answer to
/// its rotation learns nothing it could act on from a retry, and asks
/// `status` with the new token instead (spec §6.8).
#[tokio::test]
async fn a_rotation_chains_and_the_old_token_cannot_rotate_again() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let first = fresh_token(&h);
    let (status, body) = rotate(&h, &lease.token, &lease.workload_id, &first).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let (status, body) = rotate(&h, &lease.token, &lease.workload_id, &fresh_token(&h)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");

    let second = fresh_token(&h);
    let (status, body) = rotate(&h, &first, &lease.workload_id, &second).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let (status, body) = status_with(&h, &second, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let (_, body) = status_with(&h, &first, &lease.workload_id, None).await;
    assert_eq!(error_of(&body), "not_tenant");
}

/// A Warm Standby's reservation can be rotated like a running lease: every
/// state short of Ended can (spec §6.8). It stays `reserved`.
#[tokio::test]
async fn a_reservation_can_be_rotated() {
    let h = harness_with(vec![Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }])
    .await;
    let content = SpawnContent {
        standby_set: Some(vec![
            Keys::generate().public_key().to_hex(),
            h.provider.to_hex(),
        ]),
        ..spawn_content(0xab)
    };
    let token = mint().continuation_for(&h.provider);
    let spec = RequestSpec::standby(&h, &content).with_token(&token);
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby",
        json!({ "request": spec.request() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let next = fresh_token(&h);
    let (status, body) = rotate(&h, &token, &content.workload_id, &next).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let (status, body) = status_with(&h, &next, &content.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], "reserved");
    assert_eq!(body["role"], "standby");
}

/// Rotation survives a restart over the same state directory: the provider
/// persisted the lease before it answered, so a restart cannot bring the
/// old token back (spec §6.8, §6.7).
#[tokio::test]
async fn a_rotation_survives_a_restart() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let next = fresh_token(&h);
    let (status, body) = rotate(&h, &lease.token, &lease.workload_id, &next).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let backend = FakeBackend::new();
    backend.seed_running(1000);
    let h2 = restart(
        vec![listing("basic", 1, 2)],
        h.provider_key.clone(),
        h.state_path.clone(),
        backend,
        FakeClock::at(NOW + 10),
        FakeDirectory::new(),
        common::stub_registry().await,
        ImagePolicyConfig::default(),
    )
    .await;
    h2.service.restore_leases().await;

    let (status, body) = status_with(&h2, &next, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], "running");
    let (status, body) = status_with(&h2, &lease.token, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");
}

/// A rotation is a revocation: the provider may say `rotated: true` only
/// once the new token is on disk. With the state directory unwritable, the
/// save fails, and the route refuses `unavailable` rather than confirm a
/// rotation nobody can be sure survives a restart. The old token still
/// works and `next` is a stranger's, both before and after a restart — and
/// once the directory is writable again, a retry with the same `next`
/// succeeds (TOON_Network#78).
#[tokio::test]
async fn a_rotation_the_provider_cannot_persist_is_refused_unavailable() {
    use std::os::unix::fs::PermissionsExt;

    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let next = fresh_token(&h);

    let state_dir = std::path::Path::new(&h.state_path)
        .parent()
        .unwrap()
        .to_path_buf();
    let writable = std::fs::metadata(&state_dir).unwrap().permissions();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

    let (status, body) = rotate(&h, &lease.token, &lease.workload_id, &next).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{}", body);
    assert_eq!(error_of(&body), "unavailable");
    let next_hex = serde_json::to_value(&next).unwrap();
    let next_hex = next_hex.as_str().unwrap();
    assert!(
        !body.to_string().contains(next_hex),
        "no token appears in the refusal: {}",
        body
    );

    // Before a restart: memory was put back the way it was found.
    still_holds(&h, &lease).await;
    let (status, body) = status_with(&h, &next, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");

    // And after one: the save never reached disk, so a restart over the
    // same (still unwritable) directory agrees with what memory just showed.
    let backend = FakeBackend::new();
    backend.seed_running(1000);
    let h2 = restart(
        vec![listing("basic", 1, 2)],
        h.provider_key.clone(),
        h.state_path.clone(),
        backend,
        FakeClock::at(NOW),
        FakeDirectory::new(),
        common::stub_registry().await,
        ImagePolicyConfig::default(),
    )
    .await;
    h2.service.restore_leases().await;

    let (status, body) = status_with(&h2, &lease.token, &lease.workload_id, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the old token still works: {}",
        body
    );
    assert_eq!(body["state"], "running");
    let (status, body) = status_with(&h2, &next, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");

    // Once saving works again, a retry with the SAME next succeeds.
    std::fs::set_permissions(&state_dir, writable).unwrap();
    let (status, body) = rotate(&h2, &lease.token, &lease.workload_id, &next).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body,
        json!({ "workload_id": lease.workload_id, "rotated": true })
    );
    let (status, body) = status_with(&h2, &next, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let (status, body) = status_with(&h2, &lease.token, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");
}

// ── the refusals, in validation order ────────────────────────────────────

/// A Workload Gateway cannot rotate a lease out from under its tenant: the
/// field that asserts a delegation is named by `status` content alone, so a
/// rotate carrying one is `invalid_request` — refused on its shape, before
/// any lease is looked at (spec §6.5.1, §6.8). And without the field, the
/// grant is just a value that is not the lease's token.
#[tokio::test]
async fn a_gateway_cannot_rotate_with_or_without_asserting_its_grant() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let expires_at = h.clock.now() + GRANT_TTL;
    let grant = lease.token.gateway_sub(expires_at);

    let mut content = rotate_content(&lease.workload_id, &fresh_token(&h));
    content["gateway_expires_at"] = json!(expires_at);
    let (status, body) = rotate_with_content(&h, &grant, content).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    let (status, body) = rotate(&h, &grant, &lease.workload_id, &fresh_token(&h)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");

    still_holds(&h, &lease).await;
}

/// `next` is 32 bytes as 64 lowercase hex characters, and present. Anything
/// else is `invalid_request`: a corrupt rotation must never look like a
/// success, and must never be read as "no rotation" either.
#[tokio::test]
async fn a_malformed_or_missing_next_is_invalid_request() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    for next in [
        json!("AB".repeat(32)),
        json!("ab".repeat(31)),
        json!("ab".repeat(33)),
        json!(""),
        json!(null),
        json!(7),
    ] {
        let content = json!({ "workload_id": lease.workload_id, "next": next });
        let (status, body) = rotate_with_content(&h, &lease.token, content).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{} → {}", next, body);
        assert_eq!(error_of(&body), "invalid_request", "{}", next);
    }
    let (status, body) = rotate_with_content(
        &h,
        &lease.token,
        json!({ "workload_id": lease.workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    still_holds(&h, &lease).await;
}

/// A `next` equal to the token the lease already holds is a no-op dressed as
/// a rotation, and is refused as one rather than answered `rotated: true`.
/// It is weighed only AFTER the request has proved it holds that token, so
/// the refusal is no oracle for a stranger guessing a lease's token.
#[tokio::test]
async fn a_next_equal_to_the_current_token_is_invalid_request() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let (status, body) = rotate(&h, &lease.token, &lease.workload_id, &lease.token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    // A stranger naming the lease's real token as `next` learns nothing: it
    // is refused on its own token first.
    let (status, body) = rotate(&h, &fresh_token(&h), &lease.workload_id, &lease.token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");

    still_holds(&h, &lease).await;
}

/// A wrong token and an absent one are both `not_tenant` (§6.1.2 step 4).
#[tokio::test]
async fn a_rotate_with_a_wrong_or_absent_token_is_not_tenant() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let content = rotate_content(&lease.workload_id, &fresh_token(&h));
    for spec in [
        RequestSpec::op(&h, "rotate", content.clone()),
        RequestSpec::op(&h, "rotate", content.clone()).with_no_token(),
    ] {
        let (status, body) = rotate_raw(&h, &spec).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
        assert_eq!(error_of(&body), "not_tenant");
    }
    still_holds(&h, &lease).await;
}

/// A captured rotation cannot be applied a second time: the replayed
/// `request_id` is `stale_request` (§6.1.2 step 3), before its token is
/// weighed — so it is refused the same whether or not the rotation it
/// carried took effect.
#[tokio::test]
async fn a_replayed_rotate_is_stale_request() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let next = fresh_token(&h);
    let spec = RequestSpec::op(&h, "rotate", rotate_content(&lease.workload_id, &next))
        .with_token(&lease.token);
    let (status, body) = rotate_raw(&h, &spec).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let (status, body) = rotate_raw(&h, &spec).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "stale_request");
}

/// A rotate on the wrong route's `op`, or addressed to another provider, is
/// `invalid_request` at step 1 like any other authenticated route's.
#[tokio::test]
async fn a_rotate_under_another_op_or_to_another_provider_is_invalid_request() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let content = rotate_content(&lease.workload_id, &fresh_token(&h));
    let wrong_op = RequestSpec::op(&h, "terminate", content.clone()).with_token(&lease.token);
    let (status, body) = rotate_raw(&h, &wrong_op).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    let elsewhere = RequestSpec::op(&h, "rotate", content)
        .with_token(&lease.token)
        .addressed_to(Keys::generate().public_key());
    let (status, body) = rotate_raw(&h, &elsewhere).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    // And `rotate` is served on `/rotate` alone: the same request on
    // `/terminate` is the wrong op there.
    let misrouted = RequestSpec::op(
        &h,
        "rotate",
        rotate_content(&lease.workload_id, &fresh_token(&h)),
    )
    .with_token(&lease.token);
    let (_, body) = post(
        &h.app,
        "/terminate",
        json!({ "request": misrouted.request() }),
    )
    .await;
    assert_eq!(error_of(&body), "invalid_request");
    still_holds(&h, &lease).await;
}

#[tokio::test]
async fn a_rotate_for_an_unknown_workload_is_unknown_workload() {
    let h = harness().await;
    let (status, body) = rotate(&h, &fresh_token(&h), &workload_id(0xff), &fresh_token(&h)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

/// An ended lease, however it ended, is `expired`: the tenant learns the
/// lease is gone rather than that its token is wrong. That includes a lease
/// whose `expires_at` has passed before the sweep reached it.
#[tokio::test]
async fn a_rotate_on_an_ended_lease_is_expired() {
    let h = harness().await;
    let terminated = spawn_lease(&h, 0xaa).await;
    let (status, body) = terminate_with(&h, &terminated.token, &terminated.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let (status, body) = rotate(
        &h,
        &terminated.token,
        &terminated.workload_id,
        &fresh_token(&h),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");

    let lapsed = spawn_lease(&h, 0xbb).await;
    h.clock.advance(common::harness::INTERVAL);
    let (status, body) = rotate(&h, &lapsed.token, &lapsed.workload_id, &fresh_token(&h)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");
}

// ── no token reaches a log line or a message ─────────────────────────────

/// A `tracing` writer that keeps everything it is given, so a test can read
/// back every log line the provider wrote.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Neither token — nor a grant of either — appears in any log line the route
/// writes, at any level, nor in any answer it gives, success or refusal
/// (spec §6.1.1). The route is driven through every answer it has.
#[tokio::test]
async fn no_token_reaches_a_log_line_or_an_answer() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    // GLOBAL, not scoped to this thread: `tracing` caches whether a call
    // site is interesting process-wide, and the other tests in this binary
    // run on other threads, so a thread-scoped subscriber here misses lines
    // another test reached first — and an absence proved over a log that
    // was never written proves nothing. Only this test installs one; the
    // others' lines land in the same capture, carrying tokens of their own
    // that are never looked for.
    tracing::subscriber::set_global_default(subscriber)
        .expect("no other test in this binary installs a subscriber");

    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let next = fresh_token(&h);
    let expires_at = h.clock.now() + GRANT_TTL;
    let grant = lease.token.gateway_sub(expires_at);
    let mut answers = Vec::new();

    let mut asserted = rotate_content(&lease.workload_id, &next);
    asserted["gateway_expires_at"] = json!(expires_at);
    answers.push(rotate_with_content(&h, &grant, asserted).await.1);
    answers.push(
        rotate_with_content(
            &h,
            &lease.token,
            json!({ "workload_id": lease.workload_id, "next": "AB".repeat(32) }),
        )
        .await
        .1,
    );
    answers.push(
        rotate(&h, &lease.token, &lease.workload_id, &lease.token)
            .await
            .1,
    );
    answers.push(rotate(&h, &next, &lease.workload_id, &lease.token).await.1);
    answers.push(rotate(&h, &lease.token, &workload_id(0xff), &next).await.1);
    let spec = RequestSpec::op(&h, "rotate", rotate_content(&lease.workload_id, &next))
        .with_token(&lease.token);
    answers.push(rotate_raw(&h, &spec).await.1);
    answers.push(rotate_raw(&h, &spec).await.1);
    answers.push(
        status_with(&h, &lease.token, &lease.workload_id, None)
            .await
            .1,
    );
    answers.push(
        status_with(&h, &grant, &lease.workload_id, Some(expires_at))
            .await
            .1,
    );
    answers.push(terminate_with(&h, &next, &lease.workload_id).await.1);
    answers.push(
        rotate(&h, &next, &lease.workload_id, &fresh_token(&h))
            .await
            .1,
    );
    assert_eq!(error_of(answers.last().unwrap()), "expired");

    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("rotated"),
        "the capture saw the route's own log line: {}",
        log
    );
    for (what, token) in [
        ("the old token", &lease.token),
        ("the new token", &next),
        ("a grant of the old token", &grant),
        ("a grant of the new token", &next.gateway_sub(expires_at)),
    ] {
        let hex = serde_json::to_value(token).unwrap();
        let hex = hex.as_str().unwrap();
        assert!(!log.contains(hex), "{} reached the log:\n{}", what, log);
        for answer in &answers {
            assert!(
                !answer.to_string().contains(hex),
                "{} reached an answer: {}",
                what,
                answer
            );
        }
    }
}

/// Only the rotated lease moves. Another lease of the same tenant on the same
/// provider — each has its own root secret, so its own token — is untouched.
#[tokio::test]
async fn a_rotation_touches_no_other_lease() {
    let h = harness().await;
    let one = spawn_lease(&h, 0xaa).await;
    let two = spawn_lease(&h, 0xbb).await;
    let (status, body) = rotate(&h, &one.token, &one.workload_id, &fresh_token(&h)).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    still_holds(&h, &two).await;
}
