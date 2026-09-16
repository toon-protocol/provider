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
    error_of, harness, harness_with, listing, post, spawn, spawn_content, workload_id, Harness,
    RequestSpec, INTERVAL, NOW, PUBLIC_IP,
};
use common::{BackendCall, FakeBackend, FakeClock, FakeDirectory};
use std::sync::Arc;
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::Clock;

/// A lease that exists, and the tenant that owns it.
struct Lease {
    tenant: Keys,
    workload_id: String,
    expires_at: u64,
}

async fn spawn_lease(h: &Harness, seed: u8) -> Lease {
    spawn_lease_from(h, spawn_content(seed)).await
}

async fn spawn_lease_from(h: &Harness, content: SpawnContent) -> Lease {
    let spec = RequestSpec::spawn(h, &content);
    let tenant = Keys::parse(&spec.tenant.secret_key().to_secret_hex()).unwrap();
    let (status, body) = spawn(h, spec.sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    Lease {
        tenant,
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
    // ADR 0005: an extension carries no signature and reveals nothing, so a
    // sponsor pays for someone else's lease with its own channel. There is
    // nothing in the request that says who paid.
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = extend(&h, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL
    );
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
    let (status, body) = terminate_signed_by(&h, &lease.tenant, &lease.workload_id).await;
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
        json!({ "request": RequestSpec::spawn(&h, &content).sign() }),
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

async fn status_signed_by(h: &Harness, tenant: &Keys, workload_id: &str) -> (StatusCode, Value) {
    let spec = RequestSpec {
        tenant: Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(h, "status", workload_id)
    };
    post(&h.app, "/status", json!({ "request": spec.sign() })).await
}

#[tokio::test]
async fn status_reports_the_state_the_expiry_and_the_access_details() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = status_signed_by(&h, &lease.tenant, &lease.workload_id).await;
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

    let (status, body) = status_signed_by(&h, &expanded.tenant, &expanded.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["template"], TEMPLATE);

    let (status, body) = status_signed_by(&h, &by_hand.tenant, &by_hand.workload_id).await;
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

    let (status, body) = status_signed_by(&h2, &lease.tenant, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["template"], TEMPLATE);
}

#[tokio::test]
async fn status_follows_the_expiry_an_extension_bought() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    extend(&h, &lease.workload_id).await;

    let (_, body) = status_signed_by(&h, &lease.tenant, &lease.workload_id).await;
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL
    );
}

#[tokio::test]
async fn status_signed_by_anyone_but_the_tenant_is_not_tenant() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = status_signed_by(&h, &Keys::generate(), &lease.workload_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");
}

#[tokio::test]
async fn status_for_a_lease_this_provider_never_had_is_unknown_workload() {
    let h = harness().await;
    let (status, body) = status_signed_by(&h, &Keys::generate(), &workload_id(9)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

#[tokio::test]
async fn a_replayed_status_request_is_refused() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    let spec = RequestSpec {
        tenant: Keys::parse(&lease.tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(&h, "status", &lease.workload_id)
    };
    let event = spec.sign();

    let (status, _) = post(&h.app, "/status", json!({ "request": event.clone() })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(&h.app, "/status", json!({ "request": event })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "stale_request");
}

/// Only a spawn may name more than one provider, because one signed spawn
/// forms a whole Standby Set (§6.1, §7). A status or a termination is about
/// one lease on one provider, so naming a second one is a request addressed
/// to somebody else as much as to us.
#[tokio::test]
async fn a_status_or_terminate_naming_a_second_provider_is_refused() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    for op in ["status", "terminate"] {
        let spec = RequestSpec {
            tenant: Keys::parse(&lease.tenant.secret_key().to_secret_hex()).unwrap(),
            ..RequestSpec::about(&h, op, &lease.workload_id)
        }
        .addressed_to(&[h.provider, Keys::generate().public_key()]);
        let (status, body) = post(
            &h.app,
            &format!("/{}", op),
            json!({ "request": spec.sign() }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
        assert_eq!(error_of(&body), "invalid_request");
    }
    // The lease is untouched: still running, still reachable.
    let (_, body) = status_signed_by(&h, &lease.tenant, &lease.workload_id).await;
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
    let spec = RequestSpec {
        tenant: Keys::parse(&lease.tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(&h, "terminate", &lease.workload_id)
    };
    let (_, body) = post(&h.app, "/status", json!({ "request": spec.sign() })).await;
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

    let (status, body) = status_signed_by(&h, &lease.tenant, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "expiry" }));
    assert!(
        body["access"].is_null(),
        "the workload is gone; there is nothing to reach"
    );
}

// ── termination (spec §6.6) ─────────────────────────────────────────────

async fn terminate_signed_by(h: &Harness, tenant: &Keys, workload_id: &str) -> (StatusCode, Value) {
    let spec = RequestSpec {
        tenant: Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(h, "terminate", workload_id)
    };
    post(&h.app, "/terminate", json!({ "request": spec.sign() })).await
}

#[tokio::test]
async fn terminate_destroys_the_workload_immediately() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = terminate_signed_by(&h, &lease.tenant, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], lease.workload_id);
    assert_eq!(body["state"], json!({ "ended": "termination" }));
    assert_eq!(
        h.backend.calls()[2..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)],
        "stopped and deleted now, not at the next sweep"
    );

    let (_, body) = status_signed_by(&h, &lease.tenant, &lease.workload_id).await;
    assert_eq!(body["state"], json!({ "ended": "termination" }));
}

#[tokio::test]
async fn terminate_signed_by_anyone_but_the_tenant_is_not_tenant() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;

    let (status, body) = terminate_signed_by(&h, &Keys::generate(), &lease.workload_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");
    assert_eq!(
        h.backend.calls().len(),
        2,
        "the spawn's create and start, and nothing else"
    );
}

#[tokio::test]
async fn terminate_for_a_lease_this_provider_never_had_is_unknown_workload() {
    let h = harness().await;
    let (status, body) = terminate_signed_by(&h, &Keys::generate(), &workload_id(9)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

#[tokio::test]
async fn an_extension_after_a_termination_is_refused() {
    // No refund and no resurrection: the lease is over, so the money would
    // buy time on a workload that no longer exists.
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    terminate_signed_by(&h, &lease.tenant, &lease.workload_id).await;

    let (status, body) = extend(&h, &lease.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");
}

#[tokio::test]
async fn terminating_an_ended_lease_again_is_refused() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    terminate_signed_by(&h, &lease.tenant, &lease.workload_id).await;

    // A second later, so this is a new request and not a replay of the first.
    h.clock.advance(1);
    let (status, body) = terminate_signed_by(&h, &lease.tenant, &lease.workload_id).await;
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
    terminate_signed_by(&h, &lease.tenant, &lease.workload_id).await;

    // Still answerable a day after it ENDED, to the second — the expiry it
    // would have had is not what retention counts from.
    h.clock.set(NOW + 86_400 - 1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    let (status, body) = status_signed_by(&h, &lease.tenant, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    // ...and pruned after it.
    h.clock.advance(1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    let (status, body) = status_signed_by(&h, &lease.tenant, &lease.workload_id).await;
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
async fn a_restart_keeps_a_running_lease_with_its_expiry_tenant_and_access() {
    let h = harness().await;
    let lease = spawn_lease(&h, 1).await;
    extend(&h, &lease.workload_id).await;

    let backend = FakeBackend::new();
    backend.seed_running(1000);
    let h2 = restarted(&h, NOW + 10, backend).await;
    h2.service.restore_leases().await;

    let (status, body) = status_signed_by(&h2, &lease.tenant, &lease.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], "running");
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        lease.expires_at + INTERVAL,
        "the extension it had already bought"
    );
    assert_eq!(body["access"]["ssh_port"], 40000);

    // Its tenant is still the only one that may ask.
    let (_, body) = status_signed_by(&h2, &Keys::generate(), &lease.workload_id).await;
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
    terminate_signed_by(&h, &lease.tenant, &lease.workload_id).await;

    // Nothing is seeded on the new backend: the workload really is gone.
    let backend = FakeBackend::new();
    let h2 = restarted(&h, NOW + 10, backend.clone()).await;
    h2.service.restore_leases().await;

    let (status, body) = status_signed_by(&h2, &lease.tenant, &lease.workload_id).await;
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
