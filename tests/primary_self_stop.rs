//! A primary stops its own workload when its relays stop taking its Liveness,
//! and starts it again only if nobody took the workload over (spec §7.1,
//! "Primary self-stop"; ADR 0010).
//!
//! Every test here holds a lease bought through the paid routes, exactly as a
//! tenant's would be, and then drives the LIVENESS PUBLICATION cadence by
//! cadence on a fake clock over a fake Directory whose per-relay answer the
//! test sets: a minority of the Relay Set refusing is a primary that still
//! has its majority, a strict majority refusing is one that has lost it. The
//! assertions are on what the fake backend was asked to do and on what
//! `status` answers, never on the provider's internal state.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use nostr_sdk::Keys;
use serde_json::{json, Value};

use common::harness::{
    config_for, harness_from, listing, mint, post, spawn_content, Harness, RequestSpec, INTERVAL,
    NOW,
};
use common::{stub_registry, BackendCall, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::continuation::ContinuationToken;
use toon_provider::nostr::directory_events::takeover_event;
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::{persisted_leases, ImagePolicyConfig, Listing, SELF_STOP_CADENCES};

/// This provider's own Relay Set: what its Liveness is offered to, and so
/// what its own majority is counted against. Three, so a minority and a
/// majority are different things.
const OWN_RELAYS: [&str; 3] = [
    "ws://own-one:7100",
    "ws://own-two:7100",
    "ws://own-three:7100",
];

/// The provider's `liveness_cadence_s`: how far apart the publications a test
/// drives are, purely so the instants read like cadences.
const CADENCE: u64 = 60;

fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

/// A provider with a Relay Set of its own, whose Directory reports every
/// publication relay by relay against it — which is what makes a majority
/// countable at all.
async fn primary_harness(
    provider_key: &str,
    state_path: &str,
    backend: Arc<FakeBackend>,
    clock: Arc<FakeClock>,
    directory: Arc<FakeDirectory>,
) -> Harness {
    let registry = stub_registry().await;
    let mut config = config_for(
        vec![warm(), listing("basic", 1, 2)],
        provider_key,
        state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    config.relay_set = OWN_RELAYS.map(String::from).to_vec();
    config.liveness_cadence_s = CADENCE;
    directory.publishes_to(&OWN_RELAYS);
    harness_from(config, backend, clock, directory, registry)
}

async fn fresh() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    primary_harness(
        &Keys::generate().secret_key().to_secret_hex(),
        &state_path,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
    )
    .await
}

/// The same provider process again over the same lease table, backend and
/// Directory: a restart.
async fn restart(h: &Harness) -> Harness {
    primary_harness(
        &h.provider_key,
        &h.state_path,
        h.backend.clone(),
        h.clock.clone(),
        h.directory.clone(),
    )
    .await
}

/// One lease this provider holds, and whom it holds it with.
struct Lease {
    id: u32,
    /// The Continuation Token it was taken with: what every later request
    /// about it presents (spec §6.1).
    token: ContinuationToken,
    workload_id: String,
    /// The one Warm Standby behind it; nobody, for a standalone lease.
    standby: Option<Keys>,
}

fn lease_id(h: &Harness, workload_id: &str) -> u32 {
    persisted_leases(&h.state_path)
        .into_iter()
        .find(|l| l.workload_id == workload_id)
        .unwrap_or_else(|| panic!("no lease for {workload_id}"))
        .id
}

/// Buy a PRIMARY lease on `warm.v1.spawn`: one signed spawn naming a Standby
/// Set with this provider at index 0 and one Warm Standby behind it.
async fn spawn_primary(h: &Harness, seed: u8) -> Lease {
    let standby = Keys::generate();
    let set = [h.provider, standby.public_key()];
    let content = SpawnContent {
        standby_set: Some(set.iter().map(|k| k.to_hex()).collect()),
        ..spawn_content(seed)
    };
    let token = mint().continuation_for(&h.provider);
    let spec = RequestSpec::spawn(h, &content).with_token(&token);
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/spawn",
        json!({ "request": spec.request() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"], "primary");
    Lease {
        id: lease_id(h, &content.workload_id),
        token,
        workload_id: content.workload_id,
        standby: Some(standby),
    }
}

/// Buy a STANDALONE lease on `basic.v1.spawn`: no Standby Set, nobody
/// watching, nobody to take it over.
async fn spawn_standalone(h: &Harness, seed: u8) -> Lease {
    let content = spawn_content(seed);
    let token = mint().continuation_for(&h.provider);
    let spec = RequestSpec::spawn(h, &content).with_token(&token);
    let (status, body) = post(
        &h.app,
        "/listings/basic/v1/spawn",
        json!({ "request": spec.request() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"], "standalone");
    Lease {
        id: lease_id(h, &content.workload_id),
        token,
        workload_id: content.workload_id,
        standby: None,
    }
}

/// Which relays of the Relay Set refuse this provider's Liveness from now on.
fn liveness_refused_on(h: &Harness, relays: &[&str]) {
    h.directory.refuse_liveness_on(relays);
}

/// One Liveness cadence at `at`, exactly as `directory_loop` publishes one.
async fn cadence(h: &Harness, at: u64) {
    h.clock.set(at);
    h.service.publish_liveness(at).await.expect("published");
}

/// `n` cadences, one per `CADENCE`, starting one cadence after `NOW`.
async fn cadences(h: &Harness, n: u64) {
    cadences_from(h, 1, n).await;
}

/// `n` cadences, one per `CADENCE`, starting at the `from`-th after `NOW`.
async fn cadences_from(h: &Harness, from: u64, n: u64) {
    for i in from..from + n {
        cadence(h, NOW + i * CADENCE).await;
    }
}

/// A Takeover of `lease`'s workload id, as its own Warm Standby publishes one
/// to this provider's Relay Set (spec §7.1 step 2).
fn takeover_by_the_standby(h: &Harness, lease: &Lease, at: u64) {
    let standby = lease.standby.as_ref().expect("a standby set");
    h.directory.seed_takeover(
        takeover_event(&lease.workload_id, &h.provider, standby, at).expect("a Takeover"),
    );
}

/// A Takeover of `lease`'s workload id signed by a provider that is in no
/// Standby Set of this lease.
fn takeover_by_a_stranger(h: &Harness, lease: &Lease, at: u64) {
    let stranger = Keys::generate();
    h.directory.seed_takeover(
        takeover_event(&lease.workload_id, &h.provider, &stranger, at).expect("a Takeover"),
    );
}

/// `status` presenting the lease's own Continuation Token.
async fn status_of(h: &Harness, lease: &Lease) -> Value {
    let spec = RequestSpec::about(h, "status", &lease.workload_id).with_token(&lease.token);
    post(&h.app, "/status", json!({ "request": spec.request() }))
        .await
        .1
}

async fn extend(h: &Harness, lease: &Lease, listing: &str) -> (StatusCode, Value) {
    post(
        &h.app,
        &format!("/listings/{listing}/v1/extend"),
        json!({ "workload_id": lease.workload_id }),
    )
    .await
}

/// Everything the backend was asked to do to `id` since the spawn, which
/// ends with a start.
fn calls_for(h: &Harness, id: u32) -> Vec<BackendCall> {
    h.backend
        .calls()
        .into_iter()
        .filter(|c| matches!(c, BackendCall::Stop(i) | BackendCall::Start(i) if *i == id))
        .collect()
}

/// The stops and starts after the spawn's own `Start`.
fn calls_after_spawn(h: &Harness, id: u32) -> Vec<BackendCall> {
    let mut calls = calls_for(h, id);
    assert_eq!(calls.first(), Some(&BackendCall::Start(id)), "the spawn");
    calls.remove(0);
    calls
}

// ── counting the provider's own majority ─────────────────────────────────

/// One relay of three refusing is not a lost majority, however long it lasts:
/// a primary whose Liveness two relays still hold is a primary every standby
/// can still see (spec §7.1).
#[tokio::test]
async fn a_minority_of_relays_refusing_stops_nothing() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    liveness_refused_on(&h, &[OWN_RELAYS[0]]);
    cadences(&h, u64::from(SELF_STOP_CADENCES) + 2).await;

    assert_eq!(calls_after_spawn(&h, primary.id), vec![]);
    assert_eq!(status_of(&h, &primary).await["state"], "running");
}

/// Five cadences without a strict majority, and EVERY primary lease's
/// workload is stopped — a standalone one on the same provider is not. A
/// standalone lease is in no Standby Set: nobody is waiting to take it over,
/// so stopping it would take a paid workload down for nothing.
#[tokio::test]
async fn five_cadences_without_a_majority_stop_every_primary_and_no_standalone() {
    let h = fresh().await;
    let one = spawn_primary(&h, 1).await;
    let two = spawn_primary(&h, 2).await;
    let standalone = spawn_standalone(&h, 3).await;

    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences(&h, u64::from(SELF_STOP_CADENCES) - 1).await;
    assert_eq!(
        calls_after_spawn(&h, one.id),
        vec![],
        "four cadences is not five"
    );

    cadences_from(&h, SELF_STOP_CADENCES.into(), 1).await;
    assert_eq!(
        calls_after_spawn(&h, one.id),
        vec![BackendCall::Stop(one.id)]
    );
    assert_eq!(
        calls_after_spawn(&h, two.id),
        vec![BackendCall::Stop(two.id)]
    );
    assert_eq!(status_of(&h, &one).await["state"], "stopped");
    assert_eq!(status_of(&h, &two).await["state"], "stopped");

    assert_eq!(calls_after_spawn(&h, standalone.id), vec![]);
    assert_eq!(status_of(&h, &standalone).await["state"], "running");
}

/// The trigger is five cadences CONTINUOUSLY: one publication that reached a
/// majority, anywhere inside them, starts the count again (spec §7.1).
#[tokio::test]
async fn one_majority_inside_the_five_restarts_the_count() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences(&h, 4).await;
    // The fifth cadence reaches everyone.
    liveness_refused_on(&h, &[]);
    cadence(&h, NOW + 5 * CADENCE).await;
    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences_from(&h, 6, 4).await;

    assert_eq!(
        calls_after_spawn(&h, primary.id),
        vec![],
        "nine cadences, but never five in a row"
    );
    assert_eq!(status_of(&h, &primary).await["state"], "running");

    // The fifth in a row after the majority came back is still the fifth.
    cadences_from(&h, 10, 1).await;
    assert_eq!(
        calls_after_spawn(&h, primary.id),
        vec![BackendCall::Stop(primary.id)]
    );
}

/// A provider with no Relay Set publishes to nobody, so nobody watches it and
/// nothing can take its workload over: there is no majority for it to lose.
#[tokio::test]
async fn a_provider_with_no_relay_set_never_stops_anything() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let registry = stub_registry().await;
    let config = config_for(
        vec![warm(), listing("basic", 1, 2)],
        &Keys::generate().secret_key().to_secret_hex(),
        &state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    assert!(config.relay_set.is_empty());
    let h = harness_from(
        config,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
    );
    let primary = spawn_primary(&h, 1).await;

    cadences(&h, u64::from(SELF_STOP_CADENCES) + 2).await;

    assert_eq!(calls_after_spawn(&h, primary.id), vec![]);
    assert_eq!(status_of(&h, &primary).await["state"], "running");
}

// ── what a stopped lease still is ────────────────────────────────────────

/// Stopping a workload ends nothing: `status` says the workload is stopped
/// while the lease is still a lease, `.extend` still buys it another
/// interval, and the sweep still ends it at its `expires_at` — destroying the
/// workload the stop left behind (spec §7.1).
#[tokio::test]
async fn a_stopped_lease_is_still_paid_still_extends_and_still_expires() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences(&h, SELF_STOP_CADENCES.into()).await;

    let status = status_of(&h, &primary).await;
    assert_eq!(status["state"], "stopped");
    assert_eq!(status["role"], "primary");
    assert_eq!(status["expires_at"], NOW + INTERVAL);
    assert!(
        status.get("access").is_none(),
        "a stopped workload is not reachable: {status}"
    );

    let (code, body) = extend(&h, &primary, "warm").await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["expires_at"], NOW + 2 * INTERVAL);
    assert_eq!(status_of(&h, &primary).await["state"], "stopped");

    // Nothing pays the second interval: the sweep ends the lease and the
    // stopped container is destroyed rather than left on the host.
    h.service.sweep_expired_leases(NOW + 2 * INTERVAL).await;
    assert_eq!(
        status_of(&h, &primary).await["state"],
        json!({ "ended": "expiry" })
    );
    assert!(
        h.backend.calls().contains(&BackendCall::Delete(primary.id)),
        "{:?}",
        h.backend.calls()
    );
}

/// A stopped primary's tenant can still rotate its token: every state short
/// of Ended can be rotated (spec §6.8). The lease stays stopped, and the
/// backend is asked for nothing — a rotation touches the token alone.
#[tokio::test]
async fn a_stopped_lease_can_be_rotated() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences(&h, SELF_STOP_CADENCES.into()).await;
    assert_eq!(status_of(&h, &primary).await["state"], "stopped");
    let calls = h.backend.calls();

    let next = mint().continuation_for(&h.provider);
    let spec = RequestSpec::op(
        &h,
        "rotate",
        json!({ "workload_id": primary.workload_id, "next": next }),
    )
    .with_token(&primary.token);
    let (code, body) = post(&h.app, "/rotate", json!({ "request": spec.request() })).await;
    assert_eq!(code, StatusCode::OK, "{body}");

    let rotated = Lease {
        token: next,
        ..primary
    };
    assert_eq!(status_of(&h, &rotated).await["state"], "stopped");
    assert_eq!(h.backend.calls(), calls, "the backend was asked nothing");
}

// ── starting again, and the one reason not to ────────────────────────────

/// The majority comes back and nobody claimed the workload, so the same
/// container runs again — the one the stop left in place, never a new one
/// (spec §7.1).
#[tokio::test]
async fn the_majority_returning_starts_the_workload_again() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences(&h, SELF_STOP_CADENCES.into()).await;
    assert_eq!(status_of(&h, &primary).await["state"], "stopped");

    liveness_refused_on(&h, &[]);
    cadences_from(&h, u64::from(SELF_STOP_CADENCES) + 1, 1).await;

    assert_eq!(
        calls_after_spawn(&h, primary.id),
        vec![
            BackendCall::Stop(primary.id),
            BackendCall::Start(primary.id)
        ]
    );
    let status = status_of(&h, &primary).await;
    assert_eq!(status["state"], "running");
    assert!(status.get("access").is_some(), "{status}");

    // It asked the Relay Set first, for THIS workload id and among the set.
    assert!(
        h.directory
            .reads()
            .iter()
            .any(|r| r.contains("find_takeovers")
                && r.contains(&primary.workload_id)
                && r.contains("2 claimant(s)")),
        "{:?}",
        h.directory.reads()
    );
}

/// A Takeover from a member of the Standby Set means another provider is
/// running this workload now, so the stopped copy stays stopped for the rest
/// of the lease — and the provider stops asking (spec §7.1).
#[tokio::test]
async fn a_takeover_from_a_set_member_keeps_the_workload_stopped() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences(&h, SELF_STOP_CADENCES.into()).await;
    takeover_by_the_standby(&h, &primary, NOW + 3 * CADENCE);

    liveness_refused_on(&h, &[]);
    cadences_from(&h, u64::from(SELF_STOP_CADENCES) + 1, 1).await;

    assert_eq!(
        calls_after_spawn(&h, primary.id),
        vec![BackendCall::Stop(primary.id)],
        "nothing was started"
    );
    assert_eq!(status_of(&h, &primary).await["state"], "stopped");

    // For the REST of the lease: the claim is remembered, so later cadences
    // neither start the workload nor ask the relays about it again.
    let asked = h
        .directory
        .reads()
        .iter()
        .filter(|r| r.contains("find_takeovers"))
        .count();
    cadences_from(&h, u64::from(SELF_STOP_CADENCES) + 2, 3).await;
    assert_eq!(
        calls_after_spawn(&h, primary.id),
        vec![BackendCall::Stop(primary.id)]
    );
    assert_eq!(
        h.directory
            .reads()
            .iter()
            .filter(|r| r.contains("find_takeovers"))
            .count(),
        asked,
        "a lease the set has moved past is not asked about again"
    );
    assert_eq!(status_of(&h, &primary).await["state"], "stopped");
}

/// A Takeover of the same workload id signed by a provider outside the
/// `standby_set` claims nothing: only a member of the set can have been sold
/// this workload (spec §7.1 step 3).
#[tokio::test]
async fn a_takeover_from_outside_the_set_is_not_a_takeover() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences(&h, SELF_STOP_CADENCES.into()).await;
    takeover_by_a_stranger(&h, &primary, NOW + 3 * CADENCE);

    liveness_refused_on(&h, &[]);
    cadences_from(&h, u64::from(SELF_STOP_CADENCES) + 1, 1).await;

    assert_eq!(
        calls_after_spawn(&h, primary.id),
        vec![
            BackendCall::Stop(primary.id),
            BackendCall::Start(primary.id)
        ]
    );
    assert_eq!(status_of(&h, &primary).await["state"], "running");
}

// ── the partition that is a provider being down ──────────────────────────

/// The loudest partition: the provider's PROCESS is stopped while its
/// workload keeps running as a container beside it, a standby takes over, and
/// the process comes back to a lease table that says Running. It asks the
/// Relay Set before it treats that workload as live (spec §7.1).
#[tokio::test]
async fn a_restarted_primary_stops_a_workload_the_set_has_moved_past() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;
    takeover_by_the_standby(&h, &primary, NOW + CADENCE);

    let again = restart(&h).await;
    again.service.restore_leases().await;
    again.service.stand_down_if_taken_over().await;

    assert_eq!(
        calls_after_spawn(&again, primary.id),
        vec![BackendCall::Stop(primary.id)]
    );
    let status = status_of(&again, &primary).await;
    assert_eq!(status["state"], "stopped");
    assert!(status.get("access").is_none(), "{status}");

    // And it stays stopped: the workload is running on another provider, so
    // no number of good cadences here starts a second copy.
    liveness_refused_on(&again, &[]);
    cadences(&again, 2).await;
    assert_eq!(
        calls_after_spawn(&again, primary.id),
        vec![BackendCall::Stop(primary.id)]
    );
}

/// The same restart with nobody having claimed the workload: it was running
/// when the process went down and it is running now. A provider that stopped
/// a healthy workload because a relay was quiet would be the outage it is
/// there to prevent.
#[tokio::test]
async fn a_restarted_primary_nobody_claimed_keeps_running() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    let again = restart(&h).await;
    again.service.restore_leases().await;
    again.service.stand_down_if_taken_over().await;

    assert_eq!(calls_after_spawn(&again, primary.id), vec![]);
    let status = status_of(&again, &primary).await;
    assert_eq!(status["state"], "running");
    assert!(status.get("access").is_some(), "{status}");
    assert!(
        again
            .directory
            .reads()
            .iter()
            .any(|r| r.contains("find_takeovers") && r.contains(&primary.workload_id)),
        "a primary of a Standby Set asks before it carries on: {:?}",
        again.directory.reads()
    );
}

/// A stopped workload survives the provider's restart as stopped: the fact is
/// on disk, so a provider that comes back does not start again what the set
/// may have moved past.
#[tokio::test]
async fn a_stopped_workload_is_still_stopped_after_a_restart() {
    let h = fresh().await;
    let primary = spawn_primary(&h, 1).await;

    liveness_refused_on(&h, &OWN_RELAYS[0..2]);
    cadences(&h, SELF_STOP_CADENCES.into()).await;

    let again = restart(&h).await;
    again.service.restore_leases().await;
    again.service.stand_down_if_taken_over().await;

    assert_eq!(status_of(&again, &primary).await["state"], "stopped");
    assert_eq!(
        calls_after_spawn(&again, primary.id),
        vec![BackendCall::Stop(primary.id)],
        "the restart itself starts nothing"
    );

    // The count is not carried across the restart, and neither is the
    // workload's fate: one good cadence is enough to ask the relays and start
    // it again.
    liveness_refused_on(&again, &[]);
    cadences(&again, 1).await;
    assert_eq!(
        calls_after_spawn(&again, primary.id),
        vec![
            BackendCall::Stop(primary.id),
            BackendCall::Start(primary.id)
        ]
    );
}

/// A standalone lease has no Standby Set, so a restarted provider asks the
/// Relay Set nothing about it: there is nobody who could have claimed it.
#[tokio::test]
async fn a_restarted_provider_asks_nothing_about_a_standalone_lease() {
    let h = fresh().await;
    let standalone = spawn_standalone(&h, 2).await;

    let again = restart(&h).await;
    again.service.restore_leases().await;
    again.service.stand_down_if_taken_over().await;

    assert!(
        !again
            .directory
            .reads()
            .iter()
            .any(|r| r.contains("find_takeovers")),
        "{:?}",
        again.directory.reads()
    );
    assert_eq!(status_of(&again, &standalone).await["state"], "running");
}
