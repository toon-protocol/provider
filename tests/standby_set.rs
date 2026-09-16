//! Standby Sets: one signed spawn, two providers, two roles — and what a
//! Warm Standby's reservation is worth once it exists (spec §6.2 step 3,
//! §6.7, §7).
//!
//! The first test runs TWO in-process providers over ONE signed request,
//! because that is the whole of what a Standby Set is: the tenant sends the
//! same bytes to every member, and each learns its role from its own position
//! in the set and from the route the request arrived on. Everything after it
//! is what the reservation then costs this provider — it holds a capacity
//! slot nobody else is sold, it survives a restart, it expires unpaid, and
//! its tenant can give it back — and nearly every assertion ends with the
//! fake backend having been asked for NOTHING, since a standby runs nothing
//! until a Takeover.

mod common;

use axum::http::StatusCode;
use nostr_sdk::{Keys, PublicKey};
use serde_json::{json, Value};

use common::harness::{
    digest, error_of, harness_with, listing, post, restart, spawn_content, workload_id, Harness,
    RequestSpec, INTERVAL, NOW,
};
use common::{stub_registry, BackendCall, FakeBackend, FakeDirectory};
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::{ImagePolicyConfig, LeaseRecord, Listing};
use toon_provider::Clock;

/// A tier that prices Warm Standbys, so nothing here is refused merely
/// because the listing sells none. Capacity 2: room for a reservation and
/// one more, so what a reservation holds can be seen to be exactly one slot.
fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

async fn warm_harness() -> Harness {
    harness_with(vec![warm()]).await
}

const SPAWN: &str = "/listings/warm/v1/spawn";
const STANDBY: &str = "/listings/warm/v1/standby";

/// One spawn as a tenant signs it for a whole Standby Set: one
/// `workload_id`, the members primary-first in `standby_set`, and one `p` tag
/// per member so the same signed bytes are addressed to all of them (spec
/// §6.1, §7). The tenant key comes back, because it is the only key that may
/// then ask any member for `status`.
struct SetSpawn {
    tenant: Keys,
    content: SpawnContent,
    event: Value,
}

fn set_spawn(h: &Harness, seed: u8, set: &[PublicKey]) -> SetSpawn {
    let content = SpawnContent {
        standby_set: Some(set.iter().map(|k| k.to_hex()).collect()),
        ..spawn_content(seed)
    };
    let spec = RequestSpec::spawn(h, &content).addressed_to(set);
    SetSpawn {
        tenant: Keys::parse(&spec.tenant.secret_key().to_secret_hex()).unwrap(),
        content,
        event: spec.sign(),
    }
}

/// A Warm Standby's own spawn: this provider at index 1 behind some other
/// provider, which is the only shape `.standby` accepts.
fn standby_spawn(h: &Harness, seed: u8) -> SetSpawn {
    set_spawn(h, seed, &[Keys::generate().public_key(), h.provider])
}

async fn post_spawn(h: &Harness, path: &str, event: &Value) -> (StatusCode, Value) {
    post(&h.app, path, json!({ "request": event.clone() })).await
}

/// A reservation this provider holds, made through the paid route.
async fn reserve(h: &Harness, seed: u8) -> SetSpawn {
    let spawn = standby_spawn(h, seed);
    let (status, body) = post_spawn(h, STANDBY, &spawn.event).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    spawn
}

/// `status` signed by the lease's own tenant.
async fn status_of(h: &Harness, spawn: &SetSpawn) -> Value {
    let spec = RequestSpec {
        tenant: Keys::parse(&spawn.tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(h, "status", &spawn.content.workload_id)
    };
    post(&h.app, "/status", json!({ "request": spec.sign() }))
        .await
        .1
}

// ── the set forms ────────────────────────────────────────────────────────

/// The heart of the ticket: ONE signed spawn, posted to the two providers it
/// names, makes a running primary at index 0 and a Warm Standby at index 1.
/// Nothing in the request says which; the position and the route do.
#[tokio::test]
async fn one_signed_spawn_makes_a_primary_and_a_standby() {
    let primary = warm_harness().await;
    let standby = warm_harness().await;
    let spawn = set_spawn(&primary, 1, &[primary.provider, standby.provider]);

    // Index 0, on `.spawn`: a lease that runs, exactly as a standalone one
    // does today.
    let (status, body) = post_spawn(&primary, SPAWN, &spawn.event).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["role"], "primary");
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + INTERVAL);
    assert_eq!(body["access"]["ssh_port"].as_u64().unwrap(), 40000);
    assert!(matches!(
        primary.backend.calls().as_slice(),
        [BackendCall::Create(_), BackendCall::Start(_)]
    ));

    // The SAME bytes, at index 1's provider, on `.standby`: capacity held, an
    // expiry set, and nothing started. The absence of `access` is the
    // tenant's proof that nothing runs there.
    let (status, body) = post_spawn(&standby, STANDBY, &spawn.event).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["role"], "standby");
    assert_eq!(body["workload_id"], spawn.content.workload_id);
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + INTERVAL);
    assert!(
        body.get("access").is_none(),
        "a standby has nothing to reach: {}",
        body
    );
    assert!(
        standby.backend.calls().is_empty(),
        "the standby's backend was asked to load, create or start nothing: {:?}",
        standby.backend.calls()
    );
}

/// `status` on each member says which role it holds and what it is doing, so
/// a tenant knows where its workload runs (spec §6.5).
#[tokio::test]
async fn status_reports_each_members_role() {
    let primary = warm_harness().await;
    let standby = warm_harness().await;
    let spawn = set_spawn(&primary, 2, &[primary.provider, standby.provider]);
    assert_eq!(
        post_spawn(&primary, SPAWN, &spawn.event).await.0,
        StatusCode::OK
    );
    assert_eq!(
        post_spawn(&standby, STANDBY, &spawn.event).await.0,
        StatusCode::OK
    );

    let body = status_of(&primary, &spawn).await;
    assert_eq!(body["role"], "primary", "{}", body);
    assert_eq!(body["state"], "running");
    assert!(
        body.get("access").is_some(),
        "the primary runs it: {}",
        body
    );

    let body = status_of(&standby, &spawn).await;
    assert_eq!(body["role"], "standby", "{}", body);
    assert_eq!(body["state"], "reserved");
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + INTERVAL);
    assert!(
        body.get("access").is_none(),
        "a reservation runs nothing to reach: {}",
        body
    );
}

// ── every way a spawn can be mis-addressed (spec §6.2 step 3) ────────────

/// Each of these does NOTHING: no lease, no capacity held, and the backend
/// never hears of it. The refusal is billed all the same (ADR 0003), so each
/// says which rule was broken.
#[tokio::test]
async fn a_mis_addressed_spawn_does_nothing() {
    let h = warm_harness().await;
    let peer = Keys::generate().public_key();
    let stranger = Keys::generate().public_key();

    let refused = |body: &Value, fragment: &str| {
        assert_eq!(error_of(body), "invalid_request", "{}", body);
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(fragment),
            "expected {:?} in {:?}",
            fragment,
            message
        );
    };

    // No `standby_set` at all: `.standby` sells a role this spawn never asked
    // for.
    let plain = RequestSpec::spawn(&h, &spawn_content(10)).sign();
    let (status, body) = post_spawn(&h, STANDBY, &plain).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    refused(&body, "standalone");

    // A set that does not name this provider, though the request was sent
    // here: the spawn belongs to the members it does name, on either route.
    for path in [SPAWN, STANDBY] {
        let content = SpawnContent {
            standby_set: Some(vec![peer.to_hex(), stranger.to_hex()]),
            ..spawn_content(11)
        };
        let elsewhere = RequestSpec::spawn(&h, &content).sign();
        let (status, body) = post_spawn(&h, path, &elsewhere).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
        refused(&body, "not in the standby_set");
    }

    // A `p` tag naming a provider the set does not: the tenant addressed the
    // spawn beyond its own Standby Set, and a member cannot tell what the
    // stranger was meant to do with it.
    let content = SpawnContent {
        standby_set: Some(vec![h.provider.to_hex(), peer.to_hex()]),
        ..spawn_content(16)
    };
    let addressed_beyond = RequestSpec::spawn(&h, &content)
        .addressed_to(&[h.provider, peer, stranger])
        .sign();
    let (status, body) = post_spawn(&h, SPAWN, &addressed_beyond).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    refused(&body, "the standby_set does not name");

    // A member listed twice would hold two positions in one set, and so two
    // roles.
    let twice = SpawnContent {
        standby_set: Some(vec![peer.to_hex(), h.provider.to_hex(), peer.to_hex()]),
        ..spawn_content(17)
    };
    let twice = RequestSpec::spawn(&h, &twice)
        .addressed_to(&[peer, h.provider])
        .sign();
    let (status, body) = post_spawn(&h, STANDBY, &twice).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    refused(&body, "listed twice");

    // Index 0 is the primary and runs the workload, so it is not bought on
    // `.standby` whatever was paid there.
    let as_primary = set_spawn(&h, 12, &[h.provider, peer]);
    let (status, body) = post_spawn(&h, STANDBY, &as_primary.event).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    refused(&body, "index 0");

    // …and any other index is a Warm Standby, so a tenant that paid the
    // running price on `.spawn` still gets no running workload.
    let as_standby = set_spawn(&h, 13, &[peer, h.provider]);
    let (status, body) = post_spawn(&h, SPAWN, &as_standby.event).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    refused(&body, "index 1");

    assert!(
        h.backend.calls().is_empty(),
        "no mis-addressed spawn touches the backend: {:?}",
        h.backend.calls()
    );
    assert_eq!(
        available(&h).await,
        2,
        "and none of them held a slot: the listing is as empty as it started"
    );
}

/// A listing that prices no Warm Standby sells none, so it has no `.standby`
/// route to pay (spec §4.2, §5). `wrong_listing_version` is what a tenant
/// that paid one anyway is told: the same code as any other route this
/// provider does not sell, and the listing itself still sells running leases.
#[tokio::test]
async fn a_standby_spawn_on_a_listing_that_prices_none_is_refused() {
    let h = harness_with(vec![listing("basic", 1, 2)]).await;
    let peer = Keys::generate().public_key();

    let as_standby = set_spawn(&h, 14, &[peer, h.provider]);
    let (status, body) = post_spawn(&h, "/listings/basic/v1/standby", &as_standby.event).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "wrong_listing_version");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("prices no Warm Standby"));
    assert!(h.backend.calls().is_empty());

    let as_primary = set_spawn(&h, 15, &[h.provider, peer]);
    let (status, body) = post_spawn(&h, "/listings/basic/v1/spawn", &as_primary.event).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["role"], "primary",
        "a set's primary needs no standby price"
    );
}

// ── a reservation is a live lease ────────────────────────────────────────

/// It holds a capacity slot: the Liveness `available` count subtracts it and
/// `availability` refuses once reservations fill the listing. That is the
/// whole of what the tenant bought — nobody else is sold the capacity.
#[tokio::test]
async fn a_reservation_counts_against_capacity() {
    let h = warm_harness().await; // capacity 2
    assert_eq!(available(&h).await, 2);

    reserve(&h, 20).await;
    assert_eq!(available(&h).await, 1, "the reservation is held capacity");
    assert_eq!(would_run(&h, "warm", None).await, json!(true));

    reserve(&h, 21).await;
    assert_eq!(available(&h).await, 0);

    // Both roles are refused now: reservations fill a listing exactly as
    // running leases do.
    for role in [None, Some("standby")] {
        let answer = availability(&h, "warm", role).await;
        assert_eq!(answer["would_run"], false, "{}", answer);
        assert_eq!(answer["error"], "no_capacity", "{}", answer);
    }
    let third = standby_spawn(&h, 22);
    let (status, body) = post_spawn(&h, STANDBY, &third.event).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "no_capacity");

    assert!(h.backend.calls().is_empty(), "nothing ran at any point");
}

/// `availability` with `role: standby` answers whether a standby WOULD be
/// reserved, and reserves nothing (spec §6.4): the listing must price
/// standbys and have room.
#[tokio::test]
async fn availability_answers_the_standby_question_without_reserving() {
    let h = harness_with(vec![warm(), listing("basic", 1, 2)]).await;

    assert_eq!(would_run(&h, "warm", Some("standby")).await, json!(true));
    assert_eq!(available(&h).await, 2, "asking reserved nothing");

    // The tier that prices no standby has no standby to ask about — the same
    // refusal a paid `.standby` there would have bought.
    let answer = availability(&h, "basic", Some("standby")).await;
    assert_eq!(answer["would_run"], false, "{}", answer);
    assert_eq!(answer["error"], "wrong_listing_version", "{}", answer);
    // …though a primary would run there.
    assert_eq!(would_run(&h, "basic", Some("primary")).await, json!(true));

    assert!(h.backend.calls().is_empty());
}

/// A reservation must survive the provider's own restart (spec §6.7). The
/// backend has never heard of it, so a restart that asked the backend what
/// exists would drop every standby the tenant is paying for.
#[tokio::test]
async fn a_reservation_survives_a_restart() {
    let h = warm_harness().await;
    let spawn = reserve(&h, 30).await;

    // A new process over the same state file, with a backend that knows
    // nothing — which is exactly what a real one would say about a
    // reservation.
    let after = restart(
        vec![warm()],
        h.provider_key.clone(),
        h.state_path.clone(),
        FakeBackend::new(),
        h.clock.clone(),
        FakeDirectory::new(),
        stub_registry().await,
        ImagePolicyConfig::default(),
    )
    .await;
    after.service.restore_leases().await;

    let body = status_of(&after, &spawn).await;
    assert_eq!(body["state"], "reserved", "{}", body);
    assert_eq!(body["role"], "standby");
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + INTERVAL);
    assert_eq!(available(&after).await, 1, "and it still holds its slot");
    assert!(after.backend.calls().is_empty());

    // What the wire cannot show, read off the table the restart loaded: a
    // reservation that forgot whose Liveness it watches, or what it would
    // start on a Takeover, would be capacity held for nothing.
    let restored = persisted(&after.state_path);
    let set = restored.standby_set.as_ref().expect("the set it serves in");
    assert_eq!(set.index, 1);
    assert_eq!(
        set.primary(),
        Some(spawn.content.standby_set.as_ref().unwrap()[0].as_str())
    );
    assert_eq!(
        restored.reserved_spawn.as_ref(),
        Some(&spawn.content),
        "and the spawn a Takeover would start, as the tenant signed it"
    );
}

/// The one live lease in a state file, as the next process reads it.
fn persisted(state_path: &str) -> LeaseRecord {
    let mut live: Vec<LeaseRecord> = toon_provider::provider::persisted_leases(state_path)
        .into_iter()
        .filter(|l| l.state.is_live())
        .collect();
    assert_eq!(live.len(), 1, "one live lease on the table");
    live.pop().unwrap()
}

/// Unpaid, a reservation ends on the sweep like any other lease — and asks
/// the backend for nothing, because there is nothing to destroy.
#[tokio::test]
async fn an_unpaid_reservation_expires_on_the_sweep() {
    let h = warm_harness().await;
    let spawn = reserve(&h, 31).await;

    // One second before it is due, nothing happens.
    h.clock.set(NOW + INTERVAL - 1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(status_of(&h, &spawn).await["state"], "reserved");

    // `expires_at` is the first instant the lease no longer applies.
    h.clock.set(NOW + INTERVAL);
    h.service.sweep_expired_leases(h.clock.now()).await;
    let body = status_of(&h, &spawn).await;
    assert_eq!(body["state"], json!({ "ended": "expiry" }), "{}", body);
    assert_eq!(available(&h).await, 2, "the capacity is back");
    assert!(
        h.backend.calls().is_empty(),
        "there was never a workload to destroy: {:?}",
        h.backend.calls()
    );
}

/// The tenant may give the capacity back early (spec §6.6): a termination
/// releases a reservation the way it destroys a workload, minus the workload.
#[tokio::test]
async fn a_tenant_terminates_a_reservation() {
    let h = warm_harness().await;
    let spawn = reserve(&h, 32).await;

    let terminate = RequestSpec {
        tenant: Keys::parse(&spawn.tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(&h, "terminate", &spawn.content.workload_id)
    };
    let (status, body) = post(&h.app, "/terminate", json!({ "request": terminate.sign() })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "termination" }));

    let body = status_of(&h, &spawn).await;
    assert_eq!(body["state"], json!({ "ended": "termination" }), "{}", body);
    assert_eq!(available(&h).await, 2, "the capacity is back");
    assert!(h.backend.calls().is_empty());
}

// ── paying a reservation (TOON_Network #30) ───────────────────────────────

const STANDBY_EXTEND: &str = "/listings/warm/v1/standby/extend";
const EXTEND: &str = "/listings/warm/v1/extend";

async fn standby_extend_workload(h: &Harness, id: &str) -> (StatusCode, Value) {
    post(&h.app, STANDBY_EXTEND, json!({ "workload_id": id })).await
}

/// The heart of the ticket: `.standby.extend` adds ONE `lease_interval_s` to
/// a reservation's `expires_at`, exactly as `.extend` does for a running
/// lease (spec §6.3) — a second call adds another — and never touches the
/// backend, because nothing is running to reach either way.
#[tokio::test]
async fn standby_extend_pays_a_reservation_by_one_interval_each_call() {
    let h = warm_harness().await;
    let spawn = reserve(&h, 40).await;
    let id = spawn.content.workload_id.clone();

    let (status, body) = standby_extend_workload(&h, &id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], spawn.content.workload_id);
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + 2 * INTERVAL);

    let (status, body) = standby_extend_workload(&h, &id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + 3 * INTERVAL);

    let status_body = status_of(&h, &spawn).await;
    assert_eq!(status_body["state"], "reserved");
    assert_eq!(
        status_body["expires_at"].as_u64().unwrap(),
        NOW + 3 * INTERVAL
    );
    assert!(
        h.backend.calls().is_empty(),
        "paying a reservation touches no backend: {:?}",
        h.backend.calls()
    );
}

/// `.standby.extend` on a running lease of ANY role — standalone or a Standby
/// Set's primary — is `not_standby`: that lease is billed at its own price
/// on `.extend`, not here.
#[tokio::test]
async fn standby_extend_refuses_a_running_lease_of_any_role() {
    let h = warm_harness().await;

    let standalone = spawn_content(41);
    let (status, body) = post_spawn(&h, SPAWN, &RequestSpec::spawn(&h, &standalone).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["role"], "standalone");

    let (status, body) = standby_extend_workload(&h, &standalone.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "not_standby");

    let peer = Keys::generate().public_key();
    let primary = set_spawn(&h, 42, &[h.provider, peer]);
    let (status, body) = post_spawn(&h, SPAWN, &primary.event).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["role"], "primary");

    let (status, body) = standby_extend_workload(&h, &primary.content.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "not_standby");

    // Neither running lease was touched: `.extend` still buys them their
    // running-price interval.
    let (status, body) = post(
        &h.app,
        EXTEND,
        json!({ "workload_id": standalone.workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + 2 * INTERVAL);
    assert!(matches!(
        h.backend.calls().as_slice(),
        [
            BackendCall::Create(_),
            BackendCall::Start(_),
            BackendCall::Create(_),
            BackendCall::Start(_)
        ]
    ));
}

/// `.extend` met a reservation is the mirror refusal: `not_running`, the code
/// this ticket picked because none of §6.3's other three named codes fit — a
/// reservation is not unknown, not on the wrong version and not ended.
#[tokio::test]
async fn extend_refuses_a_reservation_with_not_running() {
    let h = warm_harness().await;
    let spawn = reserve(&h, 43).await;

    let (status, body) = post(
        &h.app,
        EXTEND,
        json!({ "workload_id": spawn.content.workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "not_running");

    // The reservation is exactly where it was: nothing was bought.
    let body = status_of(&h, &spawn).await;
    assert_eq!(body["state"], "reserved");
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + INTERVAL);
}

/// A reservation on another listing version cannot be extended there, on
/// either route — same rule as a running lease (ADR 0009): a lease keeps the
/// price it started at. v1 is retired (ADR 0009: its route stays only to
/// extend leases already on it) and v2 is the version on sale, so the
/// reservation is bought on v2 and v1's `.standby.extend` is the wrong one.
#[tokio::test]
async fn standby_extend_refuses_a_reservation_through_the_wrong_listing_version() {
    let h = harness_with(vec![
        warm(),
        Listing {
            version: 2,
            ..warm()
        },
    ])
    .await;
    let spawn = standby_spawn(&h, 44);
    let (status, body) = post_spawn(&h, "/listings/warm/v2/standby", &spawn.event).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby/extend",
        json!({ "workload_id": spawn.content.workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "wrong_listing_version");

    // The right version still pays it.
    let (status, body) = post(
        &h.app,
        "/listings/warm/v2/standby/extend",
        json!({ "workload_id": spawn.content.workload_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + 2 * INTERVAL);
}

/// An ended reservation — here, terminated — cannot be paid on either
/// extension route: `expired` covers every ending (spec §6.3), same as a
/// running lease.
#[tokio::test]
async fn standby_extend_refuses_an_ended_reservation() {
    let h = warm_harness().await;
    let spawn = reserve(&h, 45).await;

    let terminate = RequestSpec {
        tenant: Keys::parse(&spawn.tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(&h, "terminate", &spawn.content.workload_id)
    };
    let (status, body) = post(&h.app, "/terminate", json!({ "request": terminate.sign() })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let (status, body) = standby_extend_workload(&h, &spawn.content.workload_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "expired");
}

/// A `workload_id` this provider holds no lease for at all.
#[tokio::test]
async fn standby_extend_refuses_an_unknown_workload() {
    let h = warm_harness().await;
    let (status, body) = standby_extend_workload(&h, &workload_id(0xff)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

/// A reservation extended past a sweep instant survives that sweep; one not
/// extended is ended by it (spec §6.7) — the other half of
/// `an_unpaid_reservation_expires_on_the_sweep` above.
#[tokio::test]
async fn a_reservation_extended_past_a_sweep_instant_survives_it() {
    let h = warm_harness().await;
    let spawn = reserve(&h, 46).await;

    // Pay one more interval before the first would have ended it.
    let (status, body) = standby_extend_workload(&h, &spawn.content.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + 2 * INTERVAL);

    // The sweep at the ORIGINAL expiry instant does nothing: the reservation
    // is paid past it now.
    h.clock.set(NOW + INTERVAL);
    h.service.sweep_expired_leases(h.clock.now()).await;
    let body = status_of(&h, &spawn).await;
    assert_eq!(body["state"], "reserved", "{}", body);
    assert_eq!(available(&h).await, 1, "still held");

    // The sweep at the NEW expiry instant ends it, exactly like an unpaid
    // one.
    h.clock.set(NOW + 2 * INTERVAL);
    h.service.sweep_expired_leases(h.clock.now()).await;
    let body = status_of(&h, &spawn).await;
    assert_eq!(body["state"], json!({ "ended": "expiry" }), "{}", body);
    assert_eq!(available(&h).await, 2, "the capacity is back");
    assert!(h.backend.calls().is_empty());
}

// ── helpers ──────────────────────────────────────────────────────────────

/// What the next Liveness event would announce as `available` for `warm`:
/// `publish`'s own counter, which is the one `spawn` and `availability`
/// refuse on.
async fn available(h: &Harness) -> u32 {
    h.service.app_state().available().await["warm"]
}

async fn availability(h: &Harness, listing: &str, role: Option<&str>) -> Value {
    let mut body = json!({
        "listing": listing,
        "version": 1,
        "image": { "reference": "docker.io/library/alpine", "digest": digest() },
    });
    if let Some(role) = role {
        body["role"] = json!(role);
    }
    post(&h.app, "/availability", body).await.1
}

async fn would_run(h: &Harness, listing: &str, role: Option<&str>) -> Value {
    availability(h, listing, role).await["would_run"].clone()
}
