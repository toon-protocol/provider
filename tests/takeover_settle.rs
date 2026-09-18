//! A Takeover settles: the earliest announcement wins, the winner runs the
//! workload at full price, and the loser stays reserved and watches the
//! winner (spec §7.1 steps 3–5, ADR 0010).
//!
//! Two Warm Standbys run in-process here — index 1 and index 2 of one
//! Standby Set, each its own provider over its own fake backend, clock and
//! Directory — reserving from the SAME signed spawn, exactly as a tenant's
//! would. Each is driven through the watchdog on chosen instants; what one
//! announced is seeded into the other's Directory, as the primary's relays
//! would hold it. The assertions are on what each backend was asked to
//! create, start and stop, on what each `status` answers, and on what
//! each Directory was asked — never on the provider's internal state.

mod common;

use axum::http::StatusCode;
use nostr_sdk::{EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};

use common::harness::{
    config_for, error_of, harness_from, listing, mint, post, spawn_content, Harness, RequestSpec,
    INTERVAL, NOW, PUBLIC_IP,
};
use common::{stub_registry, BackendCall, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::continuation::RootSecret;
use toon_provider::nostr::directory_events::{takeover_event, ProfileContent, TakeoverContent};
use toon_provider::nostr::kinds::{K_PROFILE, TOON_LABEL};
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::{persisted_leases, ImagePolicyConfig, Listing, TakeoverSettlement};
use toon_provider::LivenessState::{Absent, Live};

/// The primary's `liveness_cadence_s`, as its Profile publishes it. The
/// settle window is two of these.
const CADENCE: u64 = 60;

/// The primary's Relay Set: where every claim goes, and is read back from.
const PRIMARY_RELAYS: [&str; 2] = ["ws://primary-one:7100", "ws://primary-two:7100"];

/// The Relay Set of index 2, for when it wins and index 1 must watch it
/// THERE rather than on the original primary's relays.
const WINNER_RELAYS: [&str; 2] = ["ws://winner-one:7100", "ws://winner-two:7100"];

const STANDBY: &str = "/listings/warm/v1/standby";
const EXTEND: &str = "/listings/warm/v1/extend";
const STANDBY_EXTEND: &str = "/listings/warm/v1/standby/extend";

fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

/// A Warm Standby's provider process.
async fn standby_harness(provider_key: &str) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let registry = stub_registry().await;
    let config = config_for(
        vec![warm()],
        provider_key,
        &state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    harness_from(
        config,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
    )
}

async fn fresh_standby() -> Harness {
    standby_harness(&Keys::generate().secret_key().to_secret_hex()).await
}

/// A provider's Profile as its relays hold it: the Relay Set and the
/// cadence a standby reads from it.
fn profile_of(provider: &Keys, relays: &[&str]) -> nostr_sdk::Event {
    let content = ProfileContent {
        ilp_address: "g.primary".to_string(),
        connector_url: "https://c.primary.example/ilp".to_string(),
        connector_seal_key: format!("0x04{}", "ab".repeat(64)),
        relays: relays.iter().map(|r| r.to_string()).collect(),
        settlement: vec![],
        isolation: "shared-kernel".to_string(),
        hidden: false,
        host: Some("198.51.100.9".to_string()),
        liveness_cadence_s: CADENCE,
    };
    EventBuilder::new(
        Kind::Custom(K_PROFILE),
        serde_json::to_string(&content).unwrap(),
    )
    .tags([Tag::parse(["L", TOON_LABEL]).unwrap()])
    .custom_created_at(Timestamp::from(NOW - 1000))
    .sign_with_keys(provider)
    .unwrap()
}

/// One Standby Set of three — a primary that is another provider entirely,
/// and the two in-process standbys — under one workload id.
struct Set {
    primary: Keys,
    /// The tenant's root secret for this lease: every member's Continuation
    /// Token derives from it, and each member's is its own (spec §6.1).
    root: RootSecret,
    workload_id: String,
}

/// Reserve on `s1` (index 1) and `s2` (index 2) from one set, each member
/// sent its own request, and seed the primary's Profile on both Directories.
async fn reserve_set(s1: &Harness, s2: &Harness, seed: u8) -> Set {
    let primary = Keys::generate();
    let members = [primary.public_key(), s1.provider, s2.provider];
    let content = SpawnContent {
        standby_set: Some(members.iter().map(|k| k.to_hex()).collect()),
        ..spawn_content(seed)
    };
    let root = mint();
    for h in [s1, s2] {
        let request = RequestSpec::standby(h, &content)
            .with_token(&root.continuation_for(&h.provider))
            .request();
        let (status, body) = post(&h.app, STANDBY, json!({ "request": request })).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        h.directory
            .seed_profile(profile_of(&primary, &PRIMARY_RELAYS));
    }
    Set {
        primary,
        root,
        workload_id: content.workload_id,
    }
}

/// One watchdog step at `at`.
async fn step(h: &Harness, at: u64) {
    h.clock.set(at);
    h.service.watch_primaries(at).await;
}

/// The primary goes silent on every relay of `h`'s Directory, and `h`
/// announces a Takeover at exactly `at` (the silence was first seen a
/// cadence earlier). Answers the Takeover it published.
async fn announce(h: &Harness, set: &Set, at: u64) -> nostr_sdk::Event {
    h.directory
        .set_liveness_on(set.primary.public_key(), &PRIMARY_RELAYS, Absent);
    step(h, at - CADENCE).await;
    step(h, at).await;
    let published = h.directory.takeover_publications();
    assert_eq!(published.len(), 1, "one Takeover: {published:?}");
    assert_eq!(published[0].0.created_at.as_u64(), at);
    published[0].0.clone()
}

/// Everything `from` announced is on the relays `to` reads.
fn cross_seed(from: &Harness, to: &Harness) {
    for (event, _) in from.directory.takeover_publications() {
        to.directory.seed_takeover(event);
    }
}

/// A Takeover from `claimant` on the set's workload against its primary,
/// at `created_at`, as a relay would hold it.
fn claim_by(claimant: &Keys, set: &Set, created_at: u64) -> nostr_sdk::Event {
    takeover_event(
        &set.workload_id,
        &set.primary.public_key(),
        claimant,
        created_at,
    )
    .unwrap()
}

/// The keys a harness's provider signs with, so a test can forge what that
/// provider would have announced.
fn keys_of(h: &Harness) -> Keys {
    Keys::parse(&h.provider_key).unwrap()
}

/// `status` presenting this member's own Continuation Token.
async fn status_of(h: &Harness, set: &Set) -> Value {
    let spec = RequestSpec::about(h, "status", &set.workload_id)
        .with_token(&set.root.continuation_for(&h.provider));
    post(&h.app, "/status", json!({ "request": spec.request() }))
        .await
        .1
}

async fn pay(h: &Harness, route: &str, set: &Set) -> (StatusCode, Value) {
    post(&h.app, route, json!({ "workload_id": set.workload_id })).await
}

fn strings(relays: &[&str]) -> Vec<String> {
    relays.iter().map(|r| r.to_string()).collect()
}

/// What the settle asked the Directory for.
fn settle_read(set: &Set, relays: &[&str]) -> String {
    format!(
        "find_takeovers({}, 3 claimant(s), [{}])",
        set.workload_id,
        strings(relays).join(", ")
    )
}

/// The backend was asked to create and start the one workload, and nothing
/// else. The image is the `reference@digest` form, which the backend pulls
/// itself; the content-address forms go through the same `fetch_and_start`
/// a spawn does, load included (`tests/registry_spawn.rs`).
fn started(h: &Harness) {
    assert_eq!(
        h.backend.calls(),
        vec![BackendCall::Create(1000), BackendCall::Start(1000)],
        "the workload was started from the image"
    );
}

/// The one live lease in a state file, as the next process reads it.
fn persisted(state_path: &str) -> toon_provider::LeaseRecord {
    let mut live: Vec<_> = persisted_leases(state_path)
        .into_iter()
        .filter(|l| l.state.is_live())
        .collect();
    assert_eq!(live.len(), 1, "one live lease on the table");
    live.pop().unwrap()
}

// ── who wins (spec §7.1 step 3) ──────────────────────────────────────────

/// The heart of the ticket: both standbys announce, index 2's claim is the
/// earlier one, and index 2 alone starts the workload. Index 1 reads the
/// same claims off the primary's relays, sees it lost, and starts nothing.
#[tokio::test]
async fn the_earliest_claim_wins_and_the_rest_stay_reserved() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 1).await;

    // Index 2 saw the silence half a minute before index 1 did.
    let second = announce(&s2, &set, NOW + CADENCE - 30).await;
    let first = announce(&s1, &set, NOW + CADENCE).await;
    cross_seed(&s1, &s2);
    cross_seed(&s2, &s1);
    assert!(second.created_at < first.created_at);

    // Index 2 settles two cadences after ITS announcement, and wins.
    step(&s2, NOW + 3 * CADENCE - 30).await;
    started(&s2);
    let body = status_of(&s2, &set).await;
    assert_eq!(body["state"], "running", "{body}");
    assert_eq!(body["role"], "standby", "the role never changes");
    assert_eq!(body["access"]["host"], PUBLIC_IP);
    assert_eq!(body["takeover"]["winner"], s2.provider.to_hex());

    // Index 1 settles two cadences after its own, reads the claims back
    // from the PRIMARY's relays — where they were published — and loses.
    step(&s1, NOW + 3 * CADENCE).await;
    assert!(
        s1.directory
            .reads()
            .contains(&settle_read(&set, &PRIMARY_RELAYS)),
        "{:?}",
        s1.directory.reads()
    );
    assert!(
        s1.backend.calls().is_empty(),
        "the loser starts nothing: {:?}",
        s1.backend.calls()
    );
    let body = status_of(&s1, &set).await;
    assert_eq!(body["state"], "reserved", "{body}");
    assert_eq!(body["role"], "standby");
    assert!(body.get("access").is_none(), "{body}");
    assert_eq!(
        body["takeover"]["winner"],
        s2.provider.to_hex(),
        "a loser says where the workload went"
    );
}

/// The same `created_at` at both: the lower index wins, whichever order
/// the relays answered in.
#[tokio::test]
async fn an_equal_created_at_goes_to_the_lower_index() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 2).await;

    let first = announce(&s1, &set, NOW + CADENCE).await;
    let second = announce(&s2, &set, NOW + CADENCE).await;
    assert_eq!(first.created_at, second.created_at);
    cross_seed(&s1, &s2);
    cross_seed(&s2, &s1);

    step(&s1, NOW + 3 * CADENCE).await;
    step(&s2, NOW + 3 * CADENCE).await;

    started(&s1);
    assert_eq!(status_of(&s1, &set).await["state"], "running");
    assert!(s2.backend.calls().is_empty(), "{:?}", s2.backend.calls());
    let body = status_of(&s2, &set).await;
    assert_eq!(body["state"], "reserved");
    assert_eq!(body["takeover"]["winner"], s1.provider.to_hex());
}

/// A Takeover on the same workload from a pubkey OUTSIDE the set is not a
/// claim, however early it is: the race is among the members.
#[tokio::test]
async fn a_claim_from_outside_the_set_is_ignored() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 3).await;

    let stranger = Keys::generate();
    s1.directory.seed_takeover(claim_by(&stranger, &set, NOW));
    announce(&s1, &set, NOW + CADENCE).await;

    step(&s1, NOW + 3 * CADENCE).await;
    started(&s1);
    assert_eq!(
        status_of(&s1, &set).await["takeover"]["winner"],
        s1.provider.to_hex()
    );
}

/// The settle window is measured from the standby's OWN announcement, and
/// nothing starts inside it — however early every other claim is visible.
#[tokio::test]
async fn nothing_starts_before_the_settle_window_elapses() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 4).await;

    // Index 2's claim is on the relays before index 1 even announces. It
    // is the later claim, so index 1 will win — but not yet.
    let announced_at = NOW + CADENCE;
    s1.directory
        .seed_takeover(claim_by(&keys_of(&s2), &set, announced_at + 5));
    announce(&s1, &set, announced_at).await;

    for at in [
        announced_at + 1,
        announced_at + CADENCE,
        announced_at + 2 * CADENCE - 1,
    ] {
        step(&s1, at).await;
        assert!(
            s1.backend.calls().is_empty(),
            "nothing starts at {at}: {:?}",
            s1.backend.calls()
        );
        assert!(
            !s1.directory
                .reads()
                .iter()
                .any(|r| r.starts_with("find_takeovers")),
            "the claims are not even read before the window is up: {:?}",
            s1.directory.reads()
        );
        assert_eq!(status_of(&s1, &set).await["state"], "reserved");
    }

    step(&s1, announced_at + 2 * CADENCE).await;
    started(&s1);
    assert_eq!(status_of(&s1, &set).await["state"], "running");
}

// ── after winning (spec §7.1 step 4) ─────────────────────────────────────

/// A standby that won is a running lease from then on: `status` reports
/// `running` with the access details a tenant reaches it at, `.extend`
/// buys another interval at full price, and `.standby.extend` is refused
/// `not_standby` — the lease is billed at the price for what it is doing
/// (spec §6.3).
#[tokio::test]
async fn a_winner_is_billed_at_full_price_from_then_on() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 5).await;
    announce(&s1, &set, NOW + CADENCE).await;
    step(&s1, NOW + 3 * CADENCE).await;
    started(&s1);

    let body = status_of(&s1, &set).await;
    assert_eq!(body["state"], "running", "{body}");
    assert_eq!(body["role"], "standby");
    assert_eq!(
        body["access"],
        json!({
            "host": PUBLIC_IP,
            "ssh_port": 40000,
            "ports": [{ "container_port": 443, "host_port": 41000 }],
        }),
        "the access details the reservation held from the start"
    );
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        NOW + INTERVAL,
        "winning buys no time: the reservation's own expiry stands"
    );

    let (status, body) = pay(&s1, STANDBY_EXTEND, &set).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(error_of(&body), "not_standby");

    let (status, body) = pay(&s1, EXTEND, &set).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + 2 * INTERVAL);
    // A second `status` at the same instant would be the same signed
    // request, which the provider refuses as a replay (spec §6.1).
    s1.clock.advance(1);
    let body = status_of(&s1, &set).await;
    assert_eq!(
        body["expires_at"].as_u64().unwrap(),
        NOW + 2 * INTERVAL,
        "{body}"
    );
    started(&s1);
}

/// Without a full-price `.extend`, the sweep at the reservation's ORIGINAL
/// `expires_at` stops the workload and ends the lease with `expiry`, like
/// any running lease nobody paid for.
#[tokio::test]
async fn a_winner_nobody_extends_expires_on_the_sweep() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 6).await;
    announce(&s1, &set, NOW + CADENCE).await;
    step(&s1, NOW + 3 * CADENCE).await;
    started(&s1);

    s1.clock.set(NOW + INTERVAL - 1);
    s1.service.sweep_expired_leases(NOW + INTERVAL - 1).await;
    assert_eq!(status_of(&s1, &set).await["state"], "running");

    s1.clock.set(NOW + INTERVAL);
    s1.service.sweep_expired_leases(NOW + INTERVAL).await;
    assert_eq!(
        s1.backend.calls(),
        vec![
            BackendCall::Create(1000),
            BackendCall::Start(1000),
            BackendCall::Stop(1000),
            BackendCall::Delete(1000),
        ]
    );
    let body = status_of(&s1, &set).await;
    assert_eq!(body["state"], json!({ "ended": "expiry" }), "{body}");
    assert!(body.get("access").is_none(), "{body}");
}

/// A start the backend refuses leaves the lease reserved and the backend
/// clean, and the next step tries again: the tenant paid for readiness.
#[tokio::test]
async fn a_start_that_fails_is_tried_again_on_the_next_step() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 7).await;
    announce(&s1, &set, NOW + CADENCE).await;

    s1.backend.fail_next_create("daemon busy");
    step(&s1, NOW + 3 * CADENCE).await;
    assert_eq!(
        s1.backend.calls(),
        vec![BackendCall::Delete(1000)],
        "the half-made workload was cleaned up"
    );
    let body = status_of(&s1, &set).await;
    assert_eq!(body["state"], "reserved", "nothing runs, so: {body}");
    assert_eq!(
        body["takeover"]["winner"],
        s1.provider.to_hex(),
        "the race is settled all the same"
    );

    step(&s1, NOW + 3 * CADENCE + 10).await;
    assert_eq!(
        s1.backend.calls(),
        vec![
            BackendCall::Delete(1000),
            BackendCall::Create(1000),
            BackendCall::Start(1000),
        ]
    );
    assert_eq!(status_of(&s1, &set).await["state"], "running");
}

/// A standby that announced and then restarted settles from what it kept on
/// disk — and its own claim counts even when the relays it reads back from
/// hand it nothing, because it knows it claimed.
#[tokio::test]
async fn a_standby_that_restarts_after_announcing_settles_from_disk() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 8).await;
    announce(&s1, &set, NOW + CADENCE).await;

    // A new process over the same table, with a Directory that knows
    // nothing of the first one and a backend that runs nothing.
    let registry = stub_registry().await;
    let config = config_for(
        vec![warm()],
        &s1.provider_key,
        &s1.state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    let after = harness_from(
        config,
        FakeBackend::new(),
        s1.clock.clone(),
        FakeDirectory::new(),
        registry,
    );
    after.service.restore_leases().await;

    step(&after, NOW + 3 * CADENCE).await;
    assert_eq!(
        after.directory.reads(),
        vec![settle_read(&set, &PRIMARY_RELAYS)],
        "the claims are read from the relays the announcement went to"
    );
    started(&after);
    assert_eq!(status_of(&after, &set).await["state"], "running");

    let record = persisted(&after.state_path);
    assert_eq!(record.takeover, None, "the round is over");
    assert_eq!(
        record.settled,
        Some(TakeoverSettlement {
            winner: after.provider.to_hex()
        })
    );
    assert_eq!(
        record.reserved_spawn, None,
        "a running lease keeps no spawn"
    );
}

// ── after losing (spec §7.1 step 5) ──────────────────────────────────────

/// A standby that lost stays a reservation — still paid on
/// `.standby.extend`, still refused on `.extend` — and from the next step on
/// watches the WINNER: its Profile is read, and its Liveness on the relays
/// THAT Profile lists. When the winner goes silent too, the loser announces
/// again, naming the winner as the primary, and the winner's old claim —
/// earlier, but about the first race — does not win it a second time.
#[tokio::test]
async fn a_loser_stays_reserved_and_watches_the_winner() {
    let s1 = fresh_standby().await;
    let s2 = fresh_standby().await;
    let set = reserve_set(&s1, &s2, 9).await;
    let winner = keys_of(&s2);

    // Index 2 claimed first; index 1 reads that claim back and loses.
    s1.directory
        .seed_takeover(claim_by(&winner, &set, NOW + CADENCE - 30));
    announce(&s1, &set, NOW + CADENCE).await;
    step(&s1, NOW + 3 * CADENCE).await;
    assert!(s1.backend.calls().is_empty(), "{:?}", s1.backend.calls());
    let body = status_of(&s1, &set).await;
    assert_eq!(body["state"], "reserved", "{body}");
    assert_eq!(body["takeover"]["winner"], s2.provider.to_hex());

    // Still a reservation, billed as one.
    let (status, body) = pay(&s1, EXTEND, &set).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(error_of(&body), "not_running");
    let (status, body) = pay(&s1, STANDBY_EXTEND, &set).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["expires_at"].as_u64().unwrap(), NOW + 2 * INTERVAL);

    // The next step watches the winner, on the winner's OWN Relay Set.
    s1.directory
        .seed_profile(profile_of(&winner, &WINNER_RELAYS));
    s1.directory
        .set_liveness_on(winner.public_key(), &WINNER_RELAYS, Live);
    let before = s1.directory.reads().len();
    step(&s1, NOW + 3 * CADENCE + 10).await;
    let reads = &s1.directory.reads()[before..];
    assert_eq!(
        reads,
        [
            format!("get_profile({})", winner.public_key().to_hex()),
            format!(
                "liveness_state({}, [{}])",
                winner.public_key().to_hex(),
                strings(&WINNER_RELAYS).join(", ")
            ),
        ],
        "the winner is the primary now"
    );
    assert_eq!(
        s1.directory.liveness_lookups().last().unwrap(),
        &(winner.public_key(), strings(&WINNER_RELAYS))
    );
    assert_eq!(s1.directory.takeover_publications().len(), 1);

    // The winner goes silent: a second Takeover, against the WINNER, to the
    // winner's relays.
    let silent_from = NOW + 4 * CADENCE;
    s1.directory
        .set_liveness_on(winner.public_key(), &WINNER_RELAYS, Absent);
    step(&s1, silent_from).await;
    step(&s1, silent_from + CADENCE).await;
    let published = s1.directory.takeover_publications();
    assert_eq!(published.len(), 2, "{published:?}");
    let (second, relays) = &published[1];
    assert_eq!(*relays, strings(&WINNER_RELAYS));
    let content: TakeoverContent = serde_json::from_str(&second.content).unwrap();
    assert_eq!(content.primary, winner.public_key().to_hex());
    assert_eq!(content.workload_id, set.workload_id);

    // Two cadences later the second race settles. The winner's old claim
    // is still on the relays and still the earliest — and names the FIRST
    // primary, so it is about the race that is over. Index 1 wins this one.
    step(&s1, silent_from + 3 * CADENCE).await;
    started(&s1);
    let body = status_of(&s1, &set).await;
    assert_eq!(body["state"], "running", "{body}");
    assert_eq!(body["takeover"]["winner"], s1.provider.to_hex());
}
