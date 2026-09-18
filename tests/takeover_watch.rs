//! A Warm Standby watches its primary and announces a Takeover (spec §7.1
//! steps 1–2, ADR 0010).
//!
//! Every test here holds a reservation made through the paid `.standby`
//! route, exactly as a tenant's would be, and then drives the watchdog on
//! chosen instants of a fake clock over a fake Directory whose per-relay
//! Liveness the test sets. The assertions are on what the Directory was
//! asked and what it was handed — which relays were watched, and which
//! Takeover was published where — never on the provider's internal state.
//! The primary is another provider entirely: its Profile is seeded, and
//! its Liveness is whatever each relay is told to say.

mod common;

use axum::http::StatusCode;
use nostr_sdk::{EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};

use common::harness::{
    config_for, harness_from, listing, mint, post, spawn_content, Harness, RequestSpec, NOW,
};
use common::{stub_registry, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::continuation::ContinuationToken;
use toon_provider::nostr::directory_events::{ProfileContent, TakeoverContent};
use toon_provider::nostr::kinds::{K_PROFILE, K_TAKEOVER, TOON_LABEL};
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::{persisted_leases, ImagePolicyConfig, Listing, TakeoverAnnouncement};
use toon_provider::LivenessState;
use toon_provider::LivenessState::{Absent, Expired, Live};

/// The primary's `liveness_cadence_s`, as its Profile publishes it.
const CADENCE: u64 = 60;

/// The primary's Relay Set: what its Profile lists, and so what a standby
/// watches.
const PRIMARY_RELAYS: [&str; 3] = [
    "ws://primary-one:7100",
    "ws://primary-two:7100",
    "ws://primary-three:7100",
];

/// The standby's OWN Relay Set, which it must never watch the primary on.
const OWN_RELAYS: [&str; 2] = ["ws://standby-one:7100", "ws://standby-two:7100"];

/// The fixture provider's key (`tests/wire_fixtures.rs`): the standby that
/// signs `directory.takeover.json`.
const FIXTURE_PROVIDER_SECRET: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
/// The fixture primary: index 0 of the set that fixture is about.
const FIXTURE_PRIMARY_SECRET: &str =
    "5555555555555555555555555555555555555555555555555555555555555555";
/// The workload id the fixture's Standby Set shares.
const FIXTURE_WORKLOAD_SEED: u8 = 0xa0;

fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

/// A Warm Standby's provider process, with a Relay Set of its own so a test
/// can tell the primary's relays from this provider's.
async fn standby_harness(provider_key: &str) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let registry = stub_registry().await;
    let mut config = config_for(
        vec![warm()],
        provider_key,
        &state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    config.relay_set = OWN_RELAYS.map(String::from).to_vec();
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

/// The primary's Provider Profile as its relays hold it (spec §4.1): the
/// Relay Set and the cadence a standby reads from it, and any valid rest.
fn profile_of(primary: &Keys, relays: &[&str], cadence_s: u64) -> nostr_sdk::Event {
    let content = ProfileContent {
        ilp_address: "g.primary".to_string(),
        connector_url: "https://c.primary.example/ilp".to_string(),
        connector_seal_key: format!("0x04{}", "ab".repeat(64)),
        relays: relays.iter().map(|r| r.to_string()).collect(),
        settlement: vec![],
        isolation: "shared-kernel".to_string(),
        hidden: false,
        host: Some("198.51.100.9".to_string()),
        liveness_cadence_s: cadence_s,
    };
    EventBuilder::new(
        Kind::Custom(K_PROFILE),
        serde_json::to_string(&content).unwrap(),
    )
    .tags([Tag::parse(["L", TOON_LABEL]).unwrap()])
    .custom_created_at(Timestamp::from(NOW - 1000))
    .sign_with_keys(primary)
    .unwrap()
}

/// One reservation this provider holds, and the primary it watches.
struct Reservation {
    primary: Keys,
    /// The Continuation Token this member was reserved with (spec §6.1).
    token: ContinuationToken,
    workload_id: String,
}

/// Reserve on `h` at index 1 behind `primary`, whose Profile — seeded on the
/// Directory — lists `relays` at `cadence_s`.
async fn reserve_behind(
    h: &Harness,
    seed: u8,
    primary: Keys,
    relays: &[&str],
    cadence_s: u64,
) -> Reservation {
    let set = [primary.public_key(), h.provider];
    let content = SpawnContent {
        standby_set: Some(set.iter().map(|k| k.to_hex()).collect()),
        ..spawn_content(seed)
    };
    let token = mint().continuation_for(&h.provider);
    let spec = RequestSpec::standby(h, &content).with_token(&token);
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby",
        json!({ "request": spec.request() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    h.directory
        .seed_profile(profile_of(&primary, relays, cadence_s));
    Reservation {
        primary,
        token,
        workload_id: content.workload_id,
    }
}

async fn reserve(h: &Harness, seed: u8) -> Reservation {
    reserve_behind(h, seed, Keys::generate(), &PRIMARY_RELAYS, CADENCE).await
}

/// What each of `relays` says about the primary from now on.
fn primary_is(h: &Harness, r: &Reservation, state: LivenessState, relays: &[&str]) {
    h.directory
        .set_liveness_on(r.primary.public_key(), relays, state);
}

/// One watchdog step at `at`.
async fn step(h: &Harness, at: u64) {
    h.clock.set(at);
    h.service.watch_primaries(at).await;
}

/// Every Takeover the Directory was handed, with the relays it went to.
fn takeovers(h: &Harness) -> Vec<(nostr_sdk::Event, Vec<String>)> {
    h.directory.takeover_publications()
}

fn strings(relays: &[&str]) -> Vec<String> {
    relays.iter().map(|r| r.to_string()).collect()
}

/// `status` presenting the reservation's own Continuation Token.
async fn status_of(h: &Harness, r: &Reservation) -> Value {
    let spec = RequestSpec::about(h, "status", &r.workload_id).with_token(&r.token);
    post(&h.app, "/status", json!({ "request": spec.request() }))
        .await
        .1
}

// ── whose relays are watched ─────────────────────────────────────────────

/// The primary publishes Liveness to the relays ITS Profile lists, so that
/// is where a standby must look — never on its own Relay Set, where nothing
/// was ever sent (spec §7.1).
#[tokio::test]
async fn a_standby_watches_the_relays_its_primarys_profile_lists() {
    let h = fresh_standby().await;
    let r = reserve(&h, 1).await;
    primary_is(&h, &r, Live, &PRIMARY_RELAYS);

    step(&h, NOW).await;

    let reads = h.directory.reads();
    assert_eq!(
        reads.first().map(String::as_str),
        Some(format!("get_profile({})", r.primary.public_key().to_hex()).as_str()),
        "the Profile comes first: it says where to look. {reads:?}"
    );
    assert_eq!(
        h.directory.liveness_lookups(),
        vec![(r.primary.public_key(), strings(&PRIMARY_RELAYS))],
        "the primary's Liveness was asked for on exactly its own Relay Set"
    );
    for read in &reads {
        for own in OWN_RELAYS {
            assert!(
                !read.contains(own),
                "the standby's own relay {own} was consulted: {read}"
            );
        }
    }
    assert!(takeovers(&h).is_empty(), "a live primary triggers nothing");
}

// ── the trigger (spec §7.1 step 1) ───────────────────────────────────────

/// One flaky relay never triggers a Takeover, however long it stays flaky:
/// silence must be on a STRICT majority of the primary's Relay Set.
#[tokio::test]
async fn a_minority_of_silent_relays_never_triggers() {
    let h = fresh_standby().await;
    let r = reserve(&h, 2).await;
    primary_is(&h, &r, Live, &PRIMARY_RELAYS);
    primary_is(&h, &r, Absent, &[PRIMARY_RELAYS[0]]);

    for cadences in 0..10 {
        step(&h, NOW + cadences * CADENCE).await;
    }

    assert!(takeovers(&h).is_empty());
    assert_eq!(status_of(&h, &r).await["state"], "reserved");
}

/// Silence on a majority is not enough on its own: it must last one full
/// cadence. Then exactly ONE Takeover goes out, to the primary's Relay Set,
/// shaped as spec §7.1 step 2 says — and never a second one.
#[tokio::test]
async fn majority_silence_for_one_full_cadence_announces_exactly_one_takeover() {
    let h = fresh_standby().await;
    let r = reserve(&h, 3).await;
    // Two of three: one expired, one absent, one still live.
    primary_is(&h, &r, Live, &[PRIMARY_RELAYS[0]]);
    primary_is(&h, &r, Expired, &[PRIMARY_RELAYS[1]]);
    primary_is(&h, &r, Absent, &[PRIMARY_RELAYS[2]]);

    // The silence is first seen now: the count starts.
    step(&h, NOW).await;
    assert!(
        takeovers(&h).is_empty(),
        "silence has not lasted a cadence yet"
    );

    // One second short of a cadence: still nothing.
    step(&h, NOW + CADENCE - 1).await;
    assert!(
        takeovers(&h).is_empty(),
        "less than one cadence is not one cadence"
    );

    // A full cadence of silence: the trigger holds.
    step(&h, NOW + CADENCE).await;
    let published = takeovers(&h);
    assert_eq!(published.len(), 1, "exactly one Takeover: {published:?}");
    let (event, relays) = &published[0];

    assert_eq!(
        *relays,
        strings(&PRIMARY_RELAYS),
        "addressed to the PRIMARY's Relay Set, where the other members watch"
    );
    assert_eq!(event.kind.as_u16(), K_TAKEOVER);
    assert_eq!(
        event.tags.identifier(),
        Some(r.workload_id.as_str()),
        "addressable on d = the workload id"
    );
    assert!(event
        .tags
        .iter()
        .any(|t| t.clone().to_vec() == ["L", TOON_LABEL]));
    assert_eq!(event.pubkey, h.provider, "signed by the STANDBY");
    event.verify().expect("a Takeover signs");
    assert_eq!(event.created_at.as_u64(), NOW + CADENCE);
    let content: TakeoverContent = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content.workload_id, r.workload_id);
    assert_eq!(content.primary, r.primary.public_key().to_hex());

    // Announced is announced: the silence goes on, and nothing more is said
    // — a second claim would only replace the first on the relay anyway.
    // Nothing starts either, until the settle window of two cadences is up
    // (`tests/takeover_settle.rs` takes it from there).
    step(&h, NOW + 2 * CADENCE).await;
    step(&h, NOW + 3 * CADENCE - 1).await;
    assert_eq!(takeovers(&h).len(), 1);
    assert_eq!(
        status_of(&h, &r).await["state"],
        "reserved",
        "announcing starts nothing"
    );
    assert!(h.backend.calls().is_empty());
}

/// The trigger is CONTINUOUS silence: a majority that comes back inside the
/// cadence, even for one reading, starts the count over.
#[tokio::test]
async fn a_live_reading_inside_the_cadence_restarts_the_count() {
    let h = fresh_standby().await;
    let r = reserve(&h, 4).await;
    primary_is(&h, &r, Absent, &PRIMARY_RELAYS);
    step(&h, NOW).await;

    // Half a cadence in, the primary is back on every relay.
    primary_is(&h, &r, Live, &PRIMARY_RELAYS);
    step(&h, NOW + CADENCE / 2).await;

    // …and gone again. The first cadence of silence would have been up at
    // NOW + CADENCE; it is not, because it was interrupted.
    primary_is(&h, &r, Absent, &PRIMARY_RELAYS);
    step(&h, NOW + CADENCE).await;
    assert!(
        takeovers(&h).is_empty(),
        "the count restarted at NOW + CADENCE"
    );
    step(&h, NOW + 2 * CADENCE - 1).await;
    assert!(takeovers(&h).is_empty());

    // One full uninterrupted cadence from the restart.
    step(&h, NOW + 2 * CADENCE).await;
    assert_eq!(takeovers(&h).len(), 1);
    assert_eq!(takeovers(&h)[0].0.created_at.as_u64(), NOW + 2 * CADENCE);
}

/// Strict majority, applied to a Relay Set of one and one of three: one of
/// one is a majority, one of three is not, two of three is.
#[tokio::test]
async fn a_strict_majority_is_one_of_one_and_two_of_three() {
    // One relay: silence there is the whole Relay Set.
    let one = fresh_standby().await;
    let r = reserve_behind(&one, 5, Keys::generate(), &[PRIMARY_RELAYS[0]], CADENCE).await;
    primary_is(&one, &r, Expired, &[PRIMARY_RELAYS[0]]);
    step(&one, NOW).await;
    step(&one, NOW + CADENCE).await;
    let published = takeovers(&one);
    assert_eq!(published.len(), 1, "1 of 1 is a strict majority");
    assert_eq!(published[0].1, strings(&[PRIMARY_RELAYS[0]]));

    // Three relays: one silent is not enough, two are.
    let three = fresh_standby().await;
    let r = reserve(&three, 6).await;
    primary_is(&three, &r, Live, &PRIMARY_RELAYS);
    primary_is(&three, &r, Absent, &[PRIMARY_RELAYS[2]]);
    step(&three, NOW).await;
    step(&three, NOW + CADENCE).await;
    step(&three, NOW + 2 * CADENCE).await;
    assert!(
        takeovers(&three).is_empty(),
        "1 of 3 is not a strict majority"
    );

    primary_is(&three, &r, Expired, &[PRIMARY_RELAYS[1]]);
    step(&three, NOW + 2 * CADENCE).await;
    step(&three, NOW + 3 * CADENCE - 1).await;
    assert!(
        takeovers(&three).is_empty(),
        "…and it still takes a cadence"
    );
    step(&three, NOW + 3 * CADENCE).await;
    assert_eq!(takeovers(&three).len(), 1, "2 of 3 is a strict majority");
}

/// A relay the primary's Profile names is asked whether or not the test
/// gave it an answer: one nobody set is absent, as a relay that never heard
/// of the primary is. So a primary whose Liveness is on NONE of its relays
/// is silent everywhere.
#[tokio::test]
async fn a_relay_with_no_liveness_at_all_is_absent() {
    let h = fresh_standby().await;
    let _r = reserve(&h, 7).await;
    // Nothing set on any relay.
    step(&h, NOW).await;
    step(&h, NOW + CADENCE).await;
    assert_eq!(takeovers(&h).len(), 1);
}

// ── what a step costs a provider with nothing to watch ───────────────────

/// A standalone lease and a primary lease watch nobody. A provider holding
/// only those — or nothing — steps without a single Directory read.
#[tokio::test]
async fn a_provider_with_no_reservation_reads_nothing() {
    let h = fresh_standby().await;
    step(&h, NOW).await;
    assert!(h.directory.reads().is_empty(), "{:?}", h.directory.reads());

    // A standalone lease…
    let standalone = RequestSpec::spawn(&h, &spawn_content(8)).request();
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/spawn",
        json!({ "request": standalone }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // …and a lease this provider is the PRIMARY of.
    let set = [h.provider, Keys::generate().public_key()];
    let content = SpawnContent {
        standby_set: Some(set.iter().map(|k| k.to_hex()).collect()),
        ..spawn_content(9)
    };
    let primary = RequestSpec::spawn(&h, &content).request();
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/spawn",
        json!({ "request": primary }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    step(&h, NOW).await;
    step(&h, NOW + CADENCE).await;
    assert!(
        h.directory.reads().is_empty(),
        "neither role watches anyone: {:?}",
        h.directory.reads()
    );
    assert!(takeovers(&h).is_empty());
}

/// A reservation that ended — expired unpaid, here — is watched no further.
#[tokio::test]
async fn an_ended_reservation_is_not_watched() {
    let h = fresh_standby().await;
    let r = reserve(&h, 10).await;
    primary_is(&h, &r, Absent, &PRIMARY_RELAYS);
    step(&h, NOW).await;
    assert_eq!(h.directory.liveness_lookups().len(), 1);

    h.clock.set(NOW + 3600);
    h.service.sweep_expired_leases(NOW + 3600).await;
    step(&h, NOW + 3600).await;

    assert_eq!(
        h.directory.liveness_lookups().len(),
        1,
        "nothing more was read for a lease that is over"
    );
    assert!(takeovers(&h).is_empty(), "and nothing was claimed for it");
}

// ── remembering the announcement ─────────────────────────────────────────

/// What the lease remembers of its announcement — when, in what cadence,
/// and to which relays — is on disk, so a standby that restarts settles the
/// race it entered rather than announcing again. And once announced, the
/// primary is not watched any further by this ticket's watchdog.
#[tokio::test]
async fn the_announcement_is_persisted_and_survives_a_restart() {
    let h = fresh_standby().await;
    let r = reserve(&h, 11).await;
    primary_is(&h, &r, Absent, &PRIMARY_RELAYS);
    step(&h, NOW).await;
    step(&h, NOW + CADENCE).await;
    assert_eq!(takeovers(&h).len(), 1);

    let expected = TakeoverAnnouncement {
        announced_at: NOW + CADENCE,
        cadence_s: CADENCE,
        relays: strings(&PRIMARY_RELAYS),
    };
    assert_eq!(persisted(&h.state_path).takeover, Some(expected.clone()));

    // A new process over the same table, with a Directory that knows
    // nothing of the first one — and a primary still silent.
    let registry = stub_registry().await;
    let mut config = config_for(
        vec![warm()],
        &h.provider_key,
        &h.state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    config.relay_set = OWN_RELAYS.map(String::from).to_vec();
    let after = harness_from(
        config,
        FakeBackend::new(),
        h.clock.clone(),
        FakeDirectory::new(),
        registry,
    );
    after.service.restore_leases().await;
    after
        .directory
        .seed_profile(profile_of(&r.primary, &PRIMARY_RELAYS, CADENCE));

    // Inside the settle window still: nothing to settle yet, and nothing
    // to watch — the primary's Profile and Liveness are read for a
    // reservation that has NOT announced, and this one has.
    step(&after, NOW + 2 * CADENCE).await;
    step(&after, NOW + 3 * CADENCE - 1).await;
    assert!(
        takeovers(&after).is_empty(),
        "the claim was already made; it is not made again"
    );
    assert!(
        after.directory.reads().is_empty(),
        "an announced reservation is no longer watched here: {:?}",
        after.directory.reads()
    );
    assert_eq!(persisted(&after.state_path).takeover, Some(expected));
    assert_eq!(status_of(&after, &r).await["state"], "reserved");
}

/// A Takeover the publisher could not take is not an announcement: nothing
/// is remembered, the silence still counts, and the next step tries again.
#[tokio::test]
async fn a_takeover_the_publisher_did_not_take_is_tried_again() {
    let h = fresh_standby().await;
    let r = reserve(&h, 12).await;
    primary_is(&h, &r, Absent, &PRIMARY_RELAYS);
    step(&h, NOW).await;

    h.directory.fail_next_publish("publisher down");
    step(&h, NOW + CADENCE).await;
    assert!(takeovers(&h).is_empty());
    assert_eq!(persisted(&h.state_path).takeover, None);

    step(&h, NOW + CADENCE + 10).await;
    assert_eq!(takeovers(&h).len(), 1);
    assert_eq!(
        persisted(&h.state_path).takeover.map(|t| t.announced_at),
        Some(NOW + CADENCE + 10)
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

// ── the wire ─────────────────────────────────────────────────────────────

/// The Takeover the watchdog publishes is, byte for byte, the one
/// `directory.takeover.json` shows tenants: same signer, same `created_at`,
/// same tags, same content, and so the same NIP-01 id. Only `sig` differs,
/// because the provider signs with fresh auxiliary randomness and the
/// fixture with zeros (see `docs/spec/fixtures/README.md`); a verifier
/// cannot tell the two apart.
#[tokio::test]
async fn the_published_takeover_is_byte_identical_to_the_fixture() {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/wire/directory.takeover.json"
        ))
        .unwrap(),
    )
    .unwrap();

    let h = standby_harness(FIXTURE_PROVIDER_SECRET).await;
    // The fixture's clock is stopped at NOW, so the trigger must fire THEN:
    // the silence starts one cadence earlier.
    h.clock.set(NOW - CADENCE);
    let r = reserve_behind(
        &h,
        FIXTURE_WORKLOAD_SEED,
        Keys::parse(FIXTURE_PRIMARY_SECRET).unwrap(),
        &PRIMARY_RELAYS,
        CADENCE,
    )
    .await;
    primary_is(&h, &r, Absent, &PRIMARY_RELAYS);
    step(&h, NOW - CADENCE).await;
    step(&h, NOW).await;

    let published = takeovers(&h);
    assert_eq!(published.len(), 1);
    let event = &published[0].0;
    let expected = &fixture["event"];

    assert_eq!(
        event.id.to_hex(),
        expected["id"],
        "the NIP-01 id is the hash of every other byte"
    );
    assert_eq!(event.pubkey.to_hex(), expected["pubkey"]);
    assert_eq!(event.created_at.as_u64(), expected["created_at"]);
    assert_eq!(u64::from(event.kind.as_u16()), expected["kind"]);
    assert_eq!(event.content, expected["content"]);
    let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.clone().to_vec()).collect();
    assert_eq!(serde_json::to_value(tags).unwrap(), expected["tags"]);
    event.verify().unwrap();
}
