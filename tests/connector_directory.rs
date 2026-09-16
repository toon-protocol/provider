//! The relay-backed `Directory` against a stub relay: every read a Warm
//! Standby makes about its primary, and the one write it makes, as they
//! reach a real websocket and a real directory publisher.
//!
//! `tests/directory.rs` covers what the provider PUBLISHES, through the fake
//! Directory. This file covers the other implementation of the port —
//! `ConnectorDirectory`, and the reading half of `NullDirectory` — with a
//! `common::relay::StubRelay` per relay, so a test can see which relay was
//! asked what, and a `wiremock` stub of the publisher (`tools/publisher`)
//! for the paid write. Nothing here needs a network beyond loopback.

mod common;

use std::collections::BTreeMap;

use nostr_sdk::{EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::relay::StubRelay;
use toon_provider::nostr::directory_events::{liveness_event, takeover_event, ProfileContent};
use toon_provider::nostr::kinds::{K_LIVENESS, K_PROFILE, K_TAKEOVER, TOON_LABEL};
use toon_provider::LivenessState::{Absent, Expired, Live};
use toon_provider::{ConnectorDirectory, Directory, NullDirectory};

/// The fixed instant for events that carry no `expiration`: a Profile, a
/// Takeover.
const NOW: u64 = 1_700_000_000;
const CADENCE: u64 = 60;

/// The instant for a Liveness, which does carry one: the WALL clock, because
/// nostr-sdk's relay pool drops an event whose `expiration` has passed by
/// the wall clock before the Directory ever sees it (NIP-40, client side).
/// So a Liveness a test wants a relay to still serve must expire in the
/// real future, and "expired" is shown by asking about an instant AHEAD
/// of the wall clock.
fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
/// A relay URL nothing listens on: the connection is refused at once.
const UNREACHABLE: &str = "ws://127.0.0.1:1";
/// A publisher URL no test reaches: the reads here never need one.
const NO_PUBLISHER: &str = "http://publisher.invalid/publish";

/// A Provider Profile from `provider` listing `relays`, created at `at`.
fn profile(provider: &Keys, relays: &[&str], at: u64) -> nostr_sdk::Event {
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
    .custom_created_at(Timestamp::from(at))
    .sign_with_keys(provider)
    .unwrap()
}

/// A Liveness from `provider` published at `at`: it expires five cadences
/// later (ADR 0007).
fn liveness(provider: &Keys, at: u64) -> nostr_sdk::Event {
    liveness_event(BTreeMap::new(), CADENCE, provider, at).unwrap()
}

fn takeover(workload_id: &str, primary: &PublicKey, standby: &Keys, at: u64) -> nostr_sdk::Event {
    takeover_event(workload_id, primary, standby, at).unwrap()
}

fn strings(relays: &[&str]) -> Vec<String> {
    relays.iter().map(|r| r.to_string()).collect()
}

/// The filter a relay was last asked, as the wire shows it.
fn last_request(relay: &StubRelay) -> Value {
    let requests = relay.requests();
    serde_json::to_value(requests.last().expect("the relay was asked something")).unwrap()
}

fn directory_over(relays: &[&StubRelay]) -> ConnectorDirectory {
    ConnectorDirectory::new(NO_PUBLISHER, relays.iter().map(|r| r.url()).collect()).unwrap()
}

// ── get_profile ──────────────────────────────────────────────────────────

/// The newest Profile across the provider's own Relay Set, from the pubkey
/// asked for and nobody else — on both Directories that read.
#[tokio::test]
async fn get_profile_reads_the_newest_profile_on_the_relay_set() {
    let one = StubRelay::start().await;
    let two = StubRelay::start().await;
    let primary = Keys::generate();
    let stranger = Keys::generate();
    one.hold(profile(&primary, &["ws://old:7100"], NOW - 100));
    two.hold(profile(&primary, &["ws://new:7100"], NOW));
    two.hold(profile(&stranger, &["ws://theirs:7100"], NOW + 50));

    for directory in [
        Box::new(directory_over(&[&one, &two])) as Box<dyn Directory>,
        Box::new(NullDirectory::new(vec![one.url(), two.url()])),
    ] {
        let found = directory
            .get_profile(primary.public_key())
            .await
            .unwrap()
            .expect("the Relay Set holds it");
        assert_eq!(found.pubkey, primary.public_key());
        assert_eq!(found.created_at.as_u64(), NOW, "newest wins");
        let content: ProfileContent = serde_json::from_str(&found.content).unwrap();
        assert_eq!(content.relays, vec!["ws://new:7100"]);

        assert!(directory
            .get_profile(Keys::generate().public_key())
            .await
            .unwrap()
            .is_none());
    }

    // Both relays were asked for exactly this: kind K_PROFILE by the
    // primary, newest one.
    for relay in [&one, &two] {
        let asked = last_request(relay);
        assert_eq!(asked["kinds"], json!([K_PROFILE]));
        assert!(
            asked["authors"] != json!([primary.public_key().to_hex()]),
            "the last question was about the stranger"
        );
    }
    let asked = &one.requests()[0];
    assert_eq!(
        asked
            .authors
            .as_ref()
            .map(|a| a.contains(&primary.public_key())),
        Some(true)
    );
    assert_eq!(asked.limit, Some(1));
}

/// A Relay Set with a relay nobody can reach still answers from the rest.
#[tokio::test]
async fn get_profile_survives_a_dead_relay_in_the_set() {
    let alive = StubRelay::start().await;
    let primary = Keys::generate();
    alive.hold(profile(&primary, &["ws://p:7100"], NOW));
    let directory =
        ConnectorDirectory::new(NO_PUBLISHER, vec![UNREACHABLE.to_string(), alive.url()]).unwrap();

    let found = directory.get_profile(primary.public_key()).await.unwrap();
    assert_eq!(found.map(|e| e.pubkey), Some(primary.public_key()));
}

/// No relays, no Profile, no error: the honest answer of a provider with
/// nothing configured (spec §7.1 needs a Relay Set to read; none is none).
#[tokio::test]
async fn get_profile_on_no_relay_set_finds_nothing() {
    let directory = ConnectorDirectory::new(NO_PUBLISHER, vec![]).unwrap();
    assert!(directory
        .get_profile(Keys::generate().public_key())
        .await
        .unwrap()
        .is_none());
}

// ── liveness_state ───────────────────────────────────────────────────────

/// Each relay of the PRIMARY's Relay Set is asked on its own and answers
/// for itself: live where an unexpired Liveness is, expired where only an
/// old one is, absent where none is or the relay cannot be reached. The
/// Directory's own Relay Set is not consulted at all.
#[tokio::test]
async fn liveness_state_answers_relay_by_relay_on_the_relays_given() {
    let home = StubRelay::start().await; // the standby's own relay
    let live = StubRelay::start().await;
    let expired = StubRelay::start().await;
    let empty = StubRelay::start().await;
    let primary = Keys::generate();
    let stranger = Keys::generate();
    // Asked about one cadence from now. What `live` holds expires four
    // cadences after that; what `expired` holds expires exactly then — and
    // both are still in the wall clock's future, so the relay pool serves
    // them.
    let now = wall_now();
    let asked_at = now + CADENCE;
    home.hold(liveness(&primary, now)); // the wrong place to look
    live.hold(liveness(&primary, now)); // expires at now + 5 × CADENCE
    expired.hold(liveness(&primary, now - 4 * CADENCE)); // expires AT asked_at
    expired.hold(liveness(&primary, now - 4 * CADENCE - 10)); // and an older one
    empty.hold(liveness(&stranger, now)); // somebody else's

    let relays = vec![
        live.url(),
        expired.url(),
        empty.url(),
        UNREACHABLE.to_string(),
    ];
    for directory in [
        Box::new(directory_over(&[&home])) as Box<dyn Directory>,
        Box::new(NullDirectory::new(vec![home.url()])),
    ] {
        let states = directory
            .liveness_state(primary.public_key(), &relays, asked_at)
            .await
            .unwrap();
        assert_eq!(
            states,
            BTreeMap::from([
                (live.url(), Live),
                (expired.url(), Expired),
                (empty.url(), Absent),
                (UNREACHABLE.to_string(), Absent),
            ])
        );
    }

    assert!(
        home.requests().is_empty(),
        "the standby's own relay was never asked: {:?}",
        home.requests()
    );
    for relay in [&live, &expired, &empty] {
        let asked = last_request(relay);
        assert_eq!(asked["kinds"], json!([K_LIVENESS]));
        assert_eq!(asked["authors"], json!([primary.public_key().to_hex()]));
    }
}

/// "Expired" is decided on the instant the caller passes, not on the relay
/// or the wall: the same relay is live at one instant and expired the next.
#[tokio::test]
async fn liveness_state_expires_on_the_instant_given() {
    let relay = StubRelay::start().await;
    let primary = Keys::generate();
    let now = wall_now();
    relay.hold(liveness(&primary, now)); // expires at now + 5 × CADENCE
    let directory = directory_over(&[]);
    let relays = vec![relay.url()];

    let primary = primary.public_key();
    let at = |now: u64| {
        let (directory, relays, relay) = (&directory, &relays, &relay);
        async move {
            directory
                .liveness_state(primary, relays, now)
                .await
                .unwrap()[&relay.url()]
        }
    };
    assert_eq!(at(now + 5 * CADENCE - 1).await, Live);
    assert_eq!(at(now + 5 * CADENCE).await, Expired);
}

// ── publish_takeover ─────────────────────────────────────────────────────

/// A Takeover is a paid write like any other — through the directory
/// publisher — but addressed to the PRIMARY's relays, not the Relay Set the
/// Directory was built with; `publish` still goes to the latter.
#[tokio::test]
async fn publish_takeover_pays_the_publisher_for_the_primarys_relays() {
    let publisher = MockServer::start().await;
    let primary_relays = ["ws://primary-one:7100", "ws://primary-two:7100"];
    Mock::given(method("POST"))
        .and(path("/publish"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accepted": primary_relays,
            "failed": {},
        })))
        .mount(&publisher)
        .await;
    let own_relay = "ws://standby-one:7100";
    let directory = ConnectorDirectory::new(
        format!("{}/publish", publisher.uri()),
        vec![own_relay.to_string()],
    )
    .unwrap();

    let standby = Keys::generate();
    let workload_id = "ab".repeat(32);
    let event = takeover(&workload_id, &Keys::generate().public_key(), &standby, NOW);
    let report = directory
        .publish_takeover(event.clone(), &strings(&primary_relays))
        .await
        .unwrap();
    assert_eq!(report.accepted, strings(&primary_relays));
    assert!(report.reached_every_relay());

    // …and, for contrast, what the provider says about itself.
    directory
        .publish(liveness(&standby, wall_now()))
        .await
        .unwrap();

    let requests = publisher.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body["relays"],
        json!(primary_relays),
        "the primary's relays"
    );
    assert_eq!(body["event"]["id"], event.id.to_hex());
    assert_eq!(body["event"]["kind"], K_TAKEOVER);
    let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(body["relays"], json!([own_relay]), "the Relay Set");
}

/// A publisher that refuses is an error — the write was not attempted on
/// any relay — and a Directory with no publisher announces nothing, as it
/// publishes nothing, without failing the caller.
#[tokio::test]
async fn a_takeover_nobody_can_pay_for_is_not_announced() {
    let publisher = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_string("no channel"))
        .mount(&publisher)
        .await;
    let event = takeover(
        &"ab".repeat(32),
        &Keys::generate().public_key(),
        &Keys::generate(),
        NOW,
    );
    let relays = strings(&["ws://primary-one:7100"]);

    let paid = ConnectorDirectory::new(format!("{}/publish", publisher.uri()), vec![]).unwrap();
    let refused = paid.publish_takeover(event.clone(), &relays).await;
    assert!(refused.is_err(), "{refused:?}");

    let unpaid = NullDirectory::new(vec![]);
    let report = unpaid.publish_takeover(event, &relays).await.unwrap();
    assert!(report.accepted.is_empty(), "nothing was published");
}

// ── find_takeovers ───────────────────────────────────────────────────────

/// The claims on one workload from the set's members, earliest first: a
/// stranger's claim and a member's claim on another workload never arrive,
/// because the filter names the claimants and the `d`; one event held by
/// two relays is one claim.
#[tokio::test]
async fn find_takeovers_returns_the_sets_claims_on_the_workload_earliest_first() {
    let one = StubRelay::start().await;
    let two = StubRelay::start().await;
    let primary = Keys::generate().public_key();
    let first = Keys::generate();
    let second = Keys::generate();
    let stranger = Keys::generate();
    let workload_id = "ab".repeat(32);

    let firsts = takeover(&workload_id, &primary, &first, NOW + 5);
    let seconds = takeover(&workload_id, &primary, &second, NOW + 1);
    one.hold(firsts.clone());
    one.hold(seconds.clone());
    two.hold(seconds.clone()); // the same claim, on both relays
    one.hold(takeover(&workload_id, &primary, &stranger, NOW)); // not a member
    one.hold(takeover(&"cd".repeat(32), &primary, &first, NOW - 10)); // another workload

    let claimants = [first.public_key(), second.public_key()];
    let relays = vec![one.url(), two.url()];
    for directory in [
        Box::new(directory_over(&[])) as Box<dyn Directory>,
        Box::new(NullDirectory::new(vec![])),
    ] {
        let found = directory
            .find_takeovers(&workload_id, &claimants, &relays)
            .await
            .unwrap();
        let ids: Vec<_> = found.iter().map(|e| e.id).collect();
        assert_eq!(
            ids,
            vec![seconds.id, firsts.id],
            "earliest first, once each"
        );
    }

    let asked = last_request(&one);
    assert_eq!(asked["kinds"], json!([K_TAKEOVER]));
    assert_eq!(asked["#d"], json!([workload_id]));
    let authors = asked["authors"].as_array().unwrap();
    assert_eq!(authors.len(), 2);
    assert!(authors.contains(&json!(first.public_key().to_hex())));
    assert!(authors.contains(&json!(second.public_key().to_hex())));
}

/// No claimants, or no relays, is nothing to ask: an empty answer, and no
/// relay is bothered.
#[tokio::test]
async fn find_takeovers_with_nothing_to_ask_asks_nothing() {
    let relay = StubRelay::start().await;
    let directory = directory_over(&[]);
    let workload_id = "ab".repeat(32);
    assert!(directory
        .find_takeovers(&workload_id, &[], &[relay.url()])
        .await
        .unwrap()
        .is_empty());
    assert!(directory
        .find_takeovers(&workload_id, &[Keys::generate().public_key()], &[])
        .await
        .unwrap()
        .is_empty());
    assert!(relay.requests().is_empty());
}

// ── query_liveness ───────────────────────────────────────────────────────

/// The read that was there before this milestone, against a real relay for
/// the first time: the newest Liveness across the Relay Set, from the
/// provider asked for.
#[tokio::test]
async fn query_liveness_reads_the_newest_liveness_across_the_relay_set() {
    let one = StubRelay::start().await;
    let two = StubRelay::start().await;
    let provider = Keys::generate();
    let now = wall_now();
    one.hold(liveness(&provider, now - 10));
    two.hold(liveness(&provider, now));
    two.hold(liveness(&Keys::generate(), now + 5));

    let directory = directory_over(&[&one, &two]);
    let found = directory
        .query_liveness(provider.public_key())
        .await
        .unwrap()
        .expect("held");
    assert_eq!(found.created_at.as_u64(), now);
    assert!(directory
        .query_liveness(Keys::generate().public_key())
        .await
        .unwrap()
        .is_none());
}
