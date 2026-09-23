//! A relay another provider's Provider Profile names must not aim this
//! provider's websocket at the operator's own network (TOON_Network#113).
//!
//! The sibling of `relay_hint.rs`: the same rule, the same trap, a different
//! author. A Warm Standby watches its primary on the relays the PRIMARY's
//! Profile lists (spec §7.1) — `liveness_state` to see whether it is up,
//! `publish_takeover` to announce a claim, `find_takeovers` to settle the
//! race — and a Provider Profile is a published event that anybody can sign.
//! So a peer that joins a Standby Set, or merely stands in one, can list
//! `ws://127.0.0.1:9944` and have every other member dial it; on a schedule,
//! for free, for as long as the reservation lasts.
//!
//! The rule the guard applies is #107's, unchanged. What is decided HERE is
//! what a refused relay costs the peer that named it: it is read as
//! `Absent` — the same answer a relay that refuses the connection gets —
//! and the peer's OTHER relays are still asked. The alternative, treating a
//! Profile with one bad relay as unusable, would hand every peer a way to
//! make itself un-takeover-able: a primary that lists one relay nobody may
//! dial would never be watched, never be found silent, and would hold a
//! tenant's workload until the lease ran out. So a bad relay is silence, it
//! counts in the majority of spec §7.1 step 1, and the last two tests are
//! the two halves of that: a mix still watches, and an all-bad Profile is
//! silent rather than invisible.

mod common;

use std::collections::BTreeMap;

use nostr_sdk::{Keys, PublicKey};
use serde_json::json;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::relay::StubRelay;
use common::trap::Trap;
use toon_provider::nostr::directory_events::{liveness_event, takeover_event};
use toon_provider::provider::silent_on_a_majority;
use toon_provider::LivenessState::{Absent, Live};
use toon_provider::{ConnectorDirectory, Directory, NullDirectory, RelayLiveness};

const CADENCE: u64 = 60;

/// The wall clock: nostr-sdk's relay pool drops a Liveness whose
/// `expiration` has passed by it before the Directory ever sees the event, so
/// what a stub relay holds must expire in the real future.
fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn strings(relays: &[&str]) -> Vec<String> {
    relays.iter().map(|r| r.to_string()).collect()
}

/// What a Warm Standby asks about a peer whose Profile lists `relays`, on a
/// provider whose OWN Relay Set is `relay_set`.
async fn liveness_of(peer: PublicKey, relays: &[String], relay_set: Vec<String>) -> RelayLiveness {
    NullDirectory::new(relay_set)
        .liveness_state(peer, relays, wall_now())
        .await
        .unwrap()
}

// ── the relays a peer names ─────────────────────────────────────────────

/// `relays: ["ws://127.0.0.1:<port>"]` in a peer's Profile: an address this
/// provider must not dial, and nothing leaves.
#[tokio::test]
async fn a_peers_loopback_relay_is_never_dialled() {
    let trap = Trap::set().await;
    let peer = Keys::generate().public_key();
    let relays = vec![trap.relay_url()];

    let states = liveness_of(peer, &relays, vec![]).await;

    assert_eq!(states, BTreeMap::from([(trap.relay_url(), Absent)]));
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// The same by NAME: `localhost` resolves inward, and the check is on what
/// it resolves to.
#[tokio::test]
async fn a_peers_relay_whose_name_resolves_inward_is_never_dialled() {
    let trap = Trap::set().await;
    let peer = Keys::generate().public_key();
    let relays = vec![trap.relay_url_as("localhost")];

    let states = liveness_of(peer, &relays, vec![]).await;

    assert_eq!(states.get(&relays[0]), Some(&Absent));
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// A scheme that is not `ws` or `wss` is refused before anything is
/// resolved: a provider watches a peer over a websocket and nothing else.
#[tokio::test]
async fn a_peers_relay_that_is_not_a_websocket_is_never_dialled() {
    let trap = Trap::set().await;
    let peer = Keys::generate().public_key();
    let relays = strings(&[
        &format!("http://127.0.0.1:{}", trap.addr.port()),
        &format!("https://203.0.113.7:{}", trap.addr.port()),
        "file:///etc/passwd",
        "not a URL at all",
    ]);

    let states = liveness_of(peer, &relays, vec![]).await;

    for relay in &relays {
        assert_eq!(states.get(relay), Some(&Absent), "{}", relay);
    }
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// Settling a race reads the claims off the primary's relays, so it is the
/// same door: a claim a peer says is at `ws://127.0.0.1:<port>` is not
/// fetched from there.
#[tokio::test]
async fn find_takeovers_never_dials_a_peers_bad_relay() {
    let trap = Trap::set().await;
    let claimant = Keys::generate().public_key();
    let workload_id = "ab".repeat(32);

    let found = NullDirectory::new(vec![])
        .find_takeovers(&workload_id, &[claimant], &[trap.relay_url()])
        .await
        .unwrap();

    assert!(found.is_empty(), "nothing was read");
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// Announcing one is the same door once removed: the Takeover goes to the
/// primary's relays through the directory publisher, which would be the
/// process making the dial. A relay this provider may not reach is not a
/// relay it pays somebody else to reach, so the publisher is never asked and
/// the refusal comes back on the report.
#[tokio::test]
async fn publish_takeover_never_hands_a_peers_bad_relay_to_the_publisher() {
    let trap = Trap::set().await;
    let publisher = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accepted": [],
            "failed": {},
        })))
        .mount(&publisher)
        .await;
    let directory =
        ConnectorDirectory::new(format!("{}/publish", publisher.uri()), vec![]).unwrap();
    let event = takeover_event(
        &"ab".repeat(32),
        &Keys::generate().public_key(),
        &Keys::generate(),
        wall_now(),
    )
    .unwrap();

    let report = directory
        .publish_takeover(event, &[trap.relay_url()])
        .await
        .unwrap();

    assert!(report.accepted.is_empty());
    assert!(
        report.failed[&trap.relay_url()].contains("publicly routable"),
        "the report says why: {:?}",
        report.failed
    );
    assert!(
        publisher.received_requests().await.unwrap().is_empty(),
        "the publisher was never asked to pay for it"
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

// ── what a bad relay costs the peer that named it ───────────────────────

/// A mix is a mix: the relays this provider may dial are dialled, the one it
/// may not is silent, and a peer with a working majority is still watched —
/// which is the whole of "liveness and takeover still work".
#[tokio::test]
async fn a_peer_that_names_one_bad_relay_among_good_ones_is_still_watched() {
    let good = StubRelay::start().await;
    let also_good = StubRelay::start().await;
    let trap = Trap::set().await;
    let peer = Keys::generate();
    let now = wall_now();
    let live = liveness_event(BTreeMap::new(), CADENCE, &peer, now).unwrap();
    good.hold(live.clone());
    also_good.hold(live);
    let workload_id = "ab".repeat(32);
    let claim = takeover_event(&workload_id, &Keys::generate().public_key(), &peer, now).unwrap();
    good.hold(claim.clone());
    // The operator's own Relay Set is what makes a loopback stub dialable
    // here, exactly as it does for a tenant's hint (#107).
    let relay_set = vec![good.url(), also_good.url()];
    let named = vec![good.url(), trap.relay_url(), also_good.url()];

    let states = liveness_of(peer.public_key(), &named, relay_set.clone()).await;

    assert_eq!(
        states,
        BTreeMap::from([
            (good.url(), Live),
            (also_good.url(), Live),
            (trap.relay_url(), Absent),
        ])
    );
    assert!(
        !silent_on_a_majority(&named, &states),
        "one bad relay of three is not a silent primary"
    );
    // …and the claims come back from the relays that are dialable.
    let found = NullDirectory::new(relay_set)
        .find_takeovers(&workload_id, &[peer.public_key()], &named)
        .await
        .unwrap();
    assert_eq!(
        found.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![claim.id]
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// The other half, and the reason a refused relay is `Absent` rather than a
/// reason to drop the peer: a primary whose Profile lists nothing this
/// provider may dial is SILENT on every relay it named, so the trigger of
/// spec §7.1 step 1 fires and the standby takes over. A Profile treated as
/// unusable would instead have made that primary permanently invisible —
/// never watched, never taken over, holding the tenant's workload on a
/// relay nobody can check.
#[tokio::test]
async fn a_peer_cannot_hide_behind_relays_nobody_may_dial() {
    let trap = Trap::set().await;
    let peer = Keys::generate().public_key();
    let named = vec![trap.relay_url(), trap.relay_url_as("localhost")];

    let states = liveness_of(peer, &named, vec![]).await;

    assert!(
        silent_on_a_majority(&named, &states),
        "every relay it named is silence: {:?}",
        states
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}
