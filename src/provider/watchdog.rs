// The watchdog: what a Warm Standby does with its reservation while it
// waits (spec §7.1 steps 1–2).
//
// For every reserved lease this provider holds, the primary — index 0 of the
// lease's Standby Set, or the winner of a Takeover this provider lost
// (`settle::primary_of`) — is watched on the PRIMARY's Relay Set, read from
// the primary's Provider Profile, never on this provider's own relays: a primary
// publishes Liveness to the relays IT lists, and a standby watching its own
// would be waiting for something that was never sent there. The primary is
// silent when its Liveness is expired or absent on a strict majority of that
// Relay Set — one of one, two of three — and has been so continuously for
// one `liveness_cadence_s`. One relay that lost a write, or a majority that
// comes back inside the cadence, triggers nothing.
//
// When the trigger holds, this provider publishes ONE Takeover to the
// primary's Relay Set and remembers, on the lease and on disk, that it did
// and when. Settling the race and starting the workload are `settle`'s
// (steps 3–5), run as the second half of the same step: this module
// announces, and hands over.
//
// The shape is the expiry sweep's (`cleanup`): a public step that takes an
// instant, run by a thin loop in the service and by a fake clock in tests.
// Paygress's `durable_workload` — a revocation event the primary published
// on its own eviction, and a respawn path the provider drove for itself — is
// gone rather than adapted: ADR 0010 takes over on Liveness expiry precisely
// because a crashed primary cannot announce anything.

use anyhow::Result;
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::persistence::{persist_leases, LeaseRecord, LeaseState};
use super::settle::primary_of;
use super::ProviderService;
use crate::directory::RelayLiveness;
use crate::nostr::directory_events::{takeover_event, ProfileContent};

/// How often the watchdog steps. Well inside any cadence a primary would
/// publish at, so the trigger fires within a step of the cadence elapsing;
/// reads are free (ADR 0007), so a step costs relay round trips and nothing
/// else.
pub const WATCHDOG_INTERVAL_SECS: u64 = 10;

/// The Takeover trigger, in cadences of the primary this round watches (spec
/// §7.1 step 1, normative table in §7.2): how long the primary's Liveness
/// must be silent on a strict majority of its Relay Set, continuously,
/// before a standby announces. One, so that the trigger fires as soon as a
/// single cadence has passed with no majority reached — the shortest wait
/// that still tells a flaky relay apart from a silent primary.
pub const TRIGGER_CADENCES: u64 = 1;

/// The Takeover a Warm Standby announced, kept with its lease (spec §7.1
/// step 2).
///
/// Persisted, because a standby that restarts after announcing must settle
/// the race it entered rather than announce again — and everything the
/// settle (§7.1 step 3) needs is here: when the claim was made, the cadence
/// the two-cadence window is measured in, and the relays the claim went to,
/// which is where every other member's claim is.
///
/// No `deny_unknown_fields`, for the reason `StandbySet` gives: this is on
/// disk, never on the wire, and one unknown key must not empty the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeoverAnnouncement {
    /// The instant the Takeover was published: its `created_at`.
    pub announced_at: u64,
    /// The primary's `liveness_cadence_s` when it was announced; the settle
    /// window is two of these.
    pub cadence_s: u64,
    /// The primary's Relay Set the claim was published to.
    pub relays: Vec<String>,
}

/// Spec §7.1 step 1's arithmetic: silent on a STRICT majority of `relays`.
/// One of one, two of three, three of four. A relay in `relays` that has no
/// entry in `states` is absent — it was asked, and said nothing.
pub fn silent_on_a_majority(relays: &[String], states: &RelayLiveness) -> bool {
    let silent = relays
        .iter()
        .filter(|relay| states.get(relay.as_str()).is_none_or(|s| s.is_silent()))
        .count();
    silent * 2 > relays.len()
}

/// One reservation and the primary it watches, read off the lease table.
struct Watched {
    id: u32,
    workload_id: String,
    primary: PublicKey,
}

/// The primary `lease` watches, if it watches one: a reservation that has
/// not announced yet, on the member `settle::primary_of` names — index 0
/// of the set, or the winner of a Takeover this provider lost (spec §7.1
/// step 5). Never this provider itself: a reservation whose primary is `me`
/// is one that WON and has not started yet, and `settle` starts it. A
/// reservation whose set names no parsable primary is not watched rather
/// than a panic — the record came off disk, where nothing re-checks it.
fn watched_primary(lease: &LeaseRecord, me: &str) -> Option<Watched> {
    if lease.state != LeaseState::Reserved || lease.takeover.is_some() {
        return None;
    }
    let set = lease.standby_set.as_ref()?;
    if set.is_primary() {
        return None;
    }
    let primary = primary_of(lease)?;
    if primary == me {
        return None;
    }
    let primary = PublicKey::parse(primary).ok()?;
    Some(Watched {
        id: lease.id,
        workload_id: lease.workload_id.clone(),
        primary,
    })
}

impl ProviderService {
    pub(super) async fn watchdog_loop(&self) -> Result<()> {
        let interval = tokio::time::Duration::from_secs(WATCHDOG_INTERVAL_SECS);

        loop {
            tokio::time::sleep(interval).await;
            self.watch_primaries(self.state.clock.now()).await;
        }
    }

    /// One step of the watch at `now`: read every watched primary's Profile
    /// and its Liveness on the relays that Profile lists, keep the count of
    /// silence per lease, and announce a Takeover for each primary that has
    /// been silent for a cadence — then settle every announcement whose
    /// window has elapsed and start what was won (`settle`). Public so a
    /// test can drive the trigger on chosen instants rather than waiting
    /// out cadences.
    ///
    /// A provider with no reservation reads nothing: the table is looked at
    /// first, and the Directory only for the primaries it names.
    pub async fn watch_primaries(&self, now: u64) {
        let me = self.state.keys.public_key().to_hex();
        let watched: Vec<Watched> = {
            let leases = self.state.leases.lock().await;
            leases
                .values()
                .filter_map(|l| watched_primary(l, &me))
                .collect()
        };

        // A lease that is no longer watched — ended, or announced — takes
        // its count with it, so a later reservation that reuses the id
        // starts from nothing.
        {
            let mut silence = self.silence.lock().await;
            silence.retain(|id, _| watched.iter().any(|w| w.id == *id));
        }

        for watched in &watched {
            self.watch_one(watched, now).await;
        }

        // Steps 3–5, for the reservations that announced on an earlier
        // step. A loser comes back into `watched` on the NEXT step, with the
        // winner as its primary and a count of silence that starts from
        // nothing.
        self.settle_takeovers(now).await;
    }

    /// Steps 1 and 2 of spec §7.1 for one reservation.
    ///
    /// Every read that fails ends the step for this lease and changes
    /// nothing: a Profile that cannot be read says nothing about whether the
    /// primary is up, and the count neither starts nor restarts on it. The
    /// reads happen outside the lease lock, like the sweep's backend calls,
    /// so a slow relay never holds the table against the HTTP handlers.
    async fn watch_one(&self, watched: &Watched, now: u64) {
        let state = &self.state;
        let Watched {
            id,
            workload_id,
            primary,
        } = watched;

        let profile = match state.directory.get_profile(*primary).await {
            Ok(Some(event)) if event.pubkey == *primary => event,
            Ok(_) => {
                warn!(
                    "lease {}: no Provider Profile for its primary {} on the Relay Set; \
                     cannot watch it yet",
                    id,
                    primary.to_hex()
                );
                return;
            }
            Err(e) => {
                warn!(
                    "lease {}: the primary's Profile could not be read: {:#}",
                    id, e
                );
                return;
            }
        };
        let profile: ProfileContent = match serde_json::from_str(&profile.content) {
            Ok(profile) => profile,
            Err(e) => {
                warn!(
                    "lease {}: the primary's Profile is not a Provider Profile ({}); \
                     cannot watch it",
                    id, e
                );
                return;
            }
        };
        if profile.relays.is_empty() {
            warn!(
                "lease {}: the primary's Profile lists no relay; cannot watch it",
                id
            );
            return;
        }
        let cadence_s = profile.liveness_cadence_s.max(1);

        let states = match state
            .directory
            .liveness_state(*primary, &profile.relays, now)
            .await
        {
            Ok(states) => states,
            Err(e) => {
                warn!(
                    "lease {}: the primary's Liveness could not be read: {:#}",
                    id, e
                );
                return;
            }
        };

        let since = {
            let mut silence = self.silence.lock().await;
            if !silent_on_a_majority(&profile.relays, &states) {
                // A live reading inside the cadence restarts the count: the
                // trigger is CONTINUOUS silence (spec §7.1 step 1).
                if silence.remove(id).is_some() {
                    info!(
                        "lease {}: the primary is live again on a majority of its Relay Set",
                        id
                    );
                }
                return;
            }
            *silence.entry(*id).or_insert_with(|| {
                info!(
                    "lease {}: the primary is silent on a majority of its Relay Set ({:?}); \
                     a Takeover follows if it stays so for {} s",
                    id, states, cadence_s
                );
                now
            })
        };
        if now.saturating_sub(since) < TRIGGER_CADENCES.saturating_mul(cadence_s) {
            return;
        }

        // Step 2: announce, once. To the PRIMARY's Relay Set, where every
        // other member of the set is watching.
        let takeover = match takeover_event(workload_id, primary, &state.keys, now) {
            Ok(event) => event,
            Err(e) => {
                warn!("lease {}: a Takeover could not be built: {:#}", id, e);
                return;
            }
        };
        match state
            .directory
            .publish_takeover(takeover, &profile.relays)
            .await
        {
            Ok(report) => {
                info!(
                    "lease {}: Takeover of {} announced after {} s of silence: {}",
                    id,
                    workload_id,
                    now.saturating_sub(since),
                    report.summary()
                );
            }
            Err(e) => {
                // Not announced, so nothing is remembered and the count
                // stands: the next step tries again. The publisher being
                // down is not the primary coming back.
                warn!(
                    "lease {}: the Takeover was not announced ({:#}); trying again on the \
                     next step",
                    id, e
                );
                return;
            }
        }

        let mut leases = state.leases.lock().await;
        if let Some(lease) = leases.get_mut(id) {
            // Still the reservation that was watched: a lease that ended
            // while the publication was in flight has nothing to settle.
            if lease.state == LeaseState::Reserved && lease.takeover.is_none() {
                lease.takeover = Some(TakeoverAnnouncement {
                    announced_at: now,
                    cadence_s,
                    relays: profile.relays,
                });
                persist_leases(&leases, &state.config.lease_state_path);
            }
        }
        self.silence.lock().await.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::LivenessState::{Absent, Expired, Live};

    fn relays(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("ws://relay-{i}:7100")).collect()
    }

    fn states(pairs: &[(usize, crate::directory::LivenessState)]) -> RelayLiveness {
        pairs
            .iter()
            .map(|(i, s)| (format!("ws://relay-{i}:7100"), *s))
            .collect()
    }

    #[test]
    fn a_strict_majority_is_one_of_one_and_two_of_three() {
        assert!(silent_on_a_majority(&relays(1), &states(&[(1, Absent)])));
        assert!(silent_on_a_majority(&relays(1), &states(&[(1, Expired)])));
        assert!(!silent_on_a_majority(&relays(1), &states(&[(1, Live)])));

        // One flaky relay of three is not a majority.
        assert!(!silent_on_a_majority(
            &relays(3),
            &states(&[(1, Absent), (2, Live), (3, Live)])
        ));
        assert!(silent_on_a_majority(
            &relays(3),
            &states(&[(1, Absent), (2, Expired), (3, Live)])
        ));
    }

    #[test]
    fn half_is_not_a_majority() {
        // Two of four: strict means more than half, so an even split reads
        // as not silent — the safe side of a tie.
        assert!(!silent_on_a_majority(
            &relays(4),
            &states(&[(1, Absent), (2, Absent), (3, Live), (4, Live)])
        ));
        assert!(silent_on_a_majority(
            &relays(4),
            &states(&[(1, Absent), (2, Absent), (3, Expired), (4, Live)])
        ));
    }

    #[test]
    fn a_relay_that_gave_no_answer_is_absent() {
        // Asked and unanswered is the same as asked and empty: the standby
        // cannot see a Liveness there.
        assert!(silent_on_a_majority(&relays(3), &states(&[(3, Live)])));
        assert!(!silent_on_a_majority(
            &relays(3),
            &states(&[(2, Live), (3, Live)])
        ));
    }
}
