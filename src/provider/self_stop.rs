// The primary's half of the Takeover rule: what a provider does when its own
// relays stop taking its Liveness (spec §7.1, "Primary self-stop").
//
// A standby takes over on SILENCE — a primary whose Liveness is expired or
// absent on a majority of its Relay Set (`watchdog`). The primary cannot see
// that silence from the outside, but it can see the half of it that is its
// own: every Liveness publication reports which relays of the Relay Set took
// it, and a primary that has failed to reach a strict majority of them for
// five cadences running must assume its standbys have stopped seeing it and
// stop its workload. Two copies of a workload may run briefly while a
// partitioned primary notices (ADR 0010); this is what ends that.
//
// Stopping is NOT ending. The lease is paid to its `expires_at` and stays
// exactly as live as it was: it holds its capacity slot, `.extend` still buys
// it another interval, and the sweep still ends it when nobody does. The
// container is stopped, never deleted, so the same workload starts again if
// the relays come back — and only then, and only if the set has not already
// moved on:
//
//   - majority regained, no Takeover on the Relay Set → start it again;
//   - a Takeover from a member of the `standby_set` → `taken_over`, and this
//     workload stays off for the rest of the lease. A new primary is running
//     it, and the one guarantee a Standby Set owes the tenant is that its
//     workload runs once.
//
// The same question is asked at STARTUP (`stand_down_if_taken_over`), because
// the loudest version of a partition is a provider that was down: the process
// is stopped, its workloads keep running as containers beside it on the host
// daemon, a standby takes over, and the process comes back to a lease table
// that says Running. A primary of a Standby Set therefore asks the relays
// whether anyone claimed its workload before it treats it as live.
//
// A provider with NO Relay Set is exempt from all of it: nothing it publishes
// reaches anyone, so no standby can watch it, nothing can take its workload
// over, and there is no majority for it to lose.

use std::sync::atomic::Ordering;

use anyhow::Result;
use nostr_sdk::PublicKey;
use tracing::{info, warn};

use super::persistence::{persist_leases, LeaseRecord, LeaseState};
use super::standby::StandbySet;
use super::ProviderService;
use crate::directory::PublishReport;
use crate::nostr::wire::Role;

/// How many consecutive cadences without a majority stop the workload (spec
/// §7.1). A first guess, like the takeover trigger and the settle window
/// (spec §11): long enough that a relay hiccup or a restart of the publisher
/// costs nobody their workload, short enough that a partitioned primary is
/// off before a standby has settled its Takeover.
///
/// Counted in PUBLICATIONS, which is what a cadence is here: `directory_loop`
/// makes exactly one per `liveness_cadence_s`, so the two are the same count
/// and a test can drive five of them without waiting out five cadences.
pub const SELF_STOP_CADENCES: u32 = 5;

/// Spec §7.1's arithmetic for the primary's own publication: a STRICT
/// majority of the Relay Set took it. One of one, two of three, three of
/// four.
///
/// It counts the relays that ACCEPTED, not the ones that refused, because
/// the two need not add up: a publication that could not be attempted at all
/// reports neither, and that is a cadence on which no relay took it.
pub fn reached_a_majority(relay_set: usize, report: Option<&PublishReport>) -> bool {
    let accepted = report.map_or(0, |r| r.accepted.len());
    accepted * 2 > relay_set
}

/// One primary lease, and what deciding its workload's fate needs.
struct Primary {
    id: u32,
    workload_id: String,
    members: Vec<PublicKey>,
}

/// The primary `lease` is, if it is one: a lease this provider holds as the
/// index 0 of a Standby Set. A set whose members do not parse is not one
/// rather than a panic — the record came off disk, where nothing re-checks
/// it.
///
/// Role `Primary`, so a STANDALONE lease is never one: it is in no Standby
/// Set, nobody is waiting to take it over, and stopping it would take a paid
/// workload down for a reason its tenant never bought into. A Warm Standby
/// that WON a Takeover keeps role `Standby` (spec §7.1 step 4) and is not one
/// either — the rule for the provider that is running a workload it took over
/// belongs with the ticket that starts it, since the claim it would find on
/// its own Relay Set is its own.
fn primary_of_a_set(lease: &LeaseRecord) -> Option<Primary> {
    if lease.role != Role::Primary {
        return None;
    }
    let set: &StandbySet = lease.standby_set.as_ref()?;
    let members: Vec<PublicKey> = set
        .members
        .iter()
        .filter_map(|hex| PublicKey::parse(hex).ok())
        .collect();
    if members.is_empty() {
        return None;
    }
    Some(Primary {
        id: lease.id,
        workload_id: lease.workload_id.clone(),
        members,
    })
}

impl ProviderService {
    /// What one Liveness cadence meant for this provider's own workloads
    /// (spec §7.1): the report of which relays took it, counted against the
    /// Relay Set it was offered to.
    ///
    /// `None` is a publication that asked no relay at all — the event could
    /// not be built, or the publisher could not be reached — which for this
    /// count is a cadence on which no relay took it: whatever the reason, a
    /// standby watching those relays saw nothing new.
    ///
    /// Called by `publish_liveness`, so the rule runs on exactly the
    /// publications the directory loop makes and a test drives the two
    /// together.
    pub(super) async fn note_liveness(&self, report: Option<&PublishReport>) {
        let relay_set = self.state.config.relay_set.len();
        if relay_set == 0 {
            // No Relay Set: nothing to publish to, nobody watching, no
            // majority to lose.
            return;
        }

        if reached_a_majority(relay_set, report) {
            let missed = self.cadences_without_majority.swap(0, Ordering::SeqCst);
            if missed > 0 {
                info!(
                    "Liveness reached a majority of the Relay Set again after {} cadence(s); \
                     any workload this provider stopped for it may start again",
                    missed
                );
            }
            self.restart_stopped_primaries().await;
            return;
        }

        let missed = self
            .cadences_without_majority
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        if missed < SELF_STOP_CADENCES {
            warn!(
                "Liveness reached {} of {} relay(s) — not a majority — for {} cadence(s); \
                 this provider's primaries stop at {}",
                report.map_or(0, |r| r.accepted.len()),
                relay_set,
                missed,
                SELF_STOP_CADENCES
            );
            return;
        }
        self.stop_running_primaries(missed).await;
    }

    /// Stop the workload of every primary lease this provider holds. A
    /// standalone lease is left alone: it is in no Standby Set, nobody is
    /// waiting to take it over, and stopping it would be a provider taking a
    /// paid workload down for a reason the tenant never bought into.
    ///
    /// A backend that refuses to stop leaves the lease Running, so the next
    /// cadence — which is still past the count — tries again. Reporting a
    /// workload stopped that is still running would be worse than trying
    /// twice.
    async fn stop_running_primaries(&self, missed: u32) {
        let state = &self.state;
        let running: Vec<u32> = {
            let leases = state.leases.lock().await;
            leases
                .values()
                .filter(|l| l.state == LeaseState::Running && primary_of_a_set(l).is_some())
                .map(|l| l.id)
                .collect()
        };

        for id in running {
            // Outside the lease lock, like the sweep's backend calls, so a
            // slow daemon never holds the table against the HTTP handlers.
            if let Err(e) = state.backend.stop_container(id).await {
                warn!(
                    "lease {}: its workload could not be stopped after {} cadence(s) without a \
                     relay majority ({:#}); trying again next cadence",
                    id, missed, e
                );
                continue;
            }
            let mut leases = state.leases.lock().await;
            if let Some(lease) = leases.get_mut(&id) {
                // Still the running primary that was decided about: a lease
                // that ended while the daemon was stopping it has nothing
                // left to say about its workload.
                if lease.state == LeaseState::Running {
                    info!(
                        "lease {}: workload stopped after {} cadence(s) without a majority of \
                         the Relay Set; the lease stays paid until {}",
                        id, missed, lease.expires_at
                    );
                    lease.state = LeaseState::Stopped;
                    persist_leases(&leases, &state.config.lease_state_path);
                }
            }
        }
    }

    /// Start again what the rule above stopped — for the leases the Standby
    /// Set has not moved past.
    ///
    /// Reads nothing when nothing is stopped, which is every cadence of a
    /// healthy provider: the table is looked at first, and the Directory
    /// only for the leases that are waiting on it.
    async fn restart_stopped_primaries(&self) {
        let state = &self.state;
        let stopped: Vec<Primary> = {
            let leases = state.leases.lock().await;
            leases
                .values()
                .filter(|l| l.state == LeaseState::Stopped && !l.taken_over)
                .filter_map(primary_of_a_set)
                .collect()
        };

        for primary in stopped {
            match self.takeover_exists(&primary).await {
                Ok(true) => self.record_takeover(&primary).await,
                // Not knowing is not the same as knowing there is none. A
                // Relay Set that cannot be read might be holding the claim
                // that says another provider is running this workload, so
                // the workload stays off and the next cadence asks again.
                Err(e) => warn!(
                    "lease {}: the Relay Set could not be asked whether {} was taken over \
                     ({:#}); its workload stays stopped",
                    primary.id, primary.workload_id, e
                ),
                Ok(false) => self.start_again(&primary).await,
            }
        }
    }

    /// Every Takeover the Relay Set holds for this lease's workload id from a
    /// member of its Standby Set (spec §7.1 step 3, from the primary's side).
    ///
    /// On the primary's OWN Relay Set, because that is where a standby
    /// publishes its claim — it is the set of relays the primary's Profile
    /// lists, which is what a standby reads before it announces.
    async fn takeover_exists(&self, primary: &Primary) -> Result<bool> {
        let found = self
            .state
            .directory
            .find_takeovers(
                &primary.workload_id,
                &primary.members,
                &self.state.config.relay_set,
            )
            .await?;
        Ok(!found.is_empty())
    }

    /// Remember that the set moved on, so nothing here starts this workload
    /// again for the rest of the lease.
    async fn record_takeover(&self, primary: &Primary) {
        let state = &self.state;
        let mut leases = state.leases.lock().await;
        let Some(lease) = leases.get_mut(&primary.id) else {
            return;
        };
        if lease.taken_over {
            return;
        }
        info!(
            "lease {}: a member of its Standby Set has claimed {}; this provider's copy stays \
             stopped for the rest of the lease",
            primary.id, primary.workload_id
        );
        lease.taken_over = true;
        persist_leases(&leases, &state.config.lease_state_path);
    }

    /// Start a stopped workload again. The same container, not a new one:
    /// nothing was deleted, and the lease still names the ports and the id
    /// the tenant was given.
    async fn start_again(&self, primary: &Primary) {
        let state = &self.state;
        if let Err(e) = state.backend.start_container(primary.id).await {
            warn!(
                "lease {}: its workload could not be started again ({:#}); trying again next \
                 cadence",
                primary.id, e
            );
            return;
        }
        let mut leases = state.leases.lock().await;
        if let Some(lease) = leases.get_mut(&primary.id) {
            if lease.state == LeaseState::Stopped {
                info!(
                    "lease {}: the Relay Set holds no Takeover of {}, and the majority is back; \
                     its workload is running again",
                    primary.id, primary.workload_id
                );
                lease.state = LeaseState::Running;
                persist_leases(&leases, &state.config.lease_state_path);
            }
        }
    }

    /// At startup: stop the workload of every primary lease the Standby Set
    /// has already moved past (spec §7.1).
    ///
    /// A provider whose PROCESS was down is the partition this catches. Its
    /// workloads are containers on the host daemon and kept running without
    /// it; its standbys saw no Liveness, took over, and are running the
    /// workload now. `restore_leases` asks the daemon what exists and finds
    /// every one of them, so without this the provider would carry straight
    /// on serving a lease that is being served elsewhere — the very thing the
    /// five-cadence rule exists to prevent, arrived at by a route where no
    /// cadence was ever counted.
    ///
    /// So: for each live primary lease that has a workload, the Relay Set is
    /// asked for a Takeover of its workload id from a member of its set. One
    /// found stops the workload and marks the lease `taken_over`; none found,
    /// or a Relay Set that cannot be read, changes nothing — a primary is
    /// innocent until a claim says otherwise, since the alternative is
    /// stopping a healthy workload over an unreachable relay.
    ///
    /// Run after `restore_leases` and before the loops. Public so a test can
    /// drive a restart without the loops.
    pub async fn stand_down_if_taken_over(&self) {
        let state = &self.state;
        if state.config.relay_set.is_empty() {
            return;
        }
        let primaries: Vec<Primary> = {
            let leases = state.leases.lock().await;
            leases
                .values()
                .filter(|l| l.state.is_reachable() && !l.taken_over)
                .filter_map(primary_of_a_set)
                .collect()
        };

        for primary in primaries {
            match self.takeover_exists(&primary).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    warn!(
                        "lease {}: the Relay Set could not be asked whether {} was taken over \
                         while this provider was down ({:#}); its workload keeps running",
                        primary.id, primary.workload_id, e
                    );
                    continue;
                }
            }
            if let Err(e) = state.backend.stop_container(primary.id).await {
                warn!(
                    "lease {}: {} was taken over while this provider was down, and its workload \
                     could not be stopped ({:#}); it may be running beside the new primary's",
                    primary.id, primary.workload_id, e
                );
                continue;
            }
            let mut leases = state.leases.lock().await;
            if let Some(lease) = leases.get_mut(&primary.id) {
                info!(
                    "lease {}: {} was taken over while this provider was down; its workload is \
                     stopped and stays so for the rest of the lease",
                    primary.id, primary.workload_id
                );
                lease.state = LeaseState::Stopped;
                lease.taken_over = true;
                persist_leases(&leases, &state.config.lease_state_path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(n: usize) -> PublishReport {
        PublishReport {
            accepted: (1..=n).map(|i| format!("ws://relay-{i}:7100")).collect(),
            failed: Default::default(),
        }
    }

    #[test]
    fn a_strict_majority_is_one_of_one_and_two_of_three() {
        assert!(reached_a_majority(1, Some(&accepted(1))));
        assert!(!reached_a_majority(1, Some(&accepted(0))));

        assert!(!reached_a_majority(3, Some(&accepted(1))));
        assert!(reached_a_majority(3, Some(&accepted(2))));
    }

    #[test]
    fn half_is_not_a_majority() {
        // Two of four: strict means more than half, so an even split is a
        // majority lost — the same side of the tie the standby's own trigger
        // takes (`watchdog::silent_on_a_majority`), read from the other end.
        assert!(!reached_a_majority(4, Some(&accepted(2))));
        assert!(reached_a_majority(4, Some(&accepted(3))));
    }

    #[test]
    fn a_publication_that_asked_no_relay_reached_none() {
        assert!(!reached_a_majority(1, None));
        assert!(!reached_a_majority(3, None));
    }
}
