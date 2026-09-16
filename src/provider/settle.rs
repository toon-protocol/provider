// Settling a Takeover: what a Warm Standby does once it has announced one
// (spec §7.1 steps 3–5, ADR 0010).
//
// Announcing is a claim, not a decision: every standby in the set that saw
// the primary go silent has made the same claim, and at most ONE of them may
// start the workload. So after its own announcement a standby waits a settle
// window of two cadences — long enough for every other member's claim to
// have reached the primary's Relay Set — and then reads the claims back from
// the relays it published to. The winner is the claim with the earliest
// `created_at`; a tie goes to the lower index in the set. Only claims from
// members of the set count, and only claims that name the primary THIS round
// is against: a claim naming an earlier primary is an earlier race, already
// settled, and the member that won it is who this round is about.
//
// A standby that won starts the workload from the image exactly as a spawn
// would (`spawn::fetch_and_start`; ADR 0010 carries no state), its lease
// becomes Running, and from then on it is billed at the running price. A
// standby that lost stays Reserved and watches the winner as its primary —
// the set survives a second failure — and forgets its own announcement so
// that it can announce again if the winner goes silent too.
//
// The settle is one more pass of the watchdog step (`watchdog`), not a loop
// of its own: a test drives the same instants through the same door.

use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::image_policy;
use super::persistence::{persist_leases, LeaseRecord, LeaseState};
use super::spawn::{fetch_and_start, Launch};
use super::ProviderService;
use crate::nostr::directory_events::TakeoverContent;
use crate::nostr::image_events::SpawnImage;
use crate::nostr::kinds::K_TAKEOVER;
use crate::provider_http::AppState;

/// The settle window, in cadences of the primary this round is against:
/// how long after its OWN announcement a standby waits before it reads the
/// claims back (spec §7.1 step 3). Two, so that a member that saw the
/// silence a whole cadence later than this one still has its claim on the
/// relays by the time they are read. A first guess, like the trigger (spec
/// §11).
pub const SETTLE_CADENCES: u64 = 2;

/// How the last Takeover on a lease's workload settled here (spec §7.1
/// steps 3–5), kept with the lease.
///
/// Persisted, because a standby that LOST watches the winner as its primary
/// from then on, and nothing else on the record says who that is — the set
/// still lists the original primary at index 0 — and because a standby that
/// won and restarted before its workload started must still start it. On
/// disk and on the wire (`status` answers the winner), but not the same
/// struct: no `deny_unknown_fields`, for the reason `StandbySet` gives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeoverSettlement {
    /// The member that won, as 64 lowercase hex characters: the one that
    /// runs the workload now. This provider's own key when it won.
    pub winner: String,
}

/// One member's claim on the workload, as the settle weighs it: WHEN it
/// claimed and WHERE it stands in the set. Nothing else about a Takeover
/// event decides anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claim {
    /// The claimant's index in the `standby_set`.
    pub index: usize,
    /// The Takeover's `created_at`.
    pub created_at: u64,
}

/// Spec §7.1 step 3's rule: the earliest `created_at` wins, and a tie goes
/// to the lower index in the set. `None` only for no claims at all, which a
/// standby that announced never has — its own is one.
pub fn pick_winner(claims: &[Claim]) -> Option<Claim> {
    claims
        .iter()
        .copied()
        .min_by_key(|claim| (claim.created_at, claim.index))
}

/// The member `lease` treats as its primary: the winner of the last
/// Takeover settled here, if one was, else index 0 of the set. A standby
/// that lost watches the winner (spec §7.1 step 5); everything a standby
/// does — watch, announce, settle — is against this member.
///
/// `None` for a lease in no set, and for one whose set names nobody: the
/// record came off disk, where nothing re-checks it.
pub(super) fn primary_of(lease: &LeaseRecord) -> Option<&str> {
    let set = lease.standby_set.as_ref()?;
    match &lease.settled {
        Some(settled) => Some(settled.winner.as_str()),
        None => set.primary(),
    }
}

/// One announced reservation whose settle window has elapsed, read off the
/// lease table.
struct Due {
    id: u32,
    workload_id: String,
    /// Every member's hex key, in the set's order — the claimants, and the
    /// order a tie is broken in.
    members: Vec<String>,
    /// This provider's own index in the set.
    index: usize,
    /// The primary this round is against, hex: the only `primary` a claim
    /// may name to count.
    primary: String,
    announced_at: u64,
    /// Where the claims are: the relays the announcement went to.
    relays: Vec<String>,
}

/// `lease` as a settle that is due at `now`, if it is one: a reservation
/// that announced at least `SETTLE_CADENCES` cadences ago.
fn due(lease: &LeaseRecord, now: u64) -> Option<Due> {
    if lease.state != LeaseState::Reserved {
        return None;
    }
    let takeover = lease.takeover.as_ref()?;
    let window = SETTLE_CADENCES.saturating_mul(takeover.cadence_s);
    if now < takeover.announced_at.saturating_add(window) {
        return None;
    }
    let set = lease.standby_set.as_ref()?;
    Some(Due {
        id: lease.id,
        workload_id: lease.workload_id.clone(),
        members: set.members.clone(),
        index: set.index,
        primary: primary_of(lease)?.to_string(),
        announced_at: takeover.announced_at,
        relays: takeover.relays.clone(),
    })
}

/// Whether `lease` is a reservation this provider WON and has not started
/// yet (spec §7.1 step 4): the settle said so, and the workload is not
/// running — because the settle only just happened, because the start
/// failed on an earlier step, or because the provider restarted in between.
fn won_and_not_started(lease: &LeaseRecord, me: &str) -> bool {
    lease.state == LeaseState::Reserved
        && lease.takeover.is_none()
        && lease.settled.as_ref().is_some_and(|s| s.winner == me)
}

impl ProviderService {
    /// Steps 3–5 of spec §7.1 for every reservation whose settle window has
    /// elapsed, then step 4's start for every reservation this provider won
    /// and has not started — this step's winners, and any earlier one whose
    /// start failed. Run by `watch_primaries` after the watch, so a step is
    /// the whole of what a Warm Standby does at an instant.
    pub(super) async fn settle_takeovers(&self, now: u64) {
        let state = &self.state;
        let due: Vec<Due> = {
            let leases = state.leases.lock().await;
            leases.values().filter_map(|l| due(l, now)).collect()
        };
        for due in &due {
            self.settle_one(due).await;
        }

        let me = state.keys.public_key().to_hex();
        let won: Vec<u32> = {
            let leases = state.leases.lock().await;
            leases
                .values()
                .filter(|l| won_and_not_started(l, &me))
                .map(|l| l.id)
                .collect()
        };
        for id in won {
            start_won(state, id).await;
        }
    }

    /// Step 3 for one reservation: read the claims back and decide. A read
    /// that fails decides nothing and is tried again on the next step.
    async fn settle_one(&self, due: &Due) {
        let state = &self.state;
        let claimants: Vec<PublicKey> = due
            .members
            .iter()
            .filter_map(|hex| PublicKey::parse(hex).ok())
            .collect();
        let found = match state
            .directory
            .find_takeovers(&due.workload_id, &claimants, &due.relays)
            .await
        {
            Ok(found) => found,
            Err(e) => {
                warn!(
                    "lease {}: the Takeovers on {} could not be read ({:#}); settling on the \
                     next step",
                    due.id, due.workload_id, e
                );
                return;
            }
        };

        // This provider's own claim counts whether or not a relay hands it
        // back: it was made, and a relay that lost it must not lose the
        // race for it. Every other claim must be a Takeover on this
        // workload, from a MEMBER of the set — the port filters by author,
        // and what a relay actually answered is checked again here — and
        // against the primary this round is about.
        let mut claims = vec![Claim {
            index: due.index,
            created_at: due.announced_at,
        }];
        for event in &found {
            if event.kind.as_u16() != K_TAKEOVER
                || event.tags.identifier() != Some(due.workload_id.as_str())
            {
                continue;
            }
            let signer = event.pubkey.to_hex();
            let Some(index) = due.members.iter().position(|m| *m == signer) else {
                continue;
            };
            let Ok(content) = serde_json::from_str::<TakeoverContent>(&event.content) else {
                continue;
            };
            if content.primary != due.primary {
                continue;
            }
            claims.push(Claim {
                index,
                created_at: event.created_at.as_u64(),
            });
        }
        let Some(winner) = pick_winner(&claims) else {
            return;
        };
        let won = winner.index == due.index;
        let winner_hex = due.members[winner.index].clone();
        info!(
            "lease {}: the Takeover of {} settled among {} claim(s): index {} ({}) claimed \
             first, at {}; this provider {}",
            due.id,
            due.workload_id,
            claims.len(),
            winner.index,
            winner_hex,
            winner.created_at,
            if won { "won" } else { "lost" }
        );

        let mut leases = state.leases.lock().await;
        if let Some(lease) = leases.get_mut(&due.id) {
            // Still the announced reservation that was settled: a lease
            // that ended while the relays were being read has nothing to
            // settle, and one that announced again is another round.
            let same_round = lease.state == LeaseState::Reserved
                && lease
                    .takeover
                    .as_ref()
                    .is_some_and(|t| t.announced_at == due.announced_at);
            if same_round {
                // The round is over either way. A loser forgets its claim so
                // that it can claim again if the winner goes silent; a
                // winner's claim has done its job.
                lease.takeover = None;
                lease.settled = Some(TakeoverSettlement { winner: winner_hex });
                persist_leases(&leases, &state.config.lease_state_path);
            }
        }
    }
}

/// Step 4 for one reservation this provider won: start the workload from
/// the image exactly as a spawn would — the image resolved through the same
/// policy, its bytes fetched the same way, the container made from the same
/// spawn (`reserved_spawn`, kept since the reservation for precisely this)
/// — and make the lease Running. No state is carried over (ADR 0010).
///
/// Every failure leaves the lease Reserved and the backend clean, and the
/// next step tries again: the tenant paid for readiness, and a start that
/// failed once is not a reason to hold the capacity and run nothing for the
/// rest of the lease.
async fn start_won(state: &AppState, id: u32) {
    let (content, listing, ssh_port, ports) = {
        let leases = state.leases.lock().await;
        let Some(lease) = leases.get(&id) else {
            return;
        };
        let Some(content) = lease.reserved_spawn.clone() else {
            warn!(
                "lease {}: won the Takeover of {} but keeps no spawn to start it from; \
                 nothing can be started",
                id, lease.workload_id
            );
            return;
        };
        let Some(listing) = state
            .config
            .listing(&lease.listing, lease.listing_version)
            .cloned()
        else {
            warn!(
                "lease {}: won the Takeover of {} but {} v{} is no longer in the config; \
                 nothing can be started",
                id, lease.workload_id, lease.listing, lease.listing_version
            );
            return;
        };
        (content, listing, lease.ssh_port, lease.ports.clone())
    };

    // Step 5 of a spawn's validation, again: the reservation resolved the
    // image when it was sold, but what `fetch_and_start` needs — the
    // manifest, its layers and where they are — is not kept, and the policy
    // is applied at the instant the image is run, as a spawn's is.
    let image = match SpawnImage::parse(&content.image) {
        Ok(image) => image,
        Err(e) => {
            warn!(
                "lease {}: the reserved spawn's image is not one this provider can start: {}",
                id, e.message
            );
            return;
        }
    };
    let resolved = match image_policy::check(
        &state.fetcher,
        state.directory.clone(),
        &state.image_policy,
        &listing,
        &image,
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(e) => {
            warn!(
                "lease {}: the image of {} could not be resolved ({}); trying again on the \
                 next step",
                id, content.workload_id, e.message
            );
            return;
        }
    };

    info!(
        "lease {}: starting {} ({} v{}) here after winning its Takeover",
        id, content.workload_id, listing.name, listing.version
    );
    let launch = Launch {
        id,
        listing: &listing,
        content: &content,
        ssh_port,
        ports: &ports,
    };
    if let Err(e) = fetch_and_start(state, &image, &resolved, launch).await {
        warn!(
            "lease {}: {} could not be started ({}); trying again on the next step",
            id, content.workload_id, e.message
        );
        return;
    }

    let mut leases = state.leases.lock().await;
    match leases.get_mut(&id) {
        Some(lease) if lease.state == LeaseState::Reserved => {
            lease.state = LeaseState::Running;
            // What a Takeover would start has been started; a running lease
            // keeps nothing of the sort (`LeaseRecord::reserved_spawn`).
            lease.reserved_spawn = None;
            let expires_at = lease.expires_at;
            persist_leases(&leases, &state.config.lease_state_path);
            info!(
                "lease {}: {} is running here; a full-price .extend is due before {}",
                id, content.workload_id, expires_at
            );
        }
        _ => {
            // The reservation ended while the workload was being started —
            // its tenant terminated it, or the sweep reaped it — and
            // whoever ended it destroyed nothing, since nothing existed yet.
            // So this one is ours to destroy, exactly as a spawn's is.
            warn!(
                "lease {}: ended while {} was being started; destroying it",
                id, content.workload_id
            );
            drop(leases);
            if let Err(e) = state.backend.delete_container(id).await {
                warn!("lease {}: could not clean up its workload: {}", id, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(index: usize, created_at: u64) -> Claim {
        Claim { index, created_at }
    }

    #[test]
    fn the_earliest_claim_wins_whatever_its_index() {
        let claims = [claim(1, 1000), claim(2, 900), claim(3, 950)];
        assert_eq!(pick_winner(&claims), Some(claim(2, 900)));
    }

    #[test]
    fn a_tie_goes_to_the_lower_index() {
        let claims = [claim(2, 1000), claim(1, 1000), claim(3, 1000)];
        assert_eq!(pick_winner(&claims), Some(claim(1, 1000)));
        // …and the order the claims were read in decides nothing.
        let claims = [claim(3, 1000), claim(1, 1000)];
        assert_eq!(pick_winner(&claims), Some(claim(1, 1000)));
    }

    #[test]
    fn no_claims_is_no_winner() {
        assert_eq!(pick_winner(&[]), None);
    }
}
