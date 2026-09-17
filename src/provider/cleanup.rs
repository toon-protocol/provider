// Ending a lease: the expiry sweep, and the one path every ending goes
// through.
//
// THE one path: `end_lease` is the door for all three endings — the sweep's
// Expiry, a tenant's Termination and an operator's Eviction — and
// `destroy_workload` below is the single place a lease's workload and its
// `.anyone` address are torn down. The sweep used to mark its leases ended
// inline, beside that door rather than through it, which was two copies of
// the same rule free to drift on what an ending means.
//
// There is no grace period. A lease whose `expires_at` has passed bought no
// further Lease Interval, and an unpaid workload must not keep running
// (ADR 0003). A Termination ends a lease the same way, just sooner.
//
// A RESERVATION ends by the same paths and destroys nothing: a Warm Standby
// holds capacity with no workload on it (spec §6.7), so ending one releases
// the slot and asks the compute backend for nothing at all. Everything below
// turns on `LeaseState::has_workload`, never on the role.
//
// An ended lease is NOT forgotten straight away: its record stays in the
// table for `ended_retention_s` so `status` can tell its tenant HOW it ended
// rather than that its id is unknown. It stops counting against capacity and
// stops holding its workload id the moment it ends, though — retention is
// bookkeeping, and never a hold on capacity the way a Warm Standby's
// Reservation is.

use anyhow::Result;
use tracing::{error, info, warn};

use super::lease_address;
use super::persistence::{persist_leases, LeaseEnd, LeaseState};
use super::ProviderService;
use crate::compute::ContainerStatus;
use crate::provider_http::AppState;

/// At most 30 seconds may pass between a lease expiring and its workload being
/// destroyed.
pub const SWEEP_INTERVAL_SECS: u64 = 30;

impl ProviderService {
    pub(super) async fn expiry_sweep_loop(&self) -> Result<()> {
        let interval = tokio::time::Duration::from_secs(SWEEP_INTERVAL_SECS);

        loop {
            tokio::time::sleep(interval).await;
            self.sweep_expired_leases(self.state.clock.now()).await;
        }
    }

    /// End every lease at or past its expiry, destroy whatever an earlier
    /// sweep failed to destroy, and forget the ended leases whose retention
    /// has run out. Public so a test can drive the sweep on a chosen instant
    /// rather than waiting out the interval.
    pub async fn sweep_expired_leases(&self, now: u64) {
        let state = &self.state;

        // The retries and the forgetting FIRST: whatever an earlier ending
        // could not destroy — a container that would not stop, an address
        // the daemon would not drop — and the ended records whose retention
        // has run out. Before the endings below, so that a lease this sweep
        // ends is tried once here and retried by the NEXT sweep, rather than
        // twice in a row by this one.
        let pending: Vec<u32> = {
            let mut leases = state.leases.lock().await;
            let retention = state.config.ended_retention_s;
            leases.retain(|id, lease| {
                if lease.state.is_live() {
                    return true;
                }
                // Never forget a lease whose workload may still be running: the
                // record is the only thing that will make us try again.
                let keep =
                    !lease.destroyed || lease.ended_at.unwrap_or(0).saturating_add(retention) > now;
                if !keep {
                    info!("lease {} ended over {} s ago; forgetting it", id, retention);
                }
                keep
            });

            persist_leases(&leases, &state.config.lease_state_path);

            leases
                .values()
                .filter(|l| !l.state.is_live() && !l.destroyed)
                .map(|l| l.id)
                .collect()
        };

        for id in pending {
            destroy_workload(state, id).await;
        }

        // Then the endings themselves. WHICH leases are over is decided
        // under the lock; ending them is not, so a sweep never holds the
        // table against the HTTP handlers while a daemon takes its time.
        let expired: Vec<u32> = {
            let leases = state.leases.lock().await;
            leases
                .values()
                .filter(|lease| lease.state.is_live() && lease.expires_at <= now)
                .map(|lease| lease.id)
                .collect()
        };
        // Through the SAME door a Termination and an Eviction go through, so
        // that what an ending does is written once: the state, the instant,
        // the workload and the address (spec §6.6, §6.7). `end_lease`
        // re-checks liveness under the lock, so a lease a tenant terminated
        // between the pass above and here is not ended twice.
        for id in expired {
            end_lease(state, id, LeaseEnd::Expiry, now).await;
        }
    }
}

/// End one live lease, and destroy its workload now.
///
/// `false` when the lease was already ended — the caller refuses rather than
/// ending a lease twice. Racing a sweep is the same case: whichever marks it
/// first wins, and the other sees a lease that is no longer live. The two may
/// still both reach `destroy_workload` for that id, so `ComputeBackend` must
/// tolerate being asked to stop and delete a workload twice; the second pass
/// finds it absent and records it destroyed.
pub(crate) async fn end_lease(state: &AppState, id: u32, end: LeaseEnd, now: u64) -> bool {
    let has_workload = {
        let mut leases = state.leases.lock().await;
        let Some(lease) = leases.get_mut(&id) else {
            return false;
        };
        if !lease.state.is_live() {
            return false;
        }
        let has_workload = lease.state.has_workload();
        if has_workload {
            info!("lease {} ended by {:?}; destroying its workload", id, end);
        } else {
            info!("reservation {} ended by {:?}; releasing it", id, end);
        }
        lease.state = LeaseState::Ended(end);
        lease.ended_at = Some(now);
        lease.destroyed = !has_workload;
        persist_leases(&leases, &state.config.lease_state_path);
        has_workload
    };
    // A reservation runs nothing and was never given an address, so ending
    // one asks neither the backend nor the daemon for anything: the capacity
    // it held is released by the record's own ending (spec §6.6, §6.7).
    if has_workload {
        destroy_workload(state, id).await;
    }
    true
}

/// Tear down everything a lease held: stop and delete its workload, and
/// destroy the `.anyone` address it was reachable at, if it had one.
///
/// THE single teardown path — `end_lease` above is its only caller besides
/// the sweep's retry — so a lease's ending means the same thing however it
/// ended. The success is recorded in the lease table, and a lease is not
/// `destroyed` until BOTH are gone: a failure of either is retried by every
/// later sweep, because an ended lease that left a container running would
/// run for free forever, and one that left an address standing would keep
/// answering for a workload that no longer exists.
async fn destroy_workload(state: &AppState, id: u32) {
    let container_gone = destroy_container(state, id).await;
    // Asked for even when the container would not go: the two are
    // independent, and whichever succeeded is not asked for again.
    let address_gone = lease_address::destroy_of_lease(state, id).await;
    if container_gone && address_gone {
        let mut leases = state.leases.lock().await;
        if let Some(lease) = leases.get_mut(&id) {
            lease.destroyed = true;
            persist_leases(&leases, &state.config.lease_state_path);
        }
    }
}

/// Stop the workload and delete it; `true` once the backend has no trace of
/// it left.
async fn destroy_container(state: &AppState, id: u32) -> bool {
    if let Err(e) = state.backend.stop_container(id).await {
        warn!("stop failed for {} ({}), deleting anyway", id, e);
    }
    match state.backend.delete_container(id).await {
        Ok(_) => {
            info!("workload {} destroyed", id);
            true
        }
        Err(e) => {
            // A workload that is already absent counts as destroyed: the
            // delete failed because there was nothing left to delete.
            match state.backend.get_container_status(id).await {
                Ok(ContainerStatus::Absent) => {
                    info!("workload {} was already gone ({})", id, e);
                    true
                }
                _ => {
                    error!(
                        "failed to destroy workload {}: {}; retrying on the next sweep",
                        id, e
                    );
                    false
                }
            }
        }
    }
}
