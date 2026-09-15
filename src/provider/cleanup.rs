// The expiry sweep: the only path that ends a lease once its time runs out, and
// the only one that frees a workload id for re-use.
//
// There is no grace period. A lease whose `expires_at` has passed bought no
// further Lease Interval, and an unpaid workload must not keep running.

use anyhow::Result;
use tracing::{error, info, warn};

use super::persistence::persist_leases;
use super::{now_secs, ProviderService};

/// At most 30 seconds may pass between a lease expiring and its workload being
/// destroyed.
pub const SWEEP_INTERVAL_SECS: u64 = 30;

impl ProviderService {
    pub(super) async fn expiry_sweep_loop(&self) -> Result<()> {
        let interval = tokio::time::Duration::from_secs(SWEEP_INTERVAL_SECS);

        loop {
            tokio::time::sleep(interval).await;
            self.sweep_expired_leases(now_secs()).await;
        }
    }

    /// End every lease at or past its expiry. Public so a test can drive the
    /// sweep on a chosen instant rather than waiting out the interval.
    pub async fn sweep_expired_leases(&self, now: u64) {
        let mut leases = self.leases.lock().await;
        let expired: Vec<u32> = leases
            .iter()
            .filter(|(_, l)| l.expires_at <= now)
            .map(|(id, _)| *id)
            .collect();

        for id in expired {
            info!("lease {} expired; destroying its workload", id);

            if leases.remove(&id).is_none() {
                continue;
            }

            // Delete unconditionally: the lease is already out of the table, so
            // a failed stop that skipped the delete would leak the container
            // and its id forever, with no retry.
            if let Err(e) = self.backend.stop_container(id).await {
                warn!("stop failed for {} ({}), deleting anyway", id, e);
            }
            match self.backend.delete_container(id).await {
                Ok(_) => info!("workload {} destroyed", id),
                Err(e) => error!("failed to destroy workload {}: {}", id, e),
            }

            // Persist per lease, not once per sweep: a crash midway through
            // would otherwise resurrect entries whose containers are gone.
            persist_leases(&leases, &self.config.lease_state_path);
        }
    }
}
