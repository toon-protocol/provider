// The provider service: it holds the lease table, restores it after a restart,
// serves the HTTP app its TOON connector forwards to, and sweeps expired
// leases.
//
// Paygress ran five loops here — offer publication, heartbeat, a Nostr DM
// request listener, a standby watchdog and the expiry sweep. Two are left: the
// sweep in `cleanup`, and the HTTP app in `provider_http`. Directory
// publication lands in a later ticket.
//
// The routes themselves are one module each: `spawn` starts a lease,
// `lifecycle` extends, reports and ends one, and `cleanup` is where every
// ending — Expiry or Termination — actually destroys the workload.

mod cleanup;
mod config;
mod lifecycle;
mod persistence;
pub mod routes;
mod spawn;
mod standby;

pub use cleanup::SWEEP_INTERVAL_SECS;
pub use config::{load_config, BackendKind, Listing, ProviderConfig, MAX_PORTS_PER_WORKLOAD};
pub use lifecycle::{extend, status, terminate};
pub use persistence::{LeaseEnd, LeaseRecord, LeaseState};
pub use routes::{render_routes, route_table, RouteRow};
pub use spawn::{spawn, VOLUME_MOUNT_PATH};
pub use standby::StandbySlot;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tracing::{info, warn};

use crate::clock::{system_clock, Clock};
use crate::compute::{ComputeBackend, ContainerStatus};
use crate::docker::DockerBackend;
use crate::provider_http::AppState;

use persistence::{load_leases, persist_leases};

pub struct ProviderService {
    state: AppState,
}

impl ProviderService {
    pub fn new(config: ProviderConfig) -> Result<Self> {
        let backend: Arc<dyn ComputeBackend> = match config.backend {
            BackendKind::Docker => Arc::new(DockerBackend::new()),
        };
        Self::with_backend(config, backend)
    }

    /// Builds the service over a caller-supplied backend, so the lease
    /// lifecycle can be driven against a fake without Docker.
    pub fn with_backend(config: ProviderConfig, backend: Arc<dyn ComputeBackend>) -> Result<Self> {
        Self::with_backend_and_clock(config, backend, system_clock())
    }

    /// …and a caller-supplied clock, so expiry is decided on chosen instants.
    pub fn with_backend_and_clock(
        config: ProviderConfig,
        backend: Arc<dyn ComputeBackend>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        Ok(Self {
            state: AppState::new(config, backend, clock)?,
        })
    }

    /// Arc-clones of this service's own state, so the HTTP app and the expiry
    /// sweep see the same lease table.
    pub fn app_state(&self) -> AppState {
        self.state.clone()
    }

    /// Reload leases from disk and reconcile them against the backend.
    ///
    /// The backend is the authority on what exists: a workload deleted while
    /// the provider was down would otherwise be tracked forever and
    /// re-announced as capacity that isn't there.
    pub async fn restore_leases(&self) {
        let persisted = load_leases(&self.state.config.lease_state_path);
        if persisted.is_empty() {
            return;
        }

        let now = self.state.clock.now();
        let mut restored = HashMap::new();
        let mut dropped = 0usize;
        for (id, lease) in persisted {
            // An ended lease is a record, not a workload: it is kept until
            // its retention runs out (`cleanup`), and asking the backend
            // about a container that was deleted on purpose would drop the
            // very thing `status` still has to report.
            if !lease.state.is_live() {
                restored.insert(id, lease);
                continue;
            }
            match self.state.backend.get_container_status(id).await {
                Ok(ContainerStatus::Absent) => {
                    info!("workload {} no longer exists on the backend; dropping", id);
                    dropped += 1;
                    continue;
                }
                Err(e) => {
                    // An unreachable backend must not be read as "the workload
                    // is gone". The expiry sweep deletes it at expiry anyway.
                    warn!(
                        "could not verify workload {} ({}); keeping it tracked",
                        id, e
                    );
                }
                Ok(_) => {}
            }
            restored.insert(id, lease);
        }

        let expired = restored
            .values()
            .filter(|l| l.state.is_live() && l.expires_at <= now)
            .count();
        info!(
            "restored {} lease(s) from {} ({} dropped as missing, {} already expired and due \
             for the next sweep)",
            restored.len(),
            self.state.config.lease_state_path,
            dropped,
            expired,
        );

        let mut lock = self.state.leases.lock().await;
        *lock = restored;
        // Write back now so dropped entries don't linger until the next sweep.
        persist_leases(&lock, &self.state.config.lease_state_path);
    }

    /// Run the provider until one of its loops exits.
    pub async fn run(&self) -> Result<()> {
        info!(
            "starting TOON provider: {} ({}, {} listing version(s))",
            self.state.config.provider_name,
            self.state.config.ilp_address,
            self.state.config.listings.len()
        );

        self.restore_leases().await;

        let state = self.app_state();
        let bind_addr = self.state.config.http_bind_addr.clone();

        tokio::select! {
            result = crate::provider_http::serve(state, &bind_addr) => {
                tracing::error!("HTTP app exited: {:?}", result);
                result
            }
            result = self.expiry_sweep_loop() => {
                tracing::error!("expiry sweep exited: {:?}", result);
                result
            }
        }
    }
}
