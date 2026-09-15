// The provider service: it holds the lease table, restores it after a restart,
// serves the HTTP app its TOON connector forwards to, and sweeps expired
// leases.
//
// Paygress ran five loops here — offer publication, heartbeat, a Nostr DM
// request listener, a standby watchdog and the expiry sweep. Two are left: the
// sweep in `cleanup`, and the HTTP app in `provider_http`. Directory
// publication and the lease routes land in later tickets.

mod cleanup;
mod config;
mod persistence;
mod standby;

pub use config::{load_config, BackendKind, ProviderConfig};
pub use persistence::LeaseRecord;
pub use standby::StandbySlot;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::compute::{ComputeBackend, ContainerStatus};
use crate::docker::DockerBackend;
use crate::provider_http::AppState;

use persistence::{load_leases, persist_leases};

/// Seconds since the Unix epoch.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct ProviderService {
    config: Arc<ProviderConfig>,
    backend: Arc<dyn ComputeBackend>,
    leases: Arc<Mutex<HashMap<u32, LeaseRecord>>>,
}

impl ProviderService {
    pub fn new(config: ProviderConfig) -> Result<Self> {
        let backend: Arc<dyn ComputeBackend> = match config.backend {
            BackendKind::Docker => Arc::new(DockerBackend::new()),
        };
        Ok(Self::with_backend(config, backend))
    }

    /// Builds the service over a caller-supplied backend, so the lease
    /// lifecycle can be driven against a fake without Docker.
    pub fn with_backend(config: ProviderConfig, backend: Arc<dyn ComputeBackend>) -> Self {
        Self {
            config: Arc::new(config),
            backend,
            leases: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Arc-clones of this service's own state, so the HTTP app and the expiry
    /// sweep see the same lease table.
    pub fn app_state(&self) -> AppState {
        AppState {
            config: self.config.clone(),
            backend: self.backend.clone(),
            leases: self.leases.clone(),
        }
    }

    /// Reload leases from disk and reconcile them against the backend.
    ///
    /// The backend is the authority on what exists: a workload deleted while
    /// the provider was down would otherwise be tracked forever and
    /// re-announced as capacity that isn't there.
    pub async fn restore_leases(&self) {
        let persisted = load_leases(&self.config.lease_state_path);
        if persisted.is_empty() {
            return;
        }

        let now = now_secs();
        let mut restored = HashMap::new();
        let mut dropped = 0usize;
        for (id, lease) in persisted {
            match self.backend.get_container_status(id).await {
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

        let expired = restored.values().filter(|l| l.expires_at <= now).count();
        info!(
            "restored {} lease(s) from {} ({} dropped as missing, {} already expired and due \
             for the next sweep)",
            restored.len(),
            self.config.lease_state_path,
            dropped,
            expired,
        );

        let mut lock = self.leases.lock().await;
        *lock = restored;
        // Write back now so dropped entries don't linger until the next sweep.
        persist_leases(&lock, &self.config.lease_state_path);
    }

    /// Run the provider until one of its loops exits.
    pub async fn run(&self) -> Result<()> {
        info!("starting TOON provider: {}", self.config.provider_name);

        self.restore_leases().await;

        let state = self.app_state();
        let bind_addr = self.config.http_bind_addr.clone();

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
