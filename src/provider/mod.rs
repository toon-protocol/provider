// The provider service: it holds the lease table, restores it after a restart,
// serves the HTTP app its TOON connector forwards to, sweeps expired leases,
// and watches the primary of every reservation it holds.
//
// Paygress ran five loops here — offer publication, heartbeat, a Nostr DM
// request listener, a standby watchdog and the expiry sweep. Four are left:
// the sweep in `cleanup`, the directory publication in `publish`, the
// watchdog in `watchdog` — rewritten for Liveness on the primary's Relay Set
// and ADR 0010's Takeover — and the HTTP app in `provider_http`. `self_stop`
// is the same rule read from the other end: what a PRIMARY does when its own
// relays stop taking its Liveness.
//
// The routes themselves are one module each: `spawn` starts a lease — or, on
// `.standby`, reserves capacity for one without starting it — `lifecycle`
// extends, reports and ends one, `availability` answers whether a spawn would
// run without starting anything, and `cleanup` is where every ending — Expiry
// or Termination — releases the slot and, when there is a workload, destroys
// it. `standby` is the rule the two spawn routes share: which role a
// `standby_set` and a route give this provider, and what the lease then
// remembers of the set; `settle` is what a Warm Standby does once it has
// announced a Takeover — settle the race, and start the workload if it won.
// `image_policy` is the rule both `spawn` and `availability` apply, so the
// two can never disagree; `fetcher` (over `oci` and the TOON store gateway)
// is how every image byte they read arrives, verified.

mod availability;
pub mod blob_cache;
mod cleanup;
mod config;
pub mod fetcher;
pub mod image_policy;
mod lifecycle;
pub mod oci;
pub mod oci_layout;
mod persistence;
mod publish;
pub mod routes;
mod self_stop;
mod settle;
mod spawn;
mod standby;
mod watchdog;

pub use availability::availability;
pub use blob_cache::BlobCache;
pub use cleanup::SWEEP_INTERVAL_SECS;
pub use config::{
    is_private_ip, load_config, settlement_rpc_verdict, AnonConfig, AnonControl, BackendKind,
    ImagePolicyConfig, Listing, ProviderConfig, RpcHostVerdict, MAX_PORTS_PER_WORKLOAD,
};
pub use fetcher::BlobFetcher;
pub use image_policy::{ImagePolicy, ResolvedImage};
pub use lifecycle::{evict, extend, standby_extend, status, terminate};
pub use persistence::persisted_leases;
pub use persistence::{LeaseEnd, LeaseRecord, LeaseState};
pub use routes::{render_routes, route_table, RouteRow};
pub use self_stop::{reached_a_majority, SELF_STOP_CADENCES};
pub use settle::{pick_winner, Claim, TakeoverSettlement};
pub use spawn::{spawn, standby_spawn, VOLUME_MOUNT_PATH};
pub use standby::StandbySet;
pub use watchdog::{silent_on_a_majority, TakeoverAnnouncement, WATCHDOG_INTERVAL_SECS};

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Result};
use tracing::{info, warn};

use crate::clock::{system_clock, Clock};
use crate::compute::{ComputeBackend, ContainerStatus};
use crate::directory::Directory;
use crate::docker::DockerBackend;
use crate::hidden_service::HiddenService;
use crate::provider_http::AppState;

use persistence::{load_leases, persist_leases};

pub struct ProviderService {
    state: AppState,
    /// The watchdog's count of silence: lease id -> the first instant its
    /// primary was read silent on a majority of its Relay Set, for the
    /// reservations whose primary is silent right now (`watchdog`).
    ///
    /// In memory ON PURPOSE, unlike the announcement it leads to. The trigger
    /// is silence CONTINUOUSLY for a cadence (spec §7.1 step 1), and a
    /// provider that was down cannot vouch for what happened while it was:
    /// a count carried across a restart would take over on the strength of
    /// one old reading and one new one, with anything in between unseen.
    /// A restart starts the count again, which costs at most one cadence.
    silence: tokio::sync::Mutex<HashMap<u32, u64>>,
    /// How many Liveness cadences in a row have failed to reach a strict
    /// majority of this provider's OWN Relay Set (`self_stop`). Five stop
    /// the workload of every primary lease it holds (spec §7.1).
    ///
    /// In memory for the same reason `silence` is: the rule counts
    /// CONTINUOUS cadences, and a provider that was down cannot vouch for
    /// the ones it did not publish. A restart starts the count again — and
    /// asks the Relay Set outright whether it was taken over while it was
    /// away (`stand_down_if_taken_over`), which is the question the count
    /// would have been standing in for.
    cadences_without_majority: std::sync::atomic::AtomicU32,
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
            silence: Default::default(),
            cadences_without_majority: Default::default(),
        })
    }

    /// …and a caller-supplied Directory, so what the provider publishes can
    /// be read back from a fake instead of paid for on a relay.
    pub fn with_backend_clock_and_directory(
        config: ProviderConfig,
        backend: Arc<dyn ComputeBackend>,
        clock: Arc<dyn Clock>,
        directory: Arc<dyn Directory>,
    ) -> Result<Self> {
        Ok(Self {
            state: AppState::new(config, backend, clock)?.with_directory(directory),
            silence: Default::default(),
            cadences_without_majority: Default::default(),
        })
    }

    /// …and a caller-supplied `HiddenService`, so a hidden provider's
    /// per-lease addresses can be created and destroyed against a fake
    /// that records them instead of an `anon` daemon. Before `app_state`:
    /// the router and the loops clone the state this sets.
    pub fn with_hidden_service(mut self, hidden_service: Arc<dyn HiddenService>) -> Self {
        self.state = self.state.with_hidden_service(hidden_service);
        self
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
            // A reservation is the same case for the opposite reason: a Warm
            // Standby holds capacity with NOTHING RUNNING (spec §6.7), so
            // the backend has never heard of it and would report it absent —
            // dropping every reservation the tenant is paying for. It must
            // survive a restart exactly as a running lease does.
            if !lease.state.is_live() || !lease.state.has_workload() {
                restored.insert(id, lease);
                continue;
            }
            match self.state.backend.get_container_status(id).await {
                Ok(ContainerStatus::Absent) => {
                    info!("workload {} no longer exists on the backend; dropping", id);
                    // The workload is gone, but what was built around it may
                    // not be: a `docker` lease's sidecar, volumes and network
                    // are made before its workload, and a provider that died
                    // between the two left them running. Delete is
                    // idempotent, so asking is free when there is nothing.
                    if let Err(e) = self.state.backend.delete_container(id).await {
                        warn!("could not clear what workload {} left behind: {}", id, e);
                    }
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
            "starting TOON provider: {} ({}, {} listing version(s){})",
            self.state.config.provider_name,
            self.state.config.ilp_address,
            self.state.config.listings.len(),
            if self.state.config.hidden {
                ", hidden"
            } else {
                ""
            }
        );
        self.refuse_unverified_settlement_rpc()?;
        // Beside it, and for the same reason: a Hidden Provider whose
        // daemon will not let it create addresses would publish
        // `hidden: true`, sell a lease, and only then find out it has no
        // address to give the tenant who already paid (M4-3, #40).
        crate::anon_control::refuse_unreachable_control(&self.state.config).await?;

        self.restore_leases().await;
        // Before anything is served or published: a primary whose Standby
        // Set moved on while this process was down must not carry on serving
        // a workload another provider is now running (spec §7.1).
        self.stand_down_if_taken_over().await;

        let bind_addr = self.state.config.http_bind_addr.clone();
        let operator_bind_addr = self.state.config.operator_bind_addr.clone();

        tokio::select! {
            result = crate::provider_http::serve(self.app_state(), &bind_addr) => {
                tracing::error!("HTTP app exited: {:?}", result);
                result
            }
            // A second, unrelated listener (`provider_http::operator_router`,
            // never `router`) for the loopback-only operator surface: a
            // process reachable only from this host, carrying no signature
            // and no payment, that stops a lease and publishes its Eviction
            // Notice. `ProviderConfig::validate` refuses `operator_bind_addr`
            // to be anything but loopback.
            result = crate::provider_http::serve_operator(self.app_state(), &operator_bind_addr) => {
                tracing::error!("operator endpoint exited: {:?}", result);
                result
            }
            result = self.expiry_sweep_loop() => {
                tracing::error!("expiry sweep exited: {:?}", result);
                result
            }
            // Beside the sweep, in the same shape: a reservation that nobody
            // watches for is capacity held for nothing (spec §7.1).
            result = self.watchdog_loop() => {
                tracing::error!("standby watchdog exited: {:?}", result);
                result
            }
            // After the restore above, so the first Liveness counts the
            // leases that survived the restart rather than announcing an
            // empty provider. It never returns: nothing about being
            // advertised is worth stranding a paid workload for.
            never = self.directory_loop() => never
        }
    }

    /// The half of the settlement-RPC gate that only a RUNNING provider can
    /// apply (spec §10, ADR 0008). Config load accepts an RPC hostname that
    /// does not resolve — with a warning, so that `routes` works on a host
    /// outside the sandbox's compose network — but a provider about to
    /// publish `hidden: true` must be able to show its RPC is self-hosted,
    /// and a name that does not resolve where the provider runs shows
    /// nothing. Nothing is checked twice for a provider that is not hidden.
    fn refuse_unverified_settlement_rpc(&self) -> Result<()> {
        let config = &self.state.config;
        let Some(rpc) = config
            .anon
            .settlement_rpc_url
            .as_deref()
            .filter(|_| config.hidden)
        else {
            return Ok(());
        };
        match config::settlement_rpc_verdict(rpc)? {
            config::RpcHostVerdict::Private => Ok(()),
            config::RpcHostVerdict::Unresolved(name) => bail!(
                "anon.settlement_rpc_url names {:?}, which does not resolve here, so this \
                 provider cannot show its settlement RPC is self-hosted and will not publish \
                 hidden = true. Name it by a loopback or private address, or by a name this \
                 host resolves (spec §10, ADR 0008)",
                name
            ),
        }
    }
}
