//! `toon-provider` — sell leases on workloads over the TOON Network.
//!
//! A hard fork of Paygress with its payments (Cashu, Lightning, `ngx_l402`),
//! its transport (Nostr DMs), its discovery (offer and heartbeat events) and
//! its storage (Blossom) removed. See `NOTICE` for attribution and the
//! `TOON_Network` repository for the spec, ADRs and glossary.

pub mod capabilities;
pub mod clock;
pub mod compute;
pub mod directory;
pub mod docker;
pub mod durable_workload;
pub mod nostr;
pub mod provider;
pub mod provider_http;
pub mod reputation;

pub use clock::{system_clock, Clock, SystemClock};
pub use compute::{ComputeBackend, ContainerConfig, ContainerStatus, NodeStatus, PortMapping};
pub use directory::{ConnectorDirectory, Directory, NullDirectory, PublishReport};
pub use docker::DockerBackend;
pub use provider::{
    load_config, render_routes, BackendKind, LeaseEnd, LeaseRecord, LeaseState, Listing,
    ProviderConfig, ProviderService,
};
pub use provider_http::{router, AppState};
