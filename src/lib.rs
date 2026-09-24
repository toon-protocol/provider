//! `toon-provider` — sell leases on workloads over the TOON Network.
//!
//! A hard fork of Paygress with its payments (Cashu, Lightning, `ngx_l402`),
//! its transport (Nostr DMs), its discovery (offer and heartbeat events) and
//! its storage (Blossom) removed. See `NOTICE` for attribution and the
//! `TOON_Network` repository for the spec, ADRs and glossary.

pub mod anon_control;
pub mod capabilities;
pub mod clock;
pub mod compute;
pub mod directory;
pub mod docker;
pub mod hidden_service;
pub mod nostr;
pub mod outbound_guard;
pub mod outbound_proxy;
pub mod provider;
pub mod provider_http;
pub mod reputation;
pub mod topup;

pub use anon_control::AnonControlService;
pub use clock::{system_clock, Clock, SystemClock};
pub use compute::{
    ComputeBackend, ContainerConfig, ContainerStatus, EgressPolicy, NodeStatus, PortMapping,
};
pub use directory::{
    ConnectorDirectory, Directory, LivenessState, NullDirectory, PublishReport, RelayLiveness,
};
pub use docker::DockerBackend;
pub use hidden_service::{
    is_anyone_host, AddressPort, HiddenAddress, HiddenService, ANYONE_SUFFIX,
};
pub use outbound_guard::{is_publicly_routable, OutboundGuard};
pub use outbound_proxy::{guarded_http_client, http_client, is_private_url, OutboundProxy};
pub use provider::persisted_leases;
pub use provider::{
    load_config, render_routes, AnonConfig, AnonControl, BackendKind, LeaseEnd, LeaseRecord,
    LeaseState, Listing, PaidIntervals, ProviderConfig, ProviderService, SWEEP_INTERVAL_SECS,
    WATCHDOG_INTERVAL_SECS,
};
pub use provider_http::{operator_router, router, AppState};
