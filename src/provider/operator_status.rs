// `GET /operator/status`: what this provider is, whether it is listed, and
// what it is running — read by the operator of this box and by nobody else
// (ADR 0029).
//
// It is served on the loopback operator port beside `POST /operator/evict`,
// and reaching that port is the whole of the authorisation, as it is for an
// eviction. So nothing here is a secret a tenant or a relay could not already
// see, or one this box's own operator does not already hold — and even then
// the rule is stricter than that: the answer carries NO secret at all. Not a
// lease's Continuation Token, not its reserved spawn (whose `env` may hold the
// tenant's own secrets), not a hidden lease's `.anyone` KEY, not the
// provider's Nostr secret key. A status document gets pasted into issues and
// chat; it must be safe to paste.
//
// The document is SECTIONED, with a version, so that the CLI can add the
// sections only it can read (`publisher`, `earnings`, `funding`: #172) beside
// these three, and so a Workload Gateway can answer the sections it shares
// (`identity`, `earnings`, `funding`) in the same shape (ADR 0029).

use std::collections::BTreeMap;
use std::time::Duration;

use nostr_sdk::ToBech32;
use serde::{Deserialize, Serialize};

use super::persistence::{count_live, LeaseRecord, LeaseState, PaidIntervals};
use crate::directory::{RelayEntries, RelayOutcome};
use crate::nostr::wire::{PortAccess, Role};
use crate::provider_http::AppState;

/// The shape of the document below. Bumped on a change a reader must know
/// about — a field removed or its meaning changed — and never for a field or
/// a section added.
pub const OPERATOR_STATUS_VERSION: u32 = 1;

/// How long the connector's `GET <connector_url>/identity` may take before
/// the probe is reported as failed. Short: an operator is waiting on it, and
/// a connector that takes longer than this to describe itself has a problem
/// the report should name.
pub const CONNECTOR_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The whole document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorStatus {
    /// `OPERATOR_STATUS_VERSION`.
    pub version: u32,
    /// Which kind of process answered: `provider` here, and `gateway` from a
    /// Workload Gateway answering the sections it shares (ADR 0029).
    pub service: String,
    /// The instant the document describes, on the provider's clock.
    pub generated_at: u64,
    /// When the process answering started, on the same clock. The directory
    /// section's outcomes are all from since then (they are kept in memory
    /// only), so a reader can tell "not published yet, just restarted" from
    /// "not landing". Optional to a reader: a provider from before this
    /// field answers without it.
    #[serde(default)]
    pub started_at: Option<u64>,
    pub identity: IdentitySection,
    pub directory: DirectorySection,
    pub leases: LeasesSection,
}

/// Who this provider is, and whether the connector in front of it agrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySection {
    /// The provider's Nostr identity, bech32 — the public half only.
    pub npub: String,
    /// The same key in hex, the way every event and Lease Request carries it.
    pub pubkey: String,
    pub provider_name: String,
    pub ilp_address: String,
    /// Whether this is a Hidden Provider (spec §10).
    pub hidden: bool,
    /// The sealing key the Profile publishes, which every tenant pins and
    /// seals its spawn to (ADR 0011).
    pub connector_seal_key: String,
    /// What the connector itself says its key is, right now.
    pub connector_identity: ConnectorIdentityCheck,
}

/// The connector's live `GET <connector_url>/identity`, compared with the
/// key the Profile publishes. A failed probe is REPORTED, never fatal: the
/// rest of the document is still worth reading when the connector is down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorIdentityCheck {
    /// Whether the connector answered with a key at all.
    pub reachable: bool,
    /// Whether the probe went out through `anon.socks_proxy` (a Hidden
    /// Provider's connector is at an `.anyone` host, spec §10).
    pub via_proxy: bool,
    /// The key the connector reported, verbatim.
    pub live_seal_key: Option<String>,
    /// Whether it is byte-for-byte the published `connector_seal_key` — the
    /// comparison a tenant makes before it will spawn. `None` when there
    /// was nothing to compare, because the connector did not answer.
    pub matches: Option<bool>,
    /// Why the probe failed, when it did.
    pub error: Option<String>,
}

/// Whether this provider is in the directory, relay by relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectorySection {
    /// Whether a directory publisher is configured (`publish_url`). Without
    /// one nothing is published, and every relay below says so by having
    /// no outcome at all.
    pub publishing: bool,
    pub liveness_cadence_s: u64,
    /// The latest `expiration` of a Liveness any relay of the Relay Set has
    /// taken since this process started: when this provider reads as down
    /// everywhere if nothing more lands. `None` before any has landed.
    pub liveness_expires_at: Option<u64>,
    /// Relay URL -> what it last said to the Profile, each Listing and the
    /// Liveness. Every relay of the Relay Set is here, with `null` outcomes
    /// until something is published to it.
    pub relays: BTreeMap<String, RelayDirectory>,
}

/// One relay's outcomes. `null` is "not published to this relay since the
/// provider started", which is different from a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDirectory {
    pub profile: Option<RelayOutcome>,
    /// Every listing on sale, by name, plus any other this relay was sent.
    pub listings: BTreeMap<String, Option<RelayOutcome>>,
    pub liveness: Option<RelayOutcome>,
}

/// What this provider is running, and what each lease has been billed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasesSection {
    /// Listing name -> capacity in use, across every version of it.
    pub listings: BTreeMap<String, ListingUse>,
    /// Every lease on the table — ended ones included, until their
    /// retention runs out — by backend id.
    pub leases: Vec<LeaseSummary>,
}

/// One tier's capacity, the same numbers the Liveness announces and a spawn
/// refuses on (`count_live`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingUse {
    /// The version on sale.
    pub version: u32,
    pub capacity: u32,
    pub live: u32,
    pub available: u32,
    /// µUSDC per Lease Interval of the version on sale.
    pub price: u64,
    pub standby_price: Option<u64>,
    pub lease_interval_s: u64,
}

/// One lease, as the operator sees it. Deliberately NOT the lease record:
/// every field is chosen, so a secret added to the record later does not
/// arrive here by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseSummary {
    /// The backend workload id this provider keys its table on.
    pub id: u32,
    /// The tenant's own id for the workload.
    pub workload_id: String,
    pub listing: String,
    pub listing_version: u32,
    pub role: Role,
    pub state: LeaseState,
    pub created_at: u64,
    pub expires_at: u64,
    pub ended_at: Option<u64>,
    pub ssh_port: u16,
    pub ports: Vec<PortAccess>,
    /// The lease's own `.anyone` HOST on a Hidden Provider. Never its key.
    pub hidden_address: Option<String>,
    /// The Lease Intervals paid for, at each of the listing's two prices.
    pub paid_intervals: PaidIntervals,
    /// µUSDC: `price × running + standby_price × standby`, at the lease's own
    /// listing version (ADR 0009). `None` when that version is no longer in
    /// the config, so its price is not known here.
    pub billed: Option<u64>,
    /// True for a lease recorded before the count existed: `paid_intervals`
    /// and so `billed` are then derived from its expiry, not counted.
    pub billed_estimated: bool,
}

/// The document, as of now. Probes the connector first, without holding the
/// lease table, so a slow connector delays only this answer.
pub async fn operator_status(state: &AppState) -> OperatorStatus {
    let identity = identity(state).await;
    let directory = directory(state);
    let leases = leases(state).await;
    OperatorStatus {
        version: OPERATOR_STATUS_VERSION,
        service: "provider".to_string(),
        generated_at: state.clock.now(),
        started_at: Some(state.started_at),
        identity,
        directory,
        leases,
    }
}

async fn identity(state: &AppState) -> IdentitySection {
    let config = &state.config;
    let public_key = state.keys.public_key();
    IdentitySection {
        npub: public_key
            .to_bech32()
            .unwrap_or_else(|_| public_key.to_hex()),
        pubkey: public_key.to_hex(),
        provider_name: config.provider_name.clone(),
        ilp_address: config.ilp_address.clone(),
        hidden: config.hidden,
        connector_seal_key: config.connector_seal_key.clone(),
        connector_identity: probe_connector(state).await,
    }
}

/// What the connector's self-description answers (connector ADR 0018): the
/// only field read is its sealing key.
#[derive(Deserialize)]
struct ConnectorIdentity {
    #[serde(rename = "publicKey")]
    public_key: String,
}

/// `GET <connector_url>/identity` — through `anon.socks_proxy` on a Hidden
/// Provider, since `AppState::connector_probe` is built over the same proxy
/// every other outbound request of this process rides (spec §10).
async fn probe_connector(state: &AppState) -> ConnectorIdentityCheck {
    let config = &state.config;
    let failed = |error: String| ConnectorIdentityCheck {
        reachable: false,
        via_proxy: config.hidden,
        live_seal_key: None,
        matches: None,
        error: Some(error),
    };
    if config.connector_url.is_empty() {
        return failed("connector_url is not set, so there is no connector to ask".to_string());
    }
    let url = format!("{}/identity", config.connector_url.trim_end_matches('/'));

    let response = match state.connector_probe.get(&url).send().await {
        Ok(response) => response,
        Err(e) => return failed(format!("GET {url} failed: {}", error_chain(&e))),
    };
    let status = response.status();
    if !status.is_success() {
        return failed(format!("GET {url} answered {status}"));
    }
    let identity: ConnectorIdentity = match response.json().await {
        Ok(identity) => identity,
        Err(e) => {
            return failed(format!(
                "GET {url} did not answer {{ \"publicKey\": … }}: {}",
                error_chain(&e)
            ))
        }
    };
    ConnectorIdentityCheck {
        reachable: true,
        via_proxy: config.hidden,
        matches: Some(identity.public_key == config.connector_seal_key),
        live_seal_key: Some(identity.public_key),
        error: None,
    }
}

/// An error and its causes on one line: reqwest's own `Display` stops at
/// "error sending request", which says nothing an operator can act on.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

fn directory(state: &AppState) -> DirectorySection {
    let config = &state.config;
    let mut recorded = state.publications.snapshot();

    // Every relay of the Relay Set, whether or not anything reached it yet,
    // then any other relay a report named.
    let mut relays: BTreeMap<String, RelayEntries> = config
        .relay_set
        .iter()
        .map(|relay| (relay.clone(), recorded.remove(relay).unwrap_or_default()))
        .collect();
    relays.extend(recorded);

    let liveness_expires_at = relays
        .values()
        .filter_map(|r| r.liveness.as_ref()?.expires_at)
        .max();

    let on_sale: Vec<String> = config
        .listings_on_sale()
        .iter()
        .map(|l| l.name.clone())
        .collect();
    let relays = relays
        .into_iter()
        .map(|(url, entries)| {
            let mut listings: BTreeMap<String, Option<RelayOutcome>> =
                on_sale.iter().map(|name| (name.clone(), None)).collect();
            listings.extend(
                entries
                    .listings
                    .into_iter()
                    .map(|(name, outcome)| (name, Some(outcome))),
            );
            (
                url,
                RelayDirectory {
                    profile: entries.profile,
                    listings,
                    liveness: entries.liveness,
                },
            )
        })
        .collect();

    DirectorySection {
        publishing: config.publish_url.is_some(),
        liveness_cadence_s: config.liveness_cadence_s,
        liveness_expires_at,
        relays,
    }
}

async fn leases(state: &AppState) -> LeasesSection {
    let config = &state.config;
    let table = state.leases.lock().await;
    let available = state.available_in(&table);

    let listings = config
        .listings_on_sale()
        .into_iter()
        .map(|listing| {
            let live = u32::try_from(count_live(&table, &listing.name)).unwrap_or(u32::MAX);
            (
                listing.name.clone(),
                ListingUse {
                    version: listing.version,
                    capacity: config.capacity_of(&listing.name),
                    live,
                    available: available.get(&listing.name).copied().unwrap_or(0),
                    price: listing.price,
                    standby_price: listing.standby_price,
                    lease_interval_s: listing.lease_interval_s,
                },
            )
        })
        .collect();

    let mut leases: Vec<LeaseSummary> = table
        .values()
        .map(|lease| summarise(state, lease))
        .collect();
    leases.sort_by_key(|l| l.id);

    LeasesSection { listings, leases }
}

fn summarise(state: &AppState, lease: &LeaseRecord) -> LeaseSummary {
    let listing = state.config.listing(&lease.listing, lease.listing_version);
    // Without the listing there is no interval to estimate in either; one
    // hour is only a divisor that keeps an estimate finite, and `billed` is
    // `None` then anyway.
    let interval = listing.map(|l| l.lease_interval_s).unwrap_or(3600);
    let (paid, estimated) = lease.paid_intervals_or_estimate(interval);
    let billed = listing.map(|l| {
        l.price
            .saturating_mul(u64::from(paid.running))
            .saturating_add(
                l.standby_price
                    .unwrap_or(0)
                    .saturating_mul(u64::from(paid.standby)),
            )
    });
    LeaseSummary {
        id: lease.id,
        workload_id: lease.workload_id.clone(),
        listing: lease.listing.clone(),
        listing_version: lease.listing_version,
        role: lease.role,
        state: lease.state,
        created_at: lease.created_at,
        expires_at: lease.expires_at,
        ended_at: lease.ended_at,
        ssh_port: lease.ssh_port,
        ports: lease.ports.clone(),
        hidden_address: lease.hidden_address.as_ref().map(|a| a.host.clone()),
        paid_intervals: paid,
        billed,
        billed_estimated: estimated,
    }
}
