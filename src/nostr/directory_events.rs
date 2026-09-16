// The Provider Directory events: Provider Profile, Listing and Liveness
// (spec §4). One builder per event, each signed with the provider's Nostr key.
//
// Paygress published one offer event per provider with every tier inside its
// JSON content, plus a heartbeat. Both are gone. A profile and its listings
// are separate events (ADR 0002) because every relay write is paid — changing
// one tier's price should cost one write, not a rewrite of the whole offer —
// and because NIP-01 filters match single-letter TAGS, never fields inside
// content. So everything a relay should search on is a tag here, and only
// numbers stay in content.
//
// Liveness replaces the heartbeat: replaceable, paid, and carrying a NIP-40
// expiration of five cadences (ADR 0007), so relay storage stays at one event
// per provider and a provider that dies goes quiet on its own.

use std::collections::BTreeMap;

use anyhow::Result;
use nostr_sdk::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
use serde::{Deserialize, Serialize};

use super::kinds::{K_EVICTION, K_LISTING, K_LIVENESS, K_PROFILE, K_TAKEOVER, TOON_LABEL};
use super::wire::{EvictionReason, Resources};
use crate::provider::{Listing, ProviderConfig};

/// One settlement leg a provider's connector accepts: which chain, which
/// token on it, and the token's scale. Published in the Profile so a tenant
/// knows what it can pay with before it sends anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settlement {
    /// `solana` | `evm:<chainId>`.
    pub chain: String,
    /// Mint address (Solana) or contract address (EVM).
    pub token: String,
    /// USDC is 6 everywhere in v1; carried anyway so a reader never guesses.
    pub decimals: u8,
}

/// The content of a Provider Profile (`K_PROFILE`, replaceable), spec §4.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileContent {
    pub ilp_address: String,
    /// The connector's self-description URL. A LOCATION HINT ONLY: the key
    /// below is what a tenant seals to, and it refuses if the URL reports a
    /// different one (ADR 0011).
    pub connector_url: String,
    /// The connector's sealing public key, hex.
    pub connector_seal_key: String,
    /// The Relay Set: every relay this provider publishes to.
    pub relays: Vec<String>,
    pub settlement: Vec<Settlement>,
    /// `shared-kernel` | `dedicated-host`.
    pub isolation: String,
    /// Hidden Provider declaration (spec §10). Always false in Milestone 1.
    pub hidden: bool,
    /// The host tenants connect workloads to. MUST be absent when `hidden`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub liveness_cadence_s: u64,
}

/// The content of a Listing (`K_LISTING`, addressable), spec §4.2. The `d`
/// tag carries the listing name, so the name is not repeated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListingContent {
    pub version: u32,
    pub resources: Resources,
    /// `amd64` | `arm64`.
    pub arch: String,
    pub lease_interval_s: u64,
    /// µUSDC per Lease Interval.
    pub price: u64,
    /// µUSDC per Lease Interval for a Warm Standby. Absent means the listing
    /// sells none — never `0`, which would read as "standbys are free".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standby_price: Option<u64>,
    pub capabilities: Vec<String>,
}

/// The content of a Liveness event (`K_LIVENESS`, replaceable), spec §4.3:
/// how many leases of each listing could start right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivenessContent {
    /// Listing name -> capacity minus live leases. A `BTreeMap` so the JSON
    /// is ordered and one provider's two publications differ only where the
    /// numbers do.
    pub available: BTreeMap<String, u32>,
}

/// How long a Liveness event stays valid, as a multiple of the cadence
/// (ADR 0007). Five, so four publications may be lost before a provider is
/// read as down.
pub const LIVENESS_EXPIRY_CADENCES: u64 = 5;

/// The `["L", "toon.network"]` every directory event carries, so a directory
/// query can select them without knowing the kind numbers.
fn label_tag() -> Result<Tag> {
    Ok(Tag::parse(["L", TOON_LABEL])?)
}

/// A namespaced label value: `["l", "<name>:<value>", "toon.network"]`. The
/// third cell is the namespace the `L` tag declared, which is what makes an
/// `#l` filter unambiguous across protocols sharing a relay.
fn label_value_tag(name: &str, value: &str) -> Result<Tag> {
    Ok(Tag::parse(["l", &format!("{name}:{value}"), TOON_LABEL])?)
}

/// The Provider Profile. Replaceable: one per provider, and republishing it
/// is how a provider changes its connector, its Relay Set or its cadence.
pub fn profile_event(config: &ProviderConfig, keys: &Keys, now: u64) -> Result<Event> {
    let content = profile_content(config);
    Ok(
        EventBuilder::new(Kind::Custom(K_PROFILE), serde_json::to_string(&content)?)
            .tags([label_tag()?])
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(keys)?,
    )
}

/// The Profile content this config describes. Public so a test — and the
/// availability answer — can read it without building and signing an event.
pub fn profile_content(config: &ProviderConfig) -> ProfileContent {
    ProfileContent {
        ilp_address: config.ilp_address.clone(),
        connector_url: config.connector_url.clone(),
        connector_seal_key: config.connector_seal_key.clone(),
        relays: config.relay_set.clone(),
        settlement: config.settlement.clone(),
        isolation: config.isolation.clone(),
        // Milestone 1 has no Hidden Provider (spec §10 is a follow-up), so
        // this is a constant rather than a config key nobody may set to true.
        hidden: false,
        host: Some(config.public_ip.clone()),
        liveness_cadence_s: config.liveness_cadence_s,
    }
}

/// The `a` tag pointing a Listing at its Provider Profile (ADR 0002). A
/// profile is replaceable, not addressable, so the coordinate's identifier is
/// empty and the tag ends in a colon.
pub fn profile_coordinate(provider: &nostr_sdk::PublicKey) -> String {
    format!("{}:{}:", K_PROFILE, provider.to_hex())
}

/// One Listing. Addressable with `d` = the listing name, which is stable
/// across versions — a new version REPLACES the previous event rather than
/// accumulating (ADR 0009), while the old version's routes keep serving.
pub fn listing_event(
    listing: &Listing,
    config: &ProviderConfig,
    keys: &Keys,
    now: u64,
) -> Result<Event> {
    let content = listing_content(listing);

    let mut tags = vec![
        Tag::identifier(listing.name.clone()),
        Tag::parse(["a", &profile_coordinate(&keys.public_key())])?,
        label_tag()?,
        label_value_tag("isolation", &config.isolation)?,
        label_value_tag("arch", &listing.arch)?,
    ];
    if let Some(gpu) = &listing.resources.gpu {
        tags.push(label_value_tag("gpu", gpu)?);
    }
    for capability in &listing.capabilities {
        tags.push(Tag::parse(["t", capability])?);
    }
    if let Some(geohash) = &config.geohash {
        tags.push(Tag::parse(["g", geohash])?);
    }

    Ok(
        EventBuilder::new(Kind::Custom(K_LISTING), serde_json::to_string(&content)?)
            .tags(tags)
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(keys)?,
    )
}

/// The Listing content for one configured tier.
pub fn listing_content(listing: &Listing) -> ListingContent {
    ListingContent {
        version: listing.version,
        resources: listing.resources.clone(),
        arch: listing.arch.clone(),
        lease_interval_s: listing.lease_interval_s,
        price: listing.price,
        // Only for a listing that prices standbys. A listing that sells none
        // publishes NO FIELD rather than a zero, and gets no standby routes
        // (`routes::route_table`), so a connector never terminates a route
        // this provider did not price.
        standby_price: listing.standby_price,
        capabilities: listing.capabilities.clone(),
    }
}

/// The content of an Eviction Notice (`K_EVICTION`, regular), spec §6.7: a
/// provider's signed public record that it evicted a lease, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvictionContent {
    pub workload_id: String,
    pub reason: EvictionReason,
    pub message: String,
}

/// An Eviction Notice. Unlike the Profile, a Listing or Liveness this is a
/// REGULAR kind: it records one decision at one instant rather than
/// describing an ongoing state, so nothing about it should ever replace a
/// previous publication — a provider that evicts twice leaves two notices.
pub fn eviction_event(
    workload_id: &str,
    reason: EvictionReason,
    message: &str,
    keys: &Keys,
    now: u64,
) -> Result<Event> {
    let content = EvictionContent {
        workload_id: workload_id.to_string(),
        reason,
        message: message.to_string(),
    };
    Ok(
        EventBuilder::new(Kind::Custom(K_EVICTION), serde_json::to_string(&content)?)
            .tags([Tag::parse(["x", workload_id])?, label_tag()?])
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(keys)?,
    )
}

/// The content of a Takeover event (`K_TAKEOVER`, addressable), spec §7.1: a
/// Warm Standby's claim on the workload of a primary that went silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TakeoverContent {
    /// The workload id the whole Standby Set shares.
    pub workload_id: String,
    /// The primary this claim is against: `standby_set[0]`, hex.
    pub primary: String,
}

/// A Takeover, signed by the STANDBY that claims the workload and published
/// to the PRIMARY's Relay Set (spec §7.1 step 2) — which is where every
/// other member of the set is already watching.
///
/// Addressable on `d` = the workload id, unlike the Eviction Notice above:
/// a standby announces once per workload and a second announcement about the
/// same one replaces the first rather than joining it, so the relay holds one
/// claim per standby per workload and the settle query (§7.1 step 3) reads a
/// set of claimants rather than a history.
pub fn takeover_event(
    workload_id: &str,
    primary: &nostr_sdk::PublicKey,
    keys: &Keys,
    now: u64,
) -> Result<Event> {
    let content = TakeoverContent {
        workload_id: workload_id.to_string(),
        primary: primary.to_hex(),
    };
    Ok(
        EventBuilder::new(Kind::Custom(K_TAKEOVER), serde_json::to_string(&content)?)
            .tags([Tag::identifier(workload_id.to_string()), label_tag()?])
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(keys)?,
    )
}

/// Liveness. Replaceable, so a relay holds exactly one per provider however
/// often this is published, and it expires five cadences out (ADR 0007) so a
/// provider that stops publishing goes quiet without anyone deleting anything.
pub fn liveness_event(
    available: BTreeMap<String, u32>,
    cadence_s: u64,
    keys: &Keys,
    now: u64,
) -> Result<Event> {
    let content = LivenessContent { available };
    let expires_at = now.saturating_add(LIVENESS_EXPIRY_CADENCES.saturating_mul(cadence_s));

    Ok(
        EventBuilder::new(Kind::Custom(K_LIVENESS), serde_json::to_string(&content)?)
            .tags([label_tag()?, Tag::expiration(Timestamp::from(expires_at))])
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(keys)?,
    )
}
