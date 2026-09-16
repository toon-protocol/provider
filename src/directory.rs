// The Directory port: the second of the provider's two I/O ports (the first
// is `ComputeBackend`). Everything the provider says about itself in public —
// its Provider Profile, its Listings, its Liveness and, from a later ticket,
// an Eviction Notice — leaves through `publish`, and everything it needs to
// read back about another provider's Liveness arrives through `query_liveness`.
//
// Why a port at all: a relay write on the TOON Network is PAID (ADR 0007), so
// publishing is a payment, a network round trip and a per-relay outcome, none
// of which belongs in the lease lifecycle. Tests drive a fake and assert on
// what was published; the real implementation is the only place that knows
// how money reaches a relay.
//
// Reads are free — a NIP-01 REQ over a relay's websocket costs nothing — so
// `query_liveness` and `get_image_entry` speak to relays directly and need
// no payer. `get_image_entry` reads from the ONE relay a spawn hinted at
// (spec §6.2), not the Relay Set: an Image Registry entry is a publisher's
// event, and the tenant says where it can be found.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use nostr_sdk::{Client, Event, Filter, Kind, PublicKey};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::nostr::kinds::K_LIVENESS;

/// The `<kind>:<pubkey>:<d>` coordinate of an addressable event, as a
/// spawn's `registry_entry.address` carries it (spec §6.2). `d` may itself
/// contain colons (`web:1.0`), so only the first two are separators.
pub fn parse_coordinate(address: &str) -> Result<(u16, PublicKey, String)> {
    let mut parts = address.splitn(3, ':');
    let (Some(kind), Some(pubkey), Some(d)) = (parts.next(), parts.next(), parts.next()) else {
        bail!("{:?} is not a `<kind>:<pubkey>:<d>` address", address);
    };
    let kind: u16 = kind
        .parse()
        .with_context(|| format!("{:?}: the kind is not a number", address))?;
    let pubkey = PublicKey::from_hex(pubkey)
        .with_context(|| format!("{:?}: the pubkey is not 32 bytes of hex", address))?;
    Ok((kind, pubkey, d.to_string()))
}

/// Which relays of the Relay Set took an event, and why the rest did not.
///
/// A publication is not all-or-nothing: a provider with four relays that
/// reaches three is still discoverable, so this reports rather than fails.
/// The caller logs the failures and carries on (a provider that crashed
/// because one relay was down would take its paid workloads with it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishReport {
    /// Relay URLs that stored the event.
    #[serde(default)]
    pub accepted: Vec<String>,
    /// Relay URL -> why it did not, in the Relay Set's order.
    #[serde(default)]
    pub failed: BTreeMap<String, String>,
}

impl PublishReport {
    /// True when no relay refused. Spec §4 is "to EVERY relay in its Relay
    /// Set", so a publication that reached three relays of four is not
    /// finished and the loop tries again — reaching some is not reaching all.
    ///
    /// It asks about the failures rather than counting the successes so that
    /// a Directory which attempted nothing (`NullDirectory`, a provider with
    /// no publisher) is finished rather than retried forever.
    pub fn reached_every_relay(&self) -> bool {
        self.failed.is_empty()
    }

    /// One line for the log: what went out and what did not.
    pub fn summary(&self) -> String {
        if self.failed.is_empty() {
            return format!("{} relay(s) accepted", self.accepted.len());
        }
        let failures: Vec<String> = self
            .failed
            .iter()
            .map(|(relay, why)| format!("{relay}: {why}"))
            .collect();
        format!(
            "{} relay(s) accepted, {} refused ({})",
            self.accepted.len(),
            self.failed.len(),
            failures.join("; ")
        )
    }
}

/// The provider's window onto the Provider Directory.
#[async_trait]
pub trait Directory: Send + Sync {
    /// Write one signed event to every relay in the Relay Set, paying for
    /// each write. Errors only when the publication could not be attempted at
    /// all; a relay-by-relay outcome is the report.
    async fn publish(&self, event: Event) -> Result<PublishReport>;

    /// The newest unexpired Liveness a relay in the Relay Set holds from
    /// `provider`, or `None` when it holds none — which is what "not live"
    /// means (spec §4.3). Reads are free.
    async fn query_liveness(&self, provider: PublicKey) -> Result<Option<Event>>;

    /// The Image Registry entry at `address` (`30434:<pubkey>:<name>:<tag>`)
    /// as `relay` holds it, or `None` when it holds none (spec §6.2, §8.1).
    /// The relay is the one the spawn hinted at, not the Relay Set. Reads
    /// are free. The caller checks that what came back IS the entry named:
    /// signed by the address's pubkey, under its `d`.
    async fn get_image_entry(&self, address: &str, relay: &str) -> Result<Option<Event>>;
}

/// The Directory of a provider that publishes nothing: no `publish_url` is
/// configured, so there is nobody to pay the relay writes.
///
/// It is not an error. A provider whose tenants already know its address is
/// reachable without ever appearing in the directory, and an unconfigured
/// sandbox should not fail to start.
pub struct NullDirectory;

#[async_trait]
impl Directory for NullDirectory {
    async fn publish(&self, event: Event) -> Result<PublishReport> {
        info!(
            "no publish_url configured; kind {} event {} was not published",
            event.kind.as_u16(),
            event.id
        );
        Ok(PublishReport::default())
    }

    async fn query_liveness(&self, _provider: PublicKey) -> Result<Option<Event>> {
        Ok(None)
    }

    /// A provider with no publisher can still READ: an Image Registry
    /// entry lives on whatever relay the spawn named, which needs no money.
    async fn get_image_entry(&self, address: &str, relay: &str) -> Result<Option<Event>> {
        fetch_addressable(address, relay).await
    }
}

/// One free NIP-01 REQ to `relay` for the addressable event at `address`,
/// newest publication first — two publications of one `d` may both be on
/// the wire while the older one is being replaced.
async fn fetch_addressable(address: &str, relay: &str) -> Result<Option<Event>> {
    let (kind, pubkey, d) = parse_coordinate(address)?;
    let client = Client::default();
    client
        .add_relay(relay)
        .await
        .with_context(|| format!("{} is not a usable relay URL", relay))?;
    client.connect().await;
    let filter = Filter::new()
        .kind(Kind::Custom(kind))
        .author(pubkey)
        .identifier(d)
        .limit(1);
    let events = client.fetch_events(filter, QUERY_TIMEOUT).await;
    client.disconnect().await;
    let events = events.with_context(|| format!("reading {} from {}", address, relay))?;
    Ok(events.into_iter().max_by_key(|e| e.created_at))
}

/// What `ConnectorDirectory` hands the directory publisher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    pub event: Event,
    /// The Relay Set, by read URL. The publisher maps each to that relay's
    /// PAID write route and pays it.
    pub relays: Vec<String>,
}

/// Publishes on the PAID relay route (ADR 0007) — never on the free ephemeral
/// lane, whose rate limit is keyed by remote address and is therefore shared
/// by every provider behind one connector.
///
/// The paying is delegated to a sidecar, the **directory publisher**
/// (`tools/publisher`), reached at `publish_url`. That split is deliberate
/// and is the whole of this milestone's decision: paying a TOON route means
/// opening a payment channel on Solana or EVM, signing a balance proof per
/// packet and sealing an ILP prepare to the terminating connector's key.
/// There is one proven implementation of all of that, `@toon-protocol/client`,
/// and it is not a Rust crate. Re-deriving it here would put the
/// marketplace's money on a second, unproven payer. So the provider states
/// WHAT to publish and the publisher decides HOW it is paid for; this type is
/// the boundary, and it is the only thing that changes if a Rust payer ever
/// exists.
///
/// **Whose money pays, precisely.** The publisher is a TOON CLIENT with its
/// own payment channel — it is not the provider's own connector originating a
/// packet. A provider connector serves its routes and is PAID on them; making
/// it also pay outward needs a channel in the other direction and an
/// originating write on its operator surface (a signed RFC 9421 request
/// carrying an OER ILP prepare, sealed to the relay's connector). That is a
/// second money path for the same events and it is not what this milestone
/// buys. What the ticket requires — the paid relay route, never the ephemeral
/// lane — this shape gives; what it does not give is one identity paying for
/// everything a provider does. A later milestone may collapse the two, and
/// only this type changes when it does.
///
/// Reads stay in-process: `query_liveness` is a free NIP-01 REQ.
pub struct ConnectorDirectory {
    publish_url: String,
    relay_set: Vec<String>,
    http: reqwest::Client,
}

/// How long a paid publication may take: a channel-backed packet through a
/// hub and on to a relay, not a local call.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a free relay read may take before the provider gives up on it.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

impl ConnectorDirectory {
    pub fn new(publish_url: impl Into<String>, relay_set: Vec<String>) -> Result<Self> {
        Ok(Self {
            publish_url: publish_url.into(),
            relay_set,
            http: reqwest::Client::builder()
                .timeout(PUBLISH_TIMEOUT)
                .build()
                .context("building the HTTP client for the directory publisher")?,
        })
    }
}

#[async_trait]
impl Directory for ConnectorDirectory {
    async fn publish(&self, event: Event) -> Result<PublishReport> {
        let request = PublishRequest {
            event,
            relays: self.relay_set.clone(),
        };

        let response = self
            .http
            .post(&self.publish_url)
            .json(&request)
            .send()
            .await
            .with_context(|| format!("reaching the directory publisher at {}", self.publish_url))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("reading the directory publisher's answer")?;
        if !status.is_success() {
            return Err(anyhow!(
                "the directory publisher answered {}: {}",
                status,
                body.trim()
            ));
        }

        serde_json::from_str(&body)
            .with_context(|| format!("the directory publisher answered {body:?}"))
    }

    async fn query_liveness(&self, provider: PublicKey) -> Result<Option<Event>> {
        if self.relay_set.is_empty() {
            return Ok(None);
        }

        let client = Client::default();
        for relay in &self.relay_set {
            if let Err(e) = client.add_relay(relay).await {
                warn!("relay {} is not a usable relay URL: {}", relay, e);
            }
        }
        client.connect().await;

        // A relay drops an expired event at serve time (NIP-40), so "not
        // live" and "nothing came back" are the same answer and no expiry
        // check is needed here.
        let filter = Filter::new()
            .kind(Kind::Custom(K_LIVENESS))
            .author(provider)
            .limit(1);
        let events = client.fetch_events(filter, QUERY_TIMEOUT).await;
        client.disconnect().await;

        let events = events.context("reading Liveness from the Relay Set")?;
        // Newest wins: two relays may hold different publications of a
        // replaceable event while the older one is still propagating.
        Ok(events.into_iter().max_by_key(|e| e.created_at))
    }

    async fn get_image_entry(&self, address: &str, relay: &str) -> Result<Option<Event>> {
        fetch_addressable(address, relay).await
    }
}
