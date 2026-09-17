// The Directory port: the second of the provider's two I/O ports (the first
// is `ComputeBackend`). Everything the provider says about itself in public —
// its Provider Profile, its Listings, its Liveness, an Eviction Notice —
// leaves through `publish`; a Takeover, which goes to ANOTHER provider's
// Relay Set, leaves through `publish_takeover`. What a Warm Standby needs to
// read about its primary — the primary's Profile, its Liveness relay by
// relay, and the Takeovers claimed on a workload — arrives through
// `get_profile`, `liveness_state` and `find_takeovers` (spec §7.1).
//
// Why a port at all: a relay write on the TOON Network is PAID (ADR 0007), so
// publishing is a payment, a network round trip and a per-relay outcome, none
// of which belongs in the lease lifecycle. Tests drive a fake and assert on
// what was published; the real implementation is the only place that knows
// how money reaches a relay.
//
// Reads are free — a NIP-01 REQ over a relay's websocket costs nothing — so
// every read here speaks to relays directly and needs no payer. WHICH relays
// depends on whose event is wanted. `get_image_entry` reads from the ONE
// relay a spawn hinted at (spec §6.2), not the Relay Set: an Image Registry
// entry is a publisher's event, and the tenant says where it can be found.
// `find_blob_records` and `get_profile` ask the provider's OWN Relay Set,
// because a bare digest names no relay and no signer (spec §8.4 step 3), and
// a Warm Standby cannot learn its primary's Relay Set from anywhere but the
// primary's Profile — which is what it is reading. `liveness_state` and
// `find_takeovers` take the relays to ask, because both are about the
// PRIMARY's Relay Set (spec §7.1): a primary's Liveness is on the relays it
// publishes to, and every Takeover is published there too.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use nostr_sdk::client::{Connection, ConnectionTarget};
use nostr_sdk::{
    Alphabet, Client, ClientOptions, Event, Filter, Kind, PublicKey, RelayUrl, SingleLetterTag,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::nostr::kinds::{K_BLOB, K_LIVENESS, K_PROFILE, K_TAKEOVER};
use crate::outbound_proxy::{is_loopback_url, OutboundProxy};

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

/// What ONE relay says about a provider's Liveness (spec §4.3): a provider is
/// live on a relay while that relay holds an unexpired Liveness from it.
///
/// Three answers rather than a bool, because a Warm Standby's trigger (spec
/// §7.1 step 1) counts "expired or absent" together and the two are worth
/// telling apart in a log: an expired Liveness is a primary that WAS
/// publishing here and stopped, an absent one is a relay that never had it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessState {
    /// The relay holds a Liveness whose `expiration` is still ahead.
    Live,
    /// A Liveness from the provider was found whose `expiration` is at or
    /// before the instant asked about.
    ///
    /// Rarely what the relay-backed Directory answers, because its relay
    /// pool drops an event that the WALL clock says is expired before this
    /// code sees it (NIP-40, on the client side) — so at the wall clock's
    /// own instant an expired Liveness arrives as `Absent`. The two count
    /// the same (`is_silent`); the distinction is kept for the log, for a
    /// fake that sets it directly, and for a caller asking about an
    /// instant ahead of the wall clock.
    Expired,
    /// The relay holds no Liveness from the provider — or could not be read
    /// at all. A relay this provider cannot reach holds nothing it can see,
    /// and a Liveness nobody can read keeps nobody's workload alive.
    Absent,
}

impl LivenessState {
    /// Everything but `Live`: what spec §7.1 step 1 counts.
    pub fn is_silent(self) -> bool {
        !matches!(self, Self::Live)
    }
}

/// Liveness per relay URL, for the relays that were asked.
pub type RelayLiveness = BTreeMap<String, LivenessState>;

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

    /// The newest Provider Profile the provider's OWN Relay Set holds from
    /// `provider`, or `None` when it holds none (spec §4.1). Reads are free.
    ///
    /// The one read about another provider that goes to THIS provider's
    /// relays: a Warm Standby learns its primary's Relay Set and cadence from
    /// the primary's Profile (spec §7.1), so nothing else can say where to
    /// look for it. The caller checks that what came back is signed by
    /// `provider` before it acts on the relays it names.
    async fn get_profile(&self, provider: PublicKey) -> Result<Option<Event>>;

    /// What each of `relays` says about `provider`'s Liveness at `now`:
    /// live, expired or absent (spec §4.3, §7.1 step 1). Reads are free.
    ///
    /// `relays` rather than the Relay Set, because these are the PRIMARY's
    /// relays — the ones its Profile lists — and a Warm Standby must watch
    /// where the primary publishes, not where it does itself. `now` is
    /// passed in rather than read from a wall clock so that "expired" is
    /// decided on the instant the caller acts on, which a test chooses.
    /// Every relay asked has an answer; one that could not be read is
    /// `Absent`.
    async fn liveness_state(
        &self,
        provider: PublicKey,
        relays: &[String],
        now: u64,
    ) -> Result<RelayLiveness>;

    /// Write one signed Takeover to every relay in `relays` — the PRIMARY's
    /// Relay Set, where every other member of the Standby Set is watching
    /// (spec §7.1 step 2) — paying for each write. Errors and reports as
    /// `publish` does.
    async fn publish_takeover(&self, event: Event, relays: &[String]) -> Result<PublishReport>;

    /// Every Takeover claimed on `workload_id` by one of `claimants` that
    /// `relays` hold, earliest `created_at` first (spec §7.1 step 3). Reads
    /// are free.
    ///
    /// Restricted to `claimants` — the `standby_set` — by the FILTER, so a
    /// Takeover signed by anyone outside the set never even arrives; the
    /// caller still picks the winner, because a tie goes to the lower index
    /// and only the caller knows the order.
    async fn find_takeovers(
        &self,
        workload_id: &str,
        claimants: &[PublicKey],
        relays: &[String],
    ) -> Result<Vec<Event>>;

    /// The Image Registry entry at `address` (`30434:<pubkey>:<name>:<tag>`)
    /// as `relay` holds it, or `None` when it holds none (spec §6.2, §8.1).
    /// The relay is the one the spawn hinted at, not the Relay Set. Reads
    /// are free. The caller checks that what came back IS the entry named:
    /// signed by the address's pubkey, under its `d`.
    async fn get_image_entry(&self, address: &str, relay: &str) -> Result<Option<Event>>;

    /// Every Blob Record the provider's Relay Set holds for `digest`, found
    /// by `#x = <hex>` (spec §8.4 step 3), newest first. Reads are free.
    ///
    /// EVERY signer's: a bare digest names no publisher, and a Blob Record
    /// from any signer is safe to try because the caller checks each part
    /// against its recorded sha256 and the whole blob against `digest` — a
    /// wrong record fails verification and the next one is tried (ADR
    /// 0006). An empty answer is "this Relay Set knows of none", which is
    /// the same thing a relay that is down says; it is the fetcher, having
    /// exhausted every source, that turns that into `refused_image`.
    async fn find_blob_records(&self, digest: &str) -> Result<Vec<Event>>;
}

/// The Directory of a provider that publishes nothing: no `publish_url` is
/// configured, so there is nobody to pay the relay writes.
///
/// It is not an error. A provider whose tenants already know its address is
/// reachable without ever appearing in the directory, and an unconfigured
/// sandbox should not fail to start.
///
/// It still READS. Relay reads are free (§8.4, §6.2, §7.1), so not having a
/// payer costs a provider nothing it needs to resolve an image or to watch a
/// primary: it keeps its Relay Set here purely to search it for Blob Records
/// and Profiles. A provider with no relays configured at all finds none,
/// which is the honest answer rather than an error. What it cannot do is
/// ANNOUNCE a Takeover, which is a paid write like any other — a standby
/// with no publisher watches, decides, and has nobody to pay the relay.
#[derive(Default)]
pub struct NullDirectory {
    relay_set: Vec<String>,
    /// The `anon` SOCKS port every relay read leaves through on a Hidden
    /// Provider (spec §10). `None` — direct — on every other provider.
    proxy: Option<SocketAddr>,
}

impl NullDirectory {
    /// A publisher-less Directory that still searches `relay_set` for Blob
    /// Records.
    pub fn new(relay_set: Vec<String>) -> Self {
        Self {
            relay_set,
            proxy: None,
        }
    }

    /// Every relay this Directory reads leaves through `proxy`. A Hidden
    /// Provider with no publisher still watches its primary and still
    /// resolves images, and both of those are relay reads that would
    /// otherwise name this host to a relay operator.
    pub fn with_proxy(mut self, proxy: &OutboundProxy) -> Self {
        self.proxy = Some(proxy.addr());
        self
    }
}

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
        fetch_addressable(address, relay, self.proxy).await
    }

    /// The same free search of the Relay Set the publishing Directory does:
    /// paying for writes has nothing to do with reading.
    async fn find_blob_records(&self, digest: &str) -> Result<Vec<Event>> {
        fetch_blob_records(&self.relay_set, digest, self.proxy).await
    }

    async fn get_profile(&self, provider: PublicKey) -> Result<Option<Event>> {
        fetch_profile(&self.relay_set, provider, self.proxy).await
    }

    async fn liveness_state(
        &self,
        provider: PublicKey,
        relays: &[String],
        now: u64,
    ) -> Result<RelayLiveness> {
        fetch_liveness_state(provider, relays, now, self.proxy).await
    }

    /// Not published, like everything else: a Takeover is a paid write, and
    /// there is nobody here to pay it. Logged at `warn` rather than `info`,
    /// unlike `publish`, because a standby that decided to take over and
    /// could not say so is a reservation the tenant is paying for that will
    /// never do what it is for.
    async fn publish_takeover(&self, event: Event, relays: &[String]) -> Result<PublishReport> {
        warn!(
            "no publish_url configured; Takeover {} was not announced to {}",
            event.id,
            relays.join(", ")
        );
        Ok(PublishReport::default())
    }

    async fn find_takeovers(
        &self,
        workload_id: &str,
        claimants: &[PublicKey],
        relays: &[String],
    ) -> Result<Vec<Event>> {
        fetch_takeovers(workload_id, claimants, relays, self.proxy).await
    }
}

/// A relay client that dials every relay through `proxy`, or directly when
/// there is none.
///
/// `ConnectionTarget::All`, not `Onion`: nostr-sdk's onion target matches
/// `.onion` hosts, and a Hidden Provider hides EVERY read it makes — a
/// clearnet relay in its Relay Set is exactly the read that would name this
/// host to a relay operator. The SOCKS mode resolves the destination through
/// the proxy (`socks5h`), so no relay's name is looked up here either.
fn relay_client(proxy: Option<SocketAddr>) -> Client {
    match proxy {
        None => Client::default(),
        Some(addr) => Client::builder()
            .opts(
                ClientOptions::new()
                    .connection(Connection::new().proxy(addr).target(ConnectionTarget::All)),
            )
            .build(),
    }
}

/// A client connected to every usable relay in `relays`, and which of them
/// it reached.
///
/// A relay whose URL does not parse, or that does not answer within
/// `CONNECT_TIMEOUT`, is skipped with a warning, never an error: a Relay
/// Set with one bad entry still has the others. The reads below ask only
/// the relays that connected, because a REQ to one that did not is a
/// question nobody answers, and the pool would wait the whole query timeout
/// for it — every read of a Relay Set with one dead relay would take ten
/// seconds.
struct Connected {
    client: Client,
    relays: Vec<String>,
}

impl Connected {
    async fn to(relays: &[String], proxy: Option<SocketAddr>) -> Self {
        let client = relay_client(proxy);
        for relay in relays {
            if let Err(e) = client.add_relay(relay).await {
                warn!("relay {} is not a usable relay URL: {}", relay, e);
            }
        }
        let outcome = client.try_connect(CONNECT_TIMEOUT).await;
        for (relay, why) in &outcome.failed {
            warn!("relay {} could not be reached: {}", relay, why);
        }
        let relays = relays
            .iter()
            .filter(|relay| RelayUrl::parse(relay).is_ok_and(|url| outcome.success.contains(&url)))
            .cloned()
            .collect();
        Self { client, relays }
    }

    /// One free REQ to every connected relay, the answers merged and
    /// deduplicated by the pool. Empty, without asking, when nothing
    /// connected. Consumes the connection: one question per client, which
    /// is what every caller asks.
    async fn fetch(self, filter: Filter, what: &str) -> Result<Vec<Event>> {
        if self.relays.is_empty() {
            return Ok(Vec::new());
        }
        let events = self
            .client
            .fetch_events_from(
                self.relays.iter().map(String::as_str),
                filter,
                QUERY_TIMEOUT,
            )
            .await;
        self.client.disconnect().await;
        let events = events.with_context(|| format!("reading {} from the relays", what))?;
        Ok(events.into_iter().collect())
    }
}

/// One free NIP-01 REQ to every relay in `relay_set` for the newest Provider
/// Profile from `provider`.
///
/// Newest wins across relays for the same reason as `query_liveness`: a
/// replaceable event's two publications may both be on the wire while the
/// older one is being replaced, and the newer is the one the provider means.
async fn fetch_profile(
    relay_set: &[String],
    provider: PublicKey,
    proxy: Option<SocketAddr>,
) -> Result<Option<Event>> {
    if relay_set.is_empty() {
        return Ok(None);
    }
    let filter = Filter::new()
        .kind(Kind::Custom(K_PROFILE))
        .author(provider)
        .limit(1);
    let events = Connected::to(relay_set, proxy)
        .await
        .fetch(filter, "a Provider Profile")
        .await?;
    Ok(events.into_iter().max_by_key(|e| e.created_at))
}

/// One free NIP-01 REQ PER RELAY in `relays` for `provider`'s Liveness, each
/// answered on its own: the whole point is to know which relays hold it.
///
/// `Absent` for a relay that could not be connected to, that errored, or
/// that holds nothing — which, through nostr-sdk's relay pool, includes a
/// Liveness the wall clock says has expired (see `LivenessState::Expired`).
/// `Expired` for one that arrives with an `expiration` at or before `now`,
/// or with none at all: spec §4.3 says a Liveness MUST carry one, and one
/// that says nothing about when it stops being true cannot say the
/// provider is up now.
async fn fetch_liveness_state(
    provider: PublicKey,
    relays: &[String],
    now: u64,
    proxy: Option<SocketAddr>,
) -> Result<RelayLiveness> {
    let mut states = RelayLiveness::new();
    if relays.is_empty() {
        return Ok(states);
    }

    let client = relay_client(proxy);
    for relay in relays {
        if let Err(e) = client.add_relay(relay).await {
            warn!("relay {} is not a usable relay URL: {}", relay, e);
            states.insert(relay.clone(), LivenessState::Absent);
        }
    }
    // Wait for the connections rather than fire the REQs at once: a relay
    // that refuses the connection is answered `Absent` now, instead of a
    // REQ that nobody ever answers running out the query timeout.
    let connected = client.try_connect(CONNECT_TIMEOUT).await;
    for relay in relays {
        if states.contains_key(relay) {
            continue;
        }
        if let Some(why) = RelayUrl::parse(relay)
            .ok()
            .and_then(|url| connected.failed.get(&url))
        {
            warn!(
                "relay {} could not be reached ({}); reading it as absent",
                relay, why
            );
            states.insert(relay.clone(), LivenessState::Absent);
            continue;
        }
        let filter = Filter::new()
            .kind(Kind::Custom(K_LIVENESS))
            .author(provider)
            .limit(1);
        let state = match client
            .fetch_events_from([relay.as_str()], filter, QUERY_TIMEOUT)
            .await
        {
            Ok(events) => match events.into_iter().max_by_key(|e| e.created_at) {
                Some(event) => liveness_state_of(&event, now),
                None => LivenessState::Absent,
            },
            Err(e) => {
                warn!(
                    "relay {} could not be read ({}); reading it as absent",
                    relay, e
                );
                LivenessState::Absent
            }
        };
        states.insert(relay.clone(), state);
    }
    client.disconnect().await;
    Ok(states)
}

/// Live while the Liveness's `expiration` is still ahead of `now`; expired
/// at or past it, and expired when it carries none (spec §4.3).
fn liveness_state_of(liveness: &Event, now: u64) -> LivenessState {
    match liveness.tags.expiration() {
        Some(expiration) if expiration.as_u64() > now => LivenessState::Live,
        _ => LivenessState::Expired,
    }
}

/// One free NIP-01 REQ to every relay in `relays` for the Takeovers on
/// `workload_id` from `claimants`, earliest first.
///
/// Two relays may each hold a claimant's event — a Takeover goes to the whole
/// Relay Set — so the answer is deduplicated by event id, which a relay pool
/// does on its own. Earliest first because that is the order the settle
/// reads it in (spec §7.1 step 3); the caller breaks ties by index.
async fn fetch_takeovers(
    workload_id: &str,
    claimants: &[PublicKey],
    relays: &[String],
    proxy: Option<SocketAddr>,
) -> Result<Vec<Event>> {
    if relays.is_empty() || claimants.is_empty() {
        return Ok(Vec::new());
    }
    let filter = Filter::new()
        .kind(Kind::Custom(K_TAKEOVER))
        .authors(claimants.iter().copied())
        .identifier(workload_id);
    let mut events = Connected::to(relays, proxy)
        .await
        .fetch(filter, &format!("Takeovers on {}", workload_id))
        .await?;
    events.sort_by_key(|e| e.created_at);
    Ok(events)
}

/// One free NIP-01 REQ to every relay in `relay_set` for the Blob Records
/// tagged `#x = <hex>`, newest first (spec §8.4 step 3).
///
/// No author filter: a bare digest names no publisher, so every signer's
/// record is a candidate. What makes one usable is its bytes, not its key
/// — the caller checks each part against its recorded sha256 and the whole
/// blob against the digest (ADR 0006).
async fn fetch_blob_records(
    relay_set: &[String],
    digest: &str,
    proxy: Option<SocketAddr>,
) -> Result<Vec<Event>> {
    if relay_set.is_empty() {
        return Ok(Vec::new());
    }
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);

    let filter = Filter::new()
        .kind(Kind::Custom(K_BLOB))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::X), hex);
    let mut events = Connected::to(relay_set, proxy)
        .await
        .fetch(filter, &format!("Blob Records for {}", digest))
        .await?;
    // Newest first is a hint, not a rule: the fetcher tries them in order
    // and stops at the first whose bytes verify, so the only thing this
    // order buys is that a republished record is tried before the one it
    // replaced.
    events.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    Ok(events)
}

/// One free NIP-01 REQ to `relay` for the addressable event at `address`,
/// newest publication first — two publications of one `d` may both be on
/// the wire while the older one is being replaced.
async fn fetch_addressable(
    address: &str,
    relay: &str,
    proxy: Option<SocketAddr>,
) -> Result<Option<Event>> {
    let (kind, pubkey, d) = parse_coordinate(address)?;
    let client = relay_client(proxy);
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
    /// `socks5h://<host>:<port>` — the `anon` SOCKS port the publisher is to
    /// dial the connector through, set only by a Hidden Provider (spec §10).
    ///
    /// In the request rather than in the publisher's own environment because
    /// the provider is the process that knows whether it is hidden: the
    /// publisher is a payer, and one told "pay for this, and go this way"
    /// needs no second copy of the hiding config to keep in step. ABSENT
    /// means direct, which is what every provider that is not hidden sends
    /// and what a publisher built before this field already does.
    ///
    /// The publisher honours it for EVERY host it dials, not only `.anyone`
    /// ones: a hidden provider whose payer reached a clearnet hub directly
    /// would have named this host to the hub, whatever the connector's
    /// address looked like.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
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
    /// The `anon` SOCKS port every relay READ leaves through on a Hidden
    /// Provider. `None` — direct — on every other provider.
    relay_proxy: Option<SocketAddr>,
    /// What goes in `PublishRequest::proxy`: the same proxy, for the
    /// publisher's own hop to the connector.
    request_proxy: Option<String>,
}

/// How long a paid publication may take: a channel-backed packet through a
/// hub and on to a relay, not a local call.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a free relay read may take before the provider gives up on it.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one relay may take to accept a connection before a per-relay
/// read answers `Absent` for it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The HTTP client the publish request goes out on: a 30s budget, and the
/// `anon` SOCKS port when a Hidden Provider's publisher is somewhere a packet
/// has to leave this host to reach.
fn publisher_http(proxy: Option<&OutboundProxy>) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder().timeout(PUBLISH_TIMEOUT);
    let builder = match proxy {
        Some(proxy) => proxy.apply(builder)?,
        None => builder,
    };
    builder
        .build()
        .context("building the HTTP client for the directory publisher")
}

impl ConnectorDirectory {
    pub fn new(publish_url: impl Into<String>, relay_set: Vec<String>) -> Result<Self> {
        Ok(Self {
            publish_url: publish_url.into(),
            relay_set,
            http: publisher_http(None)?,
            relay_proxy: None,
            request_proxy: None,
        })
    }

    /// A Hidden Provider's Directory: every relay read leaves through
    /// `proxy`, every publish request NAMES it, and the request itself rides
    /// it unless the publisher is on this host's loopback (spec §10).
    ///
    /// The loopback exception is not an escape from hiding. A publisher one
    /// process over is reached by a packet that never leaves this box, and
    /// asking `anon` to build a circuit back to the host it runs on would
    /// fail rather than hide anything. What has to be hidden is the hop the
    /// publisher makes NEXT, to the connector that sells the relay write —
    /// and that is what `PublishRequest::proxy` buys, loopback publisher or
    /// not.
    pub fn with_proxy(mut self, proxy: &OutboundProxy) -> Result<Self> {
        self.relay_proxy = Some(proxy.addr());
        self.request_proxy = Some(proxy.url().to_string());
        if !is_loopback_url(&self.publish_url) {
            self.http = publisher_http(Some(proxy))?;
        }
        Ok(self)
    }

    /// Hand one signed event to the directory publisher for `relays`. The
    /// Relay Set for everything the provider says about itself; the
    /// PRIMARY's relays for a Takeover (spec §7.1 step 2).
    async fn publish_to(&self, event: Event, relays: &[String]) -> Result<PublishReport> {
        let request = PublishRequest {
            event,
            relays: relays.to_vec(),
            proxy: self.request_proxy.clone(),
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
}

#[async_trait]
impl Directory for ConnectorDirectory {
    async fn publish(&self, event: Event) -> Result<PublishReport> {
        self.publish_to(event, &self.relay_set).await
    }

    async fn query_liveness(&self, provider: PublicKey) -> Result<Option<Event>> {
        if self.relay_set.is_empty() {
            return Ok(None);
        }
        // A relay drops an expired event at serve time (NIP-40), and the
        // relay pool drops one the relay did not, so "not live" and
        // "nothing came back" are the same answer and no expiry check is
        // needed here.
        let filter = Filter::new()
            .kind(Kind::Custom(K_LIVENESS))
            .author(provider)
            .limit(1);
        let events = Connected::to(&self.relay_set, self.relay_proxy)
            .await
            .fetch(filter, "Liveness")
            .await?;
        // Newest wins: two relays may hold different publications of a
        // replaceable event while the older one is still propagating.
        Ok(events.into_iter().max_by_key(|e| e.created_at))
    }

    async fn get_image_entry(&self, address: &str, relay: &str) -> Result<Option<Event>> {
        fetch_addressable(address, relay, self.relay_proxy).await
    }

    async fn find_blob_records(&self, digest: &str) -> Result<Vec<Event>> {
        fetch_blob_records(&self.relay_set, digest, self.relay_proxy).await
    }

    async fn get_profile(&self, provider: PublicKey) -> Result<Option<Event>> {
        fetch_profile(&self.relay_set, provider, self.relay_proxy).await
    }

    async fn liveness_state(
        &self,
        provider: PublicKey,
        relays: &[String],
        now: u64,
    ) -> Result<RelayLiveness> {
        fetch_liveness_state(provider, relays, now, self.relay_proxy).await
    }

    async fn publish_takeover(&self, event: Event, relays: &[String]) -> Result<PublishReport> {
        self.publish_to(event, relays).await
    }

    async fn find_takeovers(
        &self,
        workload_id: &str,
        claimants: &[PublicKey],
        relays: &[String],
    ) -> Result<Vec<Event>> {
        fetch_takeovers(workload_id, claimants, relays, self.relay_proxy).await
    }
}
