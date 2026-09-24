// Directory publication: the loop that makes this provider findable.
//
// Two rhythms, because the two kinds of event change at different rates.
// The Provider Profile and the Listings describe the config, so they go out
// once — at startup, retried on the cadence until they land, because the
// directory publisher may not be up yet — and change only when the config
// does, which is a restart (ADR 0009: a price change is a new listing version,
// and the connector has no runtime write for a retired route). Liveness
// describes the moment, so it goes out every `liveness_cadence_s` with the
// availability of that instant.
//
// The startup publication gets a second, shorter rhythm of its own
// (`publish_directory_at_startup`, TOON_Network#178): on every apply the
// devnet box recreates `provider` and its directory publisher together, so
// the very first attempt is the one most likely to find the publisher's
// hostname not resolvable yet. A short backoff there catches it within a
// handful of seconds; the plain per-cadence retry every later attempt gets
// is for a publisher that is still down after that, or refuses on relay
// grounds a backoff cannot fix.
//
// No failure of the DIRECTORY may take the provider down. A relay that
// refuses a write, a publisher that is not up yet, a paid packet that times
// out: each is logged and the loop carries on, because the leases already
// paid for are running underneath it. The one thing that does stop the loop
// is an event that cannot be BUILT — a config the provider should not have
// started with, and one no amount of retrying fixes.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::Result;
use tracing::{error, info, warn};

use super::persistence::{count_live, LeaseRecord};
use super::ProviderService;
use crate::directory::{DirectoryEntry, PublishReport};
use crate::nostr::directory_events::{listing_event, liveness_event, profile_event};
use crate::provider_http::AppState;

impl AppState {
    /// Publish one event, and say which relays of the Relay Set took it.
    ///
    /// The outcome of a Profile, a Listing or a Liveness is also kept,
    /// relay by relay, in `publications` — the latest per relay per event,
    /// which `GET /operator/status` answers from (ADR 0029). It is the only
    /// place that sees every publication, so it is the one place that
    /// notes them.
    ///
    /// `what` names the event in the log, because the caller is a loop and
    /// "published" on its own says nothing. A relay that refused is in the
    /// report, never an error; `Err` is a publication that could not be
    /// ATTEMPTED — a publisher that is down — which no relay refused and
    /// none accepted, and which the caller says in its own words. Neither
    /// is raised past the caller: a provider whose Profile did not land is
    /// not purchasable — a Listing without its Profile is refused by tenants
    /// (ADR 0002) — but its running leases still are.
    ///
    /// `pub(crate)` rather than private: `evict` (`lifecycle.rs`) publishes an
    /// Eviction Notice with the same discipline — log the outcome, never fail
    /// the caller over a relay that refused.
    pub(crate) async fn publish_one(
        &self,
        what: &str,
        event: nostr_sdk::Event,
    ) -> Result<PublishReport> {
        // Read before the event is handed over: which standing entry it is
        // and when it stops being true, for the operator's status.
        let entry = DirectoryEntry::of(&event);
        let expires_at = event.tags.expiration().map(|t| t.as_u64());

        let published = self.directory.publish(event).await;
        if let Some(entry) = entry {
            self.publications.record(
                &entry,
                expires_at,
                &published,
                &self.config.relay_set,
                self.clock.now(),
            );
        }
        let report = published?;
        info!("{what} published: {}", report.summary());
        Ok(report)
    }

    /// How many leases of each listing could start right now: the tier's
    /// declared capacity minus its live leases, across every version of it.
    ///
    /// Keyed by listing NAME, not by name and version, because capacity is a
    /// slice of hardware and every version of a tier sells the same slice —
    /// which is exactly what `ProviderConfig::capacity_of` answers and what
    /// `validate` enforces the agreement of.
    ///
    /// It counts with `persistence::count_live`, the same counter `spawn` and
    /// `availability` refuse on, so what the Liveness announces and what a
    /// spawn will actually accept cannot drift apart.
    pub async fn available(&self) -> BTreeMap<String, u32> {
        let leases = self.leases.lock().await;
        self.available_in(&leases)
    }

    /// `available` over a lease table the caller already holds locked, so a
    /// reader that needs these numbers AND the leases behind them (the
    /// operator's status) sees one consistent table.
    pub(crate) fn available_in(&self, leases: &HashMap<u32, LeaseRecord>) -> BTreeMap<String, u32> {
        let mut available = BTreeMap::new();
        for listing in &self.config.listings {
            let live = count_live(leases, &listing.name);
            let live = u32::try_from(live).unwrap_or(u32::MAX);
            available.insert(
                listing.name.clone(),
                self.config.capacity_of(&listing.name).saturating_sub(live),
            );
        }
        available
    }
}

/// What one attempt at `publish_directory` accomplished — fine enough for
/// the startup retry (below) to decide whether trying again immediately is
/// worth it (TOON_Network#178). A relay's own "no" is not: nothing about
/// asking again a moment later would change a relay's mind, and that is what
/// `directory_loop`'s regular cadence keeps trying anyway. A publisher that
/// could not be reached at all very likely is worth an immediate retry — on
/// the devnet box every apply recreates `provider` and `directory-publisher`
/// together, and the DNS record for the publisher's hostname is not always
/// there the instant this process asks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryAttempt {
    /// Every relay of the Relay Set took the Profile and every Listing.
    Landed,
    /// At least one publication could not even reach the directory
    /// publisher: not a relay's refusal, an `Err` from `publish_one`.
    NotSent,
    /// The publisher was reached for everything offered to it; at least one
    /// relay refused at least one of them.
    Refused,
}

impl DirectoryAttempt {
    fn landed(self) -> bool {
        matches!(self, Self::Landed)
    }
}

/// The startup retry's backoff: short, doubling steps totalling 7s before
/// the last of them, so the whole sequence stays well under one Liveness
/// cadence even at a fast test's — and comfortably under the devnet's 60s (a
/// publisher still not reachable after this hands off to `directory_loop`'s
/// regular per-cadence retry, which is where a publisher that stays down
/// keeps being tried).
const STARTUP_RETRY_BACKOFF_S: [u64; 3] = [1, 2, 4];

impl ProviderService {
    /// Publish the Provider Profile and every Listing, and say whether every
    /// one of them reached at least one relay of the Relay Set.
    ///
    /// The answer is what `directory_loop` retries on. Errors are NOT that
    /// answer: a relay that refused, or a publisher that is not up yet, is a
    /// `false` to try again on, while an `Err` means the event could not be
    /// built at all — a config the provider should not have started with.
    pub async fn publish_directory(&self) -> Result<bool> {
        Ok(self.publish_directory_attempt().await?.landed())
    }

    /// One attempt at `publish_directory`, reporting which KIND of miss it
    /// was rather than collapsing straight to a bool — `publish_directory`
    /// does that collapsing for its own callers, and the startup retry
    /// (`publish_directory_at_startup`) is the one caller that needs to tell
    /// "not sent" from "refused" apart.
    async fn publish_directory_attempt(&self) -> Result<DirectoryAttempt> {
        let state = &self.state;
        let now = state.clock.now();

        let mut landed = true;
        let mut not_sent = false;
        let mut note = |what: &str, published: Result<PublishReport>| match published {
            Ok(report) => {
                if !report.reached_every_relay() {
                    landed = false;
                }
            }
            Err(e) => {
                warn!("{what} was not published: {e:#}");
                landed = false;
                not_sent = true;
            }
        };

        let profile = profile_event(&state.config, &state.keys, now)?;
        note(
            "Provider Profile",
            state.publish_one("Provider Profile", profile).await,
        );

        // Exactly one Listing per NAME, the version on sale. The event is
        // addressable on `d = <listing name>` (spec §4.2), so a new version
        // REPLACES the previous Listing on the relay rather than adding one;
        // publishing a retired version beside it would be a race to be last
        // written, and half the directory would read the old price.
        for listing in state.config.listings_on_sale() {
            let what = format!("Listing {} v{}", listing.name, listing.version);
            let event = listing_event(listing, &state.config, &state.keys, now)?;
            note(&what, state.publish_one(&what, event).await);
        }

        Ok(if landed {
            DirectoryAttempt::Landed
        } else if not_sent {
            DirectoryAttempt::NotSent
        } else {
            DirectoryAttempt::Refused
        })
    }

    /// The startup publication, retried with a short backoff while the
    /// directory publisher is simply not reachable yet (TOON_Network#178):
    /// on every apply the devnet box recreates `provider` and
    /// `directory-publisher` together, and this catches the publisher within
    /// a handful of seconds instead of waiting out a whole Liveness cadence
    /// (~60s) for `directory_loop`'s regular retry to come around. It also
    /// covers a publisher that restarts on its own later, at whatever point
    /// in the cadence that happens.
    ///
    /// Stops the moment an attempt lands, or the moment one comes back a
    /// real relay refusal — retrying THAT in a hot loop would not change a
    /// relay's mind, only spend paid packets faster — and otherwise hands
    /// off to the regular cadence once the backoff runs out.
    pub async fn publish_directory_at_startup(&self) -> bool {
        // Bounded by the cadence itself, not just the fixed steps below: a
        // provider configured with a cadence shorter than the backoff (a
        // test's, mostly) hands off to the regular per-cadence retry sooner
        // rather than sleeping past the cadence it is meant to stay under.
        let cadence = Duration::from_secs(self.state.config.liveness_cadence_s.max(1));
        for backoff_s in STARTUP_RETRY_BACKOFF_S {
            match self.publish_directory_attempt().await {
                Ok(DirectoryAttempt::Landed) => return true,
                Ok(DirectoryAttempt::Refused) => return false,
                Ok(DirectoryAttempt::NotSent) => {}
                Err(e) => {
                    error!("the Provider Profile or a Listing could not be built: {e:#}");
                    return false;
                }
            }
            let wait = Duration::from_secs(backoff_s);
            if wait >= cadence {
                break;
            }
            tokio::time::sleep(wait).await;
        }
        match self.publish_directory_attempt().await {
            Ok(attempt) => attempt.landed(),
            Err(e) => {
                error!("the Provider Profile or a Listing could not be built: {e:#}");
                false
            }
        }
    }

    /// Publish one Liveness event for the instant `now`, count it against
    /// this provider's own Relay Set, and say which relays took it. Public
    /// so a test can drive a cadence on a chosen instant rather than waiting
    /// one out.
    ///
    /// The report is the answer, not a side effect in the log: a primary
    /// that cannot reach a strict majority of its own Relay Set for five
    /// cadences must stop its workload (spec §7.1), and `note_liveness`
    /// (`self_stop`) is the count. It happens HERE, on the one publication
    /// the directory loop makes each cadence, so what a test drives and what
    /// the loop does are the same thing. `Err` when no relay could even be
    /// asked — the event could not be built, or the publisher could not be
    /// reached — which for that count is a cadence on which no relay took
    /// it, and which the caller still hears about.
    pub async fn publish_liveness(&self, now: u64) -> Result<PublishReport> {
        let published = self.publish_liveness_event(now).await;
        self.note_liveness(published.as_ref().ok()).await;
        published
    }

    /// The publication itself, with nothing counted: the Liveness of this
    /// instant, offered to the Relay Set.
    async fn publish_liveness_event(&self, now: u64) -> Result<PublishReport> {
        let state = &self.state;
        let event = liveness_event(
            state.available().await,
            state.config.liveness_cadence_s,
            &state.keys,
            now,
        )?;
        state.publish_one("Liveness", event).await
    }

    /// Keep this provider in the directory, forever: the Profile and the
    /// Listings until every relay has them, then one Liveness per cadence.
    ///
    /// It never returns. Nothing about the directory is worth stopping a
    /// provider for — the sweep and the paid routes are running beside this
    /// loop, and a provider that exited because it could not be advertised
    /// would strand the workloads it has already been paid for.
    pub(super) async fn directory_loop(&self) -> ! {
        let cadence = tokio::time::Duration::from_secs(self.state.config.liveness_cadence_s.max(1));

        // An interval rather than sleep-after-publish: publishing takes as
        // long as a paid packet takes, and adding that to every wait would
        // walk the cadence out past the expiry it is measured against
        // (ADR 0007). `Delay` rather than `Burst` so a slow publication
        // delays the next tick instead of firing a backlog of them at once.
        let mut ticker = tokio::time::interval(cadence);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut directory_published = false;
        let mut first_tick = true;
        loop {
            // The first tick is immediate: the startup publication IS the
            // first cadence, and a provider that waited one out would be
            // invisible for a whole cadence after every restart.
            ticker.tick().await;

            if !directory_published {
                directory_published = if first_tick {
                    // The startup attempt gets its own short backoff rather
                    // than the plain single try every later cadence gets:
                    // this is the attempt most likely to race a directory
                    // publisher recreated alongside this provider on the
                    // same apply (TOON_Network#178), and it is over well
                    // before the next tick would otherwise retry it.
                    self.publish_directory_at_startup().await
                } else {
                    match self.publish_directory().await {
                        Ok(landed) => landed,
                        Err(e) => {
                            error!("the Provider Profile or a Listing could not be built: {e:#}");
                            false
                        }
                    }
                };
            }
            first_tick = false;
            if let Err(e) = self.publish_liveness(self.state.clock.now()).await {
                error!("Liveness was not published: {e:#}");
            }
        }
    }
}
