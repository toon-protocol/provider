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
// No failure of the DIRECTORY may take the provider down. A relay that
// refuses a write, a publisher that is not up yet, a paid packet that times
// out: each is logged and the loop carries on, because the leases already
// paid for are running underneath it. The one thing that does stop the loop
// is an event that cannot be BUILT — a config the provider should not have
// started with, and one no amount of retrying fixes.

use std::collections::BTreeMap;

use anyhow::Result;
use tracing::{error, info, warn};

use super::persistence::count_live;
use super::ProviderService;
use crate::nostr::directory_events::{listing_event, liveness_event, profile_event};
use crate::provider_http::AppState;

impl AppState {
    /// Publish one event, and say whether any relay of the Relay Set took it.
    ///
    /// `what` names the event in the log, because the caller is a loop and
    /// "published" on its own says nothing. A failure is reported, never
    /// raised: a provider whose Profile did not land is not purchasable — a
    /// Listing without its Profile is refused by tenants (ADR 0002) — but its
    /// running leases still are.
    async fn publish_one(&self, what: &str, event: nostr_sdk::Event) -> bool {
        match self.directory.publish(event).await {
            Ok(report) => {
                info!("{what} published: {}", report.summary());
                report.reached_every_relay()
            }
            Err(e) => {
                warn!("{what} was not published: {e:#}");
                false
            }
        }
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

        let mut available = BTreeMap::new();
        for listing in &self.config.listings {
            let live = count_live(&leases, &listing.name);
            let live = u32::try_from(live).unwrap_or(u32::MAX);
            available.insert(
                listing.name.clone(),
                self.config.capacity_of(&listing.name).saturating_sub(live),
            );
        }
        available
    }
}

impl ProviderService {
    /// Publish the Provider Profile and every Listing, and say whether every
    /// one of them reached at least one relay of the Relay Set.
    ///
    /// The answer is what `directory_loop` retries on. Errors are NOT that
    /// answer: a relay that refused, or a publisher that is not up yet, is a
    /// `false` to try again on, while an `Err` means the event could not be
    /// built at all — a config the provider should not have started with.
    pub async fn publish_directory(&self) -> Result<bool> {
        let state = &self.state;
        let now = state.clock.now();

        let mut landed = state
            .publish_one(
                "Provider Profile",
                profile_event(&state.config, &state.keys, now)?,
            )
            .await;

        for listing in &state.config.listings {
            let what = format!("Listing {} v{}", listing.name, listing.version);
            let event = listing_event(listing, &state.config, &state.keys, now)?;
            landed &= state.publish_one(&what, event).await;
        }

        Ok(landed)
    }

    /// Publish one Liveness event for the instant `now`. Public so a test can
    /// drive a cadence on a chosen instant rather than waiting one out.
    pub async fn publish_liveness(&self, now: u64) -> Result<()> {
        let state = &self.state;
        let event = liveness_event(
            state.available().await,
            state.config.liveness_cadence_s,
            &state.keys,
            now,
        )?;
        state.publish_one("Liveness", event).await;
        Ok(())
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
        loop {
            // The first tick is immediate: the startup publication IS the
            // first cadence, and a provider that waited one out would be
            // invisible for a whole cadence after every restart.
            ticker.tick().await;

            if !directory_published {
                match self.publish_directory().await {
                    Ok(landed) => directory_published = landed,
                    Err(e) => error!("the Provider Profile or a Listing could not be built: {e:#}"),
                }
            }
            if let Err(e) = self.publish_liveness(self.state.clock.now()).await {
                error!("Liveness could not be built: {e:#}");
            }
        }
    }
}
