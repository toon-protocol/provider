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
// Nothing here may take the provider down. A relay that refuses a write, a
// publisher that is not up yet, a paid packet that times out: each is logged
// and the loop carries on, because the leases already paid for are running
// underneath it.

use std::collections::BTreeMap;

use anyhow::Result;
use tracing::{info, warn};

use super::ProviderService;
use crate::nostr::directory_events::{listing_event, liveness_event, profile_event};

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
        let mut complete = true;

        let profile = profile_event(&state.config, &state.keys, now)?;
        match state.directory.publish(profile).await {
            Ok(report) => {
                complete &= !report.is_empty();
                info!("Provider Profile published: {}", report.summary());
            }
            // A provider whose Profile did not land is not purchasable — a
            // Listing without its Profile is refused by tenants (ADR 0002) —
            // but its running leases still are, so this warns rather than
            // returning.
            Err(e) => {
                complete = false;
                warn!("Provider Profile was not published: {e:#}");
            }
        }

        for listing in &state.config.listings {
            let event = listing_event(listing, &state.config, &state.keys, now)?;
            match state.directory.publish(event).await {
                Ok(report) => {
                    complete &= !report.is_empty();
                    info!(
                        "Listing {} v{} published: {}",
                        listing.name,
                        listing.version,
                        report.summary()
                    );
                }
                Err(e) => {
                    complete = false;
                    warn!(
                        "Listing {} v{} was not published: {e:#}",
                        listing.name, listing.version
                    );
                }
            }
        }

        Ok(complete)
    }

    /// Publish one Liveness event for the instant `now`. Public so a test can
    /// drive a cadence on a chosen instant rather than waiting one out.
    pub async fn publish_liveness(&self, now: u64) -> Result<()> {
        let state = &self.state;
        let event = liveness_event(
            self.available().await,
            state.config.liveness_cadence_s,
            &state.keys,
            now,
        )?;

        match state.directory.publish(event).await {
            Ok(report) => info!("Liveness published: {}", report.summary()),
            Err(e) => warn!("Liveness was not published: {e:#}"),
        }
        Ok(())
    }

    /// How many leases of each listing could start right now: the tier's
    /// declared capacity minus its live leases, across every version of it.
    ///
    /// Keyed by listing NAME, not by name and version, because capacity is a
    /// slice of hardware and every version of a tier sells the same slice
    /// (`ProviderConfig::validate` enforces the agreement).
    pub async fn available(&self) -> BTreeMap<String, u32> {
        let leases = self.state.leases.lock().await;

        let mut available = BTreeMap::new();
        for listing in &self.state.config.listings {
            if available.contains_key(&listing.name) {
                continue;
            }
            let live = leases
                .values()
                .filter(|l| l.state.is_live() && l.listing == listing.name)
                .count();
            let live = u32::try_from(live).unwrap_or(u32::MAX);
            available.insert(listing.name.clone(), listing.capacity.saturating_sub(live));
        }
        available
    }

    /// Keep this provider in the directory, forever: the Profile and the
    /// Listings until they land, then one Liveness per cadence.
    pub(super) async fn directory_loop(&self) -> Result<()> {
        let cadence = tokio::time::Duration::from_secs(self.state.config.liveness_cadence_s.max(1));
        let mut directory_published = false;

        loop {
            // Publish first, then wait: the startup publication IS the first
            // cadence, and a provider that waited one out would be invisible
            // for its whole cadence after every restart.
            if !directory_published {
                directory_published = self.publish_directory().await?;
            }
            self.publish_liveness(self.state.clock.now()).await?;
            tokio::time::sleep(cadence).await;
        }
    }
}
