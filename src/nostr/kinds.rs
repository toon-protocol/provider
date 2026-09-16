// Event kinds of the TOON Network protocol.
//
// These numbers are ALLOCATED (spec §3.1, ADR 0012): one contiguous block of
// ten per NIP-01 class, all sharing the `432` suffix — regular 4432..=4441,
// replaceable 10432..=10441, addressable 30432..=30441. The class decides how
// a relay stores and replaces the event; the block keeps a relay filter on
// all TOON Network kinds cheap. New kinds take the next free number in their
// class's block; the spec's kind table is the register.
//
// None of Paygress's kinds (38383..=38386, 20384) is reused: 38383 collides
// with NIP-69, and the rest name events this protocol does not have.

/// Provider Profile: who a provider is and how it is reached and paid.
/// Replaceable — one per provider.
pub const K_PROFILE: u16 = 10_432;

/// Liveness: a provider's short-lived statement that it is up. Replaceable,
/// and it MUST carry an `expiration` tag.
pub const K_LIVENESS: u16 = 10_433;

/// Listing: one sellable tier. Addressable with `d` = the listing name.
pub const K_LISTING: u16 = 30_432;

/// Takeover: a warm standby announcing it claims a lease's workload, because
/// the primary it watches went silent (spec §7.1). Addressable with `d` = the
/// workload id, so one standby leaves one claim per workload rather than a
/// history. Signed by the STANDBY, never by the primary.
pub const K_TAKEOVER: u16 = 30_433;

/// Image Registry entry. Addressable with `d` = `<name>:<tag>`. Signed by a
/// PUBLISHER, never by a provider (`nostr::image_events`).
pub const K_IMAGE: u16 = 30_434;

/// Blob Record. Addressable with `d` = `sha256:<hex>`. Signed by whoever
/// uploaded the parts (`nostr::image_events`).
pub const K_BLOB: u16 = 30_435;

/// Template. Addressable with `d` = the template name. Signed by its author,
/// expanded by the TENANT: a provider never reads one (ADR 0004).
pub const K_TEMPLATE: u16 = 30_436;

/// Deployment: a TENANT-signed statement that a repo's environment is served
/// by a lease. Addressable with `d` = the environment. Reserved in the
/// TOON Network block (spec §3.1.2) but never published by a provider.
pub const K_DEPLOYMENT: u16 = 30_437;

/// Lease Request: a tenant-signed event carried inside request bodies. It is
/// a regular kind that is NEVER PUBLISHED — the provider validates it and
/// must not forward it to any relay.
pub const K_LEASE_REQUEST: u16 = 4_432;

/// Eviction Notice: a provider's signed public record that it evicted a
/// lease, and why. Regular, with an `x` tag of the workload id.
pub const K_EVICTION: u16 = 4_433;

/// The label every directory event carries, as `["L", TOON_LABEL]`.
pub const TOON_LABEL: &str = "toon.network";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_in_their_nip01_classes() {
        // The class is normative; the numbers are the allocation in spec §3.1.
        for replaceable in [K_PROFILE, K_LIVENESS] {
            assert!((10_000..=19_999).contains(&replaceable));
        }
        for addressable in [
            K_LISTING,
            K_TAKEOVER,
            K_IMAGE,
            K_BLOB,
            K_TEMPLATE,
            K_DEPLOYMENT,
        ] {
            assert!((30_000..=39_999).contains(&addressable));
        }
        for regular in [K_LEASE_REQUEST, K_EVICTION] {
            assert!((1_000..=9_999).contains(&regular));
        }
    }

    #[test]
    fn no_paygress_kind_is_reused() {
        let all = [
            K_PROFILE,
            K_LIVENESS,
            K_LISTING,
            K_TAKEOVER,
            K_IMAGE,
            K_BLOB,
            K_TEMPLATE,
            K_DEPLOYMENT,
            K_LEASE_REQUEST,
            K_EVICTION,
        ];
        for paygress in [38383u16, 38384, 38385, 38386, 20384] {
            assert!(!all.contains(&paygress));
        }
        let mut sorted = all.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "kinds must be distinct");
    }
}
