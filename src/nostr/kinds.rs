// Event kinds of the TOON Network protocol.
//
// EVERY NUMBER HERE IS A PLACEHOLDER, NOT AN ALLOCATION (spec §11, item 1).
// What is normative is each kind's NIP-01 class — regular (1000..=9999),
// replaceable (10000..=19999) or addressable (30000..=39999) — because the
// class decides how a relay stores and replaces the event. The numbers will
// change when kinds are allocated; nothing may depend on their values beyond
// "distinct from each other and in the right class".
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

/// Takeover: a warm standby announcing it runs a lease's workload.
/// Addressable with `d` = the workload id. Not used in Milestone 1.
pub const K_TAKEOVER: u16 = 30_433;

/// Image Registry entry. Addressable with `d` = `<name>:<tag>`. Not used in
/// Milestone 1.
pub const K_IMAGE: u16 = 30_434;

/// Blob Record. Addressable with `d` = `sha256:<hex>`. Not used in Milestone 1.
pub const K_BLOB: u16 = 30_435;

/// Template. Addressable with `d` = the template name. Not used in Milestone 1.
pub const K_TEMPLATE: u16 = 30_436;

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
        // The class is normative even though the number is not.
        for replaceable in [K_PROFILE, K_LIVENESS] {
            assert!((10_000..=19_999).contains(&replaceable));
        }
        for addressable in [K_LISTING, K_TAKEOVER, K_IMAGE, K_BLOB, K_TEMPLATE] {
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
