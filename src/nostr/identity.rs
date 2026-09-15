// Npub canonicalization and the one check built on it: warm-standby role
// assignment.

/// Role this provider takes on a `WarmStandby` spawn request. `NotAddressed`
/// means the request must be rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarmStandbyRole {
    Primary,
    Standby { index: usize, count: usize },
    NotAddressed,
}

pub fn warm_standby_role(
    self_npub: &str,
    primary_npub: &str,
    standby_providers: &[String],
) -> WarmStandbyRole {
    if npubs_equal(self_npub, primary_npub) {
        return WarmStandbyRole::Primary;
    }
    for (idx, p) in standby_providers.iter().enumerate() {
        if npubs_equal(self_npub, p) {
            return WarmStandbyRole::Standby {
                index: idx,
                count: standby_providers.len(),
            };
        }
    }
    WarmStandbyRole::NotAddressed
}

/// True iff two npub strings name the same key. A provider stores its own
/// npub as hex while a tenant may ship bech32, so both sides must be
/// canonicalized before comparison — direct string comparison silently broke
/// warm standby for every bech32 tenant.
///
/// Falls back to string equality only when *neither* side parses, which keeps
/// placeholder npubs in unit tests working without risking false positives on
/// real keys.
pub fn npubs_equal(a: &str, b: &str) -> bool {
    match (
        nostr_sdk::PublicKey::parse(a),
        nostr_sdk::PublicKey::parse(b),
    ) {
        (Ok(ka), Ok(kb)) => ka == kb,
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => false,
        (Err(_), Err(_)) => a == b,
    }
}

#[cfg(test)]
mod npubs_equal_tests {
    use super::*;

    // Two encodings of one frozen public key.
    const PUBKEY_BECH32: &str = "npub1ae40uj62de87f8tvx56e6ytp5m7jd7l96mh0ew43e8q5wucm7z9q2uqvuc";
    const PUBKEY_HEX: &str = "ee6afe4b4a6e4fe49d6c35359d1161a6fd26fbe5d6eefcbab1c9c147731bf08a";

    #[test]
    fn bech32_matches_itself() {
        assert!(npubs_equal(PUBKEY_BECH32, PUBKEY_BECH32));
    }

    #[test]
    fn hex_matches_itself() {
        assert!(npubs_equal(PUBKEY_HEX, PUBKEY_HEX));
    }

    /// Regression: the provider stores hex, the consumer ships bech32, and
    /// without normalization the role check always returned `NotAddressed`.
    #[test]
    fn bech32_matches_hex_for_same_key() {
        assert!(npubs_equal(PUBKEY_BECH32, PUBKEY_HEX));
        assert!(npubs_equal(PUBKEY_HEX, PUBKEY_BECH32));
    }

    #[test]
    fn different_keys_in_different_encodings_do_not_match() {
        let other_bech32 = "npub1hyr9m7zeegr98w4e07gvdpqrk25jfp3vku8029u8pcxsc48dq6nqxtwztv";
        assert!(!npubs_equal(PUBKEY_HEX, other_bech32));
    }

    #[test]
    fn unparseable_strings_fall_back_to_string_equality() {
        assert!(npubs_equal("npub1primary", "npub1primary"));
        assert!(!npubs_equal("npub1primary", "npub1secondary"));
    }

    #[test]
    fn one_real_one_typoed_returns_false() {
        assert!(!npubs_equal(PUBKEY_BECH32, "npub1primary"));
        assert!(!npubs_equal("npub1primary", PUBKEY_HEX));
    }
}
