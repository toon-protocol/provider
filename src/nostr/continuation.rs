// The Continuation Token (spec §6.1): the secret a tenant mints for a lease,
// the provider stores against it, and every later request presents.
//
// It answers the one question a provider ever needed answered — is this the
// same party that bought this lease — and it answers nothing else. There is
// no key here, no signature and no identity: a token names nobody and links
// to no other lease, and BOTH parties hold it, so a provider that keeps one
// holds no transferable proof that a named tenant asked it to run anything
// (ADR 0016).
//
// Both sides of the wire are here, because the formula has to be one thing.
// A TENANT mints one `RootSecret` per lease and derives one token per
// provider; a PROVIDER only ever stores one and compares against it. Like
// `gateway_grant`'s builder, the deriving half is for whoever holds the
// tenant's secret — a tenant's own tooling, the wire fixtures — and never
// runs inside a serving provider.
//
// Deriving PER PROVIDER is what keeps a Standby Set honest: every member of
// the set holds a different token by construction, so one member cannot act
// as the tenant against another (spec §7). That is the whole reason the
// derivation exists rather than one secret sent to everybody.
//
// Nothing here can be printed. `ContinuationToken` has a `Debug` that
// redacts and no `Display` at all, and no accessor hands its bytes back —
// serde is the only way out, for the lease table and the wire. A token
// therefore cannot reach a log line, a metric or an error message by
// accident: operational surfaces must not become the leak the signature was.

use std::fmt;

use hkdf::Hkdf;
use nostr_sdk::PublicKey;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::wire::is_lower_hex;

/// The HKDF `info` prefix a Continuation Token is derived under (spec §6.1).
/// The provider's public key follows it as 64 lowercase hex characters, so
/// the whole `info` is ASCII and a second implementation has nothing to
/// guess about byte order or encoding.
pub const CONTINUATION_DOMAIN: &str = "toon-network-continuation:";

/// A tenant's root secret for ONE lease: 32 random bytes it mints and keeps.
///
/// It never leaves the tenant. Everything the lease needs derives from it,
/// so a tenant holds one value per lease rather than a list, and losing one
/// exposes one lease and no other (spec §6.1).
pub struct RootSecret([u8; 32]);

impl RootSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The Continuation Token this lease presents to `provider`:
    ///
    /// ```text
    /// continuation(provider) = HKDF-SHA256(root, "toon-network-continuation:" || provider_pubkey)
    /// ```
    ///
    /// HKDF-SHA256 with the root secret as the input keying material, an
    /// empty salt, the ASCII string above as `info`, and 32 bytes of output.
    pub fn continuation_for(&self, provider: &PublicKey) -> ContinuationToken {
        let info = format!("{}{}", CONTINUATION_DOMAIN, provider.to_hex());
        // An empty salt is HKDF's own default: RFC 5869 extracts with
        // `HashLen` zero bytes when none is given, which is what `None` is
        // here. There is nothing per-lease to put in a salt that the root
        // secret is not already.
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut token = [0u8; 32];
        hk.expand(info.as_bytes(), &mut token)
            .expect("32 bytes is one SHA-256 block, far inside HKDF's limit");
        ContinuationToken(token)
    }
}

/// One lease's Continuation Token: 32 bytes on the wire as 64 lowercase hex
/// characters, in the lease table as the same, and nowhere else.
///
/// `PartialEq` is CONSTANT TIME (`subtle`), so the one comparison the
/// provider makes cannot tell an attacker how much of the stored value it
/// guessed right. Every caller gets that for free — there is no other way to
/// compare two of these.
#[derive(Clone)]
pub struct ContinuationToken([u8; 32]);

impl ContinuationToken {
    /// A token as a request or the lease table spells it: exactly 64
    /// lowercase hex characters. Anything else is not a token.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if !is_lower_hex(hex, 64) {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl PartialEq for ContinuationToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for ContinuationToken {}

/// Redacted on purpose: a `LeaseRecord` or a validated request printed with
/// `{:?}` must not carry the token into a log line (spec §6.1).
impl fmt::Debug for ContinuationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationToken(<redacted>)")
    }
}

impl Serialize for ContinuationToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            hex.push(char::from_digit((byte >> 4) as u32, 16).expect("a nibble is one hex digit"));
            hex.push(
                char::from_digit((byte & 0x0f) as u32, 16).expect("a nibble is one hex digit"),
            );
        }
        serializer.serialize_str(&hex)
    }
}

impl<'de> Deserialize<'de> for ContinuationToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        Self::from_hex(&hex).ok_or_else(|| {
            // The VALUE is never in the message: a refusal a tenant reads,
            // or a log line an operator reads, must not quote a token back.
            D::Error::custom("a continuation token is 64 lowercase hex characters")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token the tenant derived and one the provider read back off disk
    /// are the same token, and two tokens that differ in one bit are not.
    /// Both comparisons go through `subtle`; this is the behaviour, and
    /// `PartialEq`'s body is the constant-time part.
    #[test]
    fn a_token_matches_only_itself() {
        let a = ContinuationToken::from_hex(&"ab".repeat(32)).unwrap();
        let b = ContinuationToken::from_hex(&"ab".repeat(32)).unwrap();
        let c = ContinuationToken::from_hex(&("ab".repeat(31) + "aa")).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn a_token_is_sixty_four_lowercase_hex_characters_and_nothing_else() {
        assert!(ContinuationToken::from_hex(&"ab".repeat(32)).is_some());
        assert!(ContinuationToken::from_hex(&"AB".repeat(32)).is_none());
        assert!(ContinuationToken::from_hex(&"ab".repeat(31)).is_none());
        assert!(ContinuationToken::from_hex("").is_none());
    }

    #[test]
    fn a_token_never_prints_itself() {
        let token = ContinuationToken::from_hex(&"ab".repeat(32)).unwrap();
        let printed = format!("{:?}", token);
        assert!(!printed.contains("ab"), "{}", printed);
    }
}
