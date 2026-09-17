// The Gateway Grant (spec §3.1.3): a tenant's signed, published delegation
// that lets one Workload Gateway read a workload's lease state and access
// details until the grant expires.
//
// Like the §8 events in `image_events`, this one is NOT a provider's: the
// TENANT signs it, and the provider only ever reads one. So there is no
// `ProviderConfig` and no provider key here — the builder is for whoever
// holds the tenant's key (the sandbox's `grant` tool, a tenant's own
// tooling, the wire fixtures), and `check` is the provider's whole side of
// the bargain.
//
// It delegates ONE thing: reading `status` (§6.5). It buys nothing, extends
// nothing and ends nothing, and no other route reads it.
//
// The provider verifies a grant FROM THE REQUEST THAT CARRIED IT and
// nothing else. It never fetches one from a relay and never stores one, so
// a Hidden Provider's `status` still costs it no outbound connection (spec
// §10) and ADR 0005's rule that identity comes from the signed request
// holds unchanged. The cost of that is stated in §6.5: a grant is revoked
// by expiring, and a tenant that wants a gateway cut off sooner respawns
// under a new workload id.

use anyhow::Result;
use nostr_sdk::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, Timestamp};
use serde::{Deserialize, Serialize};

use super::kinds::{K_GATEWAY_GRANT, TOON_LABEL};
use super::wire::{ErrorCode, ErrorResponse};

/// The content of a Gateway Grant (`K_GATEWAY_GRANT`, addressable), spec
/// §3.1.3. The `d` tag carries the `workload_id` too, so a gateway finds a
/// grant by the workload it is about; both are checked against the request,
/// because a relay's `#d` filter and the signed content must not be able to
/// disagree.
///
/// `standby_set` and `http_port` are for the GATEWAY, not the provider: they
/// say which providers to ask and which of the spawn's ports is the HTTP one
/// (ADR 0013's one open question). A provider reads neither — it already
/// knows both — and MUST NOT act on them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantContent {
    /// The workload this grant is about: 64 lowercase hex characters, the
    /// tenant's own id (spec §6.2).
    pub workload_id: String,
    /// The gateway this grant names: its Nostr public key, hex. Exactly one,
    /// and the only key whose `status` this grant admits.
    pub gateway: String,
    /// Which of the spawn's `ports` the gateway forwards HTTP to, as the
    /// CONTAINER port the spawn asked for — the host port is the provider's
    /// to choose and comes back in `access` (spec §6.2).
    pub http_port: u16,
    /// Every member of the workload's Standby Set, primary first (spec §7).
    /// A standalone lease's has one entry.
    pub standby_set: Vec<String>,
    /// Unix seconds. After this the grant admits nothing, and there is no
    /// other way to revoke it (spec §6.5).
    pub expires_at: u64,
    /// An optional readable label a gateway MAY serve the workload at
    /// beside its canonical name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Build and sign a Gateway Grant with the TENANT's key.
///
/// Addressable on `d = <workload_id>`, so republishing under the same
/// workload id — a new expiry, a different gateway — replaces the grant
/// rather than adding one: renewal and rotation are the same act as
/// publishing (spec §3.1.3). The `p` tag is what lets a gateway find every
/// grant naming it with one relay filter, and `["L","toon.network"]` is the
/// label every published TOON Network event carries (§4).
pub fn gateway_grant_event(content: &GrantContent, tenant: &Keys, now: u64) -> Result<Event> {
    Ok(EventBuilder::new(
        Kind::Custom(K_GATEWAY_GRANT),
        serde_json::to_string(content)?,
    )
    .tags([
        Tag::identifier(content.workload_id.clone()),
        Tag::custom(TagKind::p(), [content.gateway.clone()]),
        Tag::custom(TagKind::custom("L"), [TOON_LABEL]),
    ])
    .custom_created_at(Timestamp::from(now))
    .sign_with_keys(tenant)?)
}

/// Does `grant` let `gateway` read this lease's status right now?
///
/// Every one of spec §6.5's conditions, and the single refusal all of them
/// share. One code on purpose: a gateway holding a grant that does not
/// apply learns that the grant does not apply, and nothing about the lease —
/// not whose it is, not when it ends — which is what `not_tenant` would
/// otherwise start to leak to anyone willing to guess.
///
/// `tenant` is the lease's own tenant, `workload_id` the one the REQUEST
/// named, and `gateway` the key that signed the request. Nothing is read
/// from anywhere else: that is the point (see the module note).
pub fn check(
    grant: &Event,
    tenant: &PublicKey,
    workload_id: &str,
    gateway: &PublicKey,
    now: u64,
) -> Result<(), ErrorResponse> {
    if grant.verify().is_err() {
        return Err(bad_grant("the grant's own id or signature does not verify"));
    }
    if grant.kind.as_u16() != K_GATEWAY_GRANT {
        return Err(bad_grant(format!(
            "a Gateway Grant is kind {}, not {}",
            K_GATEWAY_GRANT,
            grant.kind.as_u16()
        )));
    }
    if grant.pubkey != *tenant {
        return Err(bad_grant(
            "the grant was not signed by this lease's tenant, so it delegates nothing here",
        ));
    }
    let content: GrantContent = serde_json::from_str(&grant.content)
        .map_err(|e| bad_grant(format!("the grant's content: {}", e)))?;
    let identifier = grant
        .tags
        .find(TagKind::d())
        .and_then(|t| t.content())
        .unwrap_or_default();
    if identifier != workload_id || content.workload_id != workload_id {
        return Err(bad_grant(format!(
            "the grant is about another workload (`d` {:?}, content {:?})",
            identifier, content.workload_id
        )));
    }
    // Compared as PUBLIC KEYS, not as strings: the same key has more than
    // one hex spelling, and a grant that named its gateway in the other one
    // would be refused for no reason a tenant could see.
    let granted = PublicKey::parse(&content.gateway)
        .map_err(|_| bad_grant("the grant's `gateway` is not a public key"))?;
    if granted != *gateway {
        return Err(bad_grant(
            "the grant names another gateway; a grant admits exactly the one key it names",
        ));
    }
    if now > content.expires_at {
        return Err(bad_grant(format!(
            "the grant expired at {} (now {}); a tenant renews one by publishing it again",
            content.expires_at, now
        )));
    }
    Ok(())
}

fn bad_grant(message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::BadGrant, message)
}
