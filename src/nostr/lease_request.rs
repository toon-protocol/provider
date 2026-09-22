// Lease Request validation (spec §6.1).
//
// A Lease Request is a plain JSON object carried inside a request body. It is
// what binds a lease to the party that bought it: the provider never learns
// who PAID (ADR 0005), and after ADR 0016 it never learns who ASKED either —
// only that whoever is asking now holds the Continuation Token that took the
// lease. So everything here is about the token, who the request is addressed
// to, whether it is fresh, and whether it was seen before — and nothing
// about money, and nothing about identity.
//
// Nothing is hashed or canonically serialised on either side. The tenant
// chooses `request_id` at random, so the replay set keys on it exactly as it
// once keyed on an event id, and two implementations have no serialisation
// to disagree about.

use std::collections::HashMap;
use std::sync::Mutex;

use nostr_sdk::PublicKey;
use serde_json::Value;

use super::continuation::ContinuationToken;
use super::wire::{is_lower_hex, ErrorCode, ErrorResponse, LeaseRequest, LeaseRequestEnvelope, Op};

/// A request whose `expiration` is more than this far ahead of now is
/// refused as stale: a tenant has no reason to mint one valid for longer,
/// and a captured request should not stay replayable for long.
pub const MAX_REQUEST_WINDOW_SECS: u64 = 300;

/// What survives validation: the id it was booked under, until when it is
/// good, the token it presented, and the content to parse per op.
///
/// No tenant. There is nobody to name: a Continuation Token is not an
/// identity, and the provider holds nothing else about whoever sent this
/// (ADR 0016).
#[derive(Debug, Clone)]
pub struct ValidLeaseRequest {
    /// 32 tenant-chosen random bytes, hex. The replay set's key.
    pub request_id: String,
    pub expiration: u64,
    /// The token the request presented, if it presented one. Compared
    /// against a lease's stored token by `check_continuation`; on a spawn
    /// there is nothing to compare it with yet, and it becomes the new
    /// lease's (`continuation_to_store`).
    pub continuation: Option<ContinuationToken>,
    pub content: Value,
}

/// Accept the Lease Request in a request body: parse it, validate it, and
/// book its id against replay — steps 1 to 3 of the spec's validation order
/// (§6.1), which every authenticated route runs identically.
///
/// Step 4, the Continuation Token, is `check_continuation`: it needs the
/// lease, which only the caller has found by then. A spawn skips it, because
/// there is no stored token until this request makes one.
pub fn accept(
    body: &[u8],
    provider: &PublicKey,
    op: Op,
    now: u64,
    seen: &AcceptedRequests,
) -> Result<ValidLeaseRequest, ErrorResponse> {
    let envelope: LeaseRequestEnvelope = serde_json::from_slice(body).map_err(|e| {
        ErrorResponse::new(
            ErrorCode::InvalidRequest,
            format!("body is not {{ \"request\": {{ … }} }}: {}", e),
        )
    })?;
    let request = validate(envelope.request, provider, op, now)?;
    // Booked as soon as the request is known to be fresh and ours, so a
    // captured refusal cannot be replayed onto a route that would accept it.
    if !seen.accept(&request.request_id, request.expiration, now) {
        return Err(ErrorResponse::new(
            ErrorCode::StaleRequest,
            "this Lease Request was already accepted; send a new one",
        ));
    }
    Ok(request)
}

/// Validate a Lease Request against this provider, in the spec's order: the
/// shape, the `op` and the addressee (`invalid_request`), then `expiration`
/// and the window (`stale_request`). Replay is `AcceptedRequests`, booked by
/// `accept` once everything here passed.
pub fn validate(
    request: LeaseRequest,
    provider: &PublicKey,
    op: Op,
    now: u64,
) -> Result<ValidLeaseRequest, ErrorResponse> {
    if !is_lower_hex(&request.request_id, 64) {
        return Err(ErrorResponse::new(
            ErrorCode::InvalidRequest,
            "request_id is 32 random bytes as 64 lowercase hex characters",
        ));
    }
    if request.op != op {
        return Err(ErrorResponse::new(
            ErrorCode::InvalidRequest,
            format!(
                "this route serves op={}, the Lease Request says op={}",
                op.as_str(),
                request.op.as_str()
            ),
        ));
    }
    // ONE provider, on every op — a spawn that forms a Standby Set included.
    // A tenant sends one request to each member now, so nothing is saved by
    // addressing one request to several, and a request meant for somebody
    // else is never accepted here (spec §6.1, §7).
    let addressee = PublicKey::parse(&request.provider).map_err(|e| {
        ErrorResponse::new(
            ErrorCode::InvalidRequest,
            format!("the Lease Request's `provider` is not a public key: {}", e),
        )
    })?;
    if addressee != *provider {
        return Err(ErrorResponse::new(
            ErrorCode::InvalidRequest,
            "the Lease Request is addressed to another provider",
        ));
    }
    if now > request.expiration {
        return Err(ErrorResponse::new(
            ErrorCode::StaleRequest,
            format!(
                "the Lease Request expired at {} (now {})",
                request.expiration, now
            ),
        ));
    }
    if request.expiration > now + MAX_REQUEST_WINDOW_SECS {
        return Err(ErrorResponse::new(
            ErrorCode::StaleRequest,
            format!(
                "a Lease Request may be valid for at most {} s from now",
                MAX_REQUEST_WINDOW_SECS
            ),
        ));
    }
    Ok(ValidLeaseRequest {
        request_id: request.request_id,
        expiration: request.expiration,
        continuation: request.continuation,
        content: request.content,
    })
}

/// Step 4 of the validation order (spec §6.1): the token this request
/// presented is the one the lease stored.
///
/// The comparison is constant time — that is `ContinuationToken`'s own
/// `PartialEq`, so there is no other way to make it — and the refusal says
/// nothing about the lease and quotes no token back.
///
/// A wrong token and an ABSENT one are the same answer, deliberately. A
/// request with no `continuation` asserts no authority over this lease, and
/// that is exactly what a wrong one does; telling the two apart would leave
/// a prober knowing which half of its guess was wrong, and an absent token
/// must never read as an unauthenticated success.
pub fn check_continuation(
    request: &ValidLeaseRequest,
    stored: &ContinuationToken,
) -> Result<(), ErrorResponse> {
    if presents(request, stored) {
        Ok(())
    } else {
        Err(not_tenant())
    }
}

/// Is `token` the value this request presented?
///
/// The one comparison this module makes, so its three call sites cannot
/// drift on it. It is CONSTANT TIME — that is `ContinuationToken`'s own
/// `PartialEq`, and there is no other way to compare two — and a request
/// that presented nothing at all is simply `false`: an absent value asserts
/// no authority, which is exactly what a wrong one does.
fn presents(request: &ValidLeaseRequest, token: &ContinuationToken) -> bool {
    request.continuation.as_ref() == Some(token)
}

/// Step 4 as the `status` route runs it (spec §6.5.1): the lease's own token,
/// or a Gateway Grant derived from it for the moment the request names.
///
/// The order is the whole of it, and none of it is an optimisation:
///
/// 1. The lease's stored token, in constant time. A match is FULL AUTHORITY,
///    so a tenant is never weighed against a delegation it did not assert,
///    and the ordinary path is the one comparison `terminate` makes.
/// 2. Failing that, and only with an `asserted` moment: `now <= asserted`,
///    checked BEFORE anything is derived. A delegation that has expired is
///    refused on the moment it named, so a provider derives nothing at all
///    for a grant that could not apply however well it was formed.
/// 3. Then `gateway_sub` for that one moment, in constant time. A match is
///    READ AUTHORITY, and the caller answers byte for byte what the tenant
///    would have been answered.
///
/// **The assertion decides the refusal.** Anything that is neither is
/// refused on what the request CLAIMED rather than on what it got wrong: a
/// request that asserted a delegation hears `bad_grant`, one that asserted
/// none hears `not_tenant`. A grant derived for another moment, a grant for
/// another lease, an expired one and a value that is no grant at all are one
/// code, so a gateway learns that its delegation does not apply here and
/// nothing about the lease — not whose it is, not when it ends.
pub fn check_status_continuation(
    request: &ValidLeaseRequest,
    stored: &ContinuationToken,
    asserted: Option<u64>,
    now: u64,
) -> Result<(), ErrorResponse> {
    if presents(request, stored) {
        return Ok(());
    }
    let Some(expires_at) = asserted else {
        return Err(not_tenant());
    };
    if now > expires_at {
        return Err(bad_grant(format!(
            "this delegation was derived for {}, which passed at {}; a tenant renews one by \
             deriving it again for a later moment",
            expires_at, now
        )));
    }
    if presents(request, &stored.gateway_sub(expires_at)) {
        Ok(())
    } else {
        Err(bad_grant(
            "this delegation does not apply here; ask the tenant for one derived for this \
             workload and this moment",
        ))
    }
}

/// A request presenting a token that is not the lease's — or none at all —
/// and asserting no delegation that might excuse it.
fn not_tenant() -> ErrorResponse {
    ErrorResponse::new(
        ErrorCode::NotTenant,
        "this lease was taken with another continuation token",
    )
}

/// A request that asserted a delegation which does not admit it. The message
/// quotes the moment the REQUEST named and the clock, and nothing about the
/// lease; no token is ever in it (spec §6.1.1).
fn bad_grant(message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::BadGrant, message)
}

/// The token a SPAWN stores against the lease it is about to create.
///
/// The mirror of `check_continuation`, and the other half of why step 4 is
/// skipped on a spawn: there is nothing stored to compare with, so the
/// presented token is simply kept. Absent, it is `invalid_request` rather
/// than `not_tenant` — a spawn with no token would buy a lease nobody could
/// ever read, extend or stop, which is a request the tenant must correct.
pub fn continuation_to_store(
    request: &ValidLeaseRequest,
) -> Result<ContinuationToken, ErrorResponse> {
    request.continuation.clone().ok_or_else(|| {
        ErrorResponse::new(
            ErrorCode::InvalidRequest,
            "a spawn carries the continuation token its lease will keep",
        )
    })
}

/// The ids of Lease Requests this provider has accepted, kept until they
/// expire, so a captured request cannot be replayed (spec §6.1).
///
/// In memory only: a restart forgets them, so a request captured within
/// `MAX_REQUEST_WINDOW_SECS` of a restart could be replayed once. Bounded
/// loss; persisting the set is a later ticket's call.
#[derive(Default)]
pub struct AcceptedRequests {
    seen: Mutex<HashMap<String, u64>>,
}

impl AcceptedRequests {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `request_id` as accepted until `expiration`. `false` if it was
    /// already accepted — the caller refuses the request.
    pub fn accept(&self, request_id: &str, expiration: u64, now: u64) -> bool {
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, until| *until >= now);
        if seen.contains_key(request_id) {
            return false;
        }
        seen.insert(request_id.to_string(), expiration);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replayed_id_is_refused_until_it_expires() {
        let seen = AcceptedRequests::new();
        let id = "aa".repeat(32);
        assert!(seen.accept(&id, 100, 50));
        assert!(!seen.accept(&id, 100, 60), "same id, still valid");
        assert!(seen.accept(&id, 200, 101), "expired ids are forgotten");
    }
}
