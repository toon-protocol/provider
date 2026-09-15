// Lease Request validation (spec §6.1).
//
// A Lease Request is a tenant-signed event carried inside a request body. It
// is what binds a lease to a tenant: the provider never learns who PAID (ADR
// 0005), only who SIGNED. So everything here is about the signature, who the
// request is addressed to, whether it is fresh, and whether it was seen
// before — and nothing about money.

use std::collections::HashMap;
use std::sync::Mutex;

use nostr_sdk::{Event, EventId, PublicKey, TagKind};

use super::kinds::K_LEASE_REQUEST;
use super::wire::{ErrorCode, ErrorResponse};

/// A request whose `expiration` is more than this far past its `created_at`
/// is refused as stale: a tenant has no reason to sign something valid for
/// longer, and a captured request should not stay replayable for long.
pub const MAX_REQUEST_WINDOW_SECS: u64 = 300;

/// The `op` tag: what the signed request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Spawn,
    Status,
    Terminate,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Spawn => "spawn",
            Op::Status => "status",
            Op::Terminate => "terminate",
        }
    }
}

/// What survives validation: who signed, until when it is good, and the
/// content to parse per op.
#[derive(Debug, Clone)]
pub struct ValidLeaseRequest {
    pub id: EventId,
    /// The tenant: the event's signer.
    pub tenant: PublicKey,
    pub expiration: u64,
    pub content: String,
}

/// Validate a Lease Request against this provider, in the spec's order: the
/// signature, the kind, the `p` tag, the `op` tag, then freshness. Replay is
/// `AcceptedRequests`, checked by the caller once everything here passed.
pub fn validate(
    event: &Event,
    provider: &PublicKey,
    op: Op,
    now: u64,
) -> Result<ValidLeaseRequest, ErrorResponse> {
    if event.verify().is_err() {
        return Err(ErrorResponse::new(
            ErrorCode::BadSignature,
            "the Lease Request's id or signature does not verify",
        ));
    }
    if event.kind.as_u16() != K_LEASE_REQUEST {
        return Err(ErrorResponse::new(
            ErrorCode::InvalidRequest,
            format!(
                "a Lease Request is kind {}, not {}",
                K_LEASE_REQUEST,
                event.kind.as_u16()
            ),
        ));
    }
    match event.tags.public_keys().next() {
        None => {
            return Err(ErrorResponse::new(
                ErrorCode::InvalidRequest,
                "the Lease Request names no provider (`p` tag)",
            ))
        }
        Some(p) if p != provider => {
            return Err(ErrorResponse::new(
                ErrorCode::InvalidRequest,
                "the Lease Request is addressed to another provider",
            ))
        }
        Some(_) => {}
    }
    let found_op = event
        .tags
        .find(TagKind::custom("op"))
        .and_then(|t| t.content());
    if found_op != Some(op.as_str()) {
        return Err(ErrorResponse::new(
            ErrorCode::InvalidRequest,
            format!(
                "this route serves op={}, the Lease Request says op={}",
                op.as_str(),
                found_op.unwrap_or("<none>")
            ),
        ));
    }
    let expiration = match event.tags.expiration() {
        Some(t) => t.as_u64(),
        None => {
            return Err(ErrorResponse::new(
                ErrorCode::InvalidRequest,
                "the Lease Request carries no `expiration` tag",
            ))
        }
    };
    if now > expiration {
        return Err(ErrorResponse::new(
            ErrorCode::StaleRequest,
            format!("the Lease Request expired at {} (now {})", expiration, now),
        ));
    }
    match expiration.checked_sub(event.created_at.as_u64()) {
        Some(window) if window <= MAX_REQUEST_WINDOW_SECS => {}
        _ => {
            return Err(ErrorResponse::new(
                ErrorCode::StaleRequest,
                format!(
                    "a Lease Request may be valid for at most {} s after created_at",
                    MAX_REQUEST_WINDOW_SECS
                ),
            ))
        }
    }
    Ok(ValidLeaseRequest {
        id: event.id,
        tenant: event.pubkey,
        expiration,
        content: event.content.clone(),
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
    seen: Mutex<HashMap<EventId, u64>>,
}

impl AcceptedRequests {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `id` as accepted until `expiration`. `false` if it was already
    /// accepted — the caller refuses the request.
    pub fn accept(&self, id: EventId, expiration: u64, now: u64) -> bool {
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, until| *until >= now);
        if seen.contains_key(&id) {
            return false;
        }
        seen.insert(id, expiration);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replayed_id_is_refused_until_it_expires() {
        let seen = AcceptedRequests::new();
        let id = EventId::all_zeros();
        assert!(seen.accept(id, 100, 50));
        assert!(!seen.accept(id, 100, 60), "same id, still valid");
        assert!(seen.accept(id, 200, 101), "expired ids are forgotten");
    }
}
