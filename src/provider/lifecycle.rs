// What happens to a lease after the spawn: Extension, Status and Termination
// (spec §6.3, §6.5, §6.6).
//
// The three differ in who may ask. An Extension only ADDS time and reveals
// nothing, so it carries no signature and any payer may buy one for any lease
// (ADR 0005) — a sponsor pays for a lease it does not own. Status and
// Termination reveal or destroy, so both carry a tenant-signed Lease Request
// and refuse anyone else with `not_tenant`.
//
// A lease is named by the tenant's own `workload_id`, never by the backend id
// this provider keys its table on: the tenant chose that id and it is the only
// handle it has.

use std::collections::HashMap;

use nostr_sdk::PublicKey;

use super::cleanup::end_lease;
use super::persistence::{persist_leases, LeaseEnd, LeaseRecord, LeaseState};
use crate::nostr::lease_request::{self, Op};
use crate::nostr::wire::{
    ErrorCode, ErrorResponse, ExtendRequest, ExtendResponse, LeaseRequestEnvelope, StatusResponse,
    TerminateResponse, WorkloadContent,
};
use crate::provider_http::AppState;

fn invalid(message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::InvalidRequest, message)
}

fn unknown_workload() -> ErrorResponse {
    ErrorResponse::new(
        ErrorCode::UnknownWorkload,
        "this provider holds no lease with that workload_id",
    )
}

/// The lease a `workload_id` names: the live one if there is one, otherwise
/// the most recently ended record still retained.
///
/// A tenant may spawn the same id again once its lease is over, so both can
/// exist at once; the live lease is the one every route means.
fn find(leases: &HashMap<u32, LeaseRecord>, workload_id: &str) -> Option<u32> {
    let mut candidates: Vec<&LeaseRecord> = leases
        .values()
        .filter(|l| l.workload_id == workload_id)
        .collect();
    candidates.sort_by_key(|l| (l.state.is_live(), l.ended_at.unwrap_or(0), l.created_at));
    candidates.last().map(|l| l.id)
}

/// Why a lease that is no longer live can buy nothing and end nothing.
fn already_ended(state: LeaseState) -> ErrorResponse {
    let how = match state {
        LeaseState::Ended(LeaseEnd::Expiry) => "expired",
        LeaseState::Ended(LeaseEnd::Termination) => "was terminated",
        LeaseState::Ended(LeaseEnd::Eviction) => "was evicted",
        _ => "is over",
    };
    ErrorResponse::new(
        ErrorCode::Expired,
        format!("this lease {}; spawn a new one", how),
    )
}

/// Serve one extension on `<addr>.<listing>.v<version>.extend`.
///
/// The money is already spent when this runs (ADR 0003), so a refusal is
/// billed like a success. It buys time on the lease's OWN listing version:
/// a lease keeps the price it started at (ADR 0009), and an extension bought
/// on another version's route would be bought at another price.
pub async fn extend(
    state: &AppState,
    listing_name: &str,
    version: u32,
    body: &[u8],
) -> Result<ExtendResponse, ErrorResponse> {
    let request: ExtendRequest = serde_json::from_slice(body)
        .map_err(|e| invalid(format!("body is not {{ \"workload_id\": \"…\" }}: {}", e)))?;

    let mut leases = state.leases.lock().await;
    let id = find(&leases, &request.workload_id).ok_or_else(unknown_workload)?;
    let lease = leases.get(&id).ok_or_else(unknown_workload)?;
    if !lease.state.is_live() {
        return Err(already_ended(lease.state));
    }
    if lease.listing != listing_name || lease.listing_version != version {
        return Err(ErrorResponse::new(
            ErrorCode::WrongListingVersion,
            format!(
                "this lease was spawned on {} v{}; extend it there",
                lease.listing, lease.listing_version
            ),
        ));
    }
    // The lease's own version, which is the route's: the interval a payment
    // buys is the one the lease was sold under.
    let interval = state
        .config
        .listing(&lease.listing, lease.listing_version)
        .ok_or_else(|| {
            ErrorResponse::new(
                ErrorCode::WrongListingVersion,
                format!(
                    "this provider no longer sells {} v{}",
                    lease.listing, version
                ),
            )
        })?
        .lease_interval_s;

    let lease = leases.get_mut(&id).ok_or_else(unknown_workload)?;
    lease.expires_at = lease.expires_at.saturating_add(interval);
    let expires_at = lease.expires_at;
    persist_leases(&leases, &state.config.lease_state_path);

    Ok(ExtendResponse {
        workload_id: request.workload_id,
        expires_at,
    })
}

/// Serve one status on the free `<addr>.status`.
pub async fn status(state: &AppState, body: &[u8]) -> Result<StatusResponse, ErrorResponse> {
    let (tenant, workload_id) = authenticate(state, body, Op::Status).await?;

    let leases = state.leases.lock().await;
    let id = find(&leases, &workload_id).ok_or_else(unknown_workload)?;
    let lease = leases.get(&id).ok_or_else(unknown_workload)?;
    check_tenant(lease, &tenant)?;

    Ok(StatusResponse {
        workload_id: lease.workload_id.clone(),
        role: lease.role,
        state: lease.state,
        expires_at: lease.expires_at,
        // An ended lease has no workload left, so it has nothing to reach.
        access: lease
            .state
            .is_live()
            .then(|| lease.access(&state.config.public_ip)),
    })
}

/// Serve one termination on the free `<addr>.terminate`: the workload is
/// destroyed now, and nothing is refunded (ADR 0003).
pub async fn terminate(state: &AppState, body: &[u8]) -> Result<TerminateResponse, ErrorResponse> {
    let (tenant, workload_id) = authenticate(state, body, Op::Terminate).await?;
    let now = state.clock.now();

    let id = {
        let leases = state.leases.lock().await;
        let id = find(&leases, &workload_id).ok_or_else(unknown_workload)?;
        let lease = leases.get(&id).ok_or_else(unknown_workload)?;
        check_tenant(lease, &tenant)?;
        if !lease.state.is_live() {
            return Err(already_ended(lease.state));
        }
        id
    };

    // `end_lease` re-checks liveness under the lock, so a sweep that reaped
    // this lease between the two is reported as an ending, not destroyed
    // twice.
    if !end_lease(state, id, LeaseEnd::Termination, now).await {
        return Err(already_ended(LeaseState::Ended(LeaseEnd::Expiry)));
    }

    Ok(TerminateResponse {
        workload_id,
        state: LeaseState::Ended(LeaseEnd::Termination),
    })
}

/// The Lease Request on a signed free route: validated exactly as a spawn's
/// is, replay included, and parsed down to the workload id it names.
async fn authenticate(
    state: &AppState,
    body: &[u8],
    op: Op,
) -> Result<(PublicKey, String), ErrorResponse> {
    let now = state.clock.now();
    let envelope: LeaseRequestEnvelope = serde_json::from_slice(body)
        .map_err(|e| invalid(format!("body is not {{ \"request\": <event> }}: {}", e)))?;
    let request = lease_request::validate(&envelope.request, &state.keys.public_key(), op, now)?;
    if !state
        .accepted_requests
        .accept(request.id, request.expiration, now)
    {
        return Err(ErrorResponse::new(
            ErrorCode::StaleRequest,
            "this Lease Request was already accepted; sign a new one",
        ));
    }
    let content: WorkloadContent = serde_json::from_str(&request.content)
        .map_err(|e| invalid(format!("{} content: {}", op.as_str(), e)))?;
    Ok((request.tenant, content.workload_id))
}

/// The signer must be the lease's tenant. Compared as public keys, not as
/// strings: the same key has more than one hex spelling.
fn check_tenant(lease: &LeaseRecord, signer: &PublicKey) -> Result<(), ErrorResponse> {
    let tenant = PublicKey::parse(&lease.tenant).map_err(|_| not_tenant())?;
    if tenant == *signer {
        Ok(())
    } else {
        Err(not_tenant())
    }
}

fn not_tenant() -> ErrorResponse {
    ErrorResponse::new(ErrorCode::NotTenant, "this lease belongs to another tenant")
}
