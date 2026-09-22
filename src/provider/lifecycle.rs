// What happens to a lease after the spawn: Extension, Status, Termination
// and Rotation (spec §6.3, §6.5, §6.6, §6.8).
//
// They differ in who may ask. An Extension only ADDS time and reveals
// nothing, so it carries no Lease Request at all and any payer may buy one
// for any lease (ADR 0005) — a sponsor pays for a lease it does not own.
// Status, Termination and Rotation reveal, destroy or replace the token, so
// each carries a Lease Request presenting the lease's Continuation Token, and
// refuses anyone else with `not_tenant`.
//
// The question the three ask is NOT who is this. It is whether whoever is
// asking holds the token this lease holds now — the one it was taken with,
// or the one a rotation put in its place (ADR 0016, ADR 0018) — which is the
// only question the provider ever needed answered and the one that leaks
// nothing: the comparison is constant time, and the token reaches no log,
// no metric and no message.
//
// Status asks ONE thing more, because reading is the one authority a tenant
// can hand on: a Workload Gateway may present a Gateway Grant derived from
// the lease's token for a moment the tenant chose (spec §6.5.1), which the
// provider recomputes from the token it already holds. That is the whole of
// the delegation — nothing is fetched, nothing is stored per gateway, and
// neither `terminate` nor `rotate` is part of it. Rotation is how a tenant
// ends every delegation at once: it replaces the one token each grant is
// recomputed from.
//
// A lease is named by the tenant's own `workload_id`, never by the backend id
// this provider keys its table on: the tenant chose that id and it is the only
// handle it has.

use std::collections::HashMap;

use tracing::error;

use super::cleanup::end_lease;
use super::persistence::{persist_leases, LeaseEnd, LeaseRecord, LeaseState};
use crate::nostr::directory_events::eviction_event;
use crate::nostr::lease_request::{self, ValidLeaseRequest};
use crate::nostr::wire::{
    ErrorCode, ErrorResponse, EvictResponse, EvictionReason, ExtendRequest, ExtendResponse, Op,
    RotateContent, RotateResponse, StatusContent, StatusResponse, TakeoverStatus,
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

/// `.standby.extend` met a running lease of any role: it is billed at its
/// own price on `.extend`, not this one's (spec §6.3).
fn not_standby() -> ErrorResponse {
    ErrorResponse::new(
        ErrorCode::NotStandby,
        "this lease is not a Warm Standby; extend it on .extend",
    )
}

/// `.extend` met a Warm Standby reservation: the mirror of `not_standby`
/// above. A lease is always billed at the price for what it is doing (spec
/// §6.3), and a reservation's price is `standby_price` on `.standby.extend`.
fn not_running() -> ErrorResponse {
    ErrorResponse::new(
        ErrorCode::NotRunning,
        "this lease is a Warm Standby reservation, not a running lease; extend it on \
         .standby.extend",
    )
}

/// The lease state could not be saved (spec §5, general; TOON_Network#78).
/// Nothing changed — the caller restores whatever it changed in memory
/// before returning this — and the tenant should retry.
fn unavailable() -> ErrorResponse {
    ErrorResponse::new(
        ErrorCode::Unavailable,
        "this provider could not save that right now; nothing changed, try again",
    )
}

/// The backend id of the lease a tenant's `workload_id` names: the live one
/// if there is one, otherwise the most recently ended record still retained.
///
/// A tenant may spawn the same id again once its lease is over, so both can
/// exist at once; the live lease is the one every route means.
fn lease_id_for(leases: &HashMap<u32, LeaseRecord>, workload_id: &str) -> Option<u32> {
    let mut candidates: Vec<&LeaseRecord> = leases
        .values()
        .filter(|l| l.workload_id == workload_id)
        .collect();
    candidates.sort_by_key(|l| (l.state.is_live(), l.ended_at.unwrap_or(0), l.created_at));
    candidates.last().map(|l| l.id)
}

/// A lease that is over can buy nothing and end nothing. `expired` is the
/// spec's code for all three endings (§6.3 names no other): the lease is
/// over, and the message says how.
///
/// `Ok` only while the lease still applies. A lease whose `expires_at` has
/// passed is over the instant it passes, whether or not the sweep has
/// reached it yet: there is no grace period (ADR 0003), and the ≤30 s
/// between the two must not be a window in which a payment buys time on a
/// lease that is already dead.
fn still_running(lease: &LeaseRecord, now: u64) -> Result<(), ErrorResponse> {
    let how = match lease.state {
        LeaseState::Ended(LeaseEnd::Expiry) => "expired",
        LeaseState::Ended(LeaseEnd::Termination) => "was terminated",
        LeaseState::Ended(LeaseEnd::Eviction) => "was evicted",
        _ if lease.expires_at <= now => "expired",
        _ => return Ok(()),
    };
    Err(ErrorResponse::new(
        ErrorCode::Expired,
        format!("this lease {}; spawn a new one", how),
    ))
}

/// Which of the two paid extension routes a request arrived on: the whole of
/// what tells `extend_lease` which role the lease it finds must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtendRoute {
    /// `<addr>.<listing>.v<n>.extend`, at the listing's `price`.
    Extend,
    /// `<addr>.<listing>.v<n>.standby.extend`, at its `standby_price`.
    StandbyExtend,
}

/// Serve one extension on `<addr>.<listing>.v<version>.extend`.
///
/// The money is already spent when this runs (ADR 0003), so a refusal is
/// billed like a success. It buys time on the lease's OWN listing version:
/// a lease keeps the price it started at (ADR 0009), and an extension bought
/// on another version's route would be bought at another price. A Warm
/// Standby reservation is refused `not_running` (spec §6.3): it is billed at
/// its own price on `.standby.extend`.
pub async fn extend(
    state: &AppState,
    listing_name: &str,
    version: u32,
    body: &[u8],
) -> Result<ExtendResponse, ErrorResponse> {
    extend_lease(state, listing_name, version, body, ExtendRoute::Extend).await
}

/// Serve one extension of a reservation on
/// `<addr>.<listing>.v<version>.standby.extend`.
///
/// The mirror of `extend`: the lease MUST be `Reserved` rather than running,
/// and the backend is NEVER touched — extending only ever changes
/// `expires_at` (spec §6.3). A running lease of any role — standalone,
/// primary, or a standby after Takeover — is refused `not_standby`: it is
/// billed at its own price on `.extend`.
pub async fn standby_extend(
    state: &AppState,
    listing_name: &str,
    version: u32,
    body: &[u8],
) -> Result<ExtendResponse, ErrorResponse> {
    extend_lease(
        state,
        listing_name,
        version,
        body,
        ExtendRoute::StandbyExtend,
    )
    .await
}

/// ONE function serves both extension routes, because they differ only in
/// which role the lease they find must hold — splitting them would be two
/// copies of the same lookup, freshness check, version check and interval
/// arithmetic, free to drift on the one thing they must agree about: that a
/// lease is billed at the price for what it is doing (spec §6.3).
async fn extend_lease(
    state: &AppState,
    listing_name: &str,
    version: u32,
    body: &[u8],
    route: ExtendRoute,
) -> Result<ExtendResponse, ErrorResponse> {
    let request: ExtendRequest = serde_json::from_slice(body)
        .map_err(|e| invalid(format!("body is not {{ \"workload_id\": \"…\" }}: {}", e)))?;

    let now = state.clock.now();
    let mut leases = state.leases.lock().await;
    let id = lease_id_for(&leases, &request.workload_id).ok_or_else(unknown_workload)?;
    let lease = leases.get_mut(&id).ok_or_else(unknown_workload)?;
    still_running(lease, now)?;
    if lease.listing != listing_name || lease.listing_version != version {
        return Err(ErrorResponse::new(
            ErrorCode::WrongListingVersion,
            format!(
                "this lease was spawned on {} v{}; extend it there",
                lease.listing, lease.listing_version
            ),
        ));
    }
    // AFTER the version check: a lease paid on the wrong route AND the wrong
    // version should hear about the version it can fix rather than about a
    // role rule that may move.
    match (route, lease.state) {
        (ExtendRoute::Extend, LeaseState::Reserved) => return Err(not_running()),
        (ExtendRoute::StandbyExtend, lease_state) if lease_state != LeaseState::Reserved => {
            return Err(not_standby())
        }
        _ => {}
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

    lease.expires_at = lease.expires_at.saturating_add(interval);
    let expires_at = lease.expires_at;
    persist_leases(&leases, &state.config.lease_state_path);

    Ok(ExtendResponse {
        workload_id: request.workload_id,
        expires_at,
    })
}

/// Serve one status on the free `<addr>.status`.
///
/// The one route a Gateway Grant admits (spec §6.5.1). The answer is the same
/// answer either way: a grant delegates READING this lease, so what reading
/// it says is not a thing the delegation changes.
pub async fn status(state: &AppState, body: &[u8]) -> Result<StatusResponse, ErrorResponse> {
    let (request, content): (_, StatusContent) = authenticate(state, body, Op::Status).await?;
    let now = state.clock.now();

    let leases = state.leases.lock().await;
    let id = lease_id_for(&leases, &content.workload_id).ok_or_else(unknown_workload)?;
    let lease = leases.get(&id).ok_or_else(unknown_workload)?;
    lease_request::check_status_continuation(
        &request,
        &lease.continuation,
        content.gateway_expires_at,
        now,
    )?;

    Ok(StatusResponse {
        workload_id: lease.workload_id.clone(),
        role: lease.role,
        state: lease.state,
        expires_at: lease.expires_at,
        // Only a lease whose workload is reachable has somewhere to reach.
        // An ended one has had its workload destroyed; a `Reserved` standby
        // has not started one yet, and spec §6.2 is explicit that `access`
        // is absent for a standby until Takeover; a `Stopped` primary's
        // container is off (spec §7.1). Naming a host and port that reach
        // nothing would be a lie in every one of those cases.
        //
        // The host is the lease's OWN `.anyone` address on a Hidden
        // Provider — the same one its spawn answered, re-established after
        // a restart of the provider (`lease_address::restore_all`) — and
        // the provider's `public_ip` otherwise (spec §6.2, §10).
        access: lease
            .state
            .is_reachable()
            .then(|| lease.access_host(&state.config))
            .flatten()
            .map(|host| lease.access(host)),
        template: lease.template.clone(),
        // Once a Takeover has settled here, which member won — on the winner
        // beside `running`, on a loser beside `reserved` — so a tenant
        // asking any member learns where the workload went (spec §7.1).
        takeover: lease.settled.as_ref().map(|s| TakeoverStatus {
            winner: s.winner.clone(),
        }),
    })
}

/// Serve one termination on the free `<addr>.terminate`: the workload is
/// destroyed now, and nothing is refunded (ADR 0003).
pub async fn terminate(state: &AppState, body: &[u8]) -> Result<TerminateResponse, ErrorResponse> {
    let received = std::time::Instant::now();
    let (request, content): (_, WorkloadContent) = authenticate(state, body, Op::Terminate).await?;
    let workload_id = content.workload_id;
    let now = state.clock.now();

    let id = {
        let leases = state.leases.lock().await;
        let id = lease_id_for(&leases, &workload_id).ok_or_else(unknown_workload)?;
        let lease = leases.get(&id).ok_or_else(unknown_workload)?;
        lease_request::check_continuation(&request, &lease.continuation)?;
        still_running(lease, now)?;
        id
    };

    // `end_lease` re-checks liveness under the lock, so a sweep that reaped
    // this lease between the two is reported as an ending, not destroyed
    // twice.
    if !end_lease(state, id, LeaseEnd::Termination, now).await {
        return Err(ErrorResponse::new(
            ErrorCode::Expired,
            "this lease ended while the request was in flight",
        ));
    }

    // The whole ending happens inside this request, and a connector waits
    // only so long for it; the figure is what an operator needs when one
    // times out.
    tracing::info!(
        "lease {} terminated; answering after {:.1?}",
        id,
        received.elapsed()
    );
    Ok(TerminateResponse {
        workload_id,
        state: LeaseState::Ended(LeaseEnd::Termination),
    })
}

/// Serve one rotation on the free `<addr>.rotate`: the lease's Continuation
/// Token is replaced by the `next` one the request names (spec §6.8).
///
/// REPLACED, not supplemented: the provider keeps one token per lease and
/// nothing beside it, so the old token is `not_tenant` from the moment this
/// answers, and every Gateway Grant derived from it is `bad_grant` — a grant
/// is recomputed from whatever token is stored (§6.5.1), and nothing else
/// remembers the old one (ADR 0018). There is no grace period and nothing is
/// published.
///
/// Step 4 does not branch here, exactly as on `terminate`: only the lease's
/// own token may rotate it. `next` is weighed only once the request has
/// proved it holds that token — so a `next` equal to it is `invalid_request`
/// to the tenant, and never an oracle a stranger could test guesses against.
///
/// The lease is persisted BEFORE the answer, under the same lock that
/// changed it: a crash straight after a rotation must not bring the old token
/// back, and no other request can see the new token before it is on disk.
///
/// A rotation is a revocation, so it may say `rotated: true` only once the
/// new token IS on disk. If the save fails, the old token is put back in
/// memory before the lock is released, so memory and disk never disagree,
/// and the route answers `unavailable` instead — nothing changed, and the
/// tenant retries with the same `next` once saving works again (spec §5,
/// ADR 0018, TOON_Network#78).
pub async fn rotate(state: &AppState, body: &[u8]) -> Result<RotateResponse, ErrorResponse> {
    let (request, content): (_, RotateContent) = authenticate(state, body, Op::Rotate).await?;
    let now = state.clock.now();

    let mut leases = state.leases.lock().await;
    let id = lease_id_for(&leases, &content.workload_id).ok_or_else(unknown_workload)?;
    let lease = leases.get_mut(&id).ok_or_else(unknown_workload)?;
    lease_request::check_continuation(&request, &lease.continuation)?;
    still_running(lease, now)?;
    if content.next == lease.continuation {
        return Err(invalid(
            "`next` is the token this lease already holds; a rotation names a new one",
        ));
    }
    let previous = lease.continuation.clone();
    lease.continuation = content.next;
    if !persist_leases(&leases, &state.config.lease_state_path) {
        // Restore what memory held before this request touched it. The
        // lock is still ours, so no other request has seen the new token in
        // between.
        if let Some(lease) = leases.get_mut(&id) {
            lease.continuation = previous;
        }
        return Err(unavailable());
    }

    // The lease's backend id and nothing else: neither token is ever in a
    // log line (spec §6.1.1).
    tracing::info!("lease {} rotated its continuation token", id);
    Ok(RotateResponse {
        workload_id: content.workload_id,
        rotated: true,
    })
}

/// Evict a lease: an operator decision, not a tenant one, so it carries no
/// Lease Request and no token — the caller is `provider_http`'s loopback
/// operator endpoint, reached only by whoever already controls this host.
///
/// The workload is stopped and deleted NOW, exactly like a termination
/// (`end_lease` marks it `Ended(Eviction)` regardless of whether the delete
/// succeeds; a failed delete is retried by the next sweep, same as any other
/// ending). Only once the lease is over is the Eviction Notice built and
/// published: a notice for a lease that turned out to be unknown or already
/// ended would be a public record of nothing.
///
/// Publishing is log-don't-raise, the same discipline `directory_loop` uses
/// for the Profile, Listings and Liveness: a relay that refuses the notice —
/// or a directory that cannot be reached at all — does not undo the
/// eviction, which already happened. `notice_published` in the response says
/// whether the notice reached every relay of the Relay Set; the per-relay
/// detail is in the log, via `publish_one`.
pub async fn evict(
    state: &AppState,
    workload_id: &str,
    reason: EvictionReason,
    message: &str,
) -> Result<EvictResponse, ErrorResponse> {
    let now = state.clock.now();

    let id = {
        let leases = state.leases.lock().await;
        let id = lease_id_for(&leases, workload_id).ok_or_else(unknown_workload)?;
        let lease = leases.get(&id).ok_or_else(unknown_workload)?;
        if !lease.state.is_live() {
            return Err(unknown_workload());
        }
        id
    };

    // Races a sweep the same way `terminate` does: whichever marks the lease
    // first wins. `false` here means the lease ended in the meantime, by
    // expiry — reported the same as `terminate` reports that race, `expired`,
    // since the lease did exist and this call simply lost the race to end it.
    if !end_lease(state, id, LeaseEnd::Eviction, now).await {
        return Err(ErrorResponse::new(
            ErrorCode::Expired,
            "this lease ended while the eviction was in flight",
        ));
    }

    // The lease is ALREADY EVICTED at this point — stopped, deleted, marked
    // `Ended(Eviction)` and persisted — so nothing below may turn this into a
    // refusal. `directory_loop` builds an event only from a config the
    // provider should not have started with, and that is as true here as it
    // is there: log it and answer `notice_published: false`, the same shape
    // `publish_one` already reports a relay refusal in, rather than raise an
    // `ErrorResponse` that would tell the caller the eviction was refused
    // when it already happened.
    let notice_published = match eviction_event(workload_id, reason, message, &state.keys, now) {
        Ok(event) => match state.publish_one("Eviction Notice", event).await {
            Ok(report) => report.reached_every_relay(),
            Err(e) => {
                error!(
                    "lease {} was evicted, but its Eviction Notice was not published: {:#}",
                    id, e
                );
                false
            }
        },
        Err(e) => {
            error!(
                "lease {} was evicted, but its Eviction Notice could not be built: {:#}",
                id, e
            );
            false
        }
    };

    Ok(EvictResponse {
        workload_id: workload_id.to_string(),
        state: LeaseState::Ended(LeaseEnd::Eviction),
        notice_published,
    })
}

/// The Lease Request on an authenticated free route: validated exactly as a
/// spawn's is, replay included, and parsed down to `C`, the op's own content.
///
/// Steps 1 to 3 only. The token it presented rides back in the request, for
/// `lease_request`'s step 4 to weigh against the lease once the caller has
/// found it — there is no lease to weigh it against until then.
///
/// `C` is the op's content type and not one shape for all, because the
/// contents are not the same: only `status`'s names `gateway_expires_at`
/// (spec §6.5), and only `rotate`'s names `next` (§6.8). Every field an op's
/// content does not name is `invalid_request` here, never dropped (ADR 0004)
/// — which is how a gateway asking to `terminate` or `rotate` is refused by
/// the shape rather than by a rule.
async fn authenticate<C: serde::de::DeserializeOwned>(
    state: &AppState,
    body: &[u8],
    op: Op,
) -> Result<(ValidLeaseRequest, C), ErrorResponse> {
    let now = state.clock.now();
    let request = lease_request::accept(
        body,
        &state.keys.public_key(),
        op,
        now,
        &state.accepted_requests,
    )?;
    let content: C = serde_json::from_value(request.content.clone())
        .map_err(|e| invalid(format!("{} content: {}", op.as_str(), e)))?;
    Ok((request, content))
}
