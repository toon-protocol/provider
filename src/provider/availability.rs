// Availability: the free route that answers whether a spawn would run,
// without starting anything (spec §6.4).
//
// It applies spec §6.2 steps 2 (the listing version exists), 5 (image
// policy) and 6 (capacity) — never step 4 (`workload_id_taken`, since this
// request names no workload id) and never the Lease Request checks (this
// route is unsigned and free). A positive answer is advice, not a
// reservation: a spawn that later fails is still billed (ADR 0003), and this
// function never touches `ComputeBackend` or the lease table's write side.

use super::image_policy;
use super::persistence::count_live;
use super::spawn::listing_on_sale;
use crate::nostr::wire::{AvailabilityRequest, AvailabilityResponse, ErrorCode, ErrorResponse};
use crate::provider_http::AppState;

/// Serve one `POST /availability`. Never fails: every refusal reason becomes
/// `AvailabilityResponse::Refused` rather than an `Err`, because the route
/// answers 200 either way (`provider_http::availability_route`).
pub async fn availability(state: &AppState, body: &[u8]) -> AvailabilityResponse {
    match check(state, body).await {
        Ok(()) => AvailabilityResponse::would_run(),
        Err(e) => AvailabilityResponse::refused(e.error, e.message),
    }
}

async fn check(state: &AppState, body: &[u8]) -> Result<(), ErrorResponse> {
    let request: AvailabilityRequest = serde_json::from_slice(body).map_err(|e| {
        ErrorResponse::new(
            ErrorCode::InvalidRequest,
            format!("body is not {{ listing, version, image }}: {}", e),
        )
    })?;

    // Step 2: the listing version exists and is on sale — a retired version
    // starts no lease, so `would_run` there is `false` with the same
    // `wrong_listing_version` a paid spawn would have bought. (Ports and
    // volume have no home in this request shape, so there is nothing of
    // step 2 left to check.)
    let listing = listing_on_sale(&state.config, &request.listing, request.version)?;

    // Step 5: the same image policy a paid spawn applies.
    image_policy::check(
        &state.image_registry,
        &state.image_policy,
        listing,
        &request.image,
    )
    .await?;

    // Step 6: capacity, counted the same way spawn counts it — live leases
    // against the listing name's declared capacity — read-only, so this
    // never races a spawn's insert into taking a slot.
    let leases = state.leases.lock().await;
    let running = count_live(&leases, &listing.name);
    if running >= state.config.capacity_of(&listing.name) as usize {
        return Err(ErrorResponse::new(
            ErrorCode::NoCapacity,
            format!("every {} slot is taken", listing.name),
        ));
    }
    Ok(())
}
