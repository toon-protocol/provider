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
use crate::nostr::image_events::SpawnImage;
use crate::nostr::wire::{
    AvailabilityRequest, AvailabilityResponse, AvailabilityRole, ErrorCode, ErrorResponse,
};
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
    let listing = state
        .config
        .sellable_listing(&request.listing, request.version)?;
    // A Hidden Provider gives every lease a `.anyone` address of its own,
    // and one that cannot reach the daemon that makes them starts no lease
    // (spec §10). The paid spawn refuses it; this free answer says so first
    // (spec §9).
    super::lease_address::refuse_without_a_daemon(state)?;

    // §6.4's optional `role`: a Warm Standby is bought on `.standby`, which
    // exists only for a listing that prices one, so the question "would a
    // standby be reserved here?" is answered `false` on a listing that sells
    // none — with the same code and the same reason `standby_spawn` refuses
    // it, so the free answer and the paid one cannot disagree (spec §9).
    // Nothing else differs: a reservation is refused for a denied image or a
    // full listing exactly as a running lease is, and asking costs nothing
    // and reserves nothing.
    if request.role == Some(AvailabilityRole::Standby) {
        listing.sells_standbys()?;
    }

    // Step 5: the same three-form parse and the same image policy a paid
    // spawn applies, so an image this provider cannot fetch is reported here
    // for free rather than bought.
    let image = SpawnImage::parse(&request.image)?;
    image_policy::check(
        &state.fetcher,
        state.directory.clone(),
        &state.image_policy,
        listing,
        &image,
    )
    .await?;

    // Step 6: capacity, counted the same way spawn counts it — live leases,
    // RESERVATIONS INCLUDED, against the listing name's declared capacity —
    // read-only, so this never races a spawn's insert into taking a slot. A
    // standby holds its slot with nothing running (spec §6.7), so capacity
    // held for one is not offered to anybody else, whichever role is asked
    // about.
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
