// The HTTP app.
//
// The provider's TOON connector plays the role `ngx_l402` played for Paygress:
// it terminates payment, seals and unseals the payload, and forwards a plain
// HTTP request here. So this app reads no `X-TOON-Payer`, `X-TOON-Amount` or
// `X-TOON-Chain` header (ADR 0005) — a tenant paying through hops is served
// identically to one paying directly, and identity comes from the request body,
// not from who paid.
//
// Paths are `provider::routes`'s: the connector forwards each ILP prefix to
// one of them. Spawn is served; extend, availability, status and terminate
// are listed in the route table and answer "not implemented" until their
// tickets land.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use nostr_sdk::Keys;
use tokio::sync::Mutex;
use tracing::info;

use crate::clock::Clock;
use crate::compute::ComputeBackend;
use crate::nostr::lease_request::AcceptedRequests;
use crate::nostr::wire::{ErrorCode, ErrorResponse};
use crate::provider::routes::{AVAILABILITY_PATH, STATUS_PATH, TERMINATE_PATH};
use crate::provider::{spawn, LeaseRecord, ProviderConfig};

/// Everything a handler may touch. Arc-cloned from `ProviderService`, so the
/// HTTP app and the expiry sweep see one lease table and one clock.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ProviderConfig>,
    pub backend: Arc<dyn ComputeBackend>,
    pub clock: Arc<dyn Clock>,
    /// The provider's Nostr identity: what a Lease Request must be addressed
    /// to, and what signs everything the provider publishes.
    pub keys: Keys,
    pub leases: Arc<Mutex<HashMap<u32, LeaseRecord>>>,
    pub accepted_requests: Arc<AcceptedRequests>,
}

impl AppState {
    /// Fails if the config is invalid or its `nostr_private_key` does not
    /// parse: a provider with no identity cannot be addressed.
    pub fn new(
        config: ProviderConfig,
        backend: Arc<dyn ComputeBackend>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        config.validate()?;
        let keys = Keys::parse(&config.nostr_private_key)
            .context("nostr_private_key must be a hex or nsec1 secret key")?;
        Ok(Self {
            config: Arc::new(config),
            backend,
            clock,
            keys,
            leases: Arc::new(Mutex::new(HashMap::new())),
            accepted_requests: Arc::new(AcceptedRequests::new()),
        })
    }
}

/// The app's routes. Separate from `serve` so tests can drive it in-process,
/// the way the connector drives it: an HTTP request in, a JSON response out.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/listings/:listing/:version/spawn", post(spawn_route))
        .route("/listings/:listing/:version/extend", post(not_implemented))
        .route(AVAILABILITY_PATH, post(not_implemented))
        .route(STATUS_PATH, post(not_implemented))
        .route(TERMINATE_PATH, post(not_implemented))
        .with_state(state)
}

pub async fn serve(state: AppState, bind_addr: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind the HTTP app to {}: {}", bind_addr, e))?;

    info!("HTTP app listening on {}", bind_addr);

    axum::serve(listener, router(state))
        .await
        .map_err(|e| anyhow::anyhow!("HTTP app error: {}", e))?;

    Ok(())
}

/// Free and unauthenticated: it says the process is up, and nothing more. It
/// must never report on leases — a route that costs nothing to call must not
/// leak what this provider is running.
async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

async fn spawn_route(
    State(state): State<AppState>,
    Path((listing, version)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Some(version) = parse_version(&version) else {
        return refuse(ErrorResponse::new(
            ErrorCode::WrongListingVersion,
            format!("{:?} is not a listing version (`v<n>`)", version),
        ));
    };
    match spawn(&state, &listing, version, &body).await {
        Ok(answer) => (StatusCode::OK, Json(answer)).into_response(),
        Err(e) => refuse(e),
    }
}

async fn not_implemented() -> Response {
    refuse(ErrorResponse::new(
        ErrorCode::InvalidRequest,
        "not implemented in this milestone",
    ))
}

/// `v<n>` as the route table writes it.
fn parse_version(segment: &str) -> Option<u32> {
    segment.strip_prefix('v')?.parse().ok().filter(|v| *v > 0)
}

/// Every refusal is the spec's JSON error shape with a 4xx status. The
/// connector bills a paid route regardless of status (ADR 0003); the status
/// is for tooling that reads HTTP before it reads the body.
pub fn refuse(error: ErrorResponse) -> Response {
    let status = match error.error {
        ErrorCode::BadSignature | ErrorCode::NotTenant => StatusCode::FORBIDDEN,
        ErrorCode::StaleRequest | ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
        ErrorCode::WrongListingVersion | ErrorCode::UnknownWorkload => StatusCode::NOT_FOUND,
        ErrorCode::WorkloadIdTaken
        | ErrorCode::NoCapacity
        | ErrorCode::Expired
        | ErrorCode::NotStandby => StatusCode::CONFLICT,
        ErrorCode::RefusedImage | ErrorCode::NoMatchingArch => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (status, Json(error)).into_response()
}
