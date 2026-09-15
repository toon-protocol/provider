// The HTTP app.
//
// The provider's TOON connector plays the role `ngx_l402` played for Paygress:
// it terminates payment, seals and unseals the payload, and forwards a plain
// HTTP request here. So this app reads no `X-TOON-Payer`, `X-TOON-Amount` or
// `X-TOON-Chain` header (ADR 0005) — a tenant paying through hops is served
// identically to one paying directly, and identity comes from the request body,
// not from who paid.
//
// Only `/health` exists so far. The lease routes (spawn, extend, availability,
// status, terminate) land in the next ticket; they build on `router`.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use axum::{http::StatusCode, response::Json, routing::get, Router};
use tokio::sync::Mutex;
use tracing::info;

use crate::compute::ComputeBackend;
use crate::provider::{LeaseRecord, ProviderConfig};

/// Everything a handler may touch. Arc-cloned from `ProviderService`, so the
/// HTTP app and the expiry sweep see one lease table.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ProviderConfig>,
    pub backend: Arc<dyn ComputeBackend>,
    pub leases: Arc<Mutex<HashMap<u32, LeaseRecord>>>,
}

/// The app's routes. Separate from `serve` so tests can drive it in-process,
/// the way the connector drives it: an HTTP request in, a JSON response out.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
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
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "ok" })),
    )
}
