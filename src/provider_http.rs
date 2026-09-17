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
// one of them. Spawn, extend, standby, standby.extend, availability, status
// and terminate are all served.
//
// The free routes (`availability`, `status`, `terminate`) arrive with nothing
// paid and are served exactly like the paid ones: this app never looks at what
// a packet was worth.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
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
use crate::directory::{ConnectorDirectory, Directory, NullDirectory};
use crate::hidden_service::HiddenService;
use crate::nostr::lease_request::AcceptedRequests;
use crate::nostr::wire::{ErrorCode, ErrorResponse, EvictRequest};
use crate::outbound_proxy::OutboundProxy;
use crate::provider::routes::{
    AVAILABILITY_PATH, EXTEND_PATTERN, SPAWN_PATTERN, STANDBY_EXTEND_PATTERN, STANDBY_PATTERN,
    STATUS_PATH, TERMINATE_PATH,
};
use crate::provider::{
    availability, evict, extend, spawn, standby_extend, standby_spawn, status, terminate,
    BlobCache, BlobFetcher, ImagePolicy, LeaseRecord, ProviderConfig,
};

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
    /// Where the Provider Profile, Listings, Liveness and — from a later
    /// ticket — Eviction Notices go. The second of the provider's two I/O
    /// ports; a test swaps it for a fake and reads back what was published.
    pub directory: Arc<dyn Directory>,
    /// A Hidden Provider's window onto its `anon` daemon: the per-lease
    /// `.anyone` addresses and the egress policy (spec §10). The third
    /// port, and the only optional one — `None` on a provider that is not
    /// hidden, which never touches it. A test installs a fake with
    /// `with_hidden_service`; the real adapter that drives the daemon's
    /// control port is selected from `[anon.control]` from M4-3
    /// (TOON_Network #40), so until then no config installs one.
    pub hidden_service: Option<Arc<dyn HiddenService>>,
    pub leases: Arc<Mutex<HashMap<u32, LeaseRecord>>>,
    pub accepted_requests: Arc<AcceptedRequests>,
    /// What this provider refuses to run, and the client that resolves an
    /// image reference/digest against the upstream registry. Shared by
    /// `availability` and a paid spawn's validation step 5, so the two never
    /// disagree.
    pub image_policy: Arc<ImagePolicy>,
    /// How every image byte is fetched and verified (spec §8.4): from the
    /// TOON store through the configured gateway, or from an upstream OCI
    /// registry. One instance over the one on-disk blob cache, so a blob
    /// verified for any lease serves every later one.
    pub fetcher: Arc<BlobFetcher>,
}

impl AppState {
    /// Fails if the config is invalid, its `nostr_private_key` does not
    /// parse (a provider with no identity cannot be addressed), or the blob
    /// cache directory cannot be created.
    pub fn new(
        config: ProviderConfig,
        backend: Arc<dyn ComputeBackend>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        config.validate()?;
        let keys = Keys::parse(&config.nostr_private_key)
            .context("nostr_private_key must be a hex or nsec1 secret key")?;
        let proxy = outbound_proxy_from_config(&config)?;
        let directory = directory_from_config(&config, proxy.as_ref())?;
        let image_policy = Arc::new(ImagePolicy::from_config(&config.image_policy));
        let cache = BlobCache::open(config.blob_cache_dir(), config.blob_cache_max_bytes)?;
        let fetcher = BlobFetcher::new(
            config.gateway_url_pattern.clone(),
            config.image_policy.registry_url_override.clone(),
            cache,
        );
        let fetcher = Arc::new(match &proxy {
            Some(proxy) => fetcher.with_proxy(proxy)?,
            None => fetcher,
        });
        Ok(Self {
            config: Arc::new(config),
            backend,
            clock,
            keys,
            directory,
            hidden_service: None,
            leases: Arc::new(Mutex::new(HashMap::new())),
            accepted_requests: Arc::new(AcceptedRequests::new()),
            image_policy,
            fetcher,
        })
    }

    /// Swap the Directory this state publishes through. Separate from `new`
    /// so the constructor's shape stays the one every caller already writes,
    /// and so a test can hand in a fake without a config that names a live
    /// publisher.
    pub fn with_directory(mut self, directory: Arc<dyn Directory>) -> Self {
        self.directory = directory;
        self
    }

    /// Install the `HiddenService` this state creates per-lease addresses
    /// through — a fake in tests, the `anon` control-port adapter in a
    /// running hidden provider. Shaped like `with_directory` for the same
    /// reason: the constructor stays as it is, and a test needs no config
    /// that names a live daemon.
    pub fn with_hidden_service(mut self, hidden_service: Arc<dyn HiddenService>) -> Self {
        self.hidden_service = Some(hidden_service);
        self
    }
}

/// Where this provider's OWN outbound goes: the `anon` SOCKS port when it is
/// hidden, and nowhere — direct, exactly as before — when it is not (spec
/// §10, TOON_Network #42).
///
/// Read only under `hidden = true`, though `anon.socks_proxy` is a key any
/// config may carry: a provider that publishes no `hidden: true` claims
/// nothing about where its packets come from, and silently routing it
/// through a daemon it happened to name would change what it does without
/// changing what it says.
///
/// The proxy's own name is resolved here, once, at startup — see
/// `OutboundProxy`. A daemon that cannot be resolved is a refusal to start
/// and not a warning: a hidden provider whose proxy is unreachable would
/// otherwise carry on publishing from its real address.
fn outbound_proxy_from_config(config: &ProviderConfig) -> Result<Option<OutboundProxy>> {
    if !config.hidden {
        return Ok(None);
    }
    match &config.anon.socks_proxy {
        Some(url) => Ok(Some(OutboundProxy::resolve(url)?)),
        // Unreachable through `validate`, which requires the key under
        // `hidden = true`; an `Ok(None)` here would be a provider that is
        // hidden everywhere but on its own socket.
        None => bail!(
            "hidden = true, so anon.socks_proxy must be set: this provider's own relay reads,              image fetches and Directory writes have nowhere to leave through (spec §10)"
        ),
    }
}

/// The Directory a config describes: the real one when it names a directory
/// publisher, and one that publishes nothing when it does not. A provider
/// with no `publish_url` still serves every route — it is simply not in the
/// directory.
///
/// `proxy` is `Some` only on a Hidden Provider, and then EVERY relay read
/// goes out through it — a publisher-less one included, because watching a
/// primary and resolving an image are reads that name this host to a relay
/// operator just as a publication would.
fn directory_from_config(
    config: &ProviderConfig,
    proxy: Option<&OutboundProxy>,
) -> Result<Arc<dyn Directory>> {
    match (&config.publish_url, proxy) {
        (Some(url), None) => Ok(Arc::new(ConnectorDirectory::new(
            url.clone(),
            config.relay_set.clone(),
        )?)),
        (Some(url), Some(proxy)) => Ok(Arc::new(
            ConnectorDirectory::new(url.clone(), config.relay_set.clone())?.with_proxy(proxy)?,
        )),
        (None, None) => Ok(Arc::new(NullDirectory::new(config.relay_set.clone()))),
        (None, Some(proxy)) => Ok(Arc::new(
            NullDirectory::new(config.relay_set.clone()).with_proxy(proxy),
        )),
    }
}

/// The app's routes. Separate from `serve` so tests can drive it in-process,
/// the way the connector drives it: an HTTP request in, a JSON response out.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(SPAWN_PATTERN, post(spawn_route))
        .route(EXTEND_PATTERN, post(extend_route))
        .route(STANDBY_PATTERN, post(standby_route))
        .route(STANDBY_EXTEND_PATTERN, post(standby_extend_route))
        .route(AVAILABILITY_PATH, post(availability_route))
        .route(STATUS_PATH, post(status_route))
        .route(TERMINATE_PATH, post(terminate_route))
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

/// The operator surface: `POST /operator/evict`, and nothing else. Deliberately
/// a SEPARATE router from `router` above rather than one more route on it —
/// `router` is what the TOON connector forwards tenant traffic to, and
/// eviction takes no signature and no payment because it is not a tenant
/// operation: it is the operator of this box telling its own provider process
/// to stop a lease. Keeping it a separate `Router` means it can never be
/// reached through the connector's route table by a future change that adds
/// routes to `router`, and a test can drive it exactly like `router` — an
/// HTTP request in, JSON out — without needing a real loopback socket to
/// prove the isolation.
///
/// The isolation that matters is `serve_operator`'s bind address, which
/// `ProviderConfig::validate` refuses to be anything but loopback.
pub fn operator_router(state: AppState) -> Router {
    Router::new()
        .route("/operator/evict", post(evict_route))
        .with_state(state)
}

/// Serve the operator surface on its own bind address. Bound separately from
/// `serve`'s app so the two ports can be firewalled differently: this one
/// MUST NEVER be exposed off this host (`ProviderConfig::operator_bind_addr`
/// carries the loopback requirement).
pub async fn serve_operator(state: AppState, bind_addr: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to bind the operator endpoint to {}: {}",
                bind_addr,
                e
            )
        })?;

    info!(
        "operator endpoint listening on {} (loopback only — never expose this)",
        bind_addr
    );

    axum::serve(listener, operator_router(state))
        .await
        .map_err(|e| anyhow::anyhow!("operator endpoint error: {}", e))?;

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

async fn extend_route(
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
    match extend(&state, &listing, version, &body).await {
        Ok(answer) => (StatusCode::OK, Json(answer)).into_response(),
        Err(e) => refuse(e),
    }
}

/// `POST /listings/:listing/:version/standby`, the path the connector
/// forwards `<addr>.<listing>.v<n>.standby` to. Registered for every
/// listing, priced only for the ones that sell standbys
/// (`routes::route_table`): a spawn that lands here reserves capacity for
/// the Standby Set member it names at an index other than 0, and one paid
/// on a listing that prices no standby is refused `wrong_listing_version`.
async fn standby_route(
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
    match standby_spawn(&state, &listing, version, &body).await {
        Ok(answer) => (StatusCode::OK, Json(answer)).into_response(),
        Err(e) => refuse(e),
    }
}

/// `POST /listings/:listing/:version/standby/extend`, for
/// `<addr>.<listing>.v<n>.standby.extend`.
async fn standby_extend_route(
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
    match standby_extend(&state, &listing, version, &body).await {
        Ok(answer) => (StatusCode::OK, Json(answer)).into_response(),
        Err(e) => refuse(e),
    }
}

async fn status_route(State(state): State<AppState>, body: Bytes) -> Response {
    match status(&state, &body).await {
        Ok(answer) => (StatusCode::OK, Json(answer)).into_response(),
        Err(e) => refuse(e),
    }
}

async fn terminate_route(State(state): State<AppState>, body: Bytes) -> Response {
    match terminate(&state, &body).await {
        Ok(answer) => (StatusCode::OK, Json(answer)).into_response(),
        Err(e) => refuse(e),
    }
}

/// `POST /operator/evict` on the OPERATOR router (`operator_router`), never
/// on `router`. No signature to check: the caller already reached a loopback
/// port that `router` never listens on.
async fn evict_route(State(state): State<AppState>, body: Bytes) -> Response {
    let request: EvictRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(ErrorResponse::new(
                ErrorCode::InvalidRequest,
                format!(
                    "body is not {{ \"workload_id\", \"reason\", \"message\"? }}: {}",
                    e
                ),
            ))
        }
    };
    let message = request.message.as_deref().unwrap_or("");
    match evict(&state, &request.workload_id, request.reason, message).await {
        Ok(answer) => (StatusCode::OK, Json(answer)).into_response(),
        Err(e) => refuse(e),
    }
}

/// `POST /availability`: free, unsigned, and answers 200 either way — the
/// refusal reason IS the payload here, not an HTTP status the way `spawn`'s
/// refusals are (`refuse`). It never touches `ComputeBackend`.
async fn availability_route(State(state): State<AppState>, body: Bytes) -> Response {
    (StatusCode::OK, Json(availability(&state, &body).await)).into_response()
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
        | ErrorCode::NotStandby
        | ErrorCode::NotRunning => StatusCode::CONFLICT,
        ErrorCode::RefusedImage | ErrorCode::NoMatchingArch => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (status, Json(error)).into_response()
}
