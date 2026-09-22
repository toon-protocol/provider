//! A tenant's `image.reference` must not aim this provider's fetches at the
//! operator's own network (TOON_Network#105).
//!
//! What makes these tests proof rather than decoration is the trap: a real
//! listener on a loopback port that counts every connection it accepts. A
//! guard that merely turned the answer into a refusal AFTER dialling would
//! still have told the operator's own service that someone is there, and
//! `availability` is free — so every test below asserts the count is zero,
//! not just that the fetch failed.
//!
//! The three doors a tenant can push on are one test each: the registry the
//! reference names, the token realm a hostile registry answers 401 with, and
//! a redirect. Then the whole free route, from the JSON a connector posts to
//! the refusal it answers with, because that is where this is cheapest to
//! abuse. The operator's own door — `registry_url_override`,
//! `gateway_url_pattern`, `image_policy.exempt_registries` — is the way back
//! in, and the last two tests walk through it.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use nostr_sdk::Keys;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use common::{valid_digest, valid_manifest_bytes, FakeBackend};
use toon_provider::nostr::wire::{ErrorCode, Resources};
use toon_provider::outbound_guard::MAX_REDIRECTS;
use toon_provider::provider::fetcher::BlobSources;
use toon_provider::provider::{BlobCache, BlobFetcher};
use toon_provider::{router, Listing, ProviderConfig, ProviderService};

const REPOSITORY: &str = "library/alpine";

/// A listener on loopback that accepts and counts. Nothing is served: the
/// point is the count, and a provider that got this far has already lost —
/// the operator's real service on such a port would have answered.
struct Trap {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

impl Trap {
    async fn set() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        Self { addr, connections }
    }

    fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    fn reached(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn fetcher(registry_url_override: Option<String>, exempt: &[&str]) -> (BlobFetcher, Arc<TempDir>) {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let exempt: Vec<String> = exempt.iter().map(|e| e.to_string()).collect();
    let fetcher = BlobFetcher::new(
        None,
        registry_url_override,
        &exempt,
        None,
        BlobCache::open(dir.path(), None).unwrap(),
    )
    .unwrap();
    (fetcher, dir)
}

/// A registry that answers 401 with `realm`, and serves the manifest to
/// anyone who comes back with a token — the generic bearer flow, with the
/// realm under the test's control the way a hostile registry has it under
/// its own.
async fn registry_challenging_with(realm: &str) -> MockServer {
    let registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v2/.*/manifests/.*$"))
        .and(|req: &Request| req.headers.get("authorization").is_none())
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            format!("Bearer realm=\"{}\",service=\"registry\"", realm).as_str(),
        ))
        .mount(&registry)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v2/.*/manifests/.*$"))
        .and(|req: &Request| req.headers.get("authorization").is_some())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(valid_manifest_bytes()))
        .mount(&registry)
        .await;
    registry
}

/// A token endpoint that hands out an anonymous pull token, on its own
/// server so a test can name it by address or by name.
async fn token_endpoint() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": "anonymous" })))
        .mount(&server)
        .await;
    server
}

// ── the registry the reference names ────────────────────────────────────

/// `image.reference = "127.0.0.1:<port>/library/alpine"`: the host is an
/// address the provider must not dial, and nothing leaves.
#[tokio::test]
async fn a_reference_naming_a_loopback_registry_is_refused_before_any_connection() {
    let trap = Trap::set().await;
    let (fetcher, _dir) = fetcher(None, &[]);

    let sources = BlobSources::upstream(trap.authority(), REPOSITORY);
    let refusal = fetcher
        .fetch(&valid_digest(), &sources)
        .await
        .expect_err("a loopback registry is refused");

    assert_eq!(refusal.error, ErrorCode::RefusedImage);
    assert!(
        refusal.message.contains(&trap.authority()),
        "the refusal names the source that was refused: {}",
        refusal.message
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// The same, by NAME: `localhost` resolves inward, and the check is on what
/// it resolved to. The name is resolved once and only the addresses that
/// passed are dialled, so there is no second lookup to rebind.
#[tokio::test]
async fn a_reference_whose_registry_name_resolves_inward_is_refused_too() {
    let trap = Trap::set().await;
    let (fetcher, _dir) = fetcher(None, &[]);

    let registry = format!("localhost:{}", trap.addr.port());
    let sources = BlobSources::upstream(registry.clone(), REPOSITORY);
    let refusal = fetcher
        .fetch(&valid_digest(), &sources)
        .await
        .expect_err("a registry name that resolves to loopback is refused");

    assert_eq!(refusal.error, ErrorCode::RefusedImage);
    assert!(
        refusal.message.contains(&registry),
        "the refusal names the source, not the address it resolved to: {}",
        refusal.message
    );
    assert!(
        !refusal.message.contains("127.0.0.1"),
        "and never the address: {}",
        refusal.message
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

// ── the token realm ─────────────────────────────────────────────────────

/// A registry a tenant controls answers 401 and names a realm inside the
/// operator's network. The realm is checked like any other outbound host.
#[tokio::test]
async fn a_bearer_realm_pointing_inward_is_refused_before_any_connection() {
    let trap = Trap::set().await;
    // `https`, so that only the address rule can refuse it: a plain-http
    // realm has its own test below.
    let registry = registry_challenging_with(&format!("https://{}/token", trap.authority())).await;
    let (fetcher, _dir) = fetcher(Some(registry.uri()), &[]);

    let sources = BlobSources::upstream("registry.example", REPOSITORY);
    let refusal = fetcher
        .fetch(&valid_digest(), &sources)
        .await
        .expect_err("a realm inside the operator's network is refused");

    assert_eq!(refusal.error, ErrorCode::RefusedImage);
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// A realm on a public host but a plain-http scheme: refused, because the
/// pull token is a credential and the answer is a URL this provider will
/// fetch.
#[tokio::test]
async fn a_bearer_realm_that_is_not_https_is_refused() {
    let registry = registry_challenging_with("http://auth.example/token").await;
    let (fetcher, _dir) = fetcher(Some(registry.uri()), &[]);

    let sources = BlobSources::upstream("registry.example", REPOSITORY);
    let refusal = fetcher
        .fetch(&valid_digest(), &sources)
        .await
        .expect_err("a plain-http realm is refused");
    assert_eq!(refusal.error, ErrorCode::RefusedImage);
    assert!(
        refusal.message.contains("https"),
        "and says why: {}",
        refusal.message
    );
}

// ── redirects ───────────────────────────────────────────────────────────

/// A registry that answers 302 toward the operator's network: each hop is
/// checked, so the hop is never dialled.
#[tokio::test]
async fn a_redirect_toward_the_operators_network_is_refused_before_any_connection() {
    let trap = Trap::set().await;
    let registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v2/.*$"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("http://{}/v2/{}/manifests/x", trap.authority(), REPOSITORY).as_str(),
        ))
        .mount(&registry)
        .await;
    let (fetcher, _dir) = fetcher(Some(registry.uri()), &[]);

    let sources = BlobSources::upstream("registry.example", REPOSITORY);
    let refusal = fetcher
        .fetch(&valid_digest(), &sources)
        .await
        .expect_err("a redirect toward loopback is refused");

    assert_eq!(refusal.error, ErrorCode::RefusedImage);
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
}

/// A registry that redirects for ever is given up on rather than followed
/// for ever. Each hop is a URL of its own, so it is the cap that stops this
/// and not a client's loop detection.
#[tokio::test]
async fn redirects_are_capped() {
    let registry = MockServer::start().await;
    let redirected = Arc::new(AtomicUsize::new(0));
    let counted = redirected.clone();
    Mock::given(method("GET"))
        .respond_with(move |_: &Request| {
            let hop = counted.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(302)
                .insert_header("location", format!("/hop/{}", hop + 1).as_str())
        })
        .mount(&registry)
        .await;
    let (fetcher, _dir) = fetcher(Some(registry.uri()), &[]);

    let sources = BlobSources::upstream("registry.example", REPOSITORY);
    let refusal = fetcher
        .fetch(&valid_digest(), &sources)
        .await
        .expect_err("an endless redirect is given up on");
    assert_eq!(refusal.error, ErrorCode::RefusedImage);
    let followed = redirected.load(Ordering::SeqCst);
    assert!(
        followed <= MAX_REDIRECTS + 1,
        "the provider stopped following after the cap: {} requests",
        followed
    );
}

// ── the free route, end to end ──────────────────────────────────────────

/// `availability` is where this is cheapest to abuse — unsigned, unpaid, and
/// it resolves the image — so the whole route is driven here, from the JSON
/// a connector posts to the refusal it answers with.
#[tokio::test]
async fn availability_refuses_a_reference_aimed_at_the_operators_network() {
    let trap = Trap::set().await;
    let backend = FakeBackend::new();
    let dir = tempfile::tempdir().unwrap();
    let config = ProviderConfig {
        public_ip: Some("203.0.113.7".to_string()),
        nostr_private_key: Keys::generate().secret_key().to_secret_hex(),
        listings: vec![Listing {
            name: "basic".to_string(),
            version: 1,
            resources: Resources {
                cpu_millicores: 500,
                memory_mb: 256,
                storage_gb: 4,
                gpu: None,
            },
            arch: "amd64".to_string(),
            lease_interval_s: 3600,
            price: 1000,
            standby_price: None,
            capabilities: vec![],
            capacity: 2,
        }],
        workload_id_range_start: 1000,
        workload_id_range_end: 1003,
        ssh_port_start: Some(40000),
        workload_port_start: 41000,
        lease_state_path: dir
            .path()
            .join("leases.json")
            .to_string_lossy()
            .into_owned(),
        // No `registry_url_override` and no exemption: the reference alone
        // decides where this provider would go.
        ..ProviderConfig::default()
    };
    let service = ProviderService::with_backend(config, backend.clone()).unwrap();
    let app = router(service.app_state());

    let body = json!({
        "listing": "basic",
        "version": 1,
        "image": {
            "reference": format!("{}/{}", trap.authority(), REPOSITORY),
            "digest": valid_digest(),
        }
    });
    let response = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/availability")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let answer: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(answer["would_run"], false);
    assert_eq!(answer["error"], "refused_image");
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains(&trap.authority()),
        "the refusal names the source: {}",
        answer["message"]
    );
    assert_eq!(trap.reached(), 0, "no connection reached the trap");
    assert!(
        backend.calls().is_empty(),
        "and availability never touches the backend"
    );
}

// ── the operator's way back in ──────────────────────────────────────────

/// An operator whose registry IS inside their network says so with a CIDR,
/// and the same fetch that is refused above goes through.
#[tokio::test]
async fn a_cidr_exemption_lets_an_internal_realm_through() {
    let token = token_endpoint().await;
    let realm = format!("http://127.0.0.1:{}/token", token.address().port());
    let registry = registry_challenging_with(&realm).await;
    let (fetcher, _dir) = fetcher(Some(registry.uri()), &["127.0.0.0/8"]);

    let sources = BlobSources::upstream("registry.example", REPOSITORY);
    let bytes = fetcher.fetch(&valid_digest(), &sources).await.unwrap();
    assert_eq!(bytes.as_ref(), valid_manifest_bytes().as_slice());
}

/// And with a host name, which is how an operator names a registry on their
/// own compose network.
#[tokio::test]
async fn a_host_exemption_lets_an_internal_realm_through() {
    let token = token_endpoint().await;
    let realm = format!("http://localhost:{}/token", token.address().port());
    let registry = registry_challenging_with(&realm).await;
    let (fetcher, _dir) = fetcher(Some(registry.uri()), &["localhost"]);

    let sources = BlobSources::upstream("registry.example", REPOSITORY);
    let bytes = fetcher.fetch(&valid_digest(), &sources).await.unwrap();
    assert_eq!(bytes.as_ref(), valid_manifest_bytes().as_slice());
}
