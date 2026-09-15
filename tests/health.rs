//! The HTTP app driven the way the provider's TOON connector drives it: an HTTP
//! request in, a JSON response out.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::Mutex;
use tower::ServiceExt;

use common::FakeBackend;
use toon_provider::{router, AppState, ProviderConfig};

fn app() -> axum::Router {
    router(AppState {
        config: Arc::new(ProviderConfig::default()),
        backend: FakeBackend::new(),
        leases: Arc::new(Mutex::new(HashMap::new())),
    })
}

async fn get(path: &str) -> (StatusCode, serde_json::Value) {
    let response = app()
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("app responded");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn health_answers_200() {
    let (status, body) = get("/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn health_says_nothing_about_leases() {
    // It costs nothing to call, so it must not leak what this provider runs.
    let (_, body) = get("/health").await;
    let object = body.as_object().expect("health answers a JSON object");
    assert_eq!(
        object.keys().collect::<Vec<_>>(),
        vec!["status"],
        "health must answer status and nothing else"
    );
}

#[tokio::test]
async fn an_unknown_route_is_404_not_a_panic() {
    let (status, _) = get("/no-such-route").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
