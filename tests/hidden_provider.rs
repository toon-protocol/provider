//! A Hidden Provider's wire surface before any lease is hidden (spec §10,
//! ADR 0008; TOON_Network #38): what it publishes, what it refuses, and
//! what it never touches — driven through the HTTP router and the Directory
//! port over the fakes, exactly as a tenant and a relay would see it.
//!
//! The per-lease addresses themselves are M4-2 (#39): until then a hidden
//! provider starts no lease, and this file pins the placeholder that says
//! so, in one place, so that ticket can delete it.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::harness::{
    config_for, digest, error_of, harness, harness_from, hidden_config, listing, post, spawn,
    spawn_content, RequestSpec, HIDDEN_CONNECTOR_URL, NOW, PUBLIC_IP,
};
use common::{has_tag, stub_registry, FakeBackend, FakeClock, FakeDirectory, FakeHiddenService};
use nostr_sdk::Keys;
use toon_provider::nostr::directory_events::{ProfileContent, HIDDEN_LABEL};
use toon_provider::nostr::kinds::{K_LISTING, K_PROFILE, TOON_LABEL};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::{Listing, ProviderConfig};

async fn hidden_harness(listings: Vec<Listing>) -> common::harness::Harness {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let registry = stub_registry().await;
    let config = hidden_config(config_for(
        listings,
        &keys.secret_key().to_secret_hex(),
        &state_path,
        &registry,
        ImagePolicyConfig::default(),
    ));
    harness_from(
        config,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
    )
}

// ── what it publishes ───────────────────────────────────────────────────

#[tokio::test]
async fn a_hidden_provider_publishes_hidden_true_no_host_and_the_label_on_every_listing() {
    let h = hidden_harness(vec![listing("basic", 1, 2), listing("gpu", 1, 1)]).await;
    h.service.publish_directory().await.unwrap();

    let profiles = h.directory.of_kind(K_PROFILE);
    assert_eq!(profiles.len(), 1);
    let content: ProfileContent = serde_json::from_str(&profiles[0].content).unwrap();
    assert!(content.hidden, "the declaration (spec §4.1, §10)");
    assert_eq!(content.host, None);
    let raw: serde_json::Value = serde_json::from_str(&profiles[0].content).unwrap();
    assert!(
        raw.get("host").is_none(),
        "no `host` key at all, not a null: {}",
        raw
    );
    assert_eq!(content.connector_url, HIDDEN_CONNECTOR_URL);

    let listings = h.directory.of_kind(K_LISTING);
    assert_eq!(listings.len(), 2);
    for event in &listings {
        assert!(
            has_tag(event, &["l", HIDDEN_LABEL, TOON_LABEL]),
            "every Listing carries [\"l\", \"hidden:true\", \"toon.network\"] (spec §4.2): {:?}",
            event.tags
        );
        // Beside, not instead of, the labels every Listing carries.
        assert!(has_tag(
            event,
            &["l", "isolation:shared-kernel", TOON_LABEL]
        ));
        assert!(has_tag(event, &["l", "arch:amd64", TOON_LABEL]));
    }
    // Nothing hidden was asked of the daemon: no lease exists to give an
    // address to, and the Directory needs none.
    assert!(h.hidden_service.created().is_empty());
    assert!(h.hidden_service.destroyed().is_empty());
}

#[tokio::test]
async fn a_provider_that_is_not_hidden_publishes_exactly_what_it_did_before() {
    let h = harness().await;
    h.service.publish_directory().await.unwrap();

    let profile = &h.directory.of_kind(K_PROFILE)[0];
    let content: ProfileContent = serde_json::from_str(&profile.content).unwrap();
    assert!(!content.hidden);
    assert_eq!(content.host.as_deref(), Some(PUBLIC_IP));

    for event in h.directory.of_kind(K_LISTING) {
        assert!(
            !has_tag(&event, &["l", HIDDEN_LABEL, TOON_LABEL]),
            "no hidden label, and never a `hidden:false`: {:?}",
            event.tags
        );
        assert!(!event.tags.iter().any(|t| t
            .clone()
            .to_vec()
            .get(1)
            .is_some_and(|v| v.starts_with("hidden:"))));
    }
}

// ── what it refuses, until M4-2 ─────────────────────────────────────────

#[tokio::test]
async fn a_spawn_on_a_hidden_provider_is_invalid_request_until_per_lease_addresses_land() {
    let h = hidden_harness(vec![Listing {
        standby_price: Some(400),
        ..listing("basic", 1, 2)
    }])
    .await;
    let content = spawn_content(1);

    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("later in Milestone 4"),
        "{}",
        body
    );

    // The `.standby` route is the same spawn, and a reservation would owe
    // an address at Takeover it could not give either.
    let (status, body) = post(
        &h.app,
        "/listings/basic/v1/standby",
        json!({ "request": RequestSpec::spawn(&h, &spawn_content(2)).sign() }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    // Refused before anything was taken: no slot, no workload, no address.
    assert!(h.backend.calls().is_empty(), "{:?}", h.backend.calls());
    assert!(h.hidden_service.created().is_empty());
    let (status, body) = post(
        &h.app,
        "/status",
        json!({ "request": RequestSpec::about(&h, "status", &content.workload_id).sign() }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{}", body);
    assert_eq!(error_of(&body), "unknown_workload");
}

#[tokio::test]
async fn availability_on_a_hidden_provider_says_so_for_free_first() {
    // Spec §9: a refusal a paid spawn would buy is answered on
    // `availability` first, so nobody pays for an address the provider
    // cannot yet give.
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    let (status, body) = post(
        &h.app,
        "/availability",
        json!({
            "listing": "basic",
            "version": 1,
            "image": { "reference": "docker.io/library/alpine", "digest": digest() },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["would_run"], false);
    assert_eq!(error_of(&body), "invalid_request");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("later in Milestone 4"),
        "{}",
        body
    );

    // A version this provider does not sell is still that refusal: the
    // placeholder sits behind step 2, not in front of every answer.
    let (_, body) = post(
        &h.app,
        "/availability",
        json!({
            "listing": "basic",
            "version": 2,
            "image": { "reference": "docker.io/library/alpine", "digest": digest() },
        }),
    )
    .await;
    assert_eq!(error_of(&body), "wrong_listing_version");
}

#[tokio::test]
async fn liveness_on_a_hidden_provider_still_counts_its_capacity() {
    // The Directory loop works: nothing about hiding changes what Liveness
    // says, and a hidden provider with no lease announces full capacity.
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    h.service.publish_liveness(NOW).await.unwrap();
    let liveness = h.directory.of_kind(toon_provider::nostr::kinds::K_LIVENESS);
    assert_eq!(liveness.len(), 1);
    let content: serde_json::Value = serde_json::from_str(&liveness[0].content).unwrap();
    assert_eq!(content["available"]["basic"], 2);
}

// ── what a public provider hands its backend ────────────────────────────

#[tokio::test]
async fn a_public_providers_workload_carries_no_egress_policy() {
    // The field exists on every `ContainerConfig`; a provider that is not
    // hidden fills nothing in, so today's networking is what the backend
    // gets (M4-4 fills it for a hidden lease).
    let h = harness().await;
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["access"]["host"], PUBLIC_IP);
    let created = h.backend.created();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].egress, None);
    assert!(h.hidden_service.created().is_empty(), "never touched");
}

#[tokio::test]
async fn the_fake_hidden_service_answers_a_predictable_anyone_host_and_restores_it() {
    // What M4-2's tests and fixtures will assert `access.host` against,
    // and the restart story M4-3 needs: the key `create_address` answered
    // brings back the same host through `restore_address`.
    let workload_id = "ab".repeat(32);
    let host = FakeHiddenService::address_for(&workload_id);
    assert!(host.ends_with(".anyone"));
    assert_eq!(host.len(), 56 + ".anyone".len());
    assert!(toon_provider::is_anyone_host(&host));
    assert_ne!(host, FakeHiddenService::address_for(&"cd".repeat(32)));

    use toon_provider::{AddressPort, HiddenService};
    let fake = FakeHiddenService::new();
    let ports = [AddressPort::same(40000), AddressPort::same(41000)];
    let address = fake.create_address(&workload_id, &ports).await.unwrap();
    assert_eq!(address.host, host);
    let key = address
        .key
        .expect("the fake gives a key back, as the daemon does");
    fake.destroy_address(&workload_id).await.unwrap();
    assert!(fake.live().is_empty());
    assert_eq!(
        fake.restore_address(&workload_id, &key, &ports)
            .await
            .unwrap(),
        host,
        "the same key is the same address"
    );
    assert!(fake
        .restore_address(&workload_id, "ED25519-V3:somebody-elses", &ports)
        .await
        .is_err());
    assert_eq!(fake.created().len(), 1);
    assert_eq!(fake.restored().len(), 2);
    assert_eq!(fake.destroyed(), vec![workload_id.clone()]);
    // And a hidden config the gate accepts, so the harness shape is the
    // shape an operator writes.
    hidden_config(ProviderConfig::default())
        .validate()
        .expect("the harness's hidden config passes the gate");
}
