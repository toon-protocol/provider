//! A Gateway Grant on the free `status` route (spec §3.1.3, §6.5;
//! TOON_Network #47).
//!
//! A tenant signs a Gateway Grant naming one Workload Gateway, one workload
//! and an expiry. The gateway then calls `status` with its OWN signature and
//! carries the grant inside the request. The provider answers exactly what
//! the tenant would have been answered — and nothing else changes: a grant
//! delegates reading a lease and nothing more.
//!
//! Everything here is driven through the provider's HTTP surface, the way
//! its connector drives it: a request in, JSON out. Nothing reaches inside.

mod common;

use axum::http::StatusCode;
use nostr_sdk::{EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, Timestamp};
use serde_json::{json, Value};

use common::harness::{
    config_for, digest, error_of, harness, harness_from, hidden_config, listing, post,
    socks_proxy_of, spawn, spawn_content, workload_id, Harness, RequestSpec, NOW,
};
use common::socks::SocksStub;
use common::{stub_registry, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::is_anyone_host;
use toon_provider::nostr::gateway_grant::{gateway_grant_event, GrantContent};
use toon_provider::nostr::kinds::{K_GATEWAY_GRANT, K_LEASE_REQUEST, TOON_LABEL};
use toon_provider::provider::ImagePolicyConfig;

/// How long past `NOW` a grant in these tests is good for.
const GRANT_TTL: u64 = 3600;

/// The workload's HTTP port, as the tenant's spawn published it: which of a
/// spawn's ports a gateway should forward to is exactly what the grant is
/// for.
const HTTP_PORT: u16 = 443;

/// Buy one lease on `basic.v1.spawn`, and answer the tenant that holds it.
async fn lease(h: &Harness, seed: u8) -> Keys {
    let spec = RequestSpec::spawn(h, &spawn_content(seed));
    let tenant = Keys::parse(&spec.tenant.secret_key().to_secret_hex()).unwrap();
    let (status, body) = spawn(h, spec.sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    tenant
}

/// The grant content a tenant signs for a standalone lease: one gateway, one
/// workload, a `standby_set` naming the one PROVIDER that holds the lease,
/// and an expiry. The provider reads neither `http_port` nor `standby_set` —
/// they tell the gateway which port to forward to and which providers to ask
/// — but a grant that named the wrong thing there would be a bad example.
fn grant_content(h: &Harness, gateway: &PublicKey, seed: u8, expires_at: u64) -> GrantContent {
    GrantContent {
        workload_id: workload_id(seed),
        gateway: gateway.to_hex(),
        http_port: HTTP_PORT,
        standby_set: vec![h.provider.to_hex()],
        expires_at,
        name: None,
    }
}

/// A grant as the tenant signs and publishes it, serialised the way a
/// `status` request carries it.
fn grant(content: &GrantContent, tenant: &Keys) -> Value {
    let event = gateway_grant_event(content, tenant, NOW).unwrap();
    serde_json::to_value(event).unwrap()
}

/// `status` for `seed`, signed by `signer`, carrying `grant` when there is
/// one.
async fn status_with(
    h: &Harness,
    signer: &Keys,
    seed: u8,
    grant: Option<Value>,
) -> (StatusCode, Value) {
    let mut content = json!({ "workload_id": workload_id(seed) });
    if let Some(grant) = grant {
        content["grant"] = grant;
    }
    let spec = RequestSpec {
        tenant: Keys::parse(&signer.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::op(h, "status", content)
    };
    post(&h.app, "/status", json!({ "request": spec.sign() })).await
}

#[tokio::test]
async fn a_granted_gateway_reads_exactly_what_the_tenant_reads() {
    let h = harness().await;
    let tenant = lease(&h, 0xaa).await;
    let gateway = Keys::generate();

    let (status, tenants_answer) = status_with(&h, &tenant, 0xaa, None).await;
    assert_eq!(status, StatusCode::OK, "{}", tenants_answer);

    let content = grant_content(&h, &gateway.public_key(), 0xaa, NOW + GRANT_TTL);
    let (status, gateways_answer) =
        status_with(&h, &gateway, 0xaa, Some(grant(&content, &tenant))).await;
    assert_eq!(status, StatusCode::OK, "{}", gateways_answer);
    assert_eq!(
        gateways_answer, tenants_answer,
        "a granted gateway is answered exactly what the tenant is answered"
    );
}

/// A grant event built by hand and properly signed, so a test can vary the
/// `d` tag and the kind independently of the content — which
/// `gateway_grant_event` cannot do, because it derives both from what it is
/// given.
fn signed_as(content: &GrantContent, tenant: &Keys, kind: u16, identifier: &str) -> Value {
    let event = EventBuilder::new(Kind::Custom(kind), serde_json::to_string(content).unwrap())
        .tags([
            Tag::identifier(identifier.to_string()),
            Tag::custom(TagKind::p(), [content.gateway.clone()]),
            Tag::custom(TagKind::custom("L"), [TOON_LABEL]),
        ])
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(tenant)
        .unwrap();
    serde_json::to_value(event).unwrap()
}

/// That builder with the kind a grant actually has, for the cases that vary
/// only the `d` tag.
fn grant_with_identifier(content: &GrantContent, tenant: &Keys, identifier: &str) -> Value {
    signed_as(content, tenant, K_GATEWAY_GRANT, identifier)
}

/// Every way a grant can fail to admit the gateway carrying it. Each is
/// `bad_grant` and nothing else: a gateway learns that its grant does not
/// apply, and nothing about the lease.
#[tokio::test]
async fn every_grant_defect_is_bad_grant_and_nothing_else() {
    let h = harness().await;
    let tenant = lease(&h, 0xaa).await;
    let gateway = Keys::generate();
    let good = grant_content(&h, &gateway.public_key(), 0xaa, NOW + GRANT_TTL);

    // A signature that does not verify.
    let mut tampered_sig = grant(&good, &tenant);
    let sig = tampered_sig["sig"].as_str().unwrap().to_string();
    tampered_sig["sig"] = json!(format!(
        "{}{}",
        if sig.starts_with('0') { "1" } else { "0" },
        &sig[1..]
    ));

    // An id that is no longer the hash of the fields under it: the content
    // was changed after signing, to name a gateway the tenant never named.
    let mut tampered_id = grant(&good, &tenant);
    let mut stolen = good.clone();
    stolen.gateway = Keys::generate().public_key().to_hex();
    tampered_id["content"] = json!(serde_json::to_string(&stolen).unwrap());

    // Signed by a tenant who does not hold this lease.
    let stranger = Keys::generate();
    let by_a_stranger = grant(&good, &stranger);

    // About another workload, in content and in the `d` tag together...
    let elsewhere = grant_content(&h, &gateway.public_key(), 0xbb, NOW + GRANT_TTL);
    // ...and in each of them alone, so neither can be trusted without the
    // other.
    let content_elsewhere = grant_with_identifier(&elsewhere, &tenant, &workload_id(0xaa));
    let identifier_elsewhere = grant_with_identifier(&good, &tenant, &workload_id(0xbb));

    // Naming a gateway that is not the key signing the request.
    let another_gateway = grant_content(&h, &Keys::generate().public_key(), 0xaa, NOW + GRANT_TTL);

    // Expired one second ago.
    let expired = grant_content(&h, &gateway.public_key(), 0xaa, NOW - 1);

    // Correctly signed by the tenant, about this workload, naming this
    // gateway, unexpired — and not a grant at all, because its kind is a
    // Lease Request's. Nothing the tenant signed as a kind 4432 delegates
    // anything, whatever its content happens to say.
    let wrong_kind = signed_as(&good, &tenant, K_LEASE_REQUEST, &workload_id(0xaa));

    for (case, grant_json) in [
        ("a signature that does not verify", tampered_sig),
        ("an id that no longer hashes its fields", tampered_id),
        ("signed by someone who is not the tenant", by_a_stranger),
        ("about another workload", grant(&elsewhere, &tenant)),
        ("content naming another workload", content_elsewhere),
        ("a `d` tag naming another workload", identifier_elsewhere),
        ("naming another gateway", grant(&another_gateway, &tenant)),
        ("expired", grant(&expired, &tenant)),
        ("not a Gateway Grant at all", wrong_kind),
    ] {
        let (status, body) = status_with(&h, &gateway, 0xaa, Some(grant_json)).await;
        assert_eq!(error_of(&body), "bad_grant", "{}: {}", case, body);
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {}", case, body);
    }
}

/// A grant is the only thing that admits a signer who is not the tenant, so
/// a stranger that brings none hears exactly what it always heard. The two
/// refusals stay tellable apart: `not_tenant` says "sign as the tenant",
/// `bad_grant` says "your grant does not apply".
#[tokio::test]
async fn a_stranger_with_no_grant_is_still_not_tenant() {
    let h = harness().await;
    let _tenant = lease(&h, 0xaa).await;

    let (status, body) = status_with(&h, &Keys::generate(), 0xaa, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "not_tenant");
}

/// `status` is the only route a grant means anything on. A gateway with a
/// perfectly good grant may not end the lease it reads, and the lease it
/// tried to end is untouched: a grant delegates reading and nothing more.
#[tokio::test]
async fn a_granted_gateway_may_not_terminate_the_lease_it_reads() {
    let h = harness().await;
    let tenant = lease(&h, 0xaa).await;
    let gateway = Keys::generate();
    let content = grant_content(&h, &gateway.public_key(), 0xaa, NOW + GRANT_TTL);

    let request = RequestSpec {
        tenant: Keys::parse(&gateway.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::op(
            &h,
            "terminate",
            json!({
                "workload_id": workload_id(0xaa),
                "grant": grant(&content, &tenant),
            }),
        )
    };
    let (status, body) = post(&h.app, "/terminate", json!({ "request": request.sign() })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(
        error_of(&body),
        "not_tenant",
        "a grant is not read on terminate, so its bearer is a stranger there"
    );

    let (status, body) = status_with(&h, &tenant, 0xaa, None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], "running", "the lease was never touched");
}

/// And the tenant's own termination is unchanged by a grant riding along:
/// the field is parsed and ignored, never acted on.
#[tokio::test]
async fn a_grant_on_the_tenants_own_terminate_changes_nothing() {
    let h = harness().await;
    let tenant = lease(&h, 0xaa).await;
    let gateway = Keys::generate();
    let content = grant_content(&h, &gateway.public_key(), 0xaa, NOW + GRANT_TTL);

    let request = RequestSpec {
        tenant: Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::op(
            &h,
            "terminate",
            json!({
                "workload_id": workload_id(0xaa),
                "grant": grant(&content, &tenant),
            }),
        )
    };
    let (status, body) = post(&h.app, "/terminate", json!({ "request": request.sign() })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "termination" }));
}

/// `grant` is a field of the `status`/`terminate` content and of no other,
/// so on the paid routes and on `availability` it stays what any field this
/// provider does not know has always been: `invalid_request`, never dropped
/// (ADR 0004).
#[tokio::test]
async fn a_grant_on_spawn_extend_standby_extend_or_availability_is_unknown() {
    let h = harness().await;
    let tenant = Keys::generate();
    let gateway = Keys::generate();
    let content = grant_content(&h, &gateway.public_key(), 0xaa, NOW + GRANT_TTL);
    let grant = grant(&content, &tenant);

    let mut spawn_content = serde_json::to_value(spawn_content(0xaa)).unwrap();
    spawn_content["grant"] = grant.clone();
    let (status, body) = spawn(&h, RequestSpec::op(&h, "spawn", spawn_content).sign()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    let (status, body) = post(
        &h.app,
        "/listings/basic/v1/extend",
        json!({ "workload_id": workload_id(0xaa), "grant": grant.clone() }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    let (status, body) = post(
        &h.app,
        "/listings/basic/v1/standby/extend",
        json!({ "workload_id": workload_id(0xaa), "grant": grant.clone() }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    let (status, body) = post(
        &h.app,
        "/availability",
        json!({
            "listing": "basic",
            "version": 1,
            "image": { "reference": "docker.io/library/alpine", "digest": digest() },
            "grant": grant,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["would_run"], false);
    assert_eq!(error_of(&body), "invalid_request");
}

/// A Hidden Provider answers a granted `status` exactly as it answers its
/// tenant's — with the lease's own `.anyone` address (spec §10) — and opens
/// nothing to do it.
///
/// That second half is the point of carrying the grant in the request. The
/// provider's whole outbound leaves through its `anon` SOCKS proxy, and the
/// stub here records every destination it was asked for; a grant read from a
/// relay, or any per-gateway lookup, would show up as a connection between
/// the spawn and the answer. None does.
#[tokio::test]
async fn a_hidden_providers_granted_status_names_the_anyone_host_and_dials_nothing() {
    let socks = SocksStub::start(&[]).await;
    let registry = stub_registry().await;
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let h = harness_from(
        socks_proxy_of(
            hidden_config(config_for(
                vec![listing("basic", 1, 2)],
                &keys.secret_key().to_secret_hex(),
                &state_path,
                &registry,
                ImagePolicyConfig::default(),
            )),
            &socks.url(),
        ),
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
    );

    let tenant = lease(&h, 0xaa).await;
    let gateway = Keys::generate();
    let content = grant_content(&h, &gateway.public_key(), 0xaa, NOW + GRANT_TTL);

    // The spawn fetched an image, which is outbound this provider makes for
    // every lease — and proves the stub is the only way out of this process,
    // so "nothing more was dialled" below is an assertion and not an
    // accident of nothing using the proxy at all.
    let before = socks.destinations();
    assert!(
        !before.is_empty(),
        "the spawn's own outbound left through the proxy"
    );

    let (status, body) = status_with(&h, &gateway, 0xaa, Some(grant(&content, &tenant))).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let host = body["access"]["host"].as_str().unwrap();
    assert!(
        is_anyone_host(host),
        "a hidden lease is reached at its own .anyone address, not {:?}",
        host
    );
    assert_eq!(
        socks.destinations(),
        before,
        "verifying a grant opened no connection"
    );
}

/// The wire fixture's grant — the exact bytes the tenant-side grant tool
/// (`tools/grant`) is proven to reproduce, id and signature included —
/// driven through this provider: accepted while it is in force, and
/// `bad_grant` the second after its `expires_at`.
///
/// The tool's own tests prove the bytes (`tools/grant/grant.test.mjs`);
/// this proves the bytes against the provider, over the fixture's own keys
/// and clock, so "a provider accepts what the tool produced and refuses it
/// once it has expired" is one claim checked end to end rather than two
/// halves each assuming the other.
#[tokio::test]
async fn the_fixture_grant_a_tenant_tool_reproduces_is_accepted_until_it_expires() {
    let h = harness().await;
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/wire/gateway_grant.json")).unwrap();
    let grant_json = fixture["event"].clone();
    let expires_at = fixture["content"]["expires_at"].as_u64().unwrap();

    // The keys the fixture was signed for, read from the same constants the
    // tool's tests read; the workload id (`aa` × 32) is the one its `d`
    // tag names.
    let constants: Value =
        serde_json::from_str(include_str!("fixtures/wire/constants.json")).unwrap();
    let tenant = Keys::parse(constants["tenant"]["secret_key"].as_str().unwrap()).unwrap();
    let gateway = Keys::parse(constants["gateway"]["secret_key"].as_str().unwrap()).unwrap();
    assert_eq!(grant_json["pubkey"], json!(tenant.public_key().to_hex()));
    assert_eq!(grant_json["tags"][0], json!(["d", workload_id(0xaa)]));
    assert_eq!(
        grant_json["tags"][1],
        json!(["p", gateway.public_key().to_hex()])
    );

    let spec = RequestSpec {
        tenant: Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::spawn(&h, &spawn_content(0xaa))
    };
    let (status, body) = spawn(&h, spec.sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let (status, tenants_answer) = status_with(&h, &tenant, 0xaa, None).await;
    assert_eq!(status, StatusCode::OK, "{}", tenants_answer);
    let (status, gateways_answer) = status_with(&h, &gateway, 0xaa, Some(grant_json.clone())).await;
    assert_eq!(status, StatusCode::OK, "{}", gateways_answer);
    assert_eq!(gateways_answer, tenants_answer);

    h.clock.set(expires_at + 1);
    let (status, body) = status_with(&h, &gateway, 0xaa, Some(grant_json)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "bad_grant");
    assert!(
        body["message"].as_str().unwrap().contains("expired"),
        "the refusal names the expiry: {}",
        body
    );
}
