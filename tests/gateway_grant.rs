//! A Gateway Grant on the free `status` route (spec §6.5; TOON_Network #58).
//!
//! A tenant delegates reading one workload to one Workload Gateway without
//! publishing anything and without telling the provider. The grant is
//! DERIVED from the lease's Continuation Token — `gateway_sub(provider,
//! expires_at)` — so the provider stores no second value and reads no relay:
//! it already holds the token, so it can recompute any grant it is shown.
//!
//! The gateway presents that value as its request's `continuation` and names
//! the moment it was derived for, and the provider answers exactly what the
//! tenant would have been answered. Nothing else changes: a grant delegates
//! reading a lease and nothing more.
//!
//! Everything here is driven through the provider's HTTP surface, the way
//! its connector drives it: a request in, JSON out. Nothing reaches inside.

mod common;

use axum::http::StatusCode;
use nostr_sdk::Keys;
use serde_json::{json, Value};

use common::harness::{
    config_for, digest, error_of, harness, harness_from, hidden_config, listing, mint, post,
    socks_proxy_of, spawn, spawn_content, workload_id, Harness, RequestSpec, NOW,
};
use common::socks::SocksStub;
use common::{stub_registry, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::is_anyone_host;
use toon_provider::nostr::continuation::ContinuationToken;
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::Clock;

/// How long past the harness clock a grant in these tests is good for.
const GRANT_TTL: u64 = 3600;

/// A lease that exists, and the Continuation Token it was taken with — the
/// whole of what a tenant needs to delegate reading it (spec §6.1).
struct Lease {
    token: ContinuationToken,
    workload_id: String,
}

/// Buy one lease on `basic.v1.spawn`, and hand back the token that took it.
async fn spawn_lease(h: &Harness, seed: u8) -> Lease {
    let token = mint().continuation_for(&h.provider);
    let content = spawn_content(seed);
    let spec = RequestSpec::spawn(h, &content).with_token(&token);
    let (status, body) = spawn(h, spec.request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    Lease {
        token,
        workload_id: content.workload_id,
    }
}

/// `status` for `workload_id`, presenting `token` and asserting the
/// delegation `at` when there is one.
async fn status_with(
    h: &Harness,
    token: &ContinuationToken,
    workload_id: &str,
    at: Option<u64>,
) -> (StatusCode, Value) {
    let mut content = json!({ "workload_id": workload_id });
    if let Some(expires_at) = at {
        content["gateway_expires_at"] = json!(expires_at);
    }
    let spec = RequestSpec::op(h, "status", content).with_token(token);
    post(&h.app, "/status", json!({ "request": spec.request() })).await
}

#[tokio::test]
async fn a_grant_reads_exactly_what_the_tenant_reads() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let expires_at = h.clock.now() + GRANT_TTL;

    let (status, tenants_answer) = status_with(&h, &lease.token, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", tenants_answer);

    // What the provider held before it was shown a grant it had never seen.
    let before = std::fs::read(&h.state_path).unwrap();

    let grant = lease.token.gateway_sub(expires_at);
    let (status, gateways_answer) =
        status_with(&h, &grant, &lease.workload_id, Some(expires_at)).await;
    assert_eq!(status, StatusCode::OK, "{}", gateways_answer);
    assert_eq!(
        gateways_answer, tenants_answer,
        "a gateway holding a grant is answered exactly what the tenant is answered"
    );

    // And it holds the same thing afterwards. The grant is RECOMPUTED from
    // the token the lease already stored, so there is nothing per gateway to
    // write down and nothing to look up: `Directory` is the provider's whole
    // relay surface, and it was asked nothing.
    assert_eq!(
        std::fs::read(&h.state_path).unwrap(),
        before,
        "a grant adds nothing to what the provider stores"
    );
    assert!(
        h.directory.reads().is_empty(),
        "the Directory was asked {:?}",
        h.directory.reads()
    );
}

/// A delegation ends by expiring, and there is no other way it ends: a
/// tenant that wants a gateway cut off sooner waits (spec §6.5). The value
/// presented here is the RIGHT one for the moment it names — the moment is
/// simply past, which is refused before the provider derives anything.
#[tokio::test]
async fn a_grant_whose_moment_has_passed_is_bad_grant() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let expires_at = h.clock.now() + GRANT_TTL;
    let grant = lease.token.gateway_sub(expires_at);

    // At the moment itself it still reads: `expires_at` is the last second
    // a grant is good for, not the first it is not.
    h.clock.set(expires_at);
    let (status, body) = status_with(&h, &grant, &lease.workload_id, Some(expires_at)).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    h.clock.set(expires_at + 1);
    let (status, body) = status_with(&h, &grant, &lease.workload_id, Some(expires_at)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
    assert_eq!(error_of(&body), "bad_grant");
}

/// Every way a value can fail to be a grant that applies here, and one code
/// for all of them: a gateway learns that its delegation does not apply, and
/// nothing about the lease.
#[tokio::test]
async fn every_delegation_defect_is_bad_grant_and_nothing_else() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let other = spawn_lease(&h, 0xbb).await;
    let now = h.clock.now();
    let expires_at = now + GRANT_TTL;

    for (case, presented, asserted) in [
        (
            "derived for one moment, presented with another",
            lease.token.gateway_sub(expires_at),
            expires_at + 1,
        ),
        (
            "derived for another lease of this same provider",
            other.token.gateway_sub(expires_at),
            expires_at,
        ),
        (
            "derived from a token no lease here was taken with",
            mint().continuation_for(&h.provider).gateway_sub(expires_at),
            expires_at,
        ),
        (
            "another lease's own Continuation Token, asserted as a delegation",
            other.token.clone(),
            expires_at,
        ),
        (
            "32 bytes that were derived for nothing at all",
            mint().continuation_for(&h.provider),
            expires_at,
        ),
    ] {
        let (status, body) = status_with(&h, &presented, &lease.workload_id, Some(asserted)).await;
        assert_eq!(error_of(&body), "bad_grant", "{}: {}", case, body);
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {}", case, body);
        assert!(
            !body["message"]
                .as_str()
                .unwrap()
                .contains(&lease.workload_id),
            "{}: a refusal says nothing about the lease: {}",
            case,
            body
        );
    }

    // And the lease still reads, to its tenant and to a grant that does
    // apply: nothing above changed anything.
    let (status, body) = status_with(&h, &lease.token, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

/// Rotation is re-derivation at a new moment, and nothing else — there is no
/// state to move and nothing to publish (spec §6.5). Two grants of one lease
/// for two moments both read, which is what makes handing out a later one a
/// renewal rather than a migration.
#[tokio::test]
async fn a_grant_for_a_later_moment_reads_beside_the_one_it_renews() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let now = h.clock.now();

    for at in [now + GRANT_TTL, now + 2 * GRANT_TTL] {
        let (status, body) = status_with(
            &h,
            &lease.token.gateway_sub(at),
            &lease.workload_id,
            Some(at),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        assert_eq!(body["state"], "running");
    }
}

/// A grant admits `status` and nothing else (spec §6.5, §6.6), and the shape
/// is what says so rather than a rule the terminate route has to remember.
/// `gateway_expires_at` is named by `status` content alone: with it, a
/// `terminate` is refused for a field this provider does not know; without
/// it, the grant is just a token this lease was not taken with. Neither
/// touches the lease.
#[tokio::test]
async fn a_grant_cannot_terminate_the_lease_it_reads() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let expires_at = h.clock.now() + GRANT_TTL;
    let grant = lease.token.gateway_sub(expires_at);

    let with_field = json!({
        "workload_id": lease.workload_id,
        "gateway_expires_at": expires_at,
    });
    let without = json!({ "workload_id": lease.workload_id });
    for (case, content, expected, code) in [
        (
            "asserting the delegation it holds",
            with_field,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "asserting nothing, as any stranger does",
            without,
            StatusCode::FORBIDDEN,
            "not_tenant",
        ),
    ] {
        let spec = RequestSpec::op(&h, "terminate", content).with_token(&grant);
        let (status, body) = post(&h.app, "/terminate", json!({ "request": spec.request() })).await;
        assert_eq!(status, expected, "{}: {}", case, body);
        assert_eq!(error_of(&body), code, "{}: {}", case, body);
    }

    // The lease is untouched, and its own token still ends it.
    let (status, body) = status_with(&h, &lease.token, &lease.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], "running");
}

/// The refusal a value that asserts NO delegation gets, on both routes that
/// take one: `not_tenant`, exactly as any other stranger's does. This is the
/// half of "the assertion decides the refusal" that keeps the two codes
/// tellable apart — `not_tenant` says *you are not the tenant*, `bad_grant`
/// says *your delegation does not apply here* — and it is what stops a
/// gateway learning anything by dropping the field.
#[tokio::test]
async fn a_grant_presented_without_its_moment_is_not_tenant_everywhere() {
    let h = harness().await;
    let lease = spawn_lease(&h, 0xaa).await;
    let grant = lease.token.gateway_sub(h.clock.now() + GRANT_TTL);

    for op in ["status", "terminate"] {
        let spec = RequestSpec::about(&h, op, &lease.workload_id).with_token(&grant);
        let (status, body) = post(
            &h.app,
            &format!("/{}", op),
            json!({ "request": spec.request() }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {}", op, body);
        assert_eq!(error_of(&body), "not_tenant", "{}: {}", op, body);
    }
}

/// `gateway_expires_at` is a field of `status` content and of no other, so
/// everywhere else it stays what any field this provider does not know has
/// always been: `invalid_request`, never dropped (ADR 0004). A tenant that
/// put it on the wrong request learns that, rather than believing it bought
/// a delegation.
#[tokio::test]
async fn gateway_expires_at_anywhere_but_status_is_an_unknown_field() {
    let h = harness().await;
    let expires_at = h.clock.now() + GRANT_TTL;

    let mut content = serde_json::to_value(spawn_content(0xaa)).unwrap();
    content["gateway_expires_at"] = json!(expires_at);
    let (status, body) = spawn(&h, RequestSpec::op(&h, "spawn", content).request()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");

    for path in [
        "/listings/basic/v1/extend",
        "/listings/basic/v1/standby/extend",
    ] {
        let (status, body) = post(
            &h.app,
            path,
            json!({ "workload_id": workload_id(0xaa), "gateway_expires_at": expires_at }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {}", path, body);
        assert_eq!(error_of(&body), "invalid_request", "{}: {}", path, body);
    }

    let (status, body) = post(
        &h.app,
        "/availability",
        json!({
            "listing": "basic",
            "version": 1,
            "image": { "reference": "docker.io/library/alpine", "digest": digest() },
            "gateway_expires_at": expires_at,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["would_run"], false);
    assert_eq!(error_of(&body), "invalid_request");
}

/// A Hidden Provider answers a grant's `status` exactly as it answers its
/// tenant's — with the lease's own `.anyone` address (spec §10) — and opens
/// nothing to do it.
///
/// That second half is the point of DERIVING the delegation rather than
/// publishing it. The provider's whole outbound leaves through its `anon`
/// SOCKS proxy, and the stub here records every destination it was asked
/// for; a grant read from a relay, or any per-gateway lookup, would show up
/// as a connection between the spawn and the answer. None does.
#[tokio::test]
async fn a_hidden_providers_delegated_status_names_the_anyone_host_and_dials_nothing() {
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

    let lease = spawn_lease(&h, 0xaa).await;
    let expires_at = h.clock.now() + GRANT_TTL;

    // The spawn fetched an image, which is outbound this provider makes for
    // every lease — and proves the stub is the only way out of this process,
    // so "nothing more was dialled" below is an assertion and not an
    // accident of nothing using the proxy at all.
    let before = socks.destinations();
    assert!(
        !before.is_empty(),
        "the spawn's own outbound left through the proxy"
    );

    let (status, body) = status_with(
        &h,
        &lease.token.gateway_sub(expires_at),
        &lease.workload_id,
        Some(expires_at),
    )
    .await;
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
        "checking a grant opened no connection"
    );
}
