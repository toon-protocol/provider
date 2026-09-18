//! The handover tool against this provider (`tools/grant/seal.mjs`;
//! TOON_Network #59).
//!
//! `tests/gateway_grant.rs` proves what the PROVIDER does with a delegation
//! it is shown. This proves the other half: that the Gateway Handover a real
//! run of the tenant's tool produces carries a Gateway Grant this provider
//! accepts — that the two derivations, one in Rust and one in Node, are the
//! same derivation, and that the command line a tenant types reaches it.
//!
//! So the tool is RUN, as a process, with the flags its README documents:
//! `node tools/grant/seal.mjs handover … --dry-run`, whose report is the
//! message it would have sealed. Nothing about the derivation depends on the
//! sealing, and `--dry-run` needs no `npm install`, no channel and no
//! network — so the grant proven here is byte for byte the grant a sealed
//! handover carries.
//!
//! Node is therefore required to run this file. The two tools under `tools/`
//! are part of this repository and CI already runs on an image that has it.

mod common;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use nostr_sdk::Keys;
use serde_json::{json, Value};

use common::harness::{error_of, listing, post, restart, spawn_content, Harness, RequestSpec};
use common::{stub_registry, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::continuation::{ContinuationToken, RootSecret};
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::{ImagePolicyConfig, Listing};
use toon_provider::Clock;

/// The lease's root secret, as a tenant mints one and hands it to the tool
/// (spec §6.1.1). TEST-ONLY, and the only secret the tool takes.
const ROOT_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// How long past the clock the grants derived here are good for.
const GRANT_TTL: u64 = 3600;

/// The container port `spawn_content` asks for, and so the one a handover's
/// `http_port` may name.
const HTTP_PORT: &str = "443";

/// A tier that prices Warm Standbys, so a two-member set is not refused
/// merely because the listing sells none.
fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

/// A provider whose clock is the REAL one.
///
/// The tool runs on the wall clock and refuses a moment already past, which
/// is the right thing for a tenant and would make every grant derived here
/// look expired against the fixed `NOW` the other suites freeze. So the
/// provider is started at the same moment the tenant is at — which is what a
/// provider and a tenant ordinarily are.
async fn harness_now() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    restart(
        vec![warm()],
        Keys::generate().secret_key().to_secret_hex(),
        dir.keep()
            .join("leases.json")
            .to_string_lossy()
            .into_owned(),
        FakeBackend::new(),
        FakeClock::at(now()),
        FakeDirectory::new(),
        stub_registry().await,
        ImagePolicyConfig::default(),
    )
    .await
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn seal_mjs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/grant/seal.mjs")
}

/// One run of the tenant's tool, as a tenant runs it: the JSON report it
/// prints, which for a dry run is the message it would have sealed.
async fn seal(args: &[&str]) -> Value {
    let output = tokio::process::Command::new("node")
        .arg(seal_mjs())
        // The root secret goes in the environment and not in argv, which is
        // what the tool's README tells a tenant to do.
        .env("TOON_ROOT_SECRET", ROOT_SECRET)
        .args(args)
        .output()
        .await
        .expect("run `node tools/grant/seal.mjs`: this suite drives the tenant's tool, so Node must be on PATH");
    assert!(
        output.status.success(),
        "the tool refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the tool prints one JSON report on stdout")
}

/// The handover the tool derives for `members` (primary first), for a moment
/// `GRANT_TTL` from now.
async fn handover_for(workload_id: &str, members: &[String], expires_at: u64) -> Value {
    let expires_at = expires_at.to_string();
    let mut args = vec![
        "handover",
        "--workload",
        workload_id,
        "--http-port",
        HTTP_PORT,
        "--ports",
        HTTP_PORT,
        "--expires-at",
        &expires_at,
        // The gateway's connector: where the sealed message would have gone,
        // and the key it would have been sealed to. A dry run sends nothing,
        // but the tool refuses a connector it could not seal to whether or
        // not it is about to, so a run that got this far named a real one.
        "--gateway-route",
        "g.toon.workload-gateway.handover",
        "--gateway-seal-key",
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        "--dry-run",
    ];
    for member in members {
        args.push("--standby");
        args.push(member);
    }
    let report = seal(&args).await;
    assert_eq!(report["dry_run"], json!(true));
    report["handover"].clone()
}

/// The `standby_set` a handover carries, as the list of members it must be.
fn standby_set_of(handover: &Value) -> &Vec<Value> {
    handover["standby_set"].as_array().unwrap_or_else(|| {
        panic!(
            "a handover's `standby_set` is a list of members: {}",
            handover
        )
    })
}

/// The members a handover names, in the order it names them — primary first.
///
/// An entry is exactly `{ provider, grant }` and is checked to be: a gateway
/// REFUSES a field no member names rather than dropping it (spec §12.1), so a
/// stray one would be a handover no gateway admits, however well the grant
/// inside it reads a lease here.
fn members_of(handover: &Value) -> Vec<String> {
    standby_set_of(handover)
        .iter()
        .map(|member| {
            let fields = member
                .as_object()
                .unwrap_or_else(|| panic!("a member is a JSON object: {}", handover));
            let mut named: Vec<&str> = fields.keys().map(String::as_str).collect();
            named.sort_unstable();
            assert_eq!(
                named,
                ["grant", "provider"],
                "a member names its provider and bears its grant, and carries nothing a gateway would refuse: {}",
                handover
            );
            fields["provider"]
                .as_str()
                .unwrap_or_else(|| panic!("a member names its `provider`: {}", handover))
                .to_owned()
        })
        .collect()
}

/// The grant the handover derived for `provider`, out of that member's OWN
/// entry (spec §12.1) — where the gateway reads it.
///
/// A member the handover does not name PANICS rather than answering nothing:
/// a missing grant compared against another missing one is two `null`s that
/// agree, and this file's whole business is that they must not.
fn grant_hex<'a>(handover: &'a Value, provider: &str) -> &'a str {
    standby_set_of(handover)
        .iter()
        .find(|member| member["provider"] == json!(provider))
        .and_then(|member| member["grant"].as_str())
        .unwrap_or_else(|| {
            panic!(
                "the handover carries no grant for {}: {}",
                provider, handover
            )
        })
}

/// That grant as the value a request presents.
fn grant_at(handover: &Value, provider: &str) -> ContinuationToken {
    ContinuationToken::from_hex(grant_hex(handover, provider))
        .expect("a grant is 64 lowercase hex characters")
}

/// `status` for `workload_id`, presenting `token` and asserting the
/// delegation `at` when there is one — `tests/gateway_grant.rs`'s helper, on
/// whichever member is being asked.
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

/// Buy one lease at `h` on `path`, presenting the token `ROOT_SECRET`
/// derives for that provider — the one secret every grant below comes from.
async fn spawn_lease(
    h: &Harness,
    path: &str,
    op: &'static str,
    content: &SpawnContent,
) -> ContinuationToken {
    let token = RootSecret::from_hex(ROOT_SECRET)
        .expect("the root secret is 64 lowercase hex")
        .continuation_for(&h.provider);
    let spec = RequestSpec::op(h, op, serde_json::to_value(content).unwrap()).with_token(&token);
    let (status, body) = post(&h.app, path, json!({ "request": spec.request() })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    token
}

const SPAWN: &str = "/listings/warm/v1/spawn";
const STANDBY: &str = "/listings/warm/v1/standby";

/// The whole of the acceptance criterion: what a run of the tool produced is
/// accepted by this provider as a delegated `status`, and is answered
/// exactly what the tenant is answered.
#[tokio::test]
async fn the_handover_a_run_produces_is_accepted_as_a_delegated_status() {
    let h = harness_now().await;
    let content = spawn_content(0xaa);
    let token = spawn_lease(&h, SPAWN, "spawn", &content).await;
    let expires_at = h.clock.now() + GRANT_TTL;

    let (status, tenants_answer) = status_with(&h, &token, &content.workload_id, None).await;
    assert_eq!(status, StatusCode::OK, "{}", tenants_answer);

    let handover = handover_for(&content.workload_id, &[h.provider.to_hex()], expires_at).await;

    // What the tool says the gateway must serve is what this lease is.
    assert_eq!(handover["workload_id"], json!(content.workload_id));
    assert_eq!(members_of(&handover), vec![h.provider.to_hex()]);
    assert_eq!(handover["expires_at"], json!(expires_at));
    assert!(
        tenants_answer["access"]["ports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["container_port"] == handover["http_port"]),
        "the http_port the handover names is one the provider exposes: {}",
        tenants_answer
    );

    // And the grant it derived reads the lease, at this provider, for this
    // moment — answered byte for byte what the tenant's own token is.
    let (status, gateways_answer) = status_with(
        &h,
        &grant_at(&handover, &h.provider.to_hex()),
        &content.workload_id,
        Some(expires_at),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", gateways_answer);
    assert_eq!(
        gateways_answer, tenants_answer,
        "a gateway holding the handover's grant is answered exactly what the tenant is answered"
    );
}

/// Why a handover carries one grant PER MEMBER of the Standby Set.
///
/// A grant derives from the lease's Continuation Token, and that token is
/// per provider (spec §6.1.1, §7) — so a single grant would read at one
/// member and be `bad_grant` at every other, and a gateway asking all of
/// them (§12.4) would learn nothing from the rest. The tool derives one for
/// each, in the member's own entry, and each member takes its own and no
/// other.
#[tokio::test]
async fn each_member_of_a_standby_set_takes_its_own_grant_and_refuses_the_others() {
    let primary = harness_now().await;
    let standby = harness_now().await;
    let members = vec![primary.provider.to_hex(), standby.provider.to_hex()];
    let content = SpawnContent {
        standby_set: Some(members.clone()),
        ..spawn_content(0xbb)
    };
    spawn_lease(&primary, SPAWN, "spawn", &content).await;
    spawn_lease(&standby, STANDBY, "standby", &content).await;
    let expires_at = primary.clock.now() + GRANT_TTL;

    let handover = handover_for(&content.workload_id, &members, expires_at).await;
    assert_eq!(
        members_of(&handover),
        members,
        "the set is carried primary first, as the tenant gave it"
    );
    assert_ne!(
        grant_hex(&handover, &members[0]),
        grant_hex(&handover, &members[1]),
        "one grant per member, and no member's reads at another"
    );

    for (h, mine, theirs) in [
        (&primary, &members[0], &members[1]),
        (&standby, &members[1], &members[0]),
    ] {
        let (status, body) = status_with(
            h,
            &grant_at(&handover, mine),
            &content.workload_id,
            Some(expires_at),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}: {}", mine, body);

        let (status, body) = status_with(
            h,
            &grant_at(&handover, theirs),
            &content.workload_id,
            Some(expires_at),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {}", theirs, body);
        assert_eq!(error_of(&body), "bad_grant", "{}: {}", theirs, body);
    }
}

/// The tool derives rather than stores, and this provider is the judge of
/// that: a second run of the same command produces a grant that reads the
/// same lease, and a run for a later moment produces a different grant that
/// reads it too — which is the whole of rotation (spec §6.5.1).
#[tokio::test]
async fn a_second_run_derives_the_same_grant_and_a_later_moment_another_that_also_reads() {
    let h = harness_now().await;
    let content = spawn_content(0xcc);
    spawn_lease(&h, SPAWN, "spawn", &content).await;
    let provider = h.provider.to_hex();
    let expires_at = h.clock.now() + GRANT_TTL;

    let members = [provider.clone()];
    let first = handover_for(&content.workload_id, &members, expires_at).await;
    let again = handover_for(&content.workload_id, &members, expires_at).await;
    assert_eq!(
        first, again,
        "nothing about a run but its inputs decides it"
    );

    let later = handover_for(&content.workload_id, &members, expires_at + GRANT_TTL).await;
    assert_ne!(
        grant_hex(&later, &provider),
        grant_hex(&first, &provider),
        "a later moment is a different grant"
    );

    for (at, handover) in [(expires_at, &first), (expires_at + GRANT_TTL, &later)] {
        let (status, body) = status_with(
            &h,
            &grant_at(handover, &provider),
            &content.workload_id,
            Some(at),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        assert_eq!(body["state"], "running");
    }
}
