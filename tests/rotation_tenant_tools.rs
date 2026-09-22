//! The tenant tools against a Standby Set rotated at ONE member and not the
//! other (spec §6.8, ADR 0018; TOON_Network #80).
//!
//! `tests/rotate_tool.rs` proves `rotateLease` keeps this state true in the
//! lease file: `root_secret` stays the OLD one, `rotation.root_secret` holds
//! the NEW one, and `rotation.confirmed` names the members that already read
//! it. This proves the OTHER tools read that state correctly instead of
//! ignoring it: a handover sealed mid-rotation (`seal.mjs handover --lease`)
//! carries a grant EACH member accepts — the confirmed member's derived from
//! the new root, the other's from the old one — and a terminate derived
//! through the grant tool's shared `currentRootFor` ends the lease at both.
//! Before this ticket, both read one flat root secret for the whole set: the
//! rotated member refused the handover's grant `bad_grant`, and refused the
//! terminate `not_tenant`.
//!
//! Each provider is served on a real TCP port, exactly as `tests/rotate_tool.rs`
//! and `tests/gateway_handover.rs` serve theirs, so what is proven here is
//! that a REAL admission round accepts what the tools produce — not an
//! assumption about the derivation alone.

mod common;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use nostr_sdk::Keys;
use serde_json::{json, Value};

use common::harness::{listing, post, restart, spawn_content, Harness, RequestSpec};
use common::{stub_registry, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::nostr::continuation::{ContinuationToken, RootSecret};
use toon_provider::nostr::wire::SpawnContent;
use toon_provider::provider::{ImagePolicyConfig, Listing};

/// The lease's OLD root secret — what the file holds as `root_secret` while
/// the rotation below is unfinished. TEST-ONLY.
const ROOT_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// The NEW root secret a rotation is midway through installing:
/// `rotation.root_secret` in the lease file, and what the CONFIRMED member —
/// the primary, in every test here — already reads with.
const NEW_ROOT_SECRET: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// A member's pinned sealing key, which the handover tool checks and this
/// suite's `ask`s never use. Synthetic: the secp256k1 generator point.
const SEAL_KEY: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

const SPAWN: &str = "/listings/warm/v1/spawn";
const STANDBY: &str = "/listings/warm/v1/standby";
const GRANT_TTL: u64 = 3600;

fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A provider on the REAL clock, served on a TCP port of its own — the
/// handover tool stamps `expiration` off the wall clock, exactly as
/// `tests/gateway_handover.rs`'s `harness_now` does.
async fn served_provider() -> (Harness, String) {
    let dir = tempfile::tempdir().unwrap();
    let h = restart(
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
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = h.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (h, url)
}

fn root(hex: &str) -> RootSecret {
    RootSecret::from_hex(hex).expect("a root secret is 64 lowercase hex")
}

/// A two-member Standby Set bought with `ROOT_SECRET`: the primary on
/// `.spawn`, the standby on `.standby`, each with the token derived for it —
/// `tests/rotate_tool.rs`'s `Set`, in miniature.
struct Set {
    primary: Harness,
    standby: Harness,
    urls: [String; 2],
    workload_id: String,
}

impl Set {
    async fn bought(seed: u8) -> Self {
        let (primary, primary_url) = served_provider().await;
        let (standby, standby_url) = served_provider().await;
        let content = SpawnContent {
            standby_set: Some(vec![primary.provider.to_hex(), standby.provider.to_hex()]),
            ..spawn_content(seed)
        };
        for (h, path, op) in [(&primary, SPAWN, "spawn"), (&standby, STANDBY, "standby")] {
            let token = root(ROOT_SECRET).continuation_for(&h.provider);
            let spec =
                RequestSpec::op(h, op, serde_json::to_value(&content).unwrap()).with_token(&token);
            let (status, body) = post(&h.app, path, json!({ "request": spec.request() })).await;
            assert_eq!(status, StatusCode::OK, "{}", body);
        }
        Set {
            primary,
            standby,
            urls: [primary_url, standby_url],
            workload_id: content.workload_id,
        }
    }

    /// `status` at `h` presenting `token`, as a tenant or a gateway asks it.
    async fn status(&self, h: &Harness, token: &ContinuationToken) -> (StatusCode, Value) {
        let spec = RequestSpec::about(h, "status", &self.workload_id).with_token(token);
        post(&h.app, "/status", json!({ "request": spec.request() })).await
    }

    /// `status`, presenting `token` as a Gateway Grant of a delegated moment
    /// — what a Workload Gateway holding a handover's grant asks with.
    async fn status_as_gateway(
        &self,
        h: &Harness,
        grant: &ContinuationToken,
        at: u64,
    ) -> (StatusCode, Value) {
        let content = json!({ "workload_id": self.workload_id, "gateway_expires_at": at });
        let spec = RequestSpec::op(h, "status", content).with_token(grant);
        post(&h.app, "/status", json!({ "request": spec.request() })).await
    }

    /// Rotate the PRIMARY at the real provider — a genuine `/rotate`, old
    /// token in, new token named as `next` — and write a lease file that
    /// matches what M7-2's `rotateLease` would leave behind had it reached
    /// only this member: `rotation.confirmed` names the primary,
    /// `root_secret` stays the OLD root because the standby still reads with
    /// it. Without the real rotate, the primary would still hold the old
    /// token and every assertion below would be proving nothing.
    async fn partly_rotate(&self) -> PathBuf {
        let old = root(ROOT_SECRET).continuation_for(&self.primary.provider);
        let next = root(NEW_ROOT_SECRET).continuation_for(&self.primary.provider);
        let spec = RequestSpec::op(
            &self.primary,
            "rotate",
            json!({ "workload_id": self.workload_id, "next": next }),
        )
        .with_token(&old);
        let (status, body) = post(
            &self.primary.app,
            "/rotate",
            json!({ "request": spec.request() }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the primary's real rotation: {}",
            body
        );

        let path = tempfile::tempdir().unwrap().keep().join("spawn.json");
        let lease = json!({
            "workload_id": self.workload_id,
            "root_secret": ROOT_SECRET,
            "standby_set": ["provider", "provider2"],
            "rotation": {
                "root_secret": NEW_ROOT_SECRET,
                "members": [self.primary.provider.to_hex(), self.standby.provider.to_hex()],
                "confirmed": [self.primary.provider.to_hex()],
            },
        });
        std::fs::write(&path, lease.to_string()).unwrap();
        path
    }
}

/// A distinct ILP address per provider, which the drivers below map to its URL.
fn address_of(h: &Harness) -> String {
    format!("g.test.{}", &h.provider.to_hex()[..12])
}

fn routes_of(set: &Set) -> Value {
    json!({
        address_of(&set.primary): set.urls[0],
        address_of(&set.standby): set.urls[1],
    })
}

/// The grant a handover's `standby_set` carries for `provider` (spec §12.1).
fn grant_at(handover: &Value, provider: &str) -> ContinuationToken {
    let hex = handover["standby_set"]
        .as_array()
        .and_then(|members| members.iter().find(|m| m["provider"] == json!(provider)))
        .and_then(|member| member["grant"].as_str())
        .unwrap_or_else(|| {
            panic!(
                "the handover carries no grant for {}: {}",
                provider, handover
            )
        });
    ContinuationToken::from_hex(hex).expect("a grant is 64 lowercase hex characters")
}

/// One run of `seal.mjs handover --lease <file> --dry-run`: the grant tool,
/// reading the lease file's `rotation` record instead of one flat root
/// secret (TOON_Network #80). `--dry-run` derives and prints the message —
/// nothing is paid for and no channel is opened — so this proves the
/// DERIVATION reads the file correctly; the assertions below then present
/// what it derived to the real providers to prove they accept it.
async fn handover_via_lease(
    lease_file: &Path,
    members: &[String],
    expires_at: u64,
) -> (Value, String) {
    let seal_mjs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/grant/seal.mjs");
    let mut args = vec![
        "handover".to_string(),
        "--lease".to_string(),
        lease_file.to_string_lossy().into_owned(),
        "--http-port".to_string(),
        "443".to_string(),
        "--expires-at".to_string(),
        expires_at.to_string(),
        "--gateway-route".to_string(),
        "g.toon.workload-gateway.handover".to_string(),
        "--gateway-seal-key".to_string(),
        SEAL_KEY.to_string(),
        "--dry-run".to_string(),
    ];
    for member in members {
        args.push("--standby".to_string());
        args.push(member.clone());
    }
    let output = tokio::process::Command::new("node")
        .arg(&seal_mjs)
        .args(&args)
        .output()
        .await
        .expect("run `node tools/grant/seal.mjs`: this suite drives the tenant's tool, so Node must be on PATH");
    assert!(
        output.status.success(),
        "the tool refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("the tool prints one JSON report on stdout");
    assert_eq!(report["dry_run"], json!(true));
    (
        report["handover"].clone(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// One run of a terminate for EVERY member of `set`, through the grant
/// tool's shared `currentRootFor` (`tools/grant/handover.mjs`;
/// TOON_Network #80) — the same seam `infra/sandbox/scripts/spawn.mjs
/// --terminate` reads a member's current token through. Each member is
/// asked directly over its real TCP port: the one seam a terminate crosses
/// is the Lease Request itself, not a sealed channel, exactly as
/// `spawn.mjs --terminate` sends one per member with no gateway involved.
async fn terminate_via_lease(set: &Set, lease: &Value) -> Vec<Value> {
    let handover_mjs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/grant/handover.mjs");
    let rotate_mjs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/grant/rotate.mjs");
    let members = json!([
        { "provider": set.primary.provider.to_hex(), "address": address_of(&set.primary) },
        { "provider": set.standby.provider.to_hex(), "address": address_of(&set.standby) },
    ]);
    let driver = format!(
        r#"
import {{ continuationFor, currentRootFor }} from {handover_module};
import {{ leaseRequest }} from {rotate_module};
const [leaseJson, membersJson, routesJson] = process.argv.slice(1);
const lease = JSON.parse(leaseJson);
const members = JSON.parse(membersJson);
const where = JSON.parse(routesJson);
const now = () => Math.floor(Date.now() / 1000);
const out = [];
for (const {{ provider, address }} of members) {{
  const root = currentRootFor(lease.root_secret, lease.rotation, provider);
  const continuation = continuationFor(root, provider);
  const request = leaseRequest({{ op: 'terminate', provider, continuation, content: {{ workload_id: lease.workload_id }}, now: now() }});
  const res = await fetch(`${{where[address]}}/terminate`, {{
    method: 'POST',
    headers: {{ 'content-type': 'application/json' }},
    body: JSON.stringify({{ request }}),
  }});
  out.push({{ provider, status: res.status, body: await res.json().catch(() => null) }});
}}
console.log(JSON.stringify(out));
"#,
        handover_module = json!(handover_mjs.to_string_lossy()),
        rotate_module = json!(rotate_mjs.to_string_lossy()),
    );
    let output = tokio::process::Command::new("node")
        .args(["--input-type=module", "-e", &driver])
        .arg(lease.to_string())
        .arg(members.to_string())
        .arg(routes_of(set).to_string())
        .output()
        .await
        .expect("run node: this suite drives the shared helper, so Node must be on PATH");
    assert!(
        output.status.success(),
        "the driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the driver prints one JSON array")
}

/// The first acceptance criterion: a handover sealed mid-rotation carries a
/// grant EACH member accepts — the confirmed primary's derived from the NEW
/// root, the unconfirmed standby's still from the OLD one.
#[tokio::test]
async fn a_handover_sealed_mid_rotation_carries_a_grant_each_member_accepts() {
    let set = Set::bought(0xb1).await;
    let lease_file = set.partly_rotate().await;
    let expires_at = now() + GRANT_TTL;
    let members = vec![set.primary.provider.to_hex(), set.standby.provider.to_hex()];

    let (handover, stderr) = handover_via_lease(&lease_file, &members, expires_at).await;
    assert_eq!(handover["workload_id"], json!(set.workload_id));

    // The tool warned of the unfinished rotation, and named no secret.
    assert!(
        stderr.contains("rotation is unfinished"),
        "the tool should warn of the unfinished rotation: {}",
        stderr
    );
    assert!(
        !stderr.contains(ROOT_SECRET),
        "the old root secret must never be printed"
    );
    assert!(
        !stderr.contains(NEW_ROOT_SECRET),
        "the new root secret must never be printed"
    );

    // The confirmed member's grant is the NEW root's, and it reads there.
    let primary_grant = grant_at(&handover, &set.primary.provider.to_hex());
    assert_eq!(
        primary_grant,
        root(NEW_ROOT_SECRET)
            .continuation_for(&set.primary.provider)
            .gateway_sub(expires_at),
        "the primary confirmed the rotation: its grant derives from the NEW root"
    );
    let (status, body) = set
        .status_as_gateway(&set.primary, &primary_grant, expires_at)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the primary admits the handover's grant: {}",
        body
    );

    // The member that has NOT confirmed still reads the OLD root's grant.
    let standby_grant = grant_at(&handover, &set.standby.provider.to_hex());
    assert_eq!(
        standby_grant,
        root(ROOT_SECRET)
            .continuation_for(&set.standby.provider)
            .gateway_sub(expires_at),
        "the standby has not confirmed: its grant still derives from the OLD root"
    );
    let (status, body) = set
        .status_as_gateway(&set.standby, &standby_grant, expires_at)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "before this fix the standby refused this grant bad_grant, because the tool derived it from the \
         primary's already-rotated root: {}",
        body
    );
}

/// The second acceptance criterion: a terminate, derived through the shared
/// `currentRootFor`, ends the lease at BOTH members of a partly rotated set.
#[tokio::test]
async fn a_terminate_ends_the_lease_at_both_members_of_a_partly_rotated_set() {
    let set = Set::bought(0xb2).await;
    let lease_file = set.partly_rotate().await;
    let lease: Value =
        serde_json::from_str(&std::fs::read_to_string(&lease_file).unwrap()).unwrap();

    let out = terminate_via_lease(&set, &lease).await;
    assert_eq!(out.len(), 2, "{:?}", out);
    for entry in &out {
        assert_eq!(entry["status"], json!(200), "terminate refused: {}", entry);
    }

    // Both ended: each member's OWN current token — the new one at the
    // confirmed primary, the old one at the standby that never rotated —
    // reads back `state.ended: "termination"`. A `not_tenant` here would mean
    // the terminate above presented the WRONG root for that member and ended
    // nothing there, even though it answered 200 at the other.
    let new_root_primary = root(NEW_ROOT_SECRET).continuation_for(&set.primary.provider);
    let (status, body) = set.status(&set.primary, &new_root_primary).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "termination" }), "{}", body);

    let old_root_standby = root(ROOT_SECRET).continuation_for(&set.standby.provider);
    let (status, body) = set.status(&set.standby, &old_root_standby).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "termination" }), "{}", body);
}

/// The fourth acceptance criterion, at the protocol level: a lease file with
/// no `rotation` record derives exactly what it always did — the one root
/// secret, for every member — and prints no warning.
#[tokio::test]
async fn a_lease_with_no_rotation_record_is_unchanged() {
    let set = Set::bought(0xb3).await;
    let path = tempfile::tempdir().unwrap().keep().join("spawn.json");
    std::fs::write(
        &path,
        json!({ "workload_id": set.workload_id, "root_secret": ROOT_SECRET }).to_string(),
    )
    .unwrap();
    let expires_at = now() + GRANT_TTL;
    let members = vec![set.primary.provider.to_hex(), set.standby.provider.to_hex()];

    let (handover, stderr) = handover_via_lease(&path, &members, expires_at).await;
    assert!(
        !stderr.contains("rotation is unfinished"),
        "no rotation, no warning: {}",
        stderr
    );

    for h in [&set.primary, &set.standby] {
        let grant = grant_at(&handover, &h.provider.to_hex());
        assert_eq!(
            grant,
            root(ROOT_SECRET)
                .continuation_for(&h.provider)
                .gateway_sub(expires_at),
            "every member still reads the one root secret"
        );
        let (status, body) = set.status_as_gateway(h, &grant, expires_at).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
    }
}
