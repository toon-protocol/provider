//! The tenant's rotate subcommand against this provider's real HTTP server
//! (`tools/grant/rotate.mjs`, `seal.mjs rotate`; spec §6.8; TOON_Network #75).
//!
//! `tests/rotate.rs` proves what the PROVIDER does with one rotate request.
//! This proves the tenant's half: that the tool, rotating a two-member Standby
//! Set, sends each member a request it accepts, leaves each holding the token
//! the tool's FRESH root secret derives for it, and keeps the lease file true
//! — both root secrets while a member has not confirmed, the new one alone
//! once every member has.
//!
//! Each provider is served on a real TCP port, and the tool's own
//! `rotateLease` is run in Node with an `ask` that POSTs to it. That is the
//! one seam `seal.mjs rotate` fills with a sealed packet instead; the packet
//! carries exactly this HTTP body to the provider app (spec §6.1.2), and the
//! sandbox carries it end to end (`make smoke-m7`). An `ask` can also lose an
//! answer, before or after the provider applied the request, which is the
//! case §6.8 has a tenant recover through `status`.
//!
//! Node is therefore required to run this file, as it is for
//! `tests/gateway_handover.rs`.

mod common;

use std::path::{Path, PathBuf};
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

/// The root secret the lease was spawned from: what the lease file holds
/// before the rotation. TEST-ONLY.
const ROOT_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// A member's pinned sealing key, which the tool checks and this `ask` never
/// uses. Synthetic: the secp256k1 generator point.
const SEAL_KEY: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

const SPAWN: &str = "/listings/warm/v1/spawn";
const STANDBY: &str = "/listings/warm/v1/standby";

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

/// A provider on the REAL clock, because the tool stamps its requests'
/// `expiration` from the wall clock — and served on a TCP port of its own.
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
/// `.spawn`, the standby on `.standby`, each with the token derived for it.
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

    fn members(&self) -> [&Harness; 2] {
        [&self.primary, &self.standby]
    }

    /// The `members` the tool is handed: each provider, the ILP address its
    /// routes hang off, and a sealing key.
    fn member_args(&self) -> Value {
        json!(self
            .members()
            .iter()
            .map(|h| json!({ "provider": h.provider.to_hex(), "address": address_of(h), "sealKey": SEAL_KEY }))
            .collect::<Vec<_>>())
    }

    /// Where each member's routes are really served: address → URL.
    fn routes(&self) -> Value {
        json!({
            address_of(&self.primary): self.urls[0],
            address_of(&self.standby): self.urls[1],
        })
    }

    /// A lease file as the sandbox's `spawn.mjs` writes one.
    fn lease_file(&self) -> PathBuf {
        let path = tempfile::tempdir().unwrap().keep().join("spawn.json");
        let lease = json!({
            "workload_id": self.workload_id,
            "root_secret": ROOT_SECRET,
            "standby_set": ["provider", "provider2"],
        });
        std::fs::write(&path, lease.to_string()).unwrap();
        path
    }

    /// `status` at `h` presenting `token`, as the tenant asks it.
    async fn status(&self, h: &Harness, token: &ContinuationToken) -> (StatusCode, Value) {
        let spec = RequestSpec::about(h, "status", &self.workload_id).with_token(token);
        post(&h.app, "/status", json!({ "request": spec.request() })).await
    }

    /// The same, presenting a Gateway Grant of `token` for a moment an hour out.
    async fn status_as_gateway(
        &self,
        h: &Harness,
        token: &ContinuationToken,
    ) -> (StatusCode, Value) {
        let at = h.clock.now() + 3600;
        let content = json!({ "workload_id": self.workload_id, "gateway_expires_at": at });
        let spec = RequestSpec::op(h, "status", content).with_token(&token.gateway_sub(at));
        post(&h.app, "/status", json!({ "request": spec.request() })).await
    }
}

/// A distinct ILP address per provider, which the `ask` maps to its URL.
fn address_of(h: &Harness) -> String {
    format!("g.test.{}", &h.provider.to_hex()[..12])
}

/// One run of the tool's `rotateLease`, in Node, over `ask`s that POST to the
/// providers' real ports. `lose` maps a route (`<address>.rotate`) to
/// `"before"` — the request never arrives — or `"after"` — the provider
/// applies it and the answer never comes back.
async fn rotate(set: &Set, lease_file: &Path, lose: Value) -> Value {
    let rotate_mjs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/grant/rotate.mjs");
    let driver = format!(
        r#"
import {{ rotateLease }} from {module};
const [leaseFile, members, routes, lose] = process.argv.slice(1);
const where = JSON.parse(routes);
const losing = JSON.parse(lose);
const ask = async (destination, body) => {{
  const cut = destination.lastIndexOf('.');
  const url = `${{where[destination.slice(0, cut)]}}/${{destination.slice(cut + 1)}}`;
  if (losing[destination] === 'before') return {{ lost: 'T00 the packet never arrived' }};
  const res = await fetch(url, {{ method: 'POST', headers: {{ 'content-type': 'application/json' }}, body: JSON.stringify(body) }});
  const answer = {{ status: res.status, body: await res.json().catch(() => null) }};
  return losing[destination] === 'after' ? {{ lost: 'T00 the answer never came back' }} : answer;
}};
console.log(JSON.stringify(await rotateLease({{ leaseFile, members: JSON.parse(members), ask }})));
"#,
        module = json!(rotate_mjs.to_string_lossy()),
    );
    let output = tokio::process::Command::new("node")
        .args(["--input-type=module", "-e", &driver])
        .arg(lease_file)
        .arg(set.member_args().to_string())
        .arg(set.routes().to_string())
        .arg(lose.to_string())
        .output()
        .await
        .expect("run node: this suite drives the tenant's tool, so Node must be on PATH");
    assert!(
        output.status.success(),
        "the tool failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the driver prints the tool's report")
}

fn read_lease(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn hex_of<'a>(lease: &'a Value, pointer: &str) -> &'a str {
    lease
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the lease file has no {}: {}", pointer, lease))
}

/// The acceptance criterion: every member rotated, the lease file updated.
#[tokio::test]
async fn the_tool_rotates_every_member_of_a_standby_set_and_records_the_new_root() {
    let set = Set::bought(0xa1).await;
    let lease_file = set.lease_file();

    let report = rotate(&set, &lease_file, json!({})).await;
    assert_eq!(report["rotated"], json!(true), "{}", report);
    assert_eq!(report["workload_id"], json!(set.workload_id));

    let lease = read_lease(&lease_file);
    let new_root = hex_of(&lease, "/root_secret");
    assert_ne!(new_root, ROOT_SECRET, "a FRESH root secret: {}", lease);
    assert!(
        lease.get("rotation").is_none(),
        "the old root is dropped once every member confirmed: {}",
        lease
    );
    assert_eq!(
        lease["standby_set"],
        json!(["provider", "provider2"]),
        "the file's own keys are kept"
    );

    for h in set.members() {
        let new = root(new_root).continuation_for(&h.provider);
        let old = root(ROOT_SECRET).continuation_for(&h.provider);

        let (status, body) = set.status(h, &new).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the new root's token reads the lease: {}",
            body
        );
        assert_eq!(body["workload_id"], json!(set.workload_id));

        let (status, body) = set.status(h, &old).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
        assert_eq!(
            error_of(&body),
            "not_tenant",
            "the old token is a stranger's now: {}",
            body
        );

        let (status, body) = set.status_as_gateway(h, &old).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
        assert_eq!(
            error_of(&body),
            "bad_grant",
            "every grant of the old token stopped reading: {}",
            body
        );
        let (status, body) = set.status_as_gateway(h, &new).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a grant of the new token reads it: {}",
            body
        );
    }
}

/// A member the tool could not reach: the set is partly rotated, and each
/// member still answers `status` with ITS current token — the new root's at
/// the one that rotated, the old root's at the one that did not. A second
/// run finishes it with the same new root.
#[tokio::test]
async fn a_partly_rotated_set_answers_each_member_with_its_own_current_token() {
    let set = Set::bought(0xa2).await;
    let lease_file = set.lease_file();
    let standby_rotate = format!("{}.rotate", address_of(&set.standby));

    let report = rotate(
        &set,
        &lease_file,
        json!({ standby_rotate.clone(): "before" }),
    )
    .await;
    assert_eq!(report["rotated"], json!(false), "{}", report);
    assert_eq!(report["members"][0]["rotated"], json!(true), "{}", report);
    assert_eq!(report["members"][1]["rotated"], json!(false), "{}", report);

    let lease = read_lease(&lease_file);
    assert_eq!(
        hex_of(&lease, "/root_secret"),
        ROOT_SECRET,
        "the old root stays: the standby is read with it"
    );
    let new_root = hex_of(&lease, "/rotation/root_secret").to_owned();
    assert_ne!(new_root, ROOT_SECRET);
    assert_eq!(
        lease["rotation"]["confirmed"],
        json!([set.primary.provider.to_hex()])
    );

    let current = [
        (&set.primary, &new_root[..], ROOT_SECRET),
        (&set.standby, ROOT_SECRET, &new_root[..]),
    ];
    for (h, holds, not) in current {
        let (status, body) = set
            .status(h, &root(holds).continuation_for(&h.provider))
            .await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        let (status, body) = set
            .status(h, &root(not).continuation_for(&h.provider))
            .await;
        assert_eq!(error_of(&body), "not_tenant", "{}: {}", status, body);
    }

    let report = rotate(&set, &lease_file, json!({})).await;
    assert_eq!(report["rotated"], json!(true), "{}", report);
    let lease = read_lease(&lease_file);
    assert_eq!(
        hex_of(&lease, "/root_secret"),
        new_root,
        "resumed with the same new root, not a third"
    );
    let (status, body) = set
        .status(
            &set.standby,
            &root(&new_root).continuation_for(&set.standby.provider),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

/// The answer to a rotate that took effect never came back. The tool does not
/// send it again — that would be `stale_request`, or `not_tenant` for a new
/// one — it asks `status` with the new token, and acceptance is the answer.
#[tokio::test]
async fn a_lost_answer_is_recovered_through_status_with_the_new_token() {
    let set = Set::bought(0xa3).await;
    let lease_file = set.lease_file();
    let primary_rotate = format!("{}.rotate", address_of(&set.primary));

    let report = rotate(&set, &lease_file, json!({ primary_rotate: "after" })).await;
    assert_eq!(report["rotated"], json!(true), "{}", report);
    assert_eq!(
        report["members"][0],
        json!({ "provider": set.primary.provider.to_hex(), "rotated": true, "recovered": true })
    );

    let new_root = hex_of(&read_lease(&lease_file), "/root_secret").to_owned();
    let (status, body) = set
        .status(
            &set.primary,
            &root(&new_root).continuation_for(&set.primary.provider),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}
