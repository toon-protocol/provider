//! `toon-provider redeem` (TOON_Network#173, ADR 0029) end to end, against
//! a stubbed connector: the same bearer-gated reads `status` makes, and a
//! `POST /channels/:id/redeem-latest` that answers only a request whose RFC
//! 9421 signature verifies — checked here by a verifier written from the
//! connector's `rfc9421.rs`, independently of the signer under test. The
//! signer is also pinned byte for byte to the connector's own in
//! `src/redeem/sign.rs`, and against the real connector image in
//! `tests/redeem_connector_image.rs`.

use std::io::Write;
use std::process::{Command, Stdio};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const TOKEN: &str = "fixture-bearer-token";
/// The operator key: seed 32 × 0x42. Its keyid is [`KEYID`].
const KEY: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const KEYID: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
/// A key the connector does not allowlist.
const OTHER_KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";

const EVM_BIG: &str = "0xabababababababababababababababababababababababababababababababab";
const EVM_SMALL: &str = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const SOLANA: &str = "2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip";

/// Accepts a request only if it carries a valid, unexpired signature over
/// exactly `@method`, `@path` and a `Content-Digest` that matches the body,
/// from `key` — the checks `verify_write_signature` makes, in its order.
struct SignedBy(VerifyingKey);

impl Match for SignedBy {
    fn matches(&self, request: &Request) -> bool {
        verify(&self.0, request).is_ok()
    }
}

fn verify(key: &VerifyingKey, request: &Request) -> Result<(), String> {
    let get = |name: &str| {
        request
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or(format!("no {name}"))
    };
    let input = get("signature-input")?;
    let signature = get("signature")?;
    let digest = get("content-digest")?;

    let expected_digest = format!("sha-256=:{}:", BASE64.encode(Sha256::digest(&request.body)));
    if digest != expected_digest {
        return Err("digest mismatch".into());
    }
    let params = input.strip_prefix("sig1=").ok_or("label")?;
    if !params.starts_with("(\"@method\" \"@path\" \"content-digest\");") {
        return Err(format!("components: {params}"));
    }
    let field = |name: &str| {
        params
            .split(';')
            .find_map(|p| p.strip_prefix(&format!("{name}=")))
            .map(|v| v.trim_matches('"').to_string())
            .ok_or(format!("no {name}"))
    };
    let expires: u64 = field("expires")?.parse().map_err(|_| "expires")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now > expires {
        return Err("expired".into());
    }
    if field("alg")? != "ed25519" {
        return Err("alg".into());
    }
    let keyid: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    if field("keyid")? != keyid {
        return Err("keyid not allowlisted".into());
    }
    let base = format!(
        "\"@method\": {}\n\"@path\": {}\n\"content-digest\": {digest}\n\"@signature-params\": {params}",
        request.method.as_str().to_uppercase(),
        request.url.path(),
    );
    let bytes = BASE64
        .decode(
            signature
                .strip_prefix("sig1=:")
                .and_then(|s| s.strip_suffix(':'))
                .ok_or("signature shape")?,
        )
        .map_err(|_| "signature base64")?;
    let signature = Signature::from_slice(&bytes).map_err(|_| "signature length")?;
    key.verify(base.as_bytes(), &signature)
        .map_err(|_| "signature does not verify".to_string())
}

fn allowlisted() -> VerifyingKey {
    SigningKey::from_bytes(&[0x42; 32]).verifying_key()
}

/// A connector holding three inbound channels: 2,400 unredeemed on an EVM
/// one, 600 on another, and 1,200 on a Solana one it did not list.
async fn connector() -> MockServer {
    let server = MockServer::start().await;
    let auth = format!("Bearer {TOKEN}");
    Mock::given(method("GET"))
        .and(path("/channels"))
        .and(header("authorization", auth.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": EVM_BIG, "counterparty": "0x11", "status": "open",
              "deposited": 5_000_000u64, "own_deposited": 0, "redeemed": 1_000 },
            { "id": EVM_SMALL, "counterparty": "0x22", "status": "open",
              "deposited": 5_000_000u64, "own_deposited": 0, "redeemed": 0 },
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/claims"))
        .and(header("authorization", auth.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "peer_id": null, "channel_id": format!("evm:{EVM_BIG}"), "direction": "inbound",
              "nonce": 7, "cumulative_amount": 3_400, "pending": false },
            { "peer_id": null, "channel_id": format!("evm:{EVM_SMALL}"), "direction": "inbound",
              "nonce": 2, "cumulative_amount": 600, "pending": false },
            { "peer_id": null, "channel_id": format!("solana:{SOLANA}"), "direction": "inbound",
              "nonce": 3, "cumulative_amount": 1_200, "pending": false },
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/audit-log"))
        .and(header("authorization", auth.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    // A signed redeem: the channel as it now stands.
    Mock::given(method("POST"))
        .and(path(format!("/channels/{EVM_BIG}/redeem-latest")))
        .and(SignedBy(allowlisted()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": EVM_BIG, "counterparty": "0x11", "status": "open",
            "deposited": 5_000_000u64, "own_deposited": 0, "redeemed": 3_400,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/channels/{SOLANA}/redeem-latest")))
        .and(SignedBy(allowlisted()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": SOLANA, "counterparty": "0x33", "status": "open",
            "deposited": 5_000_000u64, "own_deposited": 0, "redeemed": 1_200,
        })))
        .mount(&server)
        .await;
    // Anything else signed wrongly: the connector's 401 and its reason.
    Mock::given(method("POST"))
        .and(path_regex("^/channels/.*/redeem-latest$"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("keyid is not on the operator write allowlist"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    server
}

async fn evm_rpc() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 1, "result": "0x1c9c380", // 30,000,000 wei = 0.03 gwei
        })))
        .mount(&server)
        .await;
    server
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run the binary from "a laptop": no provider config, the connector and
/// the bearer token named by flag, `stdin` piped in.
fn redeem(connector: &MockServer, rpc: &MockServer, args: &[&str], stdin: &str) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("operator-bearer.token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_toon-provider"))
        .env_clear()
        .env(
            "TOON_PROVIDER_CONFIG",
            dir.path().join("no-such-provider.toml"),
        )
        .arg("redeem")
        .args(["--connector", &connector.uri()])
        .arg("--bearer-file")
        .arg(&token)
        .args(["--evm-rpc-url", &rpc.uri()])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run toon-provider redeem");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn redeems_asked(connector: &MockServer) -> Vec<String> {
    connector
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .map(|r| r.url.path().to_string())
        .collect()
}

fn assert_key_never_printed(run: &Run) {
    for secret in [KEY, OTHER_KEY] {
        assert!(
            !run.stdout.contains(&secret[..16]) && !run.stderr.contains(&secret[..16]),
            "the key was printed:\n{}\n{}",
            run.stdout,
            run.stderr
        );
    }
}

#[tokio::test]
async fn all_above_redeems_only_the_channels_over_the_floor_with_the_key_from_stdin() {
    let (connector, rpc) = (connector().await, evm_rpc().await);
    let run = redeem(
        &connector,
        &rpc,
        &["--all-above", "1000", "--yes"],
        &format!("{KEY}\n"),
    );
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    assert_key_never_printed(&run);

    // The listing: every channel, each chain's estimate.
    assert!(
        run.stdout.contains("total 4200 across 3 channels"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("~0.0000048 ETH"), "{}", run.stdout);
    assert!(run.stdout.contains("~0.00001 SOL"), "{}", run.stdout);

    // Only the two over 1000, each signed and answered.
    let mut asked = redeems_asked(&connector).await;
    asked.sort();
    assert_eq!(
        asked,
        [
            format!("/channels/{EVM_BIG}/redeem-latest"),
            format!("/channels/{SOLANA}/redeem-latest"),
        ]
    );
    assert!(
        run.stdout.contains(&format!("Signing as keyid {KEYID}")),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains(&format!("redeemed  {EVM_BIG}: 2400 collected")),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("2 of 2 redeemed."), "{}", run.stdout);
}

#[tokio::test]
async fn a_named_channel_is_the_only_one_redeemed() {
    let (connector, rpc) = (connector().await, evm_rpc().await);
    let run = redeem(
        &connector,
        &rpc,
        &["--channel", &format!("solana:{SOLANA}"), "--yes"],
        KEY,
    );
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    assert_eq!(
        redeems_asked(&connector).await,
        [format!("/channels/{SOLANA}/redeem-latest")]
    );
}

#[tokio::test]
async fn a_key_the_connector_does_not_allowlist_is_refused_and_named_by_keyid() {
    let (connector, rpc) = (connector().await, evm_rpc().await);
    let run = redeem(
        &connector,
        &rpc,
        &["--channel", EVM_BIG, "--yes"],
        OTHER_KEY,
    );
    assert_eq!(run.code, Some(1), "{}\n{}", run.stdout, run.stderr);
    assert_key_never_printed(&run);
    assert!(run.stdout.contains("REFUSED"), "{}", run.stdout);
    assert!(
        run.stdout
            .contains("keyid is not on the operator write allowlist"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("0 of 1 redeemed."), "{}", run.stdout);
}

#[tokio::test]
async fn list_asks_for_no_key_and_redeems_nothing() {
    let (connector, rpc) = (connector().await, evm_rpc().await);
    let run = redeem(&connector, &rpc, &["--list"], "");
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    assert!(run.stdout.contains(EVM_SMALL), "{}", run.stdout);
    assert!(redeems_asked(&connector).await.is_empty());
}

#[tokio::test]
async fn a_key_on_the_command_line_is_refused_before_anything_is_asked() {
    let (connector, rpc) = (connector().await, evm_rpc().await);
    for argv in [
        vec!["--operator-key", KEY, "--all-above", "0", "--yes"],
        vec![KEY, "--all-above", "0", "--yes"],
    ] {
        let run = redeem(&connector, &rpc, &argv, "");
        assert_ne!(run.code, Some(0), "{argv:?}");
        assert!(run.stderr.contains("refusing"), "{}", run.stderr);
        assert_key_never_printed(&run);
    }
    assert!(
        connector
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "nothing is dialled once a key is on the command line"
    );
}

#[tokio::test]
async fn a_malformed_key_redeems_nothing_and_is_not_repeated() {
    let (connector, rpc) = (connector().await, evm_rpc().await);
    let run = redeem(&connector, &rpc, &["--all-above", "0", "--yes"], &KEY[..63]);
    assert_ne!(run.code, Some(0));
    assert!(run.stderr.contains("64 hex characters"), "{}", run.stderr);
    assert_key_never_printed(&run);
    assert!(redeems_asked(&connector).await.is_empty());
}

/// Without `--yes`, a redeem needs a typed `yes`, and with the key on stdin
/// and no controlling terminal (`setsid`) there is nowhere to type it: the
/// command refuses rather than redeem unconfirmed.
#[tokio::test]
async fn without_yes_and_without_a_terminal_nothing_is_redeemed() {
    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("skipping: no setsid on this machine");
        return;
    }
    let (connector, rpc) = (connector().await, evm_rpc().await);
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("operator-bearer.token");
    std::fs::write(&token, TOKEN).unwrap();
    let mut child = Command::new("setsid")
        .arg("--wait")
        .arg(env!("CARGO_BIN_EXE_toon-provider"))
        .env_clear()
        .env("TOON_PROVIDER_CONFIG", dir.path().join("none.toml"))
        .args([
            "redeem",
            "--all-above",
            "1000",
            "--connector",
            &connector.uri(),
        ])
        .arg("--bearer-file")
        .arg(&token)
        .args(["--evm-rpc-url", &rpc.uri()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(KEY.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("no terminal to ask on"), "{stderr}");
    assert!(redeems_asked(&connector).await.is_empty());
}
