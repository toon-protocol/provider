//! `redeem`'s signatures against the REAL connector: the image
//! `deploy/docker-compose.yml` pins, run with a throwaway config whose
//! operator write allowlist holds one test key and which configures no
//! settlement backend, so no write can move anything.
//!
//! What proves the signing: a correctly signed write gets past the
//! connector's RFC 9421 check and fails on what comes AFTER it — `land`
//! on this node having no x402 settlement backend (503) — and the
//! connector's own `GET /audit-log` records it under the test keyid. Since
//! the pin is the x402-only connector (provider#66), `redeem-latest` itself
//! is gone and `redeem` meets a 404; the signing is proven on `land`.
//! A key it does not allowlist, a signature over another path, and a replay
//! each get its 401 and its reason.
//!
//! Needs docker and the image, so it is `#[ignore]`d:
//!
//! ```text
//! cargo test --locked --test redeem_connector_image -- --ignored
//! ```

use std::process::Command;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde_json::Value;
use toon_provider::redeem::sign::{keyid_hex, sign_write};
use toon_provider::redeem::{redeem_one, Outcome};

const BEARER: &str = "throwaway-bearer";
const EVM_CHANNEL: &str = "0xabababababababababababababababababababababababababababababababab";

fn pinned_image() -> String {
    let compose = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/docker-compose.yml"),
    )
    .unwrap();
    compose
        .lines()
        .find_map(|l| l.trim().strip_prefix("image: "))
        .filter(|i| i.starts_with("ghcr.io/toon-protocol/connector:"))
        .expect("the connector pin in deploy/docker-compose.yml")
        .to_string()
}

/// The container, removed when the test ends however it ends.
struct Connector {
    name: String,
    base: String,
    _dir: tempfile::TempDir,
}

impl Drop for Connector {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

async fn start(allowlisted: &SigningKey) -> Connector {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let state = dir.path().join("state");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    // The connector's own sealing key: any 32 bytes; this one seals nothing.
    std::fs::write(data.join("signer.key"), "11".repeat(32)).unwrap();
    std::fs::write(data.join("operator-bearer.token"), BEARER).unwrap();
    std::fs::write(
        data.join("operator-write.keys"),
        format!("# the test key\n{}\n", keyid_hex(allowlisted)),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("connector.toml"),
        r#"client_edge_addr = "0.0.0.0:4000"
state_dir = "/app/state"

[signer]
key_file = "/app/data/signer.key"

[operator]
bearer_token_file = "/app/data/operator-bearer.token"
write_keys_file   = "/app/data/operator-write.keys"

[node]
addresses     = ["g.test.redeem"]
http_endpoint = "http://127.0.0.1:4000"
"#,
    )
    .unwrap();
    // The image runs as uid 10001.
    for path in [dir.path(), &data, &state] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    for file in ["signer.key", "operator-bearer.token", "operator-write.keys"] {
        std::fs::set_permissions(data.join(file), std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let name = format!("toon-redeem-test-{}", std::process::id());
    let run = Command::new("docker")
        .args(["run", "-d", "--name", &name, "-p", "127.0.0.1::4000"])
        .arg("-v")
        .arg(format!(
            "{}:/app/config/connector.toml:ro",
            dir.path().join("connector.toml").display()
        ))
        .arg("-v")
        .arg(format!("{}:/app/data:ro", data.display()))
        .arg("-v")
        .arg(format!("{}:/app/state", state.display()))
        .arg(pinned_image())
        .arg("/app/config/connector.toml")
        .output()
        .expect("docker is installed");
    assert!(
        run.status.success(),
        "docker run: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let port = Command::new("docker")
        .args(["port", &name, "4000/tcp"])
        .output()
        .unwrap();
    let port = String::from_utf8_lossy(&port.stdout);
    let port = port
        .lines()
        .next()
        .and_then(|l| l.rsplit(':').next())
        .expect("a published port")
        .trim()
        .to_string();
    let connector = Connector {
        name,
        base: format!("http://127.0.0.1:{port}"),
        _dir: dir,
    };

    let client = reqwest::Client::new();
    for _ in 0..50 {
        let ready = client
            .get(format!("{}/channels", connector.base))
            .bearer_auth(BEARER)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        if ready {
            return connector;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let logs = Command::new("docker")
        .args(["logs", &connector.name])
        .output()
        .unwrap();
    panic!(
        "the connector did not come up:\n{}",
        String::from_utf8_lossy(&logs.stderr)
    );
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn post_signed(
    client: &reqwest::Client,
    base: &str,
    key: &SigningKey,
    signed_path: &str,
    sent_path: &str,
) -> (u16, String, [String; 3]) {
    let t = now();
    let signed = sign_write(key, "POST", signed_path, b"", t, t + 60);
    let headers = [
        signed.content_digest,
        signed.signature_input,
        signed.signature,
    ];
    let (status, body) = send(client, base, sent_path, &headers).await;
    (status, body, headers)
}

async fn send(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    headers: &[String; 3],
) -> (u16, String) {
    let response = client
        .post(format!("{base}{path}"))
        .header("content-digest", &headers[0])
        .header("signature-input", &headers[1])
        .header("signature", &headers[2])
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    (
        response.status().as_u16(),
        response.text().await.unwrap_or_default(),
    )
}

#[tokio::test]
#[ignore = "needs docker and the pinned connector image"]
async fn the_real_connector_accepts_redeems_signature_and_refuses_the_rest() {
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let stranger = SigningKey::from_bytes(&[0x07; 32]);
    let connector = start(&key).await;
    let client = reqwest::Client::new();
    let base = connector.base.as_str();

    // 1. The pin is the x402-only connector (provider#66): `redeem-latest`
    //    is deleted, so `redeem` as it stands meets a 404 there, before any
    //    signature is looked at. What `redeem` becomes is still open.
    let outcome = redeem_one(&client, base, &key, EVM_CHANNEL, now()).await;
    assert_eq!(
        outcome,
        Outcome::Refused {
            status: 404,
            body: String::new()
        },
        "the x402-only connector has no redeem-latest"
    );

    // 2. The signing itself still holds: `land`, its replacement, signed
    //    exactly as `redeem` signs, gets past write auth and fails only on
    //    what comes after it — this connector configures no settlement.
    let land = format!("/channels/{EVM_CHANNEL}/land");
    let (status, body, headers) = post_signed(&client, base, &key, &land, &land).await;
    assert_eq!(status, 503, "{body}");

    // 3. The connector recorded it as an authenticated write by this keyid.
    let audit: Vec<Value> = client
        .get(format!("{base}/audit-log"))
        .bearer_auth(BEARER)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        audit
            .iter()
            .any(|r| r["keyid"] == keyid_hex(&key) && r["path"] == land),
        "{audit:?}"
    );

    // 4. Replaying that exact signature: refused.
    assert_eq!(
        send(&client, base, &land, &headers).await,
        (401, "signature has already been used".into())
    );

    // 5. A key the connector does not allowlist: refused, with its reason.
    let (status, body, _) = post_signed(&client, base, &stranger, &land, &land).await;
    assert_eq!(
        (status, body.as_str()),
        (401, "keyid is not on the operator write allowlist")
    );

    // 6. The right key, over a different path than the one sent: refused.
    let other = format!("/channels/{EVM_CHANNEL}/withdraw");
    let (status, body, _) = post_signed(&client, base, &key, &other, &land).await;
    assert_eq!((status, body.as_str()), (401, "signature does not verify"));

    // 7. No signature at all.
    let response = client.post(format!("{base}{land}")).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 401);
}
