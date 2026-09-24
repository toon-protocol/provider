//! The guard on `deploy/keys.sh` (TOON_Network#162): every address it tells an
//! operator to fund is the address the component itself derives.
//!
//! An operator funds exactly what `keys.sh addresses` prints, before anything
//! has booted to disagree with it. So a derivation that is wrong by one byte
//! is money sent to a key nobody holds, and the connector restart-loops on an
//! empty wallet anyway. Each expected value below was therefore produced by
//! the COMPONENT, never by keys.py, on fixed test keys that hold nothing:
//!
//!   * ed25519 keyids: `docker run --rm -v "$PWD:/d:ro"
//!     ghcr.io/toon-protocol/connector:rust-2026.09.11.1 send --operator-key
//!     /d/<file> --print-keyid`, the deploy bundle's own connector pin.
//!     settlement-solana.key goes through the same ed25519-dalek expansion
//!     (connector `read_settlement_key_bytes` -> solana-sdk
//!     `keypair_from_seed`), and its base58 was checked with `solana-keygen
//!     pubkey`.
//!   * EVM addresses: the connector's `connector_signer::derive_evm_address`
//!     over `LocalSigner::from_secret_bytes` (lowercase, as `GET /ilp` prints
//!     it), and viem's `privateKeyToAccount` for the EIP-55 casing.
//!   * Publisher addresses: `deriveFullIdentity(mnemonic.trim(),
//!     {accountIndex: 0}).solana.publicKey`, run inside the published
//!     directory-publisher image (`provider-publisher:sha-dce2bd2`,
//!     @toon-protocol/client 3.1.0) -- the call `ToonClient.create` makes on
//!     `TOON_MNEMONIC` and `TOON_ACCOUNT_INDEX: '0'`.
//!   * npubs: derived live, here, by nostr-sdk -- the library the provider
//!     signs its Profile with.
//!
//! Beyond the derivations it holds still what an operator relies on: `init`
//! never replaces a key, stores no operator private key, and leaves a `.env`
//! the shell and compose both read; and `check-funded` refuses an unfunded
//! box with the list, warns on a box that has booted, and on a hidden box asks
//! only the box's own Solana node.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use nostr_sdk::{Keys, ToBech32};
use sha2::{Digest, Sha256};

fn deploy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy")
}

/// (key file contents, `--print-keyid`, base58 of it)
const ED25519: [(&[u8], &str, &str); 4] = [
    // RFC 8032 §7.1 TEST 1, as `openssl rand -hex 32 >` writes a key: a newline.
    (
        b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\n",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z",
    ),
    // RFC 8032 §7.1 TEST 2.
    (
        b"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb\n",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5",
    ),
    // sha256("toon keys.sh pin"), with no trailing newline.
    (
        b"99fc2e314584c8249d9a5d40de9eba25fa49a644f90852aeb4bb343f60e9cc5f",
        "7862bef3863de3311d7ec63b54dd7f9b32100a2623b02363332dfd12be1f10a8",
        "96wFoBogqaCH9YgzTpvK6nySj5XsUsU2HbncEBHDnwZ9",
    ),
    // The other format the connector reads: exactly 32 raw bytes.
    (
        &[7u8; 32],
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
        "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB",
    ),
];

/// (settlement.key contents, the address the connector derives, EIP-55).
const EVM: [(&str, &str); 3] = [
    // Anvil's first dev account: the vector every EVM tool agrees on.
    (
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n",
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    ),
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\n",
        "0x09231da7b19A016f9e576d23B16277062F4d46A8",
    ),
    (
        "99fc2e314584c8249d9a5d40de9eba25fa49a644f90852aeb4bb343f60e9cc5f",
        "0xf6888FB9CDfa10859FfCC366aD7AF9dF8208A096",
    ),
];

/// (PUBLISHER_MNEMONIC, the Solana address the publisher pays from).
const PUBLISHER: [(&str, &str); 4] = [
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
    ),
    (
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "BLeUXTx9thHGT7VJUtF9vHEmfMDgW1nnKZ9UVer2CoLX",
    ),
    // The client trims the phrase before deriving; so must keys.py.
    (
        "  legal winner thank year wave sausage worth useful legal winner thank yellow\n",
        "BLeUXTx9thHGT7VJUtF9vHEmfMDgW1nnKZ9UVer2CoLX",
    ),
    (
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "E48cosDiQZK1iDSsyUzhvW4WxJeoKuDk5qgcdkmANV4N",
    ),
];

/// `python3 keys.py provider derive` in `dir`, with `env` as the sourced .env.
fn derive(dir: &Path, env: &[(&str, &str)]) -> serde_json::Value {
    let mut command = Command::new("python3");
    command
        .arg(deploy_dir().join("keys.py"))
        .args(["provider", "derive"])
        .current_dir(dir)
        .env_remove("PUBLISHER_MNEMONIC")
        .env_remove("NOSTR_PRIVATE_KEY");
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().expect("run python3 keys.py");
    assert!(
        output.status.success(),
        "keys.py derive failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("keys.py derive prints JSON")
}

fn with_keys(solana: &[u8], evm: &str, operator: Option<&[u8]>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("settlement-solana.key"), solana).unwrap();
    fs::write(dir.path().join("settlement.key"), evm).unwrap();
    if let Some(operator) = operator {
        fs::write(dir.path().join("operator-write.key"), operator).unwrap();
    }
    dir
}

#[test]
fn the_connector_solana_address_is_its_print_keyid_in_base58() {
    for (key, keyid, address) in ED25519 {
        let dir = with_keys(key, EVM[0].0, None);
        let derived = derive(dir.path(), &[]);
        assert_eq!(derived["connector_solana_hex"], keyid, "keyid of {key:?}");
        assert_eq!(derived["connector_solana"], address, "address of {key:?}");
    }
}

#[test]
fn the_operator_write_key_is_what_print_keyid_prints() {
    for (key, keyid, _) in ED25519 {
        let dir = with_keys(ED25519[0].0, EVM[0].0, Some(key));
        assert_eq!(derive(dir.path(), &[])["operator_keyid"], keyid);
    }
}

#[test]
fn the_connector_evm_address_is_the_one_it_settles_from() {
    for (key, address) in EVM {
        let dir = with_keys(ED25519[0].0, key, None);
        let derived = derive(dir.path(), &[]);
        assert_eq!(derived["connector_evm"], address, "address of {key:?}");
    }
}

#[test]
fn the_publisher_address_is_the_one_it_pays_from() {
    for (mnemonic, address) in PUBLISHER {
        let dir = with_keys(ED25519[0].0, EVM[0].0, None);
        let derived = derive(dir.path(), &[("PUBLISHER_MNEMONIC", mnemonic)]);
        assert_eq!(
            derived["publisher_solana"], address,
            "address of {mnemonic:?}"
        );
    }
}

#[test]
fn the_npub_is_the_one_the_provider_signs_as() {
    // NIP-19's own example pair, and three plain hex keys; every expected
    // npub is nostr-sdk's.
    for secret in [
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
        "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    ] {
        let expected = Keys::parse(secret)
            .unwrap()
            .public_key()
            .to_bech32()
            .unwrap();
        let dir = with_keys(ED25519[0].0, EVM[0].0, None);
        assert_eq!(
            derive(dir.path(), &[("NOSTR_PRIVATE_KEY", secret)])["npub"],
            expected
        );
    }
    assert_eq!(
        Keys::parse("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5")
            .unwrap()
            .public_key()
            .to_bech32()
            .unwrap(),
        "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
    );
}

// ── keys.sh, run for real on a copy of the bundle ───────────────────────────

/// A scratch copy of what `keys.sh` reads: itself, keys.py, the word list
/// and `.env.example`. Nothing of an operator's own `deploy/` is read.
fn bundle() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["keys.sh", "keys.py", "bip39-english.txt", ".env.example"] {
        fs::copy(deploy_dir().join(name), dir.path().join(name)).unwrap();
    }
    dir
}

fn keys_sh(dir: &Path, args: &[&str]) -> Output {
    Command::new("bash")
        .arg(dir.join("keys.sh"))
        .args(args)
        .current_dir(dir)
        .env_remove("PUBLISHER_MNEMONIC")
        .env_remove("NOSTR_PRIVATE_KEY")
        .output()
        .expect("run keys.sh")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// .env as the shell reads it — the way bootstrap.sh and render.sh do.
fn sourced_env(dir: &Path) -> BTreeMap<String, String> {
    let names = [
        "NOSTR_PRIVATE_KEY",
        "OPERATOR_BEARER_TOKEN",
        "OPERATOR_WRITE_KEY",
        "PUBLISHER_MNEMONIC",
        "RELAY_WRITE_ROUTES",
    ];
    let script = names
        .iter()
        .map(|n| format!("printf '%s\\0' \"${n}\""))
        .collect::<Vec<_>>()
        .join("; ");
    let output = Command::new("bash")
        .arg("-c")
        .arg(format!("set -a; . ./.env; set +a; {script}"))
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "the shell cannot source .env");
    let values = String::from_utf8(output.stdout).unwrap();
    names
        .iter()
        .map(|n| n.to_string())
        .zip(values.split('\0').map(str::to_string))
        .collect()
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// BIP-39's own checksum, computed here rather than by keys.py.
fn bip39_checksum_ok(phrase: &str) -> bool {
    let list = fs::read_to_string(deploy_dir().join("bip39-english.txt")).unwrap();
    let words: Vec<&str> = list.split_whitespace().collect();
    let indices: Vec<u32> = phrase
        .split(' ')
        .map(|w| words.iter().position(|x| *x == w).expect("a BIP-39 word") as u32)
        .collect();
    assert_eq!(indices.len(), 12);
    let mut bits: u128 = 0;
    let mut check: u8 = 0;
    for (i, index) in indices.iter().enumerate() {
        for bit in (0..11).rev() {
            let b = (index >> bit) & 1;
            let position = i * 11 + (10 - bit as usize);
            if position < 128 {
                bits = (bits << 1) | u128::from(b);
            } else {
                check = (check << 1) | b as u8;
            }
        }
    }
    Sha256::digest(bits.to_be_bytes())[0] >> 4 == check
}

#[test]
fn the_word_list_is_bip39_english() {
    let digest = Sha256::digest(fs::read(deploy_dir().join("bip39-english.txt")).unwrap());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    // The sha256 of bitcoin/bips bip-0039/english.txt.
    assert_eq!(
        hex,
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
}

#[test]
fn init_generates_everything_missing_and_prints_the_operator_key_once() {
    let dir = bundle();
    let output = keys_sh(dir.path(), &["init"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = stdout(&output);

    for key in ["signer.key", "settlement.key", "settlement-solana.key"] {
        let path = dir.path().join(key);
        let text = fs::read_to_string(&path).unwrap();
        assert!(is_hex64(text.trim_end()), "{key} is 64 hex characters");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "{key} is 0600"
        );
    }
    let env = sourced_env(dir.path());
    assert!(is_hex64(&env["NOSTR_PRIVATE_KEY"]));
    assert!(Keys::parse(&env["NOSTR_PRIVATE_KEY"]).is_ok());
    assert!(is_hex64(&env["OPERATOR_BEARER_TOKEN"]));
    assert!(is_hex64(&env["OPERATOR_WRITE_KEY"]));
    assert!(bip39_checksum_ok(&env["PUBLISHER_MNEMONIC"]));
    // The preset is untouched: a JSON value with braces still reads whole.
    assert_eq!(
        env["RELAY_WRITE_ROUTES"],
        r#"{"wss://relay-ws.devnet.toonprotocol.dev":"g.toon.relay"}"#
    );

    // The private half is printed, is the key OPERATOR_WRITE_KEY is the
    // public half of, and is stored nowhere in the bundle.
    let private = printed
        .lines()
        .map(str::trim)
        .find(|l| is_hex64(l))
        .expect("the operator write key's private half is printed");
    fs::write(dir.path().join("operator-write.key"), private).unwrap();
    assert_eq!(
        derive(dir.path(), &[])["operator_keyid"],
        env["OPERATOR_WRITE_KEY"].as_str()
    );
    fs::remove_file(dir.path().join("operator-write.key")).unwrap();
    for entry in fs::read_dir(dir.path()).unwrap().flatten() {
        let text = fs::read(entry.path()).unwrap();
        assert!(
            !String::from_utf8_lossy(&text).contains(private),
            "{} holds the operator's private key",
            entry.path().display()
        );
    }
}

#[test]
fn init_never_replaces_what_exists() {
    let dir = bundle();
    let mine = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb\n";
    fs::write(dir.path().join("settlement-solana.key"), mine).unwrap();
    let example = fs::read_to_string(dir.path().join(".env.example")).unwrap();
    fs::write(
        dir.path().join(".env"),
        example.replace(
            "OPERATOR_BEARER_TOKEN=\n",
            "OPERATOR_BEARER_TOKEN=my-own-token\n",
        ),
    )
    .unwrap();

    assert!(keys_sh(dir.path(), &["init"]).status.success());
    assert_eq!(
        fs::read_to_string(dir.path().join("settlement-solana.key")).unwrap(),
        mine
    );
    assert_eq!(
        sourced_env(dir.path())["OPERATOR_BEARER_TOKEN"],
        "my-own-token"
    );

    // A second run changes nothing at all, and prints no private key.
    let snapshot = |dir: &Path| -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    fs::read(e.path()).unwrap(),
                )
            })
            .collect()
    };
    let before = snapshot(dir.path());
    let again = keys_sh(dir.path(), &["init"]);
    assert!(again.status.success());
    assert_eq!(snapshot(dir.path()), before);
    assert!(!stdout(&again).lines().any(|l| is_hex64(l.trim())));
}

#[test]
fn addresses_prints_every_address_to_fund_and_how() {
    let dir = bundle();
    assert!(keys_sh(dir.path(), &["init"]).status.success());
    fs::write(dir.path().join("settlement-solana.key"), ED25519[0].0).unwrap();
    fs::write(dir.path().join("settlement.key"), EVM[0].0).unwrap();
    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    let env: String = env
        .lines()
        .map(|l| {
            if l.starts_with("PUBLISHER_MNEMONIC=") {
                format!("PUBLISHER_MNEMONIC='{}'", PUBLISHER[1].0)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(dir.path().join(".env"), env + "\n").unwrap();

    let output = keys_sh(dir.path(), &["addresses"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = stdout(&output);
    for expected in [
        ED25519[0].2,
        PUBLISHER[1].1,
        EVM[0].1,
        "https://faucet.solana.com",
        "https://faucet.devnet.toonprotocol.dev/api/solana/usdc-request",
        "npub1",
    ] {
        assert!(
            printed.contains(expected),
            "addresses prints {expected}:\n{printed}"
        );
    }
    // The mock-USDC request names the publisher, not the connector.
    assert!(printed.contains(&format!(r#"{{"address":"{}"}}"#, PUBLISHER[1].1)));
    // Nothing is left for the operator to convert.
    assert!(
        !printed.contains(ED25519[0].1),
        "no hex keyid is offered as an address"
    );
}

#[test]
fn addresses_says_what_is_missing() {
    let dir = bundle();
    fs::copy(dir.path().join(".env.example"), dir.path().join(".env")).unwrap();
    let output = keys_sh(dir.path(), &["addresses"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("./keys.sh init"));
}

// ── check-funded, against a stub Solana RPC ─────────────────────────────────

/// A JSON-RPC server answering getBalance and getTokenAccountsByOwner from
/// `balances` (address -> (lamports, token base units)), recording every
/// address it was asked about.
fn stub_rpc(balances: BTreeMap<String, (u64, u64)>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let address = request["params"][0].as_str().unwrap().to_string();
            seen.lock().unwrap().push(address.clone());
            let (lamports, units) = balances.get(&address).copied().unwrap_or((0, 0));
            let result = match request["method"].as_str().unwrap() {
                "getBalance" => serde_json::json!({"context": {"slot": 1}, "value": lamports}),
                _ => serde_json::json!({"context": {"slot": 1}, "value": [{"account": {"data": {
                    "parsed": {"info": {"tokenAmount": {"amount": units.to_string()}}}}}}]}),
            };
            let answer =
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
            let mut stream = stream;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                answer.len()
            );
        }
    });
    (url, asked)
}

/// A bundle with fixed keys and `.env` lines appended.
fn funded_bundle(extra_env: &str) -> tempfile::TempDir {
    let dir = bundle();
    assert!(keys_sh(dir.path(), &["init"]).status.success());
    fs::write(dir.path().join("settlement-solana.key"), ED25519[0].0).unwrap();
    let mut env = fs::read_to_string(dir.path().join(".env"))
        .unwrap()
        .lines()
        .map(|l| {
            if l.starts_with("PUBLISHER_MNEMONIC=") {
                format!("PUBLISHER_MNEMONIC='{}'", PUBLISHER[1].0)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    env.push('\n');
    env.push_str(extra_env);
    fs::write(dir.path().join(".env"), env).unwrap();
    dir
}

#[test]
fn an_unfunded_box_is_refused_with_the_list() {
    let (url, _) = stub_rpc(BTreeMap::new());
    let dir = funded_bundle(&format!(
        "SETTLEMENT_SOLANA_RPC_URL={url}\nSOLANA_RPC_URL={url}\n"
    ));
    let output = keys_sh(dir.path(), &["check-funded"]);
    assert_eq!(output.status.code(), Some(1));
    let printed = stdout(&output);
    assert!(printed.contains("REFUSED"));
    assert!(printed.contains(ED25519[0].2) && printed.contains(PUBLISHER[1].1));

    // The same shortfall on a box that has booted is a warning.
    let output = keys_sh(dir.path(), &["check-funded", "--warn-only"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("::warning::"));
}

#[test]
fn a_funded_box_passes() {
    let (url, _) = stub_rpc(BTreeMap::from([
        (ED25519[0].2.to_string(), (1_000_000_000, 0)),
        (PUBLISHER[1].1.to_string(), (1_000_000_000, 1_000_000_000)),
    ]));
    let dir = funded_bundle(&format!(
        "SETTLEMENT_SOLANA_RPC_URL={url}\nSOLANA_RPC_URL={url}\n"
    ));
    let output = keys_sh(dir.path(), &["check-funded"]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_publisher_without_its_deposit_is_refused() {
    let (url, _) = stub_rpc(BTreeMap::from([
        (ED25519[0].2.to_string(), (1_000_000_000, 0)),
        (PUBLISHER[1].1.to_string(), (1_000_000_000, 9_999_999)),
    ]));
    let dir = funded_bundle(&format!(
        "SETTLEMENT_SOLANA_RPC_URL={url}\nSOLANA_RPC_URL={url}\n"
    ));
    let output = keys_sh(dir.path(), &["check-funded"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("USDC"));
}

#[test]
fn an_rpc_that_does_not_answer_is_a_warning_not_a_refusal() {
    let dir = funded_bundle(
        "SETTLEMENT_SOLANA_RPC_URL=http://127.0.0.1:1\nSOLANA_RPC_URL=http://127.0.0.1:1\n",
    );
    let output = keys_sh(dir.path(), &["check-funded"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(stdout(&output).contains("::warning::"));
}

#[test]
fn a_hidden_box_asks_only_its_own_solana_node() {
    let (url, asked) = stub_rpc(BTreeMap::from([
        (ED25519[0].2.to_string(), (1_000_000_000, 0)),
        (PUBLISHER[1].1.to_string(), (1_000_000_000, 1_000_000_000)),
    ]));
    // The public RPCs are unreachable here: were either asked, the check
    // would fail to read a balance and exit 3 instead of 0.
    let dir = funded_bundle(&format!(
        "SETTLEMENT_SOLANA_RPC_URL=http://127.0.0.1:1\nSOLANA_RPC_URL=http://127.0.0.1:1\n\
         HIDDEN=1\nHIDDEN_SETTLEMENT_SOLANA_RPC_URL={url}\n"
    ));
    let output = keys_sh(dir.path(), &["check-funded"]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    let asked = asked.lock().unwrap();
    assert!(asked.contains(&ED25519[0].2.to_string()));
    assert!(asked.contains(&PUBLISHER[1].1.to_string()));
}

#[test]
fn bootstrap_checks_funding_before_it_touches_the_host() {
    let bootstrap = fs::read_to_string(deploy_dir().join("bootstrap.sh")).unwrap();
    let check = bootstrap
        .find("./keys.sh check-funded")
        .expect("bootstrap.sh runs keys.sh check-funded");
    let firewall = bootstrap.find("apt-get install -y ufw").unwrap();
    assert!(
        check < firewall,
        "the funding check runs before anything is installed"
    );
    // Only a box that has booted (its sealing key recorded) gets a warning.
    assert!(bootstrap.contains(
        "if [ -n \"${CONNECTOR_SEAL_KEY:-}\" ]; then\n  ./keys.sh check-funded --warn-only"
    ));
}
