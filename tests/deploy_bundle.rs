//! The guard on `deploy/` — the provider box bundle, and the devnet box it
//! renders from its presets.
//!
//! It reads the REAL files, not fixtures: a fixture would keep passing while
//! the shipped artifact regressed. Expected values are literals declared here
//! and never read back out of the file under test, so a reverted fix fails
//! this suite instead of quietly agreeing with itself.
//!
//! Being a Rust test rather than a script buys the one thing the sibling
//! repositories' guards cannot have: it runs the REAL `render.sh`, with the
//! REAL `toon-provider` binary generating the connector's routes, over the
//! committed templates, the devnet preset in `.env.example` and
//! `listings.example.toml` — and then puts the output through the REAL
//! loader and the REAL route renderer. So the strongest assertion here is not
//! a regex — it is that `toon-provider routes` on the rendered
//! `provider.toml` prints exactly the `[[routes]]` block the rendered
//! `connector.toml` carries, for the devnet box and for an operator who is
//! not it.
//!
//! Only the example files are read. An operator's own `deploy/.env` and
//! `deploy/listings.toml` are never inputs here, so `cargo test` passes on a
//! box whatever that box sells.
//!
//! What else it holds still, and why:
//!   * the template LOADS, against the same validator the box runs, so a
//!     refuse-to-start is a red test here rather than a restart loop there;
//!   * `[[settlement]]` and `[settlement.*]` agree, because a Profile that
//!     advertises a token its connector does not settle is a tenant paying
//!     into nothing;
//!   * the exposure invariants: the app's listener and the operator endpoint
//!     are never published, the connector's edge is loopback-only, and only
//!     nginx faces the internet;
//!   * the firewall opens exactly the workload ports the config hands out,
//!     because a mismatch is a workload nobody can reach on a lease that was
//!     still paid for;
//!   * the connector pin, in exactly one place.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use toon_provider::{load_config, render_routes, ProviderConfig};

fn deploy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy")
}

fn deploy(name: &str) -> String {
    let path = deploy_dir().join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The values an operator fills into `.env` by hand, declared here so the
/// rendered config under test is reproducible and carries no real key.
/// Everything else — the relay and the settlement chains — comes from the
/// devnet preset `.env.example` ships, which is what this suite checks.
fn fixture_env() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("PROVIDER_NAME", "TOON Devnet Provider"),
        ("PUBLIC_IP", "203.0.113.7"),
        // 64 hex characters, like `openssl rand -hex 32`. Valueless.
        ("NOSTR_PRIVATE_KEY", "1111111111111111111111111111111111111111111111111111111111111111"),
        ("DOMAIN", "devnet.toonprotocol.dev"),
        // An uncompressed secp256k1 public key, the shape `GET /ilp/identity`
        // answers with — `0x04` and 128 hex digits.
        (
            "CONNECTOR_SEAL_KEY",
            "0x04325b06f4bcb438204ab86a36a715fdf409552da5cdc7cd28301b08088ce7c3a1bf4289f62ba89a707ed8d7db66b03cb2881ea5934e35f2d600c4cd7067ed0188",
        ),
        ("OPERATOR_BEARER_TOKEN", "2222222222222222222222222222222222222222222222222222222222222222"),
        ("OPERATOR_WRITE_KEY", "3333333333333333333333333333333333333333333333333333333333333333"),
    ])
}

/// What the devnet box's own `.env` adds to the preset: the fleet's address,
/// the flag that allows it, and the committed tiers.
fn devnet_env() -> BTreeMap<&'static str, &'static str> {
    let mut env = fixture_env();
    env.insert("ILP_ADDRESS", "g.toon.provider");
    env.insert("TOON_DEVNET_BOX", "1");
    env.insert("LISTINGS_FILE", "listings.example.toml");
    env
}

/// One run of the real `deploy/render.sh`, in a scratch copy of the bundle.
struct Render {
    dir: tempfile::TempDir,
    ok: bool,
    stderr: String,
}

impl Render {
    fn read(&self, name: &str) -> String {
        let path = self.dir.path().join(name);
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading rendered {name}: {e}"))
    }

    fn wrote(&self, name: &str) -> bool {
        self.dir.path().join(name).exists()
    }
}

/// Runs `render.sh` the way a box does, from a `.env` that is `.env.example`
/// with `env` appended — later lines win when the shell sources it, so this is
/// exactly an operator filling the example in. `listings` is written as
/// `listings.toml`, the default LISTINGS_FILE. `meminfo`, when given, is the
/// box's memory as `/proc/meminfo` would report it; otherwise the capacity
/// warning is off, so the machine running the tests does not decide what they
/// see.
fn run_render(
    env: &BTreeMap<&str, &str>,
    listings: Option<&str>,
    meminfo: Option<&str>,
    args: &[&str],
) -> Render {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in [
        "render.sh",
        "provider.toml.template",
        "connector.toml.template",
        "listings.example.toml",
    ] {
        fs::copy(deploy_dir().join(name), dir.path().join(name)).expect("copy the bundle");
    }
    fs::create_dir(dir.path().join("nginx")).unwrap();
    fs::copy(
        deploy_dir().join("nginx/node.conf.template"),
        dir.path().join("nginx/node.conf.template"),
    )
    .unwrap();

    let mut dotenv = deploy(".env.example");
    dotenv.push_str("\n# ── appended by tests/deploy_bundle.rs ──\n");
    for (name, value) in env {
        dotenv.push_str(&format!("{name}='{value}'\n"));
    }
    fs::write(dir.path().join(".env"), dotenv).unwrap();
    if let Some(listings) = listings {
        fs::write(dir.path().join("listings.toml"), listings).unwrap();
    }
    let meminfo_path = dir.path().join("meminfo");
    // Left absent when not given, so unreadable: render.sh skips the check.
    if let Some(text) = meminfo {
        fs::write(&meminfo_path, text).unwrap();
    }

    let out = Command::new("bash")
        .arg(dir.path().join("render.sh"))
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("TOON_PROVIDER_BIN", env!("CARGO_BIN_EXE_toon-provider"))
        .env("PROC_MEMINFO", &meminfo_path)
        .output()
        .expect("run deploy/render.sh (it needs bash and envsubst)");
    Render {
        dir,
        ok: out.status.success(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The devnet box's render: the preset, the committed tiers, rendered once
/// and shared, because every test below reads the same two files.
fn devnet_render() -> &'static (String, String) {
    static RENDERED: OnceLock<(String, String)> = OnceLock::new();
    RENDERED.get_or_init(|| {
        let render = run_render(&devnet_env(), None, None, &[]);
        assert!(
            render.ok,
            "deploy/render.sh refused the devnet preset:\n{}",
            render.stderr
        );
        (render.read("provider.toml"), render.read("connector.toml"))
    })
}

/// Loads a rendered provider.toml through the same validator the box runs.
fn load_rendered(text: &str) -> (ProviderConfig, tempfile::TempDir) {
    assert!(
        !text.contains("${"),
        "the rendered provider.toml still has an unsubstituted ${{…}}; either \
         render.sh does not pass that variable to envsubst or .env does not set it"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("provider.toml");
    fs::write(&path, text).expect("write rendered provider.toml");
    let config = load_config(path.to_str().expect("tempdir path is utf-8")).unwrap_or_else(|e| {
        panic!("the rendered provider.toml does not load: {e:#}");
    });
    (config, dir)
}

fn rendered_provider_config() -> (ProviderConfig, tempfile::TempDir) {
    load_rendered(&devnet_render().0)
}

/// The `prefix`/`handler_url`/`price` triples of every `[[routes]]` row, in
/// file order. Parsed with the crate's own TOML, so a syntactically broken
/// render fails here rather than on a box.
fn route_rows(connector_toml: &str) -> Vec<(String, String, i64)> {
    let value: toml::Value = toml::from_str(connector_toml).expect("connector.toml parses");
    value
        .get("routes")
        .and_then(|r| r.as_array())
        .expect("connector.toml has [[routes]]")
        .iter()
        .map(|row| {
            (
                row["prefix"]
                    .as_str()
                    .expect("prefix is a string")
                    .to_string(),
                row["handler_url"]
                    .as_str()
                    .expect("handler_url is a string")
                    .to_string(),
                row["price"].as_integer().expect("price is an integer"),
            )
        })
        .collect()
}

fn rendered_connector_toml() -> String {
    devnet_render().1.clone()
}

/// A file's lines with every comment removed: what a parser sees.
fn settings(text: &str) -> String {
    text.lines()
        .map(|l| l.split_once('#').map_or(l, |(before, _)| before))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── The one decision written twice ──────────────────────────────────────────

#[test]
fn the_connector_terminates_exactly_what_the_provider_serves() {
    let (config, _dir) = rendered_provider_config();

    // What the route renderer says for this provider.toml, with no lease
    // running — which is what a freshly rendered box is. render.sh got its
    // rows from the binary; this asks the library directly, so a splice that
    // dropped, doubled or reordered a row fails here.
    let generated = render_routes(&config, &[]);

    let want = route_rows(&generated);
    let got = route_rows(&rendered_connector_toml());

    assert_eq!(
        got, want,
        "the connector.toml render.sh wrote does not carry exactly the [[routes]] \
         `toon-provider routes` prints for the provider.toml it wrote beside it. \
         A route the connector prices and the app does not serve is a packet \
         taken and refused, and a refusal on a paid route is still billed \
         (TOON_Network ADR 0003)."
    );
    // The two free-standing decisions the devnet box has always sold, so a
    // preset that silently changed a price fails here too.
    assert!(got.contains(&(
        "g.toon.provider.basic.v1.spawn".to_string(),
        "http://provider:8080/listings/basic/v1/spawn".to_string(),
        1000
    )));
    assert!(got.contains(&(
        "g.toon.provider.basic.v1.standby".to_string(),
        "http://provider:8080/listings/basic/v1/standby".to_string(),
        400
    )));
    assert!(got.contains(&(
        "g.toon.provider.ci.v1.spawn".to_string(),
        "http://provider:8080/listings/ci/v1/spawn".to_string(),
        5000
    )));
    assert_eq!(got.len(), 10, "the devnet box sells ten routes: {got:?}");
}

#[test]
fn the_free_routes_are_priced_zero_rather_than_left_out() {
    // A terminated route is never SILENTLY free; the parser requires a price
    // either way, so writing it is what makes the intent reviewable.
    let rows = route_rows(&rendered_connector_toml());
    for name in ["availability", "status", "terminate", "rotate"] {
        let prefix = format!("g.toon.provider.{name}");
        let row = rows
            .iter()
            .find(|(p, _, _)| *p == prefix)
            .unwrap_or_else(|| panic!("no route terminates {prefix}"));
        assert_eq!(row.2, 0, "{prefix} is not free");
    }
}

#[test]
fn every_handler_is_under_the_origin_the_config_names() {
    let (config, _dir) = rendered_provider_config();
    for (prefix, handler, _) in route_rows(&rendered_connector_toml()) {
        assert!(
            handler.starts_with(&config.handler_base_url),
            "{prefix} is handled at {handler}, which is not under \
             handler_base_url ({})",
            config.handler_base_url
        );
    }
}

#[test]
fn the_connector_answers_for_the_address_every_route_hangs_off() {
    let (config, _dir) = rendered_provider_config();
    let value: toml::Value = toml::from_str(&rendered_connector_toml()).unwrap();
    let addresses: Vec<&str> = value["node"]["addresses"]
        .as_array()
        .expect("[node].addresses")
        .iter()
        .map(|a| a.as_str().expect("an address is a string"))
        .collect();
    assert_eq!(
        addresses,
        vec![config.ilp_address.as_str()],
        "the connector claims addresses that are not this provider's"
    );

    // A node that cannot say where it is cannot be paid. Both endpoints are
    // TLS, on the name the bundle's nginx serves.
    let http = value["node"]["http_endpoint"].as_str().unwrap();
    let btp = value["node"]["btp_endpoint"].as_str().unwrap();
    assert_eq!(http, "https://proxy.provider.devnet.toonprotocol.dev/ilp");
    assert_eq!(btp, "wss://proxy.provider.devnet.toonprotocol.dev/ilp/btp");
}

// ── Settlement: two files, one deployment ───────────────────────────────────

#[test]
fn the_profile_advertises_what_the_connector_actually_settles() {
    // A tenant reads `[[settlement]]` out of the Profile and decides what to
    // pay with before it has spoken to the connector at all. If the two
    // disagree it opens a channel against a token this node cannot verify.
    let (config, _dir) = rendered_provider_config();
    let connector: toml::Value = toml::from_str(&rendered_connector_toml()).unwrap();

    let evm = &connector["settlement"]["evm"];
    let solana = &connector["settlement"]["solana"];

    let advertised: BTreeMap<&str, (&str, u8)> = config
        .settlement
        .iter()
        .map(|s| (s.chain.as_str(), (s.token.as_str(), s.decimals)))
        .collect();

    assert_eq!(
        advertised.get("evm:84532"),
        Some(&(evm["token_address"].as_str().unwrap(), 6)),
        "the Profile's Base Sepolia token is not the one the connector settles"
    );
    assert_eq!(
        advertised.get("solana"),
        Some(&(solana["token_address"].as_str().unwrap(), 6)),
        "the Profile's Solana mint is not the one the connector settles"
    );

    // The registry, not the token network: the connector resolves the network
    // through it at boot, which is why a redeploy of the network needs no edit
    // here. Hard-coded so a silent swap fails.
    assert_eq!(
        evm["contract_address"].as_str().unwrap(),
        "0x0c41D9D424d6B075A3cEa1068a694f7847a8CCa5"
    );
    assert_eq!(
        solana["program_id"].as_str().unwrap(),
        "2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip"
    );
}

#[test]
fn every_credential_the_connector_reads_is_a_path() {
    let connector = rendered_connector_toml();
    for path in [
        "/app/data/signer.key",
        "/app/data/settlement.key",
        "/app/data/settlement-solana.key",
        "/app/data/operator-bearer.token",
        "/app/data/operator-write.keys",
    ] {
        assert!(
            connector.contains(path),
            "connector.toml.template does not name {path}"
        );
    }
    // The inline forms would put a credential in a committed file.
    for inline in ["bearer_token =", "write_keys =", "private_key ="] {
        assert!(
            !connector.contains(inline),
            "connector.toml.template carries an inline {inline} — every credential is a path"
        );
    }
}

// ── What this box sells ─────────────────────────────────────────────────────

#[test]
fn it_sells_a_tier_with_capabilities_and_a_tier_that_prices_warm_standbys() {
    let (config, _dir) = rendered_provider_config();

    let basic = config
        .listings
        .iter()
        .find(|l| l.name == "basic")
        .expect("no `basic` listing");
    assert!(
        basic.standby_price.is_some(),
        "`basic` prices no Warm Standby, so `toon-provider routes` prints no \
         standby rows and a Standby Set cannot be bought here at all (spec §7)"
    );
    assert_ne!(
        basic.standby_price,
        Some(0),
        "a standby price of 0 sells held capacity for nothing"
    );

    let ci = config
        .listings
        .iter()
        .find(|l| l.name == "ci")
        .expect("no `ci` listing");
    assert!(
        ci.capabilities.iter().any(|c| c == "docker"),
        "`ci` grants no capability, so nothing here demonstrates spec §4.4"
    );
}

#[test]
fn it_claims_the_isolation_it_can_actually_provide() {
    // `dedicated-host` would be a claim this deployment cannot make: the only
    // backend is Docker, and Linode's shared-CPU plans offer no nested
    // virtualization to build a hypervisor on. A relay filters on this tag.
    let (config, _dir) = rendered_provider_config();
    assert_eq!(config.isolation, "shared-kernel");
    assert!(
        !config.hidden,
        "this box publishes a host, so it is not a Hidden Provider"
    );
}

// ── Any operator, not only the devnet box ───────────────────────────────────

/// Another operator's tiers: one of their own, at their own price, selling no
/// standby. Nothing here is the devnet box's.
const ACME_LISTINGS: &str = r#"[[listings]]
name = "small"
version = 2
arch = "amd64"
lease_interval_s = 1800
price = 250
capabilities = []
capacity = 4
[listings.resources]
cpu_millicores = 250
memory_mb = 256
storage_gb = 2
"#;

fn acme_env() -> BTreeMap<&'static str, &'static str> {
    let mut env = fixture_env();
    env.insert("ILP_ADDRESS", "g.acme.provider");
    env.insert("DOMAIN", "acme.example");
    env.insert("PROVIDER_NAME", "Acme Compute");
    env
}

#[test]
fn another_operator_renders_its_own_address_and_tiers() {
    // `.env.example` plus the operator's own values and `listings.toml`, the
    // default LISTINGS_FILE — a fresh clone, filled in.
    let render = run_render(&acme_env(), Some(ACME_LISTINGS), None, &[]);
    assert!(
        render.ok,
        "render.sh refused another operator:\n{}",
        render.stderr
    );

    let provider = render.read("provider.toml");
    let connector = render.read("connector.toml");
    let (config, _dir) = load_rendered(&provider);

    assert_eq!(config.ilp_address, "g.acme.provider");
    assert_eq!(config.provider_name, "Acme Compute");
    let tiers: Vec<(&str, u32, u64)> = config
        .listings
        .iter()
        .map(|l| (l.name.as_str(), l.version, l.price))
        .collect();
    assert_eq!(tiers, vec![("small", 2, 250)]);

    let rows = route_rows(&connector);
    assert_eq!(rows, route_rows(&render_routes(&config, &[])));
    assert_eq!(
        rows.iter()
            .map(|(p, _, price)| (p.as_str(), *price))
            .collect::<Vec<_>>(),
        vec![
            ("g.acme.provider.small.v2.spawn", 250),
            ("g.acme.provider.small.v2.extend", 250),
            ("g.acme.provider.availability", 0),
            ("g.acme.provider.status", 0),
            ("g.acme.provider.terminate", 0),
            ("g.acme.provider.rotate", 0),
        ],
        "a tier that prices no standby has no standby rows"
    );

    let node: toml::Value = toml::from_str(&connector).unwrap();
    assert_eq!(
        node["node"]["addresses"].as_array().unwrap(),
        &vec![toml::Value::from("g.acme.provider")]
    );
    assert_eq!(
        node["node"]["http_endpoint"].as_str().unwrap(),
        "https://proxy.provider.acme.example/ilp"
    );

    // Nothing of the devnet box's identity or tiers comes along. (The relay and
    // the settlement chains do, deliberately: they are the preset this
    // operator kept.)
    for (name, text) in [("provider.toml", &provider), ("connector.toml", &connector)] {
        let set = settings(text);
        for theirs in ["g.toon.provider", "basic", "\"ci\"", "TOON Devnet Provider"] {
            assert!(
                !set.contains(theirs),
                "another operator's {name} carries the devnet box's {theirs}"
            );
        }
    }
}

#[test]
fn nobody_takes_the_fleet_namespace_by_accident() {
    // The devnet box's address, copied without the flag that says this IS the
    // devnet box: refused, and nothing written.
    let mut env = devnet_env();
    env.remove("TOON_DEVNET_BOX");
    let render = run_render(&env, None, None, &[]);
    assert!(
        !render.ok,
        "render.sh rendered g.toon.provider without TOON_DEVNET_BOX=1"
    );
    assert!(render.stderr.contains("g.toon."), "{}", render.stderr);
    assert!(!render.wrote("provider.toml") && !render.wrote("connector.toml"));

    for address in ["g.toon", "g.toon.someone-else"] {
        let mut env = acme_env();
        env.insert("ILP_ADDRESS", address);
        let render = run_render(&env, Some(ACME_LISTINGS), None, &[]);
        assert!(
            !render.ok,
            "render.sh rendered {address} without TOON_DEVNET_BOX=1"
        );
    }

    // A name that merely STARTS with the letters is someone else's namespace,
    // not the fleet's.
    let mut env = acme_env();
    env.insert("ILP_ADDRESS", "g.toonish.provider");
    let render = run_render(&env, Some(ACME_LISTINGS), None, &[]);
    assert!(render.ok, "{}", render.stderr);
}

#[test]
fn there_is_no_default_address_and_no_default_tiers() {
    // No ILP_ADDRESS: refused, rather than a second `g.toon.provider`.
    let mut env = acme_env();
    env.remove("ILP_ADDRESS");
    let render = run_render(&env, Some(ACME_LISTINGS), None, &[]);
    assert!(!render.ok);
    assert!(render.stderr.contains("ILP_ADDRESS"), "{}", render.stderr);

    // No listings file: refused, rather than quietly selling the example.
    let render = run_render(&acme_env(), None, None, &[]);
    assert!(!render.ok);
    assert!(
        render.stderr.contains("listings.example.toml"),
        "{}",
        render.stderr
    );
    assert!(!render.wrote("provider.toml"));
}

#[test]
fn the_connector_can_be_rendered_before_its_sealing_key_is_known() {
    // bootstrap.sh's first render: no CONNECTOR_SEAL_KEY yet, so no
    // provider.toml — but the connector still needs its routes, and they must
    // be the ones the full render will produce, or the full render restarts
    // the connector it has just asked for a key.
    let mut env = devnet_env();
    env.remove("CONNECTOR_SEAL_KEY");
    let render = run_render(&env, None, None, &["--connector-only"]);
    assert!(render.ok, "{}", render.stderr);
    assert!(
        !render.wrote("provider.toml"),
        "--connector-only wrote a provider.toml with no sealing key in it"
    );
    assert_eq!(render.read("connector.toml"), rendered_connector_toml());
}

#[test]
fn the_templates_name_no_operator() {
    // Everything that makes a box one operator's is in .env or the listings
    // file. A literal of the devnet box's in a template's SETTINGS is a value
    // every other operator inherits; the comments may still mention it.
    for name in ["provider.toml.template", "connector.toml.template"] {
        let set = settings(&deploy(name));
        for devnet in [
            "g.toon",
            "devnet",
            "0x49beE1Bca5d15Fb0963117923403F9498119a9Ce",
            "34eSxY7qxQ4GzyhDJ8GpUcTz1WWzruGbJbR8q6TtxfQU",
            "[[listings]]",
            "[[routes]]",
        ] {
            assert!(
                !set.contains(devnet),
                "{name} carries {devnet} outside a comment"
            );
        }
    }
}

// A MemTotal line the way /proc/meminfo writes it: kB.
fn meminfo(mib: u64) -> String {
    format!(
        "MemTotal:       {} kB\nMemFree:          1000 kB\n",
        mib * 1024
    )
}

#[test]
fn the_devnet_tiers_fit_the_devnet_box() {
    // A Linode 4 GB reports a little under 4096 MiB. Sold out, `basic` 3 × 512
    // and `ci` 1 × 1024 are 2560 MiB, which leaves the ~1 GiB the five
    // containers and the host need — deploy/README.md § "Sizing the box".
    let render = run_render(&devnet_env(), None, Some(&meminfo(3900)), &[]);
    assert!(render.ok, "{}", render.stderr);
    assert!(
        !render.stderr.contains("warning: sold out"),
        "the devnet tiers no longer fit the devnet box:\n{}",
        render.stderr
    );
}

#[test]
fn render_warns_when_what_is_sold_outgrows_the_box() {
    // Capacity is a promise only the operator can make, so this is a warning
    // and the render still succeeds — but it is said where they are looking.
    // 2560 MiB sold on a 3 GiB box leaves under 1 GiB for everything else.
    let render = run_render(&devnet_env(), None, Some(&meminfo(3072)), &[]);
    assert!(render.ok, "{}", render.stderr);
    assert!(
        render.stderr.contains("warning: sold out") && render.stderr.contains("2560 MiB"),
        "no capacity warning:\n{}",
        render.stderr
    );
}

// ── Exposure ────────────────────────────────────────────────────────────────

/// Every `- 'HOST:CONTAINER'` publish row in the compose file.
fn published_ports(compose: &str) -> Vec<String> {
    compose
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("- '")?.strip_suffix('\'')?;
            rest.contains(':').then(|| rest.to_string())
        })
        .filter(|row| row.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .collect()
}

#[test]
fn only_the_tls_front_faces_the_internet() {
    // Docker's iptables chain runs ahead of ufw, so an unqualified publish is
    // internet-reachable even with ufw locked to 22/80/443.
    let compose = deploy("docker-compose.yml");
    let mut unqualified: Vec<String> = published_ports(&compose)
        .into_iter()
        .filter(|row| !row.starts_with("127.0.0.1:"))
        .collect();
    unqualified.sort();
    assert_eq!(
        unqualified,
        vec!["443:443".to_string(), "80:80".to_string()]
    );
}

#[test]
fn the_app_and_the_operator_endpoint_are_never_published() {
    // The app's ONE listener carries /health and every spawn, extend, standby,
    // status, terminate and rotate handler. Publishing it would be the payment
    // skipped. The operator endpoint takes an eviction with no signature and
    // no payment, so reaching it at all is what authorises it.
    let compose = deploy("docker-compose.yml");
    for row in published_ports(&compose) {
        for port in ["8080", "8081", "8090"] {
            assert!(
                !row.ends_with(&format!(":{port}")),
                "docker-compose.yml publishes {row}, which reaches a private listener"
            );
        }
    }
    assert!(compose.contains("expose: ['8080']"));
    assert!(compose.contains("expose: ['8081']"));

    let (config, _dir) = rendered_provider_config();
    assert!(
        config.operator_bind_addr.starts_with("127.0.0.1:")
            || config.operator_bind_addr.starts_with("[::1]:"),
        "operator_bind_addr is not loopback"
    );
}

#[test]
fn the_connector_edge_is_published_on_the_loopback_only() {
    assert!(deploy("docker-compose.yml").contains("- '127.0.0.1:4000:4000'"));
}

#[test]
fn nginx_proxies_one_path_of_the_app_and_404s_the_rest() {
    // The health hostname must not become a second door to the spawn handler.
    let conf = deploy("nginx/node.conf.template");
    assert!(
        conf.contains("location = /health"),
        "health is not an EXACT-match location"
    );
    assert!(
        conf.contains("location / { return 404; }"),
        "the health host has no default deny"
    );
    assert!(
        !conf.contains("proxy_pass http://$upstream:8080;"),
        "nginx proxies the app's origin, not just its health path"
    );
}

#[test]
fn healthchecks_dial_127_0_0_1_never_localhost() {
    // "localhost" in a container can resolve to ::1, where an IPv4-bound
    // listener never answers.
    let compose = deploy("docker-compose.yml");
    for line in compose.lines().filter(|l| l.contains("http://")) {
        assert!(
            !line.contains("http://localhost"),
            "a healthcheck dials localhost: {}",
            line.trim()
        );
    }
}

// ── The firewall and the ports it is supposed to open ───────────────────────

#[test]
fn the_firewall_opens_exactly_the_workload_ports_the_config_hands_out() {
    // A tenant reaches its workload at PUBLIC_IP:<host port>. If ufw and the
    // config disagree, the lease was still paid for and the workload is
    // unreachable — and the failure is silent, because the daemon's own
    // iptables rules mean the port often works anyway and `ufw status` lies.
    let (config, _dir) = rendered_provider_config();
    let bootstrap = deploy("bootstrap.sh");

    let ids = config.workload_id_range_end - config.workload_id_range_start;
    let ssh_start = config
        .ssh_port_start
        .expect("ssh_port_start is pinned, not derived");
    let ssh_end = ssh_start as u32 + ids;
    let ports_start = config.workload_port_start as u32;
    // 16 ports per id; the last id's block ends 15 past its own start.
    let ports_end = ports_start + 16 * ids + 15;

    for rule in [
        format!("ufw allow {ssh_start}:{ssh_end}/tcp"),
        format!("ufw allow {ports_start}:{ports_end}/tcp"),
    ] {
        assert!(
            bootstrap.contains(&rule),
            "bootstrap.sh does not open the range the config hands out: expected `{rule}`"
        );
    }
}

// ── The pin ─────────────────────────────────────────────────────────────────

#[test]
fn the_connector_pin_is_immutable_and_written_once() {
    const PIN: &str = "ghcr.io/toon-protocol/connector:rust-2026.09.11.1";

    // A dated release alias or an exact commit. Never `rust-main`, and never
    // the retired `rust-release` pointer, which is frozen on a build whose
    // peerings can accept but never pay.
    let tag = PIN.rsplit(':').next().unwrap();
    assert!(
        tag.starts_with("rust-sha-") || tag.strip_prefix("rust-").is_some_and(|h| h.contains('.')),
        "{PIN} is not an immutable build"
    );

    assert!(deploy("docker-compose.yml").contains(PIN));

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy");
    let mut naming: Vec<String> = Vec::new();
    for entry in walk(&dir) {
        let name = entry
            .strip_prefix(&dir)
            .unwrap()
            .to_string_lossy()
            .to_string();
        if name == "docker-compose.yml" {
            continue;
        }
        let Ok(text) = fs::read_to_string(&entry) else {
            continue;
        };
        // .env.example and README.md quote the pin in a `docker run` recipe
        // for printing a key; that is a use of the image, not a second pin of
        // this box's connector. Only a compose-shaped `image:` line counts.
        if text
            .lines()
            .any(|l| l.trim_start().starts_with("image:") && l.contains("connector:"))
        {
            naming.push(name);
        }
    }
    assert!(
        naming.is_empty(),
        "the connector pin is written in more than one place: {naming:?}. Two copies drift."
    );
}

// ── The provider and publisher pins (TOON_Network#151) ──────────────────────
//
// Neither has been published yet — `docker-compose.yml` carries
// `sha-0000000` (git's own null-object-id spelling) for both, honestly, until
// `.github/workflows/publish-provider-image.yml` runs for real once this
// merges to `main`. So unlike `the_connector_pin_is_immutable_and_written_once`
// above, these two do not assert a literal tag — there isn't a real one to
// assert yet. What they hold still is the shape (an immutable tag, never a
// floating alias, never a `build:`) and the single-location invariant, the
// same two properties the connector's test enforces.

/// `sha-<hex>` (this repo's own scheme, see the workflow) or a bare dated
/// release handle such as `2026.09.11.1` (the connector's own alias shape,
/// minus its `rust-` prefix, in case a provider release ever wants one).
/// `latest`, `main` and anything empty are floating, not pins.
fn is_immutable_tag(tag: &str) -> bool {
    if tag.is_empty() || tag == "latest" || tag == "main" {
        return false;
    }
    if let Some(hex) = tag.strip_prefix("sha-") {
        return !hex.is_empty()
            && hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    }
    tag.contains('.') && tag.chars().all(|c| c.is_ascii_digit() || c == '.')
}

#[test]
fn is_immutable_tag_agrees_with_the_connector_pin() {
    // The predicate above must not be so loose it would have waved the
    // connector's OWN known-good and known-bad tags through differently than
    // the hand-written check in `the_connector_pin_is_immutable_and_written_once`
    // does — that would mean the two tests disagree about what a pin is.
    assert!(is_immutable_tag("sha-f278cd6"));
    assert!(is_immutable_tag("2026.09.11.1"));
    assert!(!is_immutable_tag("main"));
    assert!(!is_immutable_tag("latest"));
    assert!(!is_immutable_tag(""));
}

/// Every `image:` line in `compose` naming `image` exactly (colon-terminated,
/// so `provider` never matches a `provider-publisher` line), with its tag.
fn image_pins<'a>(compose: &'a str, image: &str) -> Vec<&'a str> {
    let prefix = format!("image: {image}:");
    compose
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix(prefix.as_str()))
        .collect()
}

fn assert_pinned_exactly_once(image: &str) {
    let compose = deploy("docker-compose.yml");
    let pins = image_pins(&compose, image);
    assert_eq!(
        pins.len(),
        1,
        "expected exactly one `image: {image}:<tag>` line in docker-compose.yml, found {pins:?}"
    );
    let tag = pins[0];
    assert!(
        is_immutable_tag(tag),
        "{image}:{tag} is not an immutable pin (floating alias or malformed tag)"
    );

    // No `build:` left for a service pinned by image — the whole point of
    // #151 is that this box no longer compiles anything.
    assert!(
        !compose.contains("build:"),
        "docker-compose.yml still has a `build:` step; {image} was supposed to replace it with a pin"
    );

    // Written once: no other file under deploy/ may carry a compose-shaped
    // `image:` line for the same image, mirroring the connector's own check.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy");
    let mut naming: Vec<String> = Vec::new();
    for entry in walk(&dir) {
        let name = entry
            .strip_prefix(&dir)
            .unwrap()
            .to_string_lossy()
            .to_string();
        if name == "docker-compose.yml" {
            continue;
        }
        let Ok(text) = fs::read_to_string(&entry) else {
            continue;
        };
        if text
            .lines()
            .any(|l| l.trim_start().starts_with(&format!("image: {image}:")))
        {
            naming.push(name);
        }
    }
    assert!(
        naming.is_empty(),
        "{image}'s pin is written in more than one place: {naming:?}. Two copies drift."
    );
}

#[test]
fn the_provider_pin_is_immutable_and_written_once() {
    assert_pinned_exactly_once("ghcr.io/toon-protocol/provider");
}

#[test]
fn the_publisher_pin_is_immutable_and_written_once() {
    assert_pinned_exactly_once("ghcr.io/toon-protocol/provider-publisher");
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

// ── Nothing secret is committable ───────────────────────────────────────────

#[test]
fn the_rendered_secret_and_every_key_are_gitignored() {
    // provider.toml is the one rendered config in this fleet that IS a secret:
    // it carries `nostr_private_key` inline, because the app takes the value
    // and not a path to it.
    let ignore = deploy(".gitignore");
    for line in [
        ".env",
        // The operator's own tiers: editing them must never dirty the tree
        // auto-apply.sh fast-forwards.
        "listings.toml",
        "provider.toml",
        "connector.toml",
        "operator-bearer.token",
        "operator-write.keys",
        "*.key",
    ] {
        assert!(
            ignore.lines().any(|l| l.trim() == line),
            "deploy/.gitignore does not carry {line}"
        );
    }
    assert!(ignore.lines().any(|l| l.trim() == "!.env.example"));

    // And the template must carry no key of its own.
    let template = deploy("provider.toml.template");
    assert!(template.contains("nostr_private_key = \"${NOSTR_PRIVATE_KEY}\""));
    for (name, value) in fixture_env() {
        if name == "NOSTR_PRIVATE_KEY" {
            assert!(
                !template.contains(value),
                "the template carries a literal key"
            );
        }
    }

    // .env.example ships every required variable present and empty, so a
    // missing one is a rendering refusal and never a silent default.
    let example = deploy(".env.example");
    for name in [
        // Who the operator is. No default: the devnet box's name, domain or
        // address, defaulted, is a second provider wearing its identity.
        "DOMAIN",
        "PROVIDER_NAME",
        "ILP_ADDRESS",
        "PUBLIC_IP",
        "NOSTR_PRIVATE_KEY",
        "PUBLISHER_MNEMONIC",
        "OPERATOR_BEARER_TOKEN",
        "OPERATOR_WRITE_KEY",
    ] {
        // `NAME=` or `NAME=''` — the quoted form is how a value with a space
        // in it survives being `source`d by render.sh, and an empty one is
        // written that way for consistency with its filled-in neighbours.
        assert!(
            example
                .lines()
                .any(|l| l.trim() == format!("{name}=") || l.trim() == format!("{name}=''")),
            "{name} is not present-and-empty in deploy/.env.example"
        );
    }

    // Anything with a space or a brace must be single-quoted: this file is
    // read by docker compose AND `source`d as shell, and the shell runs the
    // second word of an unquoted value as a command.
    for line in example.lines().map(str::trim) {
        if line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if !name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            continue;
        }
        if value.contains(' ') || value.contains('{') {
            assert!(
                value.starts_with('\'') && value.ends_with('\''),
                "{name} has a space or a brace and is not single-quoted: `source`ing \
                 deploy/.env would break on it"
            );
        }
    }
}

#[test]
fn the_publisher_pays_over_a_carriage_the_relay_will_accept() {
    // The devnet relay PINS `g.toon.relay` to BTP. An HTTP one-shot there is
    // refused, and the Profile, the Listings and the Liveness are never
    // written at all — a provider that is running fine and is invisible.
    //
    // The carriage is NAMED here rather than left to `auto`, because `auto`
    // reads the pin out of the node's own self-description and this relay
    // publishes none: its `GET /ilp` advertises `peerCarriages: []` and its
    // routes carry only a prefix and a price. `auto` therefore falls back to
    // HTTP and is refused `TRANSPORT_REQUIRED` — observed against the devnet
    // relay on 2026-09-22, once its connector carried ADR 0069's wire and
    // could refuse in words rather than in a parse error. When a connector
    // publishes the pin it enforces, this may go back to `auto`.
    let compose = deploy("docker-compose.yml");
    assert!(compose.contains("TOON_TRANSPORT: btp"));

    // And the two things a websocket carriage cannot carry are absent, which
    // is what makes this carriage safe here rather than a silent leak: the SOCKS5h
    // proxy and the endpoint rewrite both live inside the publisher's `fetch`.
    // Settings only — the comments beside them say why they are absent, and
    // saying so is not setting them.
    let set: Vec<&str> = compose
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter(|l| {
            ["TOON_ENDPOINT_REWRITE", "TOON_SOCKS_PROXY", "TOON_HIDDEN"]
                .iter()
                .any(|name| l.starts_with(&format!("{name}:")))
        })
        .collect();
    assert!(
        set.is_empty(),
        "docker-compose.yml sets something `auto` cannot carry: {set:?}"
    );
}
