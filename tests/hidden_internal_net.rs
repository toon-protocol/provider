//! A Hidden Provider's own services reach the internet only through `anon`,
//! enforced by the network (TOON_Network#181), against a REAL `anon` daemon
//! over the real Anyone network, on the topology the REAL overlay resolves
//! to.
//!
//! `tests/deploy_bundle.rs` holds the overlay's text still: the connector,
//! the provider and the publisher are on the `internal` hidden network alone.
//! What this proves, that it cannot: that such a network really leaves a
//! container no way off the box (a direct dial to an IP fails, and so does a
//! name, because Docker's embedded DNS forwards nothing out of an internal
//! network), that the daemon's SOCKS port on it really is a way out, and
//! that the loopback relay really carries the host's 127.0.0.1 port through
//! to the connector's pinned address.
//!
//! THE TOPOLOGY IS READ, NOT RETYPED. `docker compose config` resolves
//! `docker-compose.yml` + `docker-compose.hidden.yml` exactly as a box does,
//! and every network each service lands on, each network's `internal` flag,
//! every pinned address and the relay's own image and command come out of
//! that model. So putting `default` back on the provider, or dropping
//! `internal: true`, fails here as a successful direct dial. Each service is
//! stood in for by a `curl` probe on exactly that service's networks, at its
//! pinned address: which process runs in a network namespace does not change
//! where the namespace can route.
//!
//! RUNNABLE BESIDE A REAL HIDDEN BOX. Unlike `tests/hidden_dns_shim.rs`, it
//! does not take the box's fixed subnets: every address is moved one subnet
//! over (`172.30.2.x` -> `172.30.212.x`, `10.204.0.x` -> `10.214.0.x`), in the
//! resolved model and in `anon/anonrc` alike, and the relay publishes a
//! random loopback port rather than 4000. Every resource it makes is named
//! `toon-test-internal-net-*` and torn down when it ends, however it ends.
//! Not tested here: the daemon's own `iptables` (the workload egress, which
//! `hidden_dns_shim.rs` covers), and a real connector, provider and publisher
//! booting on this network, which needs funded keys.
//!
//! AND THE ONE THING `internal` COSTS, put back. The daemon dials a lease at
//! the hidden network's gateway, which Docker forwards to the lease's
//! forwarder on another bridge, out of the internal network, and drops;
//! `hidden-firewall.sh`'s rule 0 accepts exactly that dial. A host firewall
//! is not something a test may touch on the machine it runs on, so the
//! second test runs the REAL `hidden-firewall.sh` inside an isolated,
//! privileged `docker:dind`, on the overlay's own hidden network (its real
//! addresses: nothing else is in there to collide with), and checks the
//! daemon's address reaches a published lease port there while another
//! address on the same network does not.
//!
//! Needs a Docker daemon with `docker compose`, and the internet (to build
//! the `anon` image, to reach Anyone and to pull `docker:dind`), so both are
//! `#[ignore]`d:
//!
//! ```sh
//! cargo test --test hidden_internal_net -- --ignored
//! ```

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serde_json::Value;

const PREFIX: &str = "toon-test-internal-net";
const ANON_IMAGE: &str = "toon-test-internal-net-anon:latest";
const PROBE_IMAGE: &str = "curlimages/curl:8.16.0";

/// The services of a hidden box that dial out for themselves: the ones the
/// network must hold to the daemon's SOCKS port.
const DIALLERS: [&str; 3] = ["provider-connector", "provider", "directory-publisher"];

/// A direct dial by IP, and one by name.
const DIRECT_TARGETS: [&str; 2] = ["https://1.1.1.1", "https://example.com"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run(program: &str, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("invoke `{program} {}`: {e}", args.join(" ")))
}

fn docker_ok(args: &[&str]) -> String {
    let out = run("docker", args);
    assert!(
        out.status.success(),
        "docker {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Moves every address of the real box one subnet over, so this runs beside
/// one.
fn shift(text: &str) -> String {
    text.replace("172.30.2.", "172.30.212.")
        .replace("10.204.0.", "10.214.0.")
}

fn container(service: &str) -> String {
    format!("{PREFIX}-{service}")
}

fn network(key: &str) -> String {
    format!("{PREFIX}-{key}")
}

const CONTROL: &str = "toon-test-internal-net-control";

/// Best effort, never panics: safe before a run and after one.
fn cleanup() {
    let out = run(
        "docker",
        &["ps", "-aq", "--filter", &format!("name=^{PREFIX}-")],
    );
    for id in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        let _ = run("docker", &["rm", "-f", id]);
    }
    let out = run(
        "docker",
        &[
            "network",
            "ls",
            "-q",
            "--filter",
            &format!("name=^{PREFIX}-"),
        ],
    );
    for id in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        let _ = run("docker", &["network", "rm", id]);
    }
    for volume in ["anon-data", "anon-control"] {
        let _ = run("docker", &["volume", "rm", &format!("{PREFIX}-{volume}")]);
    }
}

struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        cleanup();
    }
}

/// The hidden box as compose resolves it, with placeholders for the three
/// values the base file refuses to resolve without.
fn resolved_model() -> Value {
    let out = Command::new("docker")
        .current_dir(repo_root().join("deploy"))
        .args([
            "compose",
            "-p",
            PREFIX,
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.hidden.yml",
            "config",
            "--format",
            "json",
        ])
        .env("RELAY_EDGE_URL", "https://relay.invalid/ilp")
        .env("PUBLISHER_MNEMONIC", "placeholder")
        .env("RELAY_WRITE_ROUTES", "placeholder")
        .output()
        .expect("invoke docker compose config");
    assert!(
        out.status.success(),
        "docker compose config: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("docker compose config printed JSON")
}

/// A service's networks, each with the (shifted) address it is pinned at.
fn service_networks(model: &Value, service: &str) -> BTreeMap<String, Option<String>> {
    model["services"][service]["networks"]
        .as_object()
        .unwrap_or_else(|| panic!("{service} has no networks in the resolved model"))
        .iter()
        .map(|(key, attachment)| {
            let ip = attachment
                .get("ipv4_address")
                .and_then(Value::as_str)
                .map(shift);
            (key.clone(), ip)
        })
        .collect()
}

/// `docker create` on the first network, `network connect` for the rest,
/// then start: a network connected after start is not there for a daemon
/// that binds at startup (`hidden_dns_shim.rs` found that race).
fn create_on(
    name: &str,
    networks: &BTreeMap<String, Option<String>>,
    extra: &[&str],
    image_and_command: &[&str],
) {
    let mut attachments = networks.iter();
    let (first, first_ip) = attachments.next().expect("at least one network");
    let first_net = network(first);
    let mut args = vec!["create", "--name", name, "--network", first_net.as_str()];
    if let Some(ip) = first_ip {
        args.extend(["--ip", ip.as_str()]);
    }
    args.extend(extra);
    args.extend(image_and_command);
    docker_ok(&args);
    for (key, ip) in attachments {
        let net = network(key);
        let mut args = vec!["network", "connect"];
        if let Some(ip) = ip {
            args.extend(["--ip", ip.as_str()]);
        }
        args.extend([net.as_str(), name]);
        docker_ok(&args);
    }
    docker_ok(&["start", name]);
}

fn curl_from(container: &str, args: &[&str]) -> Output {
    let mut all = vec![
        "exec",
        container,
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "--max-time",
        "10",
    ];
    all.extend(args);
    run("docker", &all)
}

fn wait_for_log_line(container: &str, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let logs = run("docker", &["logs", container]);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr)
        );
        if text.contains(needle) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{container} never logged {needle:?} within {timeout:?}; last logs:\n{text}");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
#[ignore = "needs a Docker daemon with compose and internet access (builds anon, dials Anyone); run with `cargo test --test hidden_internal_net -- --ignored`. See the module doc."]
fn the_hidden_boxs_own_services_reach_off_the_box_only_through_anon() {
    cleanup();
    let _guard = Cleanup;
    let root = repo_root();
    let model = resolved_model();

    // ── The networks, as the overlay declares them ────────────────────────
    let mut keys: Vec<String> = ["anon", "connector-loopback"]
        .iter()
        .chain(DIALLERS.iter())
        .flat_map(|s| service_networks(&model, s).into_keys())
        .collect();
    keys.sort();
    keys.dedup();
    for key in &keys {
        let declared = &model["networks"][key];
        let mut args = vec!["network".to_string(), "create".to_string()];
        if declared["internal"].as_bool() == Some(true) {
            args.push("--internal".into());
        }
        if let Some(pool) = declared["ipam"]["config"].get(0) {
            for (flag, field) in [
                ("--subnet", "subnet"),
                ("--gateway", "gateway"),
                ("--ip-range", "ip_range"),
            ] {
                if let Some(value) = pool[field].as_str() {
                    args.push(flag.into());
                    args.push(shift(value));
                }
            }
        }
        args.push(network(key));
        docker_ok(&args.iter().map(String::as_str).collect::<Vec<_>>());
    }
    // The premise the rest stands on.
    for service in DIALLERS {
        for key in service_networks(&model, service).keys() {
            assert_eq!(
                model["networks"][key]["internal"].as_bool(),
                Some(true),
                "{service} is on {key}, which is not internal"
            );
        }
    }

    // ── anon, on the real anonrc moved one subnet over ────────────────────
    docker_ok(&[
        "build",
        "-t",
        ANON_IMAGE,
        root.join("deploy/anon").to_str().unwrap(),
    ]);
    let anonrc = shift(&std::fs::read_to_string(root.join("deploy/anon/anonrc")).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let anonrc_path = dir.path().join("anonrc");
    std::fs::write(&anonrc_path, anonrc).unwrap();
    // World-readable: the daemon drops to `anond` before it reads it.
    let _ = run("chmod", &["755", dir.path().to_str().unwrap()]);
    let _ = run("chmod", &["644", anonrc_path.to_str().unwrap()]);
    let anon = container("anon");
    let anon_networks = service_networks(&model, "anon");
    let socks_ip = anon_networks["hidden"]
        .clone()
        .expect("anon is pinned on hidden");
    let mount = format!("{}:/etc/anon/anonrc:ro", anonrc_path.to_str().unwrap());
    let data = format!("{PREFIX}-anon-data:/var/lib/anon");
    let control = format!("{PREFIX}-anon-control:/var/lib/anon/control");
    create_on(
        &anon,
        &anon_networks,
        &["--init", "-v", &mount, "-v", &data, "-v", &control],
        &[ANON_IMAGE],
    );

    // ── A probe in each dialler's place, and a control on `default` ────────
    for service in DIALLERS {
        create_on(
            &container(service),
            &service_networks(&model, service),
            &["--entrypoint", "sh"],
            // The connector's stands in for the connector's edge too, for
            // the relay below to reach.
            &[
                PROBE_IMAGE,
                "-c",
                "while true; do printf 'HTTP/1.0 200 OK\\r\\n\\r\\nconnector\\n' | nc -l -p 4000; done",
            ],
        );
    }
    docker_ok(&[
        "run",
        "-d",
        "--name",
        CONTROL,
        "--network",
        &network("default"),
        "--entrypoint",
        "sleep",
        PROBE_IMAGE,
        "600",
    ]);

    // ── The relay, the overlay's own image and command ────────────────────
    let relay = &model["services"]["connector-loopback"];
    let image = relay["image"].as_str().expect("the relay has an image");
    let entrypoint: Vec<String> = relay["entrypoint"]
        .as_array()
        .expect("the relay has an entrypoint")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let command: Vec<String> = relay["command"]
        .as_array()
        .expect("the relay has a command")
        .iter()
        .map(|v| shift(v.as_str().unwrap()))
        .collect();
    let target = relay["ports"][0]["target"]
        .as_u64()
        .expect("the relay publishes a port");
    assert_eq!(relay["ports"][0]["host_ip"].as_str(), Some("127.0.0.1"));
    // A random loopback port: a real box beside this one holds 4000.
    let publish = format!("127.0.0.1::{target}");
    // `docker create --entrypoint` takes only the program, so the rest of
    // the overlay's entrypoint (`-c`) leads the command.
    let mut image_and_command = vec![image];
    image_and_command.extend(entrypoint[1..].iter().map(String::as_str));
    image_and_command.extend(command.iter().map(String::as_str));
    create_on(
        &container("connector-loopback"),
        &service_networks(&model, "connector-loopback"),
        &["--entrypoint", &entrypoint[0], "-p", &publish],
        &image_and_command,
    );

    // ── The control dials out directly, or nothing below means anything ───
    let out = curl_from(CONTROL, &[DIRECT_TARGETS[0]]);
    assert!(
        out.status.success(),
        "a container on compose's `default` network cannot dial {} directly either ({}); \
         this host has no internet, so a failed direct dial below would prove nothing",
        DIRECT_TARGETS[0],
        String::from_utf8_lossy(&out.stderr)
    );

    // ── No direct dial from any of the three ──────────────────────────────
    for service in DIALLERS {
        for target in DIRECT_TARGETS {
            let out = curl_from(&container(service), &[target]);
            assert!(
                !out.status.success(),
                "{service} dialled {target} directly, not through anon"
            );
        }
    }

    // ── And through the daemon, each of them gets out ──────────────────────
    wait_for_log_line(&anon, "Bootstrapped 100%", Duration::from_secs(120));
    let socks = format!("{socks_ip}:9050");
    for service in DIALLERS {
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut out = curl_from(
            &container(service),
            &["--socks5-hostname", &socks, "https://example.com"],
        );
        while !out.status.success() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_secs(3));
            out = curl_from(
                &container(service),
                &["--socks5-hostname", &socks, "https://example.com"],
            );
        }
        assert!(
            out.status.success(),
            "{service} could not reach https://example.com through anon at {socks}: {}\nanon logs:\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&run("docker", &["logs", "--tail", "30", &anon]).stdout),
        );
    }

    // ── The host's loopback port reaches the connector through the relay ───
    let port = docker_ok(&[
        "port",
        &container("connector-loopback"),
        &target.to_string(),
    ]);
    let host_port = port
        .lines()
        .find_map(|l| l.strip_prefix("127.0.0.1:"))
        .unwrap_or_else(|| panic!("the relay published no loopback port: {port}"))
        .to_string();
    let deadline = Instant::now() + Duration::from_secs(20);
    let answer = loop {
        let attempt = TcpStream::connect(format!("127.0.0.1:{host_port}")).and_then(|mut s| {
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(b"GET /ilp/identity HTTP/1.0\r\n\r\n")?;
            let mut body = String::new();
            s.read_to_string(&mut body)?;
            Ok(body)
        });
        match attempt {
            Ok(body) if body.contains("connector") => break body,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(500)),
            other => panic!(
                "127.0.0.1:{host_port} never reached the connector through the relay: {other:?}\nrelay logs:\n{}",
                String::from_utf8_lossy(&run("docker", &["logs", &container("connector-loopback")]).stderr)
            ),
        }
    };
    assert!(answer.starts_with("HTTP/1.0 200"), "{answer}");
}

const DIND: &str = "toon-test-lease-ingress-dind";
const DIND_IMAGE: &str = "docker:29-dind";

/// Removes the dind container, which takes everything inside it along.
struct DindCleanup;
impl Drop for DindCleanup {
    fn drop(&mut self) {
        let _ = run("docker", &["rm", "-f", DIND]);
    }
}

/// A shell command inside the dind container, with its combined output.
fn in_dind(script: &str) -> (bool, String) {
    let out = run("docker", &["exec", DIND, "sh", "-c", script]);
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
#[ignore = "needs a Docker daemon that can run a privileged docker:dind, and internet access; run with `cargo test --test hidden_internal_net -- --ignored`. See the module doc."]
fn the_daemon_alone_reaches_a_lease_from_the_internal_network() {
    let _ = run("docker", &["rm", "-f", DIND]);
    let _guard = DindCleanup;
    let root = repo_root();
    let model = resolved_model();

    // The overlay's hidden network and the daemon's address on it, unshifted.
    let hidden = &model["networks"]["hidden"];
    assert_eq!(hidden["internal"].as_bool(), Some(true));
    let pool = &hidden["ipam"]["config"][0];
    let subnet = pool["subnet"].as_str().unwrap();
    let gateway = pool["gateway"].as_str().unwrap();
    let ip_range = pool["ip_range"].as_str().unwrap();
    let bridge = hidden["driver_opts"]["com.docker.network.bridge.name"]
        .as_str()
        .expect("the hidden network names its bridge");
    let anon_ip = model["services"]["anon"]["networks"]["hidden"]["ipv4_address"]
        .as_str()
        .expect("anon is pinned on hidden")
        .to_string();
    let other_ip = anon_ip
        .rsplit_once('.')
        .map(|(net, _)| format!("{net}.5"))
        .unwrap();

    let firewall = root.join("deploy/hidden-firewall.sh");
    docker_ok(&[
        "run",
        "-d",
        "--privileged",
        "--name",
        DIND,
        "-v",
        &format!("{}:/fw/hidden-firewall.sh:ro", firewall.to_str().unwrap()),
        DIND_IMAGE,
    ]);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !in_dind("docker info >/dev/null 2>&1").0 {
        assert!(Instant::now() < deadline, "dockerd in {DIND} never came up");
        std::thread::sleep(Duration::from_secs(1));
    }

    // A lease's forwarder, publishing a port of the lease range on the host,
    // as `docker.rs` runs it: on the ordinary bridge, `-p <port>:<port>`.
    let setup = format!(
        "set -e
         apk add -q bash >/dev/null
         docker network create --internal --subnet {subnet} --gateway {gateway} \
           --ip-range {ip_range} -o com.docker.network.bridge.name={bridge} hidden >/dev/null
         docker run -d --name lease -p 41000:41000 alpine:3.20 sh -c \
           'while true; do printf \"HTTP/1.0 200 OK\\r\\n\\r\\nleaseok\\n\" | nc -l -p 41000; done' >/dev/null
         bash /fw/hidden-firewall.sh"
    );
    let (ok, output) = in_dind(&setup);
    assert!(ok, "setting up the dind box failed:\n{output}");

    let dial = |from: &str| {
        in_dind(&format!(
            "docker run --rm --network hidden --ip {from} alpine:3.20 \
             wget -q -T 5 -O- http://{gateway}:41000/"
        ))
    };
    let (ok, output) = dial(&anon_ip);
    assert!(
        ok && output.contains("leaseok"),
        "the daemon's address {anon_ip} does not reach a lease at {gateway}:41000 \
         from the internal hidden network:\n{output}\nDOCKER-USER:\n{}",
        in_dind("iptables -S DOCKER-USER").1
    );
    let (ok, output) = dial(&other_ip);
    assert!(
        !ok && !output.contains("leaseok"),
        "{other_ip}, not the daemon, reached a lease at {gateway}:41000:\n{output}"
    );
    let (ok, _) = in_dind(&format!(
        "docker run --rm --network hidden --ip {other_ip} alpine:3.20 wget -q -T 5 -O- http://1.1.1.1"
    ));
    assert!(
        !ok,
        "a container on the internal hidden network dialled 1.1.1.1 directly"
    );
}
