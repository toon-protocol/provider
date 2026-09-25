//! The Hidden Provider's DNS shim (TOON_Network#166) against REAL `anon` and
//! `dns-shim` images, on the exact addresses `docker-compose.hidden.yml` and
//! `anon/anonrc` commit to: resolves a name from an `alpine` (musl) workload
//! and from a `debian` (glibc) one, on the egress network, through the real
//! daemon over the real Anyone network.
//!
//! What this proves, that `tests/deploy_bundle.rs`'s static checks cannot:
//! `anon`'s DNAT to the shim actually reaches it (needs `ip_forward` genuinely
//! on and the `FORWARD` rules genuinely right, not just present in the
//! command text), the shim's own forwarding and local-AAAA logic behave the
//! same off a real socket as `src/dns_shim.rs`'s unit tests show them
//! behaving on parsed bytes, and a musl resolver's actual parallel A+AAAA
//! query — not a synthetic one — comes back resolved rather than "no such
//! name".
//!
//! Beside `tests/docker_backend.rs` and `tests/anon_control.rs`, this needs a
//! Docker daemon (and builds the real `anon` and `dns-shim` images, which
//! needs the internet: `anon/Dockerfile` downloads the release binary, and
//! `dns-shim/Dockerfile`'s builder stage downloads crates), so it is
//! `#[ignore]`d:
//!
//! ```sh
//! cargo test --test hidden_dns_shim -- --ignored
//! ```
//!
//! It runs on the SAME fixed addresses a real Hidden Provider box does
//! (172.30.2.0/24, 10.204.0.0/24 — `anon/anonrc` is mounted unmodified, the
//! same file the box runs), so it must not be run on a host that is at the
//! same time running an actual hidden box, real or another instance of this
//! same test: both would fight over the same subnets. Every resource this
//! test makes is named `toon-test-dns-shim-*` and torn down (containers,
//! networks and volumes) when it ends, however it ends; the two images it
//! builds are left in the local cache, exactly as `docker_backend.rs` leaves
//! `alpine:3.20` pulled, so a second run does not pay to build `anon` again.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const HIDDEN_NET: &str = "toon-test-dns-shim-hidden";
const EGRESS_NET: &str = "toon-test-dns-shim-egress";
const ANON_DATA_VOLUME: &str = "toon-test-dns-shim-anon-data";
const ANON_CONTROL_VOLUME: &str = "toon-test-dns-shim-anon-control";
const ANON_IMAGE: &str = "toon-test-dns-shim-anon:latest";
const SHIM_IMAGE: &str = "toon-test-dns-shim-shim:latest";
const ANON_CONTAINER: &str = "toon-test-dns-shim-anon";
const SHIM_CONTAINER: &str = "toon-test-dns-shim-shim";
const ALPINE_CONTAINER: &str = "toon-test-dns-shim-alpine";
const DEBIAN_CONTAINER: &str = "toon-test-dns-shim-debian";

/// The addresses `deploy/anon/anonrc` and `deploy/docker-compose.hidden.yml`
/// commit to (TOON_Network#166's module doc says why the shim sits at .3
/// rather than somewhere of this test's own choosing).
const ANON_HIDDEN_IP: &str = "172.30.2.2";
const ANON_EGRESS_IP: &str = "10.204.0.2";
const SHIM_EGRESS_IP: &str = "10.204.0.3";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run(program: &str, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("invoke `{program} {}`: {e}", args.join(" ")))
}

/// Runs a docker CLI command, panicking with its stderr on a non-zero exit.
/// Every setup step must succeed, or later steps read nothing meaningful.
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

/// Best-effort cleanup: never panics, so it is safe both before a run (a
/// previous one left something behind) and after (however this one ends).
fn cleanup() {
    let _ = run(
        "docker",
        &[
            "rm",
            "-f",
            ANON_CONTAINER,
            SHIM_CONTAINER,
            ALPINE_CONTAINER,
            DEBIAN_CONTAINER,
        ],
    );
    let _ = run("docker", &["network", "rm", HIDDEN_NET, EGRESS_NET]);
    let _ = run(
        "docker",
        &["volume", "rm", ANON_DATA_VOLUME, ANON_CONTROL_VOLUME],
    );
}

/// Removes every resource this test made, on every exit path (a panic from
/// an assertion included), the same job `Connector`'s `Drop` does in
/// `tests/redeem_connector_image.rs`.
struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        cleanup();
    }
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

#[tokio::test]
#[ignore = "needs a Docker daemon and internet access to build two images; run with `cargo test --test hidden_dns_shim -- --ignored`. See this file's module doc for the addresses it uses and why it must not run beside a real hidden box."]
async fn a_musl_and_a_glibc_workload_both_resolve_a_name_on_the_hidden_egress() {
    cleanup(); // nothing left behind by an earlier interrupted run
    let _guard = Cleanup;
    let root = repo_root();

    // ── Build the two images the real bundle builds ────────────────────────
    docker_ok(&[
        "build",
        "-t",
        ANON_IMAGE,
        "-f",
        root.join("deploy/anon/Dockerfile").to_str().unwrap(),
        root.join("deploy/anon").to_str().unwrap(),
    ]);
    docker_ok(&[
        "build",
        "-t",
        SHIM_IMAGE,
        "-f",
        root.join("deploy/dns-shim/Dockerfile").to_str().unwrap(),
        root.to_str().unwrap(),
    ]);

    // ── The two networks docker-compose.hidden.yml declares ────────────────
    docker_ok(&["network", "create", "--subnet", "172.30.2.0/24", HIDDEN_NET]);
    docker_ok(&[
        "network",
        "create",
        "--internal",
        "--subnet",
        "10.204.0.0/24",
        EGRESS_NET,
    ]);
    docker_ok(&["volume", "create", ANON_DATA_VOLUME]);
    docker_ok(&["volume", "create", ANON_CONTROL_VOLUME]);

    // ── anon, on the real committed anonrc, unmodified ──────────────────────
    // `docker create` then two `network connect`s then `docker start`,
    // rather than `docker run` with a second network attached after the
    // fact: anon's DNSPort/TransPort bind at container start, and a network
    // connected afterwards is not yet there to bind on (this is the exact
    // race a bare `docker run -d --network A --ip … ` followed by
    // `network connect B` hits — found running this test's setup by hand).
    let anonrc = root.join("deploy/anon/anonrc");
    docker_ok(&[
        "create",
        "--name",
        ANON_CONTAINER,
        "--init",
        "--cap-add",
        "NET_ADMIN",
        // Only for the DNS shim's sake — docker-compose.hidden.yml's own
        // comment on `anon`'s `sysctls:` says why this is safe.
        "--sysctl",
        "net.ipv4.ip_forward=1",
        "--network",
        HIDDEN_NET,
        "--ip",
        ANON_HIDDEN_IP,
        "-v",
        &format!("{}:/etc/anon/anonrc:ro", anonrc.to_str().unwrap()),
        "-v",
        &format!("{ANON_DATA_VOLUME}:/var/lib/anon"),
        // The real anonrc turns on `CookieAuthentication` and names this
        // nested path for it (a separate volume, like production's
        // `anon_control`, so the cookie can be handed out without the
        // address's private key beside it) — without a volume mounted
        // there, the daemon dies at startup unable to create the path.
        "-v",
        &format!("{ANON_CONTROL_VOLUME}:/var/lib/anon/control"),
        ANON_IMAGE,
    ]);
    docker_ok(&[
        "network",
        "connect",
        "--ip",
        ANON_EGRESS_IP,
        EGRESS_NET,
        ANON_CONTAINER,
    ]);
    docker_ok(&["start", ANON_CONTAINER]);
    wait_for_log_line(ANON_CONTAINER, "Bootstrapped 100%", Duration::from_secs(90));

    // ── The shim, told the real anonrc's own addresses ──────────────────────
    docker_ok(&[
        "run",
        "-d",
        "--name",
        SHIM_CONTAINER,
        "--network",
        EGRESS_NET,
        "--ip",
        SHIM_EGRESS_IP,
        SHIM_IMAGE,
        "dns-shim",
        "--listen",
        &format!("{SHIM_EGRESS_IP}:53"),
        "--upstream",
        &format!("{ANON_EGRESS_IP}:5353"),
    ]);
    wait_for_log_line(SHIM_CONTAINER, "dns shim:", Duration::from_secs(15));

    // ── A workload of each libc, on the egress network alone ────────────────
    // No other network: exactly what a hidden lease's workload has, and
    // `--dns` is the shim, exactly what the namespace owner sets it to
    // (docker.rs's `owner_args`/`sidecar_command`, `policy.gateway`).
    docker_ok(&[
        "run",
        "-d",
        "--name",
        ALPINE_CONTAINER,
        "--network",
        EGRESS_NET,
        "--dns",
        SHIM_EGRESS_IP,
        "alpine:3.20",
        "sleep",
        "120",
    ]);
    docker_ok(&[
        "run",
        "-d",
        "--name",
        DEBIAN_CONTAINER,
        "--network",
        EGRESS_NET,
        "--dns",
        SHIM_EGRESS_IP,
        "debian:bookworm-slim",
        "sleep",
        "120",
    ]);

    for (container, libc) in [(ALPINE_CONTAINER, "musl"), (DEBIAN_CONTAINER, "glibc")] {
        // A real circuit through Anyone, built fresh by this test's own
        // daemon, is not always as quick as a resolver's own patience (a
        // handful of seconds); retried rather than given one shot, so this
        // test tells apart "the fix does not work" from "the network was
        // slow this time" — the same distinction `wait_for_route` draws for
        // Docker's own network setup elsewhere in this crate.
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut out = run(
            "docker",
            &["exec", container, "getent", "hosts", "example.com"],
        );
        while !out.status.success() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_secs(3));
            out = run(
                "docker",
                &["exec", container, "getent", "hosts", "example.com"],
            );
        }
        assert!(
            out.status.success(),
            "getent hosts example.com failed on {libc} ({container}) within 60s: {}\nstdout: {}\n\
             anon logs:\n{}\nshim logs:\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(
                &run("docker", &["logs", "--tail", "30", ANON_CONTAINER]).stdout
            ),
            String::from_utf8_lossy(&run("docker", &["logs", SHIM_CONTAINER]).stdout),
        );
        let answer = String::from_utf8_lossy(&out.stdout);
        assert!(
            answer.contains("example.com"),
            "{libc} ({container}) answered {answer:?}, not a name resolved to an address"
        );
    }
}
