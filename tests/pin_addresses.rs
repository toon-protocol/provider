//! `deploy/pin-addresses.sh`: a container the compose file pins to an
//! `ipv4_address` is really at that address after an apply.
//!
//! Found upgrading the workstation hidden box to TOON_Network#181's overlay
//! (Docker Compose 5.5.1): when a network's own config changes (there,
//! `internal: true`), `up -d` removes the network, recreates it, and
//! reconnects every container that was on it WITHOUT its `ipv4_address`.
//! A container whose own config did not change is not recreated, so it
//! keeps running at an address from the pool, and every later `up -d`
//! leaves it there. On a hidden box that container is `anon`: it cannot bind
//! 172.30.2.2:9050, aborts, and restarts forever, and nothing else starts.
//!
//! The first two tests run the real script with `docker` stubbed on PATH, the
//! way `tests/auto_apply.rs` does. The third, `#[ignore]`d, is the bug
//! itself against a real daemon: a scratch project, the network flipped to
//! `internal`, the address lost, and the script putting it back.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn deploy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy")
}

/// `docker`, as far as pin-addresses.sh touches it. `inspect` answers the
/// container's networks from `STUB_NETWORKS_<service>`.
const DOCKER_STUB: &str = r#"#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
if [ "${1:-}" = compose ]; then
  shift
  rest="$*"
  case "$rest" in
    "config --format json") printf '%s' "$STUB_CONFIG_JSON"; exit 0 ;;
    "ps -q "*) svc=${rest#ps -q }; echo "cid-$svc"; exit 0 ;;
    "up -d --force-recreate --no-deps "*) exit 0 ;;
  esac
  echo "stub docker: unexpected compose call: $rest" >&2
  exit 97
fi
if [ "${1:-}" = inspect ]; then
  svc=${@: -1}; svc=${svc#cid-}
  var="STUB_NETWORKS_${svc//-/_}"
  printf '%s' "${!var}"
  exit 0
fi
echo "stub docker: unexpected call: $*" >&2
exit 97
"#;

/// The shape of the hidden overlay's resolved model: `anon` pinned on two
/// networks (one of them named apart from its compose key), the connector
/// pinned on one, and the provider pinned on none.
const CONFIG_JSON: &str = r#"{
  "services": {
    "anon": {"networks": {"default": null, "hidden": {"ipv4_address": "172.30.2.2"}, "hidden-egress": {"ipv4_address": "10.204.0.2"}}},
    "provider-connector": {"networks": {"hidden": {"ipv4_address": "172.30.2.3"}}},
    "provider": {"networks": {"hidden": {}}}
  },
  "networks": {
    "default": {"name": "box_default"},
    "hidden": {"name": "toon-provider-hidden", "internal": true},
    "hidden-egress": {"name": "toon-provider-hidden-egress", "internal": true}
  }
}"#;

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
    calls: String,
}

fn run_stubbed(anon_networks: &str) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    fs::write(&docker, DOCKER_STUB).unwrap();
    let mut perms = fs::metadata(&docker).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(&docker, perms).unwrap();
    let log = dir.path().join("calls");
    fs::write(&log, "").unwrap();

    let out = Command::new("bash")
        .arg(deploy_dir().join("pin-addresses.sh"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                dir.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("STUB_LOG", &log)
        .env("STUB_CONFIG_JSON", CONFIG_JSON)
        .env("STUB_NETWORKS_anon", anon_networks)
        .env(
            "STUB_NETWORKS_provider_connector",
            r#"{"toon-provider-hidden":{"IPAddress":"172.30.2.3"}}"#,
        )
        .output()
        .expect("run deploy/pin-addresses.sh");
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        calls: fs::read_to_string(&log).unwrap(),
    }
}

#[test]
fn a_container_off_its_pinned_address_is_recreated_alone() {
    // What the live box showed: anon back on the recreated hidden network at
    // a pool address, still right on the network that did not change.
    let run = run_stubbed(
        r#"{"box_default":{"IPAddress":"172.20.0.2"},"toon-provider-hidden":{"IPAddress":"172.30.2.130"},"toon-provider-hidden-egress":{"IPAddress":"10.204.0.2"}}"#,
    );
    assert_eq!(
        run.status, 0,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    let recreates: Vec<&str> = run
        .calls
        .lines()
        .filter(|l| l.starts_with("compose up"))
        .collect();
    assert_eq!(
        recreates,
        ["compose up -d --force-recreate --no-deps anon"],
        "calls:\n{}",
        run.calls
    );
    assert!(
        run.stdout.contains("anon") && run.stdout.contains("172.30.2.130"),
        "the script does not say which service drifted, and where to:\n{}",
        run.stdout
    );
}

#[test]
fn a_box_where_every_pinned_address_holds_recreates_nothing() {
    let run = run_stubbed(
        r#"{"box_default":{"IPAddress":"172.20.0.2"},"toon-provider-hidden":{"IPAddress":"172.30.2.2"},"toon-provider-hidden-egress":{"IPAddress":"10.204.0.2"}}"#,
    );
    assert_eq!(
        run.status, 0,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert!(
        !run.calls.contains("compose up"),
        "recreated a service that sits at its pinned address:\n{}",
        run.calls
    );
}

fn docker(args: &[&str], cwd: &Path) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("docker {args:?}: {e}"))
}

fn scratch_compose(internal: bool) -> String {
    format!(
        r#"name: toon-test-pin-addresses
services:
  pinned:
    image: alpine:3.20
    command: sleep 1d
    networks:
      default: {{}}
      net: {{ipv4_address: 172.31.199.2}}
  unpinned:
    image: alpine:3.20
    command: sleep 1d
    networks: [net]
networks:
  net:
    name: toon-test-pin-addresses-net
    internal: {internal}
    ipam:
      config: [{{subnet: 172.31.199.0/24, ip_range: 172.31.199.128/25}}]
"#
    )
}

struct Down<'a>(&'a Path);
impl Drop for Down<'_> {
    fn drop(&mut self) {
        let _ = docker(&["compose", "down", "--timeout", "1"], self.0);
    }
}

#[test]
#[ignore = "needs a Docker daemon; run with --ignored"]
fn a_network_recreated_under_a_running_container_loses_its_address_and_the_script_puts_it_back() {
    let dir = tempfile::tempdir().unwrap();
    fs::copy(
        deploy_dir().join("pin-addresses.sh"),
        dir.path().join("pin-addresses.sh"),
    )
    .unwrap();
    let compose = dir.path().join("compose.yml");
    fs::write(&compose, scratch_compose(false)).unwrap();
    let _down = Down(dir.path());

    let address = |dir: &Path| {
        let out = docker(
            &[
                "inspect",
                "toon-test-pin-addresses-pinned-1",
                "--format",
                r#"{{(index .NetworkSettings.Networks "toon-test-pin-addresses-net").IPAddress}}"#,
            ],
            dir,
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    assert!(docker(&["compose", "up", "-d"], dir.path())
        .status
        .success());
    assert_eq!(address(dir.path()), "172.31.199.2");

    // The upgrade: only the network changes.
    fs::write(&compose, scratch_compose(true)).unwrap();
    assert!(docker(&["compose", "up", "-d"], dir.path())
        .status
        .success());
    let lost = address(dir.path());
    assert_ne!(
        lost, "172.31.199.2",
        "compose kept the pinned address across a network recreate; the bug this \
         script works around may be fixed upstream"
    );

    let out = Command::new("bash")
        .arg("pin-addresses.sh")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(address(dir.path()), "172.31.199.2");
}
