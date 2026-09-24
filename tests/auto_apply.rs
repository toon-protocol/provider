//! `deploy/auto-apply.sh`, run for real -- against a real git remote and a
//! real box checkout, with `docker` and `curl` stubbed on PATH so the box
//! never needs a live daemon or a live provider to prove what THIS script
//! does with what they answer. `render.sh` itself is real, and its one
//! network-shaped step (`toon-provider routes`) runs the real binary this
//! crate just built (`TOON_PROVIDER_BIN`), the same way deploy_bundle.rs's
//! fixtures do -- so no docker is needed there either.
//!
//! TOON_Network#160: a render (or apply) failure after a fast-forward used to
//! be invisible on the NEXT run -- `git fetch` brought back nothing new, so
//! "LOCAL = REMOTE" alone read as "nothing to do", and the box sat on the new
//! commit with the OLD rendered config and containers, reporting success
//! forever. `deploy/.applied` (gitignored) is the fix: it names the last
//! commit a run actually finished applying AND verifying, written only at the
//! very end, so the NEXT run compares HEAD to that -- not to what fetch just
//! brought back -- and retries, and reports, the exact same failure on every
//! run until it is fixed.
//!
//! The first test is the fixture the issue asks for: a render that fails once
//! after a fast-forward (a newly-required .env variable, the exact shape of
//! TOON_Network#152's own change), retried and reported loudly by the very
//! next run even though that run's fetch brings back nothing new, and finally
//! applied once the variable is added. The second covers the box that has
//! never written `.applied` at all.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn deploy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy")
}

fn read(name: &str) -> String {
    let path = deploy_dir().join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn run_ok(cmd: &str, args: &[&str], cwd: &Path) -> Output {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("spawning {cmd} {args:?} in {}: {e}", cwd.display()));
    assert!(
        out.status.success(),
        "{cmd} {args:?} in {}:\n{}",
        cwd.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn git(args: &[&str], cwd: &Path) -> String {
    String::from_utf8(run_ok("git", args, cwd).stdout).unwrap()
}

fn commit_all(dir: &Path, message: &str) -> String {
    run_ok("git", &["add", "-A"], dir);
    run_ok(
        "git",
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            message,
        ],
        dir,
    );
    git(&["rev-parse", "HEAD"], dir).trim().to_string()
}

fn head_sha(dir: &Path) -> String {
    git(&["rev-parse", "HEAD"], dir).trim().to_string()
}

/// A repository shaped like the real one: `deploy/` under the repo root,
/// since that is what auto-apply.sh's own `dirname "$0")/..` assumes.
fn fresh_origin() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let deploy = dir.path().join("deploy");
    fs::create_dir(&deploy).unwrap();
    for name in [
        "render.sh",
        "pull-images.sh",
        "auto-apply.sh",
        "provider.toml.template",
        "connector.toml.template",
        "listings.example.toml",
        ".env.example",
        ".gitignore",
        "docker-compose.yml",
        "toon-provider-check.service",
        "toon-provider-check.timer",
    ] {
        fs::copy(deploy_dir().join(name), deploy.join(name))
            .unwrap_or_else(|e| panic!("copying {name}: {e}"));
    }
    fs::create_dir(deploy.join("nginx")).unwrap();
    fs::copy(
        deploy_dir().join("nginx/node.conf.template"),
        deploy.join("nginx/node.conf.template"),
    )
    .unwrap();
    for name in ["render.sh", "pull-images.sh", "auto-apply.sh"] {
        let path = deploy.join(name);
        let mut perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&path, perms).unwrap();
    }
    run_ok("git", &["init", "--quiet", "-b", "main"], dir.path());
    let sha = commit_all(dir.path(), "bundle");
    (dir, sha)
}

fn clone_box(origin: &Path) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    // `git clone` refuses to clone into an existing (even empty) directory
    // that TempDir already created without `--` trickery on some git
    // versions, so clone into a child path instead.
    let target = dir.path().join("box");
    run_ok(
        "git",
        &[
            "clone",
            "--quiet",
            origin.to_str().unwrap(),
            target.to_str().unwrap(),
        ],
        dir.path(),
    );
    dir
}

fn box_dir(handle: &tempfile::TempDir) -> PathBuf {
    handle.path().join("box")
}

/// A commit that adds a newly-required .env variable to render.sh -- the
/// exact shape of the regression TOON_Network#152 found: a fast-forward whose
/// render needs something the box's own .env does not have.
fn add_fixture_required_var(origin: &Path) -> String {
    let path = origin.join("deploy/render.sh");
    let before = fs::read_to_string(&path).unwrap();
    let marker = "set -a; . ./.env; set +a\n";
    assert!(
        before.contains(marker),
        "render.sh no longer sources .env the expected way"
    );
    let after = before.replacen(
        marker,
        &format!(
            "{marker}\n: \"${{PROVIDER_FIXTURE_FLAG:?set PROVIDER_FIXTURE_FLAG in .env (deploy/.env.example lists every required variable; this one is a TOON_Network#160 test fixture)}}\"\n"
        ),
        1,
    );
    fs::write(&path, after).unwrap();
    commit_all(origin, "render.sh now needs PROVIDER_FIXTURE_FLAG")
}

/// `.env` as an operator writes it: `.env.example` with these lines appended
/// -- later lines win when the shell sources it, exactly like deploy_bundle.rs's
/// own fixtures.
fn write_env(dir: &Path, env: &BTreeMap<&str, &str>) {
    let mut dotenv = read(".env.example");
    dotenv.push_str("\n# ── appended by tests/auto_apply.rs ──\n");
    for (name, value) in env {
        dotenv.push_str(&format!("{name}='{value}'\n"));
    }
    fs::write(dir.join("deploy/.env"), dotenv).unwrap();
    fs::copy(
        dir.join("deploy/listings.example.toml"),
        dir.join("deploy/listings.toml"),
    )
    .unwrap();
}

fn base_env() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("PROVIDER_NAME", "Fixture Provider"),
        ("DOMAIN", "fixture.example"),
        ("PUBLIC_IP", "203.0.113.9"),
        ("NOSTR_PRIVATE_KEY", "1111111111111111111111111111111111111111111111111111111111111111"),
        ("ILP_ADDRESS", "g.fixture.provider"),
        (
            "CONNECTOR_SEAL_KEY",
            "0x04325b06f4bcb438204ab86a36a715fdf409552da5cdc7cd28301b08088ce7c3a1bf4289f62ba89a707ed8d7db66b03cb2881ea5934e35f2d600c4cd7067ed0188",
        ),
        ("OPERATOR_BEARER_TOKEN", "2222222222222222222222222222222222222222222222222222222222222222"),
        ("OPERATOR_WRITE_KEY", "3333333333333333333333333333333333333333333333333333333333333333"),
    ])
}

// ── The stubbed world: docker and curl on PATH ──────────────────────────────
// The same technique the gateway repo's deploy/auto-apply.test.mjs uses,
// extended for the third service (directory-publisher) and for
// pull-images.sh's extra `compose config --format json` | jq probe (which
// asks whether a service has a `build:` -- true only for the hidden bundle's
// `anon`, which this fixture never runs).
const DOCKER_STUB: &str = r#"#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
if [ "${1:-}" = compose ]; then
  shift
  if [ "${1:-}" = -f ]; then shift 2; fi
  rest="$*"
  case "$rest" in
    "config --services") printf '%s\n' $STUB_SERVICES; exit 0 ;;
    "config --format json") printf '%s' "$STUB_CONFIG_JSON"; exit 0 ;;
    "config --images "*)
      svc=${rest#config --images }
      var="STUB_IMAGE_${svc//-/_}"
      echo "${!var}"
      exit 0
      ;;
    "pull --quiet "*) exit "${STUB_PULL_EXIT:-0}" ;;
    "build --quiet "*) exit 0 ;;
    "up -d") exit "${STUB_UP_EXIT:-0}" ;;
    "ps -q "*) svc=${rest#ps -q }; echo "cid-$svc"; exit 0 ;;
    "restart "*) exit "${STUB_RESTART_EXIT:-0}" ;;
    "logs --tail 40 "*) exit 0 ;;
    "exec -T nginx nginx -s reload") exit "${STUB_NGINX_RELOAD_EXIT:-0}" ;;
  esac
  echo "stub docker: unexpected compose call: $rest" >&2
  exit 97
fi
if [ "${1:-}" = build ]; then exit 0; fi
if [ "${1:-}" = inspect ]; then echo "${STUB_HEALTH:-healthy}"; exit 0; fi
echo "stub docker: unexpected call: $*" >&2
exit 97
"#;

const CURL_STUB: &str = r#"#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  http://127.0.0.1:*/ilp)
    addr=$(sed -n '/^\[node\]/,/^\[/s/^[[:space:]]*addresses[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p' connector.toml | head -n1)
    printf '{"ilpAddresses":[%s]}\n' "$addr"
    exit 0
    ;;
esac
echo "stub curl: unexpected call: $*" >&2
exit 7
"#;

/// systemd, as far as auto-apply.sh touches it: every call logged, every
/// call succeeding.
const SYSTEMCTL_STUB: &str = r#"#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_LOG"
exit 0
"#;

fn stub_bin() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, content) in [
        ("docker", DOCKER_STUB),
        ("curl", CURL_STUB),
        ("systemctl", SYSTEMCTL_STUB),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&path, perms).unwrap();
    }
    dir
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
    calls: String,
}

fn auto_apply(handle: &tempfile::TempDir, stub: &Path, run_id: usize) -> Run {
    // An empty unit directory: a box bootstrap.sh never set up, so nothing
    // is installed into it — and never the real /etc/systemd/system.
    let units = box_dir(handle).join("no-systemd");
    fs::create_dir_all(&units).unwrap();
    auto_apply_with_units(handle, stub, run_id, &units)
}

fn auto_apply_with_units(
    handle: &tempfile::TempDir,
    stub: &Path,
    run_id: usize,
    systemd_dir: &Path,
) -> Run {
    let dir = box_dir(handle);
    let log = dir.join(format!("stub-log-{run_id}"));
    fs::write(&log, "").unwrap();
    // The images the scripts read, from the resolved model, the way
    // `docker compose config --format json` answers them.
    let config_json = r#"{"services":{"provider":{"image":"ghcr.io/toon-protocol/provider:sha-0000000"},"provider-connector":{"image":"ghcr.io/toon-protocol/connector:rust-2026.09.11.1"},"directory-publisher":{"image":"ghcr.io/toon-protocol/directory-publisher:sha-0000000"},"nginx":{"image":"nginx:alpine"}}}"#;
    let out = Command::new("bash")
        .arg(dir.join("deploy/auto-apply.sh"))
        .env_clear()
        .env(
            "PATH",
            format!(
                "{}:{}",
                stub.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("TOON_PROVIDER_BIN", env!("CARGO_BIN_EXE_toon-provider"))
        .env("TOON_AUTOAPPLY_LOCK", dir.join(".autoapply.lock"))
        .env("TOON_SYSTEMD_DIR", systemd_dir)
        .env("STUB_LOG", &log)
        .env(
            "STUB_SERVICES",
            "provider provider-connector directory-publisher nginx",
        )
        .env("STUB_CONFIG_JSON", config_json)
        // What real compose answers for `config --images provider` once
        // provider depends_on the publisher: BOTH images, one per line. A
        // script that still asks it this way hands `docker` two references
        // (the live box's render failed exactly so after TOON_Network#178).
        .env(
            "STUB_IMAGE_provider",
            "ghcr.io/toon-protocol/provider:sha-0000000\nghcr.io/toon-protocol/directory-publisher:sha-0000000",
        )
        .env(
            "STUB_IMAGE_provider_connector",
            "ghcr.io/toon-protocol/connector:rust-2026.09.11.1",
        )
        .env(
            "STUB_IMAGE_directory_publisher",
            "ghcr.io/toon-protocol/directory-publisher:sha-0000000",
        )
        .env("STUB_IMAGE_nginx", "nginx:alpine")
        .output()
        .expect("run deploy/auto-apply.sh");
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        calls: fs::read_to_string(&log).unwrap_or_default(),
    }
}

fn applied(handle: &tempfile::TempDir) -> Option<String> {
    fs::read_to_string(box_dir(handle).join("deploy/.applied"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[test]
fn a_render_that_fails_once_after_a_fast_forward_is_retried_until_env_is_fixed() {
    let (origin, origin_sha) = fresh_origin();
    let stub = stub_bin();
    let box_handle = clone_box(origin.path());
    write_env(&box_dir(&box_handle), &base_env());

    // Run 1: the box is already on the only commit there is, and has never
    // written .applied. Treated as needing an apply (the safer of the two
    // readings), and it succeeds.
    let first = auto_apply(&box_handle, stub.path(), 0);
    assert_eq!(
        first.status, 0,
        "run 1 (no .applied yet) should apply cleanly:\n{}\n{}",
        first.stdout, first.stderr
    );
    assert_eq!(applied(&box_handle).as_deref(), Some(origin_sha.as_str()));

    // The bundle moves on: render.sh now needs a variable this box's .env
    // does not have -- exactly TOON_Network#152's shape of regression.
    let broken_sha = add_fixture_required_var(origin.path());

    // Run 2: the fetch brings back real work, the fast-forward succeeds, and
    // render.sh fails on the missing variable.
    let second = auto_apply(&box_handle, stub.path(), 1);
    assert_ne!(second.status, 0, "a render failure must fail the apply");
    assert_eq!(
        head_sha(&box_dir(&box_handle)),
        broken_sha,
        "the fast-forward still happens; only the render fails"
    );
    assert!(
        second.stderr.contains("PROVIDER_FIXTURE_FLAG"),
        "render.sh's own message must name the missing variable:\n{}",
        second.stderr
    );
    assert!(
        second.stderr.contains("FAILED: render.sh"),
        "{}",
        second.stderr
    );
    assert!(
        second.stderr.to_lowercase().contains(".env.example"),
        "it must point at .env.example:\n{}",
        second.stderr
    );
    assert_eq!(
        applied(&box_handle).as_deref(),
        Some(origin_sha.as_str()),
        ".applied must still name the last commit that DID apply"
    );

    // Run 3: nothing new to fetch (the box is already on the broken commit),
    // but HEAD still disagrees with .applied. Before TOON_Network#160 this
    // read as "nothing to do" and exited 0 silently; now it must retry, and
    // fail the same way, every time.
    let third = auto_apply(&box_handle, stub.path(), 2);
    assert_ne!(
        third.status, 0,
        "the SAME failure must be reported again on a fetch that brings back nothing new"
    );
    assert!(
        third.stdout.contains("retrying"),
        "it should say it is retrying, not applying something new:\n{}",
        third.stdout
    );
    assert!(third.stderr.contains("PROVIDER_FIXTURE_FLAG"));
    assert_eq!(
        applied(&box_handle).as_deref(),
        Some(origin_sha.as_str()),
        "still untouched after a second failed run"
    );

    // The operator fixes it exactly as the message says: add the variable to
    // their own .env.
    let mut fixed_env = base_env();
    fixed_env.insert("PROVIDER_FIXTURE_FLAG", "ok");
    write_env(&box_dir(&box_handle), &fixed_env);

    // Run 4: same commit, same "nothing to fetch" situation as run 3, but now
    // it applies -- because .applied still disagreed with HEAD, this run was
    // never going to be skipped.
    let fourth = auto_apply(&box_handle, stub.path(), 3);
    assert_eq!(
        fourth.status, 0,
        "run 4 (fixed .env) should apply cleanly:\n{}\n{}",
        fourth.stdout, fourth.stderr
    );
    assert!(fourth.stdout.contains("applied"), "{}", fourth.stdout);
    assert_eq!(
        applied(&box_handle).as_deref(),
        Some(broken_sha.as_str()),
        ".applied now names the commit that finally succeeded"
    );

    // Run 5: fully quiescent. Nothing to fetch, and .applied already agrees
    // with HEAD -- back to the quiet, common case, with no docker call at all.
    let fifth = auto_apply(&box_handle, stub.path(), 4);
    assert_eq!(fifth.status, 0);
    assert_eq!(
        fifth.calls, "",
        "a fully-applied box calls docker for nothing"
    );
}

#[test]
fn a_box_with_no_applied_file_treats_it_as_needing_an_apply() {
    let (origin, origin_sha) = fresh_origin();
    let stub = stub_bin();
    let box_handle = clone_box(origin.path());
    write_env(&box_dir(&box_handle), &base_env());

    assert_eq!(
        applied(&box_handle),
        None,
        "a fresh clone has never written .applied"
    );

    let result = auto_apply(&box_handle, stub.path(), 0);
    assert_eq!(result.status, 0, "{}\n{}", result.stdout, result.stderr);
    assert_eq!(
        applied(&box_handle).as_deref(),
        Some(origin_sha.as_str()),
        "the first run writes .applied once the apply is verified healthy"
    );
    assert!(
        result.calls.contains("ps -q provider"),
        "it actually ran the apply, not a silent no-op:\n{}",
        result.calls
    );
}

/// TOON_Network#172: a box bootstrapped before the check timer existed gets
/// it from its next apply, and one whose units are current is left alone.
#[test]
fn an_apply_installs_the_check_timer_on_a_bootstrapped_box() {
    let (origin, _) = fresh_origin();
    let stub = stub_bin();
    let box_handle = clone_box(origin.path());
    write_env(&box_dir(&box_handle), &base_env());

    // What bootstrap.sh left: its auto-apply units, and no check units.
    let units = tempfile::tempdir().unwrap();
    fs::write(units.path().join("toon-auto-apply.timer"), "[Timer]\n").unwrap();

    let first = auto_apply_with_units(&box_handle, stub.path(), 0, units.path());
    assert_eq!(first.status, 0, "{}\n{}", first.stdout, first.stderr);
    for unit in ["toon-provider-check.service", "toon-provider-check.timer"] {
        assert_eq!(
            fs::read_to_string(units.path().join(unit)).unwrap(),
            read(unit),
            "{unit} is installed as committed"
        );
    }
    assert!(
        first
            .calls
            .contains("systemctl enable --now toon-provider-check.timer"),
        "{}",
        first.calls
    );
    assert!(first
        .stdout
        .contains("installed the toon-provider-check timer"));

    // Already current: nothing to install, and systemd is not touched. (A
    // new commit makes the run do real work; .applied would otherwise skip
    // it before this step.)
    fs::write(origin.path().join("deploy/README.md"), "moved on\n").unwrap();
    commit_all(origin.path(), "an unrelated change");
    let second = auto_apply_with_units(&box_handle, stub.path(), 1, units.path());
    assert_eq!(second.status, 0, "{}\n{}", second.stdout, second.stderr);
    assert!(
        !second.calls.contains("systemctl"),
        "current units are left alone:\n{}",
        second.calls
    );
}

#[test]
fn an_apply_installs_no_unit_on_a_box_bootstrap_did_not_set_up() {
    let (origin, _) = fresh_origin();
    let stub = stub_bin();
    let box_handle = clone_box(origin.path());
    write_env(&box_dir(&box_handle), &base_env());
    let units = tempfile::tempdir().unwrap();

    let run = auto_apply_with_units(&box_handle, stub.path(), 0, units.path());
    assert_eq!(run.status, 0, "{}\n{}", run.stdout, run.stderr);
    assert!(!units.path().join("toon-provider-check.timer").exists());
    assert!(!run.calls.contains("systemctl"), "{}", run.calls);
}
