//! `deploy/init-letsencrypt.sh`, run for real -- against a stub `docker` (the
//! same technique `auto_apply.rs` uses, extended to answer for the `certbot`
//! container) and a stub `getent` (so the pre-issue DNS check is
//! deterministic and needs no real network or root).
//!
//! TOON_Network#163: a failed certificate used to be a `::warning::` this
//! script swallowed -- `bootstrap.sh` carried on and printed "provider box
//! up." on a box serving no valid certificate, the half-configured state the
//! bundle's own README calls worse than one that refused to start. Now:
//!   * issuance failure exits non-zero, naming the A-record as the likely
//!     cause (HTTP-01's own failure mode);
//!   * a pre-issue check warns (never blocks -- certbot's own attempt is the
//!     real test) when either A-record does not resolve to `PUBLIC_IP` yet;
//!   * an existing, still-valid certificate is reused without going near
//!     either of the above, so the devnet box's idempotent re-runs stay
//!     green.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn deploy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy")
}

fn write_exec(path: &Path, content: &str) {
    fs::write(path, content).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    let mut perms = fs::metadata(path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(path, perms).unwrap();
}

const DOMAIN: &str = "fixture.example";
const PUBLIC_IP: &str = "203.0.113.9";

fn base_env() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("DOMAIN", DOMAIN),
        ("PUBLIC_IP", PUBLIC_IP),
        ("LETSENCRYPT_EMAIL", "ops@fixture.example"),
        ("LETSENCRYPT_STAGING", "1"),
    ])
}

/// A `docker` that answers the three shapes of `compose run --rm --entrypoint
/// sh certbot -c "<script>"` this script makes (matched by a marker unique to
/// each), plus the certonly request and the ordinary compose calls around it.
const DOCKER_STUB: &str = r#"#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
if [ "${1:-}" = compose ]; then
  shift
  case "$1 $2 $3" in
    "up -d nginx") exit 0 ;;
    "exec nginx nginx") exit "${STUB_RELOAD_EXIT:-0}" ;;
  esac
  if [ "$1 $2 $3 $4" = "run --rm --entrypoint sh" ]; then
    script="${@: -1}"
    case "$script" in
      *checkend*) printf '%s' "${STUB_EXISTING_CERT_OK:-}"; exit 0 ;;
      *"openssl req -x509"*) exit 0 ;;
      *"rm -rf /etc/letsencrypt"*) exit 0 ;;
    esac
    echo "stub docker: unexpected certbot -c script: $script" >&2
    exit 97
  fi
  if [ "$1 $2 $3 $4" = "run --rm --entrypoint certbot" ]; then
    exit "${STUB_CERTONLY_EXIT:-0}"
  fi
  echo "stub docker: unexpected compose call: $*" >&2
  exit 97
fi
echo "stub docker: unexpected call: $*" >&2
exit 97
"#;

/// A `getent ahostsv4 <name>` that answers from `STUB_RESOLVE_<name, dots and
/// dashes as underscores>`, or nothing (NXDOMAIN-shaped: no stdout, exit 2)
/// when unset -- exactly `getent`'s real behaviour for a name that does not
/// resolve.
const GETENT_STUB: &str = r#"#!/usr/bin/env bash
if [ "${1:-}" = ahostsv4 ]; then
  key="STUB_RESOLVE_$(printf '%s' "$2" | tr '.-' '__')"
  ip="${!key:-}"
  if [ -n "$ip" ]; then printf '%s STREAM %s\n' "$ip" "$2"; exit 0; fi
  exit 2
fi
echo "stub getent: unexpected call: $*" >&2
exit 97
"#;

fn stub_bin() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write_exec(&dir.path().join("docker"), DOCKER_STUB);
    write_exec(&dir.path().join("getent"), GETENT_STUB);
    dir
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
    calls: Vec<String>,
}

#[derive(Default)]
struct Opts<'a> {
    env: BTreeMap<&'a str, &'a str>,
    existing_cert_ok: &'a str,
    certonly_exit: i32,
    resolve: BTreeMap<String, &'a str>,
}

fn init_letsencrypt(opts: Opts) -> Run {
    let stub = stub_bin();
    let dir = tempfile::tempdir().expect("tempdir");
    fs::copy(
        deploy_dir().join("init-letsencrypt.sh"),
        dir.path().join("init-letsencrypt.sh"),
    )
    .unwrap();
    let mut perms = fs::metadata(dir.path().join("init-letsencrypt.sh"))
        .unwrap()
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(dir.path().join("init-letsencrypt.sh"), perms).unwrap();

    let mut env = base_env();
    for (k, v) in &opts.env {
        env.insert(k, v);
    }
    let dotenv: String = env
        .iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect::<Vec<_>>()
        .join("");
    fs::write(dir.path().join(".env"), dotenv).unwrap();

    let log = dir.path().join("stub-log");
    fs::write(&log, "").unwrap();

    let mut cmd = Command::new("bash");
    cmd.arg("./init-letsencrypt.sh")
        .current_dir(dir.path())
        .env_clear()
        .env(
            "PATH",
            format!(
                "{}:{}",
                stub.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("STUB_LOG", &log)
        .env("STUB_EXISTING_CERT_OK", opts.existing_cert_ok)
        .env("STUB_CERTONLY_EXIT", opts.certonly_exit.to_string());
    for (name, ip) in &opts.resolve {
        let key = format!("STUB_RESOLVE_{}", name.replace(['.', '-'], "_"));
        cmd.env(key, ip);
    }
    let out = cmd.output().expect("run deploy/init-letsencrypt.sh");
    let calls = fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect();
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        calls,
    }
}

#[test]
fn reuses_an_existing_valid_certificate_without_the_dns_check_or_issuing() {
    let r = init_letsencrypt(Opts {
        existing_cert_ok: "ok",
        ..Default::default()
    });
    assert_eq!(r.status, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(
        !r.stdout.contains("::warning::"),
        "reuse must not run the pre-issue DNS check:\n{}",
        r.stdout
    );
    assert!(
        !r.calls
            .iter()
            .any(|c| c.starts_with("compose run --rm --entrypoint certbot")),
        "reuse must never call certonly -- this is what keeps the devnet box's idempotent re-runs green"
    );
}

#[test]
fn issues_cleanly_with_no_warning_when_both_a_records_resolve_here() {
    let r = init_letsencrypt(Opts {
        resolve: BTreeMap::from([
            (format!("proxy.provider.{DOMAIN}"), PUBLIC_IP),
            (format!("provider.{DOMAIN}"), PUBLIC_IP),
        ]),
        ..Default::default()
    });
    assert_eq!(r.status, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(!r.stdout.contains("::warning::"), "{}", r.stdout);
    assert!(r.stdout.contains("Done."));
}

#[test]
fn warns_but_still_issues_when_neither_a_record_resolves_yet() {
    let r = init_letsencrypt(Opts::default());
    assert_eq!(r.status, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout
            .contains(&format!("proxy.provider.{DOMAIN} does not resolve")),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains(&format!("provider.{DOMAIN} does not resolve")),
        "{}",
        r.stdout
    );
    assert!(
        r.calls
            .iter()
            .any(|c| c.starts_with("compose run --rm --entrypoint certbot")),
        "a DNS warning must not block issuance"
    );
}

#[test]
fn warns_when_an_a_record_points_somewhere_else() {
    let r = init_letsencrypt(Opts {
        resolve: BTreeMap::from([(format!("proxy.provider.{DOMAIN}"), "198.51.100.1")]),
        ..Default::default()
    });
    assert_eq!(r.status, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout
            .contains(&format!("proxy.provider.{DOMAIN} resolves to 198.51.100.1")),
        "{}",
        r.stdout
    );
}

#[test]
fn exits_non_zero_naming_the_a_record_when_issuance_fails_and_still_reseeds_a_dummy() {
    let r = init_letsencrypt(Opts {
        certonly_exit: 1,
        ..Default::default()
    });
    assert_ne!(r.status, 0, "a failed issuance must fail the script");
    assert!(
        r.stderr.contains("Certificate issuance failed"),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr.contains(PUBLIC_IP),
        "must name this box's PUBLIC_IP as part of the likely cause:\n{}",
        r.stderr
    );
    assert!(
        r.calls
            .iter()
            .any(|c| c.starts_with("compose exec nginx nginx")),
        "nginx must still be reloaded onto the reseeded dummy so it keeps answering"
    );
}

#[test]
fn staging_vs_production_is_unaffected() {
    let r = init_letsencrypt(Opts {
        env: BTreeMap::from([("LETSENCRYPT_STAGING", "0")]),
        ..Default::default()
    });
    assert_eq!(r.status, 0, "{}\n{}", r.stdout, r.stderr);
    let certonly = r
        .calls
        .iter()
        .find(|c| c.starts_with("compose run --rm --entrypoint certbot"))
        .expect("expected a certonly call");
    assert!(
        !certonly.contains("--staging"),
        "a production run must not pass --staging to certbot"
    );
}

#[test]
fn bootstrap_sh_stops_on_a_failed_certificate() {
    let bootstrap = fs::read_to_string(deploy_dir().join("bootstrap.sh")).unwrap();
    assert!(
        bootstrap.contains("! ./init-letsencrypt.sh"),
        "bootstrap.sh must guard the call so a failure is reported by name"
    );
    assert!(bootstrap.to_lowercase().contains("failed: certificate"));
    assert!(bootstrap.contains("init-letsencrypt.sh"));
    // The HIDDEN path must remain untouched: it is an `elif` sibling of the
    // failure guard, not a wrapper around it, so a hidden box never calls
    // init-letsencrypt.sh at all -- TOON_Network#163 must not affect it.
    assert!(
        bootstrap.contains(
            "if [ \"$HIDDEN\" = 1 ]; then\n  echo \"    none: a hidden box has no public name. The address is its own key.\"\nelif ! ./init-letsencrypt.sh; then"
        ),
        "HIDDEN must short-circuit before the certificate guard, unaffected by it:\n{bootstrap}"
    );
}

#[test]
fn hidden_mode_never_calls_init_letsencrypt_sh() {
    // deploy_bundle.rs already renders the HIDDEN=1 preset through the real
    // loader; this only has to confirm bootstrap.sh's own control flow never
    // reaches init-letsencrypt.sh on that path, which the exact-text check
    // above pins structurally. Re-stated here as a dedicated test so a
    // regression on this specific point (not just wording) fails by name.
    let bootstrap = fs::read_to_string(deploy_dir().join("bootstrap.sh")).unwrap();
    let tls_step = bootstrap
        .split("echo \"==> [8/9] TLS\"\n")
        .nth(1)
        .expect("bootstrap.sh must still have a TLS step");
    let tls_step = &tls_step[..tls_step.find("echo \"==> [9/9]").unwrap_or(tls_step.len())];
    assert!(
        tls_step.starts_with("if [ \"$HIDDEN\" = 1 ]; then"),
        "the TLS step must still check HIDDEN first:\n{tls_step}"
    );
    let hidden_branch = tls_step
        .split("elif")
        .next()
        .expect("an if/elif for HIDDEN vs. not");
    assert!(
        !hidden_branch.contains("init-letsencrypt.sh"),
        "the HIDDEN branch itself must not call init-letsencrypt.sh:\n{hidden_branch}"
    );
}
