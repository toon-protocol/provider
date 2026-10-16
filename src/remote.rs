//! `--ssh <user@host>` for `toon-provider status` and `toon-provider dash`
//! (TOON_Network#169, ADR 0029 "Where it runs"): the same report, read from a
//! laptop through the operator's own `ssh`.
//!
//! Nothing new is exposed on the box. The provider's operator port is
//! loopback INSIDE the provider container and the publisher's status port is
//! reachable only on the compose network, so a plain `ssh -L` has nothing to
//! forward to. Instead each local connection is relayed by one `ssh` of its
//! own, running `docker compose exec -T provider bash` in the deploy
//! directory to open the TCP connection from inside the provider container —
//! where `127.0.0.1:8090`, `directory-publisher:8081` and
//! `provider-connector:4000` all answer, exactly as they do to
//! `docker compose exec provider toon-provider status`. The box needs nothing
//! the deploy bundle does not already ship (`bash` and the compose project).
//!
//! Which means the operator's `ssh` and its config are used as they are:
//! host aliases, `-i` identities via `IdentityFile`, `ProxyJump`, an agent.
//! One master connection is opened first (so a passphrase or password is
//! asked once, before `dash` takes over the terminal) and every relay rides
//! it (`ControlPath`), on Unix.
//!
//! **Earnings go over the tunnel**, to the connector's operator API on the
//! compose network, with the bearer token read over SSH from the file the
//! provider container already mounts. The token is held in memory and sent
//! only to that tunnel; nothing is written to the laptop's disk, and the
//! connector's public edge is not asked.
//!
//! The Solana balances are read from the laptop, from the RPC the box's
//! `TOON_SETTLEMENT_SOLANA_RPC_URL` names (or `--settlement-rpc-url`): a
//! public node needs no tunnel. A Hidden Provider's are not read this way
//! (they ride its own node or anon, from the box) and say so.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use url::Url;

use crate::status::{ReportArgs, Secret, Sources, SOURCE_TIMEOUT};

/// Where the deploy bundle lives on the box, relative to the login
/// directory: `bootstrap.sh` clones to `/root/provider`.
pub const DEFAULT_DIR: &str = "provider/deploy";

/// `--ssh`, shared by `status` and `dash`.
#[derive(Debug, Clone, clap::Args)]
pub struct RemoteArgs {
    /// Read the report from a box over SSH instead of from this machine:
    /// `root@<box>`, or a host from `~/.ssh/config`. Opens the tunnels
    /// itself with your own `ssh` and its config; nothing new is exposed on
    /// the box. Needs no provider.toml here.
    #[arg(long, value_name = "USER@HOST")]
    pub ssh: Option<String>,

    /// With `--ssh`: the box's deploy directory (where `docker compose`
    /// runs), relative to the login directory unless absolute.
    #[arg(long, default_value = DEFAULT_DIR, value_name = "DIR", requires = "ssh")]
    pub ssh_dir: String,
}

/// What a box answered, read for `status` and `dash` to run on.
pub struct Link {
    pub sources: Sources,
    /// The connector's operator API, through the tunnel, for `redeem`.
    pub redeem_base: Result<String, String>,
    /// The publisher's `/publish`, through the tunnel, for `topup`.
    pub publish_url: Option<String>,
    /// The box's EVM RPC, for the redeem dialog's gas estimate.
    pub evm_rpc_url: Option<String>,
    _session: Session,
}

/// One ssh connection's worth of state: the master socket and the relays.
/// Dropping it closes both.
struct Session {
    host: String,
    control_dir: Option<PathBuf>,
    tunnels: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        for tunnel in &self.tunnels {
            tunnel.abort();
        }
        if let Some(dir) = &self.control_dir {
            let _ = std::process::Command::new("ssh")
                .args(["-S"])
                .arg(dir.join("s"))
                .args(["-O", "exit", &self.host])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// How `ssh` is run: always the same options, so the probe, the master and
/// every relay agree about the control socket.
#[derive(Clone)]
struct Ssh {
    host: String,
    dir: String,
    control: Option<PathBuf>,
}

impl Ssh {
    fn command(&self) -> Command {
        let mut command = Command::new("ssh");
        command.kill_on_drop(true).args(["-o", "ConnectTimeout=15"]);
        if let Some(dir) = &self.control {
            command
                .args(["-o", "ControlMaster=no", "-S"])
                .arg(dir.join("s"));
        }
        command
    }

    /// `cd <dir> && docker compose exec -T provider <inner>` on the box.
    fn in_provider(&self, inner: &str) -> String {
        format!(
            "cd {} && exec docker compose exec -T provider {inner}",
            sh_quote(&self.dir)
        )
    }
}

/// `'…'` for a POSIX shell.
fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// What the probe reads from inside the provider container: the few
/// environment variables the deploy bundle sets for `status`, the files they
/// name (public addresses and the bearer token), and the non-secret lines of
/// provider.toml — never the file, which holds the Nostr private key. Of
/// those, every table header too, so a key is read in the table it is in
/// (`chain` and `token` of each `[[settlement]]`, in any order).
const PROBE: &str = r#"sh -c '
env | grep -E "^(TOON_CONNECTOR_OPERATOR_URL|TOON_SETTLEMENT_SOLANA_RPC_URL|TOON_SETTLEMENT_EVM_RPC_URL|TOON_PUBLISHER_DEPOSIT|TOON_PROVIDER_CONFIG)="
for v in TOON_CONNECTOR_BEARER_TOKEN_FILE TOON_SETTLEMENT_SOLANA_ADDRESS_FILE TOON_PUBLISHER_SOLANA_ADDRESS_FILE; do
  eval f=\${$v:-}
  if [ -n "$f" ] && [ -r "$f" ]; then printf "@@FILE %s\n" "$v"; cat "$f"; printf "\n"; fi
done
printf "@@CONFIG\n"
c=${TOON_PROVIDER_CONFIG:-/etc/toon-provider/provider.toml}
grep -E "^[[:space:]]*(\[|(hidden|connector_url|publish_url|operator_url|chain|token)[[:space:]]*=)" "$c"
printf "@@END\n"
'"#;

/// What the probe found out about the box.
#[derive(Debug, Default)]
struct Facts {
    operator_connector_url: Option<String>,
    solana_rpc_url: Option<String>,
    evm_rpc_url: Option<String>,
    publisher_deposit: Option<u128>,
    bearer_token: Option<Secret>,
    settlement_address: Option<String>,
    publisher_address: Option<String>,
    hidden: bool,
    connector_url: Option<String>,
    publish_url: Option<String>,
    operator_url: Option<String>,
    solana_token: Option<String>,
}

fn parse_probe(text: &str) -> Facts {
    let mut facts = Facts::default();
    let mut file: Option<&str> = None;
    let mut content = String::new();
    let mut in_config = false;
    // Before the first table header: where `hidden` and the URLs are.
    let mut top_level = true;
    let mut settlement: Option<(Option<String>, Option<String>)> = None;

    fn finish_file(facts: &mut Facts, file: Option<&str>, content: &mut String) {
        let value = content.trim().to_string();
        content.clear();
        if value.is_empty() {
            return;
        }
        match file {
            Some("TOON_CONNECTOR_BEARER_TOKEN_FILE") => facts.bearer_token = Some(Secret(value)),
            Some("TOON_SETTLEMENT_SOLANA_ADDRESS_FILE") => facts.settlement_address = Some(value),
            Some("TOON_PUBLISHER_SOLANA_ADDRESS_FILE") => facts.publisher_address = Some(value),
            _ => {}
        }
    }
    fn close_settlement(facts: &mut Facts, block: &mut Option<(Option<String>, Option<String>)>) {
        if let Some((Some(chain), Some(token))) = block.take() {
            if chain == "solana" || chain.starts_with("solana:") {
                facts.solana_token.get_or_insert(token);
            }
        }
    }

    for line in text.lines() {
        if let Some(name) = line.strip_prefix("@@FILE ") {
            finish_file(&mut facts, file, &mut content);
            file = Some(match name.trim() {
                "TOON_CONNECTOR_BEARER_TOKEN_FILE" => "TOON_CONNECTOR_BEARER_TOKEN_FILE",
                "TOON_SETTLEMENT_SOLANA_ADDRESS_FILE" => "TOON_SETTLEMENT_SOLANA_ADDRESS_FILE",
                "TOON_PUBLISHER_SOLANA_ADDRESS_FILE" => "TOON_PUBLISHER_SOLANA_ADDRESS_FILE",
                _ => "",
            });
            continue;
        }
        if line == "@@CONFIG" {
            finish_file(&mut facts, file, &mut content);
            file = None;
            in_config = true;
            continue;
        }
        if line == "@@END" {
            close_settlement(&mut facts, &mut settlement);
            break;
        }
        if file.is_some() {
            content.push_str(line);
            content.push('\n');
            continue;
        }
        if !in_config {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_string();
            if value.is_empty() {
                continue;
            }
            match name {
                "TOON_CONNECTOR_OPERATOR_URL" => facts.operator_connector_url = Some(value),
                "TOON_SETTLEMENT_SOLANA_RPC_URL" => facts.solana_rpc_url = Some(value),
                "TOON_SETTLEMENT_EVM_RPC_URL" => facts.evm_rpc_url = Some(value),
                "TOON_PUBLISHER_DEPOSIT" => facts.publisher_deposit = value.parse().ok(),
                _ => {}
            }
            continue;
        }
        let line = line.trim();
        if line.starts_with('[') {
            close_settlement(&mut facts, &mut settlement);
            top_level = false;
            if line.split('#').next().map(str::trim) == Some("[[settlement]]") {
                settlement = Some((None, None));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), toml_scalar(value));
        match (key, &mut settlement) {
            ("chain", Some((chain, _))) => *chain = Some(value),
            ("token", Some((_, token))) => *token = Some(value),
            ("hidden", None) if top_level => facts.hidden = value == "true",
            ("connector_url", None) if top_level => facts.connector_url = Some(value),
            ("publish_url", None) if top_level => facts.publish_url = Some(value),
            ("operator_url", None) if top_level => facts.operator_url = Some(value),
            _ => {}
        }
    }
    facts
}

/// The value of a one-line TOML scalar: a quoted string's text, or the first
/// word of a bare one (so a trailing `# comment` is not part of it).
fn toml_scalar(value: &str) -> String {
    let value = value.trim();
    match value.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or("").to_string(),
        None => value.split_whitespace().next().unwrap_or("").to_string(),
    }
}

/// `host:port` of `url`, where a bare compose name is the whole point.
fn endpoint(url: &str) -> Result<(String, u16)> {
    let parsed = Url::parse(url).with_context(|| format!("{url:?} is not a URL"))?;
    let host = parsed
        .host_str()
        .with_context(|| format!("{url:?} has no host"))?
        .trim_matches(['[', ']'])
        .to_string();
    let port = parsed
        .port_or_known_default()
        .with_context(|| format!("{url:?} has no port"))?;
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        bail!("{url:?} names a host this tunnel will not dial");
    }
    Ok((host, port))
}

/// Open the connection and read what the box says about itself. Everything
/// that can need a person (a passphrase, a host-key question) happens here,
/// before a terminal UI starts.
pub async fn connect(args: &RemoteArgs, report: &ReportArgs) -> Result<Link> {
    let host = args
        .ssh
        .clone()
        .ok_or_else(|| anyhow!("--ssh was not given"))?;
    if host.starts_with('-') || host.is_empty() || host.contains(char::is_whitespace) {
        bail!("{host:?} is not an ssh destination (user@host, or a host from ~/.ssh/config)");
    }
    let mut ssh = Ssh {
        host: host.clone(),
        dir: args.ssh_dir.clone(),
        control: None,
    };
    let mut session = Session {
        host: host.clone(),
        control_dir: None,
        tunnels: Vec::new(),
    };

    open_master(&mut ssh, &mut session).await?;

    let output = tokio::time::timeout(
        Duration::from_secs(60),
        ssh.command()
            .arg(&host)
            .arg(ssh.in_provider(PROBE))
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| unreachable_error(&host, "no answer within 60s"))?
    .map_err(|e| spawn_error(&e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(match output.status.code() {
            Some(255) => unreachable_error(&host, stderr.trim()),
            _ => not_running_error(&host, &ssh.dir, stderr.trim()),
        });
    }
    let facts = parse_probe(&String::from_utf8_lossy(&output.stdout));

    // The three places the report is read from, each opened from inside the
    // provider container.
    let operator_url = facts
        .operator_url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8090".to_string());
    let publisher_origin = facts
        .publish_url
        .as_deref()
        .map(crate::topup::publisher_origin)
        .transpose()
        .map_err(|e| anyhow!("the box's publish_url: {e:#}"))?;
    let connector_operator = facts
        .operator_connector_url
        .clone()
        .unwrap_or_else(|| "http://provider-connector:4000".to_string());

    let operator_local = tunnel(&ssh, &mut session, &operator_url).await?;
    let publisher_local = match &publisher_origin {
        Some(origin) => Some(tunnel(&ssh, &mut session, origin).await?),
        None => None,
    };
    let connector_local = tunnel(&ssh, &mut session, &connector_operator).await?;

    let hidden = facts.hidden;
    let hidden_rpc = "not asked over --ssh: a hidden provider reads its Solana balance from \
                      the box, on its own node or through anon; run `docker compose exec \
                      provider toon-provider status` there"
        .to_string();
    let rpc = match report
        .settlement_rpc_url
        .clone()
        .or_else(|| facts.solana_rpc_url.clone())
        .filter(|u| !u.trim().is_empty())
    {
        _ if hidden => Err(hidden_rpc),
        Some(url) => Ok(url.trim().to_string()),
        None => Err(
            "no Solana RPC to ask: the box sets TOON_SETTLEMENT_SOLANA_RPC_URL from \
             SETTLEMENT_SOLANA_RPC_URL in its .env; or pass --settlement-rpc-url"
                .to_string(),
        ),
    };
    let address = |given: Option<&String>, read: Option<String>, what: &str| match given
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .or(read)
    {
        Some(address) => Ok(address),
        None => Err(format!(
            "{what} was not read from the box (no address file in the provider container)"
        )),
    };

    let sources = Sources {
        operator_status_url: format!("{operator_local}/operator/status"),
        publisher_status_url: match &publisher_local {
            Some(local) => Ok(format!("{local}/status")),
            None => Err("no publish_url is configured, so there is no publisher".to_string()),
        },
        connector_operator_url: Ok(connector_local.clone()),
        bearer_token_file: None,
        bearer_token: facts.bearer_token.clone(),
        dashboard_url: facts
            .connector_url
            .as_deref()
            .and_then(crate::status::origin)
            .filter(|_| !hidden)
            .map(|o| format!("{o}/dashboard")),
        settlement_address: address(
            report.settlement_address.as_ref(),
            facts.settlement_address.clone(),
            "the connector's Solana settlement address",
        ),
        settlement_rpc_url: rpc.clone(),
        settlement_rpc_via: None,
        publisher_address: address(
            report.publisher_address.as_ref(),
            facts.publisher_address.clone(),
            "the publisher's Solana wallet",
        ),
        publisher_token: facts.solana_token.clone().ok_or_else(|| {
            "provider.toml names no solana [[settlement]] token to read the publisher's wallet in"
                .to_string()
        }),
        publisher_rpc_url: rpc,
        publisher_deposit: report.publisher_deposit.or(facts.publisher_deposit),
        timeout: SOURCE_TIMEOUT,
    };
    Ok(Link {
        redeem_base: Ok(connector_local),
        publish_url: publisher_local.map(|local| format!("{local}/publish")),
        // A hidden box's EVM RPC is dialled from the box, through anon: not
        // from here, as its Solana RPC is not.
        evm_rpc_url: facts
            .evm_rpc_url
            .clone()
            .filter(|u| !u.trim().is_empty() && !hidden),
        sources,
        _session: session,
    })
}

/// One master connection, so a passphrase is asked once and every relay is
/// cheap. On Unix only; elsewhere each relay is its own `ssh`.
#[cfg(unix)]
async fn open_master(ssh: &mut Ssh, session: &mut Session) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    use std::hash::{BuildHasher, Hasher};

    // Short and in /tmp: a unix socket path is limited to ~104 bytes. Made
    // fresh under a name nobody can guess, never one already there (another
    // user of a shared /tmp could have put it there).
    let mut tries = 0;
    let dir = loop {
        let nonce = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        let dir = PathBuf::from(format!("/tmp/toon-provider-ssh-{nonce:016x}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => break dir,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 8 => tries += 1,
            Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
        }
    };
    session.control_dir = Some(dir.clone());

    // stderr goes to a file: a backgrounded master keeps its pipes open,
    // and reading a pipe would wait for it to exit.
    let err_path = dir.join("master.err");
    let err_file = std::fs::File::create(&err_path)?;
    let status = Command::new("ssh")
        .kill_on_drop(true)
        .args(["-o", "ConnectTimeout=15", "-o", "ControlPersist=no"])
        .args(["-fN", "-M", "-S"])
        .arg(dir.join("s"))
        .arg(&ssh.host)
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err_file))
        .status()
        .await
        .map_err(|e| spawn_error(&e))?;
    if !status.success() {
        let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
        return Err(match status.code() {
            Some(255) => unreachable_error(&ssh.host, stderr.trim()),
            _ => anyhow!("ssh to {} failed ({status}): {}", ssh.host, stderr.trim()),
        });
    }
    ssh.control = Some(dir);
    Ok(())
}

#[cfg(not(unix))]
async fn open_master(_ssh: &mut Ssh, _session: &mut Session) -> Result<()> {
    Ok(())
}

/// Run `work` to its end, or until Ctrl-C (or, on Unix, SIGTERM or SIGHUP):
/// `work` is dropped then, and with it the session, which closes the master
/// connection. Backgrounded with `-f`, that master would otherwise outlive
/// this process.
pub async fn until_interrupted<T>(work: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    #[cfg(unix)]
    let other = async {
        use tokio::signal::unix::{signal, SignalKind};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) {
            (Ok(mut term), Ok(mut hup)) => {
                tokio::select! { _ = term.recv() => {}, _ = hup.recv() => {} }
            }
            _ => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let other = std::future::pending::<()>();
    tokio::select! {
        result = work => result,
        _ = tokio::signal::ctrl_c() => bail!("interrupted; the ssh connection is closed"),
        _ = other => bail!("terminated; the ssh connection is closed"),
    }
}

fn spawn_error(e: &std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        anyhow!(
            "no ssh: `ssh` was not found on PATH. --ssh uses the OpenSSH client you already \
             have; install it (or run `toon-provider status` on the box)"
        )
    } else {
        anyhow!("running ssh: {e}")
    }
}

fn unreachable_error(host: &str, detail: &str) -> anyhow::Error {
    anyhow!(
        "host unreachable: ssh could not connect to {host}: {}",
        if detail.is_empty() {
            "(no detail)"
        } else {
            detail
        }
    )
}

fn not_running_error(host: &str, dir: &str, detail: &str) -> anyhow::Error {
    anyhow!(
        "provider not running on {host}: `docker compose exec provider` in {dir} failed: {}. \
         Is the provider up (`docker compose ps` there), and is --ssh-dir the deploy directory?",
        if detail.is_empty() {
            "(no detail)"
        } else {
            detail
        }
    )
}

/// Listen on a loopback port of this machine and relay each connection to
/// `url`'s host and port as seen from inside the provider container.
/// Returns the local base URL.
async fn tunnel(ssh: &Ssh, session: &mut Session, url: &str) -> Result<String> {
    let (host, port) = endpoint(url)?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("opening a local port for the tunnel")?;
    let local = listener.local_addr()?;
    let relay = ssh.in_provider(&format!(
        "bash -c {}",
        sh_quote(&format!(
            "exec 3<>/dev/tcp/{host}/{port} || exit 1; cat <&3 & cat <&0 >&3 & wait -n"
        ))
    ));
    let ssh = ssh.clone();
    session.tunnels.push(tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(relay_one(ssh.clone(), relay.clone(), socket));
        }
    }));
    Ok(format!("http://{local}"))
}

/// One connection: an `ssh` whose stdin and stdout are the socket.
async fn relay_one(ssh: Ssh, relay: String, socket: TcpStream) {
    let child = ssh
        .command()
        .arg(&ssh.host)
        .arg(relay)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return };
    let (Some(mut to_box), Some(mut from_box)) = (child.stdin.take(), child.stdout.take()) else {
        return;
    };
    let (mut read_socket, mut write_socket) = socket.into_split();
    let up = async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match read_socket.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if to_box.write_all(&buf[..n]).await.is_err() || to_box.flush().await.is_err() {
                        return;
                    }
                }
            }
        }
    };
    let down = async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match from_box.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if write_socket.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    };
    // Either side ending ends the connection (an HTTP client sends no
    // half-close); the child is killed with it.
    tokio::select! { _ = up => {}, _ = down => {} }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_is_read_into_facts() {
        let text = "TOON_CONNECTOR_OPERATOR_URL=http://provider-connector:4000\n\
TOON_SETTLEMENT_SOLANA_RPC_URL=https://api.devnet.solana.com\n\
TOON_PUBLISHER_DEPOSIT=10000000\n\
@@FILE TOON_CONNECTOR_BEARER_TOKEN_FILE\ntok-123\n\n\
@@FILE TOON_SETTLEMENT_SOLANA_ADDRESS_FILE\nSettle111\n\n\
@@CONFIG\n\
hidden = false\n\
connector_url = \"https://proxy.provider.example\"\n\
publish_url = \"http://directory-publisher:8081/publish\"\n\
operator_url = \"http://127.0.0.1:8090\"\n\
[[settlement]]\nchain = \"evm:84532\"\ntoken = \"0xabc\"\n\
[[settlement]]\nchain = \"solana\"\ntoken = \"Mint111\"\n\
[anon.settlement.evm]\n\
@@END\n";
        let facts = parse_probe(text);
        assert_eq!(
            facts.bearer_token.as_ref().map(|t| t.0.as_str()),
            Some("tok-123")
        );
        assert_eq!(facts.settlement_address.as_deref(), Some("Settle111"));
        assert_eq!(facts.publisher_address, None);
        assert_eq!(facts.publisher_deposit, Some(10_000_000));
        assert!(!facts.hidden);
        assert_eq!(facts.solana_token.as_deref(), Some("Mint111"));
        assert_eq!(
            facts.publish_url.as_deref(),
            Some("http://directory-publisher:8081/publish")
        );
    }

    #[test]
    fn a_hidden_box_is_read_as_hidden() {
        let facts = parse_probe("@@CONFIG\nhidden = true # onion\n@@END\n");
        assert!(facts.hidden);
    }

    #[test]
    fn settlement_keys_are_read_in_any_order_and_only_in_their_table() {
        let facts = parse_probe(
            "@@CONFIG\n\
hidden = false\n\
[[settlement]]\ntoken = \"Mint111\"\nchain = \"solana\"\n\
[anon]\nhidden = true\nconnector_url = \"http://elsewhere\"\n\
[anon.settlement.solana]\nchain = \"solana\"\ntoken = \"Other\"\n\
@@END\n",
        );
        assert_eq!(facts.solana_token.as_deref(), Some("Mint111"));
        assert!(!facts.hidden);
        assert_eq!(facts.connector_url, None);
    }

    #[test]
    fn endpoints_are_host_and_port() {
        assert_eq!(
            endpoint("http://directory-publisher:8081").unwrap(),
            ("directory-publisher".to_string(), 8081)
        );
        assert_eq!(
            endpoint("http://127.0.0.1:8090/x").unwrap(),
            ("127.0.0.1".to_string(), 8090)
        );
        assert!(endpoint("not a url").is_err());
    }

    #[test]
    fn quoting_survives_a_single_quote() {
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
    }
}
