// The real `HiddenService`: the `anon` daemon, driven over its control port.
//
// `src/hidden_service.rs` says what a Hidden Provider asks of its daemon;
// this module is the only thing in the provider that knows HOW to ask. The
// connector's ADR 0070 keeps the control protocol out of the connector, so
// driving the daemon is the provider's job, and it is one TCP connection to
// `[anon.control].addr` speaking Tor's control protocol — which is what
// `anon` v0.4.10.2 speaks, down to the `ADD_ONION` handler this whole
// milestone rests on.
//
// WHAT GOES OVER THE WIRE, per call:
//
//     PROTOCOLINFO 1
//     250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/var/lib/anon/control_auth_cookie"
//     250 OK
//     AUTHENTICATE <hex of the cookie file>          (or AUTHENTICATE "<password>")
//     250 OK
//     ADD_ONION NEW:ED25519-V3 Flags=Detach Port=22,127.0.0.1:40000 Port=443,…
//     250-ServiceID=<56 base32 characters>
//     250-PrivateKey=ED25519-V3:<base64>
//     250 OK
//
// and, to end a lease's address, `DEL_ONION <service id>`.
//
// THREE DECISIONS WORTH THE INK:
//
// 1. `Flags=Detach`. Without it the daemon destroys every address the
//    control connection made when that connection closes. A lease outlives
//    any one command, so every address here is detached and lives until
//    `DEL_ONION` or until the daemon itself restarts.
//
// 2. A CONNECTION PER CALL, rather than one held open for the process's
//    life. Detached services make it free to do so — nothing is lost when
//    the connection goes — and it means there is no reconnect path to get
//    wrong: an address is created by a connection that is opened,
//    authenticated, used and dropped, and a daemon that was restarted under
//    us fails the next call loudly instead of on a socket that went quiet.
//    Addresses are made once per lease, so the two extra round trips cost
//    nothing that matters.
//
// 3. PLAIN COOKIE AUTHENTICATION, not SAFECOOKIE. The daemon offers both
//    whenever `CookieAuthentication 1` is set (it lists `COOKIE,SAFECOOKIE`
//    together), and the control port is a loopback or compose-internal
//    socket that already needs the cookie FILE to be readable by this
//    process — an attacker who can read it can also speak SAFECOOKIE. So
//    the simple method, with the offered methods checked so a daemon that
//    stops offering it is a clear refusal rather than a puzzling one.
//
// WHAT THIS MODULE DOES NOT DO: it does not persist anything. The key that
// IS the address comes back from `create_address` in `HiddenAddress::key`
// and the lease record is what keeps it (M4-2, #39); a restarted provider
// hands it back to `restore_address`, which is also how this adapter
// re-learns the service id it needs for `DEL_ONION` — the id/workload map
// below is in memory and starts empty on every boot, exactly like the
// daemon's own detached-service table after ITS restart.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::compute::EgressPolicy;
use crate::hidden_service::{
    is_anyone_host, AddressPort, HiddenAddress, HiddenService, ANYONE_SUFFIX,
};
use crate::provider::ProviderConfig;

/// The control-protocol name of the key type every address here is made
/// from. Ed25519 v3 is the only onion-service version `anon` v0.4.10.2
/// serves, and the prefix of the key it hands back.
const KEY_TYPE: &str = "ED25519-V3";

/// How this provider proves itself to the control port. Exactly one of the
/// two, which is what `ProviderConfig::validate` already refuses to load
/// otherwise.
///
/// Not `Debug`, and neither is the `AnonControlService` that holds one: the
/// password variant is a secret in the clear, and the cheapest way to keep
/// it out of a panic message or a `{:?}` log line is for there to be no way
/// to print it.
#[derive(Clone)]
enum ControlAuth {
    /// The daemon's `CookieAuthFile`, read fresh on every connection: the
    /// daemon rewrites it on each restart, and a cached copy would be the
    /// one authentication failure that survives fixing the daemon.
    Cookie(PathBuf),
    /// The cleartext of `HashedControlPassword`.
    Password(String),
}

impl ControlAuth {
    /// The `PROTOCOLINFO` method name this authentication needs the daemon
    /// to offer.
    fn method(&self) -> &'static str {
        match self {
            ControlAuth::Cookie(_) => "COOKIE",
            ControlAuth::Password(_) => "HASHEDPASSWORD",
        }
    }
}

/// The `anon` daemon as a `HiddenService`.
///
/// One per provider process, shared behind an `Arc` by every lease: the
/// state it holds is the map from the lease's workload id to the service id
/// the daemon answered, which is all `DEL_ONION` needs and the only thing
/// that cannot be re-derived from the config.
pub struct AnonControlService {
    /// `host:port` of the daemon's `ControlPort`, as written in
    /// `[anon.control].addr`. Kept as the operator wrote it so every
    /// refusal names the endpoint they configured.
    addr: String,
    auth: ControlAuth,
    /// Where the daemon forwards a lease's virtual ports to — this host AS
    /// THE DAEMON SEES IT (`anon.forward_host`).
    forward_host: String,
    /// What `egress_for` answers: the configured `[anon.egress]`, the same
    /// for every workload today.
    egress: EgressPolicy,
    /// workload id → service id, for the addresses this process created or
    /// restored. Empty after a restart; `restore_address` refills it from
    /// the keys the lease records kept.
    services: Mutex<HashMap<String, String>>,
}

impl AnonControlService {
    /// The adapter a config describes. Reads `[anon.control]`,
    /// `[anon.egress]` and `anon.forward_host`, and touches no socket and no
    /// file: a provider is built before it is run, and a daemon that is not
    /// up yet must not stop the process from being constructed. The
    /// connection is proved once at startup instead
    /// (`refuse_unreachable_control`).
    ///
    /// Fails only on a config that should already have been refused by
    /// `ProviderConfig::validate` — the keys the Hidden Provider gate
    /// requires, missing — plus the two things the gate cannot check
    /// because they only matter here: an authentication secret or a forward
    /// host carrying a control character, which would be a second line
    /// smuggled into the control protocol rather than an argument.
    pub fn from_config(config: &ProviderConfig) -> Result<Self> {
        let control = config.anon.control.as_ref().context(
            "hidden = true needs [anon.control] to create per-lease addresses (spec §10)",
        )?;
        let auth = match (&control.cookie_file, &control.password) {
            (Some(cookie), None) => ControlAuth::Cookie(PathBuf::from(cookie)),
            (None, Some(password)) => {
                refuse_control_characters("anon.control.password", password)?;
                ControlAuth::Password(password.clone())
            }
            _ => bail!(
                "anon.control must name exactly one of cookie_file and password to authenticate \
                 to {}",
                control.addr
            ),
        };
        let egress = config.anon.egress.clone().context(
            "hidden = true needs [anon.egress]: the network every hidden workload is attached \
             to (spec §10)",
        )?;
        refuse_control_characters("anon.forward_host", &config.anon.forward_host)?;
        Ok(Self {
            addr: control.addr.clone(),
            auth,
            forward_host: config.anon.forward_host.clone(),
            egress,
            services: Mutex::new(HashMap::new()),
        })
    }

    /// Reach the control port and authenticate, then hang up: the one check
    /// that a Hidden Provider's `hidden = true` is not a claim its daemon
    /// will refuse the first time a tenant pays for a lease. Creates
    /// nothing.
    pub async fn preflight(&self) -> Result<()> {
        self.connect().await?;
        info!(
            "anon control port at {} answers and accepts {} authentication",
            self.addr,
            self.auth.method()
        );
        Ok(())
    }

    /// An authenticated control connection, or a refusal naming the
    /// endpoint. Every call below starts here.
    async fn connect(&self) -> Result<Control> {
        let stream = TcpStream::connect(&self.addr).await.with_context(|| {
            format!(
                "cannot reach the anon control port at {} — a Hidden Provider's addresses are \
                 created there (spec §10, ADR 0008)",
                self.addr
            )
        })?;
        let mut control = Control {
            io: BufReader::new(stream),
            addr: self.addr.clone(),
        };
        let methods = auth_methods(&control.send("PROTOCOLINFO 1").await?);
        if !methods.iter().any(|m| m == self.auth.method()) {
            bail!(
                "the anon control port at {} does not offer {} authentication, which is what \
                 [anon.control] configures; it offers {}. Set CookieAuthentication 1 (and \
                 CookieAuthFile) or HashedControlPassword in the daemon's anonrc",
                self.addr,
                self.auth.method(),
                if methods.is_empty() {
                    "nothing".to_string()
                } else {
                    methods.join(", ")
                },
            );
        }
        let command = match &self.auth {
            ControlAuth::Cookie(path) => {
                let cookie = tokio::fs::read(path).await.with_context(|| {
                    format!(
                        "cannot read the anon control cookie {} named by \
                         anon.control.cookie_file; it must be readable by this process",
                        path.display()
                    )
                })?;
                format!("AUTHENTICATE {}", hex(&cookie))
            }
            ControlAuth::Password(password) => {
                format!("AUTHENTICATE \"{}\"", quote(password))
            }
        };
        let reply = control.send(&command).await?;
        if reply.code != 250 {
            bail!(
                "the anon control port at {} refused this provider's {} authentication: {} {}",
                self.addr,
                self.auth.method(),
                reply.code,
                reply.text(),
            );
        }
        Ok(control)
    }

    /// `ADD_ONION <key spec> Flags=Detach Port=…` — one line, one mapping
    /// per lease port — and the `ServiceID=` the daemon answers. Shared by
    /// `create_address` (`NEW:ED25519-V3`) and `restore_address` (the
    /// stored key), because the two differ in nothing but that word and in
    /// which of the reply's fields matters.
    async fn add_onion(
        &self,
        workload_id: &str,
        key_spec: &str,
        ports: &[AddressPort],
    ) -> Result<(String, Option<String>)> {
        if ports.is_empty() {
            bail!(
                "lease {} asked for an address with no ports; the anon daemon has nothing to \
                 forward and refuses such a service",
                workload_id
            );
        }
        let mut command = format!("ADD_ONION {} Flags=Detach", key_spec);
        for port in ports {
            let _ = write!(
                command,
                " Port={},{}",
                port.virtual_port,
                target(&self.forward_host, port.host_port)
            );
        }
        let mut control = self.connect().await?;
        let reply = control.send(&command).await?;
        if reply.code != 250 {
            bail!(
                "the anon daemon at {} refused to add lease {}'s address: {} {}",
                self.addr,
                workload_id,
                reply.code,
                reply.text(),
            );
        }
        let service_id = reply.field("ServiceID").with_context(|| {
            format!(
                "the anon daemon at {} answered lease {}'s ADD_ONION without a ServiceID: {}",
                self.addr,
                workload_id,
                reply.text()
            )
        })?;
        let host = format!("{}{}", service_id, ANYONE_SUFFIX);
        if !is_anyone_host(&host) {
            bail!(
                "the anon daemon at {} answered lease {} the service id {:?}, which is not an \
                 address a TOON client will dial",
                self.addr,
                workload_id,
                service_id,
            );
        }
        self.services
            .lock()
            .expect("hidden-service map poisoned")
            .insert(workload_id.to_string(), service_id);
        Ok((host, reply.field("PrivateKey")))
    }
}

#[async_trait]
impl HiddenService for AnonControlService {
    async fn create_address(
        &self,
        workload_id: &str,
        ports: &[AddressPort],
    ) -> Result<HiddenAddress> {
        let (host, key) = self
            .add_onion(workload_id, &format!("NEW:{}", KEY_TYPE), ports)
            .await?;
        if key.is_none() {
            // Not fatal — the address works — but the lease would then have
            // nothing to restore from, and a restart would move the tenant's
            // host without either side being told why.
            warn!(
                "the anon daemon at {} created lease {}'s address without answering its key; a \
                 restart will give the lease a new address",
                self.addr, workload_id
            );
        }
        debug!("lease {} has the address {}", workload_id, host);
        Ok(HiddenAddress { host, key })
    }

    async fn restore_address(
        &self,
        workload_id: &str,
        key: &str,
        ports: &[AddressPort],
    ) -> Result<String> {
        // The key is the ONE thing here that came off disk rather than out
        // of the daemon, and it is written into a control-protocol command
        // line. A stored key that is not `<type>:<blob>` — truncated state,
        // a hand-edited file, anything carrying a newline — is refused
        // before a byte is sent, so a broken lease record can never become
        // a second command.
        let (key_type, blob) = key
            .split_once(':')
            .filter(|(key_type, blob)| !key_type.is_empty() && !blob.is_empty())
            .with_context(|| {
                format!(
                    "lease {}'s stored address key is not <type>:<blob> as the anon daemon \
                     writes it ({}:…), so its address cannot be restored",
                    workload_id, KEY_TYPE
                )
            })?;
        refuse_control_characters("the stored address key", key)?;
        if blob.contains(' ') || key_type.contains(' ') {
            bail!(
                "lease {}'s stored address key contains a space, which the anon daemon's \
                 control protocol cannot carry",
                workload_id
            );
        }
        let (host, _) = self.add_onion(workload_id, key, ports).await?;
        info!("lease {} is reachable again at {}", workload_id, host);
        Ok(host)
    }

    async fn destroy_address(&self, workload_id: &str) -> Result<()> {
        let service_id = self
            .services
            .lock()
            .expect("hidden-service map poisoned")
            .get(workload_id)
            .cloned();
        let Some(service_id) = service_id else {
            // Idempotent by the port's contract (spec §6.7): a lease ending
            // twice, or ending after a restart that never restored its
            // address, must not fail. The warning is the honest part — an
            // address this process never learned the id of stays up on the
            // daemon until the daemon itself restarts.
            warn!(
                "lease {} has no address known to this process; nothing to destroy on the anon \
                 daemon at {}",
                workload_id, self.addr
            );
            return Ok(());
        };
        let mut control = self.connect().await?;
        let reply = control.send(&format!("DEL_ONION {}", service_id)).await?;
        // 552 is the daemon saying it has no such service: the address is
        // gone, which is exactly what was asked for. Anything else is a
        // daemon that still holds the address, and the caller must be able
        // to try again (the lease stays pending destruction for a later
        // sweep), so it is an error and the map keeps the id.
        if reply.code != 250 && reply.code != 552 {
            bail!(
                "the anon daemon at {} refused to delete lease {}'s address {}: {} {}",
                self.addr,
                workload_id,
                service_id,
                reply.code,
                reply.text(),
            );
        }
        self.services
            .lock()
            .expect("hidden-service map poisoned")
            .remove(workload_id);
        debug!("lease {}'s address {} is gone", workload_id, service_id);
        Ok(())
    }

    fn egress_for(&self, _workload_id: &str) -> EgressPolicy {
        self.egress.clone()
    }
}

/// The startup check behind `hidden = true`: the daemon named in
/// `[anon.control]` answers and accepts this provider's authentication.
/// Called once from `ProviderService::run`, before anything is served or
/// published — a provider that cannot create addresses must not advertise
/// itself as one that can, and finding out at the first paid spawn would
/// mean refusing a tenant who already paid.
///
/// A provider that is not hidden has no daemon to check and this does
/// nothing.
pub async fn refuse_unreachable_control(config: &ProviderConfig) -> Result<()> {
    if !config.hidden {
        return Ok(());
    }
    AnonControlService::from_config(config)?.preflight().await
}

/// One control connection, and the line protocol over it.
struct Control {
    io: BufReader<TcpStream>,
    /// Only so a failure mid-protocol can name the endpoint too.
    addr: String,
}

impl Control {
    /// Write one command line and read the whole reply it answers.
    async fn send(&mut self, command: &str) -> Result<Reply> {
        self.io
            .get_mut()
            .write_all(format!("{}\r\n", command).as_bytes())
            .await
            .with_context(|| {
                format!(
                    "cannot write to the anon control port at {} (command {:?})",
                    self.addr,
                    redact(command)
                )
            })?;
        self.io.get_mut().flush().await.ok();
        self.read_reply(command).await
    }

    /// A control reply is one or more lines, each `<3 digits><separator>
    /// <text>`: `-` for a line with more to come, ` ` for the last one, and
    /// `+` for one whose text is a block ended by a lone `.`. The code of
    /// the last line is the reply's code.
    async fn read_reply(&mut self, command: &str) -> Result<Reply> {
        let mut lines = Vec::new();
        loop {
            let line = self.read_line(command).await?;
            if line.len() < 4 {
                bail!(
                    "the anon control port at {} answered {:?}, which is not a control reply \
                     (command {:?})",
                    self.addr,
                    line,
                    redact(command)
                );
            }
            let (code, rest) = line.split_at(3);
            let code: u16 = code.parse().with_context(|| {
                format!(
                    "the anon control port at {} answered {:?}, which starts with no status code",
                    self.addr, line
                )
            })?;
            let separator = rest.as_bytes()[0];
            lines.push(rest[1..].to_string());
            match separator {
                b'-' => continue,
                b' ' => return Ok(Reply { code, lines }),
                b'+' => loop {
                    let data = self.read_line(command).await?;
                    if data == "." {
                        break;
                    }
                    lines.push(data);
                },
                _ => bail!(
                    "the anon control port at {} answered {:?}, whose separator is not one of \
                     `-`, ` ` or `+`",
                    self.addr,
                    line
                ),
            }
        }
    }

    async fn read_line(&mut self, command: &str) -> Result<String> {
        let mut line = String::new();
        let read = self.io.read_line(&mut line).await.with_context(|| {
            format!(
                "cannot read from the anon control port at {} (command {:?})",
                self.addr,
                redact(command)
            )
        })?;
        if read == 0 {
            bail!(
                "the anon control port at {} closed the connection without answering (command \
                 {:?}); check its ControlPort and its authentication",
                self.addr,
                redact(command)
            );
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

/// One parsed control reply.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    /// The status code of the reply's last line: 250 is success.
    code: u16,
    /// Every line's text, separators and codes stripped, in order.
    lines: Vec<String>,
}

impl Reply {
    /// The value of a `Key=Value` line, e.g. `ServiceID` or `PrivateKey`.
    fn field(&self, key: &str) -> Option<String> {
        let prefix = format!("{}=", key);
        self.lines
            .iter()
            .find_map(|line| line.strip_prefix(&prefix))
            .map(str::to_string)
    }

    /// The reply as one line, for a refusal message.
    fn text(&self) -> String {
        self.lines.join("; ")
    }
}

/// The methods a `PROTOCOLINFO` reply's `AUTH METHODS=…` line lists.
/// Nothing else on that line is read: `COOKIEFILE=` names the cookie the
/// daemon wrote, but `anon.control.cookie_file` is what the operator gave
/// this process access to, and taking the daemon's word for a path to read
/// would let the thing being authenticated to choose the file.
fn auth_methods(reply: &Reply) -> Vec<String> {
    reply
        .lines
        .iter()
        .filter_map(|line| line.strip_prefix("AUTH "))
        .flat_map(|rest| rest.split_whitespace())
        .filter_map(|word| word.strip_prefix("METHODS="))
        .flat_map(|methods| methods.split(','))
        .map(str::to_string)
        .collect()
}

/// `host:port` as the control protocol's `Port=` target, with a bare IPv6
/// address bracketed — `[::1]:9000`, which is the only spelling the daemon
/// parses.
fn target(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Lowercase hex, which is how `AUTHENTICATE` carries the cookie file's
/// bytes.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{:02x}", byte);
            out
        })
}

/// A control-protocol QuotedString's inside: backslash and double quote
/// escaped, which is all `AUTHENTICATE "…"` needs once control characters
/// are refused at construction.
fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Refuse anything that would end a control-protocol line early. Every
/// string this module writes into a command either came from the daemon or
/// goes through here.
fn refuse_control_characters(what: &str, value: &str) -> Result<()> {
    if value.chars().any(|c| c.is_control()) {
        bail!(
            "{} contains a control character, which the anon control protocol reads as the end \
             of a command",
            what
        );
    }
    Ok(())
}

/// A command as a refusal may quote it: everything but `AUTHENTICATE`,
/// whose argument is the secret itself.
fn redact(command: &str) -> &str {
    if command.starts_with("AUTHENTICATE") {
        "AUTHENTICATE …"
    } else {
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(lines: &[&str]) -> Reply {
        Reply {
            code: 250,
            lines: lines.iter().map(|l| l.to_string()).collect(),
        }
    }

    #[test]
    fn a_field_is_the_value_after_its_key() {
        let reply = reply(&["ServiceID=abcd", "PrivateKey=ED25519-V3:blob", "OK"]);
        assert_eq!(reply.field("ServiceID").as_deref(), Some("abcd"));
        assert_eq!(
            reply.field("PrivateKey").as_deref(),
            Some("ED25519-V3:blob")
        );
        assert_eq!(reply.field("ClientAuth"), None);
    }

    #[test]
    fn the_offered_methods_come_off_the_auth_line() {
        let reply = reply(&[
            "PROTOCOLINFO 1",
            "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/lib/anon/control_auth_cookie\"",
            "VERSION Anon=\"0.4.10.2\"",
            "OK",
        ]);
        assert_eq!(auth_methods(&reply), vec!["COOKIE", "SAFECOOKIE"]);
    }

    #[test]
    fn a_daemon_with_no_authentication_offers_null() {
        assert_eq!(auth_methods(&reply(&["AUTH METHODS=NULL", "OK"])), ["NULL"]);
        assert!(auth_methods(&reply(&["OK"])).is_empty());
    }

    #[test]
    fn a_forward_target_brackets_a_bare_ipv6_address() {
        assert_eq!(target("127.0.0.1", 40000), "127.0.0.1:40000");
        assert_eq!(target("toon-provider", 40000), "toon-provider:40000");
        assert_eq!(target("::1", 40000), "[::1]:40000");
        assert_eq!(target("[::1]", 40000), "[::1]:40000");
    }

    #[test]
    fn the_cookie_goes_over_the_wire_as_lowercase_hex() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn a_quoted_password_escapes_the_two_characters_that_end_it() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote(r#"a"b"#), r#"a\"b"#);
        assert_eq!(quote(r"a\b"), r"a\\b");
    }

    #[test]
    fn a_secret_carrying_a_newline_is_refused_rather_than_sent() {
        assert!(refuse_control_characters("password", "fine").is_ok());
        assert!(refuse_control_characters("password", "two\r\nlines").is_err());
        assert!(refuse_control_characters("password", "tab\there").is_err());
    }

    #[test]
    fn a_refusal_never_quotes_the_authentication_command() {
        assert_eq!(redact("AUTHENTICATE deadbeef"), "AUTHENTICATE …");
        assert_eq!(redact("DEL_ONION abcd"), "DEL_ONION abcd");
    }
}
