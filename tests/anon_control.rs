//! The real `HiddenService` (`src/anon_control.rs`) against a stub control
//! port: the exact lines it writes, and what it makes of the lines it reads.
//!
//! The stub is an in-process `TcpListener` speaking the daemon's control
//! protocol — `PROTOCOLINFO`, `AUTHENTICATE`, `ADD_ONION`, `DEL_ONION` — and
//! recording every command it was sent, in order, so each test can say
//! exactly what went over the wire rather than only what came back. That is
//! the point of these tests: the adapter's whole job is to write the right
//! line and read the right field, and a fake of the adapter itself would
//! prove neither.
//!
//! The last test in this file is `#[ignore]` and talks to a REAL `anon`
//! daemon, beside the Docker-only tests in `tests/docker_backend.rs` and
//! `tests/registry_spawn_docker.rs`. Run it with:
//!
//! ```sh
//! TOON_ANON_CONTROL=127.0.0.1:9051 \
//!   TOON_ANON_COOKIE=/var/lib/anon/control_auth_cookie \
//!   cargo test --test anon_control -- --ignored
//! ```
//!
//! `TOON_ANON_CONTROL` is `host:port` of the daemon's `ControlPort`, and
//! either `TOON_ANON_COOKIE` (the path of its `CookieAuthFile`, readable by
//! whoever runs the test) or `TOON_ANON_PASSWORD` (the cleartext of its
//! `HashedControlPassword`) says how to authenticate. With none of them set
//! the test prints why and passes: `cargo test -- --ignored` must not fail
//! on a machine with no daemon, exactly as the Docker ones must not fail
//! with no Docker. The sandbox's `hs` profile daemon has `ControlSocket 0`
//! and no `ControlPort` today, so nothing there answers this yet; giving it
//! one is TOON_Network #43.

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use common::harness::{config_for, hidden_config as harness_hidden_config, listing, NOW};
use common::{stub_registry, FakeBackend, FakeClock};
use nostr_sdk::Keys;
use toon_provider::anon_control::refuse_unreachable_control;
use toon_provider::compute::EgressPolicy;
use toon_provider::hidden_service::{AddressPort, HiddenService};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::AppState;
use toon_provider::{AnonConfig, AnonControl, AnonControlService, ProviderConfig};

/// A 56-character base32 label, the shape `anon` v0.4.10.2 writes.
const SERVICE_ID: &str = "j5hquzqrbkqtfr2ypcm6cjxc7lsvyqxnvjbrnpx3rbl6ye4bz5btxeid";
const OTHER_SERVICE_ID: &str = "k7n4wq2bffxt6yc3dlmrvi5gaupszh64jxobe7wkydqrcm2tl5vfnaid";

/// What `ADD_ONION NEW:…` answers: the id above and a key of that id.
const PRIVATE_KEY: &str = "ED25519-V3:UEFTU1dPUkRQQVNTV09SRFBBU1NXT1JEUEFTU1dPUkQ=";

/// The daemon's cookie, as 32 bytes and as the hex `AUTHENTICATE` carries.
const COOKIE: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
const COOKIE_HEX: &str = "00112233445566778899aabbccddeeff0f1e2d3c4b5a697887\
                          96a5b4c3d2e1f0";

/// The `PROTOCOLINFO` reply of a daemon with `CookieAuthentication 1`: both
/// cookie methods, exactly as Tor's control code lists them together.
fn cookie_protocolinfo() -> Vec<String> {
    lines(&[
        "250-PROTOCOLINFO 1",
        "250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/lib/anon/control_auth_cookie\"",
        "250-VERSION Anon=\"0.4.10.2\"",
        "250 OK",
    ])
}

/// …and of one with `HashedControlPassword`.
fn password_protocolinfo() -> Vec<String> {
    lines(&[
        "250-PROTOCOLINFO 1",
        "250-AUTH METHODS=HASHEDPASSWORD",
        "250-VERSION Anon=\"0.4.10.2\"",
        "250 OK",
    ])
}

fn lines(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|l| l.to_string()).collect()
}

/// What the stub daemon answers, and what it accepts.
struct Script {
    protocolinfo: Vec<String>,
    /// The one `AUTHENTICATE` argument this daemon accepts. Anything else
    /// gets 515, as a daemon handed the wrong cookie or password does.
    accepts: String,
    /// The replies to `ADD_ONION` and `DEL_ONION`, in the order they are
    /// asked for.
    onion: VecDeque<Vec<String>>,
}

/// An in-process control port. Every connection is served the script above;
/// every command line is recorded, across connections, in order.
struct StubControl {
    addr: String,
    commands: Arc<Mutex<Vec<String>>>,
}

impl StubControl {
    async fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = listener.local_addr().expect("stub addr").to_string();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(script));
        let recorded = commands.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let script = script.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move { serve(stream, script, recorded).await });
            }
        });
        Self { addr, commands }
    }

    fn commands(&self) -> Vec<String> {
        self.commands.lock().unwrap().clone()
    }
}

async fn serve(
    stream: tokio::net::TcpStream,
    script: Arc<Mutex<Script>>,
    recorded: Arc<Mutex<Vec<String>>>,
) {
    let mut io = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match io.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let command = line.trim_end_matches(['\r', '\n']).to_string();
        if command.is_empty() {
            continue;
        }
        recorded.lock().unwrap().push(command.clone());
        // The reply is decided with the script locked and written with it
        // unlocked: a guard held across an await would not compile, and
        // would serialise the stub's connections if it did.
        let (reply, last) = {
            let mut script = script.lock().unwrap();
            let verb = command.split(' ').next().unwrap_or_default();
            match verb {
                "PROTOCOLINFO" => (script.protocolinfo.clone(), false),
                "AUTHENTICATE" => {
                    let argument = command.strip_prefix("AUTHENTICATE ").unwrap_or_default();
                    if argument == script.accepts {
                        (lines(&["250 OK"]), false)
                    } else {
                        (
                            lines(&[
                                "515 Authentication failed: Wrong length on authentication cookie.",
                            ]),
                            false,
                        )
                    }
                }
                "ADD_ONION" | "DEL_ONION" => (
                    script
                        .onion
                        .pop_front()
                        .unwrap_or_else(|| lines(&["550 the stub has no reply scripted for this"])),
                    false,
                ),
                "QUIT" => (lines(&["250 closing connection"]), true),
                _ => (lines(&["510 Unrecognized command"]), false),
            }
        };
        for line in reply {
            if io
                .get_mut()
                .write_all(format!("{}\r\n", line).as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
        if last {
            return;
        }
    }
}

/// A cookie file on disk, kept alive by the returned handle.
fn cookie_file() -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("cookie file");
    std::fs::write(file.path(), COOKIE).expect("write cookie");
    file
}

fn hidden_config(control: AnonControl) -> ProviderConfig {
    ProviderConfig {
        hidden: true,
        anon: AnonConfig {
            control: Some(control),
            egress: Some(EgressPolicy {
                network: "toon-hidden-egress".to_string(),
                gateway: "172.30.0.2".to_string(),
            }),
            forward_host: "127.0.0.1".to_string(),
            ..AnonConfig::default()
        },
        ..ProviderConfig::default()
    }
}

fn cookie_control(addr: &str, cookie: &tempfile::NamedTempFile) -> AnonControl {
    AnonControl {
        addr: addr.to_string(),
        cookie_file: Some(cookie.path().display().to_string()),
        password: None,
    }
}

fn password_control(addr: &str, password: &str) -> AnonControl {
    AnonControl {
        addr: addr.to_string(),
        cookie_file: None,
        password: Some(password.to_string()),
    }
}

fn service(control: AnonControl) -> AnonControlService {
    AnonControlService::from_config(&hidden_config(control)).expect("build the adapter")
}

fn ports() -> Vec<AddressPort> {
    vec![AddressPort::same(40000), AddressPort::same(41000)]
}

const WORKLOAD: &str = "aa";

/// `ADD_ONION NEW:ED25519-V3` answering an id and a key.
fn created() -> Vec<String> {
    lines(&[
        &format!("250-ServiceID={}", SERVICE_ID),
        &format!("250-PrivateKey={}", PRIVATE_KEY),
        "250 OK",
    ])
}

// ── creating an address ──────────────────────────────────────────────────

#[tokio::test]
async fn create_address_authenticates_with_the_cookie_and_maps_every_lease_port() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::from([created()]),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    let address = service
        .create_address(WORKLOAD, &ports())
        .await
        .expect("create the address");

    assert_eq!(address.host, format!("{}.anyone", SERVICE_ID));
    assert_eq!(address.key.as_deref(), Some(PRIVATE_KEY));
    assert_eq!(
        stub.commands(),
        vec![
            "PROTOCOLINFO 1".to_string(),
            format!("AUTHENTICATE {}", COOKIE_HEX),
            // One line, one mapping per lease port, in the order the lease
            // gave them, and `Flags=Detach` so the address outlives this
            // connection.
            "ADD_ONION NEW:ED25519-V3 Flags=Detach Port=40000,127.0.0.1:40000 \
             Port=41000,127.0.0.1:41000"
                .to_string(),
        ]
    );
}

#[tokio::test]
async fn a_lease_port_forwarded_elsewhere_is_mapped_apart() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::from([created()]),
    })
    .await;
    let mut config = hidden_config(cookie_control(&stub.addr, &cookie));
    config.anon.forward_host = "toon-provider".to_string();
    let service = AnonControlService::from_config(&config).expect("build the adapter");

    service
        .create_address(
            WORKLOAD,
            &[AddressPort {
                virtual_port: 22,
                host_port: 40000,
            }],
        )
        .await
        .expect("create the address");

    assert_eq!(
        stub.commands().last().unwrap(),
        "ADD_ONION NEW:ED25519-V3 Flags=Detach Port=22,toon-provider:40000"
    );
}

#[tokio::test]
async fn a_refused_add_onion_is_an_error_and_leaves_no_address_to_destroy() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::from([lines(&["512 Invalid 'Port' argument"])]),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    let refusal = service
        .create_address(WORKLOAD, &ports())
        .await
        .expect_err("the daemon refused");
    let refusal = format!("{:#}", refusal);
    assert!(refusal.contains(&stub.addr), "{}", refusal);
    assert!(refusal.contains("512"), "{}", refusal);
    assert!(refusal.contains("Invalid 'Port' argument"), "{}", refusal);

    // Nothing was created, so the lease's ending has nothing to delete and
    // asks the daemon nothing.
    service
        .destroy_address(WORKLOAD)
        .await
        .expect("destroying nothing is not an error");
    assert_eq!(stub.commands().len(), 3, "{:?}", stub.commands());
}

#[tokio::test]
async fn an_add_onion_with_no_service_id_is_an_error() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::from([lines(&["250 OK"])]),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    let refusal = service
        .create_address(WORKLOAD, &ports())
        .await
        .expect_err("no ServiceID");
    assert!(
        format!("{:#}", refusal).contains("without a ServiceID"),
        "{:#}",
        refusal
    );
}

#[tokio::test]
async fn an_address_with_no_ports_is_refused_before_the_daemon_is_asked() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::new(),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    service
        .create_address(WORKLOAD, &[])
        .await
        .expect_err("no ports");
    assert!(stub.commands().is_empty(), "{:?}", stub.commands());
}

// ── destroying it ────────────────────────────────────────────────────────

#[tokio::test]
async fn destroy_address_deletes_the_service_create_made() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::from([created(), lines(&["250 OK"])]),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    service
        .create_address(WORKLOAD, &ports())
        .await
        .expect("create");
    service.destroy_address(WORKLOAD).await.expect("destroy");

    assert_eq!(
        stub.commands().last().unwrap(),
        &format!("DEL_ONION {}", SERVICE_ID)
    );
    // And it is gone from this process too: a second ending asks nothing.
    let sent = stub.commands().len();
    service.destroy_address(WORKLOAD).await.expect("idempotent");
    assert_eq!(stub.commands().len(), sent);
}

#[tokio::test]
async fn an_address_the_daemon_has_already_forgotten_is_destroyed_anyway() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::from([created(), lines(&["552 Unknown Onion Service ID"])]),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    service
        .create_address(WORKLOAD, &ports())
        .await
        .expect("create");
    service
        .destroy_address(WORKLOAD)
        .await
        .expect("552 is the address being gone, which is what was asked for");
}

#[tokio::test]
async fn a_daemon_that_refuses_to_delete_leaves_the_address_to_try_again() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::from([
            created(),
            lines(&["550 Unspecified Anon error"]),
            lines(&["250 OK"]),
        ]),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    service
        .create_address(WORKLOAD, &ports())
        .await
        .expect("create");
    let refusal = service
        .destroy_address(WORKLOAD)
        .await
        .expect_err("the daemon still holds the address");
    assert!(format!("{:#}", refusal).contains("550"), "{:#}", refusal);

    // The id is still known, so a later sweep can and does try again.
    service.destroy_address(WORKLOAD).await.expect("second try");
    assert_eq!(
        stub.commands().last().unwrap(),
        &format!("DEL_ONION {}", SERVICE_ID)
    );
}

#[tokio::test]
async fn destroying_an_address_this_process_never_made_asks_the_daemon_nothing() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::new(),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    service
        .destroy_address("a lease this process never heard of")
        .await
        .expect("idempotent");
    assert!(stub.commands().is_empty(), "{:?}", stub.commands());
}

// ── restoring one after a restart ────────────────────────────────────────

#[tokio::test]
async fn restore_address_re_adds_the_stored_key_and_answers_the_same_host() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        // A restored key is not a new one, so the daemon answers no
        // PrivateKey — only the id, which is the same one it gave before.
        onion: VecDeque::from([
            lines(&[&format!("250-ServiceID={}", SERVICE_ID), "250 OK"]),
            lines(&["250 OK"]),
        ]),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    let host = service
        .restore_address(WORKLOAD, PRIVATE_KEY, &ports())
        .await
        .expect("restore");

    assert_eq!(host, format!("{}.anyone", SERVICE_ID));
    assert_eq!(
        stub.commands().last().unwrap(),
        &format!(
            "ADD_ONION {} Flags=Detach Port=40000,127.0.0.1:40000 Port=41000,127.0.0.1:41000",
            PRIVATE_KEY
        )
    );

    // And the restart has re-learned what `DEL_ONION` needs: the id is not
    // in the lease record, only the key is.
    service.destroy_address(WORKLOAD).await.expect("destroy");
    assert_eq!(
        stub.commands().last().unwrap(),
        &format!("DEL_ONION {}", SERVICE_ID)
    );
}

#[tokio::test]
async fn a_stored_key_that_is_not_a_daemon_key_is_refused_before_anything_is_sent() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::new(),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    for key in [
        "",
        "no-colon-at-all",
        "ED25519-V3:",
        ":blob",
        "ED25519-V3:blob with a space",
        "ED25519-V3:blob\r\nDEL_ONION somethingelse",
    ] {
        service
            .restore_address(WORKLOAD, key, &ports())
            .await
            .unwrap_err();
    }
    assert!(stub.commands().is_empty(), "{:?}", stub.commands());
}

#[tokio::test]
async fn each_lease_keeps_its_own_address() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::from([
            created(),
            lines(&[&format!("250-ServiceID={}", OTHER_SERVICE_ID), "250 OK"]),
            lines(&["250 OK"]),
        ]),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    service.create_address("aa", &ports()).await.expect("first");
    service
        .restore_address("bb", PRIVATE_KEY, &ports())
        .await
        .expect("second");
    service.destroy_address("bb").await.expect("destroy");

    assert_eq!(
        stub.commands().last().unwrap(),
        &format!("DEL_ONION {}", OTHER_SERVICE_ID),
        "the second lease's address, not the first's"
    );
}

// ── authentication ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_password_goes_over_the_wire_quoted() {
    let stub = StubControl::start(Script {
        protocolinfo: password_protocolinfo(),
        accepts: "\"a \\\"quoted\\\" secret\"".to_string(),
        onion: VecDeque::from([created()]),
    })
    .await;
    let service = service(password_control(&stub.addr, "a \"quoted\" secret"));

    service
        .create_address(WORKLOAD, &ports())
        .await
        .expect("create");

    assert_eq!(
        stub.commands()[1],
        "AUTHENTICATE \"a \\\"quoted\\\" secret\""
    );
}

#[tokio::test]
async fn a_rejected_cookie_names_the_control_endpoint() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: "some other cookie".to_string(),
        onion: VecDeque::new(),
    })
    .await;
    let service = service(cookie_control(&stub.addr, &cookie));

    let refusal = format!(
        "{:#}",
        service
            .create_address(WORKLOAD, &ports())
            .await
            .expect_err("515")
    );
    assert!(refusal.contains(&stub.addr), "{}", refusal);
    assert!(refusal.contains("COOKIE"), "{}", refusal);
    assert!(refusal.contains("515"), "{}", refusal);
}

#[tokio::test]
async fn a_rejected_password_names_the_control_endpoint() {
    let stub = StubControl::start(Script {
        protocolinfo: password_protocolinfo(),
        accepts: "\"the right one\"".to_string(),
        onion: VecDeque::new(),
    })
    .await;
    let service = service(password_control(&stub.addr, "the wrong one"));

    let refusal = format!("{:#}", service.preflight().await.expect_err("515"));
    assert!(refusal.contains(&stub.addr), "{}", refusal);
    assert!(refusal.contains("HASHEDPASSWORD"), "{}", refusal);
}

#[tokio::test]
async fn a_daemon_that_offers_neither_configured_method_is_refused_by_name() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: lines(&["250-PROTOCOLINFO 1", "250-AUTH METHODS=NULL", "250 OK"]),
        accepts: String::new(),
        onion: VecDeque::new(),
    })
    .await;

    let refusal = format!(
        "{:#}",
        service(cookie_control(&stub.addr, &cookie))
            .preflight()
            .await
            .expect_err("no cookie authentication offered")
    );
    assert!(refusal.contains(&stub.addr), "{}", refusal);
    assert!(refusal.contains("COOKIE"), "{}", refusal);
    assert!(refusal.contains("NULL"), "{}", refusal);
    assert!(refusal.contains("CookieAuthentication 1"), "{}", refusal);

    // The password half of the same refusal, on the same daemon.
    let refusal = format!(
        "{:#}",
        service(password_control(&stub.addr, "anything"))
            .preflight()
            .await
            .expect_err("no password authentication offered")
    );
    assert!(refusal.contains("HASHEDPASSWORD"), "{}", refusal);
}

#[tokio::test]
async fn a_cookie_file_that_cannot_be_read_names_it() {
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::new(),
    })
    .await;
    let service = service(AnonControl {
        addr: stub.addr.clone(),
        cookie_file: Some("/var/lib/anon/there-is-no-such-cookie".to_string()),
        password: None,
    });

    let refusal = format!("{:#}", service.preflight().await.expect_err("no cookie"));
    assert!(
        refusal.contains("/var/lib/anon/there-is-no-such-cookie"),
        "{}",
        refusal
    );
    assert!(refusal.contains("anon.control.cookie_file"), "{}", refusal);
}

#[tokio::test]
async fn a_password_carrying_a_newline_is_refused_at_construction() {
    // Not `expect_err`: `AnonControlService` is deliberately not `Debug`,
    // so that a panic or a log line can never print the password it holds.
    let refusal = match AnonControlService::from_config(&hidden_config(password_control(
        "127.0.0.1:9051",
        "one\r\nAUTHENTICATE two",
    ))) {
        Ok(_) => panic!("a second command smuggled into the password was accepted"),
        Err(refusal) => format!("{:#}", refusal),
    };
    assert!(refusal.contains("anon.control.password"), "{}", refusal);
}

// ── the startup check, and the egress policy ─────────────────────────────

#[tokio::test]
async fn the_startup_check_passes_on_a_daemon_that_answers() {
    let cookie = cookie_file();
    let stub = StubControl::start(Script {
        protocolinfo: cookie_protocolinfo(),
        accepts: COOKIE_HEX.to_string(),
        onion: VecDeque::new(),
    })
    .await;

    refuse_unreachable_control(&hidden_config(cookie_control(&stub.addr, &cookie)))
        .await
        .expect("the daemon answers and accepts the cookie");

    // It creates nothing: it authenticates and hangs up.
    assert_eq!(
        stub.commands(),
        vec![
            "PROTOCOLINFO 1".to_string(),
            format!("AUTHENTICATE {}", COOKIE_HEX)
        ]
    );
}

#[tokio::test]
async fn the_startup_check_refuses_a_control_port_that_is_not_there() {
    let cookie = cookie_file();
    // A port nothing listens on: bound to learn a free one, then dropped.
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        listener.local_addr().expect("addr").to_string()
    };

    let refusal = format!(
        "{:#}",
        refuse_unreachable_control(&hidden_config(cookie_control(&dead, &cookie)))
            .await
            .expect_err("nothing is listening")
    );
    assert!(refusal.contains(&dead), "{}", refusal);
    assert!(
        refusal.contains("cannot reach the anon control port"),
        "{}",
        refusal
    );
}

#[tokio::test]
async fn a_provider_that_is_not_hidden_has_no_daemon_to_check() {
    let mut config = hidden_config(password_control("127.0.0.1:1", "unused"));
    config.hidden = false;

    refuse_unreachable_control(&config)
        .await
        .expect("nothing to check");
}

#[test]
fn egress_for_answers_the_configured_policy() {
    let service = service(password_control("127.0.0.1:9051", "secret"));

    let egress = service.egress_for(WORKLOAD);

    assert_eq!(egress.network, "toon-hidden-egress");
    assert_eq!(egress.gateway, "172.30.0.2");
}

// ── which implementation a config gets ───────────────────────────────────

/// A full provider config, hidden or not, built the way the harness builds
/// one: `AppState::new` validates it, so half a config will not do.
async fn provider_config(hidden: bool) -> ProviderConfig {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let registry = stub_registry().await;
    let config = config_for(
        vec![listing("basic", 1, 2)],
        &keys.secret_key().to_secret_hex(),
        &state_path,
        &registry,
        ImagePolicyConfig::default(),
    );
    if hidden {
        harness_hidden_config(config)
    } else {
        config
    }
}

#[tokio::test]
async fn a_hidden_config_installs_the_anon_adapter_and_nothing_else_can() {
    // The only `HiddenService` a CONFIG can ask for is this one: the fake
    // lives in `tests/common` and is installed by `with_hidden_service`,
    // which no config path reaches. A running hidden provider therefore
    // drives the daemon or refuses to start — it cannot quietly pretend.
    let state = AppState::new(
        provider_config(true).await,
        FakeBackend::new(),
        FakeClock::at(NOW),
    )
    .expect("build the state");

    assert!(state.hidden_service.is_some());
    // …and it made no connection doing it: the daemon is proved reachable
    // once at startup, not while the provider is being built.
}

#[tokio::test]
async fn a_provider_that_is_not_hidden_gets_no_hidden_service_at_all() {
    let state = AppState::new(
        provider_config(false).await,
        FakeBackend::new(),
        FakeClock::at(NOW),
    )
    .expect("build the state");

    assert!(state.hidden_service.is_none());
}

// ── against a real daemon ────────────────────────────────────────────────

/// The whole cycle against a running `anon`: create an address for a made-up
/// lease, check it is a `.anyone` host with a key, restore it from that key,
/// and delete it. See this file's module docs for the environment variables
/// and what the daemon's `anonrc` must carry (`ControlPort`, and
/// `CookieAuthentication 1` with a `CookieAuthFile` this process can read).
#[tokio::test]
#[ignore = "needs a running anon daemon with a control port; run with `cargo test -- --ignored`"]
async fn a_real_anon_daemon_creates_restores_and_deletes_an_address() {
    let Ok(addr) = std::env::var("TOON_ANON_CONTROL") else {
        eprintln!(
            "skipped: set TOON_ANON_CONTROL=<host:port> and one of TOON_ANON_COOKIE=<path> or \
             TOON_ANON_PASSWORD=<password> to run this against a real anon daemon"
        );
        return;
    };
    let control = match (
        std::env::var("TOON_ANON_COOKIE"),
        std::env::var("TOON_ANON_PASSWORD"),
    ) {
        (Ok(cookie), _) => AnonControl {
            addr: addr.clone(),
            cookie_file: Some(cookie),
            password: None,
        },
        (_, Ok(password)) => AnonControl {
            addr: addr.clone(),
            cookie_file: None,
            password: Some(password),
        },
        _ => {
            eprintln!(
                "skipped: TOON_ANON_CONTROL is set but neither TOON_ANON_COOKIE nor \
                 TOON_ANON_PASSWORD is"
            );
            return;
        }
    };
    let service = service(control);
    let workload = "40".repeat(32);

    service.preflight().await.expect("the daemon authenticates");

    let address = service
        .create_address(&workload, &[AddressPort::same(40040)])
        .await
        .expect("create an address");
    assert!(
        address.host.ends_with(".anyone"),
        "the daemon answered {}",
        address.host
    );
    let key = address.key.clone().expect("a new address carries its key");

    // The daemon derives the address from the key, so re-adding the same key
    // answers the same host. It is already live, so delete it first: this is
    // what a provider restart does with the key its lease record kept, minus
    // the restart.
    service
        .destroy_address(&workload)
        .await
        .expect("delete before restoring");
    let restored = service
        .restore_address(&workload, &key, &[AddressPort::same(40040)])
        .await
        .expect("restore the address from its key");
    assert_eq!(restored, address.host, "the same key is the same address");

    service.destroy_address(&workload).await.expect("delete");
    // And again: deleting an address the daemon no longer has is not an
    // error (spec §6.7).
    service
        .destroy_address(&workload)
        .await
        .expect("idempotent");
}
