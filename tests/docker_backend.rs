//! The Docker backend against a real Docker daemon.
//!
//! `#[ignore]` by default: `cargo test` must pass on a machine with no Docker.
//! Run it with `cargo test -- --ignored` where a daemon is available.

use std::collections::HashMap;

use toon_provider::compute::{ComputeBackend, ContainerConfig, ContainerStatus};
use toon_provider::DockerBackend;

/// Small, fast to pull, and it stays up under `sleep`.
const IMAGE: &str = "alpine:3.20";

/// Well outside the default lease id range, so a stray test container can never
/// collide with a real lease.
const TEST_ID: u32 = 59001;

async fn pull_image() {
    let status = tokio::process::Command::new("docker")
        .args(["pull", IMAGE])
        .status()
        .await
        .expect("invoke docker pull");
    assert!(status.success(), "docker pull {} failed", IMAGE);
}

fn config() -> ContainerConfig {
    ContainerConfig {
        id: TEST_ID,
        name: toon_provider::compute::container_name(TEST_ID),
        image: IMAGE.to_string(),
        cpu_millicores: 1000,
        memory_mb: 64,
        storage_gb: 1,
        ssh_key: None,
        host_port: None,
        ports: Vec::new(),
        env: HashMap::from([("TOON_TEST".to_string(), "1".to_string())]),
        // alpine exits immediately with no command, and a workload that exits
        // is indistinguishable from one that never started.
        entrypoint: None,
        args: vec!["sleep".to_string(), "300".to_string()],
        data_path: None,
        capabilities: vec![],
        egress: None,
    }
}

#[tokio::test]
#[ignore = "needs a Docker daemon; run with `cargo test -- --ignored`"]
async fn docker_backend_creates_starts_and_destroys_a_workload() {
    pull_image().await;

    let backend = DockerBackend::new();

    // Leave nothing behind from an earlier interrupted run.
    backend.delete_container(TEST_ID).await.expect("pre-clean");

    backend
        .create_container(&config())
        .await
        .expect("create the container");
    assert_eq!(
        backend.get_container_status(TEST_ID).await.unwrap(),
        ContainerStatus::Running,
        "`docker run -d` leaves the container running"
    );

    // Stop then start, so both directions of the trait are exercised.
    backend.stop_container(TEST_ID).await.expect("stop");
    assert_eq!(
        backend.get_container_status(TEST_ID).await.unwrap(),
        ContainerStatus::Stopped
    );

    backend.start_container(TEST_ID).await.expect("start");
    assert_eq!(
        backend.get_container_status(TEST_ID).await.unwrap(),
        ContainerStatus::Running
    );

    // The id must come back to the pool once the lease ends.
    let taken = backend
        .find_available_id(TEST_ID, TEST_ID + 1)
        .await
        .unwrap();
    assert_ne!(
        taken, TEST_ID,
        "a live workload's id must not be handed out"
    );

    backend.delete_container(TEST_ID).await.expect("delete");
    assert_eq!(
        backend.get_container_status(TEST_ID).await.unwrap(),
        ContainerStatus::Absent,
        "an expired lease leaves no container behind"
    );
    assert_eq!(
        backend
            .find_available_id(TEST_ID, TEST_ID + 1)
            .await
            .unwrap(),
        TEST_ID,
        "the destroyed workload's id is free again"
    );
}

// ── a `docker` lease ────────────────────────────────────────────────────────

/// Well outside the default lease id range and apart from `TEST_ID`, so the
/// two ignored tests can run in one process.
const DOCKER_TEST_ID: u32 = 59002;

/// Brings a `docker` CLI and nothing else, so what it finds at
/// /var/run/docker.sock is what the lease gave it.
const CLI_IMAGE: &str = "docker:28-cli";

fn host_docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("invoke docker CLI")
}

fn host_docker_ok(args: &[&str]) -> String {
    let out = host_docker(args);
    assert!(
        out.status.success(),
        "docker {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn exists(kind: &str, name: &str) -> bool {
    let args: Vec<&str> = if kind == "container" {
        vec!["inspect", name]
    } else {
        vec![kind, "inspect", name]
    };
    host_docker(&args).status.success()
}

fn docker_config() -> ContainerConfig {
    ContainerConfig {
        id: DOCKER_TEST_ID,
        name: toon_provider::compute::container_name(DOCKER_TEST_ID),
        image: CLI_IMAGE.to_string(),
        cpu_millicores: 1000,
        memory_mb: 256,
        storage_gb: 1,
        ssh_key: None,
        host_port: None,
        ports: Vec::new(),
        env: HashMap::new(),
        entrypoint: None,
        args: vec!["sleep".to_string(), "300".to_string()],
        data_path: None,
        capabilities: vec!["docker".to_string()],
        egress: None,
    }
}

#[tokio::test]
#[ignore = "needs a Docker daemon; run with `cargo test -- --ignored`"]
async fn a_docker_lease_gets_a_daemon_of_its_own_bounded_as_one_unit_and_destroyed_with_it() {
    // Spec §4.4, on a real daemon: the workload finds a daemon at
    // /var/run/docker.sock with no DOCKER_HOST, as any uid; that daemon
    // pulls and runs a container (its egress); it is never the host's; the
    // workload container holds no privilege; the pair and everything nested
    // sit under one cgroup limit; and termination leaves nothing behind.
    for image in [CLI_IMAGE, toon_provider::docker::DIND_IMAGE] {
        host_docker_ok(&["pull", "-q", image]);
    }
    let backend = DockerBackend::new();
    let name = toon_provider::compute::container_name(DOCKER_TEST_ID);
    let sidecar = format!("{}-dind", name);

    backend
        .delete_container(DOCKER_TEST_ID)
        .await
        .expect("pre-clean");
    assert!(!exists("container", &sidecar), "a clean start");

    backend
        .create_container(&docker_config())
        .await
        .expect("create the lease");
    assert_eq!(
        backend.get_container_status(DOCKER_TEST_ID).await.unwrap(),
        ContainerStatus::Running
    );

    // The privilege sits in the provider's sidecar, and only there.
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{.HostConfig.Privileged}}", &sidecar]),
        "true"
    );
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{.HostConfig.Privileged}}", &name]),
        "false"
    );
    let binds = host_docker_ok(&["inspect", "-f", "{{json .HostConfig.Binds}}", &name]);
    assert!(
        !binds.contains("docker.sock") && !binds.contains(":/var/run/docker.sock"),
        "the workload mounts a volume, never a socket file: {}",
        binds
    );
    assert!(
        binds.contains(&format!("{}-run:/var/run", name)),
        "{}",
        binds
    );

    // A daemon of the lease's own, found where a client looks, by any uid,
    // and it is not the host's: the host daemon does not know the container
    // the nested one is about to run.
    let host_id = host_docker_ok(&["info", "--format", "{{.ID}}"]);
    let nested_id = host_docker_ok(&["exec", &name, "docker", "info", "--format", "{{.ID}}"]);
    assert_ne!(
        nested_id, host_id,
        "the lease's daemon is not the provider's"
    );
    host_docker_ok(&[
        "exec",
        "-u",
        "12345",
        &name,
        "docker",
        "version",
        "--format",
        "{{.Server.Version}}",
    ]);
    let hello = host_docker_ok(&["exec", &name, "docker", "run", "--rm", "hello-world"]);
    assert!(hello.contains("Hello from Docker!"), "{}", hello);
    host_docker_ok(&[
        "exec",
        &name,
        "docker",
        "run",
        "-d",
        "--name",
        "nested",
        "alpine:3.20",
        "sleep",
        "200",
    ]);
    assert!(
        !host_docker_ok(&["ps", "-a", "--format", "{{.Names}}"])
            .lines()
            .any(|l| l == "nested"),
        "a nested container is invisible to the host daemon"
    );

    // One unit: on a systemd/cgroup v2 host the listing's limits are on the
    // lease's parent, and the workload, the sidecar and the nested container
    // all live under it.
    let layout = host_docker_ok(&["info", "--format", "{{.CgroupDriver}} {{.CgroupVersion}}"]);
    if layout == "systemd 2" {
        let slice = format!("/sys/fs/cgroup/toon.slice/{}.slice", name);
        let read =
            |f: &str| std::fs::read_to_string(format!("{}/{}", slice, f)).unwrap_or_default();
        assert_eq!(read("cpu.max").trim(), "100000 100000", "1000 millicores");
        assert_eq!(read("memory.max").trim(), "268435456", "256 MiB");
        let mut scopes = 0;
        let mut nested_under_sidecar = false;
        for entry in walkdir(&slice) {
            if entry.ends_with("cgroup.procs") {
                let procs = std::fs::read_to_string(&entry).unwrap_or_default();
                if !procs.trim().is_empty() {
                    scopes += 1;
                    if entry.contains(".scope/docker/") {
                        nested_under_sidecar = true;
                    }
                }
            }
        }
        assert!(
            scopes >= 3,
            "workload, sidecar and nested container all hold processes under {}: {}",
            slice,
            scopes
        );
        assert!(
            nested_under_sidecar,
            "the nested container is inside the unit"
        );
    } else {
        eprintln!(
            "cgroup layout {:?}: the unit limit is not asserted here",
            layout
        );
    }

    // Stop and start both, and the daemon is back before the workload is.
    backend.stop_container(DOCKER_TEST_ID).await.expect("stop");
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{.State.Running}}", &sidecar]),
        "false"
    );
    backend
        .start_container(DOCKER_TEST_ID)
        .await
        .expect("start");
    host_docker_ok(&[
        "exec",
        &name,
        "docker",
        "version",
        "--format",
        "{{.Server.Version}}",
    ]);

    // Termination takes the sidecar, its volumes and its network with it.
    backend
        .delete_container(DOCKER_TEST_ID)
        .await
        .expect("delete");
    assert_eq!(
        backend.get_container_status(DOCKER_TEST_ID).await.unwrap(),
        ContainerStatus::Absent
    );
    assert!(!exists("container", &sidecar), "the sidecar is gone");
    assert!(!exists("container", &format!("{}-seed", name)));
    for volume in ["run", "docker"] {
        assert!(
            !exists("volume", &format!("{}-{}", name, volume)),
            "the {} volume is gone",
            volume
        );
    }
    assert!(
        !exists("network", &format!("{}-net", name)),
        "the network is gone"
    );
}

fn walkdir(root: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path.to_string_lossy().to_string());
            }
        }
    }
    out
}

// ── a hidden lease ──────────────────────────────────────────────────────────

use std::io::Read;
use std::time::{Duration, Instant};

use toon_provider::compute::{EgressPolicy, PortMapping};
use toon_provider::docker::HIDDEN_SIDECAR_IMAGE;

/// Apart from the other ids, so every ignored test can run in one process.
const HIDDEN_TEST_ID: u32 = 59003;
const HIDDEN_DOCKER_TEST_ID: u32 = 59004;

/// Where the stub gateway listens: the `TransPort` number the sandbox's anon
/// daemon uses, so the dial the test makes is the dial a workload would.
const GATEWAY_PORT: u16 = 9040;

/// The egress network as the sandbox's `hs` profile makes it — internal, a
/// fixed subnet — with a stub in the anon daemon's place: a container at
/// the gateway address that answers on the TransPort number and forwards
/// nothing, so a clearnet dial that reaches it goes nowhere. One per test,
/// on its own subnet, so the ignored tests can run at once.
struct EgressNet {
    policy: EgressPolicy,
    subnet: String,
    stub: String,
}

/// The default bridge's subnet on a stock daemon: what no hidden
/// namespace may have a route into.
const DEFAULT_BRIDGE_SUBNET: &str = "172.17.";

impl EgressNet {
    fn create(id: u32) -> Self {
        let network = format!("toon-test-egress-{}", id);
        let octet = id % 200 + 10;
        let subnet = format!("10.{}.0.0/24", octet);
        let gateway = format!("10.{}.0.2", octet);
        let stub = format!("{}-gateway", network);
        host_docker(&["rm", "-f", &stub]);
        host_docker(&["network", "rm", &network]);
        host_docker_ok(&[
            "network",
            "create",
            "--internal",
            "--subnet",
            &subnet,
            &network,
        ]);
        host_docker_ok(&[
            "run",
            "-d",
            "--name",
            &stub,
            "--network",
            &network,
            "--ip",
            &gateway,
            IMAGE,
            "sh",
            "-c",
            &format!("nc -lk -p {} -e echo hello-from-gateway", GATEWAY_PORT),
        ]);
        Self {
            policy: EgressPolicy { network, gateway },
            subnet,
            stub,
        }
    }

    fn remove(&self) {
        host_docker(&["rm", "-f", &self.stub]);
        host_docker(&["network", "rm", &self.policy.network]);
    }
}

/// `docker exec` in a container, answering (success, stdout).
fn exec(container: &str, args: &[&str]) -> (bool, String) {
    let mut argv = vec!["exec", container];
    argv.extend(args);
    let out = host_docker(&argv);
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    )
}

/// What a host-published port answers, dialed from this process as the anon
/// daemon's forward would dial it; retried, since the listeners behind it
/// are started by the workload's own command.
fn dial_published(port: u16) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer);
            if !answer.trim().is_empty() {
                return Some(answer.trim().to_string());
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// The routes a hidden namespace must have and no other: everything via the
/// gateway, and the egress subnet on-link. In particular nothing through
/// the default bridge or any other network of the host's.
fn assert_confined(container: &str, net: &EgressNet, what: &str) {
    let (ok, routes) = exec(container, &["ip", "-4", "route"]);
    assert!(ok, "{}: ip route", what);
    let lines: Vec<&str> = routes.lines().collect();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with(&format!("default via {} ", net.policy.gateway))),
        "{}: the only way out is the gateway: {}",
        what,
        routes
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with(&format!("{} dev ", net.subnet))),
        "{}: the egress subnet is on-link: {}",
        what,
        routes
    );
    assert!(
        !routes.contains(DEFAULT_BRIDGE_SUBNET),
        "{}: no route via the default bridge: {}",
        what,
        routes
    );
}

fn hidden_config(net: &EgressNet) -> ContainerConfig {
    ContainerConfig {
        id: HIDDEN_TEST_ID,
        name: toon_provider::compute::container_name(HIDDEN_TEST_ID),
        host_port: Some(59993),
        ports: vec![PortMapping {
            host_port: 59994,
            container_port: 7777,
            protocol: "tcp".to_string(),
        }],
        // Two listeners in the workload's own namespace, one per published
        // port, each answering who it is.
        entrypoint: Some("sh".to_string()),
        args: vec![
            "-c".to_string(),
            "nc -lk -p 22 -e echo hello-from-ssh & nc -lk -p 7777 -e echo hello-from-port & wait"
                .to_string(),
        ],
        egress: Some(net.policy.clone()),
        ..config()
    }
}

#[tokio::test]
#[ignore = "needs a Docker daemon; run with `cargo test -- --ignored`"]
async fn a_hidden_workload_has_no_network_path_except_the_egress_gateway() {
    // Spec §10 on a real daemon: from inside the workload a direct clearnet
    // dial fails, a dial to the gateway succeeds, and there is no route via
    // the default bridge; the workload cannot change any of it; its SSH
    // forward and port are still published on the host; the confinement
    // survives a stop and start; and termination leaves nothing behind but
    // the operator's network.
    pull_image().await;
    host_docker_ok(&["pull", "-q", HIDDEN_SIDECAR_IMAGE]);
    let backend = DockerBackend::new();
    let name = toon_provider::compute::container_name(HIDDEN_TEST_ID);
    let owner = format!("{}-egress", name);
    let forwarder = format!("{}-ingress", name);

    // Leave nothing behind from an earlier interrupted run — the lease
    // first, since its containers hold the network.
    backend
        .delete_container(HIDDEN_TEST_ID)
        .await
        .expect("pre-clean");
    let net = EgressNet::create(HIDDEN_TEST_ID);
    backend
        .create_container(&hidden_config(&net))
        .await
        .expect("create the hidden lease");
    assert_eq!(
        backend.get_container_status(HIDDEN_TEST_ID).await.unwrap(),
        ContainerStatus::Running
    );

    // The workload has no network of its own: it is in the owner's
    // namespace, and the owner is on the egress network and nothing else,
    // with the gateway as its resolver.
    let owner_id = host_docker_ok(&["inspect", "-f", "{{.Id}}", &owner]);
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{.HostConfig.NetworkMode}}", &name]),
        format!("container:{}", owner_id)
    );
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{json .NetworkSettings.Networks}}", &name]),
        "{}"
    );
    let owner_networks = host_docker_ok(&[
        "inspect",
        "-f",
        "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
        &owner,
    ]);
    assert_eq!(owner_networks.trim(), net.policy.network);
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{json .HostConfig.Dns}}", &owner]),
        format!("[\"{}\"]", net.policy.gateway)
    );
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{json .HostConfig.CapAdd}}", &name]),
        "null",
        "the workload holds no NET_ADMIN"
    );
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{.HostConfig.Privileged}}", &owner]),
        "false"
    );

    // The observable, from inside.
    assert_confined(&name, &net, "the workload");
    let (reached, _) = exec(&name, &["nc", "-z", "-w", "3", "1.1.1.1", "80"]);
    assert!(!reached, "a direct clearnet dial fails");
    let (ok, answer) = exec(
        &name,
        &[
            "sh",
            "-c",
            &format!("echo | nc -w 3 {} {}", net.policy.gateway, GATEWAY_PORT),
        ],
    );
    assert!(ok && answer == "hello-from-gateway", "{} {}", ok, answer);
    let (changed, _) = exec(&name, &["ip", "route", "del", "default"]);
    assert!(!changed, "the workload cannot change its routes");
    let (changed, _) = exec(
        &name,
        &["ip", "route", "add", "default", "via", "172.17.0.1"],
    );
    assert!(!changed, "nor add one");

    // Still published on the host, at the numbers a public lease would
    // use — by the forwarder, not the workload.
    assert_eq!(
        dial_published(59993).as_deref(),
        Some("hello-from-ssh"),
        "the SSH forward"
    );
    assert_eq!(
        dial_published(59994).as_deref(),
        Some("hello-from-port"),
        "the published port"
    );
    assert_eq!(host_docker_ok(&["port", &name]), "");
    let published = host_docker_ok(&["port", &forwarder]);
    assert!(
        published.contains("59993/tcp") && published.contains("59994/tcp"),
        "{}",
        published
    );
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{.HostConfig.Privileged}}", &forwarder]),
        "false"
    );

    // Stop and start: the namespace comes back with its route before the
    // workload joins it, and the ports come back.
    backend.stop_container(HIDDEN_TEST_ID).await.expect("stop");
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{.State.Running}}", &owner]),
        "false"
    );
    backend
        .start_container(HIDDEN_TEST_ID)
        .await
        .expect("start");
    assert_confined(&name, &net, "the workload after a restart");
    assert_eq!(dial_published(59993).as_deref(), Some("hello-from-ssh"));

    // Termination takes the owner and the forwarder with it; the network
    // is the operator's and stays, gateway and all.
    backend
        .delete_container(HIDDEN_TEST_ID)
        .await
        .expect("delete");
    assert_eq!(
        backend.get_container_status(HIDDEN_TEST_ID).await.unwrap(),
        ContainerStatus::Absent
    );
    assert!(!exists("container", &owner), "the owner is gone");
    assert!(!exists("container", &forwarder), "the forwarder is gone");
    assert!(
        exists("network", &net.policy.network),
        "the operator's network stays"
    );
    assert_eq!(
        host_docker_ok(&["inspect", "-f", "{{.State.Running}}", &net.stub]),
        "true"
    );
    net.remove();
}

#[tokio::test]
#[ignore = "needs a Docker daemon; run with `cargo test -- --ignored`"]
async fn a_hidden_docker_lease_confines_its_daemon_and_everything_nested() {
    // Spec §4.4 on a Hidden Provider: the lease's own network is internal,
    // the sidecar's only way out is the gateway, and so a container the
    // nested daemon runs can reach the gateway and nothing on the clearnet.
    for image in [
        CLI_IMAGE,
        toon_provider::docker::DIND_IMAGE,
        HIDDEN_SIDECAR_IMAGE,
        IMAGE,
    ] {
        host_docker_ok(&["pull", "-q", image]);
    }
    let backend = DockerBackend::new();
    let name = toon_provider::compute::container_name(HIDDEN_DOCKER_TEST_ID);
    let sidecar = format!("{}-dind", name);
    let lease_network = format!("{}-net", name);

    backend
        .delete_container(HIDDEN_DOCKER_TEST_ID)
        .await
        .expect("pre-clean");
    let net = EgressNet::create(HIDDEN_DOCKER_TEST_ID);
    backend
        .create_container(&ContainerConfig {
            id: HIDDEN_DOCKER_TEST_ID,
            name: name.clone(),
            host_port: Some(59992),
            egress: Some(net.policy.clone()),
            ..docker_config()
        })
        .await
        .expect("create the hidden docker lease");

    assert_eq!(
        host_docker_ok(&["network", "inspect", "-f", "{{.Internal}}", &lease_network]),
        "true",
        "the lease's own network gives no route out"
    );
    assert_confined(&sidecar, &net, "the sidecar");
    assert_confined(&name, &net, "the workload");
    // The workload still finds its daemon, and the sidecar by name.
    host_docker_ok(&[
        "exec",
        &name,
        "docker",
        "version",
        "--format",
        "{{.Server.Version}}",
    ]);
    let (ok, hosts) = exec(&name, &["getent", "hosts", "docker"]);
    assert!(
        ok && hosts.contains("docker"),
        "`docker` resolves on the lease's network: {}",
        hosts
    );

    // Nothing nested can be pulled (there is no clearnet), so an image is
    // loaded into the lease's daemon by hand; what it runs sees the
    // gateway and nothing else.
    let tar = std::env::temp_dir().join(format!("toon-test-{}.tar", HIDDEN_DOCKER_TEST_ID));
    host_docker_ok(&["save", "-o", tar.to_str().unwrap(), IMAGE]);
    host_docker_ok(&[
        "cp",
        tar.to_str().unwrap(),
        &format!("{}:/tmp/image.tar", name),
    ]);
    let _ = std::fs::remove_file(&tar);
    host_docker_ok(&["exec", &name, "docker", "load", "-i", "/tmp/image.tar"]);
    let (reached, _) = exec(
        &name,
        &[
            "docker", "run", "--rm", IMAGE, "nc", "-z", "-w", "3", "1.1.1.1", "80",
        ],
    );
    assert!(!reached, "a nested container's clearnet dial fails");
    let (ok, answer) = exec(
        &name,
        &[
            "docker",
            "run",
            "--rm",
            IMAGE,
            "sh",
            "-c",
            &format!("echo | nc -w 3 {} {}", net.policy.gateway, GATEWAY_PORT),
        ],
    );
    assert!(
        ok && answer == "hello-from-gateway",
        "a nested container reaches the gateway: {} {}",
        ok,
        answer
    );

    backend
        .delete_container(HIDDEN_DOCKER_TEST_ID)
        .await
        .expect("delete");
    assert_eq!(
        backend
            .get_container_status(HIDDEN_DOCKER_TEST_ID)
            .await
            .unwrap(),
        ContainerStatus::Absent
    );
    for extra in ["dind", "egress", "ingress"] {
        assert!(
            !exists("container", &format!("{}-{}", name, extra)),
            "the {} is gone",
            extra
        );
    }
    assert!(!exists("network", &lease_network));
    net.remove();
}
