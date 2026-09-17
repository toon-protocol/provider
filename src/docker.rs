// Docker compute backend. Shells out to the `docker` CLI.
//
// No state is persisted here: the container's existence on the host IS the
// state, and `find_available_id` scans for `toon-<n>`. The lease that pays for
// it is bookkeeping the provider keeps separately (`provider::persistence`).
//
// CAPABILITIES (spec §4.4). An ordinary workload gets a name, CPU and memory
// limits, its port forwards, its environment and a NAMED VOLUME — never
// `--privileged`, never a `--device`, never a host path. The daemon socket
// this backend itself drives is on the provider's side of the workload
// boundary and is never mounted into a workload: a provider that did mount it
// would be handing one tenant every other tenant's containers.
//
// A listing that grants `docker` gets the spec's reference shape, a per-lease
// `dind` sidecar, built from four host-side objects that all carry the
// workload's name and are all destroyed with it:
//
//   toon-<id>-dind     the sidecar: the official `dind` image pinned by digest
//                      (`DIND_IMAGE`), `--privileged` — the one privileged
//                      container per lease, and it is the PROVIDER'S, running
//                      no tenant code. Its daemon listens on ONE unix socket
//                      and no TCP port.
//   toon-<id>-run      a volume holding that socket and nothing else of the
//                      daemon's: the sidecar mounts it at `/toon/run`, the
//                      workload at `/var/run`, so the workload finds
//                      `/var/run/docker.sock` with no `DOCKER_HOST` set. A
//                      volume rather than a bind of the socket file, because
//                      a daemon restart re-creates the socket and a mounted
//                      directory follows that where a mounted file would go
//                      stale. Mounting the workload's `/var/run` would hide
//                      whatever its image built there (`/run/sshd` on a
//                      Debian sshd image, say), so before the daemon starts
//                      the volume is SEEDED with the image's own `/var/run`
//                      contents, read out of a never-started container of
//                      that image; the daemon then adds its socket beside
//                      them. The socket is made 0666 by the sidecar's own
//                      command each time it starts: every process in the
//                      workload is the tenant's and the daemon is the
//                      lease's, so there is no one to keep out.
//   toon-<id>-docker   a volume for the daemon's `/var/lib/docker`: nested
//                      image layers, containers and volumes live here, on
//                      the provider's disk, and are removed with the lease
//                      (§4.4 "scope"). The provider's own image cache is not
//                      shared in; what the daemon pulls is the lease's
//                      egress.
//   toon-<id>-net      a bridge network the pair shares. The sidecar is on
//                      it as `docker`, so a port a nested container
//                      publishes is reachable from the workload at
//                      `docker:<port>` — the convention CI images expect.
//                      The workload's own SSH forward and published ports
//                      are published on the host as for any lease.
//
// RESOURCE ACCOUNTING. §4.4 requires `cpu_millicores` and `memory_mb` to
// bound the workload, its daemon and every nested container AS ONE UNIT. Both
// containers are created under one per-lease cgroup parent (`--cgroup-parent
// toon-<id>.slice` with the systemd driver; see `CgroupLayout`), and the
// listing's limits are written to that parent's `cpu.max`, `memory.max` and
// `memory.swap.max` — through a short-lived helper container that
// bind-mounts the host's cgroup tree, because the provider may itself be a
// container with a read-only view of its own cgroup and no more. The nested
// daemon's containers are its cgroup children, so they land inside the same
// parent. Each container ALSO carries the listing's limits itself, so the
// lease is bounded even where the parent's limit cannot be written (cgroup
// v1, `CgroupLayout::Unsupported`): then the pair is bounded at twice the
// listing, per container, and the provider logs that deviation at first
// use. `storage_gb` has no hard quota here, for nested layers or for the
// workload's own — the same position as before this capability.
//
// The nested daemon's default bridge is moved to `172.16.0.0/16`
// (`NESTED_BRIDGE_IP`). Docker's own default, `172.17.0.1/16`, is also the
// address the HOST daemon's embedded DNS forwards to on a host whose
// resolver is loopback-only (systemd-resolved); a nested `docker0` on the
// same subnet captures those forwards inside the sidecar's namespace and
// every nested pull fails to resolve. `172.16.0.0/16` is outside every pool
// the host daemon hands out by default.
//
// `nesting` is still refused at config load (`capabilities::grant_refusal`):
// it would mean tenant code holding kernel privileges this backend never
// hands out.
//
// A HIDDEN LEASE (spec §10, ADR 0008; TOON_Network #41) is one whose config
// carries an `EgressPolicy`: the name of an INTERNAL Docker network whose
// only way out is the `anon` daemon, and that daemon's IP address on it. The
// workload must have no network path except that gateway, and the policy
// must hold no matter what the image does — so it is enforced by the kernel's
// routing table and Docker's own isolation of an internal network, never by
// an environment variable or a proxy setting. Two facts about Docker decide
// the shape (both verified against the daemon this backend is tested on):
//
//   * A container on an internal network gets NO default route, and the host
//     DROPS anything it forwards off that bridge. A container on any
//     non-internal network gets `default via <the host's bridge>` back every
//     time its network namespace is created — after `docker start`, after a
//     restart-policy restart, after a host reboot. So a hidden workload is
//     attached to internal networks ONLY, and can never fall open.
//   * Docker does not publish ports for a container that is on internal
//     networks only. The lease's SSH forward and published ports must still
//     be on the host (the per-lease `.anyone` address is forwarded to them),
//     so something ELSE publishes them and hands the connections on.
//
// Hence two more objects per hidden lease, both the PROVIDER'S, running no
// tenant code, from one small image pinned by digest (`HIDDEN_SIDECAR_IMAGE`):
//
//   toon-<id>-egress   owns the workload's network namespace: it is on the
//                      egress network (and, for a `docker` lease, on the
//                      lease's own network too), its DNS is the gateway, and
//                      its only privilege is `NET_ADMIN`, spent once on
//                      `ip route replace default via <gateway>`; then it
//                      sleeps. The workload joins it (`--network container:`)
//                      and so has that routing table and that resolver, holds
//                      no `NET_ADMIN` of its own, and cannot change either.
//                      Because the namespace is this container's, a workload
//                      that crashes and is restarted comes back INTO it, with
//                      the route still there; the owner's own restart re-runs
//                      the command.
//   toon-<id>-ingress  the forwarder: on the provider's ordinary network with
//                      the lease's host ports published — exactly the ports a
//                      public lease would publish, at the same numbers — and
//                      on the egress network beside the owner, forwarding each
//                      one to the workload's container port. TCP only: a
//                      hidden-service address carries nothing else. It has a
//                      default route out, so a connection the daemon makes to
//                      a host port is answered; nothing on the egress network
//                      can route THROUGH it (forwarding is off, it NATs
//                      nothing, it listens on the lease's ports and no other).
//
// A `docker` lease that is hidden gets the same: its `toon-<id>-net` is made
// internal, and the sidecar is on the egress network too with the gateway as
// its DNS and its default route (set by its own command; it is privileged
// already), so every nested pull leaves through `anon` as §4.4 requires.
//
// The ONE observable a tenant can check from inside: a direct clearnet dial
// fails, a dial to the gateway succeeds, and `ip route` names nothing but the
// egress network's subnet and the gateway. Caveat for the host: Docker's
// isolation of an internal network is a FORWARD-chain drop of anything off
// the bridge that is not addressed within its subnet; on a host with
// `br_netfilter` loaded and `bridge-nf-call-iptables = 1`, bridged frames
// traverse that chain too and the workload's transparently-proxied packets
// (addressed to the real destination, sent to the gateway's MAC) would be
// dropped with them. The reference host has no `br_netfilter`; one that does
// must accept `-i <egress bridge> -o <egress bridge>` in `DOCKER-USER`.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::capabilities;
use crate::compute::{
    container_name, id_from_container_name, ComputeBackend, ContainerConfig, ContainerStatus,
    EgressPolicy, NodeStatus, SSH_CONTAINER_PORT, SSH_PUBLIC_KEY_ENV, WORKLOAD_NAME_PREFIX,
};

/// The image every lease's daemon runs: the official `dind`, pinned by digest
/// so that a listing sells the same daemon tomorrow that it sold today, and
/// so that a tag moving under the provider cannot change what a privileged
/// component of its own runs. An operator SHOULD pre-pull it: the first
/// `docker` lease otherwise pays for the pull.
pub const DIND_IMAGE: &str =
    "docker:28-dind@sha256:2a232a42256f70d78e3cc5d2b5d6b3276710a0de0596c145f627ecfae90282ac";

/// The image a hidden lease's two sidecars run (the module docs): Alpine,
/// pinned by digest, for its BusyBox `ip` (the owner's one route) and `nc`
/// (the forwarder's listeners). Multi-arch, so the digest is the index's.
/// Small, and pulled once; an operator SHOULD still pre-pull it, as with
/// `DIND_IMAGE`, or the first hidden lease pays for it.
pub const HIDDEN_SIDECAR_IMAGE: &str =
    "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

/// The capability the namespace owner holds, and the only one: what
/// `ip route replace` needs.
const NET_ADMIN: &str = "NET_ADMIN";

/// How long the owner may take to show its default route after it starts.
/// It is one `ip` command; a container that has not run it in this long has
/// failed to, and the lease is refused rather than started unconfined.
const ROUTE_READY_TIMEOUT: Duration = Duration::from_secs(15);
const ROUTE_READY_POLL: Duration = Duration::from_millis(200);

/// Where the sidecar mounts the socket volume. A directory of its own rather
/// than the daemon's `/var/run`, so the daemon's pid file and its containerd
/// socket stay private to the sidecar and only the API socket is shared.
const SIDECAR_SOCKET_DIR: &str = "/toon/run";

/// Where the workload mounts the same volume: the directory of the
/// conventional socket path (spec §4.4).
const WORKLOAD_SOCKET_DIR: &str = "/var/run";

const SOCKET_FILE: &str = "docker.sock";

/// The nested daemon's own bridge, off Docker's default `172.17.0.0/16` (see
/// the module docs for why), plus the pool its user-defined networks draw
/// from.
const NESTED_BRIDGE_IP: &str = "172.16.0.1/24";
const NESTED_ADDRESS_POOL: &str = "base=172.16.0.0/16,size=24";

/// Where the limits helper sees the host's cgroup tree.
const HELPER_CGROUP_MOUNT: &str = "/host-cgroup";

/// How long a fresh daemon may take to answer on its socket before the lease
/// is given up. Cold, on this backend's reference host, it takes about six
/// seconds; a loaded host may take longer, and a lease that never gets its
/// daemon is one the tenant paid for and cannot use.
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(90);
const DAEMON_READY_POLL: Duration = Duration::from_millis(500);

/// How long `docker stop` gives the sidecar's daemon before killing it. Short
/// on purpose: a lease ends synchronously inside a terminate request that a
/// connector waits at most 30 s for, and the workload's own stop already
/// takes up to Docker's default 10 s. The daemon's state is either
/// disposable (the lease is ending) or recovered by the next start (dind
/// clears its stale pid file), so a killed daemon costs nothing lasting.
const SIDECAR_STOP_GRACE_S: &str = "5";

/// The CPU period Docker's `--cpus` uses, so the parent's `cpu.max` reads in
/// the same units as its children's.
const CPU_PERIOD_US: u64 = 100_000;

/// The sidecar's name and the names of the lease's other objects, all derived
/// from the workload's so `find_available_id` (which parses `toon-<n>` and
/// ignores the rest) never mistakes one for a workload.
fn sidecar_name(id: u32) -> String {
    format!("{}-dind", container_name(id))
}

fn socket_volume(id: u32) -> String {
    format!("{}-run", container_name(id))
}

fn daemon_volume(id: u32) -> String {
    format!("{}-docker", container_name(id))
}

fn network_name(id: u32) -> String {
    format!("{}-net", container_name(id))
}

/// The never-started container the socket volume is seeded from.
fn seed_name(id: u32) -> String {
    format!("{}-seed", container_name(id))
}

fn data_volume(id: u32) -> String {
    format!("{}-data", container_name(id))
}

/// The hidden lease's namespace owner (the module docs).
fn egress_name(id: u32) -> String {
    format!("{}-egress", container_name(id))
}

/// The hidden lease's forwarder.
fn ingress_name(id: u32) -> String {
    format!("{}-ingress", container_name(id))
}

fn grants_docker(config: &ContainerConfig) -> bool {
    capabilities::advertises(&config.capabilities, capabilities::DOCKER)
}

/// True when the lease has anything beside its workload: a `docker` grant's
/// sidecar, a hidden lease's owner and forwarder, or both.
fn has_extras(config: &ContainerConfig) -> bool {
    grants_docker(config) || config.egress.is_some()
}

/// The one route a hidden namespace has: everything via the gateway. `ip
/// route replace` so it also overwrites a default some other endpoint might
/// have set — a hidden namespace's endpoints are all on internal networks
/// and set none, but the intent is "this and nothing else", not "add".
fn egress_route_command(policy: &EgressPolicy) -> String {
    format!("ip route replace default via {}", policy.gateway)
}

/// The sidecar's command: the `dind` entrypoint with the daemon on ONE unix
/// socket in the shared directory and NO TCP listener (the entrypoint only
/// adds one when given no `dockerd` arguments), wrapped so the socket is made
/// world-usable as soon as it exists — on every start, restarts included, so
/// the mode cannot regress. `TERM` is forwarded so `docker stop` still shuts
/// the daemon down cleanly; the second `wait` collects it after the trap.
///
/// On a hidden lease the daemon's egress route comes first, before anything
/// could be pulled: the sidecar is on internal networks only, so until then
/// it has no route at all, and being privileged it needs no helper to set
/// one. A route that cannot be set exits the command, and so fails the
/// lease. `|| exit 1;`, not `&&`: `&&` binds tighter than the `&` that
/// backgrounds the daemon, and would background the whole list — leaving
/// `$!` naming a subshell rather than the daemon the trap must reach.
fn sidecar_command(egress: Option<&EgressPolicy>) -> String {
    let socket = format!("{}/{}", SIDECAR_SOCKET_DIR, SOCKET_FILE);
    let route = egress
        .map(|policy| format!("{} || exit 1; ", egress_route_command(policy)))
        .unwrap_or_default();
    format!(
        "{route}dockerd-entrypoint.sh dockerd --host=unix://{socket} --bip={bip} \
         --default-address-pool {pool} & pid=$!; \
         trap 'kill -TERM \"$pid\" 2>/dev/null' TERM INT; \
         while kill -0 \"$pid\" 2>/dev/null && ! [ -S {socket} ]; do sleep 0.2; done; \
         chmod 0666 {socket} 2>/dev/null; \
         wait \"$pid\"; wait \"$pid\"",
        route = route,
        socket = socket,
        bip = NESTED_BRIDGE_IP,
        pool = NESTED_ADDRESS_POOL,
    )
}

/// The owner's command: the route, then nothing, for as long as the lease
/// lives. `exec` so the sleep is pid 1 and a stop is one signal.
fn owner_command(policy: &EgressPolicy) -> String {
    format!("{} && exec sleep infinity", egress_route_command(policy))
}

/// The forwarder's command: one BusyBox `nc` server per published TCP port,
/// each forking a client to the owner's name (resolved per connection by
/// Docker's embedded DNS on the egress network they share, so the workload's
/// address is never copied anywhere) at the workload's container port.
fn forwarder_command(id: u32, ports: &[(u16, u16)]) -> String {
    let owner = egress_name(id);
    let listeners: Vec<String> = ports
        .iter()
        .map(|(host_port, container_port)| {
            format!(
                "nc -lk -p {} -e nc {} {} &",
                host_port, owner, container_port
            )
        })
        .collect();
    format!("{} wait", listeners.join(" "))
}

/// The TCP ports a hidden lease publishes, as (host port, container port):
/// the SSH forward first, then the tenant's. UDP is left out — a
/// hidden-service address cannot carry it, so a forward would reach nothing.
fn forwarded_ports(config: &ContainerConfig) -> Vec<(u16, u16)> {
    let mut ports: Vec<(u16, u16)> = config
        .host_port
        .map(|host_port| (host_port, SSH_CONTAINER_PORT))
        .into_iter()
        .collect();
    ports.extend(
        config
            .ports
            .iter()
            .filter(|p| p.protocol.eq_ignore_ascii_case("tcp"))
            .map(|p| (p.host_port, p.container_port)),
    );
    ports
}

/// How the host daemon lays out cgroups, which decides what `--cgroup-parent`
/// may name and where that parent then is under `/sys/fs/cgroup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CgroupLayout {
    /// The systemd driver on cgroup v2: a parent is a slice, and systemd
    /// nests `toon-<id>.slice` under `toon.slice` by its dash convention, so
    /// every lease sits under one tree. Verified on the reference host.
    Systemd,
    /// The cgroupfs driver on cgroup v2: a parent is an absolute path under
    /// the cgroup root. Mapped by Docker's documented rule; not exercised by
    /// this backend's own tests, which run on a systemd host.
    Cgroupfs,
    /// cgroup v1, or a daemon that would not say: no parent this backend
    /// knows how to bound. Each container still carries the listing's
    /// limits, so the lease is bounded at twice them.
    Unsupported,
}

impl CgroupLayout {
    /// From `docker info --format '{{.CgroupDriver}} {{.CgroupVersion}}'`.
    fn parse(info: &str) -> Self {
        let mut words = info.split_whitespace();
        match (words.next(), words.next()) {
            (Some("systemd"), Some("2")) => Self::Systemd,
            (Some("cgroupfs"), Some("2")) => Self::Cgroupfs,
            _ => Self::Unsupported,
        }
    }

    /// The `--cgroup-parent` value for a lease, or `None` when there is no
    /// parent worth naming.
    fn parent_arg(self, id: u32) -> Option<String> {
        match self {
            Self::Systemd => Some(format!("{}.slice", container_name(id))),
            Self::Cgroupfs => Some(format!("/{}", container_name(id))),
            Self::Unsupported => None,
        }
    }

    /// Where that parent is, relative to the cgroup root.
    fn parent_path(self, id: u32) -> Option<String> {
        match self {
            Self::Systemd => Some(format!(
                "{}.slice/{}.slice",
                WORKLOAD_NAME_PREFIX.trim_end_matches('-'),
                container_name(id)
            )),
            Self::Cgroupfs => Some(container_name(id)),
            Self::Unsupported => None,
        }
    }
}

pub struct DockerBackend {
    /// `None` = the host's default `bridge`. A `docker` lease ignores it: its
    /// pair runs on the lease's own network. A hidden lease's workload
    /// ignores it too — it is on the egress network and nothing else — and
    /// its forwarder is what sits here, publishing the lease's ports.
    network: Option<String>,
    /// Asked of the daemon once, on the first lease that needs it.
    cgroup_layout: OnceCell<CgroupLayout>,
}

impl DockerBackend {
    pub fn new() -> Self {
        Self {
            network: None,
            cgroup_layout: OnceCell::new(),
        }
    }

    pub fn with_network(network: impl Into<String>) -> Self {
        Self {
            network: Some(network.into()),
            cgroup_layout: OnceCell::new(),
        }
    }

    /// The limits every container of the lease carries itself.
    fn limit_flags(config: &ContainerConfig) -> Vec<String> {
        vec![
            "--cpus".into(),
            format!("{:.3}", f64::from(config.cpu_millicores) / 1000.0),
            "--memory".into(),
            format!("{}m", config.memory_mb),
        ]
    }

    /// The full `docker` argv for a workload. Separate from `create_container`
    /// so a unit test can assert on the real argv without a daemon.
    fn run_args(&self, config: &ContainerConfig, layout: CgroupLayout) -> Vec<String> {
        let docker = grants_docker(config);
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            container_name(config.id),
            "--restart".into(),
            "unless-stopped".into(),
        ];
        args.extend(Self::limit_flags(config));

        // The lease is one unit: a `docker` workload joins the sidecar
        // under the lease's cgroup parent.
        if docker {
            if let Some(parent) = layout.parent_arg(config.id) {
                args.push("--cgroup-parent".into());
                args.push(parent);
            }
        }
        // Where the workload is: a hidden one has no networks of its own,
        // it lives in its owner's namespace (the module docs) — and so
        // publishes nothing here either, Docker refusing `-p` in that mode
        // and the forwarder holding the ports. Otherwise the lease's own
        // network for a `docker` lease, or the provider's.
        let hidden = config.egress.is_some();
        if hidden {
            args.push("--network".into());
            args.push(format!("container:{}", egress_name(config.id)));
        } else if docker {
            args.push("--network".into());
            args.push(network_name(config.id));
        } else if let Some(net) = &self.network {
            args.push("--network".into());
            args.push(net.clone());
        }

        // The SSH forward first, then the tenant's ports. The key rides in
        // as an environment variable: `docker run` cannot write a file into
        // an image before it starts, and every sshd image reads its keys
        // from somewhere different, so the image (or the spawn's
        // entrypoint) is what installs it.
        if let Some(host_port) = config.host_port.filter(|_| !hidden) {
            args.push("-p".into());
            args.push(format!("{}:{}/tcp", host_port, SSH_CONTAINER_PORT));
        }
        if let Some(key) = &config.ssh_key {
            args.push("-e".into());
            args.push(format!("{}={}", SSH_PUBLIC_KEY_ENV, key));
        }

        if !hidden {
            for port in &config.ports {
                args.push("-p".into());
                args.push(format!(
                    "{}:{}/{}",
                    port.host_port, port.container_port, port.protocol
                ));
            }
        }

        for (k, v) in &config.env {
            args.push("-e".into());
            args.push(format!("{}={}", k, v));
        }

        // Named per workload id, so two leases never share state and a
        // re-spawn at the same id cannot inherit the last tenant's volume
        // (`delete_container` removes it).
        if let Some(path) = &config.data_path {
            args.push("-v".into());
            args.push(format!("{}:{}", data_volume(config.id), path));
        }

        // The lease's own socket, and nothing else of the daemon's: the
        // volume the sidecar's daemon writes `docker.sock` into, mounted
        // where a client with no DOCKER_HOST looks (spec §4.4).
        if docker {
            args.push("-v".into());
            args.push(format!(
                "{}:{}",
                socket_volume(config.id),
                WORKLOAD_SOCKET_DIR
            ));
        }

        if let Some(entrypoint) = &config.entrypoint {
            args.push("--entrypoint".into());
            args.push(entrypoint.clone());
        }

        // The image separates the flags from the command: docker treats
        // everything after it as the workload's argv.
        args.push(config.image.clone());
        args.extend(config.args.iter().cloned());

        args
    }

    /// The `docker create` argv for a lease's sidecar: the one privileged
    /// container of the lease, on its network as `docker`, under its cgroup
    /// parent, with the same limits the workload carries, its layers on the
    /// lease's own volume and its socket on the shared one.
    fn sidecar_args(config: &ContainerConfig, layout: CgroupLayout) -> Vec<String> {
        let id = config.id;
        let mut args: Vec<String> = vec![
            "create".into(),
            "--name".into(),
            sidecar_name(id),
            "--restart".into(),
            "unless-stopped".into(),
            "--privileged".into(),
        ];
        args.extend(Self::limit_flags(config));
        if let Some(parent) = layout.parent_arg(id) {
            args.push("--cgroup-parent".into());
            args.push(parent);
        }
        args.extend([
            "--network".into(),
            network_name(id),
            "--network-alias".into(),
            "docker".into(),
        ]);
        // Hidden: the egress network too, with the gateway as the daemon's
        // resolver (the nested daemon's containers inherit what it resolves
        // with, and any resolver they fall back to is redirected by the
        // gateway all the same). The route is the command's first act.
        if let Some(policy) = &config.egress {
            args.extend([
                "--network".into(),
                policy.network.clone(),
                "--dns".into(),
                policy.gateway.clone(),
            ]);
        }
        args.extend([
            "-v".into(),
            format!("{}:/var/lib/docker", daemon_volume(id)),
            "-v".into(),
            format!("{}:{}", socket_volume(id), SIDECAR_SOCKET_DIR),
            DIND_IMAGE.into(),
            "sh".into(),
            "-c".into(),
            sidecar_command(config.egress.as_ref()),
        ]);
        args
    }

    /// The `docker network create` argv for a `docker` lease's own network:
    /// internal on a hidden lease, so neither the sidecar nor the workload
    /// ever gets a default route through it.
    fn network_args(config: &ContainerConfig) -> Vec<String> {
        let mut args: Vec<String> = vec!["network".into(), "create".into()];
        if config.egress.is_some() {
            args.push("--internal".into());
        }
        args.push(network_name(config.id));
        args
    }

    /// The `docker run` argv for a hidden lease's namespace owner (the
    /// module docs): on the egress network — and the lease's own, for a
    /// `docker` lease — with the gateway as its resolver, `NET_ADMIN` and
    /// nothing else, running the route and then a sleep. Killed outright on
    /// stop: there is nothing to shut down.
    fn owner_args(config: &ContainerConfig, policy: &EgressPolicy) -> Vec<String> {
        let id = config.id;
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            egress_name(id),
            "--restart".into(),
            "unless-stopped".into(),
            "--stop-signal".into(),
            "SIGKILL".into(),
            "--network".into(),
            policy.network.clone(),
        ];
        if grants_docker(config) {
            args.push("--network".into());
            args.push(network_name(id));
        }
        args.extend([
            "--dns".into(),
            policy.gateway.clone(),
            "--cap-add".into(),
            NET_ADMIN.into(),
            HIDDEN_SIDECAR_IMAGE.into(),
            "sh".into(),
            "-c".into(),
            owner_command(policy),
        ]);
        args
    }

    /// The `docker run` argv for a hidden lease's forwarder (the module
    /// docs): the lease's TCP ports published on the host at the numbers a
    /// public lease would use, on the provider's network for the way back to
    /// whoever dialed. The egress network, its way to the workload, is
    /// connected AFTER the run (`connect_forwarder_args`): Docker refuses
    /// the default `bridge` beside a user-defined network in one `run`, and
    /// the forwarder's listeners resolve the owner per connection, so
    /// nothing is lost by joining a moment later. `None` when the lease
    /// publishes no TCP port: nothing to forward, so nothing runs.
    fn forwarder_args(&self, config: &ContainerConfig) -> Option<Vec<String>> {
        let ports = forwarded_ports(config);
        if ports.is_empty() {
            return None;
        }
        let id = config.id;
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            ingress_name(id),
            "--restart".into(),
            "unless-stopped".into(),
            "--stop-signal".into(),
            "SIGKILL".into(),
            "--network".into(),
            self.network.clone().unwrap_or_else(|| "bridge".into()),
        ];
        for (host_port, _) in &ports {
            args.push("-p".into());
            args.push(format!("{}:{}/tcp", host_port, host_port));
        }
        args.extend([
            HIDDEN_SIDECAR_IMAGE.into(),
            "sh".into(),
            "-c".into(),
            forwarder_command(id, &ports),
        ]);
        Some(args)
    }

    /// Joins the forwarder to the egress network, where the owner is.
    fn connect_forwarder_args(id: u32, policy: &EgressPolicy) -> Vec<String> {
        vec![
            "network".into(),
            "connect".into(),
            policy.network.clone(),
            ingress_name(id),
        ]
    }

    /// The argv of the helper that writes the listing's limits onto the
    /// lease's cgroup parent: a throwaway run of the (already present) dind
    /// image with the host's cgroup tree bind-mounted, outside the lease's
    /// unit. The parent must already exist, which it does once the sidecar
    /// has started under it.
    fn limit_args(parent_path: &str, config: &ContainerConfig) -> Vec<String> {
        let dir = format!("{}/{}", HELPER_CGROUP_MOUNT, parent_path);
        let quota = u64::from(config.cpu_millicores) * CPU_PERIOD_US / 1000;
        let bytes = u64::from(config.memory_mb) * 1024 * 1024;
        // Swap mirrors what Docker sets on a container given `--memory`
        // alone: as much swap as memory.
        let script = format!(
            "echo '{quota} {period}' > {dir}/cpu.max && echo {bytes} > {dir}/memory.max \
             && echo {bytes} > {dir}/memory.swap.max",
            quota = quota,
            period = CPU_PERIOD_US,
            bytes = bytes,
            dir = dir,
        );
        Self::helper_args(&script)
    }

    fn helper_args(script: &str) -> Vec<String> {
        vec![
            "run".into(),
            "--rm".into(),
            "-v".into(),
            format!("/sys/fs/cgroup:{}", HELPER_CGROUP_MOUNT),
            "--entrypoint".into(),
            "sh".into(),
            DIND_IMAGE.into(),
            "-c".into(),
            script.to_string(),
        ]
    }

    async fn docker(&self, args: &[&str]) -> Result<std::process::Output> {
        Self::docker_command(args).await
    }

    async fn docker_command(args: &[&str]) -> Result<std::process::Output> {
        Command::new("docker")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("invoke docker CLI")
    }

    /// Runs `docker` and fails on a non-zero exit with its stderr.
    async fn docker_ok(&self, args: &[String], what: &str) -> Result<String> {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.docker(&refs).await?;
        if !output.status.success() {
            bail!(
                "{} failed: {}",
                what,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// `Some(running)` for a container the daemon knows, `None` for one it
    /// does not.
    async fn running(&self, name: &str) -> Option<bool> {
        let output = self
            .docker(&["inspect", "-f", "{{.State.Running}}", name])
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).trim() == "true")
    }

    async fn cgroup_layout(&self) -> CgroupLayout {
        *self
            .cgroup_layout
            .get_or_init(|| async {
                let layout = match Self::docker_command(&[
                    "info",
                    "--format",
                    "{{.CgroupDriver}} {{.CgroupVersion}}",
                ])
                .await
                {
                    Ok(out) if out.status.success() => {
                        CgroupLayout::parse(&String::from_utf8_lossy(&out.stdout))
                    }
                    _ => CgroupLayout::Unsupported,
                };
                if layout == CgroupLayout::Unsupported {
                    warn!(
                        "the daemon's cgroup layout is not one this backend can put a per-lease \
                         limit on (it needs cgroup v2); a `docker` lease's workload and sidecar \
                         each carry the listing's limits, so the pair is bounded at twice them, \
                         not as one unit (spec §4.4)"
                    );
                }
                layout
            })
            .await
    }

    /// Everything a lease made besides the workload itself — a `docker`
    /// lease's sidecar, seed, volumes and network, a hidden lease's owner and
    /// forwarder — removed. Best-effort and idempotent: it runs on every
    /// delete, on a failed build, and before a re-spawn at an id whose last
    /// lease may have left pieces behind. The data volume is not touched
    /// here. Callers remove the workload first where one exists, since a
    /// hidden workload's namespace is the owner's.
    async fn remove_lease_extras(&self, id: u32) {
        let had_sidecar = self.running(&sidecar_name(id)).await.is_some();
        self.remove_lease_extras_after(id, had_sidecar).await;
    }

    /// `remove_lease_extras` for a caller that already knows whether the
    /// sidecar existed (it may have removed it itself).
    async fn remove_lease_extras_after(&self, id: u32, had_sidecar: bool) {
        let sidecar = sidecar_name(id);
        let _ = self.docker(&["rm", "-f", "-v", &sidecar]).await;
        let _ = self.docker(&["rm", "-f", &seed_name(id)]).await;
        let _ = self.docker(&["rm", "-f", &ingress_name(id)]).await;
        let _ = self.docker(&["rm", "-f", &egress_name(id)]).await;
        let _ = self
            .docker(&["volume", "rm", "-f", &socket_volume(id), &daemon_volume(id)])
            .await;
        let _ = self.docker(&["network", "rm", &network_name(id)]).await;
        // systemd collects an emptied transient slice itself; a cgroupfs
        // parent would linger, so both are asked to go.
        if had_sidecar {
            if let Some(path) = self.cgroup_layout().await.parent_path(id) {
                let args = Self::helper_args(&format!(
                    "rmdir {}/{} 2>/dev/null || true",
                    HELPER_CGROUP_MOUNT, path
                ));
                let _ = self.docker_ok(&args, "cgroup parent removal").await;
            }
        }
    }

    /// Copies the workload image's own `/var/run` contents into the socket
    /// volume, before the daemon starts (so a `docker.sock` an image might
    /// carry is replaced by the live one, never the reverse). An image with
    /// no `/var/run` seeds nothing.
    async fn seed_socket_dir(&self, config: &ContainerConfig) -> Result<()> {
        let seed = seed_name(config.id);
        let _ = self.docker(&["rm", "-f", &seed]).await;
        // A command is given so an image with neither ENTRYPOINT nor CMD can
        // still be created; nothing here is ever started.
        self.docker_ok(
            &[
                "create".to_string(),
                "--name".to_string(),
                seed.clone(),
                config.image.clone(),
                "toon-seed".to_string(),
            ],
            "creating the seed container",
        )
        .await?;
        let source = format!("{}:{}/.", seed, WORKLOAD_SOCKET_DIR);
        let read = self.docker(&["cp", "-a", "-L", &source, "-"]).await;
        let _ = self.docker(&["rm", "-f", &seed]).await;
        let tar = match read {
            Ok(out) if out.status.success() => out.stdout,
            Ok(out) => {
                info!(
                    "workload {} image has no {} to seed the socket directory from ({})",
                    config.id,
                    WORKLOAD_SOCKET_DIR,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if tar.is_empty() {
            return Ok(());
        }
        let dest = format!("{}:{}", sidecar_name(config.id), SIDECAR_SOCKET_DIR);
        let mut child = Command::new("docker")
            .args(["cp", "-a", "-", &dest])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("invoke docker cp")?;
        let mut stdin = child.stdin.take().context("docker cp stdin")?;
        stdin.write_all(&tar).await.context("write seed archive")?;
        drop(stdin);
        let output = child.wait_with_output().await.context("docker cp")?;
        if !output.status.success() {
            bail!(
                "seeding the socket directory failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Waits until the sidecar's daemon answers on its socket, giving up if
    /// the sidecar exits or the timeout passes.
    async fn wait_for_daemon(&self, id: u32) -> Result<String> {
        let sidecar = sidecar_name(id);
        let host = format!("unix://{}/{}", SIDECAR_SOCKET_DIR, SOCKET_FILE);
        let deadline = Instant::now() + DAEMON_READY_TIMEOUT;
        loop {
            let probe = self
                .docker(&[
                    "exec",
                    &sidecar,
                    "docker",
                    "-H",
                    &host,
                    "version",
                    "--format",
                    "{{.Server.Version}}",
                ])
                .await?;
            if probe.status.success() {
                return Ok(String::from_utf8_lossy(&probe.stdout).trim().to_string());
            }
            if self.running(&sidecar).await != Some(true) {
                let logs = self.docker(&["logs", "--tail", "20", &sidecar]).await?;
                bail!(
                    "the lease's daemon exited before it answered: {}",
                    String::from_utf8_lossy(&logs.stderr).trim()
                );
            }
            if Instant::now() >= deadline {
                bail!(
                    "the lease's daemon did not answer within {:?}",
                    DAEMON_READY_TIMEOUT
                );
            }
            tokio::time::sleep(DAEMON_READY_POLL).await;
        }
    }

    /// Writes the listing's limits onto the lease's cgroup parent, where
    /// there is one. A layout with none was already warned about; a layout
    /// with one that cannot be written fails the lease, because a limit the
    /// operator relies on silently not applying is worse than a refused
    /// spawn.
    async fn apply_unit_limits(
        &self,
        layout: CgroupLayout,
        config: &ContainerConfig,
    ) -> Result<()> {
        let Some(path) = layout.parent_path(config.id) else {
            return Ok(());
        };
        self.docker_ok(
            &Self::limit_args(&path, config),
            "bounding the lease as one unit",
        )
        .await?;
        info!(
            "lease {} bounded as one unit at {} millicores / {} MiB under {}",
            config.id, config.cpu_millicores, config.memory_mb, path
        );
        Ok(())
    }

    /// The gateway an owner was made for: its resolver, which `owner_args`
    /// set to exactly that. Read back rather than remembered, since this
    /// backend keeps no state and a restart knows only the id.
    async fn owner_gateway(&self, id: u32) -> Result<String> {
        self.docker_ok(
            &[
                "inspect".into(),
                "-f".into(),
                "{{index .HostConfig.Dns 0}}".into(),
                egress_name(id),
            ],
            "reading the egress namespace's gateway",
        )
        .await
    }

    /// Waits until the owner's namespace has its default route via the
    /// gateway — the one thing its command does — giving up if the owner
    /// exits (the route could not be set: a gateway that is not on the
    /// egress network, say) or the timeout passes. Nothing joins the
    /// namespace before this answers, so no workload ever runs in one
    /// without the route.
    async fn wait_for_route(&self, id: u32) -> Result<()> {
        let owner = egress_name(id);
        let via = format!("default via {} ", self.owner_gateway(id).await?);
        let deadline = Instant::now() + ROUTE_READY_TIMEOUT;
        loop {
            let probe = self
                .docker(&["exec", &owner, "ip", "-4", "route", "show", "default"])
                .await?;
            if probe.status.success() && String::from_utf8_lossy(&probe.stdout).contains(&via) {
                return Ok(());
            }
            if self.running(&owner).await != Some(true) {
                let logs = self.docker(&["logs", "--tail", "20", &owner]).await?;
                bail!(
                    "the lease's egress namespace exited before it had its route: {}",
                    String::from_utf8_lossy(&logs.stderr).trim()
                );
            }
            if Instant::now() >= deadline {
                bail!(
                    "the lease's egress namespace had no default route within {:?}",
                    ROUTE_READY_TIMEOUT
                );
            }
            tokio::time::sleep(ROUTE_READY_POLL).await;
        }
    }

    async fn build_lease(&self, config: &ContainerConfig) -> Result<String> {
        let id = config.id;
        let started = Instant::now();
        let docker = grants_docker(config);
        let layout = if docker {
            self.cgroup_layout().await
        } else {
            CgroupLayout::Unsupported
        };
        if docker {
            self.docker_ok(&Self::network_args(config), "creating the lease network")
                .await?;
            self.docker_ok(&Self::sidecar_args(config, layout), "creating the sidecar")
                .await?;
            self.seed_socket_dir(config).await?;
            self.docker_ok(&["start".into(), sidecar_name(id)], "starting the sidecar")
                .await?;
            let version = self.wait_for_daemon(id).await?;
            info!(
                "lease {} has its own daemon ({}) at {}/{} after {:.1?}",
                id,
                version,
                WORKLOAD_SOCKET_DIR,
                SOCKET_FILE,
                started.elapsed()
            );
            self.apply_unit_limits(layout, config).await?;
        }
        if let Some(policy) = &config.egress {
            let udp: Vec<u16> = config
                .ports
                .iter()
                .filter(|p| !p.protocol.eq_ignore_ascii_case("tcp"))
                .map(|p| p.host_port)
                .collect();
            if !udp.is_empty() {
                warn!(
                    "lease {} publishes UDP host ports {:?} that a hidden-service address cannot \
                     carry; they are not forwarded",
                    id, udp
                );
            }
            self.docker_ok(
                &Self::owner_args(config, policy),
                "starting the egress namespace",
            )
            .await?;
            self.wait_for_route(id).await?;
            match self.forwarder_args(config) {
                Some(args) => {
                    self.docker_ok(&args, "starting the ingress forwarder")
                        .await?;
                    self.docker_ok(
                        &Self::connect_forwarder_args(id, policy),
                        "joining the ingress forwarder to the egress network",
                    )
                    .await?;
                }
                None => info!(
                    "lease {} publishes no TCP port, so it gets no ingress forwarder",
                    id
                ),
            }
            info!(
                "lease {} is confined to {} via {} after {:.1?}",
                id,
                policy.network,
                policy.gateway,
                started.elapsed()
            );
        }
        let created = self
            .docker_ok(&self.run_args(config, layout), "docker run")
            .await?;
        info!(
            "lease {} workload started beside its sidecars after {:.1?}",
            id,
            started.elapsed()
        );
        Ok(created)
    }

    /// A lease with extras: a `docker` lease's network, sidecar, seeded
    /// socket volume and unit limits; a hidden lease's namespace owner (with
    /// its route proven) and forwarder; and then the workload, in that order
    /// so the socket is live and the namespace confined before the
    /// workload's first process runs. Whatever was made before a failure is
    /// removed again, so no sidecar outlives a lease that never started.
    async fn create_lease(&self, config: &ContainerConfig) -> Result<String> {
        let id = config.id;
        self.remove_lease_extras(id).await;
        let result = self.build_lease(config).await;
        if let Err(e) = &result {
            warn!(
                "lease {} could not be built ({}); removing what was made",
                id, e
            );
            let _ = self.docker(&["rm", "-f", "-v", &container_name(id)]).await;
            self.remove_lease_extras(id).await;
        }
        result
    }
}

impl Default for DockerBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// The id `docker load` reports for an untagged image: `Loaded image ID:
/// sha256:…`. Under the containerd image store that is the manifest's
/// digest; under the classic graph driver it is the config's — either way
/// it is what `docker run` accepts and no tag was involved. A tagged image
/// (`Loaded image: name:tag`) is refused: the layouts this provider writes
/// carry no ref name, so a tag here means the load did not read what was
/// written.
fn loaded_image_id(output: &str) -> Result<String> {
    for line in output.lines() {
        if let Some(id) = line.trim().strip_prefix("Loaded image ID:") {
            let id = id.trim();
            if id.starts_with("sha256:") {
                return Ok(id.to_string());
            }
        }
    }
    bail!(
        "docker load did not report an image id (got: {})",
        output.trim()
    )
}

#[async_trait]
impl ComputeBackend for DockerBackend {
    async fn find_available_id(&self, range_start: u32, range_end: u32) -> Result<u32> {
        let name_filter = format!("name={}", WORKLOAD_NAME_PREFIX);
        let output = self
            .docker(&[
                "ps",
                "-a",
                "--format",
                "{{.Names}}",
                "--filter",
                &name_filter,
            ])
            .await?;
        let names = String::from_utf8_lossy(&output.stdout);
        let used: std::collections::HashSet<u32> =
            names.lines().filter_map(id_from_container_name).collect();
        for id in range_start..=range_end {
            if !used.contains(&id) {
                return Ok(id);
            }
        }
        anyhow::bail!(
            "no available container id in range {}..={}",
            range_start,
            range_end
        );
    }

    async fn load_image(&self, layout_tar: &Path) -> Result<String> {
        let path = layout_tar.to_string_lossy();
        let output = self.docker(&["load", "-q", "-i", &path]).await?;
        if !output.status.success() {
            bail!(
                "docker load failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        loaded_image_id(&String::from_utf8_lossy(&output.stdout))
    }

    async fn create_container(&self, config: &ContainerConfig) -> Result<String> {
        if has_extras(config) {
            return self.create_lease(config).await;
        }
        self.docker_ok(
            &self.run_args(config, CgroupLayout::Unsupported),
            "docker run",
        )
        .await
    }

    async fn start_container(&self, id: u32) -> Result<()> {
        // A `docker` lease's daemon comes back first, so the workload never
        // runs against a socket nobody is serving.
        let sidecar = sidecar_name(id);
        if self.running(&sidecar).await.is_some() {
            self.docker_ok(&["start".into(), sidecar.clone()], "starting the sidecar")
                .await?;
            self.wait_for_daemon(id).await?;
        }
        // A hidden lease's namespace comes back before the workload joins
        // it, with its route proven again; the forwarder in any order.
        let owner = egress_name(id);
        if self.running(&owner).await.is_some() {
            self.docker_ok(
                &["start".into(), owner.clone()],
                "starting the egress namespace",
            )
            .await?;
            self.wait_for_route(id).await?;
        }
        let forwarder = ingress_name(id);
        if self.running(&forwarder).await.is_some() {
            self.docker_ok(
                &["start".into(), forwarder.clone()],
                "starting the ingress forwarder",
            )
            .await?;
        }
        let name = container_name(id);
        let output = self.docker(&["start", &name]).await?;
        if !output.status.success() {
            anyhow::bail!(
                "docker start {} failed: {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    async fn stop_container(&self, id: u32) -> Result<()> {
        // Best-effort: an already-gone container must not fail the cleanup
        // loop. Both at once, so a `docker` lease stops in the workload's
        // grace period rather than the sum of two.
        let (name, sidecar) = (container_name(id), sidecar_name(id));
        let stop_workload = ["stop", &name];
        let stop_sidecar = ["stop", "-t", SIDECAR_STOP_GRACE_S, &sidecar];
        let _ = tokio::join!(self.docker(&stop_workload), self.docker(&stop_sidecar));
        // A hidden lease's owner and forwarder go once the workload has
        // had its grace period: the owner's namespace IS the workload's,
        // and both are killed outright (their stop signal), so this costs
        // nothing.
        let (owner, forwarder) = (egress_name(id), ingress_name(id));
        let stop_owner = ["stop", &owner];
        let stop_forwarder = ["stop", &forwarder];
        let _ = tokio::join!(self.docker(&stop_owner), self.docker(&stop_forwarder));
        Ok(())
    }

    async fn delete_container(&self, id: u32) -> Result<()> {
        let name = container_name(id);
        let sidecar = sidecar_name(id);
        let had_sidecar = self.running(&sidecar).await.is_some();
        // `-v` takes the image's anonymous volumes with it; the named ones
        // are removed by name below. The pair goes at once.
        let rm_workload = ["rm", "-f", "-v", &name];
        let rm_sidecar = ["rm", "-f", "-v", &sidecar];
        let _ = tokio::join!(self.docker(&rm_workload), self.docker(&rm_sidecar));
        // Remove the volume too, so a re-spawn at the same id cannot inherit
        // the last tenant's state. Then everything else of the lease's —
        // after the workload, whose namespace a hidden lease's owner holds.
        let _ = self.docker(&["volume", "rm", "-f", &data_volume(id)]).await;
        self.remove_lease_extras_after(id, had_sidecar).await;
        Ok(())
    }

    async fn get_node_status(&self) -> Result<NodeStatus> {
        Ok(NodeStatus {
            cpu_usage: 0.0,
            memory_used: 0,
            memory_total: 0,
            disk_used: 0,
            disk_total: 0,
        })
    }

    async fn get_container_status(&self, id: u32) -> Result<ContainerStatus> {
        Ok(match self.running(&container_name(id)).await {
            // `inspect` fails only when there is no such container.
            None => ContainerStatus::Absent,
            Some(true) => ContainerStatus::Running,
            Some(false) => ContainerStatus::Stopped,
        })
    }

    async fn get_container_ip(&self, id: u32) -> Result<Option<String>> {
        let name = container_name(id);
        let output = self
            .docker(&["inspect", "-f", "{{.NetworkSettings.IPAddress}}", &name])
            .await?;
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ip))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(id: u32, capabilities: &[&str]) -> ContainerConfig {
        ContainerConfig {
            id,
            name: container_name(id),
            image: "alpine:latest".to_string(),
            cpu_millicores: 1500,
            memory_mb: 256,
            storage_gb: 1,
            ssh_key: Some("ssh-ed25519 AAAA tenant".to_string()),
            host_port: Some(30042),
            ports: vec![],
            env: std::collections::HashMap::from([("FOO".to_string(), "bar".to_string())]),
            entrypoint: None,
            args: vec![],
            data_path: Some("/data".to_string()),
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
            egress: None,
        }
    }

    /// What the harness's fake `HiddenService` answers: the shape an
    /// operator's `[anon.egress]` has.
    fn policy() -> EgressPolicy {
        EgressPolicy {
            network: "toon-hidden-egress".to_string(),
            gateway: "172.30.0.2".to_string(),
        }
    }

    /// `config`, on a Hidden Provider: the same lease with an egress policy
    /// and one published TCP port and one UDP.
    fn hidden_config(id: u32, capabilities: &[&str]) -> ContainerConfig {
        ContainerConfig {
            ports: vec![
                crate::compute::PortMapping {
                    host_port: 17777,
                    container_port: 7777,
                    protocol: "tcp".to_string(),
                },
                crate::compute::PortMapping {
                    host_port: 17778,
                    container_port: 7778,
                    protocol: "udp".to_string(),
                },
            ],
            egress: Some(policy()),
            ..config(id, capabilities)
        }
    }

    /// Every value of a repeated flag, in order.
    fn flag_values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
        args.iter()
            .enumerate()
            .filter(|(i, _)| *i > 0 && args[i - 1] == flag)
            .map(|(_, a)| a.as_str())
            .collect()
    }

    /// The `-v` values of an argv, in order.
    fn mounts(args: &[String]) -> Vec<&str> {
        flag_values(args, "-v")
    }

    fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == flag)
            .map(|i| args[i + 1].as_str())
    }

    const PRIVILEGE_FLAGS: [&str; 6] = [
        "--privileged",
        "--device",
        "--cap-add",
        "--pid",
        "--userns",
        "--security-opt",
    ];

    #[test]
    fn name_for_is_deterministic() {
        assert_eq!(container_name(1234), "toon-1234");
    }

    #[test]
    fn the_loaded_image_id_is_read_from_docker_loads_report() {
        let id = "sha256:8dfc124d76b553b66bdc6f665560d253e5459b42b9758f46a4dcb5dcbee9d3e4";
        assert_eq!(
            loaded_image_id(&format!("Loaded image ID: {}\n", id)).unwrap(),
            id
        );
        assert!(loaded_image_id("Loaded image: alpine:3.20\n").is_err());
        assert!(loaded_image_id("").is_err());
    }

    #[test]
    fn run_args_carry_every_piece_of_the_config() {
        // Asserts on the real argv builder, so a change to `create_container`
        // cannot silently pass. Shelling out to docker is `tests/docker_backend`.
        let cfg = ContainerConfig {
            ports: vec![crate::compute::PortMapping {
                host_port: 17777,
                container_port: 7777,
                protocol: "tcp".to_string(),
            }],
            entrypoint: Some("/bin/sh".to_string()),
            args: vec!["sleep".to_string(), "300".to_string()],
            data_path: Some("/var/data".to_string()),
            ..config(42, &[])
        };

        let args = DockerBackend::new().run_args(&cfg, CgroupLayout::Systemd);

        assert!(args.contains(&"toon-42".to_string()));
        assert!(
            args.contains(&"1.500".to_string()),
            "millicores become a fractional --cpus"
        );
        assert!(
            args.contains(&"30042:22/tcp".to_string()),
            "the SSH forward"
        );
        assert!(args.contains(&"SSH_PUBLIC_KEY=ssh-ed25519 AAAA tenant".to_string()));
        assert!(args.contains(&"17777:7777/tcp".to_string()));
        assert!(args.contains(&"FOO=bar".to_string()));
        assert!(args.contains(&"toon-42-data:/var/data".to_string()));
        assert!(args.contains(&"256m".to_string()));

        // Everything after the image is the workload's argv, so every flag —
        // --entrypoint included — has to come before it.
        let image_at = args.iter().position(|a| a == "alpine:latest").unwrap();
        assert_eq!(
            &args[image_at + 1..],
            &["sleep".to_string(), "300".to_string()]
        );
        assert!(args[..image_at].contains(&"--entrypoint".to_string()));
    }

    #[test]
    fn the_workload_argv_never_exposes_the_host_daemon_or_any_privilege() {
        // Spec §4.4: the provider MUST NOT expose the daemon it runs its own
        // workloads with — not by bind-mounting its socket, not through a
        // device, not over TCP. Asserted on the argv rather than by reading
        // the code, because this is the line a capability is most likely to
        // cross by accident. An ungranted lease and a `docker` one, public
        // and hidden.
        for (caps, hidden) in [
            (&[][..], false),
            (&["docker"][..], false),
            (&[][..], true),
            (&["docker"][..], true),
        ] {
            let cfg = if hidden {
                hidden_config(42, caps)
            } else {
                config(42, caps)
            };
            let args =
                DockerBackend::with_network("toon-net").run_args(&cfg, CgroupLayout::Systemd);

            for arg in &args {
                assert!(
                    !arg.contains("docker.sock"),
                    "the host daemon's socket is never a workload's: {}",
                    arg
                );
                assert!(
                    !arg.starts_with("DOCKER_HOST="),
                    "no workload is pointed at a daemon it was not given: {}",
                    arg
                );
            }
            for flag in PRIVILEGE_FLAGS {
                assert!(
                    !args.iter().any(|a| a == flag),
                    "{} is a privilege no listing on this backend grants ({:?}, hidden {})",
                    flag,
                    caps,
                    hidden
                );
            }
            // Every mount is a named volume of the lease's own, never a
            // host path.
            for m in mounts(&args) {
                assert!(m.starts_with("toon-42-"), "{}", m);
                assert!(!m.starts_with('/'), "{}", m);
            }
        }

        // Ungranted, nothing of the host's runtime dir reaches the workload
        // and the only mount is its data volume.
        let args = DockerBackend::with_network("toon-net")
            .run_args(&config(42, &[]), CgroupLayout::Systemd);
        assert!(!args.iter().any(|a| a.contains("/var/run")));
        assert!(!args.iter().any(|a| a == "--cgroup-parent"));
        assert_eq!(flag_value(&args, "--network"), Some("toon-net"));
        assert_eq!(mounts(&args), vec!["toon-42-data:/data"]);
    }

    #[test]
    fn a_docker_grant_gives_the_workload_only_the_leases_own_socket() {
        // Spec §4.4: a daemon of the lease's own at /var/run/docker.sock,
        // and the workload container itself gets no extra privilege. What
        // the workload gets is the socket VOLUME the sidecar's daemon writes
        // into — the same volume, by name — plus the lease's network and
        // cgroup parent; the sidecar is where the privilege is.
        let cfg = config(42, &["docker"]);
        let backend = DockerBackend::with_network("toon-net");
        let workload = backend.run_args(&cfg, CgroupLayout::Systemd);
        let sidecar = DockerBackend::sidecar_args(&cfg, CgroupLayout::Systemd);

        assert_eq!(
            mounts(&workload),
            vec!["toon-42-data:/data", "toon-42-run:/var/run"],
            "the socket directory is a named volume mounted where a client looks"
        );
        assert_eq!(
            mounts(&sidecar),
            vec!["toon-42-docker:/var/lib/docker", "toon-42-run:/toon/run"],
            "the sidecar writes its socket into that same volume, and its layers into the lease's own"
        );
        assert!(
            !sidecar
                .iter()
                .any(|m| m.starts_with('/') && m.contains(':')),
            "no host path reaches the sidecar either"
        );

        // The pair is one unit: same parent, same network, same limits.
        assert_eq!(
            flag_value(&workload, "--cgroup-parent"),
            Some("toon-42.slice")
        );
        assert_eq!(
            flag_value(&sidecar, "--cgroup-parent"),
            Some("toon-42.slice")
        );
        assert_eq!(flag_value(&workload, "--network"), Some("toon-42-net"));
        assert_eq!(flag_value(&sidecar, "--network"), Some("toon-42-net"));
        assert_eq!(flag_value(&sidecar, "--network-alias"), Some("docker"));
        for argv in [&workload, &sidecar] {
            assert_eq!(flag_value(argv, "--cpus"), Some("1.500"));
            assert_eq!(flag_value(argv, "--memory"), Some("256m"));
        }

        // Only the sidecar is privileged, and only in that one way.
        assert!(sidecar.contains(&"--privileged".to_string()));
        assert!(!workload.contains(&"--privileged".to_string()));
        for flag in PRIVILEGE_FLAGS.iter().filter(|f| **f != "--privileged") {
            assert!(!sidecar.iter().any(|a| a == flag), "{}", flag);
        }
        assert_eq!(
            sidecar[0], "create",
            "the sidecar is created, seeded, then started"
        );
        assert!(sidecar.contains(&DIND_IMAGE.to_string()));
        assert!(
            DIND_IMAGE.contains("@sha256:"),
            "the daemon image is pinned by digest"
        );

        // The daemon listens on its unix socket in the shared directory and
        // nowhere else; the socket is made usable by any uid on every start.
        let command = sidecar.last().unwrap();
        assert!(command.contains("--host=unix:///toon/run/docker.sock"));
        assert!(!command.contains("tcp://"));
        assert!(command.contains("chmod 0666 /toon/run/docker.sock"));
        assert!(command.contains("--bip=172.16.0.1/24"));
        // The workload's argv still says nothing about a socket: the
        // daemon puts it there.
        assert!(!workload.iter().any(|a| a.contains("docker.sock")));
    }

    // ── a hidden lease ──────────────────────────────────────────────────

    #[test]
    fn a_hidden_workload_lives_in_its_owners_namespace_and_publishes_nothing_itself() {
        // Spec §10: the workload has no network path except the anon
        // egress. It joins the owner's namespace — no network of its own,
        // never the provider's or the default bridge — and so carries no
        // `-p` (Docker refuses one in that mode; the forwarder holds the
        // ports) and no `--dns`; everything else of the lease is as it was.
        let cfg = hidden_config(42, &[]);
        let backend = DockerBackend::with_network("toon-net");
        let args = backend.run_args(&cfg, CgroupLayout::Systemd);

        assert_eq!(
            flag_values(&args, "--network"),
            vec!["container:toon-42-egress"]
        );
        assert!(!args.contains(&"-p".to_string()), "{:?}", args);
        assert!(!args.contains(&"--dns".to_string()));
        assert!(!args.contains(&"--cap-add".to_string()));
        assert!(args.contains(&"SSH_PUBLIC_KEY=ssh-ed25519 AAAA tenant".to_string()));
        assert!(args.contains(&"FOO=bar".to_string()));
        assert_eq!(mounts(&args), vec!["toon-42-data:/data"]);
        assert_eq!(flag_value(&args, "--cpus"), Some("1.500"));

        // A public lease, same config without the policy: unchanged.
        let public = backend.run_args(&config(42, &[]), CgroupLayout::Systemd);
        assert_eq!(flag_values(&public, "--network"), vec!["toon-net"]);
        assert!(public.contains(&"30042:22/tcp".to_string()));
    }

    #[test]
    fn the_owner_holds_the_route_and_net_admin_and_nothing_else() {
        // The namespace: on the egress network only, the gateway as its
        // resolver, NET_ADMIN for the one route it sets, then a sleep.
        // Nothing of the tenant's reaches it — no key, no env, no mount.
        let cfg = hidden_config(42, &[]);
        let args = DockerBackend::owner_args(&cfg, &policy());

        assert_eq!(args[0], "run");
        assert_eq!(flag_value(&args, "--name"), Some("toon-42-egress"));
        assert_eq!(flag_values(&args, "--network"), vec!["toon-hidden-egress"]);
        assert_eq!(flag_value(&args, "--dns"), Some("172.30.0.2"));
        assert_eq!(flag_values(&args, "--cap-add"), vec!["NET_ADMIN"]);
        assert_eq!(flag_value(&args, "--stop-signal"), Some("SIGKILL"));
        for flag in PRIVILEGE_FLAGS.iter().filter(|f| **f != "--cap-add") {
            assert!(!args.iter().any(|a| a == flag), "{}", flag);
        }
        assert!(mounts(&args).is_empty());
        assert!(!args.contains(&"-p".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("SSH_PUBLIC_KEY=")));
        assert!(args.contains(&HIDDEN_SIDECAR_IMAGE.to_string()));
        assert!(
            HIDDEN_SIDECAR_IMAGE.contains("@sha256:"),
            "pinned by digest"
        );
        assert_eq!(
            args.last().unwrap(),
            "ip route replace default via 172.30.0.2 && exec sleep infinity"
        );

        // A `docker` lease's owner is on the lease's network too, so the
        // workload still finds the sidecar as `docker`.
        let args = DockerBackend::owner_args(&hidden_config(42, &["docker"]), &policy());
        assert_eq!(
            flag_values(&args, "--network"),
            vec!["toon-hidden-egress", "toon-42-net"]
        );
    }

    #[test]
    fn the_forwarder_publishes_the_leases_tcp_ports_on_the_host_at_the_same_numbers() {
        // What a public lease would publish, published: the SSH forward
        // and every TCP port, host port to host port, forwarded to the
        // owner's name at the container port. UDP is not carried by an
        // address, so it is not forwarded. On the provider's network for
        // the way back, joined to the egress network for the way in; no
        // privilege, no mount, no tenant environment.
        let cfg = hidden_config(42, &[]);
        let args = DockerBackend::with_network("toon-net")
            .forwarder_args(&cfg)
            .expect("a lease with ports gets a forwarder");

        assert_eq!(flag_value(&args, "--name"), Some("toon-42-ingress"));
        assert_eq!(flag_values(&args, "--network"), vec!["toon-net"]);
        assert_eq!(
            DockerBackend::connect_forwarder_args(42, &policy()),
            vec![
                "network",
                "connect",
                "toon-hidden-egress",
                "toon-42-ingress"
            ],
            "the egress network is joined after the run"
        );
        assert_eq!(
            flag_values(&args, "-p"),
            vec!["30042:30042/tcp", "17777:17777/tcp"]
        );
        assert!(!args.iter().any(|a| a.contains("udp")));
        let command = args.last().unwrap();
        assert_eq!(
            command,
            "nc -lk -p 30042 -e nc toon-42-egress 22 & nc -lk -p 17777 -e nc toon-42-egress 7777 & wait"
        );
        for flag in PRIVILEGE_FLAGS {
            assert!(!args.iter().any(|a| a == flag), "{}", flag);
        }
        assert!(!args.contains(&"--dns".to_string()));
        assert!(mounts(&args).is_empty());
        assert!(!args.iter().any(|a| a.starts_with("SSH_PUBLIC_KEY=")));
        assert!(args.contains(&HIDDEN_SIDECAR_IMAGE.to_string()));

        // With no provider network configured, the default bridge is the
        // way back.
        let args = DockerBackend::new().forwarder_args(&cfg).unwrap();
        assert_eq!(flag_values(&args, "--network"), vec!["bridge"]);

        // Nothing to publish, nothing to run.
        let silent = ContainerConfig {
            host_port: None,
            ports: vec![crate::compute::PortMapping {
                host_port: 17778,
                container_port: 7778,
                protocol: "udp".to_string(),
            }],
            ..hidden_config(42, &[])
        };
        assert!(DockerBackend::new().forwarder_args(&silent).is_none());
    }

    #[test]
    fn a_hidden_docker_lease_confines_its_network_and_sidecar_too() {
        // Spec §4.4 on a Hidden Provider: nested pulls are the lease's
        // egress and leave through anon. The lease's own network is
        // internal (no default route through it, ever); the sidecar is on
        // the egress network too, resolves through the gateway, and its
        // command sets the route before the daemon starts.
        let cfg = hidden_config(42, &["docker"]);
        let network = DockerBackend::network_args(&cfg);
        assert_eq!(
            network,
            vec!["network", "create", "--internal", "toon-42-net"]
        );
        assert_eq!(
            DockerBackend::network_args(&config(42, &["docker"])),
            vec!["network", "create", "toon-42-net"],
            "a public lease's network is as it was"
        );

        let sidecar = DockerBackend::sidecar_args(&cfg, CgroupLayout::Systemd);
        assert_eq!(
            flag_values(&sidecar, "--network"),
            vec!["toon-42-net", "toon-hidden-egress"]
        );
        assert_eq!(flag_value(&sidecar, "--network-alias"), Some("docker"));
        assert_eq!(flag_value(&sidecar, "--dns"), Some("172.30.0.2"));
        let command = sidecar.last().unwrap();
        assert!(
            command.starts_with(
                "ip route replace default via 172.30.0.2 || exit 1; dockerd-entrypoint.sh"
            ),
            "the route is a statement of its own, so `&` still backgrounds only the daemon: {}",
            command
        );
        assert!(command.contains("dockerd-entrypoint.sh dockerd") && command.contains("& pid=$!;"));
        assert!(command.contains("--host=unix:///toon/run/docker.sock"));

        // The public sidecar has none of it.
        let public = DockerBackend::sidecar_args(&config(42, &["docker"]), CgroupLayout::Systemd);
        assert_eq!(flag_values(&public, "--network"), vec!["toon-42-net"]);
        assert!(!public.contains(&"--dns".to_string()));
        assert!(public.last().unwrap().starts_with("dockerd-entrypoint.sh"));

        // The workload joins the owner, and is still under the lease's
        // cgroup parent with the lease's socket.
        let workload = DockerBackend::new().run_args(&cfg, CgroupLayout::Systemd);
        assert_eq!(
            flag_values(&workload, "--network"),
            vec!["container:toon-42-egress"]
        );
        assert_eq!(
            flag_value(&workload, "--cgroup-parent"),
            Some("toon-42.slice")
        );
        assert_eq!(
            mounts(&workload),
            vec!["toon-42-data:/data", "toon-42-run:/var/run"]
        );
    }

    #[test]
    fn the_unit_limit_is_written_to_the_leases_cgroup_parent() {
        let cfg = ContainerConfig {
            cpu_millicores: 2000,
            memory_mb: 4096,
            ..config(1000, &["docker"])
        };
        let path = CgroupLayout::Systemd.parent_path(1000).unwrap();
        assert_eq!(path, "toon.slice/toon-1000.slice");
        let args = DockerBackend::limit_args(&path, &cfg);
        let script = args.last().unwrap();
        assert!(
            script
                .contains("echo '200000 100000' > /host-cgroup/toon.slice/toon-1000.slice/cpu.max"),
            "{}",
            script
        );
        assert!(
            script.contains("echo 4294967296 > /host-cgroup/toon.slice/toon-1000.slice/memory.max"),
            "{}",
            script
        );
        assert!(script.contains("memory.swap.max"));
        // The helper mounts the host's cgroup tree and is not itself in the
        // unit it bounds.
        assert_eq!(
            mounts(&args),
            vec!["/sys/fs/cgroup:/host-cgroup"],
            "the helper is the one place a host path is mounted, and never into a workload"
        );
        assert!(!args.iter().any(|a| a == "--cgroup-parent"));
        assert!(args.contains(&"--rm".to_string()));
    }

    #[test]
    fn the_cgroup_layout_decides_the_parent() {
        assert_eq!(CgroupLayout::parse("systemd 2\n"), CgroupLayout::Systemd);
        assert_eq!(CgroupLayout::parse("cgroupfs 2"), CgroupLayout::Cgroupfs);
        assert_eq!(CgroupLayout::parse("systemd 1"), CgroupLayout::Unsupported);
        assert_eq!(CgroupLayout::parse(""), CgroupLayout::Unsupported);

        assert_eq!(
            CgroupLayout::Systemd.parent_arg(7).as_deref(),
            Some("toon-7.slice")
        );
        assert_eq!(
            CgroupLayout::Cgroupfs.parent_arg(7).as_deref(),
            Some("/toon-7")
        );
        assert_eq!(
            CgroupLayout::Cgroupfs.parent_path(7).as_deref(),
            Some("toon-7")
        );
        assert_eq!(CgroupLayout::Unsupported.parent_arg(7), None);
        assert_eq!(CgroupLayout::Unsupported.parent_path(7), None);

        // Without a parent, neither container names one — each still
        // carries the listing's limits, so the lease is bounded at twice
        // them rather than not at all.
        let cfg = config(7, &["docker"]);
        let workload = DockerBackend::new().run_args(&cfg, CgroupLayout::Unsupported);
        let sidecar = DockerBackend::sidecar_args(&cfg, CgroupLayout::Unsupported);
        for argv in [&workload, &sidecar] {
            assert!(!argv.iter().any(|a| a == "--cgroup-parent"));
            assert_eq!(flag_value(argv, "--cpus"), Some("1.500"));
        }
    }

    #[test]
    fn a_stateless_workload_gets_no_volume() {
        let cfg = ContainerConfig {
            id: 7,
            name: "toon-7".to_string(),
            image: "alpine:latest".to_string(),
            cpu_millicores: 1000,
            memory_mb: 64,
            storage_gb: 1,
            ssh_key: None,
            host_port: None,
            ports: vec![],
            env: std::collections::HashMap::new(),
            entrypoint: None,
            args: vec![],
            data_path: None,
            capabilities: vec![],
            egress: None,
        };
        let args = DockerBackend::new().run_args(&cfg, CgroupLayout::Systemd);
        assert!(!args.contains(&"-v".to_string()));
        assert!(
            !args.contains(&"-p".to_string()),
            "no SSH forward without a key or port"
        );
        assert!(!args.iter().any(|a| a.starts_with("SSH_PUBLIC_KEY=")));
    }

    #[test]
    fn the_leases_objects_are_never_mistaken_for_workloads() {
        // `find_available_id` parses `toon-<n>`; everything else of a lease
        // carries a suffix that does not parse.
        for name in [
            sidecar_name(42),
            seed_name(42),
            socket_volume(42),
            daemon_volume(42),
            network_name(42),
            egress_name(42),
            ingress_name(42),
        ] {
            assert!(name.starts_with("toon-42-"), "{}", name);
            assert_eq!(id_from_container_name(&name), None, "{}", name);
        }
    }
}
