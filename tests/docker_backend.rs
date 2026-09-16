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
