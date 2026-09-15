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
        cpu_cores: 1,
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
    let taken = backend.find_available_id(TEST_ID, TEST_ID + 1).await.unwrap();
    assert_ne!(taken, TEST_ID, "a live workload's id must not be handed out");

    backend.delete_container(TEST_ID).await.expect("delete");
    assert_eq!(
        backend.get_container_status(TEST_ID).await.unwrap(),
        ContainerStatus::Absent,
        "an expired lease leaves no container behind"
    );
    assert_eq!(
        backend.find_available_id(TEST_ID, TEST_ID + 1).await.unwrap(),
        TEST_ID,
        "the destroyed workload's id is free again"
    );
}
