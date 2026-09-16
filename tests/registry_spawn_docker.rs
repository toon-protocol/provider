//! The paid spawn of a `{ digest, registry_entry }` image against a REAL
//! Docker daemon: the layers fetched through the entry — one from the
//! stubbed TOON store, one from the stubbed upstream registry — verified,
//! assembled into an OCI layout, loaded, and the workload run by the
//! resulting image id (spec §8.4).
//!
//! `#[ignore]` by default like `tests/docker_backend.rs`: `cargo test` must
//! pass on a machine with no Docker. Run it with `cargo test -- --ignored`
//! where a daemon is available. The rootfs layer is exported from
//! `alpine:3.20` so the workload has a `sleep` to run.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use tokio::process::Command;

use common::harness::listing;
use common::store::*;
use common::{FakeClock, FakeDirectory};
use toon_provider::nostr::wire::ImageRef;
use toon_provider::{router, DockerBackend, ProviderService};

const BASE: &str = "alpine:3.20";
/// Well outside the default lease id range, so a stray test container can
/// never collide with a real lease. The daemon is shared with everything
/// else on this host.
const ID: u32 = 59101;
const LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

async fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .output()
        .await
        .expect("invoke the docker CLI")
}

/// A root filesystem as one uncompressed layer: `alpine:3.20`, exported.
async fn base_rootfs_layer() -> Vec<u8> {
    assert!(docker(&["pull", BASE]).await.status.success());
    let created = docker(&["create", BASE, "true"]).await;
    assert!(created.status.success());
    let id = String::from_utf8_lossy(&created.stdout).trim().to_string();
    let exported = docker(&["export", &id]).await;
    let _ = docker(&["rm", &id]).await;
    assert!(exported.status.success());
    exported.stdout
}

/// A second layer adding one file, built in memory.
fn marker_layer() -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let data = b"spawned through the Image Registry\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(&mut header, "toon-marker", &data[..])
        .unwrap();
    tar.into_inner().unwrap()
}

#[tokio::test]
#[ignore = "needs a Docker daemon; run with `cargo test -- --ignored`"]
async fn a_registry_entry_image_runs_on_docker_by_digest() {
    let backend = Arc::new(DockerBackend::new());
    // Leave nothing behind from an earlier interrupted run.
    toon_provider::ComputeBackend::delete_container(backend.as_ref(), ID)
        .await
        .unwrap();

    // The image: the base rootfs in the TOON store as 1 MiB parts, the
    // marker layer upstream, the config and manifest in the store.
    let mut w = World::new().await;
    let rootfs = base_rootfs_layer().await;
    let marker = marker_layer();
    let config = json!({
        "architecture": "amd64",
        "os": "linux",
        "config": { "Cmd": ["sleep", "300"] },
        "rootfs": {
            "type": "layers",
            "diff_ids": [digest_of(&rootfs), digest_of(&marker)]
        }
    })
    .to_string()
    .into_bytes();
    let config_digest = w.store(&config, CONFIG, 64 * 1024).await;
    let rootfs_digest = w.store(&rootfs, LAYER_TAR, 1024 * 1024).await;
    let marker_digest = w.upstream(&marker, LAYER_TAR).await;
    let manifest = manifest_with_layers(
        (&config_digest, config.len()),
        &[
            (rootfs_digest.clone(), rootfs.len(), LAYER_TAR),
            (marker_digest.clone(), marker.len(), LAYER_TAR),
        ],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 4096).await;

    let config = toon_provider::ProviderConfig {
        workload_id_range_start: ID,
        workload_id_range_end: ID,
        ssh_port_start: Some(59301),
        workload_port_start: 59401,
        ..store_config(&w, vec![listing("basic", 1, 1)])
    };
    let directory = FakeDirectory::new();
    directory.seed_image_entry(w.entry(&manifest_digest, MANIFEST));
    let clock = FakeClock::at(NOW);
    let service = ProviderService::with_backend_clock_and_directory(
        config.clone(),
        backend.clone(),
        clock.clone(),
        directory.clone(),
    )
    .unwrap();
    let app = router(service.app_state());
    let h = StoreHarness {
        app,
        service,
        backend: common::FakeBackend::new(), // unused: the real one is above
        directory,
        provider: nostr_sdk::Keys::parse(&config.nostr_private_key)
            .unwrap()
            .public_key(),
        clock,
        config,
    };

    let tenant = nostr_sdk::Keys::generate();
    let (status, body) = spawn_as(
        &h,
        0x91,
        ImageRef::from_registry(manifest_digest.clone(), w.address(), RELAY),
        nostr_sdk::Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["access"]["ssh_port"], 59301, "{}", body);
    let name = toon_provider::compute::container_name(ID);
    let inspected = docker(&[
        "inspect",
        "-f",
        "{{.State.Running}} {{.Config.Image}}",
        &name,
    ])
    .await;
    let inspected = String::from_utf8_lossy(&inspected.stdout)
        .trim()
        .to_string();
    let (running, image) = inspected.split_once(' ').expect("running and image");
    assert_eq!(running, "true", "the workload is running");
    assert!(
        image.starts_with("sha256:"),
        "the workload runs the image by id, not by a tag: {}",
        image
    );
    // The upstream layer was pulled by digest; the rootfs came as parts.
    assert_eq!(
        w.registry_paths().await,
        vec![format!("/v2/{}/blobs/{}", REPOSITORY, marker_digest)]
    );
    assert!(w
        .gateway_paths()
        .await
        .contains(&format!("/raw/{}-part0", &rootfs_digest[7..19])));
    // Both layers are in the running filesystem.
    let ls = docker(&["exec", &name, "ls", "/toon-marker", "/bin/sh"]).await;
    assert!(
        ls.status.success(),
        "{}",
        String::from_utf8_lossy(&ls.stderr)
    );

    // Terminate through the app, as a tenant would, and it is gone.
    let request = signed(
        &h,
        "terminate",
        json!({ "workload_id": "91".repeat(32) }),
        Some(nostr_sdk::Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap()),
    );
    let (status, body) = post(&h.app, "/terminate", json!({ "request": request })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let gone = docker(&["inspect", &name]).await;
    assert!(!gone.status.success(), "the container was removed");
    let _ = docker(&["image", "rm", image]).await;
}
