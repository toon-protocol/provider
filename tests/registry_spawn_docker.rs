//! The paid spawn of an Image Registry image against a REAL Docker daemon:
//! the layers fetched down §8.4's chain, verified, assembled into an OCI
//! layout, loaded, and the workload run by the resulting image id.
//!
//! Both forms this provider fetches itself are run here, over the same
//! image: `{ digest, registry_entry }`, whose layers come from the entry's
//! sources (one from the stubbed TOON store, one from the stubbed upstream
//! registry), and `{ digest }` alone, whose every blob is found as a Blob
//! Record on the provider's Relay Set.
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
/// else on this host; the two forms take an id each so they never collide
/// with one another either.
const ENTRY_ID: u32 = 59101;
const DIGEST_ID: u32 = 59102;
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
    runs_on_docker(Form::Entry).await;
}

#[tokio::test]
#[ignore = "needs a Docker daemon; run with `cargo test -- --ignored`"]
async fn a_bare_digest_image_runs_on_docker_by_digest() {
    runs_on_docker(Form::BareDigest).await;
}

/// Which of the two forms names the image, and therefore where the
/// provider has to go for its blobs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `{ digest, registry_entry }`: the entry names a source per blob, and
    /// the marker layer's is the upstream registry.
    Entry,
    /// `{ digest }`: no entry at all, so every blob — the marker layer
    /// included — has to be in the store with a Blob Record on the Relay
    /// Set.
    BareDigest,
}

async fn runs_on_docker(form: Form) {
    let id = match form {
        Form::Entry => ENTRY_ID,
        Form::BareDigest => DIGEST_ID,
    };
    let seed: u8 = match form {
        Form::Entry => 0x91,
        Form::BareDigest => 0x92,
    };
    let ssh_port = 59301 + u16::from(form == Form::BareDigest);
    let backend = Arc::new(DockerBackend::new());
    // Leave nothing behind from an earlier interrupted run.
    toon_provider::ComputeBackend::delete_container(backend.as_ref(), id)
        .await
        .unwrap();

    // The image: the base rootfs in the TOON store as 1 MiB parts, the
    // config and manifest in the store, and the marker layer wherever the
    // form under test can reach it.
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
    let marker_digest = match form {
        Form::Entry => w.upstream(&marker, LAYER_TAR).await,
        Form::BareDigest => w.store(&marker, LAYER_TAR, 1024 * 1024).await,
    };
    let manifest = manifest_with_layers(
        (&config_digest, config.len()),
        &[
            (rootfs_digest.clone(), rootfs.len(), LAYER_TAR),
            (marker_digest.clone(), marker.len(), LAYER_TAR),
        ],
    );
    let manifest_digest = w.store(&manifest, MANIFEST, 4096).await;

    let config = toon_provider::ProviderConfig {
        workload_id_range_start: id,
        workload_id_range_end: id,
        ssh_port_start: Some(ssh_port),
        workload_port_start: 59401 + 10 * u16::from(form == Form::BareDigest),
        ..store_config(&w, vec![listing("basic", 1, 1)])
    };
    let directory = FakeDirectory::new();
    match form {
        Form::Entry => directory.seed_image_entry(w.entry(&manifest_digest, MANIFEST)),
        Form::BareDigest => seed_blob_records(&w, &directory),
    }
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

    let image = match form {
        Form::Entry => ImageRef::from_registry(manifest_digest.clone(), w.address(), RELAY),
        Form::BareDigest => ImageRef::by_digest(manifest_digest.clone()),
    };
    let tenant = nostr_sdk::Keys::generate();
    let (status, body) = spawn_as(
        &h,
        seed,
        image,
        nostr_sdk::Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["access"]["ssh_port"], ssh_port, "{}", body);
    let name = toon_provider::compute::container_name(id);
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
    // The rootfs came as parts either way; the marker layer came from
    // wherever this form could reach it.
    assert!(w
        .gateway_paths()
        .await
        .contains(&format!("/raw/{}-part0", &rootfs_digest[7..19])));
    match form {
        Form::Entry => assert_eq!(
            w.registry_paths().await,
            vec![format!("/v2/{}/blobs/{}", REPOSITORY, marker_digest)],
            "the entry's `oci` source was pulled by digest"
        ),
        Form::BareDigest => {
            assert!(
                w.registry_paths().await.is_empty(),
                "a bare digest pulls from no upstream registry"
            );
            assert!(w
                .gateway_paths()
                .await
                .contains(&format!("/raw/{}-part0", &marker_digest[7..19])));
        }
    }
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
        json!({ "workload_id": format!("{:02x}", seed).repeat(32) }),
        Some(nostr_sdk::Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap()),
    );
    let (status, body) = post(&h.app, "/terminate", json!({ "request": request })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let gone = docker(&["inspect", &name]).await;
    assert!(!gone.status.success(), "the container was removed");
    let _ = docker(&["image", "rm", image]).await;
}
