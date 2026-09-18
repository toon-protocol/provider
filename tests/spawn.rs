//! The spawn route, driven the way the provider's connector drives it: a
//! POST with a Lease Request in, JSON out. Assertions are on the answer and
//! on what the faked `ComputeBackend` was asked to run — never on the
//! provider's internal state.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nostr_sdk::Keys;
use serde_json::json;
use tower::ServiceExt;

use common::harness::{
    digest, error_of, harness, harness_with, harness_with_policy, listing, mint, post, restart,
    spawn, spawn_content, workload_id, RequestSpec, INTERVAL, NOW, PUBLIC_IP, SSH_KEY,
};
use common::{BackendCall, FakeBackend, FakeClock, FakeDirectory};
use toon_provider::compute::{ContainerConfig, PortMapping};
use toon_provider::nostr::wire::{ImageRef, PortRequest, Protocol, SpawnContent};
use toon_provider::provider::ImagePolicyConfig;
use toon_provider::Clock;

// ── success ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_spawn_starts_the_workload_and_answers_the_access_details() {
    let h = harness().await;
    let content = spawn_content(1);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).request()).await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["workload_id"], workload_id(1));
    assert_eq!(body["role"], "standalone");
    assert_eq!(
        body["expires_at"],
        NOW + INTERVAL,
        "one payment buys one Lease Interval"
    );
    assert_eq!(body["access"]["host"], PUBLIC_IP);
    assert_eq!(body["access"]["ssh_port"], 40000);
    assert_eq!(
        body["access"]["ports"],
        json!([{ "container_port": 443, "host_port": 41000 }])
    );

    assert_eq!(
        h.backend.calls(),
        vec![BackendCall::Create(1000), BackendCall::Start(1000)]
    );
    let created = &h.backend.created()[0];
    assert_eq!(
        created.image,
        format!("docker.io/library/alpine@{}", digest()),
        "pulled by reference@digest so the daemon verifies the bytes"
    );
    assert_eq!(created.ssh_key.as_deref(), Some(SSH_KEY));
    assert_eq!(created.host_port, Some(40000), "the SSH forward");
    assert_eq!(
        created.ports,
        vec![PortMapping {
            host_port: 41000,
            container_port: 443,
            protocol: "tcp".to_string()
        }]
    );
    assert_eq!(created.env.get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(created.entrypoint.as_deref(), Some("/bin/sh"));
    assert_eq!(
        created.args,
        vec!["-c".to_string(), "sleep 300".to_string()]
    );
    assert_eq!(created.cpu_millicores, 500);
    assert_eq!(created.memory_mb, 256);
    assert!(
        created.data_path.is_some(),
        "volume_gb asked for a persistent volume"
    );
}

// ── refusals, in the spec's order ───────────────────────────────────────

/// A spawn brings the token its lease will keep, and `status` with that
/// token is how a tenant sees that it was kept (spec §6.1). Nothing else
/// about the tenant is stored, so this is the whole of what the spawn
/// established.
#[tokio::test]
async fn a_spawn_needs_no_prior_token_and_stores_the_one_it_brings() {
    let h = harness().await;
    let content = spawn_content(1);
    let token = mint().continuation_for(&h.provider);

    // Nothing was stored before this: the token is new, and the spawn is
    // accepted on it alone.
    let (status, body) = spawn(
        &h,
        RequestSpec::spawn(&h, &content)
            .with_token(&token)
            .request(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let spec = RequestSpec::about(&h, "status", &content.workload_id).with_token(&token);
    let (status, body) = post(&h.app, "/status", json!({ "request": spec.request() })).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], "running");
}

/// A spawn with no `continuation` at all would buy a lease nobody could ever
/// read, extend or stop, so it is a request the tenant must correct — and
/// nothing is started for it.
#[tokio::test]
async fn a_spawn_with_no_token_is_invalid() {
    let h = harness().await;
    let spec = RequestSpec::spawn(&h, &spawn_content(1)).with_no_token();
    let (status, body) = spawn(&h, spec.request()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert_eq!(error_of(&body), "invalid_request");
    assert!(h.backend.calls().is_empty(), "nothing was started");
}

#[tokio::test]
async fn an_expired_request_is_stale() {
    let h = harness().await;
    let spec = RequestSpec {
        expiration: Some(NOW - 1),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (status, body) = spawn(&h, spec.request()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "stale_request");
}

#[tokio::test]
async fn a_request_valid_for_more_than_300_seconds_is_stale() {
    let h = harness().await;
    let spec = RequestSpec {
        expiration: Some(NOW + 301),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (_, body) = spawn(&h, spec.request()).await;
    assert_eq!(error_of(&body), "stale_request");

    // Exactly 300 s is fine.
    let spec = RequestSpec {
        expiration: Some(NOW + 300),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (status, body) = spawn(&h, spec.request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

#[tokio::test]
async fn a_request_with_no_expiration_is_invalid() {
    let h = harness().await;
    let spec = RequestSpec {
        expiration: None,
        ..RequestSpec::spawn(&h, &spawn_content(1))
    };
    let (_, body) = spawn(&h, spec.request()).await;
    assert_eq!(error_of(&body), "invalid_request");
}

/// A Lease Request names ONE provider on every op, a spawn included, and a
/// request naming another provider is never accepted here however good its
/// token is (spec §6.1, §7).
#[tokio::test]
async fn a_request_naming_another_provider_is_refused() {
    let h = harness().await;
    let spec =
        RequestSpec::spawn(&h, &spawn_content(1)).addressed_to(Keys::generate().public_key());
    let (status, body) = spawn(&h, spec.request()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "invalid_request");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("another provider"));
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_request_for_another_op_is_invalid() {
    let h = harness().await;
    // The `.spawn` route serves `op = spawn` and nothing else: a request
    // meant to reserve capacity, or to read a lease, is not served here.
    for op in ["standby", "status", "terminate", "nonsense"] {
        let spec = RequestSpec {
            op,
            ..RequestSpec::spawn(&h, &spawn_content(1))
        };
        let (_, body) = spawn(&h, spec.request()).await;
        assert_eq!(error_of(&body), "invalid_request", "op={}", op);
    }
    assert!(h.backend.calls().is_empty());
}

/// `request_id` is what the replay set keys on, so a request that carries
/// none it could key on is refused before anything else happens.
#[tokio::test]
async fn a_request_id_that_is_not_32_bytes_of_hex_is_invalid() {
    let h = harness().await;
    for bad in ["", "ab", &"AB".repeat(32), &"zz".repeat(32)] {
        let spec = RequestSpec {
            request_id: bad.to_string(),
            ..RequestSpec::spawn(&h, &spawn_content(1))
        };
        let (_, body) = spawn(&h, spec.request()).await;
        assert_eq!(error_of(&body), "invalid_request", "request_id={:?}", bad);
    }
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_body_that_is_not_an_envelope_is_invalid() {
    let h = harness().await;
    let (status, body) = post(&h.app, "/listings/basic/v1/spawn", json!({ "hello": 1 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "invalid_request");
}

#[tokio::test]
async fn runtime_flags_host_mounts_devices_and_capabilities_are_invalid() {
    // ADR 0004: privileges come from the listing, never from the spawn.
    let h = harness().await;
    for (field, value) in [
        ("privileged", json!(true)),
        ("runtime_flags", json!(["--privileged"])),
        ("mounts", json!([{ "host": "/", "container": "/host" }])),
        ("devices", json!(["/dev/kvm"])),
        ("capabilities", json!(["SYS_ADMIN"])),
    ] {
        let mut content = serde_json::to_value(spawn_content(1)).unwrap();
        content[field] = value;
        let spec = RequestSpec {
            content,
            ..RequestSpec::spawn(&h, &spawn_content(1))
        };
        let (status, body) = spawn(&h, spec.request()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {}", field, body);
        assert_eq!(error_of(&body), "invalid_request", "{}", field);
    }
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn asking_for_docker_in_the_workload_is_refused_when_the_listing_does_not_grant_it() {
    // Spec §4.4 and ADR 0004: a Docker daemon inside the workload is a
    // capability the LISTING grants, and the harness listing grants nothing.
    // Every shape the ask could take — the capability by name, a flag, the
    // host socket as a mount, the device a nested VM would want — is one
    // refusal, `invalid_request`, and nothing reaches the backend. Starting a
    // workload anyway would be worse than refusing: the tenant pays for the
    // interval either way (spec §2), and would only find the missing daemon
    // once its build had failed inside a lease it had already bought.
    let h = harness().await;
    for (field, value) in [
        ("capabilities", json!(["docker"])),
        ("docker", json!(true)),
        ("privileged", json!(true)),
        (
            "mounts",
            json!([{ "host": "/var/run/docker.sock", "container": "/var/run/docker.sock" }]),
        ),
        (
            "volumes",
            json!(["/var/run/docker.sock:/var/run/docker.sock"]),
        ),
        ("devices", json!(["/dev/kvm"])),
    ] {
        let mut content = serde_json::to_value(spawn_content(1)).unwrap();
        content[field] = value;
        let spec = RequestSpec {
            content,
            ..RequestSpec::spawn(&h, &spawn_content(1))
        };
        let (status, body) = spawn(&h, spec.request()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {}", field, body);
        assert_eq!(error_of(&body), "invalid_request", "{}", field);
    }
    assert!(
        h.backend.calls().is_empty(),
        "no workload starts on a capability that was never granted"
    );

    // And the daemon a tenant might hope to find is not smuggled in by the
    // fields a spawn IS allowed to set: env is env, not a grant.
    let content = SpawnContent {
        env: std::collections::BTreeMap::from([(
            "DOCKER_HOST".to_string(),
            "unix:///var/run/docker.sock".to_string(),
        )]),
        ..spawn_content(1)
    };
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let created = &h.backend.created()[0];
    assert_eq!(
        created.env.get("DOCKER_HOST").map(String::as_str),
        Some("unix:///var/run/docker.sock"),
        "the variable is set, and points at a socket nothing mounted"
    );
}

/// The Image Registry entry address of a plausible publisher: spec §6.2's
/// `30434:<pubkey>:<d>`, with the entry's `<name>:<tag>` as the `d`.
const ENTRY_ADDRESS: &str =
    "30434:4444444444444444444444444444444444444444444444444444444444444444:web:1.0";

#[tokio::test]
async fn an_image_registry_form_this_provider_cannot_serve_is_refused_image() {
    // Not `invalid_request`: both forms are exactly what §6.2 allows, and a
    // tenant that gets `invalid_request` would go and fix a request that is
    // already correct. A registry entry is resolved through the relay it
    // hints at (`tests/registry_spawn.rs` is where that succeeds); here the
    // relay holds no such entry. A bare digest is resolved through Blob
    // Records on this provider's Relay Set (`tests/bare_digest.rs`); here
    // it holds none for it. Either way the spawn is refused before capacity
    // is counted and before any container is created.
    let h = harness().await;
    for (label, image, expected) in [
        (
            "digest with a registry entry",
            ImageRef::from_registry(digest(), ENTRY_ADDRESS, "wss://relay.example"),
            "no Image Registry entry",
        ),
        (
            "digest alone",
            ImageRef::by_digest(digest()),
            "no source is known for blob",
        ),
    ] {
        let content = SpawnContent {
            image,
            ..spawn_content(1)
        };
        let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).request()).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}: {}",
            label,
            body
        );
        assert_eq!(error_of(&body), "refused_image", "{}", label);
        assert!(
            body["message"].as_str().unwrap().contains(expected),
            "{}: {}",
            label,
            body
        );
        assert!(
            h.backend.calls().is_empty(),
            "{}: nothing was started",
            label
        );
    }
}

#[tokio::test]
async fn an_image_registry_form_is_refused_before_capacity_is_counted() {
    // A one-slot listing with its slot already taken. `no_capacity` would be
    // the refusal for a runnable image; the image is refused first, so a
    // tenant learns the real reason rather than one that would change if it
    // waited.
    let h = harness_with(vec![listing("basic", 1, 1)]).await;
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);

    let content = SpawnContent {
        image: ImageRef::by_digest(digest()),
        ..spawn_content(2)
    };
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).request()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(error_of(&body), "refused_image");
}

#[tokio::test]
async fn an_image_that_is_neither_of_the_three_forms_is_invalid_request() {
    let h = harness().await;
    let cases = [
        (
            "a reference and a registry entry name two sources",
            json!({
                "reference": "docker.io/library/alpine",
                "digest": digest(),
                "registry_entry": { "address": ENTRY_ADDRESS, "relay": "wss://relay.example" },
            }),
        ),
        (
            "a digest that is not sha256:<64 hex>, with no reference",
            json!({ "digest": "sha256:abc" }),
        ),
        (
            "a registry entry address that is not an Image Registry coordinate",
            json!({
                "digest": digest(),
                "registry_entry": { "address": "30432:aa:basic", "relay": "wss://relay.example" },
            }),
        ),
        (
            "a registry entry with no relay to look it up on",
            json!({ "digest": digest(), "registry_entry": { "address": ENTRY_ADDRESS, "relay": "" } }),
        ),
        (
            "a registry entry missing a field altogether",
            json!({ "digest": digest(), "registry_entry": { "address": ENTRY_ADDRESS } }),
        ),
        (
            "no digest at all",
            json!({ "reference": "docker.io/library/alpine" }),
        ),
    ];
    for (label, image) in cases {
        let mut content = serde_json::to_value(spawn_content(1)).unwrap();
        content["image"] = image;
        let (status, body) = spawn(&h, RequestSpec::op(&h, "spawn", content).request()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {}", label, body);
        assert_eq!(error_of(&body), "invalid_request", "{}", label);
    }
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_template_grants_nothing_and_a_capability_beside_it_is_still_refused() {
    // ADR 0004: a Template grants nothing, and the provider never reads one.
    // `template` rides along informationally; anything that looks like a
    // privilege beside it is still refused.
    let h = harness().await;
    let content = SpawnContent {
        template: Some(
            "30436:4444444444444444444444444444444444444444444444444444444444444444:static-site"
                .to_string(),
        ),
        ..spawn_content(1)
    };
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let created = &h.backend.created()[0];
    assert_eq!(
        created.image,
        format!("docker.io/library/alpine@{}", digest()),
        "the template changed nothing about what runs"
    );
    // The lease got exactly the capabilities of the listing it was bought on
    // and no more: that listing grants none, and the workload the backend was
    // asked for is the one a spawn WITHOUT the Template produces, field for
    // field. A `ContainerConfig` has no privilege, device, mount or
    // capability field at all, so there is nothing for a Template to reach.
    // `capabilities::grant_refusal` refuses every capability this build could
    // publish, so a listing that grants none is the only listing there is —
    // and the strongest statement of "exactly its listing's capabilities"
    // available until the backend supplies one.
    assert!(
        listing("basic", 1, 2).capabilities.is_empty(),
        "the listing these leases are bought on grants nothing"
    );
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(2)).request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let by_hand = &h.backend.created()[1];
    assert_eq!(
        ContainerConfig {
            id: created.id,
            name: created.name.clone(),
            ssh_key: created.ssh_key.clone(),
            host_port: created.host_port,
            ports: created.ports.clone(),
            ..by_hand.clone()
        },
        *created,
        "a Template changes nothing but the id and the ports the provider chose"
    );

    for privilege in ["privileged", "capabilities", "devices", "mounts"] {
        let mut with = serde_json::to_value(&content).unwrap();
        with[privilege] = json!(true);
        let (status, body) = spawn(&h, RequestSpec::op(&h, "spawn", with).request()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {}", privilege, body);
        assert_eq!(error_of(&body), "invalid_request", "{}", privilege);
    }
}

#[tokio::test]
async fn malformed_ids_keys_images_and_ports_are_invalid() {
    let h = harness().await;
    let cases: Vec<(&str, SpawnContent)> = vec![
        (
            "short workload id",
            SpawnContent {
                workload_id: "abcd".to_string(),
                ..spawn_content(1)
            },
        ),
        (
            "no ssh key",
            SpawnContent {
                ssh_public_key: "".to_string(),
                ..spawn_content(1)
            },
        ),
        (
            "a tag instead of a digest",
            SpawnContent {
                image: ImageRef::upstream("docker.io/library/alpine:latest".to_string(), digest()),
                ..spawn_content(1)
            },
        ),
        (
            "a digest that is not sha256:<64 hex>",
            SpawnContent {
                image: ImageRef::upstream(
                    "docker.io/library/alpine".to_string(),
                    "sha256:abc".to_string(),
                ),
                ..spawn_content(1)
            },
        ),
        (
            "port 0",
            SpawnContent {
                ports: vec![PortRequest {
                    container_port: 0,
                    protocol: Protocol::Tcp,
                }],
                ..spawn_content(1)
            },
        ),
        (
            "a volume bigger than the listing's storage",
            SpawnContent {
                volume_gb: Some(5),
                ..spawn_content(1)
            },
        ),
    ];
    for (label, content) in cases {
        let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).request()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {}", label, body);
        assert_eq!(error_of(&body), "invalid_request", "{}", label);
    }
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn a_listing_version_this_provider_does_not_sell_is_wrong_listing_version() {
    let h = harness().await;
    for path in [
        "/listings/basic/v2/spawn",
        "/listings/gpu/v1/spawn",
        "/listings/basic/latest/spawn",
    ] {
        let event = RequestSpec::spawn(&h, &spawn_content(1)).request();
        let (status, body) = post(&h.app, path, json!({ "request": event })).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}: {}", path, body);
        assert_eq!(error_of(&body), "wrong_listing_version", "{}", path);
    }
}

#[tokio::test]
async fn a_workload_id_held_by_another_tenant_is_taken() {
    let h = harness().await;
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK);

    // A different token, the same id.
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&body), "workload_id_taken");
    assert_eq!(
        h.backend.calls().len(),
        2,
        "only the first spawn touched the backend"
    );
}

#[tokio::test]
async fn the_same_tenant_respawning_an_id_it_holds_is_taken_too() {
    let h = harness().await;
    let token = mint().continuation_for(&h.provider);
    let first = RequestSpec::spawn(&h, &spawn_content(1)).with_token(&token);
    let (status, _) = spawn(&h, first.request()).await;
    assert_eq!(status, StatusCode::OK);
    // The same token again, on a request of its own: a spawn buys a NEW
    // lease, and the id names a lease that already exists.
    let again = RequestSpec::spawn(&h, &spawn_content(1)).with_token(&token);
    let (_, body) = spawn(&h, again.request()).await;
    assert_eq!(error_of(&body), "workload_id_taken");
}

#[tokio::test]
async fn a_full_listing_is_no_capacity() {
    let h = harness_with(vec![listing("basic", 1, 1)]).await;
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(2)).request()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_of(&body), "no_capacity");
    assert_eq!(h.backend.calls().len(), 2);
}

#[tokio::test]
async fn capacity_is_per_listing_name_across_versions() {
    // The one slot is filled on v1, while v1 is still the version on sale.
    // Then the price changes (a new version and a restart, ADR 0009) and v2
    // is asked for the same hardware.
    let h = harness_with(vec![listing("basic", 1, 1)]).await;
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK);

    let h = restart(
        vec![listing("basic", 1, 1), listing("basic", 2, 1)],
        h.provider_key.clone(),
        h.state_path.clone(),
        h.backend.clone(),
        h.clock.clone(),
        h.directory.clone(),
        common::stub_registry().await,
        ImagePolicyConfig::default(),
    )
    .await;
    h.service.restore_leases().await;

    let event = RequestSpec::spawn(&h, &spawn_content(2)).request();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v2/spawn",
        json!({ "request": event }),
    )
    .await;
    assert_eq!(
        error_of(&body),
        "no_capacity",
        "v2 sells the same hardware as v1"
    );
}

#[tokio::test]
async fn a_replayed_lease_request_is_refused() {
    let h = harness().await;
    let event = RequestSpec::spawn(&h, &spawn_content(1)).request();
    let (status, _) = spawn(&h, event.clone()).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = spawn(&h, event).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&body), "stale_request");
    assert_eq!(h.backend.calls().len(), 2, "the replay started nothing");
}

#[tokio::test]
async fn a_request_refused_after_acceptance_cannot_be_resent_either() {
    // The id is remembered once the request was accepted as fresh and ours,
    // so a captured refusal cannot be replayed onto the right route later.
    // A tenant sends a new request instead.
    let h = harness().await;
    let event = RequestSpec::spawn(&h, &spawn_content(1)).request();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v2/spawn",
        json!({ "request": event.clone() }),
    )
    .await;
    assert_eq!(error_of(&body), "wrong_listing_version");
    let (_, body) = spawn(&h, event).await;
    assert_eq!(error_of(&body), "stale_request");
}

#[tokio::test]
async fn the_first_failing_step_is_the_one_reported() {
    // Every later fault present, one earlier fault added per case.
    let h = harness_with(vec![listing("basic", 1, 1)]).await;
    // Fill the listing and take an id, so steps 4 and 6 would fail.
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK);

    // 1 before 2: a stale request on an unsold version is stale.
    let stale = RequestSpec {
        expiration: Some(NOW - 1),
        ..RequestSpec::spawn(&h, &spawn_content(1))
    }
    .request();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v9/spawn",
        json!({ "request": stale }),
    )
    .await;
    assert_eq!(error_of(&body), "stale_request");

    // invalid content before 2: a runtime flag on an unsold version.
    let mut content = serde_json::to_value(spawn_content(1)).unwrap();
    content["privileged"] = json!(true);
    let flagged = RequestSpec {
        content,
        ..RequestSpec::spawn(&h, &spawn_content(1))
    }
    .request();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v9/spawn",
        json!({ "request": flagged }),
    )
    .await;
    assert_eq!(error_of(&body), "invalid_request");

    // 2 before 3/4/6: unsold version, with a standby set this provider holds
    // the wrong position in for the route, a taken id, full.
    let content = SpawnContent {
        standby_set: Some(vec![
            Keys::generate().public_key().to_hex(),
            h.provider.to_hex(),
        ]),
        ..spawn_content(1)
    };
    let event = RequestSpec::spawn(&h, &content).request();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v9/spawn",
        json!({ "request": event }),
    )
    .await;
    assert_eq!(error_of(&body), "wrong_listing_version");

    // 3 before 4/6.
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &content).request()).await;
    assert_eq!(error_of(&body), "invalid_request");

    // 4 before 6: a taken id on a full listing is taken.
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(error_of(&body), "workload_id_taken");

    // 6 on its own.
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(2)).request()).await;
    assert_eq!(error_of(&body), "no_capacity");
}

#[tokio::test]
async fn a_workload_that_fails_to_start_is_no_capacity_and_releases_its_slot() {
    let h = harness_with(vec![listing("basic", 1, 1)]).await;
    h.backend.fail_next_create("pull failed: manifest unknown");
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "no_capacity");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("manifest unknown"));

    // The slot and the id are free again: the tenant's next try succeeds.
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

#[tokio::test]
async fn payment_headers_are_never_read() {
    // ADR 0005: a packet through a hop carries no X-TOON-* headers, so a
    // request that carries them must be served exactly as one that does not.
    let h = harness().await;
    let event = RequestSpec::spawn(&h, &spawn_content(1)).request();
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listings/basic/v1/spawn")
                .header("content-type", "application/json")
                .header("x-toon-payer", "solana:nobody")
                .header("x-toon-amount", "0")
                .header("x-toon-chain", "solana")
                .body(Body::from(json!({ "request": event }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ── after the spawn ─────────────────────────────────────────────────────

#[tokio::test]
async fn an_unpaid_lease_expires_and_its_workload_id_is_free_again() {
    let h = harness_with(vec![listing("basic", 1, 1)]).await;
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK);
    let expires_at = body["expires_at"].as_u64().unwrap();

    h.clock.set(expires_at - 1);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(
        h.backend.calls().len(),
        2,
        "still paid for: nothing destroyed"
    );

    h.clock.set(expires_at);
    h.service.sweep_expired_leases(h.clock.now()).await;
    assert_eq!(
        h.backend.calls()[2..],
        [BackendCall::Stop(1000), BackendCall::Delete(1000)],
        "no grace period"
    );

    // The id and the slot are free: the same tenant-chosen id spawns again.
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
}

#[tokio::test]
async fn a_spawned_lease_survives_a_restart() {
    let h = harness().await;
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let expires_at = body["expires_at"].as_u64().unwrap();

    // A new process over the same lease table, with the workload still
    // running on the backend.
    let backend = FakeBackend::new();
    backend.seed_running(1000);
    let restarted = restart(
        vec![listing("basic", 1, 2)],
        h.provider_key.clone(),
        h.state_path.clone(),
        backend.clone(),
        FakeClock::at(NOW + 10),
        FakeDirectory::new(),
        common::stub_registry().await,
        ImagePolicyConfig::default(),
    )
    .await;
    restarted.service.restore_leases().await;

    // It still holds its workload id...
    let (_, body) = spawn(
        &restarted,
        RequestSpec::spawn(&restarted, &spawn_content(1)).request(),
    )
    .await;
    assert_eq!(error_of(&body), "workload_id_taken");
    // ...and it still expires when it was going to.
    restarted.service.sweep_expired_leases(expires_at).await;
    assert_eq!(
        backend.calls(),
        vec![BackendCall::Stop(1000), BackendCall::Delete(1000)]
    );
}

#[tokio::test]
async fn a_workload_that_vanished_keeps_its_id_until_its_lease_ends() {
    // The daemon no longer has toon-1000, but its lease is still paid for:
    // the next spawn must take the next id, not refuse, and not reuse 1000.
    let h = harness().await;
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::OK);
    h.backend.vanish(1000);

    h.clock.advance(1);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(2)).request()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["access"]["ssh_port"], 40001, "the second id, 1001");
    assert_eq!(h.backend.calls()[2], BackendCall::Create(1001));
}

/// `provider` is one key, not a list: a request that tries to address two
/// providers is a shape this spec does not name, and an unknown shape is
/// refused rather than read for the half that fits (spec §6.1).
#[tokio::test]
async fn a_request_naming_a_second_provider_is_refused() {
    let h = harness().await;
    let mut request = RequestSpec::spawn(&h, &spawn_content(1)).request();
    request["provider"] = json!([h.provider.to_hex(), Keys::generate().public_key().to_hex()]);
    let (_, body) = spawn(&h, request).await;
    assert_eq!(error_of(&body), "invalid_request");
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn ports_are_checked_against_the_listing_not_before_it() {
    // §6.2 step 2: the listing version first, then whether the ports fit.
    let h = harness().await;
    let content = SpawnContent {
        ports: (1..=17)
            .map(|p| PortRequest {
                container_port: p,
                protocol: Protocol::Tcp,
            })
            .collect(),
        ..spawn_content(1)
    };
    let event = RequestSpec::spawn(&h, &content).request();
    let (_, body) = post(
        &h.app,
        "/listings/basic/v9/spawn",
        json!({ "request": event }),
    )
    .await;
    assert_eq!(error_of(&body), "wrong_listing_version");
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &content).request()).await;
    assert_eq!(error_of(&body), "invalid_request");
}

// ── image policy (M1-5) ─────────────────────────────────────────────────

#[tokio::test]
async fn a_paid_spawn_with_a_denied_digest_is_refused_image() {
    let policy = ImagePolicyConfig {
        deny_digests: vec![digest()],
        ..Default::default()
    };
    let h = harness_with_policy(vec![listing("basic", 1, 2)], policy).await;
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).request()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", body);
    assert_eq!(error_of(&body), "refused_image");
    assert!(
        h.backend.calls().is_empty(),
        "a refused image must never reach the compute backend"
    );
}

#[tokio::test]
async fn a_denied_image_is_reported_before_a_full_listing() {
    // Image policy (step 5) runs before capacity (step 6): a request that is
    // both denied-image and over-capacity answers `refused_image`, the
    // spec's order (§6.2), the same order `availability` applies.
    //
    // Two distinct, independently-resolvable images so the first spawn can
    // legitimately fill the listing's one slot before the second is tried:
    // `common::stub_registry`'s catch-all only ever verifies one digest, so
    // this test mounts its own registry with both.
    let registry = wiremock::MockServer::start().await;
    let good = common::valid_manifest_bytes();
    let good_digest = format!("sha256:{}", common::sha256_hex(&good));
    let denied_bytes = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 100,
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "size": 12345,
            "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }]
    })
    .to_string()
    .into_bytes();
    let denied_digest = format!("sha256:{}", common::sha256_hex(&denied_bytes));

    for (digest, bytes) in [(&good_digest, good), (&denied_digest, denied_bytes)] {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/v2/library/alpine/manifests/{}",
                digest
            )))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(&registry)
            .await;
    }

    let policy = ImagePolicyConfig {
        deny_digests: vec![denied_digest.clone()],
        ..Default::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let h = restart(
        vec![listing("basic", 1, 1)],
        Keys::generate().secret_key().to_secret_hex(),
        state_path,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
        policy,
    )
    .await;

    // Fill the listing's one slot with the undenied image.
    let mut runnable = spawn_content(1);
    runnable.image.digest = good_digest;
    let (status, _) = spawn(&h, RequestSpec::spawn(&h, &runnable).request()).await;
    assert_eq!(status, StatusCode::OK);

    // A different workload id (so `workload_id_taken` does not fire first)
    // naming the denied digest, on a now-full listing.
    let mut refused = spawn_content(2);
    refused.image.digest = denied_digest;
    let (_, body) = spawn(&h, RequestSpec::spawn(&h, &refused).request()).await;
    assert_eq!(error_of(&body), "refused_image");
}
