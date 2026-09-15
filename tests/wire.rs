//! Every request and response shape round-trips through serde, and the
//! spawn content refuses what ADR 0004 says a spawn may not carry.

use std::collections::BTreeMap;

use serde_json::json;
use toon_provider::nostr::kinds::K_LEASE_REQUEST;
use toon_provider::nostr::wire::*;

fn spawn_content() -> SpawnContent {
    SpawnContent {
        workload_id: "ab".repeat(32),
        image: ImageRef {
            reference: "docker.io/library/alpine".to_string(),
            digest: format!("sha256:{}", "cd".repeat(32)),
            registry_entry: None,
        },
        env: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
        ports: vec![PortRequest {
            container_port: 443,
            protocol: Protocol::Tcp,
        }],
        volume_gb: Some(2),
        ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample tenant".to_string(),
        entrypoint: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), "sleep 300".to_string()]),
        standby_set: None,
        template: None,
    }
}

#[test]
fn spawn_content_round_trips() {
    let content = spawn_content();
    let json = serde_json::to_string(&content).unwrap();
    let back: SpawnContent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, content);
}

#[test]
fn spawn_content_matches_the_spec_field_names() {
    // The wire names are the spec's (§6.2), not Rust's.
    let value = serde_json::to_value(spawn_content()).unwrap();
    assert_eq!(
        value["image"]["digest"],
        format!("sha256:{}", "cd".repeat(32))
    );
    assert_eq!(value["ports"][0]["container_port"], 443);
    assert_eq!(value["ports"][0]["protocol"], "tcp");
    assert_eq!(value["volume_gb"], 2);
    assert!(value["standby_set"].is_null(), "absent options are omitted");
}

#[test]
fn a_spawn_may_not_carry_runtime_flags_host_mounts_devices_or_capabilities() {
    // ADR 0004: only the listing grants privileges. Each of these must fail
    // to parse at all, so no handler can ever act on it.
    let base = serde_json::to_value(spawn_content()).unwrap();
    for (field, value) in [
        ("privileged", json!(true)),
        ("runtime_flags", json!(["--privileged"])),
        ("mounts", json!([{ "host": "/", "container": "/host" }])),
        ("volumes", json!(["/:/host"])),
        ("devices", json!(["/dev/kvm"])),
        ("capabilities", json!(["SYS_ADMIN"])),
        ("cap_add", json!(["NET_ADMIN"])),
    ] {
        let mut with = base.clone();
        with[field] = value;
        assert!(
            serde_json::from_value::<SpawnContent>(with).is_err(),
            "a spawn carrying `{}` must not parse",
            field
        );
    }
}

#[test]
fn standby_set_and_registry_entry_parse_so_they_can_be_refused_by_name() {
    let mut with = serde_json::to_value(spawn_content()).unwrap();
    with["standby_set"] = json!(["aa".repeat(32), "bb".repeat(32)]);
    with["image"]["registry_entry"] = json!({ "address": "30434:pk:d", "relay": "wss://r" });
    let parsed: SpawnContent = serde_json::from_value(with).unwrap();
    assert_eq!(parsed.standby_set.as_ref().map(Vec::len), Some(2));
    assert!(parsed.image.registry_entry.is_some());
}

#[test]
fn lease_request_envelope_round_trips_a_signed_event() {
    let keys = nostr_sdk::Keys::generate();
    let event = nostr_sdk::EventBuilder::new(
        nostr_sdk::Kind::Custom(K_LEASE_REQUEST),
        serde_json::to_string(&spawn_content()).unwrap(),
    )
    .tags([
        nostr_sdk::Tag::custom(nostr_sdk::TagKind::custom("op"), ["spawn"]),
        nostr_sdk::Tag::expiration(nostr_sdk::Timestamp::from(1_700_000_300u64)),
    ])
    .sign_with_keys(&keys)
    .unwrap();

    let envelope = LeaseRequestEnvelope {
        request: event.clone(),
    };
    let json = serde_json::to_string(&envelope).unwrap();
    let back: LeaseRequestEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(back.request, event);
    assert!(
        back.request.verify().is_ok(),
        "the signature survives the trip"
    );
    assert_eq!(back.request.kind.as_u16(), K_LEASE_REQUEST);
}

#[test]
fn spawn_response_round_trips_and_writes_the_spec_shape() {
    let response = SpawnResponse {
        workload_id: "ab".repeat(32),
        role: Role::Standalone,
        expires_at: 1_757_350_000,
        access: Some(Access {
            host: "203.0.113.7".to_string(),
            ssh_port: 22022,
            ports: vec![PortAccess {
                container_port: 443,
                host_port: 30443,
            }],
        }),
    };
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["role"], "standalone");
    assert_eq!(value["access"]["ssh_port"], 22022);
    assert_eq!(value["access"]["ports"][0]["host_port"], 30443);
    let back: SpawnResponse = serde_json::from_value(value).unwrap();
    assert_eq!(back, response);
}

#[test]
fn a_standby_response_omits_access() {
    let value = serde_json::to_value(SpawnResponse {
        workload_id: "ab".repeat(32),
        role: Role::Standby,
        expires_at: 1,
        access: None,
    })
    .unwrap();
    assert!(value.get("access").is_none());
}

#[test]
fn every_error_code_serialises_as_the_spec_writes_it() {
    let expected = [
        (ErrorCode::UnknownWorkload, "unknown_workload"),
        (ErrorCode::WrongListingVersion, "wrong_listing_version"),
        (ErrorCode::NotTenant, "not_tenant"),
        (ErrorCode::WorkloadIdTaken, "workload_id_taken"),
        (ErrorCode::RefusedImage, "refused_image"),
        (ErrorCode::NoCapacity, "no_capacity"),
        (ErrorCode::NoMatchingArch, "no_matching_arch"),
        (ErrorCode::InvalidRequest, "invalid_request"),
        (ErrorCode::Expired, "expired"),
        (ErrorCode::NotStandby, "not_standby"),
        (ErrorCode::BadSignature, "bad_signature"),
        (ErrorCode::StaleRequest, "stale_request"),
    ];
    for (code, text) in expected {
        let value = serde_json::to_value(ErrorResponse::new(code, "why")).unwrap();
        assert_eq!(value, json!({ "error": text, "message": "why" }));
        let back: ErrorResponse = serde_json::from_value(value).unwrap();
        assert_eq!(back.error, code);
    }
}

#[test]
fn extend_status_and_terminate_shapes_round_trip() {
    let extend = ExtendRequest {
        workload_id: "ab".repeat(32),
    };
    let back: ExtendRequest =
        serde_json::from_str(&serde_json::to_string(&extend).unwrap()).unwrap();
    assert_eq!(back, extend);

    let content = WorkloadContent {
        workload_id: "ab".repeat(32),
    };
    let back: WorkloadContent =
        serde_json::from_str(&serde_json::to_string(&content).unwrap()).unwrap();
    assert_eq!(back, content);

    let response = ExtendResponse {
        workload_id: "ab".repeat(32),
        expires_at: 42,
    };
    let back: ExtendResponse =
        serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
    assert_eq!(back, response);
}

#[test]
fn resources_round_trip_with_an_optional_gpu() {
    let with_gpu = Resources {
        cpu_millicores: 2000,
        memory_mb: 4096,
        storage_gb: 20,
        gpu: Some("rtx-4090".to_string()),
    };
    let value = serde_json::to_value(&with_gpu).unwrap();
    assert_eq!(value["gpu"], "rtx-4090");
    assert_eq!(
        serde_json::from_value::<Resources>(value).unwrap(),
        with_gpu
    );

    let without = Resources {
        gpu: None,
        ..with_gpu
    };
    assert!(serde_json::to_value(&without).unwrap().get("gpu").is_none());
}
