//! Every request and response shape round-trips through serde, and the
//! spawn content refuses what ADR 0004 says a spawn may not carry.

use std::collections::BTreeMap;

use serde_json::json;
use toon_provider::nostr::directory_events::{
    EvictionContent, ListingContent, LivenessContent, ProfileContent, Settlement,
};
use toon_provider::nostr::image_events::{
    blob_record_event, image_entry_event, template_event, BlobRecord, BlobRecordContent,
    BlobSource, ImageEntry, ImageEntryContent, Template, TemplateContent,
};
use toon_provider::nostr::kinds::{K_BLOB, K_IMAGE, K_LEASE_REQUEST, K_TEMPLATE, TOON_LABEL};
use toon_provider::nostr::wire::*;

fn spawn_content() -> SpawnContent {
    SpawnContent {
        workload_id: "ab".repeat(32),
        image: ImageRef::upstream("docker.io/library/alpine".to_string(), format!("sha256:{}", "cd".repeat(32))),
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
fn eviction_reasons_serialise_as_the_readmes_snake_case_codes() {
    for (reason, code) in [
        (EvictionReason::Abuse, "abuse"),
        (EvictionReason::Policy, "policy"),
        (EvictionReason::Maintenance, "maintenance"),
        (EvictionReason::Other, "other"),
    ] {
        assert_eq!(serde_json::to_value(reason).unwrap(), json!(code));
        assert_eq!(
            serde_json::from_value::<EvictionReason>(json!(code)).unwrap(),
            reason
        );
    }
}

#[test]
fn evict_request_round_trips_with_and_without_a_message() {
    let request = EvictRequest {
        workload_id: "ab".repeat(32),
        reason: EvictionReason::Maintenance,
        message: Some("rebooting the host for a kernel update".to_string()),
    };
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["workload_id"], request.workload_id);
    assert_eq!(value["reason"], "maintenance");
    assert_eq!(value["message"], "rebooting the host for a kernel update");
    let back: EvictRequest = serde_json::from_value(value).unwrap();
    assert_eq!(back, request);

    let no_message = EvictRequest {
        message: None,
        ..request
    };
    let value = serde_json::to_value(&no_message).unwrap();
    assert!(
        value.get("message").is_none(),
        "an omitted message must not round-trip as null"
    );
    let back: EvictRequest = serde_json::from_value(value).unwrap();
    assert_eq!(back, no_message);
}

#[test]
fn an_unknown_field_in_an_evict_request_is_refused() {
    let value = json!({
        "workload_id": "ab".repeat(32),
        "reason": "abuse",
        "runtime_flags": ["--privileged"],
    });
    assert!(serde_json::from_value::<EvictRequest>(value).is_err());
}

#[test]
fn evict_response_round_trips_the_ended_state_and_publication_outcome() {
    let response = EvictResponse {
        workload_id: "ab".repeat(32),
        state: LeaseState::Ended(LeaseEnd::Eviction),
        notice_published: true,
    };
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["state"], json!({ "ended": "eviction" }));
    assert_eq!(value["notice_published"], true);
    let back: EvictResponse = serde_json::from_value(value).unwrap();
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

#[test]
fn a_lease_state_is_one_word_until_it_ends() {
    // What `status` answers and what the lease table holds on disk are the
    // same JSON, so this encoding is the one both a tenant and a restart read.
    assert_eq!(
        serde_json::to_value(LeaseState::Provisioning).unwrap(),
        json!("provisioning")
    );
    assert_eq!(
        serde_json::to_value(LeaseState::Running).unwrap(),
        json!("running")
    );
    for (state, encoded) in [
        (
            LeaseState::Ended(LeaseEnd::Expiry),
            json!({"ended": "expiry"}),
        ),
        (
            LeaseState::Ended(LeaseEnd::Termination),
            json!({"ended": "termination"}),
        ),
        (
            LeaseState::Ended(LeaseEnd::Eviction),
            json!({"ended": "eviction"}),
        ),
    ] {
        assert_eq!(serde_json::to_value(state).unwrap(), encoded);
        assert_eq!(
            serde_json::from_value::<LeaseState>(encoded).unwrap(),
            state
        );
    }
}

#[test]
fn an_ended_lease_holds_nothing() {
    assert!(LeaseState::Provisioning.is_live());
    assert!(LeaseState::Running.is_live());
    assert!(!LeaseState::Ended(LeaseEnd::Expiry).is_live());
}

#[test]
fn the_status_and_terminate_answers_round_trip() {
    let running = StatusResponse {
        workload_id: "ab".repeat(32),
        role: Role::Standalone,
        state: LeaseState::Running,
        expires_at: 1_700_003_600,
        access: Some(Access {
            host: "203.0.113.7".to_string(),
            ssh_port: 40000,
            ports: vec![PortAccess {
                container_port: 443,
                host_port: 41000,
            }],
        }),
    };
    let value = serde_json::to_value(&running).unwrap();
    assert_eq!(value["state"], json!("running"));
    assert_eq!(value["access"]["ssh_port"], 40000);
    assert_eq!(
        serde_json::from_value::<StatusResponse>(value).unwrap(),
        running
    );

    // An ended lease has no access details at all, rather than empty ones.
    let ended = StatusResponse {
        state: LeaseState::Ended(LeaseEnd::Expiry),
        access: None,
        ..running
    };
    let value = serde_json::to_value(&ended).unwrap();
    assert!(value.get("access").is_none());
    assert_eq!(value["state"], json!({ "ended": "expiry" }));

    let terminated = TerminateResponse {
        workload_id: "ab".repeat(32),
        state: LeaseState::Ended(LeaseEnd::Termination),
    };
    let value = serde_json::to_value(&terminated).unwrap();
    assert_eq!(value["state"], json!({ "ended": "termination" }));
    assert_eq!(
        serde_json::from_value::<TerminateResponse>(value).unwrap(),
        terminated
    );
}

#[test]
fn availability_request_round_trips_the_tickets_shape() {
    let request = AvailabilityRequest {
        listing: "basic".to_string(),
        version: 1,
        image: ImageRef::upstream("docker.io/library/alpine".to_string(), format!("sha256:{}", "cd".repeat(32))),
    };
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["listing"], "basic");
    assert_eq!(value["version"], 1);
    assert_eq!(
        value["image"]["digest"],
        format!("sha256:{}", "cd".repeat(32))
    );
    let back: AvailabilityRequest = serde_json::from_value(value).unwrap();
    assert_eq!(back, request);
}

#[test]
fn an_unknown_availability_field_is_refused_at_parse() {
    // Including the spec draft's own `image_digest` shape: this route's
    // ticket fixes `{ listing, version, image: { reference, digest } }`, not
    // the spec draft's flatter shape.
    let mut value = serde_json::to_value(AvailabilityRequest {
        listing: "basic".to_string(),
        version: 1,
        image: ImageRef::upstream("docker.io/library/alpine".to_string(), format!("sha256:{}", "cd".repeat(32))),
    })
    .unwrap();
    value["image_digest"] = json!(format!("sha256:{}", "cd".repeat(32)));
    assert!(serde_json::from_value::<AvailabilityRequest>(value).is_err());
}

#[test]
fn a_runnable_availability_answer_writes_and_reads_just_would_run() {
    let value = serde_json::to_value(AvailabilityResponse::would_run()).unwrap();
    assert_eq!(value, json!({ "would_run": true }));
    let back: AvailabilityResponse = serde_json::from_value(value).unwrap();
    assert_eq!(back, AvailabilityResponse::would_run());
}

#[test]
fn a_refused_availability_answer_round_trips_its_error_and_message() {
    let refused = AvailabilityResponse::refused(ErrorCode::NoMatchingArch, "no arm64 manifest");
    let value = serde_json::to_value(&refused).unwrap();
    assert_eq!(
        value,
        json!({
            "would_run": false,
            "error": "no_matching_arch",
            "message": "no arm64 manifest"
        })
    );
    let back: AvailabilityResponse = serde_json::from_value(value).unwrap();
    assert_eq!(back, refused);
}

// ── the Provider Directory event contents (spec §4) ─────────────────────────

#[test]
fn a_profile_round_trips_and_spells_every_field_the_spec_names() {
    let profile = ProfileContent {
        ilp_address: "g.acme".to_string(),
        connector_url: "https://c.acme.example/ilp".to_string(),
        connector_seal_key: format!("0x04{}", "ab".repeat(64)),
        relays: vec!["wss://relay.acme.example".to_string()],
        settlement: vec![Settlement {
            chain: "solana".to_string(),
            token: "H8HSreUF2s8r8hem4qMttE3bWYCpFuh71jbuos5bA77H".to_string(),
            decimals: 6,
        }],
        isolation: "shared-kernel".to_string(),
        hidden: false,
        host: Some("203.0.113.7".to_string()),
        liveness_cadence_s: 60,
    };

    let value = serde_json::to_value(&profile).unwrap();
    assert_eq!(value["settlement"][0]["chain"], "solana");
    assert_eq!(value["hidden"], false);
    assert_eq!(
        serde_json::from_value::<ProfileContent>(value).unwrap(),
        profile
    );
}

#[test]
fn a_hidden_provider_profile_omits_its_host() {
    // Spec §4.1: `host` MUST be absent when `hidden` is true. The shape allows
    // it now; §10 is a follow-up milestone.
    let hidden = ProfileContent {
        ilp_address: "g.acme".to_string(),
        connector_url: "https://c.acme.example/ilp".to_string(),
        connector_seal_key: format!("0x04{}", "ab".repeat(64)),
        relays: vec![],
        settlement: vec![],
        isolation: "dedicated-host".to_string(),
        hidden: true,
        host: None,
        liveness_cadence_s: 60,
    };
    let value = serde_json::to_value(&hidden).unwrap();
    assert!(value.get("host").is_none());
    assert_eq!(
        serde_json::from_value::<ProfileContent>(value).unwrap(),
        hidden
    );
}

#[test]
fn a_listing_round_trips_and_omits_a_standby_price_it_does_not_sell() {
    let listing = ListingContent {
        version: 2,
        resources: Resources {
            cpu_millicores: 500,
            memory_mb: 256,
            storage_gb: 4,
            gpu: None,
        },
        arch: "arm64".to_string(),
        lease_interval_s: 3600,
        price: 1000,
        standby_price: None,
        capabilities: vec!["docker".to_string()],
    };

    let value = serde_json::to_value(&listing).unwrap();
    assert!(value.get("standby_price").is_none());
    assert_eq!(value["price"], 1000);
    assert_eq!(
        serde_json::from_value::<ListingContent>(value).unwrap(),
        listing
    );

    let with_standby = ListingContent {
        standby_price: Some(400),
        ..listing
    };
    let value = serde_json::to_value(&with_standby).unwrap();
    assert_eq!(value["standby_price"], 400);
    assert_eq!(
        serde_json::from_value::<ListingContent>(value).unwrap(),
        with_standby
    );
}

#[test]
fn liveness_round_trips_its_per_listing_availability() {
    let liveness = LivenessContent {
        available: BTreeMap::from([("basic".to_string(), 3), ("large".to_string(), 0)]),
    };
    let value = serde_json::to_value(&liveness).unwrap();
    assert_eq!(value["available"]["basic"], 3);
    assert_eq!(value["available"]["large"], 0);
    assert_eq!(
        serde_json::from_value::<LivenessContent>(value).unwrap(),
        liveness
    );
}

#[test]
fn eviction_content_round_trips_the_spec_shape() {
    let content = EvictionContent {
        workload_id: "ab".repeat(32),
        reason: EvictionReason::Abuse,
        message: "repeated port scans from the workload".to_string(),
    };
    let value = serde_json::to_value(&content).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["message", "reason", "workload_id"],
        "spec §6.7: {{ workload_id, reason, message }}, no more and no fewer"
    );
    assert_eq!(value["reason"], "abuse");
    let back: EvictionContent = serde_json::from_value(value).unwrap();
    assert_eq!(back, content);
}

#[test]
fn an_unknown_field_in_a_directory_content_is_refused() {
    // The same rule the request shapes follow: an unknown field is a shape
    // this provider does not know, never something to drop silently.
    let value = json!({
        "version": 1,
        "resources": { "cpu_millicores": 1, "memory_mb": 1, "storage_gb": 1 },
        "arch": "amd64",
        "lease_interval_s": 60,
        "price": 1,
        "capabilities": [],
        "gpu_hours_included": 5
    });
    assert!(serde_json::from_value::<ListingContent>(value).is_err());
}

// ── Milestone 2: the Image Registry entry, Blob Record and Template ──────────
//
// Round-trips are BYTE-IDENTICAL against a literal written from spec §8, not
// against a value this file built the same way the code would: the JSON below
// is the independent source of truth, and a field renamed, reordered or
// dropped fails here.

/// An Image Registry entry's content (spec §8.1) with one blob from the TOON
/// store and one still upstream, as a publisher signs it.
const IMAGE_ENTRY_CONTENT: &str = concat!(
    r#"{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
    r#""media_type":"application/vnd.oci.image.index.v1+json","#,
    r#""blobs":[{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","#,
    r#""size":1234,"media_type":"application/vnd.oci.image.manifest.v1+json","#,
    r#""source":{"type":"toon-store","blob_record_txid":"dGVzdC10eGlkLWZvci1hLWJsb2ItcmVjb3JkLTE"}},"#,
    r#"{"digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","#,
    r#""size":5678,"media_type":"application/vnd.oci.image.layer.v1.tar+gzip","#,
    r#""source":{"type":"oci","registry":"registry-1.docker.io","repository":"library/alpine"}}]}"#,
);

/// A Blob Record's content (spec §8.2) with three ordered parts.
const BLOB_RECORD_CONTENT: &str = concat!(
    r#"{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","#,
    r#""size":235520,"part_size":102400,"#,
    r#""parts":[{"txid":"cGFydC1vbmU","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":102400},"#,
    r#"{"txid":"cGFydC10d28","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":102400},"#,
    r#"{"txid":"cGFydC10aHJlZQ","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":30720}]}"#,
);

/// A Template's content (spec §8.3), naming its image by digest and the
/// Image Registry entry that lists the blobs.
const TEMPLATE_CONTENT: &str = concat!(
    r#"{"version":1,"#,
    r#""image":{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
    r#""registry_entry":{"address":"30434:4444444444444444444444444444444444444444444444444444444444444444:web:1.0","#,
    r#""relay":"wss://relay.example"}},"#,
    r#""ports":[{"container_port":8080,"protocol":"tcp"}],"#,
    r#""data_path":"/data","#,
    r#""env_fixed":{"MODE":"production"},"#,
    r#""env_tenant":["API_KEY","SEED"],"#,
    r#""min_resources":{"cpu_millicores":500,"memory_mb":512,"storage_gb":4}}"#,
);

const ENTRY_DIGEST_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BLOB_DIGEST_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn publisher() -> nostr_sdk::Keys {
    nostr_sdk::Keys::parse("4444444444444444444444444444444444444444444444444444444444444444")
        .unwrap()
}

#[test]
fn an_image_registry_entry_round_trips_both_source_types_byte_identically() {
    let content: ImageEntryContent = serde_json::from_str(IMAGE_ENTRY_CONTENT).unwrap();
    assert_eq!(content.blobs.len(), 2);
    assert_eq!(
        content.blobs[0].source,
        BlobSource::ToonStore {
            blob_record_txid: "dGVzdC10eGlkLWZvci1hLWJsb2ItcmVjb3JkLTE".to_string()
        }
    );
    assert_eq!(
        content.blobs[1].source,
        BlobSource::Oci {
            registry: "registry-1.docker.io".to_string(),
            repository: "library/alpine".to_string(),
        }
    );
    assert_eq!(serde_json::to_string(&content).unwrap(), IMAGE_ENTRY_CONTENT);
}

#[test]
fn a_blob_record_round_trips_its_ordered_parts_byte_identically() {
    let content: BlobRecordContent = serde_json::from_str(BLOB_RECORD_CONTENT).unwrap();
    assert_eq!(content.part_size, 102_400);
    assert_eq!(
        content.parts.iter().map(|p| p.size).sum::<u64>(),
        content.size,
        "the parts cover the blob"
    );
    assert_eq!(
        content.parts.iter().map(|p| p.txid.as_str()).collect::<Vec<_>>(),
        ["cGFydC1vbmU", "cGFydC10d28", "cGFydC10aHJlZQ"],
        "parts keep their order"
    );
    assert_eq!(serde_json::to_string(&content).unwrap(), BLOB_RECORD_CONTENT);
}

#[test]
fn a_template_round_trips_byte_identically() {
    let content: TemplateContent = serde_json::from_str(TEMPLATE_CONTENT).unwrap();
    assert_eq!(content.env_tenant, ["API_KEY", "SEED"]);
    assert_eq!(content.data_path.as_deref(), Some("/data"));
    assert_eq!(serde_json::to_string(&content).unwrap(), TEMPLATE_CONTENT);
}

#[test]
fn an_unknown_field_in_any_milestone_2_content_is_refused() {
    // The same rule every other shape follows: an unknown field is refused,
    // never dropped.
    let with = |text: &str, key: &str| {
        let mut value: serde_json::Value = serde_json::from_str(text).unwrap();
        value[key] = json!("surprise");
        value
    };
    assert!(
        serde_json::from_value::<ImageEntryContent>(with(IMAGE_ENTRY_CONTENT, "signature")).is_err()
    );
    assert!(
        serde_json::from_value::<BlobRecordContent>(with(BLOB_RECORD_CONTENT, "gateway")).is_err()
    );
    assert!(serde_json::from_value::<TemplateContent>(with(TEMPLATE_CONTENT, "privileged")).is_err());
    let mut entry: serde_json::Value = serde_json::from_str(IMAGE_ENTRY_CONTENT).unwrap();
    entry["blobs"][0]["source"]["gateway"] = json!("https://example");
    assert!(
        serde_json::from_value::<ImageEntryContent>(entry).is_err(),
        "an unknown field inside a blob source too"
    );
    let mut source: serde_json::Value = serde_json::from_str(IMAGE_ENTRY_CONTENT).unwrap();
    source["blobs"][0]["source"]["type"] = json!("lading");
    assert!(
        serde_json::from_value::<ImageEntryContent>(source).is_err(),
        "and a source type this milestone does not define"
    );
}

#[test]
fn an_image_registry_entry_event_round_trips_through_its_builder_and_parser() {
    let keys = publisher();
    let content: ImageEntryContent = serde_json::from_str(IMAGE_ENTRY_CONTENT).unwrap();
    let event = image_entry_event("web", "1.0", &content, &keys, 1_700_000_000).unwrap();

    assert_eq!(event.kind.as_u16(), K_IMAGE);
    assert_eq!(d_tag(&event), Some("web:1.0".to_string()));
    assert_eq!(x_tag(&event), Some(ENTRY_DIGEST_HEX.to_string()));
    assert!(carries_the_toon_label(&event));
    assert_eq!(event.content, IMAGE_ENTRY_CONTENT);

    let parsed = ImageEntry::from_event(&event).unwrap();
    assert_eq!(parsed.publisher, keys.public_key());
    assert_eq!(parsed.name, "web");
    assert_eq!(parsed.tag, "1.0");
    assert_eq!(parsed.content, content);
    // Re-built from what the parser read: the same NIP-01 id, so every byte
    // the id covers — pubkey, created_at, kind, tags and content — came back
    // unchanged. Only `sig` differs, because signing draws fresh randomness.
    assert_eq!(
        image_entry_event(&parsed.name, &parsed.tag, &parsed.content, &keys, 1_700_000_000)
            .unwrap()
            .id,
        event.id
    );
}

#[test]
fn a_blob_record_event_round_trips_through_its_builder_and_parser() {
    let keys = publisher();
    let content: BlobRecordContent = serde_json::from_str(BLOB_RECORD_CONTENT).unwrap();
    let event = blob_record_event(&content, &keys, 1_700_000_000).unwrap();

    assert_eq!(event.kind.as_u16(), K_BLOB);
    assert_eq!(d_tag(&event), Some(format!("sha256:{}", BLOB_DIGEST_HEX)));
    assert_eq!(x_tag(&event), Some(BLOB_DIGEST_HEX.to_string()));
    assert!(carries_the_toon_label(&event));
    assert_eq!(event.content, BLOB_RECORD_CONTENT);

    let parsed = BlobRecord::from_event(&event).unwrap();
    assert_eq!(parsed.publisher, keys.public_key());
    assert_eq!(parsed.content, content);
    assert_eq!(
        blob_record_event(&parsed.content, &keys, 1_700_000_000).unwrap().id,
        event.id
    );
}

#[test]
fn a_template_event_round_trips_through_its_builder_and_parser() {
    let keys = publisher();
    let content: TemplateContent = serde_json::from_str(TEMPLATE_CONTENT).unwrap();
    let event = template_event("static-site", &content, &keys, 1_700_000_000).unwrap();

    assert_eq!(event.kind.as_u16(), K_TEMPLATE);
    assert_eq!(d_tag(&event), Some("static-site".to_string()));
    assert!(carries_the_toon_label(&event));
    assert_eq!(event.content, TEMPLATE_CONTENT);

    let parsed = Template::from_event(&event).unwrap();
    assert_eq!(parsed.publisher, keys.public_key());
    assert_eq!(parsed.name, "static-site");
    assert_eq!(parsed.content, content);
    assert_eq!(
        template_event(&parsed.name, &parsed.content, &keys, 1_700_000_000)
            .unwrap()
            .id,
        event.id
    );
}

#[test]
fn a_parser_refuses_an_event_of_the_wrong_kind_or_with_a_mismatched_tag() {
    let keys = publisher();
    let content: ImageEntryContent = serde_json::from_str(IMAGE_ENTRY_CONTENT).unwrap();
    let entry = image_entry_event("web", "1.0", &content, &keys, 1_700_000_000).unwrap();
    let blob: BlobRecordContent = serde_json::from_str(BLOB_RECORD_CONTENT).unwrap();
    let record = blob_record_event(&blob, &keys, 1_700_000_000).unwrap();

    assert!(BlobRecord::from_event(&entry).is_err(), "wrong kind");
    assert!(ImageEntry::from_event(&record).is_err(), "wrong kind");
    assert!(
        Template::from_event(&entry).is_err(),
        "wrong kind, even though a Template's `d` has no shape of its own"
    );

    // An `x` tag that does not match the content's digest: a relay could
    // serve this to a `#x` filter for a digest it does not describe.
    let lying = nostr_sdk::EventBuilder::new(
        nostr_sdk::Kind::Custom(K_BLOB),
        record.content.clone(),
    )
    .tags([
        nostr_sdk::Tag::identifier(format!("sha256:{}", BLOB_DIGEST_HEX)),
        nostr_sdk::Tag::parse(["x", ENTRY_DIGEST_HEX]).unwrap(),
    ])
    .sign_with_keys(&keys)
    .unwrap();
    assert!(BlobRecord::from_event(&lying).is_err(), "x tag must match");
}

fn d_tag(event: &nostr_sdk::Event) -> Option<String> {
    tag_value(event, "d")
}

fn x_tag(event: &nostr_sdk::Event) -> Option<String> {
    tag_value(event, "x")
}

fn tag_value(event: &nostr_sdk::Event, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .map(nostr_sdk::Tag::as_slice)
        .find(|cells| cells.first().map(String::as_str) == Some(name))
        .and_then(|cells| cells.get(1).cloned())
}

fn carries_the_toon_label(event: &nostr_sdk::Event) -> bool {
    event
        .tags
        .iter()
        .map(nostr_sdk::Tag::as_slice)
        .any(|cells| cells.first().map(String::as_str) == Some("L") && cells.get(1).map(String::as_str) == Some(TOON_LABEL))
}
