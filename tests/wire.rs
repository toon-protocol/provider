//! Every request and response shape round-trips through serde, and the
//! spawn content refuses what ADR 0004 says a spawn may not carry.

use std::collections::BTreeMap;

use serde_json::json;
use toon_provider::nostr::continuation::{ContinuationToken, RootSecret};
use toon_provider::nostr::directory_events::{
    takeover_event, EvictionContent, ListingContent, LivenessContent, ProfileContent, Settlement,
    TakeoverContent,
};
use toon_provider::nostr::image_events::{
    blob_record_event, image_entry_event, template_event, BlobRecord, BlobRecordContent,
    BlobSource, ImageEntry, ImageEntryContent, SpawnImage, Template, TemplateContent,
};
use toon_provider::nostr::kinds::{K_BLOB, K_IMAGE, K_TAKEOVER, K_TEMPLATE, TOON_LABEL};
use toon_provider::nostr::lease_request::Op;
use toon_provider::nostr::wire::*;

fn spawn_content() -> SpawnContent {
    SpawnContent {
        workload_id: "ab".repeat(32),
        image: ImageRef::upstream(
            "docker.io/library/alpine".to_string(),
            format!("sha256:{}", "cd".repeat(32)),
        ),
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
fn standby_set_parses_so_it_can_be_refused_by_name() {
    let mut with = serde_json::to_value(spawn_content()).unwrap();
    with["standby_set"] = json!(["aa".repeat(32), "bb".repeat(32)]);
    let parsed: SpawnContent = serde_json::from_value(with).unwrap();
    assert_eq!(parsed.standby_set.as_ref().map(Vec::len), Some(2));
}

#[test]
fn the_three_spawn_image_forms_write_exactly_their_own_fields() {
    // Spec §6.2 writes three shapes, and each is exactly its own fields:
    // an absent `reference` or `registry_entry` is omitted, never null.
    let digest = format!("sha256:{}", "cd".repeat(32));
    for (form, expected) in [
        (
            ImageRef::upstream("docker.io/library/alpine", &digest),
            json!({ "reference": "docker.io/library/alpine", "digest": digest }),
        ),
        (
            ImageRef::from_registry(&digest, ENTRY_ADDRESS, "wss://relay.example"),
            json!({
                "digest": digest,
                "registry_entry": { "address": ENTRY_ADDRESS, "relay": "wss://relay.example" },
            }),
        ),
        (ImageRef::by_digest(&digest), json!({ "digest": digest })),
    ] {
        let value = serde_json::to_value(&form).unwrap();
        assert_eq!(value, expected);
        assert_eq!(serde_json::from_value::<ImageRef>(value).unwrap(), form);
    }
}

#[test]
fn the_three_spawn_image_forms_are_told_apart_and_a_fourth_is_refused() {
    let digest = format!("sha256:{}", "cd".repeat(32));
    assert_eq!(
        SpawnImage::parse(&ImageRef::upstream("docker.io/library/alpine", &digest)).unwrap(),
        SpawnImage::Upstream {
            reference: "docker.io/library/alpine".to_string(),
            digest: digest.clone(),
        }
    );
    let registry =
        SpawnImage::parse(&ImageRef::from_registry(&digest, ENTRY_ADDRESS, "wss://r")).unwrap();
    assert!(matches!(registry, SpawnImage::Registry { .. }));
    assert_eq!(
        SpawnImage::parse(&ImageRef::by_digest(&digest)).unwrap(),
        SpawnImage::Digest {
            digest: digest.clone()
        }
    );

    // Only the upstream form names something to pull; the other two are
    // resolved through §8.4 instead, and say so by answering `None`.
    assert_eq!(
        SpawnImage::parse(&ImageRef::upstream("alpine", &digest))
            .unwrap()
            .upstream_pull(),
        Some(format!("alpine@{}", digest))
    );
    assert_eq!(
        SpawnImage::parse(&ImageRef::by_digest(&digest))
            .unwrap()
            .upstream_pull(),
        None
    );

    let mut fourth = ImageRef::upstream("docker.io/library/alpine", &digest);
    fourth.registry_entry = Some(RegistryEntryRef {
        address: ENTRY_ADDRESS.to_string(),
        relay: "wss://r".to_string(),
    });
    for (label, image) in [
        ("a reference and a registry entry", fourth),
        (
            "a tag instead of a repository",
            ImageRef::upstream("docker.io/library/alpine:latest", &digest),
        ),
        ("a truncated digest", ImageRef::by_digest("sha256:abc")),
        (
            "an uppercase digest",
            ImageRef::by_digest(format!("sha256:{}", "CD".repeat(32))),
        ),
        (
            "a digest with no algorithm",
            ImageRef::by_digest("cd".repeat(32)),
        ),
        (
            "an address that names another kind",
            ImageRef::from_registry(&digest, "30432:aa:basic", "wss://r"),
        ),
        (
            "an address with no `d`",
            ImageRef::from_registry(&digest, format!("30434:{}:", "44".repeat(32)), "wss://r"),
        ),
        (
            "an entry with no relay",
            ImageRef::from_registry(&digest, ENTRY_ADDRESS, ""),
        ),
    ] {
        let refused = SpawnImage::parse(&image).expect_err(label);
        assert_eq!(refused.error, ErrorCode::InvalidRequest, "{}", label);
    }
}

#[test]
fn a_lease_request_round_trips_and_writes_the_spec_shape() {
    let provider = nostr_sdk::Keys::generate().public_key();
    let request = LeaseRequest {
        request_id: "ef".repeat(32),
        op: Op::Spawn,
        provider: provider.to_hex(),
        expiration: 1_700_000_300,
        continuation: Some(RootSecret::from_bytes([7u8; 32]).continuation_for(&provider)),
        content: serde_json::to_value(spawn_content()).unwrap(),
    };
    let envelope = serde_json::to_value(LeaseRequestEnvelope { request }).unwrap();

    // The shape spec §6.1 writes: six keys, all plain JSON, nothing signed.
    let sent = &envelope["request"];
    assert_eq!(sent["op"], "spawn");
    assert_eq!(sent["provider"], provider.to_hex());
    assert_eq!(sent["expiration"], 1_700_000_300u64);
    assert_eq!(sent["content"]["ports"][0]["container_port"], 443);
    assert_eq!(
        sent["continuation"].as_str().unwrap().len(),
        64,
        "a token on the wire is 64 lowercase hex characters"
    );
    assert!(sent.get("sig").is_none(), "nothing here is signed");

    let back: LeaseRequestEnvelope = serde_json::from_value(envelope).unwrap();
    assert_eq!(back.request.op, Op::Spawn);
    assert_eq!(back.request.request_id, "ef".repeat(32));
}

#[test]
fn a_lease_request_with_no_continuation_still_parses() {
    // Absence is a legal SHAPE and a refused one: `not_tenant` on `status`
    // and `terminate`, `invalid_request` on a spawn (spec §6.1). Parsing it
    // as `null`-that-is-not-there is what lets the refusal be about the
    // authority rather than about the spelling.
    let provider = nostr_sdk::Keys::generate().public_key();
    let body = json!({ "request": {
        "request_id": "ef".repeat(32),
        "op": "status",
        "provider": provider.to_hex(),
        "expiration": 1_700_000_300u64,
        "content": { "workload_id": "ab".repeat(32) },
    }});
    let parsed: LeaseRequestEnvelope = serde_json::from_value(body).unwrap();
    assert!(parsed.request.continuation.is_none());
}

#[test]
fn a_continuation_token_is_sixty_four_lowercase_hex_characters() {
    let good = json!("ab".repeat(32));
    assert!(serde_json::from_value::<ContinuationToken>(good).is_ok());
    for bad in ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32)] {
        let refused = serde_json::from_value::<ContinuationToken>(json!(bad.clone())).unwrap_err();
        assert!(
            !refused.to_string().contains(&bad),
            "a refusal never quotes a token back: {}",
            refused
        );
    }
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
        (ErrorCode::NotRunning, "not_running"),
        (ErrorCode::StaleRequest, "stale_request"),
        (ErrorCode::BadGrant, "bad_grant"),
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

    // One field: the workload. Authority is the request's Continuation
    // Token, which is not part of the content (spec §6.1).
    let content = WorkloadContent {
        workload_id: "ab".repeat(32),
    };
    let rendered = serde_json::to_string(&content).unwrap();
    assert_eq!(
        rendered,
        json!({ "workload_id": "ab".repeat(32) }).to_string()
    );
    let back: WorkloadContent = serde_json::from_str(&rendered).unwrap();
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
        template: None,
        takeover: None,
    };
    let value = serde_json::to_value(&running).unwrap();
    assert_eq!(value["state"], json!("running"));
    assert_eq!(
        value.get("takeover"),
        None,
        "a lease no Takeover settled on says nothing about one"
    );
    assert_eq!(
        value.get("template"),
        None,
        "a lease from no Template says nothing about one"
    );
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
        image: ImageRef::upstream(
            "docker.io/library/alpine".to_string(),
            format!("sha256:{}", "cd".repeat(32)),
        ),
        role: None,
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
        image: ImageRef::upstream(
            "docker.io/library/alpine".to_string(),
            format!("sha256:{}", "cd".repeat(32)),
        ),
        role: None,
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

/// A publisher's Image Registry entry coordinate, as spec §6.2 writes it.
const ENTRY_ADDRESS: &str =
    "30434:4444444444444444444444444444444444444444444444444444444444444444:web:1.0";

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
    assert_eq!(
        serde_json::to_string(&content).unwrap(),
        IMAGE_ENTRY_CONTENT
    );
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
        content
            .parts
            .iter()
            .map(|p| p.txid.as_str())
            .collect::<Vec<_>>(),
        ["cGFydC1vbmU", "cGFydC10d28", "cGFydC10aHJlZQ"],
        "parts keep their order"
    );
    assert_eq!(
        serde_json::to_string(&content).unwrap(),
        BLOB_RECORD_CONTENT
    );
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
        serde_json::from_value::<ImageEntryContent>(with(IMAGE_ENTRY_CONTENT, "signature"))
            .is_err()
    );
    assert!(
        serde_json::from_value::<BlobRecordContent>(with(BLOB_RECORD_CONTENT, "gateway")).is_err()
    );
    assert!(
        serde_json::from_value::<TemplateContent>(with(TEMPLATE_CONTENT, "privileged")).is_err()
    );
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
        image_entry_event(
            &parsed.name,
            &parsed.tag,
            &parsed.content,
            &keys,
            1_700_000_000
        )
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
        blob_record_event(&parsed.content, &keys, 1_700_000_000)
            .unwrap()
            .id,
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
    let lying =
        nostr_sdk::EventBuilder::new(nostr_sdk::Kind::Custom(K_BLOB), record.content.clone())
            .tags([
                nostr_sdk::Tag::identifier(format!("sha256:{}", BLOB_DIGEST_HEX)),
                nostr_sdk::Tag::parse(["x", ENTRY_DIGEST_HEX]).unwrap(),
            ])
            .sign_with_keys(&keys)
            .unwrap();
    assert!(BlobRecord::from_event(&lying).is_err(), "x tag must match");
}

// ── Milestone 3: Warm Standby, Takeover and the reserved state ──────────────
//
// Byte-identical against literals written from spec §4.2, §6.4, §6.5 and
// §7.1, the same way the Milestone 2 contents above are: the JSON here is the
// independent source of truth, and a field renamed, reordered or dropped
// fails here rather than only in the fixtures.

/// The provider whose Liveness a standby watches: index 0 of the
/// `standby_set`. A test-only key, like everything else in this file.
const PRIMARY_SECRET: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// A Takeover's content (spec §7.1 step 2): the workload the set serves and
/// the primary that went silent, nothing else.
const TAKEOVER_CONTENT: &str = concat!(
    r#"{"workload_id":"abababababababababababababababababababababababababababababababab","#,
    r#""primary":"9ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b"}"#,
);

/// A Listing that sells Warm Standbys (spec §4.2): `standby_price` sits
/// between `price` and `capabilities`, and is a price per interval like
/// `price` itself.
const LISTING_WITH_STANDBY_PRICE: &str = concat!(
    r#"{"version":1,"resources":{"cpu_millicores":500,"memory_mb":256,"storage_gb":4},"#,
    r#""arch":"amd64","lease_interval_s":3600,"price":1000,"standby_price":400,"#,
    r#""capabilities":[]}"#,
);

/// The `status` answer for a Warm Standby before Takeover (spec §6.5,
/// §6.7): `reserved` is one word like `running`, the role says which member
/// of the Standby Set this is, and there is no `access` because nothing is
/// running here yet.
const STATUS_RESERVED: &str = concat!(
    r#"{"workload_id":"abababababababababababababababababababababababababababababababab","#,
    r#""role":"standby","state":"reserved","expires_at":1700003600}"#,
);

/// The `status` answer for a Warm Standby that WON a Takeover (spec §6.5,
/// §7.1 step 4): `running` with `access`, the role still `standby`, and
/// `takeover.winner` naming this provider — the same member that answers.
/// `takeover` is last, after `access`, and absent until a Takeover settles.
const STATUS_TAKEN_OVER: &str = concat!(
    r#"{"workload_id":"abababababababababababababababababababababababababababababababab","#,
    r#""role":"standby","state":"running","expires_at":1700003600,"#,
    r#""access":{"host":"203.0.113.7","ssh_port":40000,"ports":[]},"#,
    r#""takeover":{"winner":"6666666666666666666666666666666666666666666666666666666666666666"}}"#,
);

/// The `status` answer for a primary that stopped its own workload (spec
/// §6.5, §6.7, §7.1): `stopped` is one word like `running`, the role is
/// still `primary`, `expires_at` is untouched because the lease is still
/// paid, and there is no `access` because the container is off.
const STATUS_STOPPED: &str = concat!(
    r#"{"workload_id":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","#,
    r#""role":"primary","state":"stopped","expires_at":1700003600}"#,
);

/// An availability request that asks about a standby rather than a primary
/// (spec §6.4). `role` is last, and absent when the question is about an
/// ordinary spawn.
const AVAILABILITY_WITH_ROLE: &str = concat!(
    r#"{"listing":"warm","version":1,"#,
    r#""image":{"reference":"docker.io/library/alpine","#,
    r#""digest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},"#,
    r#""role":"standby"}"#,
);

fn primary() -> nostr_sdk::Keys {
    nostr_sdk::Keys::parse(PRIMARY_SECRET).unwrap()
}

#[test]
fn a_takeover_event_round_trips_byte_identically_through_its_builder() {
    let standby =
        nostr_sdk::Keys::parse("6666666666666666666666666666666666666666666666666666666666666666")
            .unwrap();
    let workload_id = "ab".repeat(32);
    let event = takeover_event(
        &workload_id,
        &primary().public_key(),
        &standby,
        1_700_000_000,
    )
    .expect("a Takeover signs");

    assert_eq!(event.kind.as_u16(), K_TAKEOVER);
    assert_eq!(
        d_tag(&event).as_deref(),
        Some(workload_id.as_str()),
        "spec §7.1: addressable on d = the workload id"
    );
    assert!(carries_the_toon_label(&event));
    assert_eq!(
        event.pubkey,
        standby.public_key(),
        "the STANDBY announces a Takeover, never the primary"
    );

    // The content is exactly what §7.1 writes, and parses back to itself.
    assert_eq!(event.content, TAKEOVER_CONTENT);
    let content: TakeoverContent = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content.workload_id, workload_id);
    assert_eq!(content.primary, primary().public_key().to_hex());
    assert_eq!(serde_json::to_string(&content).unwrap(), TAKEOVER_CONTENT);
}

#[test]
fn an_unknown_field_in_a_takeover_is_refused() {
    let mut value: serde_json::Value = serde_json::from_str(TAKEOVER_CONTENT).unwrap();
    value["standby_index"] = json!(1);
    assert!(serde_json::from_value::<TakeoverContent>(value).is_err());
}

#[test]
fn a_listing_that_prices_standbys_round_trips_byte_identically() {
    let content: ListingContent = serde_json::from_str(LISTING_WITH_STANDBY_PRICE).unwrap();
    assert_eq!(content.standby_price, Some(400));
    assert_eq!(
        serde_json::to_string(&content).unwrap(),
        LISTING_WITH_STANDBY_PRICE
    );

    // And a listing that sells none writes no field at all: zero would read
    // as "standbys are free".
    let without = ListingContent {
        standby_price: None,
        ..content
    };
    let rendered = serde_json::to_string(&without).unwrap();
    assert!(!rendered.contains("standby_price"), "{}", rendered);
}

#[test]
fn a_reserved_status_round_trips_byte_identically() {
    let response: StatusResponse = serde_json::from_str(STATUS_RESERVED).unwrap();
    assert_eq!(response.state, LeaseState::Reserved);
    assert_eq!(response.role, Role::Standby);
    assert!(
        response.access.is_none(),
        "a reservation runs nothing to reach"
    );
    assert_eq!(serde_json::to_string(&response).unwrap(), STATUS_RESERVED);
}

#[test]
fn a_taken_over_status_round_trips_byte_identically() {
    let response: StatusResponse = serde_json::from_str(STATUS_TAKEN_OVER).unwrap();
    assert_eq!(response.state, LeaseState::Running);
    assert_eq!(response.role, Role::Standby, "the role never changes");
    assert!(response.access.is_some(), "the workload runs here now");
    assert_eq!(
        response.takeover.as_ref().map(|t| t.winner.as_str()),
        Some("66".repeat(32).as_str())
    );
    assert_eq!(serde_json::to_string(&response).unwrap(), STATUS_TAKEN_OVER);

    // A standby that LOST answers the same field beside `reserved`: still
    // no `access`, and `winner` is the OTHER member — where the workload
    // went.
    let lost = StatusResponse {
        state: LeaseState::Reserved,
        access: None,
        ..response
    };
    let value = serde_json::to_value(&lost).unwrap();
    assert_eq!(value["state"], json!("reserved"));
    assert!(value.get("access").is_none());
    assert_eq!(value["takeover"]["winner"], json!("66".repeat(32)));
}

#[test]
fn a_reservation_holds_its_workload_id_and_its_capacity_slot() {
    // `Reserved` is a LIVE state (spec §6.7): a standby is holding the
    // capacity it was paid for, so it counts exactly as a running lease does.
    assert!(LeaseState::Reserved.is_live());
    assert_eq!(
        serde_json::to_value(LeaseState::Reserved).unwrap(),
        json!("reserved")
    );
    assert_eq!(
        serde_json::from_value::<LeaseState>(json!("reserved")).unwrap(),
        LeaseState::Reserved
    );
}

#[test]
fn a_stopped_status_round_trips_byte_identically() {
    let response: StatusResponse = serde_json::from_str(STATUS_STOPPED).unwrap();
    assert_eq!(response.state, LeaseState::Stopped);
    assert_eq!(response.role, Role::Primary);
    assert!(
        response.access.is_none(),
        "a stopped workload has nothing listening"
    );
    assert_eq!(serde_json::to_string(&response).unwrap(), STATUS_STOPPED);
}

#[test]
fn a_stopped_primary_still_holds_its_lease_and_its_workload() {
    // `Stopped` is a LIVE state (spec §6.7, §7.1): the lease is paid to its
    // `expires_at` and the container still exists, so the slot is still held
    // and the ending still has something to destroy — only the tenant has
    // nowhere to reach.
    assert!(LeaseState::Stopped.is_live());
    assert!(LeaseState::Stopped.has_workload());
    assert!(!LeaseState::Stopped.is_reachable());
    assert_eq!(
        serde_json::to_value(LeaseState::Stopped).unwrap(),
        json!("stopped")
    );
    assert_eq!(
        serde_json::from_value::<LeaseState>(json!("stopped")).unwrap(),
        LeaseState::Stopped
    );
}

#[test]
fn an_availability_request_round_trips_its_role_byte_identically() {
    let request: AvailabilityRequest = serde_json::from_str(AVAILABILITY_WITH_ROLE).unwrap();
    assert_eq!(request.role, Some(AvailabilityRole::Standby));
    assert_eq!(
        serde_json::to_string(&request).unwrap(),
        AVAILABILITY_WITH_ROLE
    );

    // Absent is the ordinary question, and writes no field.
    let without = AvailabilityRequest {
        role: None,
        ..request
    };
    assert!(!serde_json::to_string(&without).unwrap().contains("role"));
}

#[test]
fn an_availability_role_outside_the_spec_vocabulary_is_refused() {
    // §6.4 names `primary` and `standby` and nothing else. `standalone` is a
    // lease ROLE (§6.2) but not a question this route can be asked: every
    // spawn with no Standby Set is standalone already.
    let mut value: serde_json::Value = serde_json::from_str(AVAILABILITY_WITH_ROLE).unwrap();
    for refused in ["standalone", "Standby", "", "primary "] {
        value["role"] = json!(refused);
        assert!(
            serde_json::from_value::<AvailabilityRequest>(value.clone()).is_err(),
            "role {:?} is not §6.4 vocabulary",
            refused
        );
    }
    value["role"] = json!("primary");
    assert_eq!(
        serde_json::from_value::<AvailabilityRequest>(value)
            .unwrap()
            .role,
        Some(AvailabilityRole::Primary)
    );
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
        .any(|cells| {
            cells.first().map(String::as_str) == Some("L")
                && cells.get(1).map(String::as_str) == Some(TOON_LABEL)
        })
}
