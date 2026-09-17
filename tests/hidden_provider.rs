//! A Hidden Provider, lease by lease (spec §10, ADR 0008; TOON_Network
//! #38, #39): what it publishes, what every lease is reached at, and what a
//! provider that is not hidden never touches — driven through the HTTP
//! router, the Directory port and the `HiddenService` port over the fakes,
//! exactly as a tenant and a relay would see it.
//!
//! The rule the whole file turns on: a Hidden Provider publishes no host,
//! so every lease gets a `.anyone` address OF ITS OWN, created before its
//! workload starts, answered by `access` and by `status`, re-established
//! after a restart of the provider, and destroyed on every way the lease
//! can end. A tenant never sees an IP.

mod common;

use common::socks::SocksStub;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use common::harness::{
    config_for, error_of, harness, harness_from, hidden_config, listing, post, socks_proxy_of,
    spawn, spawn_content, Harness, RequestSpec, HIDDEN_CONNECTOR_URL, INTERVAL, NOW, PUBLIC_IP,
};
use common::{
    has_tag, stub_registry, BackendCall, FakeBackend, FakeClock, FakeDirectory, FakeHiddenService,
};
use nostr_sdk::{EventBuilder, Keys, Kind, Tag, Timestamp};
use toon_provider::nostr::directory_events::{ProfileContent, HIDDEN_LABEL};
use toon_provider::nostr::kinds::{K_LISTING, K_PROFILE, TOON_LABEL};
use toon_provider::nostr::wire::{EvictionReason, SpawnContent};
use toon_provider::provider::{persisted_leases, ImagePolicyConfig};
use toon_provider::LivenessState::Absent;
use toon_provider::{operator_router, LeaseRecord, Listing, ProviderConfig};

/// A fresh Hidden Provider selling `listings`, on a lease table of its own.
async fn hidden_harness(listings: Vec<Listing>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    hidden_harness_on(
        listings,
        &Keys::generate().secret_key().to_secret_hex(),
        &state_path,
        FakeBackend::new(),
        FakeDirectory::new(),
        |config| config,
    )
    .await
}

/// A Hidden Provider's process over a lease table, a backend and a Directory
/// the caller owns — so the same three can be handed to a SECOND process and
/// make a restart, which is what a lease's address has to survive.
async fn hidden_harness_on(
    listings: Vec<Listing>,
    provider_key: &str,
    state_path: &str,
    backend: std::sync::Arc<FakeBackend>,
    directory: std::sync::Arc<FakeDirectory>,
    adjust: impl FnOnce(ProviderConfig) -> ProviderConfig,
) -> Harness {
    let registry = stub_registry().await;
    // A hidden provider's own outbound — the image fetch a spawn makes
    // against the stub registry included — leaves through `anon.socks_proxy`
    // (spec §10), so a hidden harness needs a proxy that answers. The stub
    // dials an IP literal as given, which is what the registry override is.
    // Leaked on purpose: its accept loop must outlive this function, and the
    // process it serves is dropped with the test.
    let socks = Box::leak(Box::new(SocksStub::start(&[]).await));
    let config = adjust(socks_proxy_of(
        hidden_config(config_for(
            listings,
            provider_key,
            state_path,
            &registry,
            ImagePolicyConfig::default(),
        )),
        &socks.url(),
    ));
    harness_from(config, backend, FakeClock::at(NOW), directory, registry)
}

/// The same provider process again over the same lease table, backend and
/// Directory — but a NEW `HiddenService`, because a restart of the provider
/// is usually a restart of the daemon too, and every address it had made is
/// gone with it.
async fn restart(h: &Harness, listings: Vec<Listing>) -> Harness {
    let restarted = hidden_harness_on(
        listings,
        &h.provider_key,
        &h.state_path,
        h.backend.clone(),
        h.directory.clone(),
        |config| config,
    )
    .await;
    restarted.service.restore_leases().await;
    restarted
}

/// Buy one lease on `basic.v1.spawn` and answer the spawn's response beside
/// the tenant that holds it.
async fn spawn_lease(h: &Harness, seed: u8) -> (Keys, SpawnContent, Value) {
    let content = spawn_content(seed);
    let spec = RequestSpec::spawn(h, &content);
    let tenant = Keys::parse(&spec.tenant.secret_key().to_secret_hex()).unwrap();
    let (status, body) = spawn(h, spec.sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    (tenant, content, body)
}

/// `status` for a lease, signed by the tenant that holds it.
async fn status_of(h: &Harness, tenant: &Keys, workload_id: &str) -> Value {
    let spec = RequestSpec {
        tenant: Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(h, "status", workload_id)
    };
    post(&h.app, "/status", json!({ "request": spec.sign() }))
        .await
        .1
}

/// `terminate` for a lease, signed by the tenant that holds it.
async fn terminate(h: &Harness, tenant: &Keys, workload_id: &str) -> (StatusCode, Value) {
    let spec = RequestSpec {
        tenant: Keys::parse(&tenant.secret_key().to_secret_hex()).unwrap(),
        ..RequestSpec::about(h, "terminate", workload_id)
    };
    post(&h.app, "/terminate", json!({ "request": spec.sign() })).await
}

/// `POST /operator/evict` on the operator router, as `toon-provider evict`
/// reaches it.
async fn evict(h: &Harness, workload_id: &str) -> (StatusCode, Value) {
    let response = operator_router(h.service.app_state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operator/evict")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "workload_id": workload_id,
                        "reason": EvictionReason::Maintenance,
                        "message": "the capacity is needed back",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The lease a workload id names, as the next process would read it off the
/// table.
fn persisted(h: &Harness, workload_id: &str) -> LeaseRecord {
    persisted_leases(&h.state_path)
        .into_iter()
        .find(|lease| lease.workload_id == workload_id)
        .unwrap_or_else(|| panic!("no lease for {workload_id}"))
}

/// The ports a lease's address must answer on: the SSH forward this
/// harness's config hands out first, then the one published port.
fn lease_ports() -> Vec<toon_provider::AddressPort> {
    use toon_provider::AddressPort;
    vec![AddressPort::same(40000), AddressPort::same(41000)]
}

/// Nothing in this JSON looks like an IP address. A tenant of a Hidden
/// Provider must never be handed one — not as the host, not anywhere else in
/// the answer (spec §10).
fn mentions_no_ip(body: &Value) {
    for word in body
        .to_string()
        .split(|c: char| !(c.is_ascii_digit() || c == '.' || c == ':'))
    {
        let looks_like_ipv4 = {
            let octets: Vec<&str> = word.split('.').collect();
            octets.len() == 4
                && octets
                    .iter()
                    .all(|o| !o.is_empty() && o.parse::<u8>().is_ok())
        };
        assert!(!looks_like_ipv4, "{:?} is an IP address in {}", word, body);
    }
}

// ── what it publishes ───────────────────────────────────────────────────

#[tokio::test]
async fn a_hidden_provider_publishes_hidden_true_no_host_and_the_label_on_every_listing() {
    let h = hidden_harness(vec![listing("basic", 1, 2), listing("gpu", 1, 1)]).await;
    h.service.publish_directory().await.unwrap();

    let profiles = h.directory.of_kind(K_PROFILE);
    assert_eq!(profiles.len(), 1);
    let content: ProfileContent = serde_json::from_str(&profiles[0].content).unwrap();
    assert!(content.hidden, "the declaration (spec §4.1, §10)");
    assert_eq!(content.host, None);
    let raw: serde_json::Value = serde_json::from_str(&profiles[0].content).unwrap();
    assert!(
        raw.get("host").is_none(),
        "no `host` key at all, not a null: {}",
        raw
    );
    assert_eq!(content.connector_url, HIDDEN_CONNECTOR_URL);

    let listings = h.directory.of_kind(K_LISTING);
    assert_eq!(listings.len(), 2);
    for event in &listings {
        assert!(
            has_tag(event, &["l", HIDDEN_LABEL, TOON_LABEL]),
            "every Listing carries [\"l\", \"hidden:true\", \"toon.network\"] (spec §4.2): {:?}",
            event.tags
        );
        // Beside, not instead of, the labels every Listing carries.
        assert!(has_tag(
            event,
            &["l", "isolation:shared-kernel", TOON_LABEL]
        ));
        assert!(has_tag(event, &["l", "arch:amd64", TOON_LABEL]));
    }
    // Nothing hidden was asked of the daemon: no lease exists to give an
    // address to, and the Directory needs none.
    assert!(h.hidden_service.created().is_empty());
    assert!(h.hidden_service.destroyed().is_empty());
}

#[tokio::test]
async fn a_provider_that_is_not_hidden_publishes_exactly_what_it_did_before() {
    let h = harness().await;
    h.service.publish_directory().await.unwrap();

    let profile = &h.directory.of_kind(K_PROFILE)[0];
    let content: ProfileContent = serde_json::from_str(&profile.content).unwrap();
    assert!(!content.hidden);
    assert_eq!(content.host.as_deref(), Some(PUBLIC_IP));

    for event in h.directory.of_kind(K_LISTING) {
        assert!(
            !has_tag(&event, &["l", HIDDEN_LABEL, TOON_LABEL]),
            "no hidden label, and never a `hidden:false`: {:?}",
            event.tags
        );
        assert!(!event.tags.iter().any(|t| t
            .clone()
            .to_vec()
            .get(1)
            .is_some_and(|v| v.starts_with("hidden:"))));
    }
}

// ── every lease gets an address of its own ──────────────────────────────

#[tokio::test]
async fn a_spawn_gets_one_anyone_address_carrying_its_ssh_port_and_every_port() {
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    let (tenant, content, body) = spawn_lease(&h, 1).await;

    // One address, for THIS workload, mapping the SSH forward and the one
    // port the spawn published — each on the number the tenant was handed,
    // because that is what it dials (spec §6.2, §10).
    assert_eq!(
        h.hidden_service.created(),
        vec![(content.workload_id.clone(), lease_ports())]
    );
    let host = FakeHiddenService::address_for(&content.workload_id);
    assert_eq!(body["access"]["host"], host);
    assert!(toon_provider::is_anyone_host(&host));
    assert_eq!(body["access"]["ssh_port"], 40000);
    assert_eq!(body["access"]["ports"][0]["host_port"], 41000);
    mentions_no_ip(&body);

    // And `status` answers the same one: the lease is reached where the
    // spawn said it is.
    let status = status_of(&h, &tenant, &content.workload_id).await;
    assert_eq!(status["state"], "running");
    assert_eq!(status["access"]["host"], host);
    mentions_no_ip(&status);

    // The workload itself started exactly as any other does.
    assert_eq!(
        h.backend.calls(),
        vec![BackendCall::Create(1000), BackendCall::Start(1000)]
    );
    assert!(h.hidden_service.destroyed().is_empty());
}

#[tokio::test]
async fn a_restart_re_establishes_the_same_address_rather_than_inventing_one() {
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    let (tenant, content, body) = spawn_lease(&h, 1).await;
    let host = body["access"]["host"].as_str().unwrap().to_string();

    // The key the daemon gave is on the lease table, which is the only
    // thing that survives the process.
    let lease = persisted(&h, &content.workload_id);
    let address = lease.hidden_address.expect("the lease keeps its address");
    assert_eq!(address.host, host);
    assert!(address.key.is_some(), "and the key the host comes from");

    let restarted = restart(&h, vec![listing("basic", 1, 2)]).await;
    assert_eq!(
        restarted.hidden_service.restored(),
        vec![(
            content.workload_id.clone(),
            FakeHiddenService::key_for(&content.workload_id),
            lease_ports()
        )],
        "restored from the stored key, with the lease's own ports"
    );
    assert!(
        restarted.hidden_service.created().is_empty(),
        "a live lease is not given a different address"
    );
    let status = status_of(&restarted, &tenant, &content.workload_id).await;
    assert_eq!(status["access"]["host"], host, "the same address");
    mentions_no_ip(&status);
}

#[tokio::test]
async fn a_live_lease_that_kept_no_key_is_given_a_fresh_address() {
    // A key the daemon never gave back (an implementation that cannot
    // export one) leaves nothing to restore FROM. The lease is not left
    // unreachable: it gets a new address, and `status` is where its tenant
    // reads it.
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    let (tenant, content, _) = spawn_lease(&h, 1).await;
    forget_the_stored_key(&h.state_path);

    let restarted = restart(&h, vec![listing("basic", 1, 2)]).await;
    assert!(restarted.hidden_service.restored().is_empty());
    assert_eq!(
        restarted.hidden_service.created(),
        vec![(content.workload_id.clone(), lease_ports())]
    );
    let status = status_of(&restarted, &tenant, &content.workload_id).await;
    let host = status["access"]["host"].as_str().unwrap();
    assert!(toon_provider::is_anyone_host(host), "{}", status);
    mentions_no_ip(&status);
}

#[tokio::test]
async fn a_lease_whose_address_cannot_be_re_established_is_left_with_none() {
    // The commonest cause is a provider that restarted while its daemon did
    // not: the daemon is still serving the address and refuses to add the
    // key twice. Naming the old host anyway would have the tenant dialling
    // something this provider cannot account for, so `status` answers no
    // `access` at all — the truth, and what tells the tenant to look.
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    let (tenant, content, _) = spawn_lease(&h, 1).await;
    rewrite_the_stored_key(&h.state_path, "ED25519-V3:somebody-elses");

    let restarted = restart(&h, vec![listing("basic", 1, 2)]).await;
    assert_eq!(restarted.hidden_service.restored().len(), 1, "it tried");
    assert!(
        restarted.hidden_service.created().is_empty(),
        "and did not paper over it with a second address beside the daemon's"
    );
    let status = status_of(&restarted, &tenant, &content.workload_id).await;
    assert_eq!(status["state"], "running", "{}", status);
    assert!(
        status.get("access").is_none(),
        "no host rather than a dead one: {}",
        status
    );
    assert_eq!(
        persisted(&restarted, &content.workload_id).hidden_address,
        None,
        "and the record stops claiming one"
    );
}

#[tokio::test]
async fn a_lease_dropped_at_restore_takes_its_address_with_it() {
    // A workload that vanished from the backend while the provider was down
    // takes its whole lease off the table — and nothing will ever ask about
    // that lease again, so its address has to go here or it outlives every
    // lease on the daemon.
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    let (_, content, _) = spawn_lease(&h, 1).await;
    h.backend.vanish(1000);

    let restarted = restart(&h, vec![listing("basic", 1, 2)]).await;
    assert!(
        persisted_leases(&restarted.state_path).is_empty(),
        "the lease is gone"
    );
    assert_eq!(
        restarted.hidden_service.destroyed(),
        vec![content.workload_id.clone()],
        "and so is its address"
    );
    assert!(restarted.hidden_service.restored().is_empty());
}

/// Rewrite the lease table with every `key` replaced by `key`, so the
/// daemon refuses to restore from it.
fn rewrite_the_stored_key(state_path: &str, key: &str) {
    let mut table: serde_json::Map<String, Value> =
        serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
    for lease in table.values_mut() {
        if let Some(address) = lease.get_mut("hidden_address") {
            address
                .as_object_mut()
                .unwrap()
                .insert("key".into(), json!(key));
        }
    }
    std::fs::write(state_path, serde_json::to_vec_pretty(&table).unwrap()).unwrap();
}

/// Rewrite the lease table with every `key` dropped, as a provider whose
/// `HiddenService` gives none would have written it.
fn forget_the_stored_key(state_path: &str) {
    let mut table: serde_json::Map<String, Value> =
        serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
    for lease in table.values_mut() {
        if let Some(address) = lease.get_mut("hidden_address") {
            address.as_object_mut().unwrap().remove("key");
        }
    }
    std::fs::write(state_path, serde_json::to_vec_pretty(&table).unwrap()).unwrap();
}

// ── and loses it on every ending ────────────────────────────────────────

#[tokio::test]
async fn expiry_terminate_and_eviction_each_destroy_the_leases_address_once() {
    let h = hidden_harness(vec![listing("basic", 1, 3)]).await;
    let (tenant, terminated, _) = spawn_lease(&h, 1).await;
    let (_, evicted, _) = spawn_lease(&h, 2).await;
    let (_, expired, _) = spawn_lease(&h, 3).await;
    assert_eq!(h.hidden_service.live().len(), 3);

    let (status, body) = terminate(&h, &tenant, &terminated.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        h.hidden_service.destroyed(),
        vec![terminated.workload_id.clone()]
    );

    let (status, body) = evict(&h, &evicted.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        h.hidden_service.destroyed(),
        vec![terminated.workload_id.clone(), evicted.workload_id.clone()]
    );

    // And the third goes the way every unpaid lease goes: the sweep.
    h.service.sweep_expired_leases(NOW + INTERVAL).await;
    assert_eq!(
        h.hidden_service.destroyed(),
        vec![
            terminated.workload_id.clone(),
            evicted.workload_id.clone(),
            expired.workload_id.clone()
        ],
        "each address destroyed exactly once, by whichever ending came"
    );
    assert!(
        h.hidden_service.live().is_empty(),
        "nothing answers for a lease that is over"
    );

    // A later sweep asks for nothing more: the addresses are already gone,
    // and a destroyed lease is not retried.
    h.service.sweep_expired_leases(NOW + INTERVAL + 1).await;
    assert_eq!(h.hidden_service.destroyed().len(), 3);
}

#[tokio::test]
async fn a_destroy_that_fails_leaves_the_lease_pending_and_a_later_sweep_retries() {
    // Exactly what a container that would not stop gets (spec §6.7): the
    // lease is over, but it is not reported destroyed until everything it
    // held is actually gone.
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    let (tenant, content, _) = spawn_lease(&h, 1).await;

    h.hidden_service
        .fail_next_destroy("the control port is not answering");
    let (status, body) = terminate(&h, &tenant, &content.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["state"], json!({ "ended": "termination" }));

    let pending = persisted(&h, &content.workload_id);
    assert!(
        !pending.destroyed,
        "not destroyed while its address still answers"
    );
    assert!(
        pending.hidden_address.is_some(),
        "and the record keeps it, so the retry knows what to destroy"
    );
    assert_eq!(h.hidden_service.live().len(), 1);

    h.service.sweep_expired_leases(NOW + 1).await;
    assert_eq!(
        h.hidden_service.destroyed(),
        vec![content.workload_id.clone(), content.workload_id.clone()],
        "the sweep asked again"
    );
    assert!(h.hidden_service.live().is_empty());
    let done = persisted(&h, &content.workload_id);
    assert!(done.destroyed);
    assert_eq!(done.hidden_address, None, "there is no address any more");
}

#[tokio::test]
async fn a_spawn_whose_address_the_daemon_refuses_starts_nothing() {
    // The address IS how a tenant reaches the lease, so a workload behind
    // one that could not be made would be unreachable. Nothing runs, the
    // slot is given back, and nothing is refunded (ADR 0003).
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    h.hidden_service.fail_next_create("ADD_ONION refused");
    let content = spawn_content(1);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "no_capacity");
    assert!(h.backend.created().is_empty(), "no workload was made");
    assert!(persisted_leases(&h.state_path).is_empty(), "no slot held");

    // And the id is free again, so the tenant's next try succeeds.
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["access"]["host"],
        FakeHiddenService::address_for(&content.workload_id)
    );
}

#[tokio::test]
async fn a_workload_that_would_not_start_takes_its_address_with_it() {
    // The address is made before the workload; a start the backend refuses
    // must not leave one answering for nothing.
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    h.backend.fail_next_create("no room on the daemon");
    let content = spawn_content(1);
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(error_of(&body), "no_capacity");
    assert_eq!(h.hidden_service.created().len(), 1);
    assert_eq!(
        h.hidden_service.destroyed(),
        vec![content.workload_id.clone()]
    );
    assert!(h.hidden_service.live().is_empty());
}

// ── hiding does not exclude resilience (spec §7.1, §10) ─────────────────

/// The primary's `liveness_cadence_s`, and the standby's settle window is
/// two of them.
const CADENCE: u64 = 60;

/// A Relay Set of one: the whole of it is a majority, so one refusal is a
/// primary that has lost its own relays.
const RELAYS: [&str; 1] = ["ws://hidden-relay:7100"];

fn warm() -> Listing {
    Listing {
        standby_price: Some(400),
        ..listing("warm", 1, 2)
    }
}

/// A hidden provider that publishes Liveness to a Relay Set of its own, so
/// a majority is something it can lose.
async fn hidden_with_relays() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let directory = FakeDirectory::new();
    directory.publishes_to(&RELAYS);
    hidden_harness_on(
        vec![warm()],
        &Keys::generate().secret_key().to_secret_hex(),
        &state_path,
        FakeBackend::new(),
        directory,
        |mut config| {
            config.relay_set = RELAYS.map(String::from).to_vec();
            config.liveness_cadence_s = CADENCE;
            config
        },
    )
    .await
}

#[tokio::test]
async fn a_self_stopped_primary_keeps_its_address() {
    // Stopping is not ending (spec §7.1): the lease is still paid, still
    // holds its slot and its workload id, and its container is still there
    // to be started again. Destroying its address would make the lease
    // unreachable for good, and `status` says `stopped` rather than lying
    // about a host — but the address is the lease's until the lease ends.
    let h = hidden_with_relays().await;
    let standby = Keys::generate();
    let set = [h.provider, standby.public_key()];
    let content = SpawnContent {
        standby_set: Some(set.iter().map(|k| k.to_hex()).collect()),
        ..spawn_content(1)
    };
    let spec = RequestSpec::spawn(&h, &content).addressed_to(&set);
    let tenant = Keys::parse(&spec.tenant.secret_key().to_secret_hex()).unwrap();
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/spawn",
        json!({ "request": spec.sign() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["role"], "primary");
    let host = body["access"]["host"].as_str().unwrap().to_string();

    // Five cadences in a row that no relay took: the primary stops its own
    // workload.
    h.directory.refuse_liveness_on(&RELAYS);
    for i in 1..=5 {
        let at = NOW + i * CADENCE;
        h.clock.set(at);
        h.service.publish_liveness(at).await.expect("published");
    }
    assert!(
        h.backend.calls().contains(&BackendCall::Stop(1000)),
        "{:?}",
        h.backend.calls()
    );
    let stopped = status_of(&h, &tenant, &content.workload_id).await;
    assert_eq!(stopped["state"], "stopped");
    assert!(stopped.get("access").is_none(), "{}", stopped);

    // The address is untouched, and the record still carries it.
    assert!(h.hidden_service.destroyed().is_empty());
    assert_eq!(h.hidden_service.live().len(), 1);
    assert_eq!(
        persisted(&h, &content.workload_id)
            .hidden_address
            .map(|a| a.host),
        Some(host)
    );

    // Only the ENDING takes it: the lease is still a lease until then.
    let (status, body) = terminate(&h, &tenant, &content.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        h.hidden_service.destroyed(),
        vec![content.workload_id.clone()]
    );
}

#[tokio::test]
async fn a_reservation_has_no_address_until_the_takeover_it_wins_starts_its_workload() {
    // A Warm Standby holds capacity with NOTHING RUNNING (spec §6.7), so
    // there is nowhere to reach and no address to make. Winning a Takeover
    // is where the lease first has a workload — and it gets an address then,
    // by the same call a spawn makes it with (ADR 0010).
    let h = hidden_with_relays().await;
    let primary = Keys::generate();
    let set = [primary.public_key(), h.provider];
    let content = SpawnContent {
        standby_set: Some(set.iter().map(|k| k.to_hex()).collect()),
        ..spawn_content(1)
    };
    let spec = RequestSpec::spawn(&h, &content).addressed_to(&set);
    let tenant = Keys::parse(&spec.tenant.secret_key().to_secret_hex()).unwrap();
    let (status, body) = post(
        &h.app,
        "/listings/warm/v1/standby",
        json!({ "request": spec.sign() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["role"], "standby");
    assert!(body.get("access").is_none(), "nowhere to reach: {}", body);
    assert!(
        h.hidden_service.created().is_empty(),
        "a reservation is given no address"
    );
    let reserved = status_of(&h, &tenant, &content.workload_id).await;
    assert_eq!(reserved["state"], "reserved");
    assert!(reserved.get("access").is_none(), "{}", reserved);

    // The primary goes silent on its own Relay Set, this standby announces,
    // and two cadences later it settles the race alone and wins.
    h.directory.seed_profile(profile_of(&primary));
    h.directory
        .set_liveness_on(primary.public_key(), &RELAYS, Absent);
    for at in [NOW, NOW + CADENCE, NOW + 3 * CADENCE] {
        h.clock.set(at);
        h.service.watch_primaries(at).await;
    }

    assert_eq!(
        h.hidden_service.created(),
        vec![(content.workload_id.clone(), lease_ports())],
        "the winner's start makes the address a spawn would have made"
    );
    let won = status_of(&h, &tenant, &content.workload_id).await;
    assert_eq!(won["state"], "running", "{}", won);
    assert_eq!(won["role"], "standby", "the role never changes");
    assert_eq!(
        won["access"]["host"],
        FakeHiddenService::address_for(&content.workload_id)
    );
    assert_eq!(won["takeover"]["winner"], h.provider.to_hex());
    mentions_no_ip(&won);
}

/// The silent primary's Profile, as its Relay Set holds it: where a standby
/// reads the relays to watch and the cadence to count.
fn profile_of(primary: &Keys) -> nostr_sdk::Event {
    let content = ProfileContent {
        ilp_address: "g.primary".to_string(),
        connector_url: "https://c.primary.example/ilp".to_string(),
        connector_seal_key: format!("0x04{}", "ab".repeat(64)),
        relays: RELAYS.map(String::from).to_vec(),
        settlement: vec![],
        isolation: "shared-kernel".to_string(),
        hidden: false,
        host: Some("198.51.100.9".to_string()),
        liveness_cadence_s: CADENCE,
    };
    EventBuilder::new(
        Kind::Custom(K_PROFILE),
        serde_json::to_string(&content).unwrap(),
    )
    .tags([Tag::parse(["L", TOON_LABEL]).unwrap()])
    .custom_created_at(Timestamp::from(NOW - 1000))
    .sign_with_keys(primary)
    .unwrap()
}

#[tokio::test]
async fn liveness_on_a_hidden_provider_still_counts_its_capacity() {
    // The Directory loop works: nothing about hiding changes what Liveness
    // says, and a hidden provider with no lease announces full capacity.
    let h = hidden_harness(vec![listing("basic", 1, 2)]).await;
    h.service.publish_liveness(NOW).await.unwrap();
    let liveness = h.directory.of_kind(toon_provider::nostr::kinds::K_LIVENESS);
    assert_eq!(liveness.len(), 1);
    let content: serde_json::Value = serde_json::from_str(&liveness[0].content).unwrap();
    assert_eq!(content["available"]["basic"], 2);
}

// ── what a public provider hands its backend ────────────────────────────

#[tokio::test]
async fn a_public_providers_workload_carries_no_egress_policy() {
    // The field exists on every `ContainerConfig`; a provider that is not
    // hidden fills nothing in, so today's networking is what the backend
    // gets; a hidden lease's is filled from `HiddenService::egress_for`.
    let h = harness().await;
    let (status, body) = spawn(&h, RequestSpec::spawn(&h, &spawn_content(1)).sign()).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["access"]["host"], PUBLIC_IP);
    let created = h.backend.created();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].egress, None);
    assert!(h.hidden_service.created().is_empty(), "never touched");
}

#[tokio::test]
async fn a_provider_that_is_not_hidden_touches_the_port_at_no_point_of_a_lease() {
    // The whole lease, start to end, on a provider whose config says
    // nothing about hiding: `public_ip` is the host all the way through and
    // the `HiddenService` beside it is never asked for anything.
    let h = harness().await;
    let (tenant, content, body) = spawn_lease(&h, 1).await;
    assert_eq!(body["access"]["host"], PUBLIC_IP);

    let running = status_of(&h, &tenant, &content.workload_id).await;
    assert_eq!(running["access"]["host"], PUBLIC_IP);
    assert_eq!(
        persisted(&h, &content.workload_id).hidden_address,
        None,
        "and nothing about an address is written down"
    );

    let (status, body) = terminate(&h, &tenant, &content.workload_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    h.service.sweep_expired_leases(NOW + INTERVAL).await;
    assert!(h.hidden_service.created().is_empty());
    assert!(h.hidden_service.restored().is_empty());
    assert!(h.hidden_service.destroyed().is_empty());

    // A restart of it asks the port nothing either.
    let restarted = harness_from(
        config_for(
            vec![listing("basic", 1, 2)],
            &h.provider_key,
            &h.state_path,
            &stub_registry().await,
            ImagePolicyConfig::default(),
        ),
        h.backend.clone(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        stub_registry().await,
    );
    restarted.service.restore_leases().await;
    assert!(restarted.hidden_service.restored().is_empty());
    assert!(restarted.hidden_service.created().is_empty());
}

#[tokio::test]
async fn the_fake_hidden_service_answers_a_predictable_anyone_host_and_restores_it() {
    // What the lease tests and fixtures assert `access.host` against, and
    // the restart story the real adapter relies on: the key `create_address`
    // answered brings back the same host through `restore_address`.
    let workload_id = "ab".repeat(32);
    let host = FakeHiddenService::address_for(&workload_id);
    assert!(host.ends_with(".anyone"));
    assert_eq!(host.len(), 56 + ".anyone".len());
    assert!(toon_provider::is_anyone_host(&host));
    assert_ne!(host, FakeHiddenService::address_for(&"cd".repeat(32)));

    use toon_provider::{AddressPort, HiddenService};
    let fake = FakeHiddenService::new();
    let ports = [AddressPort::same(40000), AddressPort::same(41000)];
    let address = fake.create_address(&workload_id, &ports).await.unwrap();
    assert_eq!(address.host, host);
    let key = address
        .key
        .expect("the fake gives a key back, as the daemon does");
    fake.destroy_address(&workload_id).await.unwrap();
    assert!(fake.live().is_empty());
    assert_eq!(
        fake.restore_address(&workload_id, &key, &ports)
            .await
            .unwrap(),
        host,
        "the same key is the same address"
    );
    assert!(fake
        .restore_address(&workload_id, "ED25519-V3:somebody-elses", &ports)
        .await
        .is_err());
    assert_eq!(fake.created().len(), 1);
    assert_eq!(fake.restored().len(), 2);
    assert_eq!(fake.destroyed(), vec![workload_id.clone()]);
    // And a hidden config the gate accepts, so the harness shape is the
    // shape an operator writes.
    hidden_config(ProviderConfig::default())
        .validate()
        .expect("the harness's hidden config passes the gate");
}
