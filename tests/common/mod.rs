//! Fixtures shared by the integration tests. Each test binary is its own crate,
//! so this is pulled in with `mod common;` rather than imported from the lib.
#![allow(dead_code)]

pub mod harness;
pub mod relay;
pub mod store;

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use nostr_sdk::PublicKey;
use sha2::{Digest, Sha256};
use toon_provider::compute::{
    ComputeBackend, ContainerConfig, ContainerStatus, EgressPolicy, NodeStatus,
};
use toon_provider::nostr::kinds::{K_LIVENESS, K_PROFILE, K_TAKEOVER};
use toon_provider::{
    AddressPort, Clock, Directory, HiddenService, LivenessState, PublishReport, RelayLiveness,
};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// One thing the provider asked the compute backend to do. Tests assert on this
/// sequence rather than on the provider's internal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendCall {
    /// An image layout was loaded; the string is the file name it came in
    /// as (`<manifest hex>.oci.tar`).
    LoadImage(String),
    Create(u32),
    Start(u32),
    Stop(u32),
    Delete(u32),
}

/// An in-memory `ComputeBackend`, so the lease lifecycle can be driven without
/// Docker.
#[derive(Default)]
pub struct FakeBackend {
    calls: Mutex<Vec<BackendCall>>,
    /// Every `ContainerConfig` a create was asked for, in order — what the
    /// provider told the backend to run.
    created: Mutex<Vec<ContainerConfig>>,
    containers: Mutex<HashMap<u32, ContainerStatus>>,
    /// When set, the next create fails with this message, as a daemon that
    /// cannot pull the image or is out of disk would.
    fail_next_create: Mutex<Option<String>>,
    /// When set, the next delete fails with this message and leaves the
    /// container where it is, as a busy or wedged daemon would.
    fail_next_delete: Mutex<Option<String>>,
}

impl FakeBackend {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn calls(&self) -> Vec<BackendCall> {
        self.calls.lock().unwrap().clone()
    }

    pub fn created(&self) -> Vec<ContainerConfig> {
        self.created.lock().unwrap().clone()
    }

    pub fn status_of(&self, id: u32) -> ContainerStatus {
        *self
            .containers
            .lock()
            .unwrap()
            .get(&id)
            .unwrap_or(&ContainerStatus::Absent)
    }

    /// Pretend a workload is already running, as it would be after a provider
    /// restart. Records no call: nothing asked for it in this process.
    pub fn seed_running(&self, id: u32) {
        self.containers
            .lock()
            .unwrap()
            .insert(id, ContainerStatus::Running);
    }

    /// The workload disappears from the daemon without the provider asking —
    /// an operator's `docker rm`, a host reboot. Records no call.
    pub fn vanish(&self, id: u32) {
        self.containers.lock().unwrap().remove(&id);
    }

    pub fn fail_next_create(&self, why: &str) {
        *self.fail_next_create.lock().unwrap() = Some(why.to_string());
    }

    pub fn fail_next_delete(&self, why: &str) {
        *self.fail_next_delete.lock().unwrap() = Some(why.to_string());
    }

    fn record(&self, call: BackendCall) {
        self.calls.lock().unwrap().push(call);
    }
}

/// The image id the fake answers for a loaded layout: what a spawn then
/// runs, so a test can see that the workload was started by the id the
/// load produced and by nothing else.
pub fn loaded_image_id(layout_tar: &Path) -> String {
    format!(
        "loaded:{}",
        layout_tar.file_name().unwrap().to_string_lossy()
    )
}

#[async_trait]
impl ComputeBackend for FakeBackend {
    async fn find_available_id(&self, range_start: u32, range_end: u32) -> Result<u32> {
        let used = self.containers.lock().unwrap();
        for id in range_start..=range_end {
            if !used.contains_key(&id) {
                return Ok(id);
            }
        }
        anyhow::bail!("no available id in {}..={}", range_start, range_end)
    }

    async fn load_image(&self, layout_tar: &Path) -> Result<String> {
        anyhow::ensure!(
            layout_tar.is_file(),
            "no layout at {}",
            layout_tar.display()
        );
        self.record(BackendCall::LoadImage(
            layout_tar
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ));
        Ok(loaded_image_id(layout_tar))
    }

    async fn create_container(&self, config: &ContainerConfig) -> Result<String> {
        if let Some(why) = self.fail_next_create.lock().unwrap().take() {
            anyhow::bail!("{}", why);
        }
        self.record(BackendCall::Create(config.id));
        self.created.lock().unwrap().push(config.clone());
        self.containers
            .lock()
            .unwrap()
            .insert(config.id, ContainerStatus::Stopped);
        Ok(config.name.clone())
    }

    async fn start_container(&self, id: u32) -> Result<()> {
        self.record(BackendCall::Start(id));
        self.containers
            .lock()
            .unwrap()
            .insert(id, ContainerStatus::Running);
        Ok(())
    }

    async fn stop_container(&self, id: u32) -> Result<()> {
        self.record(BackendCall::Stop(id));
        self.containers
            .lock()
            .unwrap()
            .insert(id, ContainerStatus::Stopped);
        Ok(())
    }

    async fn delete_container(&self, id: u32) -> Result<()> {
        self.record(BackendCall::Delete(id));
        if let Some(why) = self.fail_next_delete.lock().unwrap().take() {
            anyhow::bail!("{}", why);
        }
        self.containers.lock().unwrap().remove(&id);
        Ok(())
    }

    async fn get_node_status(&self) -> Result<NodeStatus> {
        Ok(NodeStatus {
            cpu_usage: 0.0,
            memory_used: 0,
            memory_total: 8 * 1024 * 1024 * 1024,
            disk_used: 0,
            disk_total: 256 * 1024 * 1024 * 1024,
        })
    }

    async fn get_container_ip(&self, _id: u32) -> Result<Option<String>> {
        Ok(Some("10.0.0.2".to_string()))
    }

    async fn get_container_status(&self, id: u32) -> Result<ContainerStatus> {
        Ok(self.status_of(id))
    }
}

/// A tiny, syntactically valid OCI manifest naming no real image: a config
/// blob and one layer, together 1000 bytes, small enough to sit under any
/// cap a test configures. It names no index, so it needs no arch to match.
pub fn valid_manifest_bytes() -> Vec<u8> {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 100,
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "size": 900,
            "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }]
    })
    .to_string()
    .into_bytes()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// The digest a spawn or availability body must name to get
/// `valid_manifest_bytes` back from `stub_registry`.
pub fn valid_digest() -> String {
    format!("sha256:{}", sha256_hex(&valid_manifest_bytes()))
}

/// A registry stub that answers every manifest request with
/// `valid_manifest_bytes`, regardless of repository or digest asked for —
/// enough for any test that only needs *a* runnable image. Tests that care
/// about a specific size, arch selection or a denied digest mount their own
/// `Mock`s on the returned server instead (or alongside; wiremock tries
/// mounted mocks most-specific-first).
///
/// The returned `MockServer` owns the listening socket and the task serving
/// it: it must be kept alive (e.g. as a field on the test harness) for as
/// long as the code under test may still call it.
pub async fn stub_registry() -> MockServer {
    let server = MockServer::start().await;
    mount_default_manifest(&server).await;
    server
}

pub async fn mount_default_manifest(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/v2/.*/manifests/.*$"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(valid_manifest_bytes()))
        .mount(server)
        .await;
}

/// A clock the test moves by hand, so expiry and request freshness are
/// decided on chosen instants rather than on the wall.
pub struct FakeClock(AtomicU64);

impl FakeClock {
    pub fn at(now: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(now)))
    }

    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }

    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The egress policy the fake `HiddenService` answers unless a test sets
/// another: what a hidden provider's `[anon.egress]` names in the sandbox.
pub const FAKE_EGRESS_NETWORK: &str = "toon-hidden-egress";
pub const FAKE_EGRESS_GATEWAY: &str = "172.30.0.2";

/// An in-memory `HiddenService`, so a hidden provider's per-lease addresses
/// can be created and destroyed without an `anon` daemon. It records every
/// address created (with the ports it maps) and destroyed, in order, and
/// answers a deterministic `.anyone` host for each workload id, so a test —
/// and a fixture — can say exactly what `access.host` must be.
pub struct FakeHiddenService {
    /// Every `create_address`, in order: the workload id and the ports it
    /// asked for.
    created: Mutex<Vec<(String, Vec<AddressPort>)>>,
    /// Every `destroy_address`, in order, whether or not an address existed.
    destroyed: Mutex<Vec<String>>,
    /// The addresses that exist right now: workload id -> host.
    live: Mutex<HashMap<String, String>>,
    /// When set, the next create fails with this message, as a daemon whose
    /// control port refused `ADD_ONION` would.
    fail_next_create: Mutex<Option<String>>,
    /// When set, the next destroy fails with this message and leaves the
    /// address where it is, as a daemon that could not be reached would.
    fail_next_destroy: Mutex<Option<String>>,
    /// What `egress_for` answers.
    egress: Mutex<EgressPolicy>,
}

impl FakeHiddenService {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            created: Mutex::default(),
            destroyed: Mutex::default(),
            live: Mutex::default(),
            fail_next_create: Mutex::default(),
            fail_next_destroy: Mutex::default(),
            egress: Mutex::new(EgressPolicy {
                network: FAKE_EGRESS_NETWORK.to_string(),
                gateway: FAKE_EGRESS_GATEWAY.to_string(),
            }),
        })
    }

    /// The `.anyone` host this fake gives `workload_id`: the first 56 hex
    /// digits of the id, each mapped onto a letter, so the host has the
    /// shape of a real address (56 base32 characters), is different for
    /// every workload, and can be predicted by the test that spawned it.
    pub fn address_for(workload_id: &str) -> String {
        let label: String = workload_id
            .chars()
            .take(56)
            .map(|c| (b'a' + c.to_digit(16).unwrap_or(0) as u8) as char)
            .collect();
        format!("{label}.anyone")
    }

    pub fn created(&self) -> Vec<(String, Vec<AddressPort>)> {
        self.created.lock().unwrap().clone()
    }

    pub fn destroyed(&self) -> Vec<String> {
        self.destroyed.lock().unwrap().clone()
    }

    /// The addresses that exist right now, by workload id.
    pub fn live(&self) -> HashMap<String, String> {
        self.live.lock().unwrap().clone()
    }

    pub fn fail_next_create(&self, why: &str) {
        *self.fail_next_create.lock().unwrap() = Some(why.to_string());
    }

    pub fn fail_next_destroy(&self, why: &str) {
        *self.fail_next_destroy.lock().unwrap() = Some(why.to_string());
    }

    pub fn set_egress(&self, egress: EgressPolicy) {
        *self.egress.lock().unwrap() = egress;
    }
}

#[async_trait]
impl HiddenService for FakeHiddenService {
    async fn create_address(&self, workload_id: &str, ports: &[AddressPort]) -> Result<String> {
        self.created
            .lock()
            .unwrap()
            .push((workload_id.to_string(), ports.to_vec()));
        if let Some(why) = self.fail_next_create.lock().unwrap().take() {
            anyhow::bail!("{}", why);
        }
        let host = Self::address_for(workload_id);
        self.live
            .lock()
            .unwrap()
            .insert(workload_id.to_string(), host.clone());
        Ok(host)
    }

    async fn destroy_address(&self, workload_id: &str) -> Result<()> {
        self.destroyed.lock().unwrap().push(workload_id.to_string());
        if let Some(why) = self.fail_next_destroy.lock().unwrap().take() {
            anyhow::bail!("{}", why);
        }
        self.live.lock().unwrap().remove(workload_id);
        Ok(())
    }

    fn egress_for(&self, _workload_id: &str) -> EgressPolicy {
        self.egress.lock().unwrap().clone()
    }
}

/// An in-memory `Directory`, so what the provider publishes can be read back
/// without paying a relay. It records every event in publication order; tests
/// assert on that sequence, never on the provider's internal state.
#[derive(Default)]
pub struct FakeDirectory {
    published: Mutex<Vec<nostr_sdk::Event>>,
    /// The Liveness `query_liveness` answers with, as a relay holding one
    /// would.
    liveness: Mutex<Option<nostr_sdk::Event>>,
    /// When set, the next publish fails with this message — a relay that is
    /// down, or a paid packet that was refused.
    fail_next_publish: Mutex<Option<String>>,
    /// When set, every publish is recorded but reports this relay as having
    /// refused — a Relay Set reached only in part.
    relay_always_refuses: Mutex<Option<String>>,
    /// The Relay Set every publication is offered to, when a test says so
    /// (`publishes_to`). Unset, the fake answers as it always has: one
    /// nameless relay took it.
    relay_set: Mutex<Option<Vec<String>>>,
    /// Relays of that set which refuse every LIVENESS from now on
    /// (`refuse_liveness_on`), taking everything else. What a primary's own
    /// majority count reads (spec §7.1).
    liveness_refusals: Mutex<Vec<String>>,
    /// Image Registry entries `get_image_entry` answers with, as relays
    /// holding them would: matched by kind, signer and `d`, newest first.
    image_entries: Mutex<Vec<nostr_sdk::Event>>,
    /// Every `(address, relay)` the provider asked for, in order — so a
    /// test can see that a relay was (or was not) consulted.
    entry_lookups: Mutex<Vec<(String, String)>>,
    /// Blob Records `find_blob_records` answers with, as the Relay Set
    /// holding them would: matched by kind and `#x`, in the order they were
    /// seeded. Seeding order models the order a Relay Set answered in —
    /// `ConnectorDirectory` sorts its own answer newest first — so a test
    /// can say which of two records for one digest the provider tries
    /// first, whatever decided that order in production.
    blob_records: Mutex<Vec<nostr_sdk::Event>>,
    /// Every digest the provider looked Blob Records up for, in order — so
    /// a test can see that the Relay Set was (or was not) searched, and for
    /// what.
    blob_record_lookups: Mutex<Vec<String>>,
    /// Provider Profiles `get_profile` answers with, as the Relay Set
    /// holding them would: matched by kind and signer, newest first.
    profiles: Mutex<Vec<nostr_sdk::Event>>,
    /// What each relay says about each provider's Liveness, as a test sets
    /// it: `(provider hex, relay URL) -> state`. A pair nobody set is
    /// `Absent`, as a relay that never heard of the provider is.
    liveness_states: Mutex<HashMap<(String, String), LivenessState>>,
    /// Every `(provider, relays)` the provider asked `liveness_state` for,
    /// in order — so a test can see WHICH relays a standby watched.
    liveness_lookups: Mutex<Vec<(PublicKey, Vec<String>)>>,
    /// Every Takeover handed to `publish_takeover`, with the relays it was
    /// addressed to. Also in `published`, so `of_kind(K_TAKEOVER)` sees it.
    takeover_publications: Mutex<Vec<(nostr_sdk::Event, Vec<String>)>>,
    /// Takeovers `find_takeovers` answers with, as the relays holding them
    /// would: matched by kind, `d` and signer.
    takeovers: Mutex<Vec<nostr_sdk::Event>>,
    /// Every READ the provider made through the Directory port, in order. A
    /// test that asserts the provider looked nothing up (a spawn's
    /// `template`, which it never resolves) needs the fake to record the
    /// question, not just the answer.
    ///
    /// Prose rather than a `BackendCall`-style enum on purpose: the tests
    /// that read it ask whether the journal is EMPTY, and the string is what
    /// the failure prints. A new read on the port needs one `push` here and
    /// no new variant anywhere.
    reads: Mutex<Vec<String>>,
}

impl FakeDirectory {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Everything published so far, in order.
    pub fn published(&self) -> Vec<nostr_sdk::Event> {
        self.published.lock().unwrap().clone()
    }

    /// Everything published so far of one kind.
    pub fn of_kind(&self, kind: u16) -> Vec<nostr_sdk::Event> {
        self.published()
            .into_iter()
            .filter(|e| e.kind.as_u16() == kind)
            .collect()
    }

    /// Every Directory read so far, in order.
    pub fn reads(&self) -> Vec<String> {
        self.reads.lock().unwrap().clone()
    }

    pub fn seed_liveness(&self, event: nostr_sdk::Event) {
        *self.liveness.lock().unwrap() = Some(event);
    }

    pub fn fail_next_publish(&self, why: &str) {
        *self.fail_next_publish.lock().unwrap() = Some(why.to_string());
    }

    /// One relay of the Relay Set refuses every write from now on, while the
    /// rest take it.
    pub fn relay_always_refuses(&self, relay: &str) {
        *self.relay_always_refuses.lock().unwrap() = Some(relay.to_string());
    }

    /// Every publication from now on is offered to exactly these relays, and
    /// the report names them one by one. Set it to the provider's own
    /// `relay_set` whenever the per-relay outcome has to MEAN something: a
    /// primary counts the relays of its own Relay Set that took its Liveness
    /// (spec §7.1), which a report about one nameless relay says nothing
    /// about.
    pub fn publishes_to(&self, relays: &[&str]) {
        *self.relay_set.lock().unwrap() = Some(relays.iter().map(|r| r.to_string()).collect());
    }

    /// These relays refuse every LIVENESS from now on and take everything
    /// else — one relay of three is a primary that still has its majority,
    /// two of three is one that has lost it. Only meaningful beside
    /// `publishes_to`, which says what the whole Relay Set is.
    pub fn refuse_liveness_on(&self, relays: &[&str]) {
        *self.liveness_refusals.lock().unwrap() = relays.iter().map(|r| r.to_string()).collect();
    }

    /// A relay holds this Image Registry entry (or any addressable event):
    /// `get_image_entry` will answer with it for its own address.
    pub fn seed_image_entry(&self, event: nostr_sdk::Event) {
        self.image_entries.lock().unwrap().push(event);
    }

    /// Every `(address, relay)` the provider has asked `get_image_entry`
    /// for, in order.
    pub fn entry_lookups(&self) -> Vec<(String, String)> {
        self.entry_lookups.lock().unwrap().clone()
    }

    /// A relay of the provider's Relay Set holds this Blob Record:
    /// `find_blob_records` will answer with it for the digest its `x` tag
    /// names. Seed two for one digest to choose the order they are tried
    /// in.
    pub fn seed_blob_record(&self, event: nostr_sdk::Event) {
        self.blob_records.lock().unwrap().push(event);
    }

    /// Every digest the provider has asked `find_blob_records` for, in
    /// order.
    pub fn blob_record_lookups(&self) -> Vec<String> {
        self.blob_record_lookups.lock().unwrap().clone()
    }

    /// The Relay Set holds this Provider Profile: `get_profile` will answer
    /// with it for its signer.
    pub fn seed_profile(&self, event: nostr_sdk::Event) {
        self.profiles.lock().unwrap().push(event);
    }

    /// What `relay` says about `provider`'s Liveness from now on.
    pub fn set_liveness(&self, provider: PublicKey, relay: &str, state: LivenessState) {
        self.liveness_states
            .lock()
            .unwrap()
            .insert((provider.to_hex(), relay.to_string()), state);
    }

    /// `provider` is `state` on every relay of `relays` from now on.
    pub fn set_liveness_on(&self, provider: PublicKey, relays: &[&str], state: LivenessState) {
        for relay in relays {
            self.set_liveness(provider, relay, state);
        }
    }

    /// Every `(provider, relays)` the provider has asked `liveness_state`
    /// for, in order.
    pub fn liveness_lookups(&self) -> Vec<(PublicKey, Vec<String>)> {
        self.liveness_lookups.lock().unwrap().clone()
    }

    /// Every Takeover handed to `publish_takeover` so far, in order, each
    /// with the relays it was addressed to.
    pub fn takeover_publications(&self) -> Vec<(nostr_sdk::Event, Vec<String>)> {
        self.takeover_publications.lock().unwrap().clone()
    }

    /// The relays hold this Takeover: `find_takeovers` will answer with it
    /// for its `d` and signer.
    pub fn seed_takeover(&self, event: nostr_sdk::Event) {
        self.takeovers.lock().unwrap().push(event);
    }

    fn read(&self, what: String) {
        self.reads.lock().unwrap().push(what);
    }
}

impl FakeDirectory {
    /// What every publication through the fake answers: recorded, then
    /// accepted by one nameless relay — or, once `publishes_to` has named a
    /// Relay Set, by every relay of it but those refusing this kind — and
    /// refused by the one `relay_always_refuses` names, if any, unless the
    /// next publication was told to fail.
    fn record_publication(&self, event: nostr_sdk::Event) -> Result<PublishReport> {
        if let Some(why) = self.fail_next_publish.lock().unwrap().take() {
            anyhow::bail!("{}", why);
        }
        let kind = event.kind.as_u16();
        self.published.lock().unwrap().push(event);

        let mut report = match self.relay_set.lock().unwrap().clone() {
            // A named Relay Set: every relay of it took the event, except
            // those refusing this kind.
            Some(relays) => {
                let refuses: Vec<String> = if kind == K_LIVENESS {
                    self.liveness_refusals.lock().unwrap().clone()
                } else {
                    Vec::new()
                };
                let (failed, accepted): (Vec<String>, Vec<String>) =
                    relays.into_iter().partition(|r| refuses.contains(r));
                PublishReport {
                    accepted,
                    failed: failed
                        .into_iter()
                        .map(|r| (r, "relay refused".to_string()))
                        .collect(),
                }
            }
            None => PublishReport {
                accepted: vec!["wss://relay.example".to_string()],
                failed: Default::default(),
            },
        };
        if let Some(relay) = self.relay_always_refuses.lock().unwrap().clone() {
            report.failed.insert(relay, "relay refused".to_string());
        }
        Ok(report)
    }
}

#[async_trait]
impl Directory for FakeDirectory {
    async fn publish(&self, event: nostr_sdk::Event) -> Result<PublishReport> {
        self.record_publication(event)
    }

    async fn query_liveness(
        &self,
        provider: nostr_sdk::PublicKey,
    ) -> Result<Option<nostr_sdk::Event>> {
        self.read(format!("query_liveness({})", provider.to_hex()));
        Ok(self
            .liveness
            .lock()
            .unwrap()
            .clone()
            .filter(|e| e.pubkey == provider))
    }

    async fn get_image_entry(
        &self,
        address: &str,
        relay: &str,
    ) -> Result<Option<nostr_sdk::Event>> {
        self.read(format!("get_image_entry({address}, {relay})"));
        self.entry_lookups
            .lock()
            .unwrap()
            .push((address.to_string(), relay.to_string()));
        let (kind, pubkey, d) = toon_provider::directory::parse_coordinate(address)?;
        Ok(self
            .image_entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.kind.as_u16() == kind
                    && e.pubkey == pubkey
                    && e.tags
                        .find(nostr_sdk::TagKind::d())
                        .and_then(|t| t.content())
                        == Some(d.as_str())
            })
            .max_by_key(|e| e.created_at)
            .cloned())
    }

    async fn find_blob_records(&self, digest: &str) -> Result<Vec<nostr_sdk::Event>> {
        self.read(format!("find_blob_records({digest})"));
        self.blob_record_lookups
            .lock()
            .unwrap()
            .push(digest.to_string());
        // What a relay answers a `#x` filter with: every kind-30435 event
        // tagged with the hex, whoever signed it. Seeding order is the
        // answer's order, so a test can put the record it wants tried
        // first, first.
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        Ok(self
            .blob_records
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.kind.as_u16() == toon_provider::nostr::kinds::K_BLOB
                    && e.tags
                        .find(nostr_sdk::TagKind::custom("x"))
                        .and_then(|t| t.content())
                        == Some(hex)
            })
            .cloned()
            .collect())
    }

    async fn get_profile(&self, provider: PublicKey) -> Result<Option<nostr_sdk::Event>> {
        self.read(format!("get_profile({})", provider.to_hex()));
        Ok(self
            .profiles
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.kind.as_u16() == K_PROFILE && e.pubkey == provider)
            .max_by_key(|e| e.created_at)
            .cloned())
    }

    async fn liveness_state(
        &self,
        provider: PublicKey,
        relays: &[String],
        _now: u64,
    ) -> Result<RelayLiveness> {
        self.read(format!(
            "liveness_state({}, [{}])",
            provider.to_hex(),
            relays.join(", ")
        ));
        self.liveness_lookups
            .lock()
            .unwrap()
            .push((provider, relays.to_vec()));
        // The test SETS each relay's answer, so `now` decides nothing here:
        // "expired" is what the test said, not what a tag says.
        let states = self.liveness_states.lock().unwrap();
        Ok(relays
            .iter()
            .map(|relay| {
                let state = states
                    .get(&(provider.to_hex(), relay.clone()))
                    .copied()
                    .unwrap_or(LivenessState::Absent);
                (relay.clone(), state)
            })
            .collect())
    }

    async fn publish_takeover(
        &self,
        event: nostr_sdk::Event,
        relays: &[String],
    ) -> Result<PublishReport> {
        let report = self.record_publication(event.clone())?;
        self.takeover_publications
            .lock()
            .unwrap()
            .push((event.clone(), relays.to_vec()));
        // A relay that took the claim holds it: the provider's own Takeover
        // is among what `find_takeovers` answers, as it would be on the
        // primary's Relay Set. A fake built fresh — a restart with a
        // Directory that knows nothing — holds none of it.
        self.takeovers.lock().unwrap().push(event);
        Ok(report)
    }

    async fn find_takeovers(
        &self,
        workload_id: &str,
        claimants: &[PublicKey],
        relays: &[String],
    ) -> Result<Vec<nostr_sdk::Event>> {
        self.read(format!(
            "find_takeovers({}, {} claimant(s), [{}])",
            workload_id,
            claimants.len(),
            relays.join(", ")
        ));
        // What the relays answer an authors + `#d` filter with, earliest
        // first, as `ConnectorDirectory` orders it.
        let mut found: Vec<nostr_sdk::Event> = self
            .takeovers
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.kind.as_u16() == K_TAKEOVER
                    && e.tags.identifier() == Some(workload_id)
                    && claimants.contains(&e.pubkey)
            })
            .cloned()
            .collect();
        found.sort_by_key(|e| e.created_at);
        Ok(found)
    }
}
