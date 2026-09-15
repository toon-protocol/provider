//! Fixtures shared by the integration tests. Each test binary is its own crate,
//! so this is pulled in with `mod common;` rather than imported from the lib.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use toon_provider::compute::{ComputeBackend, ContainerConfig, ContainerStatus, NodeStatus};
use toon_provider::{Clock, Directory, PublishReport};

/// One thing the provider asked the compute backend to do. Tests assert on this
/// sequence rather than on the provider's internal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendCall {
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

    fn record(&self, call: BackendCall) {
        self.calls.lock().unwrap().push(call);
    }
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

    pub fn seed_liveness(&self, event: nostr_sdk::Event) {
        *self.liveness.lock().unwrap() = Some(event);
    }

    pub fn fail_next_publish(&self, why: &str) {
        *self.fail_next_publish.lock().unwrap() = Some(why.to_string());
    }
}

#[async_trait]
impl Directory for FakeDirectory {
    async fn publish(&self, event: nostr_sdk::Event) -> Result<PublishReport> {
        if let Some(why) = self.fail_next_publish.lock().unwrap().take() {
            anyhow::bail!("{}", why);
        }
        self.published.lock().unwrap().push(event);
        Ok(PublishReport {
            accepted: vec!["wss://relay.example".to_string()],
            failed: Default::default(),
        })
    }

    async fn query_liveness(
        &self,
        provider: nostr_sdk::PublicKey,
    ) -> Result<Option<nostr_sdk::Event>> {
        Ok(self
            .liveness
            .lock()
            .unwrap()
            .clone()
            .filter(|e| e.pubkey == provider))
    }
}
