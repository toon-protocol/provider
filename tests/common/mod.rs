//! Fixtures shared by the integration tests. Each test binary is its own crate,
//! so this is pulled in with `mod common;` rather than imported from the lib.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use toon_provider::compute::{ComputeBackend, ContainerConfig, ContainerStatus, NodeStatus};

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
    containers: Mutex<HashMap<u32, ContainerStatus>>,
}

impl FakeBackend {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn calls(&self) -> Vec<BackendCall> {
        self.calls.lock().unwrap().clone()
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
        self.record(BackendCall::Create(config.id));
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
