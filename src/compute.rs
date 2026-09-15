// The compute port: everything the provider does to hardware goes through
// `ComputeBackend`, so the lease lifecycle can be tested against a fake.
//
// Docker is the only implementation in this milestone. The trait stays
// backend-agnostic — ids, not Docker handles; `Result`, not exit codes — so an
// LXD, Proxmox or KVM backend can return without touching its callers.
//
// This module deliberately says "container": it is the backend's own noun for
// the object it creates and destroys. Everything above it — leases, tenants,
// listings — speaks the glossary, and calls the same thing a workload.

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Prefix on every host-visible workload name. `find_available_id` scans for
/// it, so a backend must never create a workload outside this namespace.
pub const WORKLOAD_NAME_PREFIX: &str = "toon-";

/// Host-visible name for a workload. `find_available_id` parses the id back out
/// of this form, so the two must stay in sync.
pub fn container_name(id: u32) -> String {
    format!("{}{}", WORKLOAD_NAME_PREFIX, id)
}

pub fn id_from_container_name(name: &str) -> Option<u32> {
    name.strip_prefix(WORKLOAD_NAME_PREFIX)?.parse().ok()
}

/// The environment variable a workload finds the tenant's SSH public key in.
/// The one convention this provider imposes on an image that wants to serve
/// SSH (spec §9: the tenant's key, and nothing else, opens the workload).
pub const SSH_PUBLIC_KEY_ENV: &str = "SSH_PUBLIC_KEY";

/// The container port `ContainerConfig::host_port` forwards to.
pub const SSH_CONTAINER_PORT: u16 = 22;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub cpu_usage: f64,
    pub memory_used: u64,
    pub memory_total: u64,
    pub disk_used: u64,
    pub disk_total: u64,
}

/// One published port mapping, exposed on the host as `host_port`. Distinct
/// from the SSH forward in `ContainerConfig::host_port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    /// "tcp" | "udp"
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerConfig {
    pub id: u32,
    pub name: String,
    /// What to run: a content-addressed OCI reference, `reference@digest`,
    /// so the backend verifies the bytes it pulls.
    pub image: String,
    /// CPU as the listing prices it. 1000 = one core.
    pub cpu_millicores: u32,
    pub memory_mb: u32,
    pub storage_gb: u32,
    /// The tenant's SSH public key. There is no password: no usable credential
    /// ever travels in a response. Handed to the workload as the environment
    /// variable `SSH_PUBLIC_KEY_ENV`; an image whose sshd installs it gets
    /// SSH at `host_port`, and an image can always bridge it with the spawn's
    /// entrypoint and args.
    pub ssh_key: Option<String>,
    /// SSH host-port forward to `SSH_CONTAINER_PORT`. Distinct from `ports`.
    pub host_port: Option<u16>,
    pub ports: Vec<PortMapping>,
    pub env: HashMap<String, String>,
    /// Overrides the image's entrypoint. `None` = whatever the image declares.
    pub entrypoint: Option<String>,
    /// Arguments passed to the entrypoint.
    pub args: Vec<String>,
    /// In-container path for persistent state. `None` = stateless.
    pub data_path: Option<String>,
}

#[async_trait]
pub trait ComputeBackend: Send + Sync {
    async fn find_available_id(&self, range_start: u32, range_end: u32) -> Result<u32>;

    /// Returns the backend's container ID/name.
    async fn create_container(&self, config: &ContainerConfig) -> Result<String>;

    async fn start_container(&self, id: u32) -> Result<()>;

    async fn stop_container(&self, id: u32) -> Result<()>;

    async fn delete_container(&self, id: u32) -> Result<()>;

    async fn get_node_status(&self) -> Result<NodeStatus>;

    async fn get_container_ip(&self, id: u32) -> Result<Option<String>>;

    /// Defaults to `Running` so a backend that cannot answer never causes a
    /// destructive action to be taken on its behalf.
    async fn get_container_status(&self, _id: u32) -> Result<ContainerStatus> {
        Ok(ContainerStatus::Running)
    }
}

/// Three-valued: an unreachable backend must not be mistaken for a stopped
/// workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatus {
    Running,
    Stopped,
    /// The backend answered, but the workload is not in its list.
    Absent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_name_round_trips() {
        assert_eq!(container_name(1234), "toon-1234");
        assert_eq!(id_from_container_name("toon-1234"), Some(1234));
        assert_eq!(id_from_container_name("something-else"), None);
        assert_eq!(id_from_container_name("toon-notanumber"), None);
    }
}
