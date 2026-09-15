// Provider configuration: one TOML file, no environment variables.
//
// Paygress spread its settings over a JSON config, an `.env` file read by the
// nginx module and CLI flags. A provider joining the TOON marketplace needs
// nobody's approval and should need one file, so this is the only source.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Which `ComputeBackend` the provider runs workloads on.
///
/// Docker is the only one in this milestone. The enum stays so that adding a
/// backend is a config change rather than a new config shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    #[default]
    Docker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub backend: BackendKind,

    /// Name this provider publishes for itself.
    pub provider_name: String,

    /// The address tenants reach workloads at. Ports are exposed as
    /// `public_ip:host_port`; there are no hostnames and no TLS.
    pub public_ip: String,

    /// Nostr secret key. It signs everything this provider publishes and is
    /// the identity a Lease Request is addressed to.
    pub nostr_private_key: String,

    /// The relays this provider publishes its profile, listings and liveness
    /// to. Nothing is published yet; the directory lands in a later ticket.
    #[serde(default)]
    pub relay_set: Vec<String>,

    /// Capabilities this provider is willing to grant — privileges beyond an
    /// ordinary workload, e.g. `docker`, `nesting`.
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Where the HTTP app listens. The provider's TOON connector is the only
    /// thing that should be able to reach it.
    #[serde(default = "default_http_bind_addr")]
    pub http_bind_addr: String,

    /// Inclusive range of backend workload ids this provider may use.
    #[serde(default = "default_id_range_start")]
    pub workload_id_range_start: u32,
    #[serde(default = "default_id_range_end")]
    pub workload_id_range_end: u32,

    /// First host port handed out for a workload's SSH forward. Unset derives
    /// one from the workload id.
    #[serde(default)]
    pub ssh_port_start: Option<u16>,

    /// Where the lease table is mirrored to disk. It is the only record that a
    /// lease exists — the backend knows a workload is running but not whose it
    /// is or when it expires — so held purely in memory, a restart would strand
    /// every paid workload.
    #[serde(default = "default_lease_state_path")]
    pub lease_state_path: String,
}

impl ProviderConfig {
    /// Host port forwarded to a workload's SSH. Derived rather than stored, so
    /// every answer that names a port for a given id names the same one.
    ///
    /// The offset is computed in `u32` and saturated: narrowing it first would
    /// let an id far above the range start wrap to a low offset and hand two
    /// leases the same port.
    pub fn ssh_host_port(&self, id: u32) -> u16 {
        match self.ssh_port_start {
            Some(start) => {
                let offset = id.saturating_sub(self.workload_id_range_start);
                u16::try_from(u32::from(start).saturating_add(offset)).unwrap_or(u16::MAX)
            }
            None => 30000 + (id % 10000) as u16,
        }
    }
}

fn default_http_bind_addr() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_id_range_start() -> u32 {
    1000
}

fn default_id_range_end() -> u32 {
    1999
}

fn default_lease_state_path() -> String {
    "./toon-provider-leases.json".to_string()
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            backend: BackendKind::Docker,
            provider_name: "TOON Provider".to_string(),
            public_ip: "127.0.0.1".to_string(),
            nostr_private_key: String::new(),
            relay_set: Vec::new(),
            capabilities: Vec::new(),
            http_bind_addr: default_http_bind_addr(),
            workload_id_range_start: default_id_range_start(),
            workload_id_range_end: default_id_range_end(),
            ssh_port_start: None,
            lease_state_path: default_lease_state_path(),
        }
    }
}

pub fn load_config(path: &str) -> Result<ProviderConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read provider config at {}", path))?;
    toml::from_str(&content).with_context(|| format!("parse provider config at {}", path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_toml_file_is_enough() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.toml");
        std::fs::write(
            &path,
            r#"
provider_name = "Test Provider"
public_ip = "203.0.113.7"
nostr_private_key = "nsec1example"
"#,
        )
        .unwrap();

        let cfg = load_config(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.provider_name, "Test Provider");
        assert_eq!(cfg.public_ip, "203.0.113.7");
        assert_eq!(cfg.backend, BackendKind::Docker);
        assert_eq!(cfg.http_bind_addr, "127.0.0.1:8080");
        assert_eq!(cfg.lease_state_path, "./toon-provider-leases.json");
    }

    #[test]
    fn config_round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.toml");
        let cfg = ProviderConfig {
            provider_name: "Round Trip".to_string(),
            relay_set: vec!["wss://relay.toon.example".to_string()],
            capabilities: vec!["docker".to_string()],
            ssh_port_start: Some(40000),
            ..ProviderConfig::default()
        };

        std::fs::write(&path, toml::to_string_pretty(&cfg).unwrap()).unwrap();
        let back = load_config(path.to_str().unwrap()).unwrap();

        assert_eq!(back.provider_name, "Round Trip");
        assert_eq!(back.relay_set, vec!["wss://relay.toon.example".to_string()]);
        assert_eq!(back.capabilities, vec!["docker".to_string()]);
        assert_eq!(back.ssh_port_start, Some(40000));
    }

    #[test]
    fn ssh_host_port_is_stable_for_an_id() {
        let cfg = ProviderConfig {
            ssh_port_start: Some(40000),
            workload_id_range_start: 1000,
            ..ProviderConfig::default()
        };
        assert_eq!(cfg.ssh_host_port(1000), 40000);
        assert_eq!(cfg.ssh_host_port(1007), 40007);
        assert_eq!(cfg.ssh_host_port(1007), cfg.ssh_host_port(1007));
    }

    #[test]
    fn ssh_host_port_never_wraps_for_an_id_far_above_the_range() {
        // Narrowing the offset to u16 before adding would wrap 1000 + 65536
        // back to `start`, handing two leases the same forward.
        let cfg = ProviderConfig {
            ssh_port_start: Some(40000),
            workload_id_range_start: 1000,
            ..ProviderConfig::default()
        };
        assert_eq!(cfg.ssh_host_port(1000 + 65_536), u16::MAX);
        assert_ne!(cfg.ssh_host_port(1000 + 65_536), cfg.ssh_host_port(1000));
    }

    #[test]
    fn ssh_host_port_falls_back_to_a_derived_port() {
        let cfg = ProviderConfig::default();
        assert_eq!(cfg.ssh_host_port(1042), 31042);
    }
}
