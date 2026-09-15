// Provider configuration: one TOML file, no environment variables.
//
// Paygress spread its settings over a JSON config, an `.env` file read by the
// nginx module and CLI flags. A provider joining the TOON marketplace needs
// nobody's approval and should need one file, so this is the only source.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::nostr::directory_events::Settlement;
use crate::nostr::wire::Resources;

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

/// The most ports one workload may publish. Bounds the host-port block each
/// workload id owns (`ProviderConfig::workload_host_port`).
pub const MAX_PORTS_PER_WORKLOAD: u16 = 16;

/// One sellable tier: the resources a lease gets, the capabilities it grants,
/// and its price per Lease Interval. Published as a Listing event and sold on
/// `<addr>.<name>.v<version>.spawn` / `.extend`.
///
/// A price or resource change is a NEW VERSION with its own routes, so a lease
/// keeps the price it started at (ADR 0009). Two entries may share a name as
/// long as their versions differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listing {
    /// Stable across versions; the Listing event's `d` tag and an ILP address
    /// segment, so `[A-Za-z0-9_~-]+`.
    pub name: String,
    /// Starts at 1; increases on every price or resource change.
    pub version: u32,
    pub resources: Resources,
    /// `amd64` | `arm64`.
    pub arch: String,
    /// Length of one Lease Interval, in seconds.
    pub lease_interval_s: u64,
    /// µUSDC per Lease Interval.
    pub price: u64,
    /// Capabilities granted to every workload of this tier (ADR 0004).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// How many leases of this tier may run at once, across all its versions.
    ///
    /// Declared rather than measured: a tier is a slice of hardware the
    /// provider has decided to sell, and only the provider knows how many
    /// slices its box holds. Liveness publishes `capacity - running`.
    pub capacity: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    #[serde(default)]
    pub backend: BackendKind,

    /// Name this provider publishes for itself.
    pub provider_name: String,

    /// The provider's ILP address, e.g. `g.acme`. Every route is a suffix
    /// of it (`<ilp_address>.<listing>.v<n>.spawn`), and the Provider Profile
    /// publishes it.
    #[serde(default = "default_ilp_address")]
    pub ilp_address: String,

    /// The address tenants reach workloads at. Ports are exposed as
    /// `public_ip:host_port`; there are no hostnames and no TLS.
    pub public_ip: String,

    /// Nostr secret key (hex or `nsec1…`). It signs everything this provider
    /// publishes and is the identity a Lease Request is addressed to.
    pub nostr_private_key: String,

    /// The Relay Set: every relay this provider publishes its Profile,
    /// Listings and Liveness to, and the list the Profile itself carries.
    #[serde(default)]
    pub relay_set: Vec<String>,

    /// The provider connector's self-description URL, published in the
    /// Profile. A LOCATION HINT ONLY — `connector_seal_key` is what a tenant
    /// seals to (ADR 0011).
    #[serde(default)]
    pub connector_url: String,

    /// The provider connector's sealing public key, hex. A tenant seals its
    /// spawn to this and refuses if the URL reports another (ADR 0011).
    #[serde(default)]
    pub connector_seal_key: String,

    /// The settlement legs the provider's connector accepts, published in
    /// the Profile so a tenant knows what it can pay with.
    #[serde(default)]
    pub settlement: Vec<Settlement>,

    /// `shared-kernel` | `dedicated-host`. Published in the Profile and as
    /// every Listing's `l isolation:<value>` tag, which is how a relay
    /// filters on it.
    #[serde(default = "default_isolation")]
    pub isolation: String,

    /// How often Liveness is republished, in seconds. Each one expires five
    /// cadences out (ADR 0007), so a provider may lose four publications
    /// before it reads as down.
    #[serde(default = "default_liveness_cadence_s")]
    pub liveness_cadence_s: u64,

    /// Optional region, published as every Listing's `g` tag.
    #[serde(default)]
    pub geohash: Option<String>,

    /// Where `ConnectorDirectory` hands an event to be PAID FOR and written
    /// to the Relay Set — the directory publisher that speaks TOON on this
    /// provider's behalf (`tools/publisher`). Unset means this provider
    /// publishes nothing, which is legal: a provider serving only tenants
    /// who already know its address needs no directory.
    #[serde(default)]
    pub publish_url: Option<String>,

    /// Capabilities this provider is willing to grant — privileges beyond an
    /// ordinary workload, e.g. `docker`, `nesting`.
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// What this provider sells. Empty is legal: a provider with no listings
    /// serves only the free routes.
    #[serde(default)]
    pub listings: Vec<Listing>,

    /// Where the HTTP app listens. The provider's TOON connector is the only
    /// thing that should be able to reach it.
    #[serde(default = "default_http_bind_addr")]
    pub http_bind_addr: String,

    /// Where the CONNECTOR reaches this app — the origin of every
    /// `handler_url` that `toon-provider routes` prints. Distinct from
    /// `http_bind_addr` because inside compose the connector dials the app
    /// by service name, not by the address the app bound.
    #[serde(default = "default_handler_base_url")]
    pub handler_base_url: String,

    /// Inclusive range of backend workload ids this provider may use.
    #[serde(default = "default_id_range_start")]
    pub workload_id_range_start: u32,
    #[serde(default = "default_id_range_end")]
    pub workload_id_range_end: u32,

    /// First host port handed out for a workload's SSH forward. Unset derives
    /// one from the workload id.
    #[serde(default)]
    pub ssh_port_start: Option<u16>,

    /// First host port of the block a workload's published ports come from:
    /// workload id `i` (counted from `workload_id_range_start`) owns
    /// `[start + i * MAX_PORTS_PER_WORKLOAD, +MAX_PORTS_PER_WORKLOAD)`.
    #[serde(default = "default_workload_port_start")]
    pub workload_port_start: u16,

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

    /// Host port for the `index`-th published port of workload `id`. Derived
    /// like `ssh_host_port`, and `None` when the block would leave the port
    /// range (`validate` refuses a config where that can happen for an id in
    /// range, so a `None` here is an id outside the range).
    pub fn workload_host_port(&self, id: u32, index: u16) -> Option<u16> {
        if index >= MAX_PORTS_PER_WORKLOAD {
            return None;
        }
        let offset = id.checked_sub(self.workload_id_range_start)?;
        let block = offset.checked_mul(u32::from(MAX_PORTS_PER_WORKLOAD))?;
        let port = u32::from(self.workload_port_start)
            .checked_add(block)?
            .checked_add(u32::from(index))?;
        u16::try_from(port).ok()
    }

    /// The listing sold on `<addr>.<name>.v<version>.*`, if this provider has
    /// one.
    pub fn listing(&self, name: &str, version: u32) -> Option<&Listing> {
        self.listings
            .iter()
            .find(|l| l.name == name && l.version == version)
    }

    /// How many leases of the named tier may run at once, across versions.
    /// Every version of a listing declares the same capacity; the first one
    /// found is authoritative and `validate` enforces the agreement.
    pub fn capacity_of(&self, name: &str) -> u32 {
        self.listings
            .iter()
            .find(|l| l.name == name)
            .map(|l| l.capacity)
            .unwrap_or(0)
    }

    /// Refuse a config that would misbehave at runtime rather than at load:
    /// listing names that are not ILP segments, duplicate versions, versions
    /// below 1, a zero interval, and a port block that overflows `u16`.
    pub fn validate(&self) -> Result<()> {
        if self.ilp_address.is_empty()
            || !self
                .ilp_address
                .split('.')
                .all(|seg| !seg.is_empty() && seg.chars().all(is_ilp_segment_char))
        {
            bail!("ilp_address {:?} is not an ILP address", self.ilp_address);
        }
        if !matches!(self.isolation.as_str(), "shared-kernel" | "dedicated-host") {
            bail!(
                "isolation {:?} is neither shared-kernel nor dedicated-host",
                self.isolation
            );
        }
        if self.liveness_cadence_s == 0 {
            bail!("liveness_cadence_s must be positive: it is a publishing interval");
        }
        // Empty means "not published yet"; anything else is pinned by a
        // tenant and sealed to (ADR 0011), so a typo must fail at load rather
        // than as an unopenable seal. The length is NOT fixed here: a
        // connector's self-description reports an uncompressed secp256k1 key
        // (65 bytes, `0x`-prefixed) and this value is copied from it verbatim,
        // so that a tenant's comparison is byte-for-byte.
        if !self.connector_seal_key.is_empty() {
            let digits = self
                .connector_seal_key
                .strip_prefix("0x")
                .unwrap_or(&self.connector_seal_key);
            if digits.len() < 64
                || !digits.len().is_multiple_of(2)
                || !digits.chars().all(|c| c.is_ascii_hexdigit())
            {
                bail!(
                    "connector_seal_key {:?} is not a public key in hex (at least 32 bytes, \
                     optionally 0x-prefixed) — copy it from the connector's /ilp identity",
                    self.connector_seal_key
                );
            }
        }
        for listing in &self.listings {
            if listing.name.is_empty() || !listing.name.chars().all(is_ilp_segment_char) {
                bail!(
                    "listing name {:?} is not an ILP address segment ([A-Za-z0-9_~-]+)",
                    listing.name
                );
            }
            if listing.version == 0 {
                bail!("listing {:?}: versions start at 1", listing.name);
            }
            if listing.lease_interval_s == 0 {
                bail!(
                    "listing {:?}: lease_interval_s must be positive",
                    listing.name
                );
            }
            if listing.capacity != self.capacity_of(&listing.name) {
                bail!(
                    "listing {:?}: every version of a listing must declare the same capacity",
                    listing.name
                );
            }
            let same = self
                .listings
                .iter()
                .filter(|l| l.name == listing.name && l.version == listing.version)
                .count();
            if same > 1 {
                bail!(
                    "listing {:?} v{} is declared more than once",
                    listing.name,
                    listing.version
                );
            }
        }
        if self.workload_id_range_end < self.workload_id_range_start {
            bail!("workload_id_range_end is below workload_id_range_start");
        }
        let Some(last_port) =
            self.workload_host_port(self.workload_id_range_end, MAX_PORTS_PER_WORKLOAD - 1)
        else {
            bail!(
                "workload_port_start {} leaves no room for {} ports per workload id up to {}",
                self.workload_port_start,
                MAX_PORTS_PER_WORKLOAD,
                self.workload_id_range_end
            );
        };
        // The SSH forwards and the port blocks are two ranges on one host;
        // a forward inside a block would hand two workloads the same port.
        let ssh = (
            self.ssh_host_port(self.workload_id_range_start),
            self.ssh_host_port(self.workload_id_range_end),
        );
        let blocks = (self.workload_port_start, last_port);
        if ssh.0 <= blocks.1 && blocks.0 <= ssh.1 {
            bail!(
                "SSH forwards {}..={} overlap the workload port blocks {}..={}",
                ssh.0,
                ssh.1,
                blocks.0,
                blocks.1
            );
        }
        Ok(())
    }
}

fn is_ilp_segment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '~' | '-')
}

fn default_isolation() -> String {
    "shared-kernel".to_string()
}

fn default_liveness_cadence_s() -> u64 {
    60
}

fn default_ilp_address() -> String {
    "g.toon.provider".to_string()
}

fn default_http_bind_addr() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_handler_base_url() -> String {
    "http://127.0.0.1:8080".to_string()
}

fn default_id_range_start() -> u32 {
    1000
}

fn default_id_range_end() -> u32 {
    1999
}

fn default_workload_port_start() -> u16 {
    41000
}

fn default_lease_state_path() -> String {
    "./toon-provider-leases.json".to_string()
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            backend: BackendKind::Docker,
            provider_name: "TOON Provider".to_string(),
            ilp_address: default_ilp_address(),
            public_ip: "127.0.0.1".to_string(),
            nostr_private_key: String::new(),
            relay_set: Vec::new(),
            connector_url: String::new(),
            connector_seal_key: String::new(),
            settlement: Vec::new(),
            isolation: default_isolation(),
            liveness_cadence_s: default_liveness_cadence_s(),
            geohash: None,
            publish_url: None,
            capabilities: Vec::new(),
            listings: Vec::new(),
            http_bind_addr: default_http_bind_addr(),
            handler_base_url: default_handler_base_url(),
            workload_id_range_start: default_id_range_start(),
            workload_id_range_end: default_id_range_end(),
            ssh_port_start: None,
            workload_port_start: default_workload_port_start(),
            lease_state_path: default_lease_state_path(),
        }
    }
}

pub fn load_config(path: &str) -> Result<ProviderConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read provider config at {}", path))?;
    let config: ProviderConfig =
        toml::from_str(&content).with_context(|| format!("parse provider config at {}", path))?;
    config
        .validate()
        .with_context(|| format!("invalid provider config at {}", path))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(name: &str, version: u32) -> Listing {
        Listing {
            name: name.to_string(),
            version,
            resources: Resources {
                cpu_millicores: 500,
                memory_mb: 256,
                storage_gb: 1,
                gpu: None,
            },
            arch: "amd64".to_string(),
            lease_interval_s: 3600,
            price: 1000,
            capabilities: vec![],
            capacity: 2,
        }
    }

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
        assert!(cfg.listings.is_empty());
    }

    #[test]
    fn listings_are_read_from_toml_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.toml");
        std::fs::write(
            &path,
            r#"
provider_name = "Test Provider"
ilp_address = "g.acme"
public_ip = "203.0.113.7"
nostr_private_key = "nsec1example"

[[listings]]
name = "basic"
version = 1
arch = "amd64"
lease_interval_s = 3600
price = 1000
capabilities = ["docker"]
capacity = 4
[listings.resources]
cpu_millicores = 500
memory_mb = 256
storage_gb = 1
"#,
        )
        .unwrap();

        let cfg = load_config(path.to_str().unwrap()).unwrap();
        let basic = cfg.listing("basic", 1).expect("basic v1 exists");
        assert_eq!(basic.price, 1000);
        assert_eq!(basic.resources.cpu_millicores, 500);
        assert_eq!(basic.capabilities, vec!["docker".to_string()]);
        assert_eq!(cfg.capacity_of("basic"), 4);
        assert!(cfg.listing("basic", 2).is_none());
    }

    #[test]
    fn config_round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.toml");
        let cfg = ProviderConfig {
            provider_name: "Round Trip".to_string(),
            relay_set: vec!["wss://relay.toon.example".to_string()],
            capabilities: vec!["docker".to_string()],
            listings: vec![listing("basic", 1)],
            ssh_port_start: Some(40000),
            ..ProviderConfig::default()
        };

        std::fs::write(&path, toml::to_string_pretty(&cfg).unwrap()).unwrap();
        let back = load_config(path.to_str().unwrap()).unwrap();

        assert_eq!(back.provider_name, "Round Trip");
        assert_eq!(back.relay_set, vec!["wss://relay.toon.example".to_string()]);
        assert_eq!(back.capabilities, vec!["docker".to_string()]);
        assert_eq!(back.listings, vec![listing("basic", 1)]);
        assert_eq!(back.ssh_port_start, Some(40000));
    }

    #[test]
    fn a_duplicate_listing_version_is_refused_at_load() {
        let cfg = ProviderConfig {
            listings: vec![listing("basic", 1), listing("basic", 1)],
            ..ProviderConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_listing_name_that_is_not_an_ilp_segment_is_refused() {
        // A dot would split the route prefix into two segments.
        let cfg = ProviderConfig {
            listings: vec![listing("basic.tier", 1)],
            ..ProviderConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn versions_of_one_listing_must_agree_on_capacity() {
        let mut v2 = listing("basic", 2);
        v2.capacity = 9;
        let cfg = ProviderConfig {
            listings: vec![listing("basic", 1), v2],
            ..ProviderConfig::default()
        };
        assert!(cfg.validate().is_err());
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

    #[test]
    fn each_workload_id_owns_its_own_port_block() {
        let cfg = ProviderConfig {
            workload_id_range_start: 1000,
            workload_port_start: 41000,
            ..ProviderConfig::default()
        };
        assert_eq!(cfg.workload_host_port(1000, 0), Some(41000));
        assert_eq!(cfg.workload_host_port(1000, 15), Some(41015));
        assert_eq!(cfg.workload_host_port(1001, 0), Some(41016));
        assert_eq!(cfg.workload_host_port(1000, 16), None, "past the block");
        assert_eq!(cfg.workload_host_port(999, 0), None, "below the range");
    }

    #[test]
    fn the_shipped_example_config_loads() {
        // README says "copy provider.example.toml and edit it", so the copy
        // must at least pass validation before any editing.
        let cfg = load_config(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/provider.example.toml"
        ))
        .expect("provider.example.toml loads");
        assert_eq!(cfg.listings.len(), 1);
    }

    #[test]
    fn ssh_forwards_may_not_overlap_the_port_blocks() {
        let cfg = ProviderConfig {
            workload_id_range_start: 1000,
            workload_id_range_end: 1099,
            ssh_port_start: Some(41000), // inside the blocks 41000..=42599
            workload_port_start: 41000,
            ..ProviderConfig::default()
        };
        assert!(cfg.validate().is_err());
        let apart = ProviderConfig {
            ssh_port_start: Some(40000),
            ..cfg
        };
        assert!(apart.validate().is_ok());
    }

    #[test]
    fn a_port_block_that_overflows_u16_is_refused_at_load() {
        let cfg = ProviderConfig {
            workload_id_range_start: 1000,
            workload_id_range_end: 1999,
            workload_port_start: 60000, // 60000 + 1000 * 16 > 65535
            ..ProviderConfig::default()
        };
        assert!(cfg.validate().is_err());
        assert!(ProviderConfig::default().validate().is_ok());
    }
}
