// The HiddenService port: the third of the provider's I/O ports (after
// `ComputeBackend` and `Directory`), and the one only a Hidden Provider has.
//
// Spec §10 and ADR 0008 make a Hidden Provider a set of conditions, and two
// of them are things the provider must DO per lease rather than declare
// once: give every lease's SSH and ports an `.anyone` address of their own,
// and route every workload's egress through `anon`. Both are the `anon`
// daemon's business, and driving it — its control port, its keys, its
// egress — is exactly the kind of I/O the lease lifecycle should not know
// about. So it is a port: the lifecycle asks for an address and hands the
// backend an egress policy; the real implementation (M4-3, TOON_Network #40)
// speaks the daemon's control protocol, and a fake answers deterministic
// addresses so the whole hidden lifecycle is tested in-process.
//
// The connector's ADR 0070 keeps the anon control protocol out of the
// connector, which is why driving the daemon is the provider's job and not
// something the connector does on its behalf.
//
// Nothing calls this port in Milestone 4's first ticket (#38): it exists so
// the later tickets — per-lease addresses at spawn and their teardown on
// every ending (#39), the real adapter (#40), the Docker egress (#41) — can
// proceed against one signature. A provider that is not hidden has no
// `HiddenService` at all (`AppState::hidden_service` is `None`), and never
// touches one.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::compute::EgressPolicy;

/// The suffix of every hidden-service host the Anyone network resolves.
/// `.anyone`, never `.onion`: the daemon this provider drives (v0.4.10.2)
/// writes and refuses the latter by name, and so does every TOON client.
pub const ANYONE_SUFFIX: &str = ".anyone";

/// True when `host` is a hidden-service name: something ending in
/// `.anyone` with a label in front of it. Only the shape; nothing here can
/// say whether the network knows the address.
pub fn is_anyone_host(host: &str) -> bool {
    host.strip_suffix(ANYONE_SUFFIX)
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

/// One port of a per-lease address: the port a tenant dials on the
/// `.anyone` host, and the host port on this provider it reaches.
///
/// The two are the SAME number for every port a lease publishes — a tenant
/// reads `ssh_port` and `ports[].host_port` out of its access details and
/// dials them on the address exactly as it would on an IP (spec §6.2, §10),
/// so the address must answer on the same ports the host does. They are
/// still two fields, because the daemon's mapping is virtual port → target,
/// and a backend whose forwards are not on this host would map them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressPort {
    /// The port a tenant dials on the `.anyone` host.
    pub virtual_port: u16,
    /// The host port on this provider it is forwarded to: the lease's SSH
    /// forward or one of its published ports.
    pub host_port: u16,
}

impl AddressPort {
    /// The mapping every lease port gets: the same number on both sides.
    pub fn same(port: u16) -> Self {
        Self {
            virtual_port: port,
            host_port: port,
        }
    }
}

/// What a Hidden Provider asks of its `anon` daemon, per lease.
///
/// Keyed by the tenant-chosen workload id (the 64-hex id every Lease
/// Request names, spec §6.1) rather than the backend's numeric id: the
/// address belongs to the LEASE the tenant bought, which is what a Takeover
/// carries to another provider and what a restart re-establishes (M4-2),
/// and the backend id is a detail of one host's daemon.
#[async_trait]
pub trait HiddenService: Send + Sync {
    /// Create one `.anyone` address for `workload_id` that forwards each of
    /// `ports` to this host, and answer the host (`<56 base32 chars>.anyone`,
    /// no scheme, no port) — what a spawn's `access.host` then carries in
    /// place of an IP (spec §10). The address exists until
    /// `destroy_address`. An error is a spawn that must not run a
    /// workload: an address the daemon could not create is a lease the
    /// tenant could never reach.
    async fn create_address(&self, workload_id: &str, ports: &[AddressPort]) -> Result<String>;

    /// Destroy the address `create_address` gave `workload_id`. Idempotent:
    /// destroying an address that does not exist is not an error, so that a
    /// lease ending can be retried until it succeeds (spec §6.7).
    async fn destroy_address(&self, workload_id: &str) -> Result<()>;

    /// The egress policy the backend attaches `workload_id`'s workload with
    /// (spec §10: all workload egress leaves through `anon`). Per workload,
    /// so an implementation may give leases networks of their own; the
    /// configured `[anon.egress]` is what every one answers today.
    fn egress_for(&self, workload_id: &str) -> EgressPolicy;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_anyone_host_is_one_label_before_the_suffix() {
        assert!(is_anyone_host(&format!("{}.anyone", "a".repeat(56))));
        assert!(is_anyone_host("short.anyone"));
        assert!(!is_anyone_host(".anyone"), "no label");
        assert!(!is_anyone_host("c.acme.example"));
        assert!(!is_anyone_host("abc.onion"), "Tor's suffix, not Anyone's");
        assert!(!is_anyone_host("a.b.anyone"), "one label, not a subdomain");
        assert!(!is_anyone_host("anyone"));
    }

    #[test]
    fn the_same_port_maps_to_itself() {
        let port = AddressPort::same(40000);
        assert_eq!(port.virtual_port, 40000);
        assert_eq!(port.host_port, 40000);
    }
}
