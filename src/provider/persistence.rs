// The lease table, mirrored to disk.
//
// A running lease must survive a provider restart: the backend knows a
// workload exists but not whose lease it is or when that lease expires, so
// losing this file strands a paid workload or forgets who it belongs to.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{error, warn};

/// One lease: a tenant's prepaid right to one workload on this provider, until
/// it expires.
///
/// What bought the time is deliberately absent. Paygress stored the Cashu
/// amount and a per-second rate and divided; under TOON one payment buys one
/// Lease Interval, and the interval comes from the listing, so only the
/// resulting `expires_at` is worth keeping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    /// Backend workload id. Keys the lease table and names the workload on
    /// the host.
    pub id: u32,

    /// The tenant-chosen workload id from the spawn, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,

    /// The Nostr identity this lease belongs to. A payer need not be the
    /// tenant, so this is never derived from who paid.
    pub tenant_npub: String,

    /// The listing version this lease was spawned from. An extension must buy
    /// time on the same one.
    #[serde(default)]
    pub listing: String,

    pub created_at: u64,

    /// The first instant the lease no longer applies. The expiry sweep reaps
    /// anything at or past it.
    pub expires_at: u64,
}

/// Mirror the lease table to disk.
///
/// Written to a sibling temp file and renamed, because a truncated state file
/// is worse than a stale one: the loader would treat every lease past the
/// truncation point as never having existed. `rename` is atomic on POSIX.
///
/// Failures are logged, never propagated — refusing a paid-for spawn over an
/// unwritable bookkeeping file would be worse than a stale mirror.
pub(crate) fn persist_leases(leases: &HashMap<u32, LeaseRecord>, path: &str) {
    let tmp = format!("{}.tmp", path);
    let encoded = match serde_json::to_vec_pretty(leases) {
        Ok(v) => v,
        Err(e) => {
            error!("failed to encode lease table: {}", e);
            return;
        }
    };
    if let Err(e) = std::fs::write(&tmp, &encoded) {
        error!("failed to write lease table to {}: {}", tmp, e);
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        error!("failed to install lease table at {}: {}", path, e);
        let _ = std::fs::remove_file(&tmp);
    }
}

/// A missing file is the normal first-run case; a corrupt one degrades to
/// empty, because a provider that refuses to boot over unreadable bookkeeping
/// is worse than one that boots having forgotten some leases.
pub(crate) fn load_leases(path: &str) -> HashMap<u32, LeaseRecord> {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(e) => {
            warn!("failed to read lease table from {}: {}", path, e);
            return HashMap::new();
        }
    };
    match serde_json::from_slice(&raw) {
        Ok(w) => w,
        Err(e) => {
            error!(
                "lease table at {} is unreadable ({}); starting with an empty table. \
                 Workloads it referenced will need manual cleanup.",
                path, e
            );
            HashMap::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "toon-provider-lease-state-{}-{}.json",
            std::process::id(),
            name
        ));
        p.to_string_lossy().into_owned()
    }

    fn lease(id: u32, expires_at: u64) -> LeaseRecord {
        LeaseRecord {
            id,
            workload_id: Some(format!("wid-{}", id)),
            tenant_npub: "npub1tenant".to_string(),
            listing: "basic.v1".to_string(),
            created_at: 1000,
            expires_at,
        }
    }

    #[test]
    fn missing_state_file_loads_empty() {
        let p = temp_path("absent");
        let _ = std::fs::remove_file(&p);
        assert!(load_leases(&p).is_empty());
    }

    #[test]
    fn round_trips_the_fields_the_lease_lifecycle_depends_on() {
        let p = temp_path("roundtrip");
        let mut map = HashMap::new();
        map.insert(2000, lease(2000, 1234567890));
        map.insert(2001, lease(2001, 1234567999));
        persist_leases(&map, &p);

        let loaded = load_leases(&p);
        assert_eq!(loaded.len(), 2);
        // expires_at drives the expiry sweep and tenant_npub says whose lease
        // it is; losing either would strand or misassign a paid workload.
        assert_eq!(loaded[&2000].expires_at, 1234567890);
        assert_eq!(loaded[&2001].expires_at, 1234567999);
        assert_eq!(loaded[&2000].tenant_npub, "npub1tenant");
        assert_eq!(loaded[&2000].workload_id.as_deref(), Some("wid-2000"));
        assert_eq!(loaded[&2000].listing, "basic.v1");

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn corrupt_state_degrades_to_empty_rather_than_failing() {
        let p = temp_path("corrupt");
        std::fs::write(&p, b"{ this is not json").unwrap();
        assert!(load_leases(&p).is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn write_leaves_no_temp_file_behind() {
        let p = temp_path("tmpfile");
        let map = HashMap::from([(2000, lease(2000, 42))]);
        persist_leases(&map, &p);
        assert!(!std::path::Path::new(&format!("{}.tmp", p)).exists());
        assert!(std::path::Path::new(&p).exists());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rewrite_replaces_rather_than_merges() {
        // The expiry sweep removes entries by rewriting the whole table; if a
        // rewrite merged, ended leases would resurrect on restart.
        let p = temp_path("replace");
        persist_leases(&HashMap::from([(2000, lease(2000, 1))]), &p);
        persist_leases(&HashMap::from([(2001, lease(2001, 2))]), &p);

        let loaded = load_leases(&p);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&2001));
        let _ = std::fs::remove_file(&p);
    }
}
