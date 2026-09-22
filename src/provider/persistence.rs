// The lease table, mirrored to disk.
//
// A running lease must survive a provider restart: the backend knows a
// workload exists but not whose lease it is or when that lease expires, so
// losing this file strands a paid workload or forgets who it belongs to.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{error, warn};

// `LeaseEnd` and `LeaseState` live in `nostr::wire`: `status` answers them,
// so their JSON is a wire shape, and this table is the same JSON on disk.
pub use crate::nostr::wire::{LeaseEnd, LeaseState};

use super::settle::TakeoverSettlement;
use super::standby::StandbySet;
use super::watchdog::TakeoverAnnouncement;
use crate::hidden_service::HiddenAddress;
use crate::nostr::continuation::ContinuationToken;
use crate::nostr::wire::{Access, PortAccess, Role, SpawnContent};

/// How many live (`Provisioning`, `Reserved` or `Running`) leases of
/// `listing` are on the table right now. Shared by `availability`'s capacity
/// check, spawn's and the Liveness `available` count, so a change to what
/// counts as "live" cannot desync them (they must agree: spec §9,
/// "availability... applies the same policy").
///
/// A RESERVATION counts: a Warm Standby holds its slot with nothing running,
/// and the whole of what its tenant bought is that nobody else is sold it
/// (spec §6.7).
pub fn count_live(leases: &HashMap<u32, LeaseRecord>, listing: &str) -> usize {
    leases
        .values()
        .filter(|l| l.state.is_live() && l.listing == listing)
        .count()
}

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

    /// The tenant-chosen workload id from the spawn (32 bytes, hex).
    pub workload_id: String,

    /// The lease's Continuation Token: the secret its spawn presented, and
    /// the only thing this provider holds about whoever took the lease (spec
    /// §6.1, ADR 0016). A payer need not be the tenant, so it is never
    /// derived from who paid; and it is not an identity, so there is nothing
    /// here to leak or to be compelled for.
    ///
    /// Persisted, because a restart that forgot it would leave a paid
    /// workload running that nobody could read, extend or stop.
    pub continuation: ContinuationToken,

    /// The listing and version this lease was spawned from. An extension
    /// must buy time on the same version (ADR 0009).
    pub listing: String,
    pub listing_version: u32,

    pub role: Role,
    pub state: LeaseState,

    /// The Standby Set this lease was spawned into, and this provider's
    /// position in it (spec §7). Absent for a standalone lease, which is
    /// every lease that named no `standby_set`.
    ///
    /// Persisted with the rest: a Warm Standby that restarts must still know
    /// whose Liveness to watch — `set.primary()` — and among whom a Takeover
    /// is settled, and neither is derivable from anything else the record
    /// holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standby_set: Option<StandbySet>,

    /// The spawn a Takeover would start, kept only while the lease is a
    /// RESERVATION (spec §7.1 step 4).
    ///
    /// A reservation is capacity held for a workload that does not exist
    /// yet, so the spawn that described it is the only thing that says what
    /// to start if the primary goes silent; a lease whose workload is
    /// already running needs nothing of the sort. It is on disk and never on
    /// the wire: `status` answers the lease, not the request that made it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_spawn: Option<SpawnContent>,

    /// The Takeover this Warm Standby announced, once it has (spec §7.1
    /// step 2): absent until then, and always for a lease that is not a
    /// reservation. Persisted so a standby that restarts after announcing
    /// settles the race it entered instead of announcing again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<TakeoverAnnouncement>,

    /// How the last Takeover on this workload settled here (spec §7.1 steps
    /// 3–5), once one has: who won. Persisted because a standby that LOST
    /// watches the winner as its primary from then on, and nothing else on
    /// the record says who that is; a standby that won and restarts before
    /// its workload started still has to start it. `status` answers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled: Option<TakeoverSettlement>,
    /// Set on a PRIMARY whose Standby Set has moved past it: a Takeover for
    /// this lease's `workload_id` was found on the Relay Set, signed by a
    /// member of the set (spec §7.1). Its workload is never started again
    /// for the rest of the lease, whatever the relays say later.
    ///
    /// Persisted, and persisted as a FACT rather than re-derived, because
    /// the guarantee is for the rest of the lease: a relay that has since
    /// dropped the claim, or a provider that restarts and cannot read one,
    /// must not put a second copy of the workload beside the new primary's.
    #[serde(default)]
    pub taken_over: bool,

    pub created_at: u64,

    /// The first instant the lease no longer applies. The expiry sweep reaps
    /// anything at or past it.
    pub expires_at: u64,

    /// When the lease ended, for a lease that has. An ended record is kept
    /// so `status` can still say HOW it ended, and pruned once
    /// `ended_retention_s` has passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<u64>,

    /// Whether the backend has confirmed the workload is gone. An ended
    /// lease whose workload outlived it is retried by every sweep until this
    /// is true, so a failed delete never strands a running container.
    #[serde(default)]
    pub destroyed: bool,

    /// The Template the tenant expanded to make this spawn, if it named one
    /// (spec §6.2). INFORMATIONAL: the provider never read it and never will
    /// (ADR 0004) — it is kept so `status` can say where the values came
    /// from, which is the whole of what a `template` is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,

    /// The SSH forward and the published ports, as handed to the tenant.
    pub ssh_port: u16,
    #[serde(default)]
    pub ports: Vec<PortAccess>,

    /// The lease's OWN `.anyone` address, on a Hidden Provider: the host a
    /// tenant dials in place of an IP, and the key that host is derived from
    /// (spec §10, ADR 0008). `None` on every lease of a provider that is not
    /// hidden, and on a Warm Standby's reservation until a Takeover starts
    /// its workload — there is nowhere to reach until then.
    ///
    /// Persisted because an address made over the daemon's control port
    /// lives only as long as the daemon: a provider restarted on this file
    /// hands the KEY back (`HiddenService::restore_address`) so every live
    /// lease is reachable where its tenant last found it, rather than at a
    /// new address the tenant was never told about. Cleared when the daemon
    /// confirms the address destroyed, which is part of a lease's ending
    /// (`cleanup::destroy_workload`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_address: Option<HiddenAddress>,
}

impl LeaseRecord {
    /// The access details a tenant reaches this workload at.
    pub fn access(&self, host: &str) -> Access {
        Access {
            host: host.to_string(),
            ssh_port: self.ssh_port,
            ports: self.ports.clone(),
        }
    }

    /// The host this lease is reached at: its own `.anyone` address when it
    /// has one, and otherwise the provider's `public_ip`.
    ///
    /// The two are exclusive by construction — a Hidden Provider has no
    /// `public_ip` (`ProviderConfig::access_host` is `None` there) and a
    /// provider that is not hidden gives no lease an address — so this is
    /// the whole of what `access.host` may say on either kind of provider
    /// (spec §6.2, §10). `None` only while a lease has neither: a hidden
    /// lease whose address is gone, which is a lease with nowhere to reach.
    pub fn access_host<'a>(&'a self, config: &'a super::ProviderConfig) -> Option<&'a str> {
        match &self.hidden_address {
            Some(address) => Some(address.host.as_str()),
            None => config.access_host(),
        }
    }
}

/// Mirror the lease table to disk. Returns whether it reached disk.
///
/// Written to a sibling temp file and renamed, because a truncated state file
/// is worse than a stale one: the loader would treat every lease past the
/// truncation point as never having existed. `rename` is atomic on POSIX.
///
/// Every failure is logged here, at the one place that sees it. Most callers
/// still don't propagate it — refusing a paid-for spawn over an unwritable
/// bookkeeping file would be worse than a stale mirror, so a spawn, extend,
/// termination and the rest go on answering their tenant and simply ignore
/// the return value. `rotate` is the one caller that cannot: a rotation is a
/// revocation, so it may confirm one only once the new token is on disk
/// (spec §6.8, ADR 0018, TOON_Network#78), and it checks this to know.
pub(crate) fn persist_leases(leases: &HashMap<u32, LeaseRecord>, path: &str) -> bool {
    let tmp = format!("{}.tmp", path);
    let encoded = match serde_json::to_vec_pretty(leases) {
        Ok(v) => v,
        Err(e) => {
            error!("failed to encode lease table: {}", e);
            return false;
        }
    };
    if let Err(e) = std::fs::write(&tmp, &encoded) {
        error!("failed to write lease table to {}: {}", tmp, e);
        return false;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        error!("failed to install lease table at {}: {}", path, e);
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    true
}

/// The persisted lease table, read from outside a running provider.
///
/// `toon-provider routes` needs it: which listing versions still have a live
/// lease is what decides which retired versions keep their connector routes
/// (ADR 0009), and the operator runs that command against a provider it is
/// about to restart, not through it. Strictly read-only, and an absent or
/// unreadable file is an empty table — the same degradation the provider's
/// own loader makes.
pub fn persisted_leases(path: &str) -> Vec<LeaseRecord> {
    load_leases(path).into_values().collect()
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
            workload_id: format!("wid-{}", id),
            continuation: ContinuationToken::from_hex(&"ee".repeat(32)).unwrap(),
            listing: "basic".to_string(),
            listing_version: 1,
            role: Role::Standalone,
            state: LeaseState::Running,
            standby_set: None,
            reserved_spawn: None,
            takeover: None,
            settled: None,
            taken_over: false,
            created_at: 1000,
            expires_at,
            ended_at: None,
            destroyed: false,
            template: None,
            ssh_port: 40000 + id as u16,
            ports: vec![PortAccess {
                container_port: 443,
                host_port: 41000,
            }],
            hidden_address: None,
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
        // expires_at drives the expiry sweep, the continuation token says
        // who may act on the lease, and the access details are what status
        // answers; losing any would strand or misassign a paid workload.
        assert_eq!(loaded[&2000], map[&2000]);
        assert_eq!(loaded[&2001].expires_at, 1234567999);
        assert_eq!(loaded[&2000].state, LeaseState::Running);

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_reservation_keeps_the_set_it_watches_across_a_restart() {
        // What a Warm Standby cannot re-derive after a restart: whose
        // Liveness it watches, and which position it holds.
        let p = temp_path("reservation");
        let mut reserved = lease(2000, 9999);
        reserved.role = Role::Standby;
        reserved.state = LeaseState::Reserved;
        reserved.standby_set = Some(StandbySet {
            members: vec!["aa".repeat(32), "bb".repeat(32)],
            index: 1,
        });
        persist_leases(&HashMap::from([(2000, reserved.clone())]), &p);

        let loaded = load_leases(&p);
        assert_eq!(loaded[&2000], reserved);
        let set = loaded[&2000].standby_set.as_ref().unwrap();
        assert_eq!(set.primary(), Some("aa".repeat(32).as_str()));
        assert!(!set.is_primary());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_table_written_before_standby_sets_still_loads() {
        // The two Warm Standby fields arrived after the first leases were
        // written. A provider restarting over a table from before them must
        // not lose every lease in it: one unreadable record empties the
        // WHOLE table (`load_leases`), which would strand every paid
        // workload on the host.
        let p = temp_path("pre-standby");
        std::fs::write(
            &p,
            serde_json::json!({ "2000": {
                "id": 2000,
                "workload_id": "aa".repeat(32),
                "continuation": "ee".repeat(32),
                "listing": "basic",
                "listing_version": 1,
                "role": "standalone",
                "state": "running",
                "created_at": 1000,
                "expires_at": 4600,
                "destroyed": false,
                "ssh_port": 40000,
                "ports": [],
            }})
            .to_string(),
        )
        .unwrap();

        let loaded = load_leases(&p);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[&2000].expires_at, 4600);
        assert_eq!(loaded[&2000].role, Role::Standalone);
        assert_eq!(loaded[&2000].standby_set, None);
        assert_eq!(loaded[&2000].reserved_spawn, None);
        assert_eq!(loaded[&2000].takeover, None);
        assert_eq!(loaded[&2000].settled, None);
        assert!(!loaded[&2000].taken_over);
        assert_eq!(loaded[&2000].hidden_address, None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_settled_takeover_survives_a_restart() {
        // A standby that lost watches the winner from then on (spec §7.1
        // step 5), and only this field says who that is: the set on the
        // record still lists the original primary at index 0.
        let p = temp_path("settled");
        let mut lost = lease(2000, 9999);
        lost.role = Role::Standby;
        lost.state = LeaseState::Reserved;
        lost.settled = Some(TakeoverSettlement {
            winner: "cc".repeat(32),
        });
        persist_leases(&HashMap::from([(2000, lost.clone())]), &p);

        assert_eq!(load_leases(&p)[&2000], lost);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_self_stopped_primary_survives_a_restart() {
        // What a primary that stopped its own workload cannot re-derive
        // after a restart (spec §7.1): that the workload is off, and that a
        // member of its Standby Set has claimed the workload id — which is
        // why it must never be started again for this lease, whatever the
        // relays hold by then.
        let p = temp_path("self-stopped");
        let mut stopped = lease(2000, 9999);
        stopped.role = Role::Primary;
        stopped.state = LeaseState::Stopped;
        stopped.standby_set = Some(StandbySet {
            members: vec!["aa".repeat(32), "bb".repeat(32)],
            index: 0,
        });
        stopped.taken_over = true;
        persist_leases(&HashMap::from([(2000, stopped.clone())]), &p);

        let loaded = load_leases(&p);
        assert_eq!(loaded[&2000], stopped);
        assert_eq!(loaded[&2000].state, LeaseState::Stopped);
        // Still a lease: it holds its slot and its workload, and only the
        // ending destroys the container the stop left behind.
        assert!(loaded[&2000].state.is_live());
        assert!(loaded[&2000].state.has_workload());
        assert!(!loaded[&2000].state.is_reachable());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn an_announced_takeover_survives_a_restart() {
        // A standby that announced and then restarted must settle the race
        // it entered (spec §7.1 step 3), not announce a second time: when
        // it claimed, in what cadence, and where the other claims are.
        let p = temp_path("announced");
        let mut announced = lease(2000, 9999);
        announced.role = Role::Standby;
        announced.state = LeaseState::Reserved;
        announced.takeover = Some(TakeoverAnnouncement {
            announced_at: 5000,
            cadence_s: 60,
            relays: vec!["ws://relay-one:7100".to_string()],
        });
        persist_leases(&HashMap::from([(2000, announced.clone())]), &p);

        assert_eq!(load_leases(&p)[&2000], announced);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_hidden_leases_address_and_key_survive_a_restart() {
        // What a Hidden Provider cannot re-derive after a restart: the
        // `.anyone` host its tenant was handed, and the key that host comes
        // from. Without the key the daemon would answer a DIFFERENT address
        // and the tenant would be left dialling one nothing answers on
        // (spec §10).
        let p = temp_path("hidden-address");
        let mut hidden = lease(2000, 9999);
        hidden.hidden_address = Some(HiddenAddress {
            host: "k".repeat(56) + ".anyone",
            key: Some("ED25519-V3:fake-aaaaaaaaaaaaaaaa".to_string()),
        });
        persist_leases(&HashMap::from([(2000, hidden.clone())]), &p);

        let loaded = load_leases(&p);
        assert_eq!(loaded[&2000], hidden);
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
        assert!(persist_leases(&map, &p), "a writable path succeeds");
        assert!(!std::path::Path::new(&format!("{}.tmp", p)).exists());
        assert!(std::path::Path::new(&p).exists());
        let _ = std::fs::remove_file(&p);
    }

    /// The seam `rotate` depends on (TOON_Network#78): a write that cannot
    /// reach disk reports failure rather than only logging it, so a caller
    /// that must not confirm a change it could not save can find out. A
    /// directory with no write permission is the failure a full disk or a
    /// yanked mount both look like from here.
    #[test]
    fn a_write_into_an_unwritable_directory_reports_failure() {
        use std::os::unix::fs::PermissionsExt;

        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "toon-provider-lease-state-unwritable-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().into_owned();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let p = format!("{}/leases.json", dir);
        let map = HashMap::from([(2000, lease(2000, 42))]);
        let ok = persist_leases(&map, &p);

        // Restored before asserting, so a failed assertion still leaves a
        // directory the test runner can clean up.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !ok,
            "a write into a read-only directory must report failure, not just log it"
        );
        assert!(!std::path::Path::new(&p).exists(), "nothing was installed");
        let _ = std::fs::remove_dir_all(&dir);
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
