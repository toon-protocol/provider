// Warm Standby: a provider holding capacity to take over a lease's workload if
// the provider running it goes silent.
//
// Kept for Milestone 3, unwired. Nothing in the app reads any of this; the
// pieces that survived the Paygress strip are the ones that do not depend on
// its removed DM transport or its promotion event kind. The promotion
// scheduler itself was deleted with those.
#![allow(dead_code)]

use std::collections::HashMap;

use crate::compute::ContainerConfig;

/// Cadence at which the standby watchdog re-checks a primary's liveness.
pub(crate) const STANDBY_WATCHDOG_INTERVAL_SECS: u64 = 30;

/// How long without a sign of the primary before we treat it as gone.
pub(crate) const STANDBY_SILENCE_SECS: u64 = 180;

/// Standby `i` waits `i * DELAY` before taking over. Single-writer is
/// best-effort: a brief two-live window is an accepted trade-off.
pub(crate) const STANDBY_TAKEOVER_DELAY_SECS: u64 = 30;

/// A paid-for, acknowledged warm-standby reservation. No workload exists yet;
/// the standby is armed and waiting for the primary to go silent.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StandbySlot {
    pub workload_id: String,
    pub primary_npub: String,
    pub standby_index: usize,
    pub standby_count: usize,
    pub container_config: ContainerConfig,
    pub listing: String,
    pub expires_at: u64,
    pub tenant_npub: String,
    /// The watchdog's silence baseline before any sign of the primary is
    /// observed; without it a fresh slot would read `last_seen == 0` as silence
    /// and take over from a healthy primary.
    pub created_at: u64,
    /// The other standbys, checked at takeover time to detect that a peer got
    /// there first; without it every standby would take over independently.
    pub peer_standby_npubs: Vec<String>,
}

/// `baseline` is the most recent sign of the primary, or the slot's reservation
/// timestamp when none has been observed. `baseline == 0` means the caller
/// mis-wired the lookup and returns `false`: a missed takeover beats a spurious
/// one against a healthy primary.
pub(crate) fn primary_is_silent(now: u64, baseline: u64, threshold: u64) -> bool {
    if baseline == 0 {
        return false;
    }
    now.saturating_sub(baseline) >= threshold
}

/// Slots whose lease window passed without a takeover. Without reaping them the
/// map grows unbounded on a long-running provider.
pub(crate) fn select_expired(slots: &HashMap<String, StandbySlot>, now: u64) -> Vec<String> {
    slots
        .iter()
        .filter(|(_, slot)| slot.expires_at <= now)
        .map(|(workload_id, _)| workload_id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pure gate a watchdog uses to decide whether to take over. The edge
    // cases are pinned so a refactor can't silently flip the semantics the
    // crash-detection promise rests on.

    #[test]
    fn a_fresh_sign_of_the_primary_is_not_silence() {
        assert!(!primary_is_silent(1_000_000, 999_940, 180));
    }

    #[test]
    fn primary_just_past_threshold_is_silent() {
        assert!(primary_is_silent(1_000_000, 999_820, 180));
        // 179s old — still alive.
        assert!(!primary_is_silent(1_000_000, 999_821, 180));
    }

    #[test]
    fn unset_baseline_is_not_silent() {
        assert!(!primary_is_silent(1_000_000, 0, 180));
        assert!(!primary_is_silent(50, 0, 180));
    }

    #[test]
    fn fresh_slot_within_grace_window_is_not_silent() {
        let created_at = 1_000_000;
        assert!(!primary_is_silent(created_at + 30, created_at, 180));
    }

    #[test]
    fn fresh_slot_past_grace_window_is_silent() {
        let created_at = 1_000_000;
        assert!(primary_is_silent(created_at + 180, created_at, 180));
    }

    #[test]
    fn clock_skew_underflow_does_not_panic_or_misfire() {
        // baseline > now (clock went backwards, or a future-stamped event).
        assert!(!primary_is_silent(100, 200, 180));
    }

    fn make_slot(workload_id: &str, expires_at: u64) -> StandbySlot {
        StandbySlot {
            workload_id: workload_id.to_string(),
            primary_npub: "npub1primary".to_string(),
            standby_index: 0,
            standby_count: 1,
            container_config: ContainerConfig {
                id: 1,
                name: "toon-1".to_string(),
                image: "img".to_string(),
                cpu_millicores: 1000,
                memory_mb: 1024,
                storage_gb: 10,
                ssh_key: None,
                host_port: None,
                ports: vec![],
                env: HashMap::new(),
                entrypoint: None,
                args: vec![],
                data_path: None,
            },
            listing: "basic.v1".to_string(),
            expires_at,
            tenant_npub: "npub1tenant".to_string(),
            created_at: 0,
            peer_standby_npubs: vec![],
        }
    }

    #[test]
    fn select_expired_returns_only_past_expiry_slots() {
        let mut slots = HashMap::new();
        slots.insert("active".to_string(), make_slot("active", 2_000));
        slots.insert("expired".to_string(), make_slot("expired", 999));
        let mut expired = select_expired(&slots, 1_000);
        expired.sort();
        assert_eq!(expired, vec!["expired".to_string()]);
    }

    #[test]
    fn select_expired_treats_expires_at_equals_now_as_expired() {
        // expires_at is the FIRST instant the lease no longer applies, so a
        // slot ending exactly now is reaped on this tick.
        let mut slots = HashMap::new();
        slots.insert("boundary".to_string(), make_slot("boundary", 1_000));
        assert_eq!(select_expired(&slots, 1_000), vec!["boundary".to_string()]);
    }

    #[test]
    fn select_expired_returns_empty_when_no_slots_expired() {
        let mut slots = HashMap::new();
        slots.insert("a".to_string(), make_slot("a", 9_999));
        slots.insert("b".to_string(), make_slot("b", 9_999));
        assert!(select_expired(&slots, 1_000).is_empty());
    }

    #[test]
    fn a_slot_round_trips_through_serde() {
        let slot = make_slot("w-1", 999);
        let json = serde_json::to_string(&slot).unwrap();
        let back: StandbySlot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, slot);
    }
}
