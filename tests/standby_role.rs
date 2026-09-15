//! The `warm_standby_role` routing matrix: one Lease Request naming a primary
//! and its standbys lands at N+1 providers, and each must pick its own path.
//!
//! Warm Standby is Milestone 3 work and is unwired in the app, but the routing
//! rule is pure and cheap to keep honest.
//!
//! Convention: `primary_npub` names the primary; `standby_providers` holds only
//! the standbys.

use toon_provider::nostr::{warm_standby_role, WarmStandbyRole};

#[test]
fn role_primary_when_self_matches_primary_npub() {
    let r = warm_standby_role("npub1primary", "npub1primary", &["npub1b".into()]);
    assert_eq!(r, WarmStandbyRole::Primary);
}

#[test]
fn role_standby_with_correct_index() {
    let r = warm_standby_role(
        "npub1c",
        "npub1primary",
        &["npub1b".into(), "npub1c".into(), "npub1d".into()],
    );
    assert_eq!(r, WarmStandbyRole::Standby { index: 1, count: 3 });
}

#[test]
fn role_not_addressed_when_self_unknown() {
    let r = warm_standby_role(
        "npub1stranger",
        "npub1primary",
        &["npub1b".into(), "npub1c".into()],
    );
    assert_eq!(r, WarmStandbyRole::NotAddressed);
}
