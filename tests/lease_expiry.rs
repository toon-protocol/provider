//! A restart must not strand a paid workload, and an expired lease must not
//! keep one running. Both are driven through a fake `ComputeBackend`, so the
//! assertions are on what the provider asked the backend to do — never on its
//! internal state.

mod common;

use std::sync::Arc;

use common::{BackendCall, FakeBackend};
use toon_provider::{LeaseRecord, ProviderConfig, ProviderService};

const LIVE: u32 = 1000;
const EXPIRED: u32 = 1001;
const NOW: u64 = 1_700_000_000;

fn lease(id: u32, expires_at: u64) -> LeaseRecord {
    LeaseRecord {
        id,
        workload_id: Some(format!("wid-{}", id)),
        tenant_npub: "npub1tenant".to_string(),
        listing: "basic.v1".to_string(),
        created_at: NOW - 600,
        expires_at,
    }
}

/// A lease table left behind by a previous run of the provider.
fn state_file(dir: &std::path::Path, leases: &[LeaseRecord]) -> String {
    let path = dir.join("leases.json");
    let table: std::collections::HashMap<u32, &LeaseRecord> =
        leases.iter().map(|l| (l.id, l)).collect();
    std::fs::write(&path, serde_json::to_vec_pretty(&table).unwrap()).unwrap();
    path.to_string_lossy().into_owned()
}

fn service(state_path: String, backend: Arc<FakeBackend>) -> ProviderService {
    ProviderService::with_backend(
        ProviderConfig {
            lease_state_path: state_path,
            ..ProviderConfig::default()
        },
        backend,
    )
}

#[tokio::test]
async fn an_expired_lease_is_swept_and_a_live_one_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = state_file(
        dir.path(),
        &[lease(LIVE, NOW + 600), lease(EXPIRED, NOW - 1)],
    );

    let backend = FakeBackend::new();
    backend.seed_running(LIVE);
    backend.seed_running(EXPIRED);

    let provider = service(path.clone(), backend.clone());
    provider.restore_leases().await;
    provider.sweep_expired_leases(NOW).await;

    assert_eq!(
        backend.calls(),
        vec![BackendCall::Stop(EXPIRED), BackendCall::Delete(EXPIRED)],
        "only the expired lease's workload is destroyed"
    );

    // The rewritten table is what the next restart reads, so the ended lease
    // must be gone from it and the live one still there.
    let after: std::collections::HashMap<u32, LeaseRecord> =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(after.contains_key(&LIVE));
    assert!(!after.contains_key(&EXPIRED));
}

#[tokio::test]
async fn a_lease_whose_workload_vanished_while_we_were_down_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = state_file(dir.path(), &[lease(LIVE, NOW + 600)]);

    // The backend is the authority on what exists: nothing was seeded, so the
    // container is gone.
    let backend = FakeBackend::new();
    let provider = service(path.clone(), backend.clone());
    provider.restore_leases().await;

    let after: std::collections::HashMap<u32, LeaseRecord> =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        after.is_empty(),
        "a lease with no workload must not be re-announced as capacity"
    );

    // And it must not then be swept, because there is nothing to destroy.
    provider.sweep_expired_leases(NOW + 10_000).await;
    assert!(backend.calls().is_empty());
}

#[tokio::test]
async fn expires_at_equal_to_now_is_already_expired() {
    // expires_at is the FIRST instant the lease no longer applies. There is no
    // grace period: one payment bought one Lease Interval and no more.
    let dir = tempfile::tempdir().unwrap();
    let path = state_file(dir.path(), &[lease(LIVE, NOW)]);

    let backend = FakeBackend::new();
    backend.seed_running(LIVE);

    let provider = service(path, backend.clone());
    provider.restore_leases().await;
    provider.sweep_expired_leases(NOW).await;

    assert_eq!(
        backend.calls(),
        vec![BackendCall::Stop(LIVE), BackendCall::Delete(LIVE)]
    );
}
