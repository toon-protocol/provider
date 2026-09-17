//! What a Hidden Provider hands its backend for every workload it starts
//! (spec §10, ADR 0008; TOON_Network #41): the egress policy the
//! `HiddenService` port answers, on every create — driven through the HTTP
//! router over the fakes. The other half, that a provider which is not
//! hidden hands none, is `tests/hidden_provider.rs`.

mod common;

use common::socks::SocksStub;

use axum::http::StatusCode;

use common::harness::{
    config_for, harness_from, hidden_config, listing, socks_proxy_of, spawn, spawn_content,
    RequestSpec, NOW,
};
use common::{stub_registry, FakeBackend, FakeClock, FakeDirectory};
use nostr_sdk::Keys;
use toon_provider::compute::EgressPolicy;
use toon_provider::provider::ImagePolicyConfig;

#[tokio::test]
async fn every_workload_of_a_hidden_provider_carries_the_egress_policy_the_port_answers() {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir
        .keep()
        .join("leases.json")
        .to_string_lossy()
        .into_owned();
    let registry = stub_registry().await;
    // A hidden provider's image fetch leaves through `anon.socks_proxy`
    // (§10), so the stub registry is reached through a SOCKS stub.
    let socks = SocksStub::start(&[]).await;
    let config = socks_proxy_of(
        hidden_config(config_for(
            vec![listing("basic", 1, 2)],
            &keys.secret_key().to_secret_hex(),
            &state_path,
            &registry,
            ImagePolicyConfig::default(),
        )),
        &socks.url(),
    );
    let h = harness_from(
        config,
        FakeBackend::new(),
        FakeClock::at(NOW),
        FakeDirectory::new(),
        registry,
    );
    // Not what the config says: what the port answers. The backend must be
    // handed the port's policy, so a `HiddenService` that gives leases
    // networks of their own is obeyed.
    let policy = EgressPolicy {
        network: "toon-sandbox_hs-egress".to_string(),
        gateway: "10.203.0.2".to_string(),
    };
    h.hidden_service.set_egress(policy.clone());

    for seed in [1, 2] {
        let content = spawn_content(seed);
        let (status, body) = spawn(&h, RequestSpec::spawn(&h, &content).sign()).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
    }

    let created = h.backend.created();
    assert_eq!(created.len(), 2, "one create per lease");
    for config in &created {
        assert_eq!(
            config.egress.as_ref(),
            Some(&policy),
            "the policy arrives on every create"
        );
        // Still published on the host: the per-lease address is forwarded
        // to these, so the backend must still be told them.
        assert!(config.host_port.is_some(), "the SSH forward");
        assert!(!config.ports.is_empty(), "the published ports");
    }
}
