//! A Hidden Provider's OWN outbound, through a SOCKS5 stub (spec §10,
//! ADR 0008; TOON_Network #42): the relay reads, the TOON store gateway, the
//! OCI registry and its anonymous token exchange, and the publish request to
//! the directory publisher.
//!
//! What makes these tests proof rather than decoration is the naming. Each
//! stub backend — the relay, the gateway, the registry — is reachable at a
//! loopback address the test knows, but the provider is configured with a
//! `.anyone` NAME for it that nothing on this host resolves. Only the SOCKS
//! stub holds the route from the name to the address. So a read that arrives
//! is a read that went through the proxy, and a provider that dialled
//! directly could not have got there at all — which is also what proves the
//! proxy is used as `socks5h`, the proxy resolving the name, rather than
//! `socks5`, this host resolving it first.
//!
//! The relay closes the loop from the other end: it records the peer address
//! of every connection it accepts, and the stub records the local address of
//! every connection it opens onward, so "no connection reached the relay
//! except through the proxy" is an assertion and not an inference.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use nostr_sdk::{EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use common::harness::{config_for, hidden_config, socks_proxy_of, NOW};
use common::relay::StubRelay;
use common::socks::{PeerTap, SocksStub};
use common::store::{World, LAYER};
use common::{stub_registry, valid_digest, valid_manifest_bytes, FakeBackend, FakeClock};
use toon_provider::nostr::directory_events::{liveness_event, takeover_event, ProfileContent};
use toon_provider::nostr::image_events::ImageEntry;
use toon_provider::nostr::kinds::{K_PROFILE, TOON_LABEL};
use toon_provider::provider::fetcher::BlobSources;
use toon_provider::provider::{BlobCache, BlobFetcher, ImagePolicyConfig};
use toon_provider::{
    ConnectorDirectory, Directory, NullDirectory, OutboundProxy, ProviderConfig, ProviderService,
};

/// The names the provider is configured with. Each is a host nothing on this
/// machine resolves; the SOCKS stub is the only thing that knows where it is.
const RELAY_HOST: &str = "relayfixturerelayfixturerelayfixturerelayfixturerelayfi.anyone";
const GATEWAY_HOST: &str = "gatewayfixture.anyone";
const REGISTRY_HOST: &str = "registryfixture.anyone";
/// The registry's token realm: a THIRD host, because that is what a real
/// registry's `WWW-Authenticate` names and it is the one image request that
/// would otherwise leave unproxied.
const TOKEN_HOST: &str = "tokenfixture.anyone";
const PUBLISHER_HOST: &str = "publisherfixture.anyone";

const CADENCE: u64 = 60;
const REPOSITORY: &str = "library/alpine";

// ── fixtures ────────────────────────────────────────────────────────────

fn profile(provider: &Keys, at: u64) -> nostr_sdk::Event {
    let content = ProfileContent {
        ilp_address: "g.primary".to_string(),
        connector_url: "https://c.primary.example/ilp".to_string(),
        connector_seal_key: format!("0x04{}", "ab".repeat(64)),
        relays: vec![],
        settlement: vec![],
        isolation: "shared-kernel".to_string(),
        hidden: false,
        host: Some("198.51.100.9".to_string()),
        liveness_cadence_s: CADENCE,
    };
    EventBuilder::new(
        Kind::Custom(K_PROFILE),
        serde_json::to_string(&content).unwrap(),
    )
    .tags([Tag::parse(["L", TOON_LABEL]).unwrap()])
    .custom_created_at(Timestamp::from(at))
    .sign_with_keys(provider)
    .unwrap()
}

/// The wall clock, because nostr-sdk's relay pool drops a Liveness whose
/// `expiration` has passed by it before the Directory ever sees the event.
fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Every read the `Directory` port makes of a relay, against one relay that
/// holds an answer to each. Returns nothing: what a caller asserts on is the
/// proxy and the relay, not the events, which the port's own tests cover.
async fn read_everything(directory: &dyn Directory, provider: &Keys, relay: &str) {
    let relays = vec![relay.to_string()];
    assert!(
        directory
            .get_profile(provider.public_key())
            .await
            .unwrap()
            .is_some(),
        "the Profile came back through the proxy"
    );
    assert!(
        directory
            .query_liveness(provider.public_key())
            .await
            .unwrap()
            .is_some(),
        "the Liveness came back through the proxy"
    );
    let states = directory
        .liveness_state(provider.public_key(), &relays, wall_now())
        .await
        .unwrap();
    assert_eq!(
        states.get(relay),
        Some(&toon_provider::LivenessState::Live),
        "watching a primary, relay by relay"
    );
    let takeovers = directory
        .find_takeovers(&"ab".repeat(32), &[provider.public_key()], &relays)
        .await
        .unwrap();
    assert_eq!(
        takeovers.len(),
        1,
        "the Takeover came back through the proxy"
    );
    // Nothing holds a Blob Record here: the read still has to reach the
    // relay, which is what is being proven.
    assert!(directory
        .find_blob_records(&format!("sha256:{}", "cd".repeat(32)))
        .await
        .unwrap()
        .is_empty());
}

/// One relay holding a Profile, a Liveness and a Takeover from `provider`.
fn seed(relay: &StubRelay, provider: &Keys) {
    relay.hold(profile(provider, NOW));
    relay.hold(liveness_event(BTreeMap::new(), CADENCE, provider, wall_now()).unwrap());
    relay.hold(
        takeover_event(
            &"ab".repeat(32),
            &Keys::generate().public_key(),
            provider,
            NOW,
        )
        .unwrap(),
    );
}

/// The proxy was asked for `destination` by the name only it can resolve, and
/// every connection the backend accepted is one the proxy opened — so the
/// count of direct connections is zero, asserted rather than inferred.
fn assert_only_through(socks: &SocksStub, peers: Vec<std::net::SocketAddr>, destination: &str) {
    assert!(
        socks.asked_for(destination),
        "the proxy was asked for {destination}; it saw {:?}",
        socks.destinations()
    );
    assert!(!peers.is_empty(), "the backend was reached at all");
    let outgoing = socks.outgoing();
    for peer in &peers {
        assert!(
            outgoing.contains(peer),
            "a connection arrived from {peer}, which the proxy did not open \
             (it opened {outgoing:?}) — something dialled the backend directly"
        );
    }
}

/// `assert_only_through` for a stub relay, which knows its own port.
fn assert_relay_only_through(socks: &SocksStub, relay: &StubRelay, name: &str) {
    let destination = format!("{}:{}", name, relay.socket_addr().port());
    assert_only_through(socks, relay.peers(), &destination);
}

// ── relay reads ─────────────────────────────────────────────────────────

/// Liveness watching, Profile lookups, Takeover and Blob Record queries, on
/// BOTH Directories that read: the publishing one and the publisher-less
/// one, because a Hidden Provider with no payer still watches its primary
/// and still resolves images.
#[tokio::test]
async fn every_relay_read_on_a_hidden_provider_leaves_through_the_socks_proxy() {
    let relay = StubRelay::start().await;
    let socks = SocksStub::start(&[(RELAY_HOST, relay.socket_addr())]).await;
    let proxy = OutboundProxy::resolve(&socks.url()).unwrap();
    let url = relay.url_as(RELAY_HOST);
    let provider = Keys::generate();
    seed(&relay, &provider);

    let publishing = ConnectorDirectory::new("http://127.0.0.1:1/publish", vec![url.clone()])
        .unwrap()
        .with_proxy(&proxy)
        .unwrap();
    read_everything(&publishing, &provider, &url).await;

    let publisherless = NullDirectory::new(vec![url.clone()]).with_proxy(&proxy);
    assert!(publisherless
        .get_profile(provider.public_key())
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        publisherless
            .find_takeovers(
                &"ab".repeat(32),
                &[provider.public_key()],
                std::slice::from_ref(&url),
            )
            .await
            .unwrap()
            .len(),
        1
    );

    assert_relay_only_through(&socks, &relay, RELAY_HOST);
}

/// A TENANT's relay hint on a hidden provider (TOON_Network#107): a name
/// only the proxy can resolve, hinted at by a spawn and NOT in this
/// provider's Relay Set, is dialled through the proxy rather than refused.
/// A hidden provider resolves no name itself, so a name is the proxy's to
/// judge — while an address literal inside the operator's network is refused
/// here as anywhere.
#[tokio::test]
async fn a_relay_hint_on_a_hidden_provider_rides_the_proxy_and_is_not_resolved_here() {
    let relay = StubRelay::start().await;
    let socks = SocksStub::start(&[(RELAY_HOST, relay.socket_addr())]).await;
    let proxy = OutboundProxy::resolve(&socks.url()).unwrap();
    let hint = relay.url_as(RELAY_HOST);
    let address = format!("30434:{}:web:1.0", Keys::generate().public_key().to_hex());

    // No Relay Set at all: nothing here is exempt, and the hint is still
    // dialled — the read reaches the relay and answers "no such entry".
    let directory = NullDirectory::new(vec![]).with_proxy(&proxy);
    assert!(directory
        .get_image_entry(&address, &hint)
        .await
        .unwrap()
        .is_none());
    assert_relay_only_through(&socks, &relay, RELAY_HOST);

    let refusal = directory
        .get_image_entry(&address, "ws://127.0.0.1:9944")
        .await
        .expect_err("loopback is refused on a hidden provider too");
    assert!(
        refusal.to_string().contains("ws://127.0.0.1:9944"),
        "{}",
        refusal
    );
}

/// The other half of the claim: a provider that is not hidden opens every
/// connection itself, and the proxy — running, and reachable — is never
/// asked for anything.
#[tokio::test]
async fn a_provider_that_is_not_hidden_dials_every_relay_directly() {
    let relay = StubRelay::start().await;
    let socks = SocksStub::start(&[(RELAY_HOST, relay.socket_addr())]).await;
    let provider = Keys::generate();
    seed(&relay, &provider);

    let directory =
        ConnectorDirectory::new("http://127.0.0.1:1/publish", vec![relay.url()]).unwrap();
    read_everything(&directory, &provider, &relay.url()).await;

    assert!(
        socks.destinations().is_empty(),
        "nothing was asked of the proxy: {:?}",
        socks.destinations()
    );
    assert!(!relay.peers().is_empty(), "the relay was reached directly");
}

/// The end of the wiring, not just the type: a hidden config whose
/// `anon.socks_proxy` names the stub gets a Directory that rides it, built
/// by `AppState::new` from the config alone.
#[tokio::test]
async fn a_hidden_config_wires_its_relay_reads_through_anon_socks_proxy() {
    let relay = StubRelay::start().await;
    let socks = SocksStub::start(&[(RELAY_HOST, relay.socket_addr())]).await;
    let provider = Keys::generate();
    seed(&relay, &provider);

    let registry = stub_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let config = ProviderConfig {
        relay_set: vec![relay.url_as(RELAY_HOST)],
        blob_cache_dir: Some(dir.path().to_string_lossy().into_owned()),
        ..socks_proxy_of(
            hidden_config(config_for(
                vec![],
                &Keys::generate().secret_key().to_secret_hex(),
                &dir.path().join("leases.json").to_string_lossy(),
                &registry,
                ImagePolicyConfig::default(),
            )),
            &socks.url(),
        )
    };
    let service =
        ProviderService::with_backend_and_clock(config, FakeBackend::new(), FakeClock::at(NOW))
            .unwrap();

    assert!(service
        .app_state()
        .directory
        .get_profile(provider.public_key())
        .await
        .unwrap()
        .is_some());
    assert_relay_only_through(&socks, &relay, RELAY_HOST);
}

// ── image fetches ───────────────────────────────────────────────────────

/// The TOON store gateway: the Blob Record's own upload and every part of
/// the blob, all of them read through the proxy from a gateway named by a
/// host nothing here resolves.
#[tokio::test]
async fn store_gateway_fetches_leave_through_the_socks_proxy() {
    let mut world = World::new().await;
    let payload = b"a layer worth hiding the fetch of".repeat(4);
    let digest = world.store(&payload, LAYER, 16).await;
    // `wiremock` cannot report its own callers, so the tap in front of it
    // does: the proxy's route points here, and this forwards to the gateway.
    let tap = PeerTap::infront_of(*world.gateway.address()).await;
    let gateway = tap.socket_addr();
    let socks = SocksStub::start(&[(GATEWAY_HOST, gateway)]).await;
    let proxy = OutboundProxy::resolve(&socks.url()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let fetcher = BlobFetcher::new(
        Some(format!(
            "http://{}:{}/raw/{{txid}}",
            GATEWAY_HOST,
            gateway.port()
        )),
        None,
        &[],
        None,
        BlobCache::open(dir.path(), None).unwrap(),
    )
    .unwrap()
    .with_proxy(&proxy)
    .unwrap();

    let entry = ImageEntry::from_event(&world.entry(&digest, LAYER)).unwrap();
    let sources = BlobSources::entry(entry, Arc::new(NullDirectory::new(vec![])));
    let bytes = fetcher.fetch(&digest, &sources).await.unwrap();
    assert_eq!(bytes.as_ref(), payload.as_slice());

    let destination = format!("{}:{}", GATEWAY_HOST, gateway.port());
    assert_only_through(&socks, tap.peers(), &destination);
    assert!(
        socks.destinations().iter().all(|d| d == &destination),
        "and nothing but the gateway was named to the proxy: {:?}",
        socks.destinations()
    );
    // The Blob Record's own upload and every part of the blob — more reads
    // than connections, because reqwest keeps the proxied connection alive
    // and buys one circuit for all of them.
    assert!(
        world.gateway_request_count().await >= 2,
        "the record and its parts all arrived"
    );
}

/// The upstream registry AND the anonymous pull token its 401 sends the
/// provider to fetch — a request to a different host again, and the one
/// that would otherwise name this provider to a registry's auth service.
#[tokio::test]
async fn registry_fetches_and_the_anonymous_token_exchange_leave_through_the_socks_proxy() {
    let registry = MockServer::start().await;
    let tap = PeerTap::infront_of(*registry.address()).await;
    let addr = tap.socket_addr();
    let realm = format!("http://{}:{}/token", TOKEN_HOST, addr.port());

    // Anonymous first, as every registry client tries: the challenge names
    // the realm, and only a request carrying the token is served.
    Mock::given(method("GET"))
        .and(path_regex(r"^/v2/.*/manifests/.*$"))
        .and(|req: &Request| req.headers.get("authorization").is_none())
        .respond_with(
            ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                format!(
                    "Bearer realm=\"{}\",service=\"registry\",scope=\"repository:{}:pull\"",
                    realm, REPOSITORY
                )
                .as_str(),
            ),
        )
        .mount(&registry)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v2/.*/manifests/.*$"))
        .and(|req: &Request| req.headers.get("authorization").is_some())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(valid_manifest_bytes()))
        .mount(&registry)
        .await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": "anonymous" })))
        .mount(&registry)
        .await;

    let socks = SocksStub::start(&[(REGISTRY_HOST, addr), (TOKEN_HOST, addr)]).await;
    let proxy = OutboundProxy::resolve(&socks.url()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let fetcher = BlobFetcher::new(
        None,
        Some(format!("http://{}:{}", REGISTRY_HOST, addr.port())),
        // The realm is a third host over plain http, which only an
        // operator's own network is (TOON_Network#105): the operator says so
        // here, the way the sandbox's `image_policy.exempt_registries` would.
        &[TOKEN_HOST.to_string()],
        None,
        BlobCache::open(dir.path(), None).unwrap(),
    )
    .unwrap()
    .with_proxy(&proxy)
    .unwrap();

    let digest = valid_digest();
    let sources = BlobSources::upstream("docker.io", REPOSITORY);
    let bytes = fetcher.fetch(&digest, &sources).await.unwrap();
    assert_eq!(bytes.as_ref(), valid_manifest_bytes().as_slice());

    assert_only_through(
        &socks,
        tap.peers(),
        &format!("{}:{}", REGISTRY_HOST, addr.port()),
    );
    assert!(
        socks.asked_for(&format!("{}:{}", TOKEN_HOST, addr.port())),
        "the anonymous token exchange went through the proxy too: {:?}",
        socks.destinations()
    );
}

// ── the publish request ─────────────────────────────────────────────────

/// A publisher that is not on this host: the request carries the proxy AND
/// rides it, because the packet to the publisher leaves this box too.
#[tokio::test]
async fn a_publish_request_to_a_remote_publisher_names_the_proxy_and_rides_it() {
    let publisher = accepting_publisher().await;
    let addr = *publisher.address();
    let socks = SocksStub::start(&[(PUBLISHER_HOST, addr)]).await;
    let proxy = OutboundProxy::resolve(&socks.url()).unwrap();

    let directory = ConnectorDirectory::new(
        format!("http://{}:{}/publish", PUBLISHER_HOST, addr.port()),
        vec!["ws://relay.example:7100".to_string()],
    )
    .unwrap()
    .with_proxy(&proxy)
    .unwrap();

    let provider = Keys::generate();
    directory
        .publish(liveness_event(BTreeMap::new(), CADENCE, &provider, NOW).unwrap())
        .await
        .unwrap();

    assert_eq!(
        published(&publisher).await["proxy"],
        json!(socks.url()),
        "the publisher is told which proxy to dial the connector through"
    );
    assert!(
        socks.asked_for(&format!("{}:{}", PUBLISHER_HOST, addr.port())),
        "the request itself rode the proxy: {:?}",
        socks.destinations()
    );
}

/// A publisher on loopback — or on a private network, as a sidecar container
/// is — is dialled directly: `anon` builds no circuit to such an address, and
/// the packet leaves nothing anyone outside can see. It is still TOLD the
/// proxy, because the hop it makes next, to the connector that sells the
/// relay write, is the one that leaves.
#[tokio::test]
async fn a_near_publisher_is_dialled_directly_and_still_told_the_proxy() {
    let publisher = accepting_publisher().await;
    let socks = SocksStub::start(&[]).await;
    let proxy = OutboundProxy::resolve(&socks.url()).unwrap();

    let directory = ConnectorDirectory::new(
        format!("{}/publish", publisher.uri()),
        vec!["ws://relay.example:7100".to_string()],
    )
    .unwrap()
    .with_proxy(&proxy)
    .unwrap();

    let provider = Keys::generate();
    directory
        .publish(liveness_event(BTreeMap::new(), CADENCE, &provider, NOW).unwrap())
        .await
        .unwrap();

    assert_eq!(published(&publisher).await["proxy"], json!(socks.url()));
    assert!(
        socks.destinations().is_empty(),
        "the loopback hop was not sent through anon: {:?}",
        socks.destinations()
    );
}

/// A provider that is not hidden sends what it always sent: no `proxy` key
/// at all, so a publisher built before this field behaves identically.
#[tokio::test]
async fn a_provider_that_is_not_hidden_names_no_proxy_in_the_publish_request() {
    let publisher = accepting_publisher().await;
    let directory = ConnectorDirectory::new(
        format!("{}/publish", publisher.uri()),
        vec!["ws://relay.example:7100".to_string()],
    )
    .unwrap();

    let provider = Keys::generate();
    directory
        .publish(liveness_event(BTreeMap::new(), CADENCE, &provider, NOW).unwrap())
        .await
        .unwrap();

    let body = published(&publisher).await;
    assert!(
        body.get("proxy").is_none(),
        "absent, not null — the field is optional on the wire: {body}"
    );
}

async fn accepting_publisher() -> MockServer {
    let publisher = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/publish"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "accepted": [], "failed": {} })),
        )
        .mount(&publisher)
        .await;
    publisher
}

/// The body of the one request the publisher was sent.
async fn published(publisher: &MockServer) -> Value {
    let requests = publisher.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    serde_json::from_slice(&requests[0].body).unwrap()
}

// ── the startup refusal ─────────────────────────────────────────────────

/// `socks5`, not `socks5h`, is refused before the provider is built, and the
/// message says why: under plain `socks5` this host resolves the
/// destination, which for a relay or an `.anyone` address is exactly the
/// lookup hiding exists to withhold.
#[tokio::test]
async fn a_proxy_that_is_not_socks5h_is_refused_at_startup() {
    let registry = stub_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let config = socks_proxy_of(
        hidden_config(config_for(
            vec![],
            &Keys::generate().secret_key().to_secret_hex(),
            &dir.path().join("leases.json").to_string_lossy(),
            &registry,
            ImagePolicyConfig::default(),
        )),
        "socks5://127.0.0.1:9050",
    );
    let refused =
        ProviderService::with_backend_and_clock(config, FakeBackend::new(), FakeClock::at(NOW))
            .err()
            .expect("a socks5 proxy is refused");
    let why = format!("{refused:#}");
    assert!(why.contains("socks5h"), "{why}");
    assert!(why.contains("anon.socks_proxy"), "{why}");
}

/// A `socks5h` proxy whose own host does not resolve is a refusal too: a
/// hidden provider that cannot reach its daemon must not carry on
/// publishing from its real address instead.
#[tokio::test]
async fn a_proxy_whose_host_does_not_resolve_is_refused_at_startup() {
    let registry = stub_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let config = socks_proxy_of(
        hidden_config(config_for(
            vec![],
            &Keys::generate().secret_key().to_secret_hex(),
            &dir.path().join("leases.json").to_string_lossy(),
            &registry,
            ImagePolicyConfig::default(),
        )),
        &format!("socks5h://{}:9050", RELAY_HOST),
    );
    let refused =
        ProviderService::with_backend_and_clock(config, FakeBackend::new(), FakeClock::at(NOW))
            .err()
            .expect("an unresolvable proxy is refused");
    assert!(
        format!("{refused:#}").contains("does not resolve here"),
        "{refused:#}"
    );
}
