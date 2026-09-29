//! `toon-provider status` (TOON_Network#172, ADR 0029): the four sources it
//! reads, each stubbed with `wiremock` — the provider's own
//! `GET /operator/status`, the publisher's `GET /status`, the connector's
//! bearer-gated `GET /claims`, `/channels` and `/audit-log`, and a Solana
//! RPC's `getBalance` (the connector's SOL) and `getTokenAccountsByOwner`
//! (the publisher wallet's USDC) — and what it makes of them: six sections in ADR 0029's
//! order, one JSON document, each source degrading on its own, and every
//! `--check` rule.
//!
//! The provider's document is the wire fixture `operator_status.listed.json`
//! (what `tests/wire_fixtures.rs` generates from the real route), edited per
//! test, so the command is proven against the shape the provider actually
//! answers.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

use common::socks::SocksStub;
use toon_provider::nostr::directory_events::Settlement;
use toon_provider::provider::{AnonConfig, SettlementRpc, SettlementRpcs};
use toon_provider::status::{
    check, from_json, gather, render_text, to_json, Report, ReportArgs, Sources, Thresholds,
};
use toon_provider::ProviderConfig;

const TOKEN: &str = "fixture-bearer-token";
const ADDRESS: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
/// The publisher's Solana wallet, and the mint it pays in: the provider's
/// own `[[settlement]]` solana token, as on the devnet.
const PUBLISHER: &str = "7cVfgArCheMR6Cs4t6vz5rfnqd56vZq4ndaBrY5xkxXy";
const MINT: &str = "34eSxY7qxQ4GzyhDJ8GpUcTz1WWzruGbJbR8q6TtxfQU";
/// The publisher's `TOON_DEPOSIT`: what each Solana channel it opens takes.
const NEXT_DEPOSIT: u128 = 10_000_000;
const EVM_CHANNEL: &str = "0xabababababababababababababababababababababababababababababababab";
const SOLANA_CHANNEL: &str = "2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip";
/// A port nothing listens on: a source that is down.
const DEAD: &str = "http://127.0.0.1:9";

/// The fixture's `generated_at`.
const AT: u64 = 1_700_000_060;

fn fixture_doc() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wire/operator_status.listed.json");
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    fixture["response_body"].clone()
}

/// The fixture as a provider with nothing wrong: relay two's refused
/// Liveness is replaced by an accepted one, and the process has been up for
/// an hour.
fn healthy_doc() -> Value {
    let mut doc = fixture_doc();
    doc["started_at"] = json!(AT - 3_600);
    doc["directory"]["relays"]["ws://relay-two.fixture.example:7100"]["liveness"] = json!({
        "expires_at": AT + 300,
        "last_accepted_at": AT,
        "last_attempt_at": AT,
        "refusal": null,
    });
    doc["directory"]["liveness_expires_at"] = json!(AT + 300);
    doc
}

/// The same answer from a publisher paying on Base, whose channel is topped
/// up rather than replaced.
fn evm_publisher_body(remaining: &str, runway_s: Value) -> Value {
    let mut body = publisher_body(remaining, runway_s);
    body["channelId"] = json!(EVM_CHANNEL);
    body["chain"] = json!("evm:84532");
    body
}

fn publisher_body(remaining: &str, runway_s: Value) -> Value {
    json!({
        "channelId": "PubChanne1111111111111111111111111111111111",
        "chain": "solana",
        "deposit": "10000000",
        "spent": "2981",
        "remaining": remaining,
        "signedCeiling": "2981",
        "watermarkUncertain": false,
        "runway_s": runway_s,
        "assumptions": ["runway = remaining ÷ (price per write × writes per cadence)"],
    })
}

/// The four stubbed sources, all healthy until a test says otherwise.
struct World {
    operator: MockServer,
    publisher: MockServer,
    connector: MockServer,
    rpc: MockServer,
    token_file: tempfile::NamedTempFile,
}

impl World {
    async fn new() -> Self {
        let world = World {
            operator: MockServer::start().await,
            publisher: MockServer::start().await,
            connector: MockServer::start().await,
            rpc: MockServer::start().await,
            token_file: {
                let file = tempfile::NamedTempFile::new().unwrap();
                std::fs::write(file.path(), format!("{TOKEN}\n")).unwrap();
                file
            },
        };
        world
    }

    async fn healthy() -> Self {
        let world = Self::new().await;
        world.operator_answers(healthy_doc()).await;
        world
            .publisher_answers(publisher_body("9997019", json!(1_209_600)))
            .await;
        world.connector_answers().await;
        world.rpc_answers(1_500_000_000).await;
        world.wallet_answers(25_000_000).await;
        world
    }

    async fn operator_answers(&self, doc: Value) {
        Mock::given(method("GET"))
            .and(path("/operator/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc))
            .mount(&self.operator)
            .await;
    }

    async fn publisher_answers(&self, body: Value) {
        Mock::given(method("GET"))
            .and(path("/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.publisher)
            .await;
    }

    /// The connector's operator reads, gated on the bearer token exactly as
    /// `connector-operator` gates them: anything else is a 401.
    async fn connector_answers(&self) {
        let auth = format!("Bearer {TOKEN}");
        Mock::given(method("GET"))
            .and(path("/channels"))
            .and(header("authorization", auth.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "id": EVM_CHANNEL,
                    "counterparty": "0x1111111111111111111111111111111111111111",
                    "status": "open",
                    "deposited": 5_000_000u64,
                    "own_deposited": 0,
                    "redeemed": 1_000,
                },
            ])))
            .mount(&self.connector)
            .await;
        Mock::given(method("GET"))
            .and(path("/claims"))
            .and(header("authorization", auth.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                // A peer-book row and a client-edge row, whose channel id is
                // the chain-prefixed key and in upper case.
                {
                    "peer_id": null,
                    "channel_id": format!("evm:{}", EVM_CHANNEL.to_uppercase().replace("0X", "0x")),
                    "direction": "inbound",
                    "nonce": 7,
                    "cumulative_amount": 3_400,
                    "pending": false,
                    "book": "client",
                },
                {
                    "peer_id": null,
                    "channel_id": format!("solana:{SOLANA_CHANNEL}"),
                    "direction": "inbound",
                    "nonce": 2,
                    "cumulative_amount": 600,
                    "pending": false,
                    "book": "client",
                },
                // Outbound is money this node signed away, not earnings.
                {
                    "peer_id": "hub",
                    "channel_id": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                    "direction": "outbound",
                    "nonce": 1,
                    "cumulative_amount": 99_999,
                    "pending": false,
                    "book": "peer",
                },
            ])))
            .mount(&self.connector)
            .await;
        Mock::given(method("GET"))
            .and(path("/audit-log"))
            .and(header("authorization", auth.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "keyid": "k",
                    "signature": "s",
                    "method": "POST",
                    "path": format!("/channels/{EVM_CHANNEL}/redeem-latest"),
                    "created": AT - 600,
                    "expires": AT,
                },
                {
                    "keyid": "k",
                    "signature": "s",
                    "method": "POST",
                    "path": "/peers",
                    "created": AT - 60,
                    "expires": AT,
                },
            ])))
            .mount(&self.connector)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&self.connector)
            .await;
    }

    async fn rpc_answers(&self, lamports: u64) {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({
                "method": "getBalance",
                "params": [ADDRESS],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "context": { "slot": 1 }, "value": lamports },
            })))
            .mount(&self.rpc)
            .await;
    }

    /// The publisher wallet's token accounts for `MINT`: `units` in two of
    /// them, since a wallet may hold more than one and every one counts.
    async fn wallet_answers(&self, units: u128) {
        let account = |amount: u128| {
            json!({ "account": { "data": { "parsed": { "info": {
                "tokenAmount": { "amount": amount.to_string(), "decimals": 6 },
            } } } } })
        };
        Mock::given(method("POST"))
            .and(body_partial_json(json!({
                "method": "getTokenAccountsByOwner",
                "params": [PUBLISHER, { "mint": MINT }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "context": { "slot": 1 },
                    "value": [account(units - units / 5), account(units / 5)],
                },
            })))
            .mount(&self.rpc)
            .await;
    }

    fn config(&self) -> ProviderConfig {
        ProviderConfig {
            provider_name: "Fixture Provider".to_string(),
            operator_url: self.operator.uri(),
            publish_url: Some(format!("{}/publish", self.publisher.uri())),
            connector_url: "https://proxy.provider.fixture.example/ilp".to_string(),
            settlement: vec![Settlement {
                chain: "solana".to_string(),
                token: MINT.to_string(),
                decimals: 6,
            }],
            ..ProviderConfig::default()
        }
    }

    fn args(&self) -> ReportArgs {
        ReportArgs {
            min_runway: 7 * 86_400,
            min_sol: 5_000_000,
            connector_operator_url: Some(self.connector.uri()),
            bearer_token_file: Some(self.token_file.path().to_path_buf()),
            settlement_address: Some(ADDRESS.to_string()),
            settlement_address_file: None,
            settlement_rpc_url: Some(self.rpc.uri()),
            publisher_address: Some(PUBLISHER.to_string()),
            publisher_address_file: None,
            publisher_deposit: Some(NEXT_DEPOSIT),
        }
    }

    async fn report(&self) -> Report {
        self.report_with(&self.config(), &self.args()).await
    }

    async fn report_with(&self, config: &ProviderConfig, args: &ReportArgs) -> Report {
        gather(&Sources::from_config(config, args), AT).await
    }
}

fn thresholds() -> Thresholds {
    Thresholds {
        min_runway_s: 7 * 86_400,
        min_lamports: 5_000_000,
    }
}

fn problems(report: &Report) -> Vec<String> {
    check(report, &thresholds()).problems
}

fn warnings(report: &Report) -> Vec<String> {
    check(report, &thresholds()).warnings
}

fn any_contains(lines: &[String], needle: &str) -> bool {
    lines.iter().any(|l| l.contains(needle))
}

// ── The report ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn six_sections_in_adr_0029s_order() {
    let world = World::healthy().await;
    let text = render_text(&world.report().await);
    let order = [
        "\nIDENTITY\n",
        "\nDIRECTORY\n",
        "\nPUBLISHER\n",
        "\nLEASES\n",
        "\nEARNINGS\n",
        "\nFUNDING\n",
    ];
    let positions: Vec<usize> = order
        .iter()
        .map(|h| {
            text.find(h)
                .unwrap_or_else(|| panic!("no {h:?} in:\n{text}"))
        })
        .collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{text}");

    assert!(text.contains("npub1gekhljh9v0jukzdq6xrshdvqx3yqgctc0xs5jjw0yg597xaw8uns47vduw"));
    assert!(text.contains("matches the connector's live key"), "{text}");
    assert!(
        text.contains("ws://relay-two.fixture.example:7100"),
        "{text}"
    );
    assert!(text.contains("remaining 9997019"), "{text}");
    assert!(
        text.contains("14d at the current Liveness cadence"),
        "{text}"
    );
    assert!(text.contains("#1000 basic v1 standalone running"), "{text}");
    assert!(text.contains("billed 2000"), "{text}");
    assert!(text.contains("1.5 SOL"), "{text}");
    assert!(text.contains("up 1h"), "{text}");
}

// ── DIRECTORY: NOT SENT vs REFUSED (TOON_Network#178) ────────────────────────

#[tokio::test]
async fn a_write_that_never_reached_a_relay_reads_as_not_sent_not_refused() {
    // A relay's own "no" is REFUSED; a write the directory publisher never
    // managed to make was never offered to any relay to refuse, so it reads
    // as NOT SENT instead.
    let world = World::new().await;
    let mut doc = fixture_doc();
    doc["started_at"] = json!(AT - 3_600);
    doc["directory"]["relays"]["ws://relay-two.fixture.example:7100"]["liveness"] = json!({
        "expires_at": null,
        "last_accepted_at": null,
        "last_attempt_at": AT - 5,
        "refusal": "not attempted: dns error: failed to lookup address information",
        "kind": "not_sent",
    });
    world.operator_answers(doc).await;
    world
        .publisher_answers(publisher_body("9997019", json!(1_209_600)))
        .await;
    world.connector_answers().await;
    world.rpc_answers(1_500_000_000).await;

    let text = render_text(&world.report().await);
    assert!(text.contains("NOT SENT"), "{text}");
    assert!(!text.contains("REFUSED"), "{text}");
}

#[tokio::test]
async fn a_relays_own_refusal_still_reads_as_refused() {
    // The fixture as generated has relay-two really refuse the latest
    // Liveness (`"kind": "refused"`) — the case NOT SENT must not swallow.
    let world = World::new().await;
    let mut doc = fixture_doc();
    doc["started_at"] = json!(AT - 3_600);
    world.operator_answers(doc).await;
    world
        .publisher_answers(publisher_body("9997019", json!(1_209_600)))
        .await;
    world.connector_answers().await;
    world.rpc_answers(1_500_000_000).await;

    let text = render_text(&world.report().await);
    assert!(text.contains("REFUSED"), "{text}");
    assert!(!text.contains("NOT SENT"), "{text}");
}

// ── LEASES: an ended state in words, not raw JSON (TOON_Network#178) ────────

#[tokio::test]
async fn an_ended_lease_prints_its_reason_in_words() {
    let world = World::new().await;
    let mut doc = fixture_doc();
    doc["started_at"] = json!(AT - 3_600);
    doc["leases"]["leases"][0]["state"] = json!({ "ended": "termination" });
    doc["leases"]["leases"][0]["ended_at"] = json!(AT - 60);
    world.operator_answers(doc).await;
    world
        .publisher_answers(publisher_body("9997019", json!(1_209_600)))
        .await;
    world.connector_answers().await;
    world.rpc_answers(1_500_000_000).await;

    let text = render_text(&world.report().await);
    assert!(text.contains("ended (termination)"), "{text}");
    assert!(!text.contains("{\"ended\""), "{text}");
}

#[tokio::test]
async fn earnings_join_claims_to_channels_and_name_the_dashboard() {
    let world = World::healthy().await;
    let report = world.report().await;
    let earnings = &report.earnings;
    assert_eq!(earnings.error, None);
    assert_eq!(earnings.channels.len(), 2, "{:?}", earnings.channels);

    let evm = earnings
        .channels
        .iter()
        .find(|c| c.channel_id == EVM_CHANNEL)
        .expect("the listed channel");
    assert_eq!(
        evm.claimed, 3_400,
        "the client-edge claim joins the bare id"
    );
    assert_eq!(evm.redeemed, 1_000);
    assert_eq!(evm.unredeemed, 2_400);
    assert_eq!(evm.last_redeemed_at, Some(AT - 600));
    assert_eq!(evm.status.as_deref(), Some("open"));

    let solana = earnings
        .channels
        .iter()
        .find(|c| c.channel_id == SOLANA_CHANNEL)
        .expect("a claim on a channel the connector did not list is still money held");
    assert_eq!(solana.unredeemed, 600);
    assert_eq!(
        earnings.total_unredeemed(),
        3_000,
        "outbound claims are not earnings"
    );

    let text = render_text(&report);
    assert!(
        text.contains("https://proxy.provider.fixture.example/dashboard"),
        "the earnings section names the connector's dashboard:\n{text}"
    );
    assert!(text.contains("total unredeemed 3000"), "{text}");
    assert!(
        text.contains("To collect it: `toon-provider redeem`"),
        "the earnings section points at redeem:\n{text}"
    );
}

#[tokio::test]
async fn json_is_the_operator_document_with_three_more_sections() {
    let world = World::healthy().await;
    let report = world.report().await;
    let doc = to_json(&report, None);
    let provider = healthy_doc();
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["service"], "provider");
    for section in [
        "identity",
        "directory",
        "leases",
        "generated_at",
        "started_at",
    ] {
        assert_eq!(
            doc[section], provider[section],
            "{section} passes through verbatim"
        );
    }
    assert_eq!(doc["publisher"]["remaining"], "9997019");
    assert_eq!(doc["publisher"]["runway_s"], 1_209_600);
    assert_eq!(doc["publisher"]["error"], Value::Null);
    assert_eq!(doc["earnings"]["total_unredeemed"], "3000");
    assert_eq!(
        doc["earnings"]["dashboard_url"],
        "https://proxy.provider.fixture.example/dashboard"
    );
    assert_eq!(doc["funding"]["lamports"], 1_500_000_000u64);
    assert_eq!(doc["funding"]["sol"], "1.5");
    assert_eq!(doc["funding"]["address"], ADDRESS);
    assert!(doc.get("check").is_none());

    let outcome = check(&report, &thresholds());
    let doc = to_json(&report, Some(&outcome));
    assert_eq!(doc["check"]["ok"], true, "{}", doc["check"]);
}

#[tokio::test]
async fn the_funding_rpc_is_shown_without_its_path_or_query() {
    let world = World::healthy().await;
    let mut args = world.args();
    args.settlement_rpc_url = Some(format!("{}/?api-key=do-not-print", world.rpc.uri()));
    let report = world.report_with(&world.config(), &args).await;
    let doc = to_json(&report, None);
    assert_eq!(doc["funding"]["lamports"], 1_500_000_000u64);
    let everything = format!("{}{}", doc, render_text(&report));
    assert!(!everything.contains("do-not-print"), "{everything}");
}

#[tokio::test]
async fn a_healthy_box_passes_the_check() {
    let world = World::healthy().await;
    let outcome = check(&world.report().await, &thresholds());
    assert!(outcome.ok(), "{outcome:?}");
    assert!(outcome.warnings.is_empty(), "{outcome:?}");
    assert!(outcome.render().contains("OK"));
}

// ── Each source degrades on its own ──────────────────────────────────────────

#[tokio::test]
async fn a_provider_that_does_not_answer_leaves_the_other_sections() {
    let world = World::healthy().await;
    let config = ProviderConfig {
        operator_url: DEAD.to_string(),
        ..world.config()
    };
    let report = world.report_with(&config, &world.args()).await;
    assert!(report.operator.status.is_none());
    assert!(report.publisher.status.is_some());
    assert_eq!(report.earnings.error, None);
    assert_eq!(report.funding.lamports, Some(1_500_000_000));

    let text = render_text(&report);
    assert!(text.contains("is the provider running?"), "{text}");
    assert!(text.contains("remaining 9997019"), "{text}");

    let doc = to_json(&report, None);
    assert_eq!(doc["version"], 1);
    assert!(doc["identity"]["error"].is_string(), "{doc}");
    assert!(doc["directory"]["error"].is_string(), "{doc}");
    assert!(doc["leases"]["error"].is_string(), "{doc}");
    assert_eq!(doc["publisher"]["remaining"], "9997019");

    assert!(any_contains(&problems(&report), "provider:"));
}

#[tokio::test]
async fn a_publisher_that_does_not_answer_is_shown_and_is_a_problem() {
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world.connector_answers().await;
    world.rpc_answers(1_500_000_000).await;
    let config = ProviderConfig {
        publish_url: Some(format!("{DEAD}/publish")),
        ..world.config()
    };
    let report = world.report_with(&config, &world.args()).await;
    assert!(report.operator.status.is_some());
    assert!(report.publisher.status.is_none());
    let text = render_text(&report);
    assert!(text.contains("is directory-publisher running?"), "{text}");
    assert!(
        text.contains("#1000 basic"),
        "the rest still prints:\n{text}"
    );
    assert!(any_contains(&problems(&report), "publisher:"));
}

#[tokio::test]
async fn a_refused_bearer_token_is_shown_and_only_warned() {
    let world = World::healthy().await;
    std::fs::write(world.token_file.path(), "wrong-token").unwrap();
    let report = world.report().await;
    let error = report.earnings.error.clone().expect("earnings unavailable");
    assert!(error.contains("401"), "{error}");
    assert!(error.contains("bearer token"), "{error}");
    let text = render_text(&report);
    assert!(
        text.contains("/dashboard"),
        "the dashboard is still named:\n{text}"
    );
    assert!(problems(&report).is_empty(), "{:?}", problems(&report));
    assert!(any_contains(&warnings(&report), "earnings:"));
}

#[tokio::test]
async fn a_missing_bearer_token_file_is_shown() {
    let world = World::healthy().await;
    let mut args = world.args();
    args.bearer_token_file = Some(PathBuf::from("/nonexistent/operator-bearer.token"));
    let report = world.report_with(&world.config(), &args).await;
    let error = report.earnings.error.clone().unwrap();
    assert!(
        error.contains("/nonexistent/operator-bearer.token"),
        "{error}"
    );
}

#[tokio::test]
async fn an_rpc_that_refuses_is_shown_and_only_warned() {
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(publisher_body("9997019", json!(1_209_600)))
        .await;
    world.connector_answers().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32602, "message": "Invalid param: WrongSize" },
        })))
        .mount(&world.rpc)
        .await;
    let report = world.report().await;
    let error = report.funding.error.clone().unwrap();
    assert!(error.contains("WrongSize"), "{error}");
    assert!(problems(&report).is_empty(), "{:?}", problems(&report));
    assert!(any_contains(&warnings(&report), "funding:"));
}

#[tokio::test]
async fn the_settlement_address_is_read_from_the_rendered_file() {
    let world = World::healthy().await;
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), format!("{ADDRESS}\n")).unwrap();
    let mut args = world.args();
    args.settlement_address = None;
    args.settlement_address_file = Some(file.path().to_path_buf());
    let report = world.report_with(&world.config(), &args).await;
    assert_eq!(report.funding.lamports, Some(1_500_000_000));

    std::fs::write(file.path(), "").unwrap();
    let report = world.report_with(&world.config(), &args).await;
    assert!(report.funding.error.unwrap().contains("is empty"));
}

// ── --check, rule by rule ─────────────────────────────────────────────────────

#[tokio::test]
async fn liveness_under_two_cadences_is_a_problem() {
    let world = World::new().await;
    let mut doc = healthy_doc();
    doc["directory"]["liveness_expires_at"] = json!(AT + 90);
    world.operator_answers(doc).await;
    let report = world.report().await;
    let found = problems(&report);
    assert!(
        any_contains(&found, "the Liveness expires in 1m 30s, under 2 cadences"),
        "{found:?}"
    );
}

#[tokio::test]
async fn an_expired_liveness_is_a_problem() {
    let world = World::new().await;
    let mut doc = healthy_doc();
    doc["directory"]["liveness_expires_at"] = json!(AT - 30);
    world.operator_answers(doc).await;
    let found = problems(&world.report().await);
    assert!(
        any_contains(&found, "the Liveness expired 30s ago"),
        "{found:?}"
    );
}

#[tokio::test]
async fn a_relay_refusing_the_latest_write_is_a_problem() {
    let world = World::healthy().await;
    // The fixture as generated: relay two refused the latest Liveness.
    let world_refused = World::new().await;
    let mut doc = fixture_doc();
    doc["started_at"] = json!(AT - 3_600);
    world_refused.operator_answers(doc).await;
    let found = problems(
        &world_refused
            .report_with(&world_refused.config(), &world.args())
            .await,
    );
    assert!(
        any_contains(
            &found,
            "ws://relay-two.fixture.example:7100 refused the latest write of the Liveness: relay refused (last accepted 1m ago)"
        ),
        "{found:?}"
    );
}

#[tokio::test]
async fn a_refusal_in_the_first_cadence_after_a_restart_is_not_a_problem() {
    // What the live box showed after a joint restart: every relay's first
    // attempt "not attempted: dns error", healed by the next cadence.
    let world = World::new().await;
    let refused = json!({
        "expires_at": null,
        "last_accepted_at": null,
        "last_attempt_at": AT - 5,
        "refusal": "not attempted: error sending request: dns error",
        "kind": "not_sent",
    });
    let mut doc = fixture_doc();
    doc["started_at"] = json!(AT - 10);
    doc["directory"]["liveness_expires_at"] = Value::Null;
    for relay in doc["directory"]["relays"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        relay["profile"] = refused.clone();
        relay["liveness"] = refused.clone();
        for listing in relay["listings"].as_object_mut().unwrap().values_mut() {
            *listing = refused.clone();
        }
    }
    world.operator_answers(doc.clone()).await;
    let found = problems(&world.report_with(&world.config(), &world.args()).await);
    assert!(
        !any_contains(&found, "directory:"),
        "a publication that has not landed YET is not a problem: {found:?}"
    );

    // Still refusing well after startup: now it is.
    let later = World::new().await;
    doc["started_at"] = json!(AT - 600);
    later.operator_answers(doc).await;
    let found = problems(&later.report_with(&later.config(), &world.args()).await);
    assert!(
        any_contains(&found, "never accepted since the provider started"),
        "{found:?}"
    );
    assert!(
        any_contains(&found, "no relay has accepted a Liveness"),
        "{found:?}"
    );
    // A write that never reached a relay is NOT SENT, never "refused" — a
    // relay was never asked to say no (TOON_Network#178).
    assert!(
        any_contains(
            &found,
            "was not sent: not attempted: error sending request: dns error"
        ),
        "{found:?}"
    );
    assert!(
        !any_contains(&found, "refused the latest write"),
        "{found:?}"
    );
}

#[tokio::test]
async fn nothing_offered_to_a_relay_after_startup_is_a_problem() {
    let world = World::new().await;
    let mut doc = healthy_doc();
    doc["directory"]["relays"]["ws://relay-two.fixture.example:7100"]["profile"] = Value::Null;
    world.operator_answers(doc.clone()).await;
    let found = problems(&world.report().await);
    assert!(
        any_contains(&found, "the Profile has not been offered to this relay"),
        "{found:?}"
    );

    // …but not in the first cadence.
    let starting = World::new().await;
    doc["started_at"] = json!(AT - 20);
    starting.operator_answers(doc).await;
    let found = problems(
        &starting
            .report_with(&starting.config(), &world.args())
            .await,
    );
    assert!(!any_contains(&found, "directory:"), "{found:?}");
}

#[tokio::test]
async fn a_short_runway_is_a_problem() {
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(evm_publisher_body("400000", json!(3 * 86_400)))
        .await;
    let found = problems(&world.report().await);
    assert!(
        any_contains(&found, "3d of runway left, under --min-runway 7d"),
        "{found:?}"
    );
    assert!(
        any_contains(&found, "`toon-provider topup <amount>`"),
        "{found:?}"
    );
}

#[tokio::test]
async fn the_runway_threshold_is_the_operators() {
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(evm_publisher_body("400000", json!(3 * 86_400)))
        .await;
    let report = world.report().await;
    let outcome = check(
        &report,
        &Thresholds {
            min_runway_s: 86_400,
            ..thresholds()
        },
    );
    assert!(
        !any_contains(&outcome.problems, "publisher:"),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_unknown_runway_is_a_warning_not_a_problem() {
    // The live publisher's answer before it has priced a write.
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    let mut body = publisher_body("9997019", Value::Null);
    body["assumptions"] = json!([
        "the relay's advertised write price is not known yet — this publisher has not talked to its connector — so the runway cannot be estimated."
    ]);
    world.publisher_answers(body).await;
    let report = world.report().await;
    assert!(!any_contains(&problems(&report), "publisher:"));
    assert!(any_contains(
        &warnings(&report),
        "the runway is unknown: the relay's advertised write price is not known yet"
    ));
}

#[tokio::test]
async fn a_drained_channel_fails_the_check_even_with_no_runway() {
    // The ticket's acceptance: `--check` fails when the publisher's channel
    // is drained.
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    let mut body = evm_publisher_body("0", Value::Null);
    body["spent"] = json!("10000000");
    world.publisher_answers(body).await;
    let report = world.report().await;
    let found = problems(&report);
    assert!(
        any_contains(&found, "is drained (remaining 0 of 10000000)"),
        "{found:?}"
    );
    assert!(
        any_contains(&found, "`toon-provider topup <amount>`"),
        "{found:?}"
    );
    let text = render_text(&report);
    assert!(text.contains("DRAINED"), "{text}");
    assert!(text.contains("toon-provider topup"), "{text}");
}

// ── A Solana publisher: its channel is replaced, never topped up ─────────────
//
// An x402 Solana channel is opened by the connector's sponsor, which only
// opens. The payment a channel cannot cover opens a fresh one of
// TOON_DEPOSIT from the publisher wallet's own USDC. So what decides whether
// a write can be paid for is the WALLET, and nothing here tells an operator
// to top up.

/// A world whose publisher pays on Solana from a channel with `remaining`
/// left and `runway_s` of runway, and whose wallet holds `wallet` units.
async fn solana_world(remaining: &str, runway_s: Value, wallet: u128) -> World {
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(publisher_body(remaining, runway_s))
        .await;
    world.connector_answers().await;
    world.rpc_answers(1_500_000_000).await;
    world.wallet_answers(wallet).await;
    world
}

fn says_top_up(lines: &[String]) -> bool {
    any_contains(lines, "topup") || any_contains(lines, "top up")
}

#[tokio::test]
async fn the_publisher_wallet_is_read_for_its_token() {
    let world = World::healthy().await;
    let report = world.report().await;
    let wallet = &report.funding.publisher;
    assert_eq!(wallet.error, None);
    assert_eq!(wallet.address.as_deref(), Some(PUBLISHER));
    assert_eq!(wallet.token.as_deref(), Some(MINT));
    assert_eq!(wallet.units, Some(25_000_000), "every token account counts");
    assert_eq!(wallet.next_deposit, Some(NEXT_DEPOSIT));

    let text = render_text(&report);
    assert!(
        text.contains(&format!(
            "publisher     {PUBLISHER} holds 25000000 of {MINT}"
        )),
        "{text}"
    );
    assert!(text.contains("the next channel takes 10000000"), "{text}");

    let doc = to_json(&report, None);
    assert_eq!(doc["funding"]["publisher"]["address"], PUBLISHER);
    assert_eq!(doc["funding"]["publisher"]["token"], MINT);
    assert_eq!(doc["funding"]["publisher"]["units"], "25000000");
    assert_eq!(doc["funding"]["publisher"]["next_deposit"], "10000000");
}

#[tokio::test]
async fn a_drained_solana_channel_with_a_funded_wallet_is_not_a_problem() {
    let world = solana_world("0", Value::Null, 25_000_000).await;
    let report = world.report().await;
    let outcome = check(&report, &thresholds());
    assert!(outcome.ok(), "{outcome:?}");
    assert!(!says_top_up(&outcome.warnings), "{outcome:?}");
    let text = render_text(&report);
    assert!(!text.contains("DRAINED"), "{text}");
    assert!(!text.contains("topup"), "{text}");
    assert!(
        text.contains("the next write opens a fresh channel of 10000000"),
        "{text}"
    );
}

#[tokio::test]
async fn a_drained_solana_channel_and_a_wallet_short_of_the_next_is_a_problem() {
    let world = solana_world("0", Value::Null, 4_000_000).await;
    let report = world.report().await;
    let found = problems(&report);
    assert!(
        any_contains(
            &found,
            &format!(
                "publisher: the channel is drained, and the wallet {PUBLISHER} holds 4000000, \
                 less than the 10000000 the next channel takes"
            )
        ),
        "{found:?}"
    );
    assert!(!says_top_up(&found), "{found:?}");
    let text = render_text(&report);
    assert!(text.contains("DRAINED"), "{text}");
    assert!(!text.contains("topup"), "{text}");
}

#[tokio::test]
async fn a_short_solana_runway_is_a_problem_only_when_the_wallet_is_short_too() {
    let world = solana_world("400000", json!(3 * 86_400), 25_000_000).await;
    let outcome = check(&world.report().await, &thresholds());
    assert!(
        outcome.ok(),
        "the wallet funds the next channel: {outcome:?}"
    );

    let world = solana_world("400000", json!(3 * 86_400), 4_000_000).await;
    let found = problems(&world.report().await);
    assert!(
        any_contains(&found, "3d of runway left, under --min-runway 7d"),
        "{found:?}"
    );
    assert!(
        any_contains(&found, "less than the 10000000 the next channel takes"),
        "{found:?}"
    );
    assert!(!says_top_up(&found), "{found:?}");
}

#[tokio::test]
async fn a_wallet_short_of_the_next_channel_behind_a_long_runway_is_a_warning() {
    let world = solana_world("9997019", json!(1_209_600), 4_000_000).await;
    let outcome = check(&world.report().await, &thresholds());
    assert!(outcome.ok(), "{outcome:?}");
    assert!(
        any_contains(
            &outcome.warnings,
            "less than the 10000000 the next channel takes; fund it before this channel's 14d \
             run out"
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn no_channel_yet_and_a_wallet_that_cannot_open_one_is_a_problem() {
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(json!({
            "channelId": null, "chain": null, "deposit": null, "spent": "0",
            "remaining": null, "signedCeiling": null, "watermarkUncertain": false,
            "runway_s": null, "assumptions": ["no channel has been opened yet."],
        }))
        .await;
    world.wallet_answers(1).await;
    let found = problems(&world.report().await);
    assert!(
        any_contains(&found, "publisher: no channel is open yet, and the wallet"),
        "{found:?}"
    );
    assert!(
        any_contains(
            &found,
            "holds 1, less than the 10000000 the first channel takes"
        ),
        "{found:?}"
    );

    // Funded: only the usual "nothing to measure yet".
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(json!({ "channelId": null, "spent": "0", "assumptions": [] }))
        .await;
    world.wallet_answers(10_000_000).await;
    let found = problems(&world.report().await);
    assert!(!any_contains(&found, "publisher:"), "{found:?}");
}

#[tokio::test]
async fn a_drained_solana_channel_and_an_unread_wallet_is_a_warning() {
    // Nothing answers getTokenAccountsByOwner: the check cannot tell.
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(publisher_body("0", Value::Null))
        .await;
    world.rpc_answers(1_500_000_000).await;
    let report = world.report().await;
    assert!(report.funding.publisher.error.is_some());
    let outcome = check(&report, &thresholds());
    assert!(
        !any_contains(&outcome.problems, "publisher:"),
        "{outcome:?}"
    );
    assert!(
        any_contains(
            &outcome.warnings,
            "publisher: the channel is drained; the next write opens a fresh channel of \
             10000000 from the wallet, whose balance could not be read"
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn the_publisher_address_is_read_from_the_rendered_file() {
    let world = World::healthy().await;
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), format!("{PUBLISHER}\n")).unwrap();
    let mut args = world.args();
    args.publisher_address = None;
    args.publisher_address_file = Some(file.path().to_path_buf());
    let report = world.report_with(&world.config(), &args).await;
    assert_eq!(report.funding.publisher.units, Some(25_000_000));

    std::fs::write(file.path(), "").unwrap();
    let report = world.report_with(&world.config(), &args).await;
    assert!(report.funding.publisher.error.unwrap().contains("is empty"));
}

#[tokio::test]
async fn without_the_next_deposit_only_an_empty_wallet_is_short() {
    let world = solana_world("0", Value::Null, 1).await;
    let mut args = world.args();
    args.publisher_deposit = None;
    let report = world.report_with(&world.config(), &args).await;
    assert!(
        !any_contains(&problems(&report), "publisher:"),
        "{:?}",
        problems(&report)
    );

    let world = solana_world("0", Value::Null, 0).await;
    let args = ReportArgs {
        publisher_deposit: None,
        ..world.args()
    };
    let report = world.report_with(&world.config(), &args).await;
    let found = problems(&report);
    assert!(
        any_contains(&found, "holds 0, nothing to open the next channel with"),
        "{found:?}"
    );
}

#[tokio::test]
async fn a_sealing_key_mismatch_is_a_problem() {
    let world = World::new().await;
    let mut doc = healthy_doc();
    doc["identity"]["connector_identity"]["matches"] = json!(false);
    doc["identity"]["connector_identity"]["live_seal_key"] =
        json!("0x04ffffffffffffffffffffffffff");
    world.operator_answers(doc).await;
    let report = world.report().await;
    let found = problems(&report);
    assert!(any_contains(&found, "identity:"), "{found:?}");
    assert!(
        any_contains(&found, "every tenant will refuse to spawn"),
        "{found:?}"
    );
    assert!(render_text(&report).contains("MISMATCH"));
}

#[tokio::test]
async fn an_unanswered_seal_probe_is_only_a_warning() {
    let world = World::new().await;
    let mut doc = healthy_doc();
    doc["identity"]["connector_identity"] = json!({
        "reachable": false,
        "via_proxy": false,
        "live_seal_key": null,
        "matches": null,
        "error": "GET http://c/ilp/identity failed",
    });
    world.operator_answers(doc).await;
    let report = world.report().await;
    assert!(!any_contains(&problems(&report), "identity:"));
    assert!(any_contains(&warnings(&report), "identity:"));
}

#[tokio::test]
async fn sol_under_the_floor_is_a_problem() {
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(publisher_body("9997019", json!(1_209_600)))
        .await;
    world.rpc_answers(4_000_000).await;
    let found = problems(&world.report().await);
    assert!(
        any_contains(&found, "holds 0.004 SOL, under --min-sol 0.005"),
        "{found:?}"
    );
}

// ── A Hidden Provider ─────────────────────────────────────────────────────────

fn hidden(config: ProviderConfig, rpc: &str) -> ProviderConfig {
    ProviderConfig {
        hidden: true,
        public_ip: None,
        connector_url:
            "http://hiddenfixturehiddenfixturehiddenfixturehiddenfixturehidde.anyone/ilp"
                .to_string(),
        anon: AnonConfig {
            settlement_rpc_url: Some(rpc.to_string()),
            ..AnonConfig::default()
        },
        ..config
    }
}

#[tokio::test]
async fn a_hidden_provider_reads_its_balance_from_its_own_node_only() {
    let world = World::healthy().await;
    let config = hidden(world.config(), &world.rpc.uri());
    let mut args = world.args();
    // What the base compose file would hand it: a public RPC. Ignored.
    args.settlement_rpc_url = Some("https://api.devnet.solana.com".to_string());
    let sources = Sources::from_config(&config, &args);
    assert_eq!(
        sources.settlement_rpc_url.as_deref(),
        Ok(world.rpc.uri().as_str())
    );
    let report = gather(&sources, AT).await;
    assert_eq!(report.funding.lamports, Some(1_500_000_000));
    assert_eq!(
        report.funding.publisher.units,
        Some(25_000_000),
        "its own node is asked for the publisher's wallet too: {:?}",
        report.funding.publisher.error
    );
    assert_eq!(
        report.earnings.error, None,
        "compose-internal connector URL is near"
    );
}

#[tokio::test]
async fn a_hidden_provider_reads_a_public_rpc_only_through_anon_on_the_solana_circuit() {
    // ADR 0030's other option: a public RPC, reached through the proxy on
    // the circuit the connector keeps for Solana. The RPC is named by a
    // host nothing here resolves, so a direct dial could not have reached
    // it: the balance arriving is the proof it went through the stub.
    let world = World::healthy().await;
    let rpc_addr = *world.rpc.address();
    let socks = SocksStub::start(&[("solana-rpc.invalid", rpc_addr)]).await;
    let rpc = format!("http://solana-rpc.invalid:{}", rpc_addr.port());
    let config = ProviderConfig {
        anon: AnonConfig {
            socks_proxy: Some(socks.url()),
            settlement: SettlementRpcs {
                evm: None,
                solana: Some(SettlementRpc {
                    rpc_url: rpc.clone(),
                    rpc_via_socks_proxy: true,
                }),
            },
            ..AnonConfig::default()
        },
        ..hidden(world.config(), "unused")
    };
    let sources = Sources::from_config(&config, &world.args());
    assert_eq!(sources.settlement_rpc_url.as_deref(), Ok(rpc.as_str()));
    let report = gather(&sources, AT).await;
    assert_eq!(
        report.funding.lamports,
        Some(1_500_000_000),
        "{:?}",
        report.funding.error
    );
    assert!(socks.asked_for(&format!("solana-rpc.invalid:{}", rpc_addr.port())));
    // …and ONLY the connector's balance: the publisher's wallet asked on
    // that same circuit would link the two addresses at the RPC.
    assert_eq!(
        socks.usernames(),
        vec!["toon-settlement-solana".to_string()]
    );
    let error = report.funding.publisher.error.clone().unwrap();
    assert!(error.contains("not asked"), "{error}");
    assert_eq!(report.funding.publisher.units, None);

    // No proxy configured is not a direct dial: it is not asked at all.
    let unproxied = ProviderConfig {
        anon: AnonConfig {
            socks_proxy: None,
            ..config.anon.clone()
        },
        ..config.clone()
    };
    let sources = Sources::from_config(&unproxied, &world.args());
    let error = sources.settlement_rpc_url.expect_err("no proxy, no read");
    assert!(error.contains("not asked"), "{error}");
}

#[tokio::test]
async fn a_hidden_provider_dials_nothing_public() {
    let world = World::healthy().await;
    let config = ProviderConfig {
        publish_url: Some("http://198.51.100.7:8081/publish".to_string()),
        ..hidden(world.config(), "http://203.0.113.9:8899")
    };
    let mut args = world.args();
    args.connector_operator_url = None;
    let sources = Sources::from_config(&config, &args);
    for (what, source) in [
        ("publisher", &sources.publisher_status_url),
        ("connector", &sources.connector_operator_url),
        ("rpc", &sources.settlement_rpc_url),
    ] {
        let error = source.as_ref().expect_err(what);
        assert!(error.contains("not asked"), "{what}: {error}");
    }
    let doc = to_json(&gather(&sources, AT).await, None);
    assert!(doc["publisher"]["error"]
        .as_str()
        .unwrap()
        .contains("not asked"));
    assert!(doc["earnings"]["error"]
        .as_str()
        .unwrap()
        .contains(".anyone"));
    assert!(doc["funding"]["error"]
        .as_str()
        .unwrap()
        .contains("not asked"));
    assert_eq!(
        doc["earnings"]["dashboard_url"],
        "http://hiddenfixturehiddenfixturehiddenfixturehiddenfixturehidde.anyone/dashboard"
    );
}

// ── The binary ────────────────────────────────────────────────────────────────

fn write_config(world: &World, dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("provider.toml");
    std::fs::write(
        &path,
        format!(
            r#"
provider_name = "Fixture Provider"
public_ip = "203.0.113.7"
nostr_private_key = "1111111111111111111111111111111111111111111111111111111111111111"
connector_url = "https://proxy.provider.fixture.example/ilp"
connector_seal_key = "0x04325b06f4bcb438204ab86a36a715fdf409552da5cdc7cd28301b08088ce7c3a1bf4289f62ba89a707ed8d7db66b03cb2881ea5934e35f2d600c4cd7067ed0188"
relay_set = ["ws://relay.fixture.example:7100"]
operator_url = "{}"
publish_url = "{}/publish"
lease_state_path = "{}/leases.json"

[[settlement]]
chain = "solana"
token = "34eSxY7qxQ4GzyhDJ8GpUcTz1WWzruGbJbR8q6TtxfQU"
decimals = 6
"#,
            world.operator.uri(),
            world.publisher.uri(),
            dir.path().display()
        ),
    )
    .unwrap();
    path
}

fn run_binary(world: &World, config: &std::path::Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_toon-provider"))
        .env_clear()
        .env("TOON_PROVIDER_CONFIG", config)
        .env("TOON_CONNECTOR_OPERATOR_URL", world.connector.uri())
        .env("TOON_CONNECTOR_BEARER_TOKEN_FILE", world.token_file.path())
        .env("TOON_SETTLEMENT_SOLANA_ADDRESS", ADDRESS)
        .env("TOON_SETTLEMENT_SOLANA_RPC_URL", world.rpc.uri())
        .env("TOON_PUBLISHER_SOLANA_ADDRESS", PUBLISHER)
        .env("TOON_PUBLISHER_DEPOSIT", NEXT_DEPOSIT.to_string())
        .arg("status")
        .args(extra)
        .output()
        .expect("run toon-provider status")
}

#[tokio::test]
async fn the_binary_exits_zero_on_a_healthy_box_and_one_on_a_drained_publisher() {
    let dir = tempfile::tempdir().unwrap();
    let world = World::healthy().await;
    let config = write_config(&world, &dir);

    let out = run_binary(&world, &config, &["--check"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("toon-provider status --check: OK"),
        "{stdout}"
    );

    let out = run_binary(&world, &config, &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("\nFUNDING\n"));

    let out = run_binary(&world, &config, &["--json", "--check"]);
    let doc: Value = serde_json::from_slice(&out.stdout).expect("--json prints one document");
    assert_eq!(doc["check"]["ok"], true);
    assert_eq!(doc["version"], 1);

    let drained = World::new().await;
    drained.operator_answers(healthy_doc()).await;
    drained
        .publisher_answers(evm_publisher_body("0", Value::Null))
        .await;
    drained.connector_answers().await;
    drained.rpc_answers(1_500_000_000).await;
    let config = write_config(&drained, &dir);
    let out = run_binary(&drained, &config, &["--check"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("PROBLEM publisher: the channel"),
        "{stdout}"
    );
    assert!(stdout.contains("1 problem needs a person"), "{stdout}");

    // A threshold the operator sets on the command line.
    let out = run_binary(
        &world,
        &write_config(&world, &dir),
        &["--check", "--min-sol", "2"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("under --min-sol 2"), "{stdout}");
}

// ── `status --json --check` fixtures (TOON_Network#174) ─────────────────────
//
// `toon-provider dash` is a view over the document `status --json` prints,
// and its snapshot tests are fed these files. They are generated HERE, by
// the real `gather` over the stubbed sources above and the real `to_json`,
// with each stub's random port replaced by a fixed, compose-like address —
// so nothing in them is typed by hand. The suite verifies them byte for
// byte; `TOON_UPDATE_FIXTURES=1 cargo test --test status_cli` rewrites them.

fn status_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/status")
}

/// `status --json --check` for `world`, with its stubs' addresses fixed.
async fn status_json(world: &World, config: &ProviderConfig) -> String {
    let report = world.report_with(config, &world.args()).await;
    let doc = to_json(&report, Some(&check(&report, &thresholds())));
    let mut text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    for (server, fixed) in [
        (&world.operator, "http://127.0.0.1:8090"),
        (&world.publisher, "http://directory-publisher:8081"),
        (&world.connector, "http://provider-connector:4000"),
        (&world.rpc, "https://solana-rpc.fixture.example"),
    ] {
        text = text.replace(&server.uri(), fixed);
    }
    text
}

fn golden_status(name: &str, text: String) {
    let path = status_fixture_dir().join(format!("{name}.json"));
    if std::env::var_os("TOON_UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(status_fixture_dir()).unwrap();
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}. Generate it (TOON_UPDATE_FIXTURES=1 cargo test --test status_cli) and \
             commit the result.",
            path.display()
        )
    });
    assert_eq!(
        on_disk,
        text,
        "{} has drifted from what `status --json` prints; regenerate it \
         (TOON_UPDATE_FIXTURES=1 cargo test --test status_cli) and commit the result",
        path.display()
    );
}

#[tokio::test]
async fn status_json_fixture_healthy() {
    let world = World::healthy().await;
    golden_status("healthy", status_json(&world, &world.config()).await);
}

/// A box with something wrong in every section `--check` judges: the
/// sealing key mismatched, a relay refusing the latest Liveness, the
/// publisher drained with a wallet short of the next channel, the bearer
/// token refused, and the settlement key low on SOL.
#[tokio::test]
async fn status_json_fixture_troubled() {
    let world = World::new().await;
    let mut doc = fixture_doc();
    doc["started_at"] = json!(AT - 3_600);
    doc["identity"]["connector_identity"]["matches"] = json!(false);
    doc["identity"]["connector_identity"]["live_seal_key"] =
        json!("0x04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    world.operator_answers(doc).await;
    let mut body = publisher_body("0", Value::Null);
    body["spent"] = json!("10000000");
    world.publisher_answers(body).await;
    world.rpc_answers(4_000_000).await;
    world.wallet_answers(4_000_000).await;
    // No connector stub answers: every read is a 404.
    golden_status("troubled", status_json(&world, &world.config()).await);
}

#[tokio::test]
async fn status_json_fixture_provider_down() {
    let world = World::healthy().await;
    let config = ProviderConfig {
        operator_url: DEAD.to_string(),
        ..world.config()
    };
    golden_status("provider_down", status_json(&world, &config).await);
}

/// What `dash` reads back is what `status --json` printed: every fixture
/// parses into a `Report` that prints the same document again.
#[test]
fn every_status_json_fixture_reads_back_into_the_same_document() {
    let mut seen = 0;
    for entry in std::fs::read_dir(status_fixture_dir()).unwrap() {
        let path = entry.unwrap().path();
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let report = from_json(&doc).unwrap_or_else(|e| panic!("{}: {e:#}", path.display()));
        let mut again = to_json(&report, Some(&check(&report, &thresholds())));
        assert_eq!(again, doc, "{}", path.display());
        again.as_object_mut().unwrap().remove("check");
        assert_eq!(to_json(&report, None), again, "{}", path.display());
        seen += 1;
    }
    assert!(
        seen >= 3,
        "only {seen} fixtures under tests/fixtures/status"
    );
}

#[test]
fn a_document_that_is_not_a_status_is_refused() {
    assert!(from_json(&json!([1, 2])).is_err());
    assert!(from_json(&json!({ "version": 1 })).is_err());
}
