//! `toon-provider status` (TOON_Network#172, ADR 0029): the four sources it
//! reads, each stubbed with `wiremock` — the provider's own
//! `GET /operator/status`, the publisher's `GET /status`, the connector's
//! bearer-gated `GET /claims`, `/channels` and `/audit-log`, and a Solana
//! RPC's `getBalance` — and what it makes of them: six sections in ADR 0029's
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

use toon_provider::provider::AnonConfig;
use toon_provider::status::{
    check, gather, render_text, to_json, Report, Sources, StatusArgs, Thresholds,
};
use toon_provider::ProviderConfig;

const TOKEN: &str = "fixture-bearer-token";
const ADDRESS: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
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

    fn config(&self) -> ProviderConfig {
        ProviderConfig {
            provider_name: "Fixture Provider".to_string(),
            operator_url: self.operator.uri(),
            publish_url: Some(format!("{}/publish", self.publisher.uri())),
            connector_url: "https://proxy.provider.fixture.example/ilp".to_string(),
            ..ProviderConfig::default()
        }
    }

    fn args(&self) -> StatusArgs {
        StatusArgs {
            json: false,
            check: false,
            min_runway: 7 * 86_400,
            min_sol: 5_000_000,
            connector_operator_url: Some(self.connector.uri()),
            bearer_token_file: Some(self.token_file.path().to_path_buf()),
            settlement_address: Some(ADDRESS.to_string()),
            settlement_address_file: None,
            settlement_rpc_url: Some(self.rpc.uri()),
        }
    }

    async fn report(&self) -> Report {
        self.report_with(&self.config(), &self.args()).await
    }

    async fn report_with(&self, config: &ProviderConfig, args: &StatusArgs) -> Report {
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
        .publisher_answers(publisher_body("400000", json!(3 * 86_400)))
        .await;
    let found = problems(&world.report().await);
    assert!(
        any_contains(&found, "3d of runway left, under --min-runway 7d"),
        "{found:?}"
    );
}

#[tokio::test]
async fn the_runway_threshold_is_the_operators() {
    let world = World::new().await;
    world.operator_answers(healthy_doc()).await;
    world
        .publisher_answers(publisher_body("400000", json!(3 * 86_400)))
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
    let mut body = publisher_body("0", Value::Null);
    body["spent"] = json!("10000000");
    world.publisher_answers(body).await;
    let report = world.report().await;
    let found = problems(&report);
    assert!(
        any_contains(&found, "is drained (remaining 0 of 10000000)"),
        "{found:?}"
    );
    assert!(render_text(&report).contains("DRAINED"));
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
        report.earnings.error, None,
        "compose-internal connector URL is near"
    );
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
        .publisher_answers(publisher_body("0", Value::Null))
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
