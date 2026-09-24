//! Where each section comes from, and reading it. Every source is read on its
//! own and fails on its own: a failure is kept as that section's `error`,
//! never returned.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::{StatusArgs, SOURCE_TIMEOUT};
use crate::outbound_proxy::is_private_url;
use crate::provider::operator_status::{OperatorStatus, OPERATOR_STATUS_VERSION};
use crate::provider::ProviderConfig;
use crate::topup::publisher_origin;

/// Where each source is, resolved from the config and the flags. A source
/// that cannot be asked — not configured, or one a Hidden Provider must not
/// dial directly — is `Err` with the reason, which the report shows in its
/// place.
#[derive(Debug, Clone)]
pub struct Sources {
    /// `<operator_url>/operator/status`.
    pub operator_status_url: String,
    /// `<publisher origin>/status`.
    pub publisher_status_url: Result<String, String>,
    /// The connector operator API's base URL.
    pub connector_operator_url: Result<String, String>,
    /// Where the bearer token for it is read from.
    pub bearer_token_file: Option<PathBuf>,
    /// `<connector edge>/dashboard`, told to the operator in the earnings
    /// section (ADR 0029: `status` is where they learn it exists).
    pub dashboard_url: Option<String>,
    /// The connector's Solana settlement address.
    pub settlement_address: Result<String, String>,
    /// The Solana RPC the balance is read from.
    pub settlement_rpc_url: Result<String, String>,
    pub timeout: Duration,
}

impl Sources {
    pub fn from_config(config: &ProviderConfig, args: &StatusArgs) -> Self {
        let hidden = config.hidden;
        // A Hidden Provider dials nothing public directly: every source it
        // asks here must be on this box's own private network, which is
        // where the deploy bundle puts all of them (compose names and
        // loopback). Checked before anything is dialled.
        let near = |what: &str, url: String| -> Result<String, String> {
            if hidden && !is_private_url(&url) {
                Err(format!(
                    "not asked: {url} is not on this box's private network, and a hidden \
                     provider dials nothing else directly ({what})"
                ))
            } else {
                Ok(url)
            }
        };

        let operator_status_url = format!(
            "{}/operator/status",
            config.operator_url.trim_end_matches('/')
        );

        let publisher_status_url = match config.publish_url.as_deref() {
            None => Err("no publish_url is configured, so there is no publisher".to_string()),
            Some(publish_url) => match publisher_origin(publish_url) {
                Ok(origin) => near("the publisher", format!("{origin}/status")),
                Err(e) => Err(format!("{e:#}")),
            },
        };

        let connector_operator_url =
            connector_operator_url(config, args.connector_operator_url.as_deref());

        let dashboard_url = origin(&config.connector_url).map(|o| format!("{o}/dashboard"));

        let settlement_address = match (&args.settlement_address, &args.settlement_address_file) {
            (Some(address), _) if !address.trim().is_empty() => Ok(address.trim().to_string()),
            (_, Some(path)) => match std::fs::read_to_string(path) {
                Ok(text) if !text.trim().is_empty() => Ok(text.trim().to_string()),
                Ok(_) => Err(format!(
                    "{} is empty: deploy/render.sh writes it from settlement-solana.key, and \
                     wrote nothing (no key file, or no python3, on the box)",
                    path.display()
                )),
                Err(e) => Err(format!("reading {}: {e}", path.display())),
            },
            _ => Err(
                "the connector's Solana settlement address is not known here: set \
                 TOON_SETTLEMENT_SOLANA_ADDRESS or TOON_SETTLEMENT_SOLANA_ADDRESS_FILE"
                    .to_string(),
            ),
        };

        let settlement_rpc_url = if hidden {
            // Never a public RPC from a hidden box: its own node, which the
            // config gate has already required to be private (keys.py reads
            // HIDDEN_SETTLEMENT_SOLANA_RPC_URL for the same reason).
            match &config.anon.settlement_rpc_url {
                Some(url) => near("the settlement RPC", url.clone()),
                None => Err("anon.settlement_rpc_url is not set".to_string()),
            }
        } else {
            match &args.settlement_rpc_url {
                Some(url) if !url.trim().is_empty() => Ok(url.trim().to_string()),
                _ => Err(
                    "no Solana RPC to ask: set TOON_SETTLEMENT_SOLANA_RPC_URL (the deploy \
                     bundle sets it from SETTLEMENT_SOLANA_RPC_URL)"
                        .to_string(),
                ),
            }
        };

        Sources {
            operator_status_url,
            publisher_status_url,
            connector_operator_url,
            bearer_token_file: args.bearer_token_file.clone(),
            dashboard_url,
            settlement_address,
            settlement_rpc_url,
            timeout: SOURCE_TIMEOUT,
        }
    }
}

/// The connector's operator API base URL: `explicit` when given (on a
/// Hidden Provider only if it is on this box's private network), else a
/// public provider's `connector_url` origin. Shared by `status` and
/// `redeem`, which must ask the same connector.
pub(crate) fn connector_operator_url(
    config: &ProviderConfig,
    explicit: Option<&str>,
) -> Result<String, String> {
    match explicit {
        Some(url) if !url.trim().is_empty() => {
            let url = url.trim().trim_end_matches('/').to_string();
            if config.hidden && !is_private_url(&url) {
                Err(format!(
                    "not asked: {url} is not on this box's private network, and a hidden \
                     provider dials nothing else directly (the connector's operator API)"
                ))
            } else {
                Ok(url)
            }
        }
        _ if config.hidden => Err(
            "not asked: a hidden provider's connector_url is an .anyone address; set \
             TOON_CONNECTOR_OPERATOR_URL to its compose-internal address (the deploy \
             bundle sets http://provider-connector:4000)"
                .to_string(),
        ),
        _ => match origin(&config.connector_url) {
            Some(origin) => Ok(origin),
            None => Err(
                "no connector_url is configured and TOON_CONNECTOR_OPERATOR_URL is not set"
                    .to_string(),
            ),
        },
    }
}

/// `scheme://host[:port]` of `url`, or `None` for an empty or unparseable
/// one.
pub(crate) fn origin(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{}://{}:{}", parsed.scheme(), host, port),
        None => format!("{}://{}", parsed.scheme(), host),
    })
}

/// Everything `status` read, source by source.
#[derive(Debug, Clone)]
pub struct Report {
    /// This machine's clock when the report was gathered — used only when
    /// the provider did not answer, since its `generated_at` is otherwise
    /// the instant everything is measured against.
    pub now: u64,
    pub operator: OperatorSource,
    pub publisher: PublisherSection,
    pub earnings: EarningsSection,
    pub funding: FundingSection,
}

impl Report {
    /// The instant the report describes: the provider's `generated_at`
    /// when it answered, else this machine's clock.
    pub fn at(&self) -> u64 {
        self.operator
            .status
            .as_ref()
            .map(|s| s.generated_at)
            .unwrap_or(self.now)
    }
}

/// The running provider's own document.
#[derive(Debug, Clone)]
pub struct OperatorSource {
    pub url: String,
    /// The document verbatim, so `--json` passes on every field, including
    /// any this build does not know.
    pub raw: Option<Value>,
    /// The same document, read.
    pub status: Option<OperatorStatus>,
    pub error: Option<String>,
}

/// The publisher's `GET /status` (tools/publisher/status.mjs).
#[derive(Debug, Clone)]
pub struct PublisherSection {
    pub url: Option<String>,
    pub raw: Option<serde_json::Map<String, Value>>,
    pub status: Option<PublisherStatus>,
    pub error: Option<String>,
}

/// The fields of the publisher's answer `status` reads. Amounts are decimal
/// strings in the token's base units, as the publisher sends them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PublisherStatus {
    #[serde(rename = "channelId", default)]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(default)]
    pub deposit: Option<String>,
    #[serde(default)]
    pub spent: Option<String>,
    #[serde(default)]
    pub remaining: Option<String>,
    #[serde(rename = "watermarkUncertain", default)]
    pub watermark_uncertain: bool,
    #[serde(default)]
    pub runway_s: Option<u64>,
    #[serde(default)]
    pub assumptions: Vec<String>,
}

impl PublisherStatus {
    /// Whether the channel is known to hold nothing more: a deposit is
    /// recorded and `remaining` is zero.
    pub fn drained(&self) -> bool {
        self.remaining
            .as_deref()
            .and_then(|r| r.parse::<u128>().ok())
            .is_some_and(|r| r == 0)
    }
}

/// What the connector says this provider has earned.
#[derive(Debug, Clone, Default)]
pub struct EarningsSection {
    pub url: Option<String>,
    pub dashboard_url: Option<String>,
    pub channels: Vec<ChannelEarnings>,
    /// Why the claims and channels could not be read, when they could not.
    pub error: Option<String>,
    /// Why the audit log (last redeemed) could not be read, when only it
    /// could not.
    pub audit_error: Option<String>,
}

impl EarningsSection {
    pub fn total_unredeemed(&self) -> u128 {
        self.channels.iter().map(|c| c.unredeemed).sum()
    }
}

/// One channel a payer holds with this provider's connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEarnings {
    pub channel_id: String,
    pub counterparty: Option<String>,
    /// `open`, `closed` or `settled`; `None` for a channel the connector
    /// holds claims on but did not list.
    pub status: Option<String>,
    /// What the payer deposited: the most that can ever be redeemed.
    pub deposited: Option<u128>,
    /// The latest inbound claim's cumulative amount: everything the payer
    /// has signed over.
    pub claimed: u128,
    /// What has been redeemed on chain.
    pub redeemed: u128,
    /// `claimed - redeemed`: what a redeem would collect now.
    pub unredeemed: u128,
    /// The latest redeem write the connector's audit log holds for the
    /// channel — since the connector started, since the log is in memory.
    pub last_redeemed_at: Option<u64>,
}

/// The connector's settlement key's SOL balance.
#[derive(Debug, Clone)]
pub struct FundingSection {
    pub address: Option<String>,
    /// The RPC's origin only: an RPC URL's path or query often carries an
    /// API key, and the report must be safe to paste.
    pub rpc: Option<String>,
    pub lamports: Option<u64>,
    pub error: Option<String>,
}

/// Read every source, concurrently, each on its own.
pub async fn gather(sources: &Sources, now: u64) -> Report {
    let client = reqwest::Client::builder()
        // Every source here is on this box: nothing rides a proxy, and an
        // `HTTP_PROXY` in the environment must not quietly send the bearer
        // token somewhere else.
        .no_proxy()
        .timeout(sources.timeout)
        .build()
        .unwrap_or_default();
    let (operator, publisher, earnings, funding) = tokio::join!(
        read_operator(&client, sources),
        read_publisher(&client, sources),
        read_earnings(&client, sources),
        read_funding(&client, sources),
    );
    Report {
        now,
        operator,
        publisher,
        earnings,
        funding,
    }
}

/// An error and its causes on one line: reqwest's own `Display` stops at
/// "error sending request", which says nothing an operator can act on.
pub(crate) fn error_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

/// `GET url` → JSON, with every failure worded for the report.
async fn get_json(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
) -> Result<Value, String> {
    let mut request = client.get(url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("GET {url} failed: {}", error_chain(&e)))?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED && bearer.is_some() {
        return Err(format!(
            "GET {url} answered 401: the connector refused the bearer token"
        ));
    }
    if !status.is_success() {
        return Err(format!("GET {url} answered {status}"));
    }
    response
        .json()
        .await
        .map_err(|e| format!("GET {url} did not answer JSON: {}", error_chain(&e)))
}

async fn read_operator(client: &reqwest::Client, sources: &Sources) -> OperatorSource {
    let url = sources.operator_status_url.clone();
    match get_json(client, &url, None).await {
        Err(e) => OperatorSource {
            error: Some(format!("{e} — is the provider running?")),
            url,
            raw: None,
            status: None,
        },
        Ok(raw) => match serde_json::from_value::<OperatorStatus>(raw.clone()) {
            Ok(status) if status.version == OPERATOR_STATUS_VERSION => OperatorSource {
                url,
                raw: Some(raw),
                status: Some(status),
                error: None,
            },
            Ok(status) => OperatorSource {
                error: Some(format!(
                    "the provider answered status version {}, and this command reads version \
                     {OPERATOR_STATUS_VERSION}",
                    status.version
                )),
                url,
                raw: Some(raw),
                status: None,
            },
            Err(e) => OperatorSource {
                error: Some(format!(
                    "{url} answered a document this command cannot read: {e}"
                )),
                url,
                raw: None,
                status: None,
            },
        },
    }
}

async fn read_publisher(client: &reqwest::Client, sources: &Sources) -> PublisherSection {
    let url = match &sources.publisher_status_url {
        Ok(url) => url.clone(),
        Err(e) => {
            return PublisherSection {
                url: None,
                raw: None,
                status: None,
                error: Some(e.clone()),
            }
        }
    };
    let failed = |error: String| PublisherSection {
        url: Some(url.clone()),
        raw: None,
        status: None,
        error: Some(error),
    };
    let raw = match get_json(client, &url, None).await {
        Ok(Value::Object(raw)) => raw,
        Ok(_) => return failed(format!("{url} did not answer a JSON object")),
        Err(e) => return failed(format!("{e} — is directory-publisher running?")),
    };
    match serde_json::from_value::<PublisherStatus>(Value::Object(raw.clone())) {
        Ok(status) => PublisherSection {
            url: Some(url),
            raw: Some(raw),
            status: Some(status),
            error: None,
        },
        Err(e) => failed(format!(
            "{url} answered a status this command cannot read: {e}"
        )),
    }
}

/// The connector's `ChannelView`, as much of it as is read.
#[derive(Deserialize)]
struct ChannelView {
    id: String,
    #[serde(default)]
    counterparty: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    deposited: Option<u128>,
    #[serde(default)]
    redeemed: u128,
}

/// The connector's `ClaimView`, as much of it as is read.
#[derive(Deserialize)]
struct ClaimView {
    channel_id: String,
    direction: String,
    cumulative_amount: u64,
}

/// The connector's `AuditRecord`: one accepted operator write.
#[derive(Deserialize)]
struct AuditRecord {
    method: String,
    path: String,
    created: u64,
}

/// One channel id however the connector spells it: `GET /channels` answers
/// the bare id and a client-edge claim row the chain-prefixed key
/// (`evm:0x…`, `solana:…`), and an EVM id's hex case is not significant.
pub(crate) fn channel_key(id: &str) -> String {
    let bare = id
        .strip_prefix("evm:")
        .or_else(|| id.strip_prefix("solana:"))
        .unwrap_or(id);
    let hex = bare.strip_prefix("0x").unwrap_or(bare);
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        format!("0x{}", hex.to_ascii_lowercase())
    } else {
        bare.to_string()
    }
}

async fn read_earnings(client: &reqwest::Client, sources: &Sources) -> EarningsSection {
    read_earnings_from(
        client,
        &sources.connector_operator_url,
        sources.bearer_token_file.as_deref(),
        sources.dashboard_url.clone(),
    )
    .await
}

/// The connector's inbound claims joined to its channels (and the audit
/// log's last redeem), from the operator API at `connector_operator_url`
/// with the bearer token in `bearer_token_file`. What `status` prints as
/// earnings and what `redeem` offers to collect.
pub(crate) async fn read_earnings_from(
    client: &reqwest::Client,
    connector_operator_url: &Result<String, String>,
    bearer_token_file: Option<&std::path::Path>,
    dashboard_url: Option<String>,
) -> EarningsSection {
    let mut section = EarningsSection {
        dashboard_url,
        ..Default::default()
    };
    let base = match connector_operator_url {
        Ok(base) => base.clone(),
        Err(e) => {
            section.error = Some(e.clone());
            return section;
        }
    };
    section.url = Some(base.clone());
    let token = match bearer_token_file {
        None => {
            section.error = Some(
                "no bearer token: set TOON_CONNECTOR_BEARER_TOKEN_FILE to the rendered \
                 operator-bearer.token"
                    .to_string(),
            );
            return section;
        }
        Some(path) => match std::fs::read_to_string(path) {
            Ok(token) if !token.trim().is_empty() => token.trim().to_string(),
            Ok(_) => {
                section.error = Some(format!("{} is empty", path.display()));
                return section;
            }
            Err(e) => {
                section.error = Some(format!("reading the bearer token {}: {e}", path.display()));
                return section;
            }
        },
    };

    let (claims_url, channels_url, audit_url) = (
        format!("{base}/claims"),
        format!("{base}/channels"),
        format!("{base}/audit-log"),
    );
    let (claims, channels, audit) = tokio::join!(
        get_json(client, &claims_url, Some(&token)),
        get_json(client, &channels_url, Some(&token)),
        get_json(client, &audit_url, Some(&token)),
    );
    let claims: Vec<ClaimView> = match claims
        .and_then(|v| serde_json::from_value(v).map_err(|e| format!("GET {base}/claims: {e}")))
    {
        Ok(claims) => claims,
        Err(e) => {
            section.error = Some(e);
            return section;
        }
    };
    let channels: Vec<ChannelView> = match channels
        .and_then(|v| serde_json::from_value(v).map_err(|e| format!("GET {base}/channels: {e}")))
    {
        Ok(channels) => channels,
        Err(e) => {
            section.error = Some(e);
            return section;
        }
    };
    let audit: Vec<AuditRecord> = match audit
        .and_then(|v| serde_json::from_value(v).map_err(|e| format!("GET {base}/audit-log: {e}")))
    {
        Ok(audit) => audit,
        Err(e) => {
            section.audit_error = Some(e);
            Vec::new()
        }
    };

    // The latest redeem write per channel: `POST /channels/:id/redeem` or
    // `/redeem-latest`.
    let mut last_redeemed: BTreeMap<String, u64> = BTreeMap::new();
    for record in &audit {
        if !record.method.eq_ignore_ascii_case("POST") {
            continue;
        }
        let Some(rest) = record.path.strip_prefix("/channels/") else {
            continue;
        };
        let Some((id, action)) = rest.split_once('/') else {
            continue;
        };
        if action == "redeem" || action == "redeem-latest" {
            let at = last_redeemed.entry(channel_key(id)).or_insert(0);
            *at = (*at).max(record.created);
        }
    }

    // The latest inbound claim per channel: a claim's amount is cumulative,
    // so the largest is everything signed over.
    let mut claimed: BTreeMap<String, u128> = BTreeMap::new();
    for claim in claims.iter().filter(|c| c.direction == "inbound") {
        let amount = claimed.entry(channel_key(&claim.channel_id)).or_insert(0);
        *amount = (*amount).max(u128::from(claim.cumulative_amount));
    }

    let mut rows: BTreeMap<String, ChannelEarnings> = BTreeMap::new();
    for channel in channels {
        let key = channel_key(&channel.id);
        let claimed_here = claimed.remove(&key).unwrap_or(0);
        rows.insert(
            key.clone(),
            ChannelEarnings {
                channel_id: channel.id,
                counterparty: channel.counterparty,
                status: channel.status,
                deposited: channel.deposited,
                claimed: claimed_here,
                redeemed: channel.redeemed,
                unredeemed: claimed_here.saturating_sub(channel.redeemed),
                last_redeemed_at: last_redeemed.get(&key).copied(),
            },
        );
    }
    // Claims on a channel the connector did not list: still money held.
    for (key, amount) in claimed {
        rows.insert(
            key.clone(),
            ChannelEarnings {
                channel_id: key.clone(),
                counterparty: None,
                status: None,
                deposited: None,
                claimed: amount,
                redeemed: 0,
                unredeemed: amount,
                last_redeemed_at: last_redeemed.get(&key).copied(),
            },
        );
    }
    section.channels = rows.into_values().collect();
    section
}

async fn read_funding(client: &reqwest::Client, sources: &Sources) -> FundingSection {
    let mut section = FundingSection {
        address: sources.settlement_address.as_ref().ok().cloned(),
        rpc: sources
            .settlement_rpc_url
            .as_ref()
            .ok()
            .map(|u| origin(u).unwrap_or_else(|| "(unparseable RPC URL)".to_string())),
        lamports: None,
        error: None,
    };
    let address = match &sources.settlement_address {
        Ok(address) => address.clone(),
        Err(e) => {
            section.error = Some(e.clone());
            return section;
        }
    };
    let rpc = match &sources.settlement_rpc_url {
        Ok(rpc) => rpc.clone(),
        Err(e) => {
            section.error = Some(e.clone());
            return section;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address, { "commitment": "confirmed" }],
    });
    let shown = section.rpc.clone().unwrap_or_default();
    let answer: Result<Value, String> = async {
        let response = client
            .post(&rpc)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("getBalance at {shown} failed: {}", error_chain(&e)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("getBalance at {shown} answered {status}"));
        }
        response
            .json()
            .await
            .map_err(|e| format!("getBalance at {shown} did not answer JSON: {e}"))
    }
    .await;
    match answer {
        Err(e) => section.error = Some(e),
        Ok(answer) => {
            if let Some(error) = answer.get("error") {
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| error.to_string());
                section.error = Some(format!("getBalance at {shown} refused: {message}"));
            } else {
                match answer.pointer("/result/value").and_then(Value::as_u64) {
                    Some(lamports) => section.lamports = Some(lamports),
                    None => {
                        section.error =
                            Some(format!("getBalance at {shown} answered no result.value"))
                    }
                }
            }
        }
    }
    section
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_key_ignores_the_chain_prefix_and_hex_case() {
        let hex = "AB".repeat(32);
        assert_eq!(
            channel_key(&format!("evm:0x{hex}")),
            channel_key(&format!("0x{}", hex.to_lowercase()))
        );
        assert_eq!(channel_key(&hex), channel_key(&format!("0x{hex}")));
        assert_eq!(
            channel_key("solana:9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"),
            "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
        );
    }

    #[test]
    fn origin_keeps_scheme_host_and_port_only() {
        assert_eq!(
            origin("https://proxy.provider.example/ilp").as_deref(),
            Some("https://proxy.provider.example")
        );
        assert_eq!(
            origin("https://rpc.example:8899/?api-key=secret").as_deref(),
            Some("https://rpc.example:8899")
        );
        assert_eq!(origin(""), None);
    }
}
