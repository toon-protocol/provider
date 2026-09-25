//! `toon-provider status` (TOON_Network#172, ADR 0029 "What status says",
//! "Alerts are an exit code").
//!
//! One command answers, from the box: am I listed, am I funded, what have I
//! earned, what am I running. It reads four sources, each on its own, and a
//! source that does not answer is SHOWN as not answering rather than failing
//! the report — the rest of it is still worth reading when, say, the
//! publisher is down:
//!
//! | section                         | source                                                            |
//! |---------------------------------|-------------------------------------------------------------------|
//! | identity, directory, leases     | the running provider's `GET <operator_url>/operator/status`       |
//! | publisher                       | the publisher's `GET /status`, on `publish_url`'s origin          |
//! | earnings                        | the connector's operator reads `GET /claims`, `/channels`, `/audit-log`, with its bearer token |
//! | funding                         | `getBalance` of the connector's Solana settlement address         |
//!
//! Printed in ADR 0029's order, human-readable by default; `--json` prints
//! one document — the operator status document with `publisher`, `earnings`
//! and `funding` added beside its own sections, at the same `version`; and
//! `--check` turns the report into an exit code (`check`).
//!
//! Everything here is reachable from INSIDE the provider container, which is
//! where `docker compose exec provider toon-provider status` and the
//! `toon-provider-check.timer` run it: `deploy/docker-compose.yml` sets the
//! environment variables `StatusArgs` reads (the connector's compose-internal
//! address, the bearer token's read-only mount, the settlement address file
//! and the settlement RPC). `deploy/README.md` § "Is it working?" has the
//! details.

mod check;
mod gather;
mod render;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};

pub use check::{check, CheckOutcome, Thresholds};
pub use gather::{
    gather, ChannelEarnings, EarningsSection, FundingSection, OperatorSource, PublisherSection,
    PublisherStatus, Report, Sources,
};
// What `redeem` shares with `status`: the same connector, the same earnings.
pub(crate) use gather::{
    channel_key, connector_operator_url, error_chain, origin, read_earnings_from,
};
pub use render::{render_text, to_json};

use crate::provider::ProviderConfig;

/// How long each source may take to answer before it is reported as not
/// answering. One slow source delays the report by this much and no more.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(10);

/// 0.005 SOL: `deploy/keys.py`'s `MIN_LAMPORTS`, the floor below which the
/// connector cannot pay for the transaction it submits at boot.
pub const DEFAULT_MIN_SOL: &str = "0.005";

/// A week of publisher runway: long enough for an operator who reads the
/// journal once a week to top up before the Liveness stops.
pub const DEFAULT_MIN_RUNWAY: &str = "7d";

/// `toon-provider status`'s flags. Where a source is found is overridable
/// here, and each such flag has an environment variable, which is how the
/// deploy bundle's compose file points the command at the box's own
/// services without an operator typing any of it.
#[derive(Debug, Clone, clap::Args)]
pub struct StatusArgs {
    /// Print one JSON document instead of the human-readable report.
    #[arg(long)]
    pub json: bool,

    /// Exit non-zero, naming each problem, when something needs a person:
    /// Liveness close to expiry, a relay refusing the latest write, the
    /// publisher's runway short, the sealing key mismatched, or the
    /// settlement key low on SOL.
    #[arg(long)]
    pub check: bool,

    /// `--check` fails when the publisher's runway is under this: `7d`,
    /// `36h`, `90m`, `3600s` or plain seconds.
    #[arg(long, default_value = DEFAULT_MIN_RUNWAY, value_parser = parse_duration)]
    pub min_runway: u64,

    /// `--check` fails when the connector's Solana settlement address holds
    /// less than this many SOL.
    #[arg(long, default_value = DEFAULT_MIN_SOL, value_parser = parse_sol)]
    pub min_sol: u64,

    /// The connector's operator API (`GET /claims`, `/channels`), e.g.
    /// `http://provider-connector:4000`. Unset, a public provider uses its
    /// `connector_url`'s origin; a hidden one asks nothing, since that is an
    /// `.anyone` address.
    #[arg(long, env = "TOON_CONNECTOR_OPERATOR_URL")]
    pub connector_operator_url: Option<String>,

    /// A file holding the connector's operator bearer token — the one
    /// `deploy/render.sh` writes as `operator-bearer.token`.
    #[arg(long, env = "TOON_CONNECTOR_BEARER_TOKEN_FILE")]
    pub bearer_token_file: Option<PathBuf>,

    /// The connector's Solana settlement address (public).
    #[arg(long, env = "TOON_SETTLEMENT_SOLANA_ADDRESS")]
    pub settlement_address: Option<String>,

    /// A file holding the connector's Solana settlement address, as
    /// `deploy/render.sh` writes it (`settlement-solana.address`).
    #[arg(long, env = "TOON_SETTLEMENT_SOLANA_ADDRESS_FILE")]
    pub settlement_address_file: Option<PathBuf>,

    /// The Solana RPC the balance is read from. Ignored on a Hidden
    /// Provider, which reads only the one its config names
    /// (`[anon.settlement.solana]`, or the older `anon.settlement_rpc_url`)
    /// by the route it names: its own node directly, or a public one
    /// through anon (spec §10, ADR 0030).
    #[arg(long, env = "TOON_SETTLEMENT_SOLANA_RPC_URL")]
    pub settlement_rpc_url: Option<String>,
}

/// Run the command: gather, print, and return the process exit code — 0,
/// or 1 when `--check` found a problem.
pub async fn run(config: &ProviderConfig, args: &StatusArgs) -> Result<i32> {
    let sources = Sources::from_config(config, args);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let report = gather(&sources, now).await;
    let outcome = args.check.then(|| {
        check(
            &report,
            &Thresholds {
                min_runway_s: args.min_runway,
                min_lamports: args.min_sol,
            },
        )
    });

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&to_json(&report, outcome.as_ref()))?
        );
    } else if let Some(outcome) = &outcome {
        print!("{}", outcome.render());
    } else {
        print!("{}", render_text(&report));
    }
    Ok(match outcome {
        Some(outcome) if !outcome.ok() => 1,
        _ => 0,
    })
}

/// `7d`, `36h`, `90m`, `3600s` or plain seconds, as seconds.
pub fn parse_duration(text: &str) -> Result<u64> {
    let text = text.trim();
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => text.split_at(i),
        None => (text, "s"),
    };
    if digits.is_empty() {
        bail!("{text:?} is not a duration: a number, then d, h, m or s (e.g. 7d)");
    }
    let n: u64 = digits
        .parse()
        .with_context(|| format!("{text:?} is not a duration"))?;
    let scale = match unit {
        "d" => 86_400,
        "h" => 3_600,
        "m" => 60,
        "s" => 1,
        other => bail!("{other:?} is not a unit: use d, h, m or s (e.g. 7d)"),
    };
    n.checked_mul(scale)
        .with_context(|| format!("{text:?} is too long"))
}

/// A decimal SOL amount (`0.005`) as lamports, exactly: no float is
/// involved, so `0.005` is 5,000,000 and not 4,999,999.
pub fn parse_sol(text: &str) -> Result<u64> {
    let text = text.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits_only = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty()) || !digits_only(whole) || !digits_only(fraction) {
        bail!("{text:?} is not an amount of SOL (e.g. 0.005)");
    }
    if fraction.len() > 9 {
        bail!("{text:?} has more than 9 decimal places; a lamport is 0.000000001 SOL");
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().context("SOL amount too large")?
    };
    let fraction: u64 = format!("{fraction:0<9}").parse().unwrap_or(0);
    whole
        .checked_mul(1_000_000_000)
        .and_then(|w| w.checked_add(fraction))
        .context("SOL amount too large")
}

/// Lamports as SOL, to 9 places with trailing zeros dropped (`0.005`).
pub fn format_sol(lamports: u64) -> String {
    let whole = lamports / 1_000_000_000;
    let fraction = lamports % 1_000_000_000;
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:09}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

/// A number of seconds the way an operator reads it: `2d 3h`, `4m 10s`,
/// `45s` — the two largest units, no more.
pub fn format_duration(secs: u64) -> String {
    let units = [("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)];
    let mut parts = Vec::new();
    let mut rest = secs;
    for (name, size) in units {
        if rest >= size || (parts.is_empty() && size == 1) {
            parts.push(format!("{}{name}", rest / size));
            rest %= size;
        }
        if parts.len() == 2 {
            break;
        }
        if !parts.is_empty() && rest == 0 {
            break;
        }
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_in_each_unit() {
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        assert_eq!(parse_duration("36h").unwrap(), 129_600);
        assert_eq!(parse_duration("90m").unwrap(), 5_400);
        assert_eq!(parse_duration("3600s").unwrap(), 3_600);
        assert_eq!(parse_duration("3600").unwrap(), 3_600);
        assert!(parse_duration("d").is_err());
        assert!(parse_duration("7w").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn sol_parses_exactly() {
        assert_eq!(parse_sol("0.005").unwrap(), 5_000_000);
        assert_eq!(parse_sol("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_sol("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_sol(".25").unwrap(), 250_000_000);
        assert_eq!(parse_sol("0.000000001").unwrap(), 1);
        assert!(parse_sol("0.0000000001").is_err());
        assert!(parse_sol("-1").is_err());
        assert!(parse_sol("one").is_err());
        assert!(parse_sol(".").is_err());
    }

    #[test]
    fn sol_formats_without_trailing_zeros() {
        assert_eq!(format_sol(5_000_000), "0.005");
        assert_eq!(format_sol(1_000_000_000), "1");
        assert_eq!(format_sol(1_234_500_000), "1.2345");
        assert_eq!(format_sol(0), "0");
    }

    #[test]
    fn durations_format_with_two_units_at_most() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(250), "4m 10s");
        assert_eq!(format_duration(3_600), "1h");
        assert_eq!(format_duration(183_900), "2d 3h");
        assert_eq!(format_duration(604_800), "7d");
    }
}
