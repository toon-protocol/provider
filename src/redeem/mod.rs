//! `toon-provider redeem` (TOON_Network#173, ADR 0029 "Money: shown
//! everywhere, moved only by a person").
//!
//! Collects what payers have signed over to this provider's connector, one
//! channel at a time, and only when a person says so:
//!
//! 1. Lists each inbound channel with money unredeemed — the same claims
//!    joined to the same channels `toon-provider status` prints as earnings
//!    (`status::read_earnings_from`, bearer token) — and an estimated gas
//!    cost for its chain (`gas`).
//! 2. Picks channels: `--channel <id>` (repeatable), `--all-above
//!    <amount>`, or at the prompt. Then asks for a typed `yes`, unless
//!    `--yes`.
//! 3. Reads the operator key from stdin (`key`), and for each channel signs
//!    the connector's existing `POST /channels/:id/redeem-latest` exactly
//!    as `connector send` signs a write (`sign`): the connector submits the
//!    latest claim it holds on chain and answers the channel as it now
//!    stands.
//!
//! Nothing here runs on its own: no schedule, no threshold that fires
//! (ADR 0029 "Nothing is automatic").
//!
//! It runs inside the provider container (`docker compose exec provider
//! toon-provider redeem`, where the deploy bundle sets
//! `TOON_CONNECTOR_OPERATOR_URL` and `TOON_CONNECTOR_BEARER_TOKEN_FILE`), or
//! from a laptop against the public edge: `--connector
//! https://proxy.provider.<domain> --bearer-file <file>`. The operator
//! surface is on the edge: the bearer token gates the reads, the signature
//! the writes. A laptop needs no provider config.

pub mod gas;
pub mod key;
pub mod select;
pub mod sign;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{BufRead, IsTerminal, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::status::{connector_operator_url, error_chain, read_earnings_from, ChannelEarnings};
use gas::{chain_of, estimate, Chain, Estimate};
use sign::{keyid_hex, sign_write, SIGNATURE_TTL_SECONDS};

/// How long the listing's reads may take.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long one redeem may take: the connector answers only once the
/// transaction is confirmed on chain.
const REDEEM_TIMEOUT: Duration = Duration::from_secs(300);

/// `toon-provider redeem`'s flags.
///
/// The operator key is deliberately NOT one of them: it is read from stdin.
/// `--operator-key` (and `--key`, `--private-key`, `--secret-key`,
/// `--key-file`) and any stray argument are accepted by the parser only so
/// they can be refused without being repeated back.
#[derive(Debug, Clone, clap::Args)]
pub struct RedeemArgs {
    /// Redeem this channel, as `--list` prints its id. Repeatable.
    #[arg(long = "channel", value_name = "ID")]
    pub channels: Vec<String>,

    /// Redeem every channel with MORE than this many token base units
    /// unredeemed (e.g. `1000` = 0.001 USDC at 6dp).
    #[arg(long, value_name = "AMOUNT", conflicts_with = "channels")]
    pub all_above: Option<u128>,

    /// Print the channels and their gas estimates, and redeem nothing. Asks
    /// for no key.
    #[arg(long, conflicts_with_all = ["channels", "all_above", "yes"])]
    pub list: bool,

    /// Redeem without asking for a typed `yes` first.
    #[arg(long)]
    pub yes: bool,

    /// The connector's operator API: `http://provider-connector:4000`
    /// inside the provider container (the deploy bundle sets it), or
    /// `https://proxy.provider.<domain>` from a laptop. Unset, a public
    /// provider's `connector_url` origin, as `status` does.
    #[arg(
        long = "connector",
        visible_alias = "connector-operator-url",
        env = "TOON_CONNECTOR_OPERATOR_URL",
        value_name = "URL"
    )]
    pub connector: Option<String>,

    /// A file holding the connector's operator bearer token
    /// (`operator-bearer.token`, `OPERATOR_BEARER_TOKEN` in `.env`). It
    /// gates the reads; a redeem itself is authorised by the signature.
    #[arg(
        long = "bearer-file",
        visible_alias = "bearer-token-file",
        env = "TOON_CONNECTOR_BEARER_TOKEN_FILE",
        value_name = "FILE"
    )]
    pub bearer_file: Option<PathBuf>,

    /// The EVM RPC to read a gas price from, for the EVM estimate. Unset,
    /// the EVM estimate is "unknown"; nothing else changes.
    #[arg(long, env = "TOON_SETTLEMENT_EVM_RPC_URL", value_name = "URL")]
    pub evm_rpc_url: Option<String>,

    /// Refused: the operator key is read from stdin only.
    #[arg(
        long = "operator-key",
        aliases = ["key", "private-key", "secret-key", "key-file", "operator-key-file"],
        hide = true,
        num_args = 0..=1,
        value_name = "REFUSED"
    )]
    pub key_on_argv: Option<Option<String>>,

    /// Refused: `redeem` takes no positional argument, and one that is a
    /// key must not be echoed back in a parse error.
    #[arg(hide = true, value_name = "REFUSED")]
    pub stray: Vec<String>,
}

impl RedeemArgs {
    /// Refuse a key given on the command line, and any positional argument
    /// (the likeliest shape of one), without repeating it: by the time this
    /// runs it is already in `ps`, `/proc/<pid>/cmdline` and the shell's
    /// history, and the operator should know to replace it.
    pub fn refuse_key_on_argv(&self) -> Result<()> {
        if self.key_on_argv.is_some() {
            bail!(
                "refusing --operator-key: the operator key is read from stdin, never from the \
                 command line, where `ps`, /proc and your shell's history can read it. If you \
                 typed the real key, treat it as exposed: generate a new pair and replace \
                 OPERATOR_WRITE_KEY. Pipe the key in instead: `toon-provider redeem … < \
                 operator.key`, or type it at the prompt."
            );
        }
        if let Some(first) = self.stray.first() {
            let looks_like_a_key = self.stray.iter().any(|a| {
                let t = a.trim().trim_start_matches("0x");
                t.len() >= 32 && t.bytes().all(|b| b.is_ascii_hexdigit())
            });
            if looks_like_a_key {
                bail!(
                    "refusing a positional argument that looks like a key (not repeated here): \
                     the operator key is read from stdin, never from the command line. If it \
                     was the real key, treat it as exposed: generate a new pair and replace \
                     OPERATOR_WRITE_KEY."
                );
            }
            bail!(
                "redeem takes no positional argument ({} given, the first {} characters long); \
                 name channels with --channel <id>",
                self.stray.len(),
                first.len()
            );
        }
        Ok(())
    }
}

/// Where a question is asked and answered: the terminal, or nowhere when
/// there is none (the key is piped in and there is no `/dev/tty`).
pub trait Ask {
    fn ask(&mut self, question: &str) -> Result<String>;
}

/// The operator's terminal: stdin when stdin is one, else `/dev/tty` (the
/// key is on stdin), else none.
pub struct Terminal {
    reader: Option<Box<dyn BufRead>>,
}

impl Terminal {
    pub fn open(stdin_is_terminal: bool) -> Self {
        let reader: Option<Box<dyn BufRead>> = if stdin_is_terminal {
            Some(Box::new(std::io::stdin().lock()))
        } else {
            std::fs::File::open("/dev/tty")
                .ok()
                .map(|f| Box::new(std::io::BufReader::new(f)) as Box<dyn BufRead>)
        };
        Terminal { reader }
    }
}

impl Ask for Terminal {
    fn ask(&mut self, question: &str) -> Result<String> {
        let Some(reader) = self.reader.as_mut() else {
            bail!(
                "no terminal to ask on (stdin carries the key and there is no /dev/tty): name the \
                 channels with --channel or --all-above, and confirm with --yes"
            );
        };
        eprint!("{question}");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("reading the answer from the terminal")?;
        Ok(line)
    }
}

/// The channels to redeem: named, over a floor, or picked at the prompt.
pub fn choose(
    candidates: &[ChannelEarnings],
    args: &RedeemArgs,
    ask: &mut dyn Ask,
) -> Result<Vec<ChannelEarnings>> {
    if !args.channels.is_empty() {
        return select::by_ids(candidates, &args.channels);
    }
    if let Some(floor) = args.all_above {
        return Ok(select::above(candidates, floor));
    }
    let answer = ask.ask("Redeem which? Row numbers (1,3 or 2-4), `all`, or Enter for none: ")?;
    let picks = select::parse_picks(&answer, candidates.len())?;
    Ok(picks.into_iter().map(|i| candidates[i].clone()).collect())
}

/// Whether to go ahead: `--yes`, or a typed `yes`.
pub fn confirm(picked: &[ChannelEarnings], yes: bool, ask: &mut dyn Ask) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    let total: u128 = picked.iter().map(|c| c.unredeemed).sum();
    let answer = ask.ask(&format!(
        "Redeem {} channel{}, {total} token base units in all? Each is one on-chain transaction \
         the connector's settlement key pays gas for. Type \"yes\" to continue: ",
        picked.len(),
        if picked.len() == 1 { "" } else { "s" },
    ))?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

/// The table of redeemable channels, and how each chain's gas was
/// estimated.
pub fn render_table(
    base: &str,
    candidates: &[ChannelEarnings],
    estimates: &BTreeMap<Chain, Estimate>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Unredeemed earnings at {base} (token base units):\n");
    if candidates.is_empty() {
        let _ = writeln!(out, "  No inbound channel has anything unredeemed.");
        return out;
    }
    let _ = writeln!(
        out,
        "  {:>3}  {:<6}  {:>12}  {:<18}  channel",
        "#", "chain", "unredeemed", "est. gas"
    );
    for (i, c) in candidates.iter().enumerate() {
        let chain = chain_of(&c.channel_id);
        let gas = estimates
            .get(&chain)
            .map(Estimate::short)
            .unwrap_or_else(|| "unknown".into());
        let _ = writeln!(
            out,
            "  {:>3}  {:<6}  {:>12}  {:<18}  {}{}",
            i + 1,
            chain.to_string(),
            c.unredeemed,
            gas,
            c.channel_id,
            match c.status.as_deref() {
                Some("closed") => " (closed)",
                _ => "",
            }
        );
    }
    let total: u128 = candidates.iter().map(|c| c.unredeemed).sum();
    let _ = writeln!(
        out,
        "\n  total {total} across {} channel{}",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "s" }
    );
    for (chain, estimate) in estimates {
        let _ = writeln!(out, "  gas, {chain}: {}", estimate.basis());
    }
    let _ = writeln!(
        out,
        "  Gas is an estimate, paid by the connector's settlement key in the chain's own coin, \
         not out of the channel."
    );
    out
}

/// What one redeem came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The connector submitted the claim and answered the channel as it
    /// now stands (its `ChannelView`).
    Redeemed { channel: Value },
    /// The connector answered, and not with success.
    Refused { status: u16, body: String },
    /// The connector could not be asked, or its answer not read.
    Failed(String),
}

/// Sign and send `POST <base>/channels/<id>/redeem-latest`, valid from
/// `now` for [`SIGNATURE_TTL_SECONDS`]. The signed `@path` is the URL's own
/// path, which is what the connector sees behind the deploy bundle's nginx
/// (it passes the request URI through unchanged).
pub async fn redeem_one(
    client: &reqwest::Client,
    base: &str,
    key: &SigningKey,
    channel_id: &str,
    now: u64,
) -> Outcome {
    if channel_id.is_empty() || !channel_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Outcome::Failed(format!(
            "{channel_id:?} is not a channel id this command will put in a path"
        ));
    }
    let url = format!(
        "{}/channels/{channel_id}/redeem-latest",
        base.trim_end_matches('/')
    );
    let path = match url::Url::parse(&url) {
        Ok(parsed) => parsed.path().to_string(),
        Err(e) => return Outcome::Failed(format!("{url} is not a URL: {e}")),
    };
    let body: &[u8] = b"";
    let signed = sign_write(key, "POST", &path, body, now, now + SIGNATURE_TTL_SECONDS);
    let response = match client
        .post(&url)
        .header("content-digest", signed.content_digest)
        .header("signature-input", signed.signature_input)
        .header("signature", signed.signature)
        .body(body.to_vec())
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => return Outcome::Failed(format!("POST {url} failed: {}", error_chain(&e))),
    };
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if status.is_success() {
        match serde_json::from_str(&text) {
            Ok(channel) => Outcome::Redeemed { channel },
            Err(e) => Outcome::Failed(format!(
                "the connector answered {status} to POST {url}, and not JSON: {e}"
            )),
        }
    } else {
        Outcome::Refused {
            status: status.as_u16(),
            body: text.trim().to_string(),
        }
    }
}

/// One line per outcome.
pub fn render_outcome(channel: &ChannelEarnings, outcome: &Outcome, keyid: &str) -> String {
    match outcome {
        Outcome::Redeemed { channel: view } => {
            let after = view.get("redeemed").and_then(|v| {
                v.as_u64()
                    .map(u128::from)
                    .or_else(|| v.as_str()?.parse().ok())
            });
            match after {
                Some(after) => format!(
                    "  redeemed  {}: {} collected; the chain now shows {after} redeemed on this \
                     channel (was {}). The connector returns no transaction id: find it under \
                     the settlement key's address on the chain's explorer.",
                    channel.channel_id,
                    after.saturating_sub(channel.redeemed),
                    channel.redeemed
                ),
                None => format!(
                    "  redeemed  {}: the connector answered {view}",
                    channel.channel_id
                ),
            }
        }
        Outcome::Refused { status: 401, body } => format!(
            "  REFUSED   {}: 401, the connector refused the signature ({body}). Is keyid {keyid} \
             the OPERATOR_WRITE_KEY in operator-write.keys, and this machine's clock right?",
            channel.channel_id
        ),
        Outcome::Refused { status, body } => {
            format!("  REFUSED   {}: {status}, {body}", channel.channel_id)
        }
        Outcome::Failed(why) => format!("  FAILED    {}: {why}", channel.channel_id),
    }
}

/// Read the operator key from stdin: at a prompt with echo off when stdin
/// is a terminal, else the first line of what is piped in. Read through an
/// unbuffered handle, so no copy is left in std's stdin buffer.
fn read_key(stdin_is_terminal: bool) -> Result<SigningKey> {
    let _echo_off = stdin_is_terminal.then(|| {
        let guard = key::EchoOff::new();
        eprint!("Operator key (64 hex characters, not shown): ");
        std::io::stderr().flush().ok();
        guard
    });
    match std::fs::File::open("/dev/stdin") {
        Ok(file) => key::read_operator_key(file),
        // No /dev/stdin (not Linux or macOS): std's stdin, whose buffer is
        // not wiped. Still never written anywhere.
        Err(_) => key::read_operator_key(std::io::stdin().lock()),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run the command, returning the process exit code: 0 when every redeem
/// asked for succeeded (or none was asked for), 1 when any did not.
pub async fn run(config_path: &str, args: &RedeemArgs) -> Result<i32> {
    // First, before a config is read or anything is dialled.
    args.refuse_key_on_argv()?;

    // A laptop has no provider config; the box does.
    let config = if Path::new(config_path).exists() {
        Some(crate::load_config(config_path).with_context(|| format!("config: {config_path}"))?)
    } else {
        None
    };
    let hidden = config.as_ref().is_some_and(|c| c.hidden);
    let base = match &config {
        Some(config) => connector_operator_url(config, args.connector.as_deref()),
        None => match args.connector.as_deref().map(str::trim) {
            Some(url) if !url.is_empty() => Ok(url.trim_end_matches('/').to_string()),
            _ => Err(format!(
                "no connector to ask: pass --connector https://proxy.provider.<domain> from a \
                 laptop, or run this in the provider container, where TOON_CONNECTOR_OPERATOR_URL \
                 is set (and there is no config at {config_path} to fall back on)"
            )),
        },
    }
    .map_err(anyhow::Error::msg)?;

    // Nothing rides a proxy: an HTTP_PROXY in the environment must not see
    // the bearer token or the signed writes (as `status`).
    let read_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(READ_TIMEOUT)
        .build()?;
    let earnings = read_earnings_from(
        &read_client,
        &Ok(base.clone()),
        args.bearer_file.as_deref(),
        None,
    )
    .await;
    if let Some(error) = earnings.error {
        bail!("reading what the connector holds: {error}");
    }
    let candidates = select::redeemable(&earnings.channels);

    let mut estimates = BTreeMap::new();
    let chains: BTreeSet<Chain> = candidates.iter().map(|c| chain_of(&c.channel_id)).collect();
    for chain in chains {
        estimates.insert(
            chain,
            estimate(chain, args.evm_rpc_url.as_deref(), hidden).await,
        );
    }
    print!("{}", render_table(&base, &candidates, &estimates));
    if candidates.is_empty() || args.list {
        return Ok(0);
    }

    let stdin_is_terminal = std::io::stdin().is_terminal();
    let mut terminal = Terminal::open(stdin_is_terminal);
    let picked = choose(&candidates, args, &mut terminal)?;
    if picked.is_empty() {
        println!("\nNothing picked; nothing was redeemed.");
        return Ok(0);
    }
    if !confirm(&picked, args.yes, &mut terminal)? {
        println!("\nNot confirmed; nothing was redeemed.");
        return Ok(0);
    }
    drop(terminal);

    let key = read_key(stdin_is_terminal)?;
    let keyid = keyid_hex(&key);
    println!("\nSigning as keyid {keyid}:");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(REDEEM_TIMEOUT)
        .build()?;
    let mut failed = 0;
    for channel in &picked {
        let outcome = redeem_one(&client, &base, &key, &channel.channel_id, unix_now()).await;
        if !matches!(outcome, Outcome::Redeemed { .. }) {
            failed += 1;
        }
        println!("{}", render_outcome(channel, &outcome, &keyid));
    }
    // Wiped here (SigningKey zeroises on drop), before the summary.
    drop(key);
    println!("\n{} of {} redeemed.", picked.len() - failed, picked.len());
    Ok(if failed == 0 { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: RedeemArgs,
    }

    fn parse(argv: &[&str]) -> Result<RedeemArgs, clap::Error> {
        Cli::try_parse_from(std::iter::once("redeem").chain(argv.iter().copied())).map(|c| c.args)
    }

    const KEY: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    /// Answers each question from a script, and records them.
    struct Scripted(Vec<&'static str>, Vec<String>);
    impl Ask for Scripted {
        fn ask(&mut self, question: &str) -> Result<String> {
            self.1.push(question.to_string());
            if self.0.is_empty() {
                bail!("no terminal");
            }
            Ok(self.0.remove(0).to_string())
        }
    }

    fn channel(id: &str, unredeemed: u128) -> ChannelEarnings {
        ChannelEarnings {
            channel_id: id.into(),
            counterparty: None,
            status: Some("open".into()),
            deposited: None,
            claimed: unredeemed,
            redeemed: 0,
            unredeemed,
            last_redeemed_at: None,
        }
    }

    #[test]
    fn a_key_on_the_command_line_is_refused_and_not_repeated() {
        for argv in [
            vec!["--operator-key", KEY],
            vec![&*Box::leak(
                format!("--operator-key={KEY}").into_boxed_str(),
            )],
            vec!["--key", KEY],
            vec!["--private-key", KEY],
            vec!["--operator-key"],
            vec![KEY],
            vec!["--all-above", "1000", KEY],
        ] {
            let args = parse(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            let error = format!("{:#}", args.refuse_key_on_argv().unwrap_err());
            assert!(error.contains("refusing"), "{argv:?}: {error}");
            assert!(
                !error.contains(&KEY[..16]),
                "the refusal repeats the key: {error}"
            );
        }
        let stray = format!(
            "{:#}",
            parse(&["hello"]).unwrap().refuse_key_on_argv().unwrap_err()
        );
        assert!(
            stray.contains("no positional argument") && !stray.contains("hello"),
            "{stray}"
        );
        assert!(parse(&["--all-above", "1000", "--yes"])
            .unwrap()
            .refuse_key_on_argv()
            .is_ok());
    }

    #[test]
    fn channel_and_all_above_do_not_combine() {
        assert!(parse(&["--channel", "a", "--all-above", "1"]).is_err());
        assert!(parse(&["--list", "--yes"]).is_err());
        let args = parse(&["--channel", "a", "--channel", "b"]).unwrap();
        assert_eq!(args.channels, ["a", "b"]);
    }

    #[test]
    fn flags_choose_without_asking_and_the_prompt_picks_otherwise() {
        let evm = |n: u8| format!("0x{}", format!("{n:02x}").repeat(32));
        let candidates = [channel(&evm(1), 500), channel(&evm(2), 5_000)];

        let mut silent = Scripted(vec![], vec![]);
        let picked = choose(
            &candidates,
            &parse(&["--all-above", "1000"]).unwrap(),
            &mut silent,
        )
        .unwrap();
        assert_eq!(picked, [candidates[1].clone()]);
        let picked = choose(
            &candidates,
            &parse(&["--channel", &evm(1)]).unwrap(),
            &mut silent,
        )
        .unwrap();
        assert_eq!(picked, [candidates[0].clone()]);
        assert!(silent.1.is_empty(), "a flag selection asks nothing");

        let mut prompt = Scripted(vec!["2,1\n"], vec![]);
        let picked = choose(&candidates, &parse(&[]).unwrap(), &mut prompt).unwrap();
        assert_eq!(picked, [candidates[1].clone(), candidates[0].clone()]);

        let mut none = Scripted(vec![], vec![]);
        assert!(choose(&candidates, &parse(&[]).unwrap(), &mut none).is_err());
    }

    #[test]
    fn only_a_typed_yes_confirms_unless_yes_was_passed() {
        let picked = [channel("a", 1_000), channel("b", 2_000)];
        for (answer, expected) in [
            ("yes\n", true),
            ("YES", true),
            ("y\n", false),
            ("\n", false),
        ] {
            let mut ask = Scripted(vec![answer], vec![]);
            assert_eq!(
                confirm(&picked, false, &mut ask).unwrap(),
                expected,
                "{answer:?}"
            );
            assert!(ask.1[0].contains("2 channels, 3000"), "{}", ask.1[0]);
        }
        let mut silent = Scripted(vec![], vec![]);
        assert!(confirm(&picked, true, &mut silent).unwrap());
        assert!(silent.1.is_empty());
    }

    #[test]
    fn the_table_shows_each_chains_estimate_and_how_it_was_made() {
        let evm = format!("0x{}", "ab".repeat(32));
        let solana = "2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip";
        let estimates = BTreeMap::from([
            (
                Chain::Evm,
                Estimate::Evm {
                    gas: 160_000,
                    wei_per_gas: 30_000_000,
                },
            ),
            (Chain::Solana, Estimate::Solana { lamports: 10_000 }),
        ]);
        let text = render_table(
            "http://connector",
            &[channel(&evm, 2_400), channel(solana, 600)],
            &estimates,
        );
        assert!(text.contains("~0.0000048 ETH"), "{text}");
        assert!(text.contains("~0.00001 SOL"), "{text}");
        assert!(text.contains("total 3000 across 2 channels"), "{text}");
        assert!(text.contains("160000 gas x 0.03 gwei"), "{text}");
        let unknown = render_table(
            "http://connector",
            &[channel(&evm, 1)],
            &BTreeMap::from([(Chain::Evm, Estimate::Unknown("no EVM RPC".into()))]),
        );
        assert!(unknown.contains("unknown") && unknown.contains("gas, evm: no EVM RPC"));
    }
}
