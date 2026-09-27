//! `toon-provider dash` (TOON_Network#174, ADR 0029): a full-screen view over
//! the same report `toon-provider status` prints.
//!
//! Six panes in ADR 0029's order (identity, directory, publisher, leases,
//! earnings, funding), each holding what `status` prints under that heading.
//! The report is read again on the provider's Liveness cadence (and on `u`),
//! and whatever `status --check` would fail on is drawn in red.
//!
//! Two actions move money, both only through a dialog one keypress cannot
//! pass, and neither ever on its own (ADR 0029 "Nothing is automatic"):
//!
//! - **redeem** (`r`): the same channels `toon-provider redeem` offers, with
//!   the same gas estimates, then the operator key typed into a field that
//!   shows only how much has been typed. The key is held in memory while the
//!   redeems are signed and sent, then wiped; it is never written anywhere.
//!   Each redeem is `redeem::redeem_one`, exactly as the command sends it.
//! - **top up** (`t`): an amount, then the publisher's `POST /topup`, as
//!   `toon-provider topup` sends it.
//!
//! No eviction and no listing edits (ADR 0029). ANSI colours only, the
//! Console's visual rule (ADR 0028), and none of its code.
//!
//! The pieces: `app` is the state and what each key does to it, `view` draws
//! a frame from it, both pure. This file is the terminal and the network:
//! it reads keys, carries out each `Effect` in the background, and feeds the
//! outcome back as an `Update`.

mod app;
mod view;

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use crossterm::event::{Event, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

pub use app::{sections_of, App, Effect, Modal, Spend, Tone, Update};
pub use view::draw;

use crate::provider::ProviderConfig;
use crate::redeem::{
    estimates, redeem_one, render_outcome, sign::keyid_hex, unix_now, Outcome, REDEEM_TIMEOUT,
};
use crate::status::{connector_operator_url, gather, ReportArgs, Sources};

/// `toon-provider dash`'s flags: where the report is read from and what it
/// is judged by, as `status` takes them, and the EVM RPC `redeem` estimates
/// gas with.
#[derive(Debug, Clone, clap::Args)]
pub struct DashArgs {
    #[command(flatten)]
    pub report: ReportArgs,

    /// The EVM RPC to read a gas price from, for the redeem dialog's EVM
    /// estimate (as `toon-provider redeem --evm-rpc-url`).
    #[arg(long, env = "TOON_SETTLEMENT_EVM_RPC_URL", value_name = "URL")]
    pub evm_rpc_url: Option<String>,
}

/// What the loop hears: a key, or an effect's outcome.
enum Message {
    Key(crossterm::event::KeyEvent),
    Resize,
    Update(Update),
}

/// Puts the terminal back however `run` ends.
struct Screen;

impl Screen {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("switching the terminal to raw mode")?;
        let screen = Screen;
        std::io::stdout()
            .execute(EnterAlternateScreen)
            .context("opening the alternate screen")?;
        Ok(screen)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = std::io::stdout().execute(LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

pub async fn run(config: &ProviderConfig, args: &DashArgs) -> Result<()> {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        bail!(
            "dash needs a terminal: run it as `docker compose exec provider toon-provider dash` \
             (exec allocates one), or use `toon-provider status` for text or JSON"
        );
    }
    let sources = Sources::from_config(config, &args.report);
    let mut app = App::new(args.report.thresholds());
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Raw mode first, so no key is read cooked.
    let _screen = Screen::enter()?;
    // Keys, on a thread of their own: crossterm's read blocks.
    let keys = tx.clone();
    std::thread::spawn(move || loop {
        let message = match crossterm::event::read() {
            Ok(Event::Key(key)) if key.kind != KeyEventKind::Release => Message::Key(key),
            Ok(Event::Resize(..)) => Message::Resize,
            Ok(_) => continue,
            Err(_) => return,
        };
        if keys.send(message).is_err() {
            return;
        }
    });

    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    terminal.clear()?;

    let mut next_refresh = tokio::time::Instant::now();
    loop {
        let mut limits = None;
        terminal.draw(|frame| limits = Some(draw(frame, &app)))?;
        if let Some(limits) = limits {
            app.set_scroll_limits(limits);
        }

        let message = tokio::select! {
            message = rx.recv() => match message {
                Some(message) => message,
                None => return Ok(()),
            },
            _ = tokio::time::sleep_until(next_refresh) => {
                // One read at a time: the next is scheduled when it lands.
                next_refresh = far_future();
                refresh(&sources, &tx);
                app.start_refresh();
                continue;
            }
        };
        let effect = match message {
            Message::Key(key) => app.handle_key(key),
            Message::Resize => None,
            Message::Update(update) => {
                let fresh = matches!(update, Update::Report(_));
                let effect = app.apply(update);
                if fresh {
                    next_refresh =
                        tokio::time::Instant::now() + Duration::from_secs(app.cadence_s());
                }
                effect
            }
        };
        match effect {
            None => {}
            Some(Effect::Quit) => return Ok(()),
            Some(Effect::Refresh) => {
                next_refresh = far_future();
                refresh(&sources, &tx);
            }
            Some(Effect::EstimateGas { round, channels }) => {
                let (config, evm_rpc_url, tx) =
                    (config.clone(), args.evm_rpc_url.clone(), tx.clone());
                tokio::spawn(async move {
                    let estimates =
                        estimates(Some(&config), evm_rpc_url.as_deref(), &channels).await;
                    let _ = tx.send(Message::Update(Update::Estimates { round, estimates }));
                });
            }
            Some(Effect::Redeem { channels, key }) => {
                let base =
                    connector_operator_url(config, args.report.connector_operator_url.as_deref());
                let tx = tx.clone();
                tokio::spawn(async move {
                    let say = |line: String| {
                        let _ = tx.send(Message::Update(Update::Redeemed(line)));
                    };
                    match (base, client(REDEEM_TIMEOUT)) {
                        (Err(e), _) => say(format!("  not sent: {e}")),
                        (_, Err(e)) => say(format!("  not sent: {e:#}")),
                        (Ok(base), Ok(client)) => {
                            let keyid = keyid_hex(&key);
                            say(format!("signing as keyid {keyid}:"));
                            let mut redeemed = 0;
                            for channel in &channels {
                                let outcome = redeem_one(
                                    &client,
                                    &base,
                                    &key,
                                    &channel.channel_id,
                                    unix_now(),
                                )
                                .await;
                                if matches!(outcome, Outcome::Redeemed { .. }) {
                                    redeemed += 1;
                                }
                                say(render_outcome(channel, &outcome, &keyid));
                            }
                            say(format!("{redeemed} of {} redeemed.", channels.len()));
                        }
                    }
                    // Wiped here (SigningKey zeroises on drop), before the
                    // dialog says it is done.
                    drop(key);
                    let _ = tx.send(Message::Update(Update::RedeemFinished));
                });
            }
            Some(Effect::Topup { amount }) => {
                let (publish_url, tx) = (config.publish_url.clone(), tx.clone());
                tokio::spawn(async move {
                    let answer = match publish_url {
                        None => Err("no publish_url is configured".to_string()),
                        Some(url) => match crate::topup::send(&url, &amount).await {
                            Err(e) => Err(format!("{e:#}")),
                            Ok((status, body)) => {
                                let body = serde_json::to_string_pretty(&body)
                                    .unwrap_or_else(|_| body.to_string());
                                if status.is_success() {
                                    Ok(body)
                                } else {
                                    Err(format!("top-up refused: {status}\n{body}"))
                                }
                            }
                        },
                    };
                    let _ = tx.send(Message::Update(Update::ToppedUp(answer)));
                });
            }
        }
    }
}

/// Gather the report in the background.
fn refresh(sources: &Sources, tx: &mpsc::UnboundedSender<Message>) {
    let (sources, tx) = (sources.clone(), tx.clone());
    tokio::spawn(async move {
        let report = gather(&sources, unix_now()).await;
        let _ = tx.send(Message::Update(Update::Report(Box::new(report))));
    });
}

/// Nothing rides a proxy: an `HTTP_PROXY` in the environment must not see
/// the signed writes (as `toon-provider redeem`).
fn client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .build()?)
}

fn far_future() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(365 * 86_400)
}
