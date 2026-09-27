//! The dashboard's state, and what each key does to it. Pure: no terminal,
//! no network, no clock. A key or an update comes in, the state changes, and
//! at most one [`Effect`] comes out for `dash::run` to carry out, so every
//! step between a keypress and money moving is testable key by key.
//!
//! Money moves only through a dialog a single keypress cannot pass (ADR 0028
//! "Destructive and spending actions ask for confirmation", ADR 0029 "Money:
//! shown everywhere, moved only by a person"): `y` arms it, and only Enter
//! while armed confirms. Any other key disarms it.

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ed25519_dalek::SigningKey;
use zeroize::{Zeroize, Zeroizing};

use crate::redeem::gas::{chain_of, Chain, Estimate};
use crate::redeem::key::parse_operator_key;
use crate::redeem::select::redeemable;
use crate::status::{check, ChannelEarnings, CheckOutcome, Report, Section, Thresholds};
use crate::topup::validate_amount;

/// How often the report is read when the provider has not said its Liveness
/// cadence (it did not answer, or has not yet): a minute, the default
/// cadence.
pub const DEFAULT_CADENCE_S: u64 = 60;

/// The longest operator key line the field takes: a key and some slack. The
/// buffer is allocated at this size once and never grows, so it never
/// reallocates and leaves a copy of what was typed behind.
const KEY_FIELD: usize = 128;

/// How many hex characters an operator key is.
pub(super) const KEY_HEX: usize = 64;

/// The longest top-up amount the field takes, in digits.
const AMOUNT_FIELD: usize = 30;

/// What `dash::run` is asked to do.
// `Redeem` carries the signing key by value: boxing it would be one more
// copy of the key in memory, not one fewer, for an effect made once per
// keypress and consumed at once.
#[allow(clippy::large_enum_variant)]
pub enum Effect {
    Quit,
    /// Read every source again, now.
    Refresh,
    /// Estimate the gas to redeem these, per chain. `round` comes back with
    /// the answer, so one for a dialog since closed is not taken for the
    /// open one's.
    EstimateGas {
        round: u64,
        channels: Vec<ChannelEarnings>,
    },
    /// Redeem each of these, signing with `key`. The key lives exactly as
    /// long as the redeem does, and is wiped when it is dropped.
    Redeem {
        channels: Vec<ChannelEarnings>,
        key: SigningKey,
    },
    /// Add `amount` to the publisher's channel.
    Topup {
        amount: String,
    },
}

/// What `dash::run` tells the app.
pub enum Update {
    /// A fresh report.
    Report(Box<Report>),
    /// The gas estimates asked for with [`Effect::EstimateGas`].
    Estimates {
        round: u64,
        estimates: BTreeMap<Chain, Estimate>,
    },
    /// One redeem's outcome, as `toon-provider redeem` prints it.
    Redeemed(String),
    /// Every redeem asked for has an outcome.
    RedeemFinished,
    /// The publisher's answer to a top-up (its body), or why there was none.
    ToppedUp(Result<String, String>),
}

/// What a confirmed dialog does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spend {
    Redeem(Vec<ChannelEarnings>),
    Topup(String),
}

/// The dialog on top of the panes, if any.
#[derive(Debug, Clone, PartialEq)]
pub enum Modal {
    /// Which channels to redeem. `estimates` is `None` until they arrive.
    RedeemPick {
        candidates: Vec<ChannelEarnings>,
        picked: Vec<bool>,
        cursor: usize,
        estimates: Option<BTreeMap<Chain, Estimate>>,
        error: Option<String>,
    },
    /// A spend, shown in full, waiting for `y` then Enter.
    Confirm {
        title: String,
        lines: Vec<String>,
        armed: bool,
        spend: Spend,
    },
    /// The operator key, being typed. Only how many characters have been
    /// typed is here; what they are is held by the app alone.
    RedeemKey {
        channels: Vec<ChannelEarnings>,
        typed: usize,
        error: Option<String>,
    },
    /// The top-up amount, being typed.
    TopupAmount {
        input: String,
        error: Option<String>,
    },
    /// Money is moving; keys wait.
    Working { title: String, lines: Vec<String> },
    /// What happened; any key closes it.
    Done { title: String, lines: Vec<String> },
}

/// A pane's standing, by what `--check` says about its section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Fine,
    Warning,
    Problem,
}

pub struct App {
    thresholds: Thresholds,
    report: Option<Report>,
    outcome: CheckOutcome,
    modal: Option<Modal>,
    /// The operator key as typed, while `Modal::RedeemKey` is open.
    key_field: Zeroizing<String>,
    /// A line for the footer: why an action did not start.
    message: Option<String>,
    /// Which redeem dialog the gas estimates in flight are for.
    estimate_round: u64,
    focus: Section,
    scroll: BTreeMap<Section, u16>,
    /// How far each pane can scroll, as the last frame drew it.
    scroll_limit: BTreeMap<Section, u16>,
    refreshing: bool,
}

impl App {
    pub fn new(thresholds: Thresholds) -> Self {
        App {
            thresholds,
            report: None,
            outcome: CheckOutcome::default(),
            modal: None,
            key_field: Zeroizing::new(String::with_capacity(KEY_FIELD)),
            message: None,
            estimate_round: 0,
            focus: Section::Identity,
            scroll: BTreeMap::new(),
            scroll_limit: BTreeMap::new(),
            refreshing: true,
        }
    }

    pub fn report(&self) -> Option<&Report> {
        self.report.as_ref()
    }

    /// What `status --check` would say about the current report.
    pub fn outcome(&self) -> &CheckOutcome {
        &self.outcome
    }

    pub fn modal(&self) -> Option<&Modal> {
        self.modal.as_ref()
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The pane `Tab` has picked, which `j`/`k` scroll.
    pub fn focus(&self) -> Section {
        self.focus
    }

    /// How many lines `section`'s pane is scrolled down.
    pub fn scroll(&self, section: Section) -> u16 {
        self.scroll.get(&section).copied().unwrap_or(0)
    }

    /// How far each pane can scroll, as `view::draw` found it: the lines
    /// that did not fit.
    pub fn set_scroll_limits(&mut self, limits: BTreeMap<Section, u16>) {
        for (section, offset) in &mut self.scroll {
            *offset = (*offset).min(limits.get(section).copied().unwrap_or(0));
        }
        self.scroll_limit = limits;
    }

    /// Whether a read of the report is under way.
    pub fn refreshing(&self) -> bool {
        self.refreshing
    }

    /// A read of the report has started, on the cadence.
    pub fn start_refresh(&mut self) {
        self.refreshing = true;
    }

    /// How often the report is read: the provider's Liveness cadence.
    pub fn cadence_s(&self) -> u64 {
        self.report
            .as_ref()
            .and_then(|r| r.operator.status.as_ref())
            .map(|s| s.directory.liveness_cadence_s)
            .filter(|&c| c > 0)
            .unwrap_or(DEFAULT_CADENCE_S)
    }

    /// How `section`'s pane is drawn: a problem when `--check` fails on it,
    /// a warning when it only warns.
    pub fn tone(&self, section: Section) -> Tone {
        let about = |finding: &String| sections_of(finding).contains(&section);
        if self.outcome.problems.iter().any(about) {
            Tone::Problem
        } else if self.outcome.warnings.iter().any(about) {
            Tone::Warning
        } else {
            Tone::Fine
        }
    }

    pub fn apply(&mut self, update: Update) -> Option<Effect> {
        match update {
            Update::Report(report) => {
                self.outcome = check(&report, &self.thresholds);
                self.report = Some(*report);
                self.refreshing = false;
                None
            }
            Update::Estimates { round, estimates } => {
                if round != self.estimate_round {
                    return None;
                }
                match &mut self.modal {
                    Some(Modal::RedeemPick { estimates: e, .. }) => *e = Some(estimates),
                    // Enter came before the estimates did: the dialog that
                    // asks for the money shows them anyway.
                    Some(Modal::Confirm {
                        spend: Spend::Redeem(channels),
                        armed,
                        ..
                    }) => {
                        let armed = *armed;
                        let mut confirm = redeem_confirm(channels.clone(), Some(&estimates));
                        if let Modal::Confirm { armed: a, .. } = &mut confirm {
                            *a = armed;
                        }
                        self.modal = Some(confirm);
                    }
                    _ => {}
                }
                None
            }
            Update::Redeemed(line) => {
                if let Some(Modal::Working { lines, .. }) = &mut self.modal {
                    lines.push(line);
                }
                None
            }
            Update::RedeemFinished => {
                let lines = match self.modal.take() {
                    Some(Modal::Working { lines, .. }) => lines,
                    _ => Vec::new(),
                };
                self.modal = Some(Modal::Done {
                    title: "Redeem".into(),
                    lines,
                });
                self.refreshing = true;
                Some(Effect::Refresh)
            }
            Update::ToppedUp(answer) => {
                let lines = match answer {
                    Ok(body) => body.lines().map(str::to_string).collect(),
                    Err(error) => vec![error],
                };
                self.modal = Some(Modal::Done {
                    title: "Top up".into(),
                    lines,
                });
                self.refreshing = true;
                Some(Effect::Refresh)
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Effect> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            // Not while money is moving: quitting would drop the redeem or
            // top-up in flight, which the chain may still carry out, and the
            // operator would never see its outcome.
            if let Some(Modal::Working { lines, .. }) = &mut self.modal {
                const WAIT: &str = "(Ctrl-C waits: what was sent is not called back, so its \
                                    outcome is shown first)";
                if lines.last().map(String::as_str) != Some(WAIT) {
                    lines.push(WAIT.to_string());
                }
                return None;
            }
            return Some(Effect::Quit);
        }
        match self.modal.take() {
            None => self.key_on_panes(key),
            Some(modal) => self.key_on_modal(modal, key),
        }
    }

    fn key_on_panes(&mut self, key: KeyEvent) -> Option<Effect> {
        self.message = None;
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => Some(Effect::Quit),
            KeyCode::Char('u') => {
                self.refreshing = true;
                Some(Effect::Refresh)
            }
            KeyCode::Char('r') => self.open_redeem(),
            KeyCode::Char('t') => {
                self.open_topup();
                None
            }
            KeyCode::Tab => {
                self.focus = self.focus.next();
                None
            }
            KeyCode::BackTab => {
                self.focus = self.focus.prev();
                None
            }
            KeyCode::Char(c @ '1'..='6') => {
                self.focus = Section::ALL[c as usize - '1' as usize];
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let limit = self.scroll_limit.get(&self.focus).copied().unwrap_or(0);
                let offset = self.scroll.entry(self.focus).or_insert(0);
                *offset = offset.saturating_add(1).min(limit);
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let offset = self.scroll.entry(self.focus).or_insert(0);
                *offset = offset.saturating_sub(1);
                None
            }
            _ => None,
        }
    }

    fn open_redeem(&mut self) -> Option<Effect> {
        let Some(report) = &self.report else {
            self.message = Some("the status has not been read yet".into());
            return None;
        };
        if let Some(error) = &report.earnings.error {
            self.message = Some(format!(
                "nothing to redeem: the earnings could not be read ({error})"
            ));
            return None;
        }
        let candidates = redeemable(&report.earnings.channels);
        if candidates.is_empty() {
            self.message = Some("nothing to redeem: no channel has anything unredeemed".into());
            return None;
        }
        self.modal = Some(Modal::RedeemPick {
            picked: vec![false; candidates.len()],
            candidates: candidates.clone(),
            cursor: 0,
            estimates: None,
            error: None,
        });
        self.estimate_round += 1;
        Some(Effect::EstimateGas {
            round: self.estimate_round,
            channels: candidates,
        })
    }

    fn open_topup(&mut self) {
        match &self.report {
            Some(report) if report.publisher.url.is_some() => {
                self.modal = Some(Modal::TopupAmount {
                    input: String::new(),
                    error: None,
                });
            }
            Some(report) => {
                self.message = Some(format!(
                    "no publisher to top up: {}",
                    report
                        .publisher
                        .error
                        .as_deref()
                        .unwrap_or("none is configured")
                ));
            }
            None => self.message = Some("the status has not been read yet".into()),
        }
    }

    fn key_on_modal(&mut self, modal: Modal, key: KeyEvent) -> Option<Effect> {
        match modal {
            Modal::RedeemPick {
                candidates,
                mut picked,
                mut cursor,
                estimates,
                ..
            } => {
                let mut error = None;
                match key.code {
                    KeyCode::Esc => return None,
                    KeyCode::Down | KeyCode::Char('j') => {
                        cursor = (cursor + 1).min(candidates.len() - 1)
                    }
                    KeyCode::Up | KeyCode::Char('k') => cursor = cursor.saturating_sub(1),
                    KeyCode::Char(' ') => picked[cursor] = !picked[cursor],
                    KeyCode::Char('a') => {
                        let all = picked.iter().all(|&p| p);
                        picked.iter_mut().for_each(|p| *p = !all);
                    }
                    KeyCode::Enter => {
                        let chosen: Vec<ChannelEarnings> = candidates
                            .iter()
                            .zip(&picked)
                            .filter(|(_, &p)| p)
                            .map(|(c, _)| c.clone())
                            .collect();
                        if !chosen.is_empty() {
                            self.modal = Some(redeem_confirm(chosen, estimates.as_ref()));
                            return None;
                        }
                        error = Some("pick at least one channel (Space)".to_string());
                    }
                    _ => {}
                }
                self.modal = Some(Modal::RedeemPick {
                    candidates,
                    picked,
                    cursor,
                    estimates,
                    error,
                });
                None
            }

            Modal::Confirm {
                title,
                lines,
                armed,
                spend,
            } => match key.code {
                KeyCode::Enter if armed => match spend {
                    Spend::Redeem(channels) => {
                        self.key_field.clear();
                        self.modal = Some(Modal::RedeemKey {
                            channels,
                            typed: 0,
                            error: None,
                        });
                        None
                    }
                    Spend::Topup(amount) => {
                        self.modal = Some(Modal::Working {
                            title: "Top up".into(),
                            lines: vec![format!("adding {amount} to the publisher's channel…")],
                        });
                        Some(Effect::Topup { amount })
                    }
                },
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => None,
                code => {
                    // `y` arms it; anything else, a stray Enter included,
                    // disarms it.
                    let armed = matches!(code, KeyCode::Char('y') | KeyCode::Char('Y'));
                    self.modal = Some(Modal::Confirm {
                        title,
                        lines,
                        armed,
                        spend,
                    });
                    None
                }
            },

            Modal::RedeemKey {
                channels, error, ..
            } => {
                let mut error = error;
                match key.code {
                    KeyCode::Esc => {
                        self.wipe_key_field();
                        return None;
                    }
                    KeyCode::Char(c) if self.key_field.len() + c.len_utf8() <= KEY_FIELD => {
                        self.key_field.push(c);
                        error = None;
                    }
                    KeyCode::Backspace => {
                        self.key_field.pop();
                    }
                    KeyCode::Enter => {
                        let parsed = key_from_field(&self.key_field);
                        self.wipe_key_field();
                        match parsed {
                            Ok(key) => {
                                self.modal = Some(Modal::Working {
                                    title: "Redeem".into(),
                                    lines: vec![format!(
                                        "redeeming {} channel{}; each waits for its transaction \
                                         to confirm…",
                                        channels.len(),
                                        plural(channels.len())
                                    )],
                                });
                                return Some(Effect::Redeem { channels, key });
                            }
                            Err(e) => error = Some(e),
                        }
                    }
                    _ => {}
                }
                self.modal = Some(Modal::RedeemKey {
                    channels,
                    typed: self.key_field.chars().count(),
                    error,
                });
                None
            }

            Modal::TopupAmount { mut input, error } => {
                let mut error = error;
                match key.code {
                    KeyCode::Esc => return None,
                    KeyCode::Char(c) if c.is_ascii_digit() && input.len() < AMOUNT_FIELD => {
                        input.push(c);
                        error = None;
                    }
                    KeyCode::Backspace => {
                        input.pop();
                    }
                    KeyCode::Enter => match validate_amount(&input) {
                        Ok(()) => {
                            self.modal = Some(topup_confirm(input, self.report.as_ref()));
                            return None;
                        }
                        Err(e) => error = Some(format!("{e:#}")),
                    },
                    _ => {}
                }
                self.modal = Some(Modal::TopupAmount { input, error });
                None
            }

            // Money is moving: no key does anything until it has an outcome.
            working @ Modal::Working { .. } => {
                self.modal = Some(working);
                None
            }

            Modal::Done { .. } => None,
        }
    }

    /// Zero the typed key and empty the field. `zeroize` wipes the whole
    /// allocation, spare capacity included, and keeps it, so the next key
    /// typed lands in the same fixed-size buffer.
    fn wipe_key_field(&mut self) {
        self.key_field.zeroize();
    }
}

/// `"s"` unless there is exactly one.
pub(super) fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// The typed field as an operator key, or why it is not one, worded for this
/// field rather than for `redeem`'s stdin, and never repeating what was
/// typed.
fn key_from_field(field: &str) -> Result<SigningKey, String> {
    let trimmed = field.trim();
    if trimmed.is_empty() {
        return Err("type the operator key first".into());
    }
    parse_operator_key(trimmed.as_bytes()).map_err(|_| {
        format!(
            "that is not an operator key: it is {KEY_HEX} hex characters, and {} were typed{}. \
             The field is cleared; type it again.",
            trimmed.chars().count(),
            if trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                ""
            } else {
                ", not all of them hex"
            }
        )
    })
}

/// The panes a `--check` finding is about, by the section name every
/// finding starts with (`status::check`). `provider:` is the provider not
/// answering, which empties all three of its own panes.
pub fn sections_of(finding: &str) -> &'static [Section] {
    match finding.split_once(':').map(|(head, _)| head) {
        Some("identity") => &[Section::Identity],
        Some("directory") => &[Section::Directory],
        Some("publisher") => &[Section::Publisher],
        Some("earnings") => &[Section::Earnings],
        Some("funding") => &[Section::Funding],
        Some("provider") => &[Section::Identity, Section::Directory, Section::Leases],
        _ => &[],
    }
}

fn redeem_confirm(
    channels: Vec<ChannelEarnings>,
    estimates: Option<&BTreeMap<Chain, Estimate>>,
) -> Modal {
    let total: u128 = channels.iter().map(|c| c.unredeemed).sum();
    let mut lines: Vec<String> = channels
        .iter()
        .map(|c| {
            let chain = chain_of(&c.channel_id);
            format!(
                "{} {} on {chain}, gas {}",
                c.unredeemed,
                c.channel_id,
                estimates
                    .and_then(|e| e.get(&chain))
                    .map(Estimate::short)
                    .unwrap_or_else(|| "unknown".into())
            )
        })
        .collect();
    lines.push(String::new());
    lines.push(format!(
        "Redeem {} channel{}, {total} token base units in all? Each is one on-chain transaction \
         the connector's settlement key pays gas for. The operator key is asked next.",
        channels.len(),
        plural(channels.len()),
    ));
    Modal::Confirm {
        title: "Redeem".into(),
        lines,
        armed: false,
        spend: Spend::Redeem(channels),
    }
}

fn topup_confirm(amount: String, report: Option<&Report>) -> Modal {
    let status = report.and_then(|r| r.publisher.status.as_ref());
    let mut lines = vec![format!(
        "Add {amount} (token base units) to the publisher's channel{}?",
        status
            .and_then(|s| s.channel_id.as_deref())
            .map(|c| format!(" {c}"))
            .unwrap_or_default()
    )];
    if let Some(remaining) = status.and_then(|s| s.remaining.as_deref()) {
        lines.push(format!("It has {remaining} remaining now."));
    }
    lines.push("The publisher deposits it on chain from its own wallet.".into());
    Modal::Confirm {
        title: "Top up".into(),
        lines,
        armed: false,
        spend: Spend::Topup(amount),
    }
}
