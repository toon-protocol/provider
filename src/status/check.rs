//! `--check`: the report as an exit code (ADR 0029 "Alerts are an exit
//! code"). A PROBLEM is something that needs a person and fails the check; a
//! WARNING is something the check could not decide, or that is worth a look,
//! and is printed without failing it — an alert that fires on "I could not
//! tell" teaches an operator to ignore it.

use crate::directory::RelayOutcome;

use super::gather::Report;
use super::{format_duration, format_sol};

/// The operator's thresholds (`--min-runway`, `--min-sol`).
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub min_runway_s: u64,
    pub min_lamports: u64,
}

/// What `--check` found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckOutcome {
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

impl CheckOutcome {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }

    /// One line per finding, then a verdict — what the journal shows for
    /// each run of `toon-provider-check.service`.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for problem in &self.problems {
            out.push_str(&format!("PROBLEM {problem}\n"));
        }
        for warning in &self.warnings {
            out.push_str(&format!("warning {warning}\n"));
        }
        if self.ok() {
            out.push_str(&format!(
                "toon-provider status --check: OK{}\n",
                match self.warnings.len() {
                    0 => String::new(),
                    1 => " (1 warning)".to_string(),
                    n => format!(" ({n} warnings)"),
                }
            ));
        } else {
            out.push_str(&format!(
                "toon-provider status --check: {} problem{} need{} a person \
                 (run `toon-provider status` for the whole report)\n",
                self.problems.len(),
                if self.problems.len() == 1 { "" } else { "s" },
                if self.problems.len() == 1 { "s" } else { "" },
            ));
        }
        out
    }
}

/// How many Liveness cadences of warning `--check` gives before a Liveness
/// expires. Each Liveness expires five cadences out (ADR 0007), so under two
/// left means at least three in a row have not landed anywhere.
pub const LIVENESS_WARNING_CADENCES: u64 = 2;

/// Everything wrong with `report`, by the rules of ADR 0029.
pub fn check(report: &Report, thresholds: &Thresholds) -> CheckOutcome {
    let mut out = CheckOutcome::default();
    check_provider(report, &mut out);
    check_publisher(report, thresholds, &mut out);
    check_earnings(report, &mut out);
    check_funding(report, thresholds, &mut out);
    out
}

fn check_provider(report: &Report, out: &mut CheckOutcome) {
    let Some(status) = &report.operator.status else {
        out.problems.push(format!(
            "provider: {}",
            report
                .operator
                .error
                .as_deref()
                .unwrap_or("the operator status could not be read")
        ));
        return;
    };

    // ── Identity: the sealing key every tenant pins ──────────────────────
    let probe = &status.identity.connector_identity;
    match probe.matches {
        Some(false) => out.problems.push(format!(
            "identity: the Profile's connector_seal_key {} is not the key the connector \
             reports ({}); every tenant will refuse to spawn",
            abbreviate(&status.identity.connector_seal_key),
            abbreviate(probe.live_seal_key.as_deref().unwrap_or("?")),
        )),
        Some(true) => {}
        None => out.warnings.push(format!(
            "identity: the sealing key could not be compared with the connector's: {}",
            probe
                .error
                .as_deref()
                .unwrap_or("the connector did not answer")
        )),
    }

    // ── Directory: listed, and staying listed ────────────────────────────
    let directory = &status.directory;
    if !directory.publishing {
        out.warnings.push(
            "directory: no publish_url is configured, so this provider is in no directory"
                .to_string(),
        );
        return;
    }
    let now = status.generated_at;
    let cadence = directory.liveness_cadence_s.max(1);
    // The first cadence after a restart, and the retry that ends it: a
    // publication that has not landed YET is not a problem. The live box
    // showed exactly this — "not attempted: dns error" right after a joint
    // restart, healed by the next cadence. Without `started_at` (a provider
    // from before it) there is no grace.
    let starting = status
        .started_at
        .is_some_and(|started| now < started.saturating_add(2 * cadence));

    match directory.liveness_expires_at {
        None if starting => {}
        None => out.problems.push(
            "directory: no relay has accepted a Liveness since the provider started, so it \
             reads as down everywhere"
                .to_string(),
        ),
        Some(expires) if expires <= now => out.problems.push(format!(
            "directory: the Liveness expired {} ago on every relay; this provider reads as down",
            format_duration(now - expires)
        )),
        Some(expires) if expires - now < LIVENESS_WARNING_CADENCES * cadence => {
            out.problems.push(format!(
                "directory: the Liveness expires in {}, under {LIVENESS_WARNING_CADENCES} \
                 cadences ({}s each), and nothing newer has landed",
                format_duration(expires - now),
                cadence
            ))
        }
        Some(_) => {}
    }

    for (relay, entries) in &directory.relays {
        let mut outcomes: Vec<(String, Option<&RelayOutcome>)> = vec![
            ("the Profile".to_string(), entries.profile.as_ref()),
            ("the Liveness".to_string(), entries.liveness.as_ref()),
        ];
        outcomes.extend(
            entries
                .listings
                .iter()
                .map(|(name, o)| (format!("the {name} Listing"), o.as_ref())),
        );
        for (what, outcome) in outcomes {
            match outcome {
                None if starting => {}
                None => out.problems.push(format!(
                    "directory: {relay}: {what} has not been offered to this relay since the \
                     provider started"
                )),
                Some(outcome) => {
                    let Some(refusal) = &outcome.refusal else {
                        continue;
                    };
                    if starting && outcome.last_accepted_at.is_none() {
                        continue;
                    }
                    let last = match outcome.last_accepted_at {
                        Some(at) => format!(
                            "last accepted {} ago",
                            format_duration(now.saturating_sub(at))
                        ),
                        None => "never accepted since the provider started".to_string(),
                    };
                    out.problems.push(format!(
                        "directory: {relay} refused the latest write of {what}: {refusal} ({last})"
                    ));
                }
            }
        }
    }
}

fn check_publisher(report: &Report, thresholds: &Thresholds, out: &mut CheckOutcome) {
    let publishing = report
        .operator
        .status
        .as_ref()
        .map(|s| s.directory.publishing);
    let section = &report.publisher;
    let Some(status) = &section.status else {
        let why = section
            .error
            .as_deref()
            .unwrap_or("the publisher's status could not be read");
        if section.url.is_none() && publishing != Some(true) {
            // No publisher configured, and the provider says it publishes
            // nothing: already a warning under directory.
            return;
        }
        out.problems.push(format!("publisher: {why}"));
        return;
    };
    if status.drained() {
        out.problems.push(format!(
            "publisher: the channel{} is drained (remaining 0 of {}); no directory write can \
             be paid for — `toon-provider topup <amount>`",
            status
                .channel_id
                .as_deref()
                .map(|c| format!(" {}", abbreviate(c)))
                .unwrap_or_default(),
            status.deposit.as_deref().unwrap_or("?"),
        ));
        return;
    }
    if status.channel_id.is_none() {
        out.warnings.push(
            "publisher: no channel has been opened yet, so there is nothing to measure a \
             runway on"
                .to_string(),
        );
        return;
    }
    match status.runway_s {
        Some(runway) if runway < thresholds.min_runway_s => out.problems.push(format!(
            "publisher: {} of runway left, under --min-runway {} (remaining {}) — \
             `toon-provider topup <amount>`",
            format_duration(runway),
            format_duration(thresholds.min_runway_s),
            status.remaining.as_deref().unwrap_or("?"),
        )),
        Some(_) => {}
        None => out.warnings.push(format!(
            "publisher: the runway is unknown{}",
            status
                .assumptions
                .first()
                .map(|a| format!(": {a}"))
                .unwrap_or_default()
        )),
    }
    if status.watermark_uncertain {
        out.warnings.push(
            "publisher: the channel's watermark is uncertain (a write's outcome was not \
             confirmed); spent may be understated"
                .to_string(),
        );
    }
}

fn check_earnings(report: &Report, out: &mut CheckOutcome) {
    // Nothing about earnings needs a person on a timer; not being able to
    // read them is worth a line, since redeeming needs the same surface.
    if let Some(error) = &report.earnings.error {
        out.warnings.push(format!("earnings: {error}"));
    }
}

fn check_funding(report: &Report, thresholds: &Thresholds, out: &mut CheckOutcome) {
    let section = &report.funding;
    match section.lamports {
        Some(lamports) if lamports < thresholds.min_lamports => out.problems.push(format!(
            "funding: the connector's Solana settlement address {} holds {} SOL, under \
             --min-sol {}; the connector cannot pay for its boot transaction",
            section.address.as_deref().unwrap_or("?"),
            format_sol(lamports),
            format_sol(thresholds.min_lamports),
        )),
        Some(_) => {}
        None => out.warnings.push(format!(
            "funding: the settlement key's SOL balance could not be read: {}",
            section.error.as_deref().unwrap_or("no answer")
        )),
    }
}

/// A long key or id as its first and last few characters.
pub(super) fn abbreviate(text: &str) -> String {
    if text.chars().count() <= 20 {
        return text.to_string();
    }
    let head: String = text.chars().take(10).collect();
    let tail: String = text
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}
