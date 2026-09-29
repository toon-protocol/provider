//! The report, printed: six sections in ADR 0029's order — identity,
//! directory, publisher, leases, earnings, funding — for a person, or one
//! JSON document for a program.

use std::fmt::Write as _;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::directory::{RefusalKind, RelayOutcome};
use crate::nostr::wire::LeaseState;
use crate::provider::operator_status::{OperatorStatus, OPERATOR_STATUS_VERSION};

use super::check::{abbreviate, CheckOutcome};
use super::gather::{
    ChannelEarnings, EarningsSection, FundingSection, OperatorSource, PublisherSection,
    PublisherStatus, PublisherWallet, Report,
};
use super::{format_duration, format_sol};

/// `t` relative to `now`: `4m 10s ago`, `in 2h`.
fn relative(now: u64, t: u64) -> String {
    if t <= now {
        format!("{} ago", format_duration(now - t))
    } else {
        format!("in {}", format_duration(t - now))
    }
}

/// A serde enum's wire name (`running`, `standby`).
fn wire_name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(s)) => s,
        Ok(other) => other.to_string(),
        Err(_) => "?".to_string(),
    }
}

/// The report's six sections, in ADR 0029's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    Identity,
    Directory,
    Publisher,
    Leases,
    Earnings,
    Funding,
}

impl Section {
    pub const ALL: [Section; 6] = [
        Section::Identity,
        Section::Directory,
        Section::Publisher,
        Section::Leases,
        Section::Earnings,
        Section::Funding,
    ];

    /// The section after this one, round to the first.
    pub fn next(self) -> Section {
        Section::ALL[(self.index() + 1) % Section::ALL.len()]
    }

    /// The section before this one, round to the last.
    pub fn prev(self) -> Section {
        Section::ALL[(self.index() + Section::ALL.len() - 1) % Section::ALL.len()]
    }

    fn index(self) -> usize {
        Section::ALL.iter().position(|&s| s == self).unwrap_or(0)
    }

    /// The heading `render_text` prints it under.
    pub fn title(self) -> &'static str {
        match self {
            Section::Identity => "IDENTITY",
            Section::Directory => "DIRECTORY",
            Section::Publisher => "PUBLISHER",
            Section::Leases => "LEASES",
            Section::Earnings => "EARNINGS",
            Section::Funding => "FUNDING",
        }
    }
}

/// The human-readable report.
pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    let now = report.at();
    let status = report.operator.status.as_ref();

    match status {
        Some(s) => {
            let _ = writeln!(
                out,
                "toon-provider status: {} ({})",
                s.identity.provider_name,
                match s.started_at {
                    Some(started) => format!("up {}", format_duration(now.saturating_sub(started))),
                    None => "uptime unknown".to_string(),
                }
            );
        }
        None => {
            let _ = writeln!(out, "toon-provider status");
        }
    }

    for section in Section::ALL {
        let _ = writeln!(out, "\n{}", section.title());
        out.push_str(&section_text(report, section));
        if section == Section::Earnings {
            earnings_hints(&mut out, &report.earnings);
        }
    }
    out
}

/// One section's lines, as `render_text` prints them under its heading —
/// also what each of `toon-provider dash`'s panes shows.
pub fn section_text(report: &Report, section: Section) -> String {
    let mut out = String::new();
    let now = report.at();
    let status = report.operator.status.as_ref();
    match section {
        Section::Identity => match status {
            None => unreachable_line(&mut out, report.operator.error.as_deref()),
            Some(s) => {
                let id = &s.identity;
                let _ = writeln!(out, "  npub          {}", id.npub);
                let _ = writeln!(out, "  ILP address   {}", id.ilp_address);
                let _ = writeln!(
                    out,
                    "  mode          {}",
                    if id.hidden {
                        "hidden (reached only at .anyone addresses)"
                    } else {
                        "public"
                    }
                );
                let probe = &id.connector_identity;
                let verdict = match probe.matches {
                    Some(true) => "matches the connector's live key".to_string(),
                    Some(false) => format!(
                        "MISMATCH: the connector reports {}; tenants will refuse to spawn",
                        abbreviate(probe.live_seal_key.as_deref().unwrap_or("?"))
                    ),
                    None => format!(
                        "not compared: {}",
                        probe
                            .error
                            .as_deref()
                            .unwrap_or("the connector did not answer")
                    ),
                };
                let _ = writeln!(
                    out,
                    "  sealing key   {} — {verdict}",
                    abbreviate(&id.connector_seal_key)
                );
            }
        },
        Section::Directory => match status {
            None => unreachable_line(&mut out, report.operator.error.as_deref()),
            Some(s) if !s.directory.publishing => {
                let _ = writeln!(
                    out,
                    "  not publishing: no publish_url is configured, so this provider is in no \
                     directory"
                );
            }
            Some(s) => {
                let d = &s.directory;
                let _ = writeln!(
                    out,
                    "  Liveness every {}s; {}",
                    d.liveness_cadence_s,
                    match d.liveness_expires_at {
                        Some(t) if t > now => format!("the latest expires {}", relative(now, t)),
                        Some(t) => format!("EXPIRED {} on every relay", relative(now, t)),
                        None => "no relay has accepted one since the provider started".to_string(),
                    }
                );
                for (relay, entries) in &d.relays {
                    let _ = writeln!(out, "  {relay}");
                    outcome_line(&mut out, now, "profile", entries.profile.as_ref());
                    outcome_line(&mut out, now, "liveness", entries.liveness.as_ref());
                    for (name, outcome) in &entries.listings {
                        outcome_line(&mut out, now, &format!("listing {name}"), outcome.as_ref());
                    }
                }
            }
        },
        Section::Publisher => {
            let p = &report.publisher;
            match &p.status {
                None => unreachable_line(&mut out, p.error.as_deref()),
                Some(ps) => {
                    let _ = writeln!(
                        out,
                        "  channel       {}",
                        match (&ps.channel_id, &ps.chain) {
                            (Some(id), Some(chain)) => format!("{id} on {chain}"),
                            (Some(id), None) => id.clone(),
                            _ => "none opened yet".to_string(),
                        }
                    );
                    let _ = writeln!(
                        out,
                        "  deposit       {}   spent {}   remaining {}   (token base units)",
                        ps.deposit.as_deref().unwrap_or("unknown"),
                        ps.spent.as_deref().unwrap_or("unknown"),
                        ps.remaining.as_deref().unwrap_or("unknown"),
                    );
                    let _ = writeln!(
                        out,
                        "  runway        {}",
                        match ps.runway_s {
                            Some(r) =>
                                format!("{} at the current Liveness cadence", format_duration(r)),
                            None => format!(
                                "unknown{}",
                                ps.assumptions
                                    .first()
                                    .map(|a| format!(" — {a}"))
                                    .unwrap_or_default()
                            ),
                        }
                    );
                    let wallet = &report.funding.publisher;
                    match (ps.drained(), ps.on_solana(), wallet.short()) {
                        (false, _, _) => {}
                        // Replaced, never topped up: the wallet decides.
                        (true, true, Some(true)) => {
                            let _ = writeln!(
                                out,
                                "  DRAINED: no directory write can be paid for until the wallet \
                                 {} holds {} (it holds {}).",
                                wallet.address.as_deref().unwrap_or("?"),
                                next_deposit(wallet),
                                wallet.units.unwrap_or(0),
                            );
                        }
                        (true, true, _) => {
                            let _ = writeln!(
                                out,
                                "  spent: the next write opens a fresh channel of {} from the \
                                 publisher's wallet.",
                                next_deposit(wallet),
                            );
                        }
                        (true, false, _) => {
                            let _ = writeln!(
                                out,
                                "  DRAINED: no directory write can be paid for. Top up with \
                                 `toon-provider topup <amount>`."
                            );
                        }
                    }
                    if ps.watermark_uncertain {
                        let _ = writeln!(
                            out,
                            "  the channel watermark is uncertain: spent may be understated"
                        );
                    }
                }
            }
        }
        Section::Leases => match status {
            None => unreachable_line(&mut out, report.operator.error.as_deref()),
            Some(s) => {
                let l = &s.leases;
                if l.listings.is_empty() {
                    let _ = writeln!(out, "  no listing is on sale");
                }
                for (name, use_) in &l.listings {
                    let _ = writeln!(
                        out,
                        "  {name} v{}: {} of {} in use, {} available — {} per {}s{}",
                        use_.version,
                        use_.live,
                        use_.capacity,
                        use_.available,
                        use_.price,
                        use_.lease_interval_s,
                        use_.standby_price
                            .map(|p| format!(" ({p} standby)"))
                            .unwrap_or_default(),
                    );
                }
                if l.leases.is_empty() {
                    let _ = writeln!(out, "  no leases");
                }
                for lease in &l.leases {
                    let ports: Vec<String> = lease
                        .ports
                        .iter()
                        .map(|p| format!("{}→{}", p.container_port, p.host_port))
                        .collect();
                    let _ = writeln!(
                        out,
                        "  #{} {} v{} {} {}, {} {}; ssh {}{}{}; billed {}{}",
                        lease.id,
                        lease.listing,
                        lease.listing_version,
                        wire_name(&lease.role),
                        lease_state_name(&lease.state),
                        match lease.ended_at {
                            Some(_) => "expired",
                            None => "expires",
                        },
                        relative(now, lease.ended_at.unwrap_or(lease.expires_at)),
                        lease.ssh_port,
                        if ports.is_empty() {
                            String::new()
                        } else {
                            format!(", ports {}", ports.join(" "))
                        },
                        lease
                            .hidden_address
                            .as_deref()
                            .map(|a| format!(", at {a}"))
                            .unwrap_or_default(),
                        lease
                            .billed
                            .map(|b| b.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        if lease.billed_estimated {
                            " (estimated)"
                        } else {
                            ""
                        },
                    );
                }
            }
        },
        Section::Earnings => {
            let e = &report.earnings;
            match &e.error {
                Some(error) => unreachable_line(&mut out, Some(error)),
                None => {
                    if e.channels.is_empty() {
                        let _ = writeln!(out, "  no payer has opened a channel yet");
                    }
                    for c in &e.channels {
                        let _ = writeln!(
                            out,
                            "  {}{}: claimed {}, redeemed {}, unredeemed {}; last redeemed {}",
                            abbreviate(&c.channel_id),
                            c.status
                                .as_deref()
                                .map(|s| format!(" ({s})"))
                                .unwrap_or_default(),
                            c.claimed,
                            c.redeemed,
                            c.unredeemed,
                            match c.last_redeemed_at {
                                Some(t) => relative(now, t),
                                None => "not since the connector started".to_string(),
                            }
                        );
                    }
                    let _ = writeln!(
                        out,
                        "  total unredeemed {} (token base units)",
                        e.total_unredeemed()
                    );
                    if let Some(error) = &e.audit_error {
                        let _ = writeln!(out, "  (last redeemed unknown: {error})");
                    }
                }
            }
        }
        Section::Funding => {
            let f = &report.funding;
            match f.lamports {
                Some(lamports) => {
                    let _ = writeln!(
                        out,
                        "  settlement    {} holds {} SOL (read from {})",
                        f.address.as_deref().unwrap_or("?"),
                        format_sol(lamports),
                        f.rpc.as_deref().unwrap_or("?"),
                    );
                }
                None => unreachable_line(&mut out, f.error.as_deref()),
            }
            let w = &f.publisher;
            match w.units {
                Some(units) => {
                    let _ = writeln!(
                        out,
                        "  publisher     {} holds {} of {}; {}",
                        w.address.as_deref().unwrap_or("?"),
                        units,
                        w.token.as_deref().unwrap_or("?"),
                        match w.next_deposit {
                            Some(n) => format!("the next channel takes {n}"),
                            None => "the next channel's size is unknown (TOON_PUBLISHER_DEPOSIT)"
                                .to_string(),
                        },
                    );
                }
                None => {
                    let _ = writeln!(
                        out,
                        "  publisher     unavailable: {}",
                        w.error.as_deref().unwrap_or("this source did not answer")
                    );
                }
            }
        }
    }
    out
}

/// What the publisher's next channel takes, for a sentence.
fn next_deposit(wallet: &PublisherWallet) -> String {
    match wallet.next_deposit {
        Some(n) => n.to_string(),
        None => "(TOON_DEPOSIT)".to_string(),
    }
}

/// Where the rest of the earnings story is: `redeem`, and the connector's
/// dashboard. Printed by `status`, not in `dash`, which redeems itself.
fn earnings_hints(out: &mut String, e: &EarningsSection) {
    let _ = writeln!(
        out,
        "  To collect it: `toon-provider redeem` lists each channel with a gas estimate and \
         redeems the ones you pick, or `--all-above <amount>`; it reads the operator key from \
         stdin (deploy/README.md \"Redeeming earnings\")."
    );
    let _ = writeln!(
        out,
        "  Every claim and channel in full: the connector's dashboard{}, signed in with the \
         operator bearer token.",
        match &e.dashboard_url {
            Some(url) => format!(
                " at {url} (or http://127.0.0.1:4000/dashboard through \
                 `ssh -L 4000:127.0.0.1:4000` to this box)"
            ),
            None => " at <connector edge>/dashboard".to_string(),
        },
    );
}

fn unreachable_line(out: &mut String, error: Option<&str>) {
    let _ = writeln!(
        out,
        "  unavailable: {}",
        error.unwrap_or("this source did not answer")
    );
}

fn outcome_line(out: &mut String, now: u64, what: &str, outcome: Option<&RelayOutcome>) {
    let text = match outcome {
        None => "not offered since the provider started".to_string(),
        Some(o) => match &o.refusal {
            None => format!(
                "accepted {}{}",
                relative(now, o.last_accepted_at.unwrap_or(o.last_attempt_at)),
                o.expires_at
                    .map(|t| format!(", expires {}", relative(now, t)))
                    .unwrap_or_default()
            ),
            // A relay's own "no" is REFUSED; a write that never reached a
            // relay to be refused — the directory publisher was not
            // reachable — is NOT SENT (TOON_Network#178). `None` (a
            // document from before this field, or one written by
            // something else) reads as a refusal, the safer of the two to
            // assume when it is not known which it was.
            Some(refusal) => {
                let verdict = match o.kind {
                    Some(RefusalKind::NotSent) => "NOT SENT",
                    Some(RefusalKind::Refused) | None => "REFUSED",
                };
                format!(
                    "{verdict} {}: {refusal}{}",
                    relative(now, o.last_attempt_at),
                    match o.last_accepted_at {
                        Some(t) => format!(" (last accepted {})", relative(now, t)),
                        None => String::new(),
                    }
                )
            }
        },
    };
    let _ = writeln!(out, "    {what:<14}{text}");
}

/// The lease state, for a person: `provisioning`, `reserved`, `running`,
/// `stopped`, or for an ended lease `ended (<reason>)` — `expiry`,
/// `termination` or `eviction` — rather than `wire_name`'s verbatim
/// externally-tagged JSON, `{"ended":"termination"}` (TOON_Network#178).
fn lease_state_name(state: &LeaseState) -> String {
    match state {
        LeaseState::Ended(reason) => format!("ended ({})", wire_name(reason)),
        other => wire_name(other),
    }
}

/// The report as one JSON document: the provider's own status document, with
/// `publisher`, `earnings` and `funding` beside its `identity`, `directory`
/// and `leases`, at the same `version`; and `check` when `--check` ran.
/// A source that did not answer is a section holding only `error`.
pub fn to_json(report: &Report, outcome: Option<&CheckOutcome>) -> Value {
    let mut doc: Map<String, Value> = match &report.operator.raw {
        Some(Value::Object(raw)) if report.operator.status.is_some() => raw.clone(),
        _ => {
            let error = json!({
                "error": report.operator.error.clone().unwrap_or_else(|| "no answer".to_string()),
                "url": report.operator.url,
            });
            let mut doc = Map::new();
            doc.insert("version".into(), json!(OPERATOR_STATUS_VERSION));
            doc.insert("service".into(), json!("provider"));
            doc.insert("generated_at".into(), json!(report.now));
            doc.insert("identity".into(), error.clone());
            doc.insert("directory".into(), error.clone());
            doc.insert("leases".into(), error);
            doc
        }
    };

    let p = &report.publisher;
    let mut publisher = Map::new();
    publisher.insert("url".into(), json!(p.url));
    publisher.insert("error".into(), json!(p.error));
    if let Some(raw) = &p.raw {
        for (k, v) in raw {
            publisher.insert(k.clone(), v.clone());
        }
    }
    doc.insert("publisher".into(), Value::Object(publisher));

    let e = &report.earnings;
    doc.insert(
        "earnings".into(),
        json!({
            "url": e.url,
            "dashboard_url": e.dashboard_url,
            "error": e.error,
            "audit_error": e.audit_error,
            // Amounts are decimal strings, like the publisher's: a channel's
            // deposit is a u128 on the connector's side.
            "total_unredeemed": e.total_unredeemed().to_string(),
            "channels": e.channels.iter().map(|c| json!({
                "channel_id": c.channel_id,
                "counterparty": c.counterparty,
                "status": c.status,
                "deposited": c.deposited.map(|d| d.to_string()),
                "claimed": c.claimed.to_string(),
                "redeemed": c.redeemed.to_string(),
                "unredeemed": c.unredeemed.to_string(),
                "last_redeemed_at": c.last_redeemed_at,
            })).collect::<Vec<_>>(),
        }),
    );

    let f = &report.funding;
    doc.insert(
        "funding".into(),
        json!({
            "chain": "solana",
            "address": f.address,
            "rpc": f.rpc,
            "lamports": f.lamports,
            "sol": f.lamports.map(format_sol),
            "error": f.error,
            "publisher": {
                "address": f.publisher.address,
                "token": f.publisher.token,
                "units": f.publisher.units.map(|u| u.to_string()),
                "next_deposit": f.publisher.next_deposit.map(|n| n.to_string()),
                "error": f.publisher.error,
            },
        }),
    );

    if let Some(outcome) = outcome {
        doc.insert(
            "check".into(),
            json!({
                "ok": outcome.ok(),
                "problems": outcome.problems,
                "warnings": outcome.warnings,
            }),
        );
    }
    Value::Object(doc)
}

/// The sections `to_json` adds beside the provider's own document.
const ADDED_SECTIONS: [&str; 4] = ["publisher", "earnings", "funding", "check"];

/// A document `to_json` printed, read back into the report it was printed
/// from — what `toon-provider dash` is fed in its snapshot tests, and what a
/// view on another machine reads from `status --json`. `check` is ignored:
/// it is recomputed from the report with the reader's own thresholds.
pub fn from_json(doc: &Value) -> Result<Report> {
    let doc = doc
        .as_object()
        .context("a status document is a JSON object")?;
    let now = doc
        .get("generated_at")
        .and_then(Value::as_u64)
        .context("a status document has a generated_at")?;

    let identity = doc.get("identity").context("no identity section")?;
    let operator = match identity.get("error").and_then(Value::as_str) {
        // The provider did not answer: `to_json` wrote its error into each
        // of the provider's own sections.
        Some(error) if identity.get("npub").is_none() => OperatorSource {
            url: string_field(identity, "url").unwrap_or_default(),
            raw: None,
            status: None,
            error: Some(error.to_string()),
        },
        _ => {
            let mut raw = doc.clone();
            for key in ADDED_SECTIONS {
                raw.remove(key);
            }
            let raw = Value::Object(raw);
            let status: OperatorStatus = serde_json::from_value(raw.clone())
                .context("the provider's sections are not an operator status document")?;
            OperatorSource {
                url: String::new(),
                raw: Some(raw),
                status: Some(status),
                error: None,
            }
        }
    };

    let p = doc
        .get("publisher")
        .and_then(Value::as_object)
        .context("no publisher section")?;
    let publisher = match p.get("error").and_then(Value::as_str) {
        Some(error) => PublisherSection {
            url: p.get("url").and_then(Value::as_str).map(str::to_string),
            raw: None,
            status: None,
            error: Some(error.to_string()),
        },
        None => {
            let mut raw = p.clone();
            raw.remove("url");
            raw.remove("error");
            let status: PublisherStatus = serde_json::from_value(Value::Object(raw.clone()))
                .context("the publisher section is not a publisher status")?;
            PublisherSection {
                url: p.get("url").and_then(Value::as_str).map(str::to_string),
                raw: Some(raw),
                status: Some(status),
                error: None,
            }
        }
    };

    let e = doc.get("earnings").context("no earnings section")?;
    let channels = match e.get("channels").and_then(Value::as_array) {
        None => Vec::new(),
        Some(rows) => rows
            .iter()
            .map(|c| {
                Ok(ChannelEarnings {
                    channel_id: string_field(c, "channel_id").context("a channel with no id")?,
                    counterparty: string_field(c, "counterparty"),
                    status: string_field(c, "status"),
                    deposited: amount(c, "deposited")?,
                    claimed: amount(c, "claimed")?.unwrap_or(0),
                    redeemed: amount(c, "redeemed")?.unwrap_or(0),
                    unredeemed: amount(c, "unredeemed")?.unwrap_or(0),
                    last_redeemed_at: c.get("last_redeemed_at").and_then(Value::as_u64),
                })
            })
            .collect::<Result<_>>()?,
    };
    let earnings = EarningsSection {
        url: string_field(e, "url"),
        dashboard_url: string_field(e, "dashboard_url"),
        channels,
        error: string_field(e, "error"),
        audit_error: string_field(e, "audit_error"),
    };

    let f = doc.get("funding").context("no funding section")?;
    let funding = FundingSection {
        address: string_field(f, "address"),
        rpc: string_field(f, "rpc"),
        lamports: f.get("lamports").and_then(Value::as_u64),
        error: string_field(f, "error"),
        publisher: match f.get("publisher") {
            None | Some(Value::Null) => PublisherWallet::default(),
            Some(w) => PublisherWallet {
                address: string_field(w, "address"),
                token: string_field(w, "token"),
                units: amount(w, "units")?,
                next_deposit: amount(w, "next_deposit")?,
                error: string_field(w, "error"),
            },
        },
    };

    Ok(Report {
        now,
        operator,
        publisher,
        earnings,
        funding,
    })
}

fn string_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

/// A decimal-string amount, as `to_json` writes one.
fn amount(v: &Value, key: &str) -> Result<Option<u128>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            Ok(Some(s.parse().with_context(|| {
                format!("{key} {s:?} is not an amount")
            })?))
        }
        Some(Value::Number(n)) => match n.as_u64() {
            Some(n) => Ok(Some(u128::from(n))),
            None => bail!("{key} {n} is not an amount"),
        },
        Some(other) => bail!("{key} {other} is not an amount"),
    }
}
