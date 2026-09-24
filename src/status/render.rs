//! The report, printed: six sections in ADR 0029's order — identity,
//! directory, publisher, leases, earnings, funding — for a person, or one
//! JSON document for a program.

use std::fmt::Write as _;

use serde_json::{json, Map, Value};

use crate::directory::{RefusalKind, RelayOutcome};
use crate::nostr::wire::LeaseState;
use crate::provider::operator_status::OPERATOR_STATUS_VERSION;

use super::check::{abbreviate, CheckOutcome};
use super::gather::Report;
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

    // ── 1. Identity ───────────────────────────────────────────────────────
    let _ = writeln!(out, "\nIDENTITY");
    match status {
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
    }

    // ── 2. Directory ──────────────────────────────────────────────────────
    let _ = writeln!(out, "\nDIRECTORY");
    match status {
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
    }

    // ── 3. Publisher ──────────────────────────────────────────────────────
    let _ = writeln!(out, "\nPUBLISHER");
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
                    Some(r) => format!("{} at the current Liveness cadence", format_duration(r)),
                    None => format!(
                        "unknown{}",
                        ps.assumptions
                            .first()
                            .map(|a| format!(" — {a}"))
                            .unwrap_or_default()
                    ),
                }
            );
            if ps.drained() {
                let _ = writeln!(
                    out,
                    "  DRAINED: no directory write can be paid for. Top up with \
                     `toon-provider topup <amount>`."
                );
            }
            if ps.watermark_uncertain {
                let _ = writeln!(
                    out,
                    "  the channel watermark is uncertain: spent may be understated"
                );
            }
        }
    }

    // ── 4. Leases ─────────────────────────────────────────────────────────
    let _ = writeln!(out, "\nLEASES");
    match status {
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
    }

    // ── 5. Earnings ───────────────────────────────────────────────────────
    let _ = writeln!(out, "\nEARNINGS");
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

    // ── 6. Funding ────────────────────────────────────────────────────────
    let _ = writeln!(out, "\nFUNDING");
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
    out
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
