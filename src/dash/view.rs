//! Drawing one frame of the dashboard from an [`App`]. Pure: the same app
//! draws the same frame, which is what the snapshot tests rely on.
//!
//! The layout, top to bottom: a title line; what `--check` would fail on (in
//! red) and warn about (in yellow), when there is any; the six panes in ADR
//! 0029's order, two to a row, or one to a row on a narrow terminal; and a
//! footer of keys. Each pane holds the lines `toon-provider status` prints
//! under its heading (`status::section_text`), and its border is red when
//! `--check` fails on it and yellow when it only warns.
//!
//! Every colour is one of the terminal's own ANSI colours, or a modifier,
//! as the Console's TUI does (ADR 0028), so an Omarchy theme recolours it.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Modal, Tone};
use crate::redeem::gas::{chain_of, Estimate};
use crate::status::{abbreviate, format_duration, section_text, Section};

/// Below this many columns the panes are stacked one to a row.
const TWO_COLUMNS_FROM: u16 = 100;

/// The most lines the findings box takes before it cuts the list short.
const MAX_FINDINGS: usize = 6;

/// The fewest rows the findings box may be held to, however small the
/// screen; otherwise it takes up to a third of it.
const MIN_FINDINGS_ROWS: u16 = 4;

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let findings = findings_box(findings(app));
    let findings_height = match &findings {
        None => 0,
        Some(p) => (p.line_count(area.width) as u16).min((area.height / 3).max(MIN_FINDINGS_ROWS)),
    };
    let [title, findings_area, panes, footer] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(findings_height),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .areas(area);

    draw_title(frame, title, app);
    if let Some(findings) = findings {
        frame.render_widget(findings, findings_area);
    }
    if app.report().is_some() {
        draw_panes(frame, panes, app);
    } else {
        frame.render_widget(
            Paragraph::new("  reading the status…").block(Block::default().borders(Borders::ALL)),
            panes,
        );
    }
    draw_footer(frame, footer, app);

    if let Some(modal) = app.modal() {
        draw_modal(frame, area, modal);
    }
}

fn draw_title(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![Span::styled(
        " toon-provider dash ",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    if let Some(report) = app.report() {
        let now = report.at();
        if let Some(status) = &report.operator.status {
            spans.push(Span::raw(format!("── {} ", status.identity.provider_name)));
            if let Some(started) = status.started_at {
                spans.push(Span::raw(format!(
                    "── up {} ",
                    format_duration(now.saturating_sub(started))
                )));
            }
        }
        let outcome = app.outcome();
        spans.push(Span::raw("── "));
        spans.push(if outcome.ok() {
            Span::styled("● check OK", Style::default().fg(Color::Green))
        } else {
            Span::styled(
                format!(
                    "● {} problem{}",
                    outcome.problems.len(),
                    if outcome.problems.len() == 1 { "" } else { "s" }
                ),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )
        });
        spans.push(Span::raw(format!(
            " ── as of {} UTC, every {}s ",
            clock(now),
            app.cadence_s()
        )));
    }
    if app.refreshing {
        spans.push(Span::styled(
            "── refreshing… ",
            Style::default().add_modifier(Modifier::DIM),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// `--check`'s problems, then its warnings, one line each.
fn findings(app: &App) -> Vec<Line<'static>> {
    let outcome = app.outcome();
    let problems = outcome.problems.iter().map(|p| {
        Line::from(vec![
            Span::styled(
                "PROBLEM ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(p.clone(), Style::default().fg(Color::Red)),
        ])
    });
    let warnings = outcome.warnings.iter().map(|w| {
        Line::from(vec![
            Span::styled("warning ", Style::default().fg(Color::Yellow)),
            Span::raw(w.clone()),
        ])
    });
    problems.chain(warnings).collect()
}

/// The findings, boxed, or `None` when there are none.
fn findings_box(mut lines: Vec<Line<'static>>) -> Option<Paragraph<'static>> {
    if lines.is_empty() {
        return None;
    }
    let total = lines.len();
    if total > MAX_FINDINGS {
        lines.truncate(MAX_FINDINGS - 1);
        lines.push(Line::raw(format!(
            "… and {} more: `toon-provider status --check` lists them all",
            total - (MAX_FINDINGS - 1)
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" NEEDS A PERSON ")
        .border_style(Style::default().fg(Color::Red));
    Some(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
    )
}

fn draw_panes(frame: &mut Frame, area: Rect, app: &App) {
    let report = app.report().expect("drawn only once there is a report");
    let cells: Vec<Rect> = if area.width >= TWO_COLUMNS_FROM {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Fill(1); 3])
            .split(area);
        rows.iter()
            .flat_map(|row| {
                Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50); 2])
                    .split(*row)
                    .to_vec()
            })
            .collect()
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Fill(1); 6])
            .split(area)
            .to_vec()
    };

    for (section, cell) in Section::ALL.into_iter().zip(cells) {
        let tone = app.tone(section);
        let border = match tone {
            Tone::Problem => Style::default().fg(Color::Red),
            Tone::Warning => Style::default().fg(Color::Yellow),
            Tone::Fine => Style::default(),
        };
        let focused = app.focus == section;
        let title_style = if focused {
            border.add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            border.add_modifier(Modifier::BOLD)
        };
        let lines: Vec<Line> = section_text(report, section)
            .lines()
            .map(|l| styled_line(l.strip_prefix("  ").unwrap_or(l)))
            .collect();
        let scroll = app.scroll.get(&section).copied().unwrap_or(0);
        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
        let rows = paragraph.line_count(cell.width.saturating_sub(2)) as u16;
        let mut block = Block::default()
            .borders(Borders::ALL)
            .border_style(border)
            .title(Span::styled(format!(" {} ", section.title()), title_style));
        // More below than fits: say so, and how to see it.
        if rows > cell.height.saturating_sub(2).saturating_add(scroll) {
            block = block.title_bottom(Line::from(" ↓ more: Tab here, then j ").right_aligned());
        }
        frame.render_widget(paragraph.block(block).scroll((scroll, 0)), cell);
    }
}

/// One of `status`'s lines, coloured by what it says: what `--check` fails
/// on in red, what could not be read in yellow.
fn styled_line(line: &str) -> Line<'static> {
    const PROBLEM: [&str; 5] = ["REFUSED", "NOT SENT", "MISMATCH", "EXPIRED", "DRAINED"];
    const UNKNOWN: [&str; 2] = ["unavailable:", "not compared:"];
    let style = if PROBLEM.iter().any(|w| line.contains(w)) {
        Style::default().fg(Color::Red)
    } else if UNKNOWN.iter().any(|w| line.contains(w)) {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    Line::styled(line.to_string(), style)
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let key = |k: &'static str| Span::styled(k, Style::default().add_modifier(Modifier::BOLD));
    let mut spans = vec![
        Span::raw(" "),
        key("r"),
        Span::raw(" redeem  "),
        key("t"),
        Span::raw(" top up  "),
        key("u"),
        Span::raw(" refresh  "),
        key("Tab"),
        Span::raw(" pane  "),
        key("j/k"),
        Span::raw(" scroll  "),
        key("q"),
        Span::raw(" quit"),
    ];
    if let Some(message) = app.message() {
        spans.push(Span::raw("  ── "));
        spans.push(Span::styled(
            message.to_string(),
            Style::default().fg(Color::Yellow),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_modal(frame: &mut Frame, area: Rect, modal: &Modal) {
    let (title, lines, tone): (&str, Vec<Line>, Color) = match modal {
        Modal::RedeemPick {
            candidates,
            picked,
            cursor,
            estimates,
            error,
        } => {
            let mut lines = vec![Line::raw(format!(
                "     {:>12}  {:<6}  {:<18}  channel",
                "unredeemed", "chain", "est. gas"
            ))];
            for (i, c) in candidates.iter().enumerate() {
                let chain = chain_of(&c.channel_id);
                let gas = match estimates {
                    None => "estimating…".to_string(),
                    Some(e) => e
                        .get(&chain)
                        .map(Estimate::short)
                        .unwrap_or_else(|| "unknown".into()),
                };
                let row = format!(
                    "{} [{}] {:>12}  {:<6}  {:<18}  {:<17}{}",
                    if i == *cursor { "›" } else { " " },
                    if picked[i] { "x" } else { " " },
                    c.unredeemed,
                    chain.to_string(),
                    gas,
                    abbreviate(&c.channel_id),
                    match c.status.as_deref() {
                        Some("closed") => " (closed)",
                        _ => "",
                    }
                );
                lines.push(if i == *cursor {
                    Line::styled(row, Style::default().add_modifier(Modifier::REVERSED))
                } else {
                    Line::raw(row)
                });
            }
            let total: u128 = candidates
                .iter()
                .zip(picked)
                .filter(|(_, &p)| p)
                .map(|(c, _)| c.unredeemed)
                .sum();
            lines.push(Line::raw(""));
            lines.push(Line::raw(format!(
                "picked: {total} token base units. Gas is an estimate, paid by the connector's \
                 settlement key in the chain's own coin, not out of the channel."
            )));
            if let Some(Some(basis)) = estimates.as_ref().map(|e| {
                (!e.is_empty()).then(|| {
                    e.iter()
                        .map(|(chain, est)| format!("gas, {chain}: {}", est.basis()))
                        .collect::<Vec<_>>()
                        .join("; ")
                })
            }) {
                lines.push(Line::raw(basis));
            }
            push_error(&mut lines, error.as_deref());
            lines.push(keys(&[
                ("Space", "pick"),
                ("a", "all"),
                ("Enter", "continue"),
                ("Esc", "cancel"),
            ]));
            ("Redeem earnings", lines, Color::Cyan)
        }
        Modal::Confirm {
            title,
            lines,
            armed,
            ..
        } => {
            let mut out: Vec<Line> = lines.iter().map(|l| Line::raw(l.clone())).collect();
            out.push(Line::raw(""));
            out.push(Line::from(vec![
                Span::styled(
                    "y",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" then "),
                Span::styled(
                    "Enter",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(if *armed {
                    " confirms: armed, press Enter"
                } else {
                    " confirms"
                }),
                Span::raw("   "),
                Span::styled("Esc", Style::default().fg(Color::Red)),
                Span::raw(" cancels"),
            ]));
            (title.as_str(), out, Color::Yellow)
        }
        Modal::RedeemKey {
            channels,
            typed,
            error,
        } => {
            let mut lines = vec![
                Line::raw(format!(
                    "The operator key signs {} redeem{}: 64 hex characters, the private half \
                     `./keys.sh init` printed.",
                    channels.len(),
                    if channels.len() == 1 { "" } else { "s" }
                )),
                Line::raw(
                    "It is held in memory until the redeems are sent, then wiped; it is never \
                     shown or written anywhere.",
                ),
                Line::raw(""),
                Line::raw(format!(
                    "key: {}  ({typed} of 64)",
                    "•".repeat((*typed).min(64))
                )),
            ];
            push_error(&mut lines, error.as_deref());
            lines.push(keys(&[("Enter", "sign and redeem"), ("Esc", "cancel")]));
            ("Operator key", lines, Color::Yellow)
        }
        Modal::TopupAmount { input, error } => {
            let mut lines = vec![
                Line::raw(
                    "How much to add to the publisher's channel, in the token's smallest unit \
                     (5000000 = 5 USDC at 6dp)?",
                ),
                Line::raw(""),
                Line::raw(format!("amount: {input}▏")),
            ];
            push_error(&mut lines, error.as_deref());
            lines.push(keys(&[("Enter", "continue"), ("Esc", "cancel")]));
            ("Top up the publisher", lines, Color::Cyan)
        }
        Modal::Working { title, lines } => {
            let mut out: Vec<Line> = lines.iter().map(|l| Line::raw(l.clone())).collect();
            out.push(Line::raw(""));
            out.push(Line::styled(
                "working… (Ctrl-C quits, but what was sent is not called back)",
                Style::default().add_modifier(Modifier::DIM),
            ));
            (title.as_str(), out, Color::Cyan)
        }
        Modal::Done { title, lines } => {
            let mut out: Vec<Line> = lines.iter().map(|l| styled_line(l)).collect();
            out.push(Line::raw(""));
            out.push(keys(&[("any key", "close")]));
            (title.as_str(), out, Color::Green)
        }
    };

    let width = area.width.saturating_sub(8).clamp(20, 110);
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    let height = (paragraph.line_count(width.saturating_sub(2)) as u16 + 2).min(area.height);
    let popup = Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(tone))
        .title(format!(" {title} "));
    frame.render_widget(paragraph.block(block), popup);
}

fn push_error(lines: &mut Vec<Line<'static>>, error: Option<&str>) {
    lines.push(Line::raw(""));
    if let Some(error) = error {
        lines.push(Line::styled(
            error.to_string(),
            Style::default().fg(Color::Red),
        ));
    }
}

fn keys(pairs: &[(&'static str, &'static str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (key, what) in pairs {
        spans.push(Span::styled(
            *key,
            Style::default().add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(format!(" {what}   ")));
    }
    Line::from(spans)
}

/// A Unix time's time of day, `HH:MM:SS`, in UTC.
fn clock(t: u64) -> String {
    let s = t % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3_600, s % 3_600 / 60, s % 60)
}
