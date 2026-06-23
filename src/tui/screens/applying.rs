// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

use crate::actions::ApplyPhase;
use crate::app::App;
use crate::model::action::RevalidationMode;
use crate::tui::human_bytes;

/// Spinner frames ("process is alive") — animated by `app.tick` on every TUI frame.
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Action-applying screen (background worker): phase, gauge, counters, cancel.
/// Mirror of `screens/scanning.rs` — the UI does not freeze, progress arrives via events.
pub fn render(frame: &mut Frame, app: &App) {
    let applying = &app.applying;
    let area = frame.area();

    let mode_label = match applying.mode {
        RevalidationMode::Strict => "strict",
        RevalidationMode::Hybrid => "hybrid",
        RevalidationMode::Fast => "fast",
    };
    let block = Block::default().borders(Borders::ALL).title(format!(
        " DedupCommando — applying actions · mode: {mode_label} "
    ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(inner);

    let phase = match applying.phase {
        ApplyPhase::Snapshots => "Creating safety ZFS snapshots…",
        ApplyPhase::Applying => "Verifying content and moving/linking…",
        ApplyPhase::Done => "Finishing…",
    };
    // The spinner rotates on every TUI frame — a "process is alive" signal, even when
    // the counter is stuck on a long re-hash of a large file.
    let spinner = SPINNER[(app.tick % SPINNER.len() as u64) as usize];
    frame.render_widget(
        Paragraph::new(format!("{spinner}  {phase}").bold()),
        rows[0],
    );

    // Gauge: by the volume of re-verified bytes (if the total is known — Hybrid/Strict),
    // otherwise by the number of actions (snapshot phase / while bytes aren't instrumented yet).
    let ratio = if applying.bytes_total > 0 {
        (applying.bytes_done as f64 / applying.bytes_total as f64).clamp(0.0, 1.0)
    } else if applying.total > 0 {
        (applying.index as f64 / applying.total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let gauge = Gauge::default()
        .gauge_style(Style::new().fg(Color::Cyan))
        .ratio(ratio)
        .label(format!("{:.0}%", ratio * 100.0));
    frame.render_widget(gauge, rows[2]);

    let current = if applying.total > 0 {
        (applying.index + 1).min(applying.total)
    } else {
        0
    };
    let mut stat_lines = vec![Line::from(format!(
        "Action:            {current} / {}",
        applying.total
    ))];
    if applying.bytes_total > 0 {
        stat_lines.push(Line::from(format!(
            "Re-verified:       {} / {}",
            human_bytes(applying.bytes_done),
            human_bytes(applying.bytes_total),
        )));
    }
    frame.render_widget(Paragraph::new(Text::from(stat_lines)), rows[3]);

    frame.render_widget(
        Paragraph::new(
            "[Esc] stop after the current action — the snapshot is done, applied items are in quarantine"
                .dim(),
        ),
        rows[4],
    );
}
