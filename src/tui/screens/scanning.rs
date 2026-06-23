// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

use crate::app::App;
use crate::model::scan::{ScanPhase, WalkStage};
use crate::tui::commander::panel::ellipsize_left;
use crate::tui::human_bytes;

/// Spinner frames ("process is alive") — animated by `app.tick` on every TUI frame.
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Scanning screen: phase, progress indicator, counters.
pub fn render(frame: &mut Frame, app: &App) {
    let scanning = &app.scanning;
    let area = frame.area();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" DedupCommando — scanning ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(inner);

    let phase = match scanning.phase {
        Some(ScanPhase::Walking(WalkStage::Scanning)) => "Phase 1/3 · walking files",
        Some(ScanPhase::Walking(WalkStage::Persisting)) => "Phase 1/3 · writing manifest",
        Some(ScanPhase::Hashing) => "Phase 2/3: hashing content",
        Some(ScanPhase::Grouping) => "Phase 3/3: grouping",
        None => "Preparing…",
    };
    // The spinner rotates on every TUI frame — giving a "process is alive" signal,
    // even when the entry counter is stuck on slow I/O.
    let spinner = SPINNER[(app.tick % SPINNER.len() as u64) as usize];
    frame.render_widget(
        Paragraph::new(format!("{spinner}  {phase}").bold()),
        rows[0],
    );

    // The currently processed path — truncated on the left.
    if let Some(path) = &scanning.current_path {
        let text = ellipsize_left(
            &path.display().to_string(),
            rows[1].width.saturating_sub(2) as usize,
        );
        frame.render_widget(
            Paragraph::new(format!("  {text}")).style(Style::new().fg(Color::DarkGray)),
            rows[1],
        );
    }

    // Progress by data volume, not by file count: files vary enormously
    // in size, and a file counter doesn't reflect the work actually done.
    // On Phase 1/3 we do NOT draw the gauge: `bytes_total` isn't known yet (hashing
    // hasn't started), and `files_total` is only known by the end of the Persisting sub-stage
    // — a bar frozen at 0% confused the user. The fact of
    // progress itself is visible from the counters below and from the spinner in the header.
    if !matches!(scanning.phase, Some(ScanPhase::Walking(_))) {
        let ratio = if scanning.bytes_total > 0 {
            (scanning.bytes_done as f64 / scanning.bytes_total as f64).clamp(0.0, 1.0)
        } else if scanning.files_total > 0 {
            (scanning.files_done as f64 / scanning.files_total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let gauge = Gauge::default()
            .gauge_style(Style::new().fg(Color::Cyan))
            .ratio(ratio)
            .label(format!("{:.0}%", ratio * 100.0));
        frame.render_widget(gauge, rows[2]);
    }

    let mut stat_lines = vec![
        Line::from(format!(
            "Walked:            {} entries · {} files",
            scanning.entries_walked, scanning.files_walked,
        )),
        Line::from(format!(
            "Hashed:            {} / {} files",
            scanning.files_done, scanning.files_total
        )),
        Line::from(format!(
            "Read:              {} / {}",
            human_bytes(scanning.bytes_done),
            human_bytes(scanning.bytes_total),
        )),
    ];
    // Speed and ETA — measured from the pool's real throughput.
    if scanning.rate_bytes_per_sec > 0 {
        stat_lines.push(Line::from(format!(
            "Speed:             {}/s · remaining ~{}",
            human_bytes(scanning.rate_bytes_per_sec),
            crate::tui::format_duration(scanning.eta_secs as f64),
        )));
    }
    if scanning.chunk_total > 0 {
        stat_lines.push(Line::from(format!(
            "Chunk:             {} / {} files  (Esc stops after the chunk)",
            scanning.chunk_done, scanning.chunk_total
        )));
    }
    // Candidates that didn't get a hash (read error / identity-mismatch) — yellow.
    // These files do NOT participate in duplicate search; the result is recorded as "ready ⚠".
    if scanning.hash_failures > 0 {
        stat_lines.push(
            Line::from(format!(
                "Failed to hash:     {} files",
                scanning.hash_failures
            ))
            .style(Style::new().fg(Color::Yellow)),
        );
    }
    // Memory warning for the grouping phase — yellow, right before the phase.
    if let Some(notice) = &scanning.notice {
        stat_lines.push(Line::from(notice.clone()).style(Style::new().fg(Color::Yellow)));
    }
    frame.render_widget(Paragraph::new(Text::from(stat_lines)), rows[4]);

    frame.render_widget(
        Paragraph::new("[Esc] stop — progress is saved, you can resume later".dim()),
        rows[5],
    );
}
