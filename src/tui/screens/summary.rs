// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    style::Stylize,
    text::{Line, Text},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;
use crate::tui::human_bytes;

/// Summary screen: what was done, safety snapshots, the path to freeing disk space.
pub fn render(frame: &mut Frame, app: &App) {
    let result = match &app.summary_result {
        Some(result) => result,
        None => return,
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(
            format!(
                "  Completed successfully: {} operations      Errors: {}",
                result.succeeded(),
                result.failed(),
            )
            .bold(),
        ),
    ];

    for outcome in &result.outcomes {
        if let Err(message) = &outcome.result {
            lines.push(
                Line::from(format!(
                    "    ✗ {} {} — {}",
                    outcome.kind.label(),
                    outcome.target.display(),
                    message,
                ))
                .red(),
            );
        }
    }

    lines.push(Line::from(""));
    if !result.snapshots.is_empty() {
        lines.push(Line::from("  Safety snapshots created:"));
        for snapshot in &result.snapshots {
            lines.push(Line::from(format!("    {snapshot}")));
        }
    }
    if !result.quarantine_dirs.is_empty() {
        lines.push(Line::from("  Files moved to quarantine:"));
        for dir in &result.quarantine_dirs {
            lines.push(Line::from(format!("    {}", dir.display())));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "  Planned to be freed: {}",
        human_bytes(result.bytes_planned),
    )));
    lines.push(Line::from(format!(
        "  Volume of successfully processed files: {}",
        human_bytes(result.bytes_reclaimed()),
    )));
    lines.push(Line::from(
        "  Space is freed AFTER verifying and purging with the commands:".to_string(),
    ));
    for snapshot in &result.snapshots {
        lines.push(Line::from(format!("    zfs destroy {snapshot}")));
    }
    if !result.quarantine_dirs.is_empty() {
        lines.push(Line::from("    dedcom --purge-quarantine"));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("  [Esc] to configuration · [Q] quit".dim()));

    frame.render_widget(
        Paragraph::new(Text::from(lines)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" DedupCommando — summary "),
        ),
        frame.area(),
    );
}
