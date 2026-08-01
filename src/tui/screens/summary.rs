// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    style::Stylize,
    text::{Line, Text},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;
use crate::model::action::BatchResult;
use crate::model::plan::{ObjectRealization, ZeroReason};
use crate::tui::human_bytes;

/// How many exact quarantine pathnames the screen prints before summarising the rest.
const QUARANTINE_LINES: usize = 10;

/// How many allocations came out worth nothing, grouped by the reason, in a fixed order so the
/// same batch always reads the same way.
fn zeros_by_reason(result: &BatchResult) -> Vec<(&'static str, usize)> {
    const REASONS: [ZeroReason; 7] = [
        ZeroReason::NotFullyCovered,
        ZeroReason::ExternalLinks,
        ZeroReason::PartialCoverage,
        ZeroReason::RolledBack,
        ZeroReason::Refused,
        ZeroReason::Cancelled,
        ZeroReason::AlreadyLinked,
    ];
    REASONS
        .into_iter()
        .filter_map(|wanted| {
            let count = result
                .realized
                .iter()
                .filter(|(_, state)| {
                    matches!(state, ObjectRealization::Zero { reason } if *reason == wanted)
                })
                .count();
            (count > 0).then_some((wanted.describe(), count))
        })
        .collect()
}

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

    // The batch refused itself as a whole after the snapshots existed. Nothing ran, and the
    // snapshots listed below are what has to be cleaned up.
    if let Some(reason) = &result.aborted {
        lines.push(
            Line::from(format!("  BATCH REFUSED before any change: {reason}"))
                .bold()
                .red(),
        );
    }

    // A cancelled batch must not read as a finished one — the header above counts only what was
    // reached, and the rest of the plan is still marked and waiting.
    if result.cancelled {
        lines.push(Line::from(
            format!(
                "  CANCELLED: {} of {} actions were reached — the marks of the rest are kept",
                result.outcomes.len(),
                result.planned,
            )
            .bold()
            .yellow(),
        ));
    }

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
    // The exact pathnames, because that is what a recovery works from: one file among a batch of
    // them is not findable from a directory name.
    let originals = result.quarantined_paths();
    if !originals.is_empty() {
        lines.push(Line::from("  Originals, by their exact path:"));
        for path in originals.iter().take(QUARANTINE_LINES) {
            lines.push(Line::from(format!("    {}", path.display())));
        }
        if originals.len() > QUARANTINE_LINES {
            lines.push(Line::from(format!(
                "    … and {} more",
                originals.len() - QUARANTINE_LINES
            )));
        }
    }

    // Planned and realized are different values and are printed as two. The plan said what the
    // allocations were worth; what the batch achieved is folded per allocation from typed
    // outcomes, never from one file size per successful pathname.
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "  planned: {}",
        crate::tui::reclaim_phrase(result.plan.estimate()),
    )));
    lines.push(Line::from(format!(
        "  realized: guaranteed after quarantine purge: {}  ({} allocation(s))",
        human_bytes(result.realized_summary.guaranteed_bytes()),
        result.realized_summary.completed_objects(),
    )));
    for (reason, count) in zeros_by_reason(result) {
        lines.push(Line::from(format!(
            "  {count} allocation(s): zero guaranteed reclaim — {reason}",
        )));
    }
    // A progress figure, named as one. It says how much was re-read to prove the content, and it
    // is never a claim about space.
    lines.push(Line::from(format!(
        "  re-checked during the batch: {}",
        human_bytes(result.bytes_read),
    )));
    for (reason, quarantine) in result.unknown_objects() {
        let line = match quarantine {
            Some(path) => format!("  unknown — check {}: {reason}", path.display()),
            None => format!("  unknown — {reason}"),
        };
        lines.push(Line::from(line).red());
    }
    lines.push(Line::from(
        "  Space is released AFTER verifying and purging with the commands:".to_string(),
    ));
    for snapshot in &result.snapshots {
        lines.push(Line::from(format!("    zfs destroy {snapshot}")));
    }
    if !result.quarantine_dirs.is_empty() {
        lines.push(Line::from("    dedcom --purge-quarantine"));
    }

    // The batch is over, but the marks may not be: a durable-state warning belongs where the
    // operator is looking, not only in the log.
    if app.marks_unsettled {
        lines.push(Line::from(""));
        lines.push(
            Line::from(format!("  {}", crate::app::MARKS_NOT_SETTLED))
                .red()
                .bold(),
        );
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
