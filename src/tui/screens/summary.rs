// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    style::Stylize,
    text::{Line, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::app::App;
use crate::model::action::BatchResult;
use crate::model::plan::{ObjectRealization, ZeroReason};
use crate::tui::human_bytes;

/// How many exact quarantine pathnames the screen prints before summarising the rest.
const QUARANTINE_LINES: usize = 10;

/// The heading over the commands that release the space; the manual quotes it.
const RELEASE_HEADING: &str = "Space is released AFTER verifying and purging with the commands:";

/// The two purge commands the screen offers, as the manual's §8.8 prints them.
const PURGE_COMMANDS: [&str; 2] = [
    "dedcom --purge-quarantine       # shows what it would remove",
    "dedcom --purge-quarantine --yes # removes every quarantine, for good",
];

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
    //
    // The refusal here, the error of an action and the reason an allocation is unsettled below
    // are sentences written by lower layers, and any of them may quote the pathname or the xattr
    // name it was about. Each is escaped whole; text that is already safe comes through unchanged.
    if let Some(reason) = &result.aborted {
        lines.push(
            Line::from(format!(
                "  BATCH REFUSED before any change: {}",
                crate::textsan::terminal(reason)
            ))
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
                    crate::textsan::path(&outcome.target),
                    crate::textsan::terminal(message),
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
            lines.push(Line::from(format!("    {}", crate::textsan::path(dir))));
        }
    }
    // The exact pathnames, because that is what a recovery works from: one file among a batch of
    // them is not findable from a directory name.
    let originals = result.quarantined_paths();
    if !originals.is_empty() {
        lines.push(Line::from("  Originals, by their exact path:"));
        for path in originals.iter().take(QUARANTINE_LINES) {
            lines.push(Line::from(format!("    {}", crate::textsan::path(path))));
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
        let reason = crate::textsan::terminal(reason);
        let line = match quarantine {
            Some(path) => format!("  unknown — check {}: {reason}", crate::textsan::path(path)),
            None => format!("  unknown — {reason}"),
        };
        lines.push(Line::from(line).red());
    }
    lines.push(Line::from(format!("  {RELEASE_HEADING}")));
    for snapshot in &result.snapshots {
        lines.push(Line::from(format!("    zfs destroy {snapshot}")));
    }
    // On its own the purge only lists; offering it alone as the way to release the space offered a
    // command that releases nothing. Both, as the manual's §8.8 prints them.
    if !result.quarantine_dirs.is_empty() {
        for command in PURGE_COMMANDS {
            lines.push(Line::from(format!("    {command}")));
        }
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

    // Wrapped: the reason an action failed comes after its pathname, and the screen does not scroll
    // sideways — unwrapped, a long pathname pushed the reason off the edge.
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" DedupCommando — summary "),
            ),
        frame.area(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::action::{ActionKind, ActionOutcome};
    use ratatui::{backend::TestBackend, Terminal};
    use std::path::PathBuf;

    fn screen(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn batch_with_quarantine(outcomes: Vec<ActionOutcome>) -> BatchResult {
        BatchResult {
            planned: outcomes.len(),
            outcomes,
            snapshots: vec!["tank@dedcom-20260925-120000-0".to_string()],
            quarantine_dirs: vec![PathBuf::from("/tank/.dedcom-quarantine/20260925-120000-0")],
            ..Default::default()
        }
    }

    /// `--purge-quarantine` on its own only lists what it would remove. A screen that offers it
    /// as the way to release the space offers a command that releases nothing, so both are shown:
    /// the one that lists, and the one that removes.
    #[test]
    fn the_summary_offers_the_purge_that_removes_and_the_one_that_lists() {
        let (mut app, _events) = crate::app::test_app();
        app.summary_result = Some(batch_with_quarantine(Vec::new()));
        let shown = screen(&app, 100, 30);
        assert!(shown.contains("--purge-quarantine --yes"), "{shown}");
        for line in [RELEASE_HEADING, PURGE_COMMANDS[0], PURGE_COMMANDS[1]] {
            assert!(shown.contains(line), "{line}\n{shown}");
        }
    }

    /// The manual quotes the screen word for word — the heading and both commands — where it says
    /// what to run after an apply. The strings come from the screen's own constants, so a change to
    /// the screen that the manual does not follow fails here.
    #[test]
    fn the_manual_quotes_the_purge_commands_of_the_summary() {
        let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let chapter = words(&crate::testfixtures::manual("08-actions.md"));
        for line in [RELEASE_HEADING, PURGE_COMMANDS[0], PURGE_COMMANDS[1]] {
            assert!(
                chapter.contains(&words(line)),
                "08-actions.md must quote: {line}"
            );
        }
    }

    /// The reason an action failed comes after its pathname, and the screen does not scroll
    /// sideways: without wrapping, a long pathname pushed the reason off the edge.
    #[test]
    fn a_long_pathname_does_not_push_the_reason_off_the_screen() {
        let (mut app, _events) = crate::app::test_app();
        let deep = PathBuf::from(format!("/tank/{}/file.bin", "d".repeat(150)));
        app.summary_result = Some(batch_with_quarantine(vec![ActionOutcome {
            kind: ActionKind::Hardlink,
            target: deep,
            quarantine: None,
            result: Err("ZZREASONZZ".to_string()),
        }]));
        let shown = screen(&app, 100, 30);
        assert!(shown.contains("ZZREASONZZ"), "{shown}");
    }
}
