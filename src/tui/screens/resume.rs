// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::App;
use crate::model::scan::{ResumeInfo, ScanStatus};

/// Sessions screen: list of saved scans — choose which one to resume.
pub fn render(frame: &mut Frame, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(4),
    ])
    .split(frame.area());

    // DB size in the header: shows when it's time to --compact-db / empty the trash.
    // The frame title got a brand stripe in a unified style with
    // the commander header (`bg=Blue, fg=White, BOLD`) + a separate "Scans" span
    // (unified terminology everywhere, replaced "sessions" with "scans").
    let brand = Span::styled(
        format!(" DedupCommando v{} ", crate::version()),
        Style::new()
            .bg(Color::Blue)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    let title = Line::from(vec![brand, Span::raw(" Scans ")]);
    let header = Paragraph::new(Line::from(format!(
        " Saved scans · DB on disk: {} ",
        crate::tui::human_bytes(crate::maint::db_size_bytes(&app.db_path)),
    )))
    .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(header, rows[0]);

    // The session list loads in the background — a heavy DB query
    // does not block the interface.
    if app.sessions_loading {
        const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let spinner = SPINNER[(app.tick % SPINNER.len() as u64) as usize];
        frame.render_widget(
            Paragraph::new(Line::from(format!("  {spinner}  Loading scan list…")))
                .block(Block::default().borders(Borders::ALL).title(" Scans ")),
            rows[1],
        );
        crate::tui::render_footer(frame, rows[2], &app.status, "Q quit");
        return;
    }

    // List row format — `#N   DATE   STATUS   stats
    // (if Complete)   /roots`. Columns are aligned with spaces; `#N` (scan.id from
    // the DB) is the unified scan identifier (the same one as in the commander header). The ID
    // is tinted light blue — visually separating the numbering column.
    let items: Vec<ListItem> = app
        .sessions
        .iter()
        .map(|session| {
            let roots = session
                .roots
                .iter()
                .map(|root| root.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let mut spans = vec![
                Span::styled(
                    format!("#{:<4}   ", session.scan_id),
                    Style::new()
                        .fg(Color::LightBlue)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{}   ", session.created_at)),
                status_span(session),
            ];
            // For a completed scan — how much was scanned (E2E feedback), before the roots so a
            // long path doesn't crowd out the number.
            if session.status.is_completed() {
                spans.push(Span::styled(
                    format!("   {} files", session.files_scanned),
                    Style::new().fg(Color::DarkGray),
                ));
            }
            spans.push(Span::raw(format!("   {roots}")));
            let mut lines = vec![Line::from(spans)];
            // What the scan is worth goes on its own line. On an 80-column terminal the id, date,
            // status, file count and roots already fill the row, and the qualifier that makes the
            // number true is not the part that may fall off the end.
            if session.status.is_completed() {
                lines.push(Line::from(Span::styled(
                    format!("        {}", crate::tui::reclaim_cell(session.reclaim)),
                    Style::new().fg(Color::DarkGray),
                )));
            }
            ListItem::new(lines)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Scans — R/Enter open · Del to trash · t trash · N new "),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    if !app.sessions.is_empty() {
        state.select(Some(app.session_cursor));
    }
    frame.render_stateful_widget(list, rows[1], &mut state);

    crate::tui::render_footer(
        frame,
        rows[2],
        &app.status,
        "↑↓ · R/Enter open · Del to trash · t trash · N new · Q quit",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::reclaim::ReclaimEstimate;
    use ratatui::{backend::TestBackend, Terminal};
    use std::path::PathBuf;

    fn session(reclaim: ReclaimEstimate) -> ResumeInfo {
        ResumeInfo {
            scan_id: 7,
            created_at: "2026-07-31 10:00:00".to_string(),
            status: ScanStatus::Complete,
            roots: vec![PathBuf::from("/tank/data")],
            files_total: 10,
            files_hashed: 10,
            cand_bytes_total: 1000,
            cand_bytes_hashed: 1000,
            files_scanned: 100,
            reclaim,
            already_linked_sets: None,
        }
    }

    /// The saved-scan list is the other consumer of the compact claim, and it is drawn at the
    /// full terminal width — where the id, date, status, file count and roots already fill an
    /// 80-column row. The claim gets its own line, so the qualifier reads in full at that width.
    #[test]
    fn a_saved_scan_row_states_its_claim_post_purge_at_eighty_columns() {
        for (state, expected) in [
            (
                ReclaimEstimate::exact(4096),
                "guaranteed after quarantine purge: 4.0 KiB",
            ),
            (
                ReclaimEstimate::upper_bound(4096),
                "up to 4.0 KiB after quarantine purge",
            ),
            (ReclaimEstimate::unknown(), "rescan required"),
        ] {
            let (mut app, _events) = crate::app::test_app();
            app.sessions_loading = false;
            app.sessions = vec![session(state)];
            app.session_cursor = 0;
            let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered: String = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(
                rendered.contains(expected),
                "at 80 columns the claim must read in full: {rendered}"
            );
            assert!(
                !rendered.contains("free"),
                "nothing is free before the quarantine is purged: {rendered}"
            );
            assert!(
                rendered.contains("/tank/data"),
                "the roots must survive the extra line: {rendered}"
            );
        }
    }
}

fn status_text(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Walking => "walking",
        ScanStatus::Hashing => "hashing",
        ScanStatus::Complete => "ready",
        ScanStatus::CompleteWithWarnings => "ready ⚠",
        ScanStatus::Aborted => "aborted",
    }
}

/// Colored status for the list (E2E feedback): "ready" in soft green; hashing — the word +
/// an honest % by candidate volume (yellow); walking — blue; aborted — red.
fn status_span(session: &ResumeInfo) -> Span<'static> {
    let (text, color) = match session.status {
        ScanStatus::Complete => (
            status_text(ScanStatus::Complete).to_string(),
            Color::LightGreen,
        ),
        // Completed, but with warnings — yellow, as a "check the counter" signal.
        ScanStatus::CompleteWithWarnings => (
            status_text(ScanStatus::CompleteWithWarnings).to_string(),
            Color::Yellow,
        ),
        ScanStatus::Hashing => {
            let text = match session
                .cand_bytes_hashed
                .saturating_mul(100)
                .checked_div(session.cand_bytes_total)
            {
                Some(pct) => format!("hashing {pct}%"),
                None => "hashing".to_string(),
            };
            (text, Color::Yellow)
        }
        ScanStatus::Walking => (status_text(ScanStatus::Walking).to_string(), Color::Cyan),
        ScanStatus::Aborted => (status_text(ScanStatus::Aborted).to_string(), Color::Red),
    };
    Span::styled(text, Style::new().fg(color))
}
