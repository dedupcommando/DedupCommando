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
            // For a completed scan — the summary: how much was scanned and how much will be freed
            // (E2E feedback). Placed before the roots so a long path doesn't crowd out the numbers.
            if session.status.is_completed() {
                spans.push(Span::styled(
                    format!(
                        "   {} files · free {}",
                        session.files_scanned,
                        crate::tui::human_bytes(session.reclaimable_bytes),
                    ),
                    Style::new().fg(Color::DarkGray),
                ));
            }
            spans.push(Span::raw(format!("   {roots}")));
            ListItem::new(Line::from(spans))
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
