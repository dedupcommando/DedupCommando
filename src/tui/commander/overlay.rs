// SPDX-License-Identifier: Apache-2.0
//! Modal overlays of the commander — drawn on top of the panels.

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use super::state::ConfirmTab;
use crate::model::scan::ResumeInfo;
use crate::tui::{centered, human_bytes};

/// Draws the F9 dropdown menu; the cursor is on item `cursor`.
pub fn render_menu(frame: &mut Frame, cursor: usize, labels: &[&str]) {
    let width = labels
        .iter()
        .map(|label| label.chars().count())
        .max()
        .unwrap_or(20) as u16
        + 6;
    let height = labels.len() as u16 + 2;
    let area = centered(frame.area(), width, height);
    frame.render_widget(Clear, area);

    let items: Vec<ListItem> = labels
        .iter()
        .map(|label| ListItem::new(Line::from(format!("  {label}  "))))
        .collect();
    let mut state = ListState::default();
    state.select(Some(cursor.min(labels.len().saturating_sub(1))));

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Menu — F9 "))
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, area, &mut state);
}

/// Draws the F11 confirmation overlay with two tabs:
/// "Summary" (what and how much) and "Commands" (the plan's full shell-script).
pub fn render_confirm(
    frame: &mut Frame,
    files: usize,
    reclaim: u64,
    tab: ConfirmTab,
    script: &str,
) {
    let tabs = Line::from(vec![
        Span::raw("  "),
        tab_span("Summary", matches!(tab, ConfirmTab::Summary)),
        Span::raw("  "),
        tab_span("Commands", matches!(tab, ConfirmTab::Commands)),
    ]);
    let hint = Line::from("  [Tab] tab  [S] save .sh  [Y] execute  [N]/[Esc] cancel");

    let (area, body): (Rect, Vec<Line>) = match tab {
        ConfirmTab::Summary => {
            let body = vec![
                Line::from(""),
                Line::from(format!("  Actions to be executed: {files}")),
                Line::from(format!("  Approximately freed: {}", human_bytes(reclaim))),
                Line::from(""),
                Line::from("  A ZFS snapshot for rollback is created before changes."),
            ];
            // tabs + empty + body + empty + hint + border(2).
            let height = body.len() as u16 + 6;
            (centered(frame.area(), 66, height), body)
        }
        ConfirmTab::Commands => {
            let avail = frame.area();
            let width = avail.width.saturating_sub(4).clamp(40, 110);
            let height = avail.height.saturating_sub(4).clamp(10, 44);
            // Visible script rows: height − border(2) − tabs − 2 empties − hint.
            let body_rows = height.saturating_sub(6) as usize;
            let all: Vec<&str> = script.lines().collect();
            let body = if all.len() > body_rows && body_rows > 0 {
                let shown = body_rows - 1;
                let mut lines: Vec<Line> = all
                    .iter()
                    .take(shown)
                    .map(|l| Line::from(format!(" {l}")))
                    .collect();
                lines.push(Line::from(format!(
                    " … {} more lines — save with [S]",
                    all.len() - shown
                )));
                lines
            } else {
                all.iter()
                    .take(body_rows)
                    .map(|l| Line::from(format!(" {l}")))
                    .collect()
            };
            (centered(avail, width, height), body)
        }
    };

    frame.render_widget(Clear, area);
    let mut content = vec![tabs, Line::from("")];
    content.extend(body);
    content.push(Line::from(""));
    content.push(hint);
    frame.render_widget(
        Paragraph::new(Text::from(content)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Confirmation — F11 "),
        ),
        area,
    );
}

/// Tab-label span of the confirmation overlay; the active one is inverted.
fn tab_span(label: &str, active: bool) -> Span<'static> {
    let text = format!(" {label} ");
    if active {
        Span::styled(
            text,
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(text, Style::new().fg(Color::DarkGray))
    }
}

/// Draws the F2 overlay: a summary by roots — an unfinished session and/or
/// the last completed scan with dates and progress — plus a recommendation and a choice.
pub fn render_resume_scan(
    frame: &mut Frame,
    root: &str,
    unfinished: Option<&ResumeInfo>,
    complete: Option<&ResumeInfo>,
) {
    let mut body = vec![Line::from(""), Line::from(format!("  Root: {root}"))];
    if let Some(u) = unfinished {
        // % by candidate volume — the same denominator as in the F12 list,
        // so both screens show the same progress for the same scan.
        let percent = u
            .cand_bytes_hashed
            .saturating_mul(100)
            .checked_div(u.cand_bytes_total)
            .unwrap_or(0)
            .min(100);
        body.push(Line::from(format!(
            "  Unfinished scan from {} · progress {percent}%",
            u.created_at
        )));
    }
    if let Some(c) = complete {
        body.push(Line::from(format!(
            "  Last completed from {} · files {} · frees {}",
            c.created_at,
            c.files_scanned,
            crate::tui::human_bytes(c.reclaimable_bytes),
        )));
    }
    body.push(Line::from(""));
    body.push(Line::from(format!(
        "  {}",
        resume_recommendation(unfinished, complete)
    )));
    body.push(Line::from(""));
    let mut opts: Vec<&str> = Vec::new();
    if unfinished.is_some() {
        opts.push("[R]/[Enter] resume");
    }
    if complete.is_some() {
        opts.push("[O] open completed");
    }
    opts.push("[N] new scan");
    opts.push("[Esc] cancel");
    body.push(Line::from(format!("  {}", opts.join(" · "))));

    let height = body.len() as u16 + 2;
    let area = centered(frame.area(), 74, height);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(Text::from(body)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Scan roots — F2 "),
        ),
        area,
    );
}

/// Recommendation for the F2 overlay — a pure function of the presence
/// of an unfinished/completed session and which is newer (by `created_at`;
/// the `%Y-%m-%d %H:%M:%S` format sorts lexicographically).
fn resume_recommendation(
    unfinished: Option<&ResumeInfo>,
    complete: Option<&ResumeInfo>,
) -> &'static str {
    match (unfinished, complete) {
        (Some(u), Some(c)) if u.created_at < c.created_at => {
            "Recommended: [O] open the completed one (current) or [N] new; [R] is usually not needed"
        }
        (Some(_), _) => "Recommended: [R] resume — hashes are inherited, the disk is barely read",
        (None, Some(_)) => "Recommended: [O] open results or [N] new scan",
        (None, None) => "",
    }
}

#[cfg(test)]
mod resume_tests {
    use super::resume_recommendation;
    use crate::model::scan::{ResumeInfo, ScanStatus};
    use std::path::PathBuf;

    fn info(created: &str, status: ScanStatus) -> ResumeInfo {
        ResumeInfo {
            scan_id: 1,
            created_at: created.to_string(),
            status,
            roots: vec![PathBuf::from("/x")],
            files_total: 10,
            files_hashed: 2,
            cand_bytes_total: 1000,
            cand_bytes_hashed: 200,
            files_scanned: 100,
            reclaimable_bytes: 4096,
        }
    }

    #[test]
    fn recommends_open_when_unfinished_older_than_complete() {
        let u = info("2026-05-01 10:00:00", ScanStatus::Hashing);
        let c = info("2026-05-02 10:00:00", ScanStatus::Complete);
        assert!(resume_recommendation(Some(&u), Some(&c)).contains("[O]"));
    }

    #[test]
    fn recommends_resume_when_unfinished_newest() {
        let u = info("2026-05-03 10:00:00", ScanStatus::Hashing);
        let c = info("2026-05-02 10:00:00", ScanStatus::Complete);
        assert!(resume_recommendation(Some(&u), Some(&c)).contains("[R]"));
    }

    #[test]
    fn recommends_open_or_new_when_only_complete() {
        let c = info("2026-05-02 10:00:00", ScanStatus::Complete);
        let r = resume_recommendation(None, Some(&c));
        assert!(r.contains("[O]") || r.contains("[N]"));
    }
}

/// Draws the file-info overlay (F3).
pub fn render_info(frame: &mut Frame, lines: &[String]) {
    let height = (lines.len() as u16 + 2).clamp(5, frame.area().height);
    let width = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(40)
        .clamp(40, 100) as u16
        + 4;
    let area = centered(frame.area(), width, height);
    frame.render_widget(Clear, area);
    let text: Vec<Line> = lines
        .iter()
        .map(|line| Line::from(format!(" {line}")))
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(text)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" File — F3 · Esc to close "),
        ),
        area,
    );
}
