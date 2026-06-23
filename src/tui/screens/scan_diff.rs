// SPDX-License-Identifier: Apache-2.0
//! Screen comparing two scans: a per-category summary +
//! the list of the selected category. The data is computed by `state::move_track::diff`
//! in the background; this module only renders.

use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::{App, ScanDiffState};
use crate::state::move_track::{DiffReport, FileChange};
use crate::tui::commander::panel::ellipsize_left;

/// Listed categories in the order they cycle through with Tab. "Unchanged" is
/// only a counter in the header, not surfaced in the list.
pub const CATEGORIES: [&str; 6] = [
    "New duplicates",
    "Moved (inode)",
    "Moved (hash)",
    "Modified",
    "Deleted",
    "New",
];

/// The list of changes for the selected category.
fn category_changes(report: &DiffReport, index: usize) -> &[FileChange] {
    match index {
        0 => &report.new_dup_candidates,
        1 => &report.moved_inode,
        2 => &report.moved_hash,
        3 => &report.modified,
        4 => &report.deleted,
        5 => &report.new,
        _ => &[],
    }
}

/// Length of the current category (for cursor navigation).
pub fn category_len(state: &ScanDiffState) -> usize {
    match &state.report {
        Some(report) => category_changes(report, state.category).len(),
        None => 0,
    }
}

/// Human-readable line for a single change.
fn change_line(change: &FileChange, width: usize) -> String {
    let cut = |p: &std::path::Path| ellipsize_left(&p.display().to_string(), width);
    match change {
        FileChange::NewDupCandidate { path, peers_in_old } => {
            let peer = peers_in_old
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            format!("{}  ← duplicate of: {}", cut(path), peer)
        }
        FileChange::MovedByInode { from, to } => format!("{} → {}", cut(from), cut(to)),
        FileChange::MovedByHash { from, to } => {
            format!("{} → {} (by content)", cut(from), cut(to))
        }
        FileChange::Modified { new_path, .. } => cut(new_path),
        FileChange::Deleted { path } => cut(path),
        FileChange::New { path } => cut(path),
    }
}

pub fn render(frame: &mut Frame, app: &App) {
    let state = &app.scan_diff;
    let rows = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(4),
    ])
    .split(frame.area());

    // Summary header.
    let header_text = match &state.report {
        _ if state.loading => Text::from("  Computing the differences between scans…"),
        Some(report) => summary_text(report),
        None => Text::from("  No data to compare"),
    };
    frame.render_widget(
        Paragraph::new(header_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Scan comparison "),
        ),
        rows[0],
    );

    // The list of the selected category.
    let width = rows[1].width.saturating_sub(4) as usize;
    let (title, items): (String, Vec<ListItem>) = match &state.report {
        Some(report) => {
            let changes = category_changes(report, state.category);
            let title = format!(
                " {} ({}) — Tab next category ",
                CATEGORIES[state.category],
                changes.len()
            );
            let items = changes
                .iter()
                .map(|c| ListItem::new(change_line(c, width)))
                .collect();
            (title, items)
        }
        None => (" — ".to_string(), Vec::new()),
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut list_state = state.list.clone();
    frame.render_stateful_widget(list, rows[1], &mut list_state);

    crate::tui::render_footer(
        frame,
        rows[2],
        &app.status,
        "↑↓ select · Tab/Shift+Tab category · Esc/F10 back",
    );
}

/// Summary text: counters across all categories.
fn summary_text(report: &DiffReport) -> Text<'static> {
    let dup_style = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    Text::from(vec![
        Line::from(format!(
            "  Scans #{} ↔ #{} · root {}",
            report.old_scan_id,
            report.new_scan_id,
            report.root.display()
        )),
        Line::from(format!(
            "  Unchanged: {} · Moved: inode {} / hash {}",
            report.unchanged_count,
            report.moved_inode.len(),
            report.moved_hash.len(),
        )),
        Line::from(format!(
            "  Modified: {} · Deleted: {} · New: {}",
            report.modified.len(),
            report.deleted.len(),
            report.new.len(),
        )),
        Line::styled(
            format!(
                "  New duplicates (a duplicate arrived): {}",
                report.new_dup_candidates.len()
            ),
            dup_style,
        ),
    ])
}
