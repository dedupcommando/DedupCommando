// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::App;

/// "Trash" screen: sessions marked for deletion — restore
/// or purge permanently. A hard purge frees disk space (VACUUM — c9).
pub fn render(frame: &mut Frame, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(4),
    ])
    .split(frame.area());

    let header = Paragraph::new(Line::from(" Trash — deleted scans ")).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" DedupCommando — trash "),
    );
    frame.render_widget(header, rows[0]);

    let items: Vec<ListItem> = app
        .trashed
        .iter()
        .map(|session| {
            let roots = session
                .roots
                .iter()
                .map(|root| root.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            ListItem::new(format!("{}  ·  {}", session.created_at, roots))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" R/Enter restore · Del purge permanently · Esc back "),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    if !app.trashed.is_empty() {
        state.select(Some(app.trash_cursor));
    }
    frame.render_stateful_widget(list, rows[1], &mut state);

    crate::tui::render_footer(
        frame,
        rows[2],
        &app.status,
        "↑↓ select · R restore · Del purge permanently · Esc back",
    );
}
