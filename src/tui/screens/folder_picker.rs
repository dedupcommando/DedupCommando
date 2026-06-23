// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::App;

/// File-browser screen: navigate the host's directories to pick a folder to scan.
pub fn render(frame: &mut Frame, app: &App) {
    let picker = &app.folder_picker;
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(frame.area());

    let header = Paragraph::new(Line::from(format!(
        " Current directory:  {} ",
        picker.current_dir.display()
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" DedupCommando — pick a folder to scan "),
    );
    frame.render_widget(header, rows[0]);

    let items: Vec<ListItem> = if picker.entries.is_empty() {
        vec![ListItem::new("(no subdirectories)")]
    } else {
        picker
            .entries
            .iter()
            .map(|path| {
                let name = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string());
                ListItem::new(format!("{name}/"))
            })
            .collect()
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Subdirectories — Enter to enter "),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    if !picker.entries.is_empty() {
        state.select(Some(picker.cursor));
    }
    frame.render_stateful_widget(list, rows[1], &mut state);

    let footer = Paragraph::new(Line::from(
        "↑↓ select · Enter enter · Backspace up · A select this directory · Esc cancel",
    ))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, rows[2]);
}
