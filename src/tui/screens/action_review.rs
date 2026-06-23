// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::Stylize,
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};

use crate::app::App;
use crate::tui::{centered, human_bytes};

/// Action review screen: dry-run list + confirmation modal.
pub fn render(frame: &mut Frame, app: &App) {
    let rows = Layout::vertical([Constraint::Min(0), Constraint::Length(6)]).split(frame.area());

    let items: Vec<ListItem> = app
        .review
        .actions
        .iter()
        .map(|action| {
            ListItem::new(format!(
                "{:9}  {}   ({})",
                action.kind.label(),
                action.target.display(),
                human_bytes(action.size),
            ))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Action review — dry-run, nothing executed yet "),
    );
    frame.render_widget(list, rows[0]);

    let total: u64 = app.review.actions.iter().map(|action| action.size).sum();
    let footer = vec![
        Line::from(format!(
            " Operations: {} · potential to free: {} ",
            app.review.actions.len(),
            human_bytes(total),
        )),
        Line::from(" Before applying, ZFS snapshots of the affected datasets will be created. "),
        Line::from(format!(" {} ", app.status)),
        Line::from(" [Y] execute · [Esc] back to review ".dim()),
    ];
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
        rows[1],
    );

    if app.review.confirming {
        render_confirm(frame, app.review.actions.len(), total);
    }
}

fn render_confirm(frame: &mut Frame, count: usize, total: u64) {
    let area = centered(frame.area(), 56, 8);
    frame.render_widget(Clear, area);

    let text = vec![
        Line::from(""),
        Line::from(format!("  Execute {count} operations?").bold()),
        Line::from("  A snapshot + quarantine are created — actions"),
        Line::from(format!(
            "  are reversible until purge.  (frees ~{})",
            human_bytes(total)
        )),
        Line::from(""),
        Line::from("            [Y] yes        [N] no"),
    ];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Confirmation "),
        ),
        area,
    );
}
