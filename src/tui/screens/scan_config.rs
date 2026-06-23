// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::App;

/// Configuration screen: selecting datasets and arbitrary folders to scan.
pub fn render(frame: &mut Frame, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(3),
        // The "Scan parameters" frame: 3 content rows (preset/cache/intensity) + 2 border
        // lines = 5. It was 4 — the "Intensity" row got clipped, and switching the profile
        // with the g key looked like "no reaction" (an invisible row was changing).
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(4),
    ])
    .split(frame.area());

    let caps = &app.zfs.capabilities;
    let header = Paragraph::new(Line::from(format!(
        " ZFS: {} · block cloning: supported={} enabled={} · reflink: {} ",
        caps.zfs_version.as_deref().unwrap_or("not detected"),
        yes_no(caps.block_cloning_supported),
        yes_no(caps.block_cloning_enabled),
        if caps.reflink_safe {
            "available"
        } else {
            "unavailable"
        },
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" DedupCommando — scan configuration "),
    );
    frame.render_widget(header, rows[0]);

    let preset_line = match app.config.presets.get(app.config.preset_index) {
        Some(preset) if preset.extensions.is_empty() => {
            format!("Filter by type: {} — all files", preset.name)
        }
        Some(preset) => {
            format!(
                "Filter by type: {} ({})",
                preset.name,
                preset.extensions.join(", ")
            )
        }
        None => "Filter by type: —".to_string(),
    };
    let cache_line = if app.config.reuse_hashes {
        "Hash cache: on — repeat scans skip unchanged files".to_string()
    } else {
        "Hash cache: off — all files will be re-hashed".to_string()
    };
    let profile = app.config.hash_profile;
    let profile_line = format!("Intensity: {} — {}", profile.label(), profile.hint());
    let params = Paragraph::new(Text::from(vec![
        Line::from(preset_line),
        Line::from(cache_line),
        Line::from(profile_line),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Scan parameters — P preset · C cache · G intensity "),
    );
    frame.render_widget(params, rows[1]);

    let items: Vec<ListItem> = if app.config.roots.is_empty() {
        vec![ListItem::new("No roots set — press F to add a folder")]
    } else {
        app.config
            .roots
            .iter()
            .map(|root| {
                let mark = if root.selected { "[x]" } else { "[ ]" };
                let text = if root.is_dataset {
                    format!("{mark}  {}   →  {}", root.label, root.path.display())
                } else {
                    format!("{mark}  [folder]  {}", root.path.display())
                };
                ListItem::new(text)
            })
            .collect()
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Datasets and folders — Space select, F add folder "),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    if !app.config.roots.is_empty() {
        state.select(Some(app.config.cursor));
    }
    frame.render_stateful_widget(list, rows[2], &mut state);

    crate::tui::render_footer(
        frame,
        rows[3],
        &app.status,
        "↑↓ · Space · F folder · P preset · C cache · G intensity · Del remove · S start · Q quit",
    );
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
