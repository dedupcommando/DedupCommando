// SPDX-License-Identifier: Apache-2.0
//! Triage Board — separate 3-panel screen for manual file layout.
//!
//! Center — source, 4 receivers in the corners with labels 1–4. The existing
//! 4-panel commander is NOT touched: Board is drawn on top of it and intercepts
//! input while `board_active`. Focus cycles across all 5 panels (Tab/←→/mouse);
//! navigation and move act on the focused panel. Digit 1–4 sends the file
//! (or Insert-batch) from the focused panel to receiver N. The move/dedup/
//! log engine is reused from `super` (triage v1).

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind},
    layout::{Constraint, Layout, Position, Rect},
    style::{Color, Style},
    text::Line,
    widgets::Paragraph,
    Frame,
};

use crate::app::App;

use super::state::{BoardState, EntryKind, LoadTarget, Mark, Panel, PanelLoadRequest};
use super::{
    collect_source_batch, ensure_panel_loader, layout, next_survivor, panel, reload_target,
    restore_one, spawn_move, DOUBLE_CLICK,
};

/// Splits the Board area vertically: panels, status line, legend.
fn board_rows(area: Rect) -> [Rect; 3] {
    let rows = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);
    [rows[0], rows[1], rows[2]]
}

/// `(focus-slot, rectangle)` of the five Board panels top-to-bottom/left-to-right.
fn board_slots(panels_area: Rect) -> [(usize, Rect); 5] {
    let r = layout::board_regions(panels_area);
    [
        (0, r.center),
        (1, r.left_top),
        (2, r.left_bot),
        (3, r.right_top),
        (4, r.right_bot),
    ]
}

/// Renders the Triage Board screen: source in the center, 4 receivers in the
/// corners, status line and legend at the bottom. The focused panel is highlighted.
pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    app.commander.term_width = area.width;
    app.commander.term_height = area.height;
    let [panels_area, status_area, legend_area] = board_rows(area);
    let slots = board_slots(panels_area);

    // Take BoardState by value for the duration of rendering — otherwise a
    // simultaneous `&mut board` and `&app.commander.dedup` conflict on borrow.
    let Some(mut board) = app.commander.board.take() else {
        let para =
            Paragraph::new("  Board — not initialized").style(Style::new().fg(Color::DarkGray));
        frame.render_widget(para, panels_area);
        return;
    };

    let dir_sizes = &app.commander.dir_size_cache;
    let cross: HashSet<String> = HashSet::new();
    let focus = board.focus;

    let source_dedup = app.commander.dedup.dir(&board.source.cwd);
    // Board does not use watch_cache (source/receivers are fixed).
    panel::render_panel(
        frame,
        slots[0].1,
        &mut board.source,
        source_dedup,
        &cross,
        dir_sizes,
        &[],
        &[],
        None,
        None,
        None,
        None,
        0,
        focus == 0,
        Some("SOURCE"),
    );
    let labels = ["1", "2", "3", "4"];
    for (i, label) in labels.iter().enumerate() {
        let dedup = app.commander.dedup.dir(&board.receivers[i].cwd);
        panel::render_panel(
            frame,
            slots[i + 1].1,
            &mut board.receivers[i],
            dedup,
            &cross,
            dir_sizes,
            &[],
            &[],
            None,
            None,
            None,
            None,
            i,
            focus == i + 1,
            Some(label),
        );
    }

    app.commander.board = Some(board);

    let mut status = if app.commander.status.is_empty() {
        "Triage Board".to_string()
    } else {
        app.commander.status.clone()
    };
    if app.commander.move_pending > 0 {
        status.push_str(&format!(
            "  [background moves: {}]",
            app.commander.move_pending
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(format!(" {status}"))).style(Style::new().fg(Color::Gray)),
        status_area,
    );
    frame.render_widget(
        Paragraph::new(Line::from(
            " Tab/←→ panel · ↑↓ file · Enter enter · Insert batch · 1-4 send · a+N receiver · S save · u undo · Esc exit",
        ))
        .style(Style::new().fg(Color::DarkGray)),
        legend_area,
    );
}

/// Triage Board input. Focus cycles across all 5 panels; `↑↓/Enter/Backspace/Insert`
/// act on the focused panel; `1`–`4` — send to receiver; `a`+digit —
/// assign a directory to a receiver; `u` — undo; `Esc`/`` `+F12 `` — exit.
pub fn on_key(app: &mut App, key: KeyEvent) {
    // ` prefix — second layer, so that `+F12 closes Board with the same combo
    // it opens with (xterm.js does not transmit Shift being held).
    if key.code == KeyCode::Char('`') {
        app.commander.second_layer = !app.commander.second_layer;
        return;
    }
    let layered = app.commander.second_layer;
    app.commander.second_layer = false;
    if let KeyCode::F(12) = key.code {
        if layered || key.modifiers.contains(KeyModifiers::SHIFT) {
            toggle(app);
            return;
        }
    }
    // Receiver directory assignment mode is armed (`a`): digit 1–4 assigns,
    // anything else — cancel.
    if assign_pending(app) {
        match key.code {
            KeyCode::Char(c @ '1'..='4') => assign_receiver(app, (c as u8 - b'1') as usize),
            _ => clear_assign(app),
        }
        return;
    }
    match key.code {
        KeyCode::Esc => toggle(app),
        KeyCode::Tab | KeyCode::Right => focus_step(app, 1),
        KeyCode::BackTab | KeyCode::Left => focus_step(app, -1),
        KeyCode::Up | KeyCode::Char('k') => move_focused_cursor(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_focused_cursor(app, 1),
        KeyCode::PageUp => move_focused_cursor(app, -15),
        KeyCode::PageDown => move_focused_cursor(app, 15),
        KeyCode::Home => move_focused_cursor(app, i32::MIN / 2),
        KeyCode::End => move_focused_cursor(app, i32::MAX / 2),
        KeyCode::Enter => enter_focused(app),
        KeyCode::Backspace => parent_focused(app),
        KeyCode::Insert => mark_focused_cursor(app),
        KeyCode::Char(c @ '1'..='4') => send_to_receiver(app, (c as u8 - b'1') as usize),
        KeyCode::Char('a') | KeyCode::Char('A') => begin_assign(app),
        KeyCode::Char('s') | KeyCode::Char('S') => {
            app.commander.status = if save_layout(app) {
                "Board layout saved".to_string()
            } else {
                "Failed to save layout".to_string()
            };
        }
        KeyCode::Char('u') | KeyCode::Char('U') => undo(app),
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            save_layout(app);
            app.should_quit = true;
        }
        _ => {}
    }
}

/// Mouse in Board: left click — focus the panel + cursor on the entry (a double
/// click on a directory enters it), wheel — scroll the panel under the cursor.
pub fn on_mouse(app: &mut App, mouse: MouseEvent) {
    let area = Rect::new(0, 0, app.commander.term_width, app.commander.term_height);
    let [panels_area, _, _] = board_rows(area);
    let pos = Position {
        x: mouse.column,
        y: mouse.row,
    };
    let Some((focus, rect)) = board_slots(panels_area)
        .into_iter()
        .find(|(_, rect)| rect.contains(pos))
    else {
        return;
    };
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            set_focus(app, focus);
            let Some(entry) = entry_at(app, focus, rect, pos) else {
                return;
            };
            set_cursor(app, focus, entry);
            let now = Instant::now();
            let double = app
                .commander
                .last_click
                .map(|(when, panel, row)| {
                    panel == focus && row == entry && now.duration_since(when) <= DOUBLE_CLICK
                })
                .unwrap_or(false);
            if double {
                app.commander.last_click = None;
                enter_focused(app);
            } else {
                app.commander.last_click = Some((now, focus, entry));
            }
        }
        MouseEventKind::ScrollDown => {
            set_focus(app, focus);
            move_focused_cursor(app, 1);
        }
        MouseEventKind::ScrollUp => {
            set_focus(app, focus);
            move_focused_cursor(app, -1);
        }
        _ => {}
    }
}

/// Persisted Board layout: directories of the source and 4 receivers.
#[derive(serde::Serialize, serde::Deserialize)]
struct BoardLayout {
    source: PathBuf,
    receivers: [PathBuf; 4],
}

/// File path of the saved Board layout: `<state_dir>/board.json`
/// (state_dir — parent of the checkpoint DB).
fn layout_path(app: &App) -> Option<PathBuf> {
    app.db_path.parent().map(|dir| dir.join("board.json"))
}

/// Saves the current Board panel directories to disk. Returns success.
fn save_layout(app: &App) -> bool {
    let Some(board) = app.commander.board.as_ref() else {
        return false;
    };
    let Some(path) = layout_path(app) else {
        return false;
    };
    let layout = BoardLayout {
        source: board.source.cwd.clone(),
        receivers: [
            board.receivers[0].cwd.clone(),
            board.receivers[1].cwd.clone(),
            board.receivers[2].cwd.clone(),
            board.receivers[3].cwd.clone(),
        ],
    };
    match serde_json::to_string_pretty(&layout) {
        Ok(json) => std::fs::write(&path, json).is_ok(),
        Err(_) => false,
    }
}

/// Reads the saved Board layout, if the file exists and is valid.
fn load_layout(app: &App) -> Option<BoardLayout> {
    let path = layout_path(app)?;
    let json = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&json).ok()
}

/// Opens/closes the Triage Board. On first open it takes directories from the
/// saved layout (`board.json`), otherwise — from the current commander panels, and
/// starts background loading. On close the layout is saved to disk.
/// BoardState is also kept in memory between shows within a session.
pub fn toggle(app: &mut App) {
    if app.commander.board_active {
        let saved = save_layout(app);
        app.commander.board_active = false;
        app.commander.status = if saved {
            "Board closed · layout saved".to_string()
        } else {
            "Board closed".to_string()
        };
        return;
    }
    if app.commander.board.is_none() {
        let (src, receivers) = match load_layout(app) {
            Some(saved) => (saved.source, saved.receivers),
            None => {
                let src = app.commander.active_panel().cwd.clone();
                let panel_cwd = |i: usize| app.commander.panels.get(i).map(|p| p.cwd.clone());
                let receivers = [
                    panel_cwd(0).unwrap_or_else(|| src.clone()),
                    panel_cwd(1).unwrap_or_else(|| src.clone()),
                    panel_cwd(2).unwrap_or_else(|| src.clone()),
                    panel_cwd(3).unwrap_or_else(|| src.clone()),
                ];
                (src, receivers)
            }
        };
        app.commander.board = Some(BoardState::new(src, receivers));
        reload_all(app);
    }
    if let Some(board) = app.commander.board.as_mut() {
        board.assign_pending = false;
        board.focus = 0;
    }
    app.commander.board_active = true;
    app.show_help = false;
    app.commander.status =
        "Board: Tab panel · 1-4 send · a+N receiver · S save · Esc exit".to_string();
}

// --- Focus and access to the focused panel --------------------------------

/// Current focus slot (0 — source, 1–4 — receivers).
fn current_focus(app: &App) -> usize {
    app.commander.board.as_ref().map_or(0, |b| b.focus)
}

/// Background-load target for the focus slot.
fn focus_target(focus: usize) -> LoadTarget {
    if focus == 0 {
        LoadTarget::BoardSource
    } else {
        LoadTarget::BoardReceiver(focus - 1)
    }
}

/// Reference to the panel of slot `focus` (0 — source, 1–4 — receivers).
fn focused_panel_ref(app: &App, focus: usize) -> Option<&Panel> {
    let board = app.commander.board.as_ref()?;
    if focus == 0 {
        Some(&board.source)
    } else {
        board.receivers.get(focus - 1)
    }
}

/// Mutable reference to the panel of slot `focus`.
fn focused_panel_mut(app: &mut App, focus: usize) -> Option<&mut Panel> {
    let board = app.commander.board.as_mut()?;
    if focus == 0 {
        Some(&mut board.source)
    } else {
        board.receivers.get_mut(focus - 1)
    }
}

/// Cycles focus by `delta` wrapping around (5 panels total).
fn focus_step(app: &mut App, delta: i32) {
    if let Some(board) = app.commander.board.as_mut() {
        board.focus = (board.focus as i32 + delta).rem_euclid(5) as usize;
    }
}

/// Sets focus to slot `focus`.
fn set_focus(app: &mut App, focus: usize) {
    if let Some(board) = app.commander.board.as_mut() {
        board.focus = focus;
    }
}

/// Sets the cursor of slot `focus`'s panel to entry `entry`.
fn set_cursor(app: &mut App, focus: usize, entry: usize) {
    if let Some(panel) = focused_panel_mut(app, focus) {
        panel.select(entry);
    }
}

/// Moves the focused panel's cursor by `delta`.
fn move_focused_cursor(app: &mut App, delta: i32) {
    let focus = current_focus(app);
    if let Some(panel) = focused_panel_mut(app, focus) {
        panel.move_cursor(delta);
    }
}

// --- Focused panel navigation ---------------------------------------------

/// Enter: enter the directory under the focused panel's cursor (for a file — nothing).
fn enter_focused(app: &mut App) {
    let focus = current_focus(app);
    let target = match focused_panel_ref(app, focus).and_then(|p| p.selected()) {
        Some(entry) if entry.is_dir() => entry.path.clone(),
        _ => return,
    };
    navigate(app, focus_target(focus), target);
}

/// Backspace: move to the parent directory of the focused panel.
fn parent_focused(app: &mut App) {
    let focus = current_focus(app);
    let parent =
        focused_panel_ref(app, focus).and_then(|p| p.cwd.parent().map(|x| x.to_path_buf()));
    if let Some(parent) = parent {
        navigate(app, focus_target(focus), parent);
    }
}

/// Navigates panel `target` into directory `dir`: read in the background, the panel
/// is marked "loading…", the cursor will return to the directory it left.
fn navigate(app: &mut App, target: LoadTarget, dir: PathBuf) {
    ensure_panel_loader(app);
    let Some(board) = app.commander.board.as_mut() else {
        return;
    };
    let panel = match target {
        LoadTarget::BoardSource => &mut board.source,
        LoadTarget::BoardReceiver(i) => match board.receivers.get_mut(i) {
            Some(panel) => panel,
            None => return,
        },
        LoadTarget::Commander(_) => return,
    };
    let previous = std::mem::replace(&mut panel.cwd, dir);
    panel.entries.clear();
    panel.list.select(None);
    panel.loading = true;
    panel.generation += 1;
    let request = PanelLoadRequest {
        target,
        generation: panel.generation,
        dir: panel.cwd.clone(),
        previous: Some(previous),
    };
    if let Some(loader) = &app.commander.panel_loader {
        let _ = loader.send(request);
    }
}

// --- Panel loading ---------------------------------------------------------

/// Starts background loading of the source and all 4 receivers.
fn reload_all(app: &mut App) {
    load(app, LoadTarget::BoardSource);
    for i in 0..4 {
        load(app, LoadTarget::BoardReceiver(i));
    }
}

/// Re-reads a Board panel's directory in the background, preserving cursor position.
/// Delegates to the shared `reload_target`.
fn load(app: &mut App, target: LoadTarget) {
    reload_target(app, target, None);
}

// --- Move ------------------------------------------------------------------

/// Insert: marks/unmarks the entry under the focused panel's cursor into the batch
/// (`Mark::Selected`) and steps down. File or directory (folder layout); not `..`.
fn mark_focused_cursor(app: &mut App) {
    let focus = current_focus(app);
    let Some(panel) = focused_panel_mut(app, focus) else {
        return;
    };
    let path = match panel.selected() {
        Some(entry) if matches!(entry.kind, EntryKind::File | EntryKind::Dir) => entry.path.clone(),
        _ => return,
    };
    match panel.marks.get(&path) {
        Some(Mark::Selected) => {
            panel.marks.remove(&path);
        }
        Some(_) => {}
        None => {
            panel.marks.insert(path, Mark::Selected);
        }
    }
    panel.move_cursor(1);
}

/// Digit 1–4: moves the entry under the focused panel's cursor (or the marked
/// batch) into receiver `receiver` in the BACKGROUND (UI is not blocked). Files — dedup-aware,
/// directories — whole. The source cursor auto-advances to the next surviving item.
fn send_to_receiver(app: &mut App, receiver: usize) {
    let focus = current_focus(app);
    if focus == receiver + 1 {
        app.commander.status = "Receiver matches the focused panel".to_string();
        return;
    }
    let from = focus_target(focus);
    let sources = match focused_panel_ref(app, focus) {
        Some(panel) => collect_source_batch(panel),
        None => return,
    };
    if sources.is_empty() {
        app.commander.status = "No file/directory under the cursor or marked".to_string();
        return;
    }
    let dest_dir = match app.commander.board.as_ref() {
        Some(board) => board.receivers[receiver].cwd.clone(),
        None => return,
    };
    // P0: safety snapshot BEFORE clearing marks; failure → cancel, marks intact.
    if let Err(msg) = super::ensure_source_snapshots(app, &sources) {
        app.commander.status = msg;
        return;
    }
    // Clear Selected marks immediately — the move goes to the background.
    if let Some(panel) = focused_panel_mut(app, focus) {
        for src in &sources {
            panel.marks.remove(src);
        }
    }
    // Auto-advance the source panel's cursor to the next surviving item.
    let keep = focused_panel_ref(app, focus).and_then(|panel| next_survivor(panel, &sources));
    let reload = vec![(from, keep), (LoadTarget::BoardReceiver(receiver), None)];
    spawn_move(
        app,
        sources,
        dest_dir,
        reload,
        format!("receiver {}", receiver + 1),
    );
}

/// `u`: undoes the last move (log shared with the old commander's triage),
/// then re-reads the Board source and receivers.
fn undo(app: &mut App) {
    let Some(record) = app.commander.move_log.pop() else {
        app.commander.status = "Nothing to undo".to_string();
        return;
    };
    let mut restored = 0usize;
    let mut failed = 0usize;
    for (from, to) in record.items.iter().rev() {
        match restore_one(to, from) {
            Ok(_) => restored += 1,
            Err(_) => failed += 1,
        }
    }
    app.commander.status = if failed == 0 {
        format!("Undone: {restored} restored")
    } else {
        format!("Partially undone: {restored} restored, {failed} errors")
    };
    let affected: Vec<PathBuf> = record
        .items
        .iter()
        .flat_map(|(from, to)| [from.clone(), to.clone()])
        .collect();
    super::invalidate_dir_sizes(app, &affected);
    reload_all(app);
}

// --- Receiver directory assignment ------------------------------------------

/// Which entry of slot `focus`'s panel is under point `pos` in area `rect` (as in
/// the old commander's `panel_hit`: entries below the top border).
fn entry_at(app: &App, focus: usize, rect: Rect, pos: Position) -> Option<usize> {
    let panel = focused_panel_ref(app, focus)?;
    let inner_rows = rect.height.saturating_sub(2);
    let row = pos.y.checked_sub(rect.y + 1)?;
    if row >= inner_rows {
        return None;
    }
    let index = panel.list.offset() + row as usize;
    (index < panel.entries.len()).then_some(index)
}

/// Whether receiver directory assignment mode is armed (`a` pressed).
fn assign_pending(app: &App) -> bool {
    app.commander
        .board
        .as_ref()
        .is_some_and(|b| b.assign_pending)
}

/// `a`: arms assignment — the next digit 1–4 assigns the focused panel's current
/// directory to a receiver (the center works as a folder browser).
fn begin_assign(app: &mut App) {
    if let Some(board) = app.commander.board.as_mut() {
        board.assign_pending = true;
    }
    app.commander.status =
        "Assign receiver: digit 1–4 = current focused directory · Esc cancel".to_string();
}

/// Clears assignment mode.
fn clear_assign(app: &mut App) {
    if let Some(board) = app.commander.board.as_mut() {
        board.assign_pending = false;
    }
    app.commander.status = "Assignment cancelled".to_string();
}

/// Assigns the focused panel's current directory to receiver `receiver` and loads it.
fn assign_receiver(app: &mut App, receiver: usize) {
    let focus = current_focus(app);
    let dir = match focused_panel_ref(app, focus) {
        Some(panel) => panel.cwd.clone(),
        None => return,
    };
    if let Some(board) = app.commander.board.as_mut() {
        board.assign_pending = false;
        let panel = &mut board.receivers[receiver];
        panel.cwd = dir.clone();
        panel.entries.clear();
        panel.list.select(None);
        panel.marks.clear();
    }
    load(app, LoadTarget::BoardReceiver(receiver));
    app.commander.status = format!("Receiver {} ← {}", receiver + 1, dir.display());
}
