// SPDX-License-Identifier: Apache-2.0
//! Multi-panel file manager DedupCommando (commander).

pub mod actions;
pub mod board;
pub mod dedup;
pub mod layout;
pub mod move_batch;
pub mod overlay;
pub mod panel;
pub mod state;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind},
    layout::{Position, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::app::{App, Screen};
use crate::model::duplicate::{DirGroup, DuplicateGroup, FileEntry};
use crate::state::ScanStore;
use crate::tui::centered;
use crate::tui::event::AppEvent;

use self::dedup::{DedupStatus, DirDedup};
use self::state::{
    CommanderState, CompareMode, ConfirmTab, EntryKind, Mark, MoveRecord, Overlay, Panel,
    PanelEntry, PanelView, TriagePending, WatchResult,
};

/// Renders the commander screen.
pub fn render(frame: &mut Frame, app: &mut App) {
    // Triage Board — a separate full-screen view on top of the commander;
    // the old panels are not drawn.
    if app.commander.board_active {
        board::render(frame, app);
        return;
    }
    let regions = layout::regions(frame.area());
    app.commander.term_width = frame.area().width;
    app.commander.term_height = frame.area().height;
    render_header(frame, regions.header, app);

    let total = app.commander.panels.len();
    let visible = visible_panel_count(app, regions.panels.width);
    let rects = layout::panel_rects(regions.panels, visible);
    let cross = cross_panel_hashes(app);
    // Hybrid B — on a cwd change of the active panel
    // pick the freshest completed scan whose roots cover the cwd. If the
    // active one already covers it — noop; if not — `spawn_dedup_load(Some(new_id))`
    // or clear the overlay. Better called BEFORE `ensure_commander_groups_loaded` —
    // otherwise that would load the old scan's groups in vain.
    maybe_auto_switch_scan(app);
    // Group/directory summaries are loaded once on the first show of the groups mode;
    // groups of "watching" panels are resolved into a cache (DB — only on a source
    // change) so as not to open a connection every frame and not to conflict with
    // `&mut panels[index]`.
    ensure_commander_groups_loaded(app);
    resolve_watch_groups(app);
    // Maps of adjacent panels for side-by-side comparison —
    // collected before the render loop into an owning Vec so as not to conflict
    // with `&mut panels[index]` (the source_groups pattern).
    let compare_peers: Vec<Option<HashMap<String, panel::ComparePeer>>> =
        if matches!(app.commander.compare_mode, CompareMode::SideBySide) {
            (0..total)
                .map(|i| Some(build_compare_peer(app, (i + 1) % total)))
                .collect()
        } else {
            (0..total).map(|_| None).collect()
        };
    // A window of `visible` panels, always including the active one.
    let start = if app.commander.active < visible {
        0
    } else {
        app.commander.active + 1 - visible
    };
    for (slot, rect) in rects.iter().enumerate() {
        let index = start + slot;
        if index >= total {
            break;
        }
        let focused = index == app.commander.active;
        let dedup = app.commander.dedup.dir(&app.commander.panels[index].cwd);
        // We pass the whole WatchEntry — render uses both `result`
        // and `empty` (the reason for emptiness) for a targeted fallback.
        let source = app.commander.watch_cache.get(index);
        let source_dir_group = app
            .commander
            .watch_dir_cache
            .get(index)
            .and_then(|slot| slot.as_ref());
        panel::render_panel(
            frame,
            *rect,
            &mut app.commander.panels[index],
            dedup,
            &cross,
            &app.commander.dir_size_cache,
            &app.commander.group_summaries,
            &app.commander.dir_groups,
            source,
            source_dir_group,
            compare_peers[index].as_ref(),
            app.commander.dedup_scan_id,
            index,
            focused,
            None,
        );
    }

    render_status(frame, regions.status, app, visible);
    render_fkeys(frame, regions.fkeys, app.commander.second_layer);

    match app.commander.overlay {
        Overlay::Menu { cursor } => {
            let labels: Vec<&str> = MENU.iter().map(|(label, _)| *label).collect();
            overlay::render_menu(frame, cursor, &labels);
        }
        Overlay::Confirm {
            files,
            reclaim,
            tab,
        } => overlay::render_confirm(frame, files, reclaim, tab, &app.commander.confirm_script),
        Overlay::FileInfo => overlay::render_info(frame, &app.commander.info_lines),
        Overlay::ResumeScan => {
            let root = app
                .commander
                .pending_scan_roots
                .first()
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            overlay::render_resume_scan(
                frame,
                &root,
                app.commander.resume_unfinished.as_ref(),
                app.commander.resume_complete.as_ref(),
            );
        }
        Overlay::None => {}
    }
}

/// How many panels to actually show (no more than fit by width).
fn visible_panel_count(app: &App, width: u16) -> usize {
    app.commander
        .panels
        .len()
        .min(layout::max_panels(width))
        .max(1)
}

/// File hashes and folder signatures that appear in two or more panels —
/// cross-panel matches for bright highlighting.
fn cross_panel_hashes(app: &App) -> HashSet<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for panel in app.commander.panels.iter() {
        // Dedup data of the panel's directory; not in cache → panel does not participate.
        let Some(dir) = app.commander.dedup.dir(&panel.cwd) else {
            continue;
        };
        // A key is counted once per panel — even if there are several matches.
        let mut panel_keys: HashSet<&str> = HashSet::new();
        for entry in &panel.entries {
            match entry.kind {
                EntryKind::File => {
                    if let Some(hash) = dir.hash_for(&entry.path) {
                        panel_keys.insert(hash);
                    }
                }
                EntryKind::Dir => {
                    if let Some(sig) = dir.dir_signature(&entry.path) {
                        panel_keys.insert(sig);
                    }
                }
                EntryKind::Parent => {}
            }
        }
        for key in panel_keys {
            *seen.entry(key.to_string()).or_insert(0) += 1;
        }
    }
    seen.into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(key, _)| key)
        .collect()
}

/// Map of panel `panel_index`'s files for side-by-side comparison:
/// file name → size/mtime/hash. Built into an owning structure so as to
/// outlive the mutable borrow of panels in the render loop.
fn build_compare_peer(app: &App, panel_index: usize) -> HashMap<String, panel::ComparePeer> {
    let panel = &app.commander.panels[panel_index];
    let dir = app.commander.dedup.dir(&panel.cwd);
    let mut map = HashMap::new();
    for entry in &panel.entries {
        if !matches!(entry.kind, EntryKind::File) {
            continue;
        }
        map.insert(
            entry.name.clone(),
            panel::ComparePeer {
                size: entry.size,
                mtime: entry.mtime,
                hash: dir
                    .and_then(|d| d.hash_for(&entry.path))
                    .map(str::to_string),
            },
        );
    }
    map
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let _ = area; // width is no longer computed — no roots, the date is short
    let zfs = if app.zfs.warnings.is_empty() {
        format!("ZFS: datasets {}", app.zfs.dataset_count())
    } else {
        format!(
            "ZFS: datasets {} · warnings {}",
            app.zfs.dataset_count(),
            app.zfs.warnings.len(),
        )
    };
    // Instead of roots (a prior approach: superfluous static data that did not
    // react to the active panel's cwd) — the relative date of the
    // active scan. If there is no scan (auto-switch found none covering it) — an explicit
    // hint «F12 — select» so the user understands what to do.
    let dedup = match app.commander.dedup_scan_id {
        None => format!(
            "no scan for {} · F12 — select",
            app.commander.active_panel().cwd.display()
        ),
        Some(id) => {
            let when = scan_created_at(app, id)
                .as_deref()
                .map(humanize_ago)
                .unwrap_or_else(|| "—".to_string());
            if app
                .commander
                .dedup
                .is_pending(&app.commander.active_panel().cwd)
            {
                format!("scan #{id} · {when} (loading…)")
            } else {
                format!("scan #{id} · {when}")
            }
        }
    };
    let version_str = crate::version();
    let mode_label = "Multi-panel mode";
    // A brand strip in the style of the RAM/CPU indicator (white on
    // blue) + bold for weight. The color is aligned with the top-right badge — a single
    // visual class of "system plates".
    let brand = Span::styled(
        format!(" DedupCommando v{version_str} "),
        Style::new()
            .bg(Color::Blue)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    let para = Paragraph::new(Line::from(format!(" {mode_label}     {zfs}     {dedup} ",))).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Line::from(brand)),
    );
    frame.render_widget(para, area);
}

/// `created_at` of the active scan for the header. A pinpoint
/// lookup in `scan(id)`. Called every frame — a PK lookup is cheap.
fn scan_created_at(app: &App, scan_id: i64) -> Option<String> {
    ScanStore::open(&app.db_path)
        .ok()
        .and_then(|store| store.scan_created_at(scan_id).ok().flatten())
}

/// Human-readable "age" from a `created_at` string
/// (`"YYYY-MM-DD HH:MM:SS"` in local time, as written by `store::now_string`).
/// `< 1 h → "N min ago"`, `< 24 h → "N h ago"`, `< 7 days → "N d ago"`,
/// beyond that — `YYYY-MM-DD`. A broken string → `"long ago"` (we don't panic).
pub(crate) fn humanize_ago(created_at: &str) -> String {
    use chrono::{Local, NaiveDateTime};
    let parsed = NaiveDateTime::parse_from_str(created_at, "%Y-%m-%d %H:%M:%S");
    let Ok(naive) = parsed else {
        return "long ago".to_string();
    };
    let now = Local::now().naive_local();
    let delta = now.signed_duration_since(naive);
    let secs = delta.num_seconds().max(0);
    if secs < 60 {
        "just now".to_string()
    } else if secs < 60 * 60 {
        format!("{} min ago", secs / 60)
    } else if secs < 24 * 60 * 60 {
        format!("{} h ago", secs / 3600)
    } else if secs < 7 * 24 * 60 * 60 {
        format!("{} d ago", secs / 86400)
    } else {
        naive.format("%Y-%m-%d").to_string()
    }
}

/// Hybrid B — auto-switch of the active scan on a cwd change
/// of the active panel. If the current `dedup_scan_id` covers the cwd (or it is cached
/// as current), noop. Otherwise query `latest_scan_covering(cwd)`. We remember the
/// result in `scan_coverage_cache` so as not to hit the DB every frame.
fn maybe_auto_switch_scan(app: &mut App) {
    let cwd = app.commander.active_panel().cwd.clone();
    // Cache hit — we already know the covering id (or None).
    if let Some(&cached) = app.commander.scan_coverage_cache.get(&cwd) {
        apply_auto_switch(app, &cwd, cached);
        return;
    }
    // Cache miss — query the DB.
    let found = ScanStore::open(&app.db_path)
        .ok()
        .and_then(|store| store.latest_scan_covering(&cwd).ok().flatten());
    app.commander.scan_coverage_cache.insert(cwd.clone(), found);
    apply_auto_switch(app, &cwd, found);
}

/// Applies the auto-switch result. If `target ==
/// dedup_scan_id` (including both None) — nothing. Otherwise we update the overlay: a new id
/// → `spawn_dedup_load(Some(id))` (full background load); None → we reset the
/// active scan manually, WITHOUT a fallback to `latest_scan_id` (that was the root
/// bug previously — `spawn_dedup_load(None)` drags in any latest scan, even
/// if it concerns someone else's part of the tree).
fn apply_auto_switch(app: &mut App, cwd: &Path, target: Option<i64>) {
    if target == app.commander.dedup_scan_id {
        return;
    }
    match target {
        Some(id) => {
            let when = scan_created_at(app, id)
                .as_deref()
                .map(humanize_ago)
                .unwrap_or_else(|| "—".to_string());
            app.commander.status = format!("Scan #{id} activated · {when}");
            app.spawn_dedup_load(Some(id));
        }
        None => {
            app.commander.status = format!("No scan for {} · F12 — select", cwd.display());
            app.commander.dedup = dedup::DedupCache::default();
            app.commander.dedup_scan_id = None;
            app.commander.group_summaries = Vec::new();
            app.commander.dir_groups = Vec::new();
            app.commander.groups_loaded_for = None;
            app.commander.watch_cache = Vec::new();
            app.commander.watch_dir_cache = Vec::new();
        }
    }
}

fn render_status(frame: &mut Frame, area: Rect, app: &App, visible: usize) {
    // Triage (triage v1) — a hint about choosing the receiver panel.
    if let Some(pending) = &app.commander.triage {
        let total = app.commander.panels.len();
        let what = if pending.sources.len() == 1 {
            pending
                .sources
                .first()
                .and_then(|path| path.file_name())
                .map(|name| format!("«{}»", name.to_string_lossy()))
                .unwrap_or_else(|| "file".to_string())
        } else {
            format!("{} files", pending.sources.len())
        };
        frame.render_widget(
            Paragraph::new(Line::from(format!(
                " Move {what} → panel 1-{total} · Esc — cancel "
            ))),
            area,
        );
        return;
    }
    // Layer 2 is armed — a hint instead of the usual status line.
    if app.commander.second_layer {
        frame.render_widget(
            Paragraph::new(Line::from(" Layer 2: choose an F-key · Esc — cancel ")),
            area,
        );
        return;
    }
    let total = app.commander.panels.len();
    let base = if app.commander.status.is_empty() {
        let panel = app.commander.active_panel();
        // The color-semaphore legend is visible while there is no status message.
        format!(
            " Panel {}/{} · {} entries · m+1-4 triage · Insert select · u undo · =dup ≈similar ⚠cross · `layer2 ",
            app.commander.active + 1,
            total,
            panel.entries.len(),
        )
    } else {
        format!(" {} ", app.commander.status)
    };
    let text = if total > visible {
        format!(
            "{base}· panels hidden: {} — widen the window ",
            total - visible
        )
    } else {
        base
    };
    frame.render_widget(Paragraph::new(Line::from(text)), area);
}

/// Short labels of the FIRST-layer F-keys (F1..F12) for the footer. F3
/// was historically labeled «View» — out of habit from classic
/// two-panel shells, where F3 = view file contents. In our case this
/// key invokes `show_file_info` — an overlay with file PROPERTIES (size,
/// mtime, hash, dedup status), not a text view. Renamed to «File»
/// so the label reflects the actual action.
const FIRST_LAYER: [&str; 12] = [
    "Help", "Scan", "File", "Hash", "Hard", "Ref", "Keep", "Del", "Menu", "Exit", "Exec",
    "Sessions",
];

/// A single SECOND-layer F-key command (prefix `` ` `` or `Shift+F`). The SINGLE
/// source for the footer (`short`) and the help screen (`long`); over time the README is
/// auto-generated from here (roadmap). Empty `short`/`long` — the key is not assigned.
/// Changing the layout — edit ONLY `SECOND_LAYER`/`SECOND_LAYER_DISPATCH`; the test
/// `keymap_tests` guards against divergence of the footer, help, and dispatcher.
struct KeyHint {
    fkey: u8,
    short: &'static str,
    long: &'static str,
}

const SECOND_LAYER: [KeyHint; 12] = [
    KeyHint {
        fkey: 1,
        short: "Sync",
        long: "synchronize panels",
    },
    KeyHint {
        fkey: 2,
        short: "Compare",
        long: "compare panels (files and folders)",
    },
    KeyHint {
        fkey: 3,
        short: "+Panel",
        long: "add a panel",
    },
    KeyHint {
        fkey: 4,
        short: "-Panel",
        long: "remove a panel",
    },
    KeyHint {
        fkey: 5,
        short: "Root",
        long: "change the active panel's root",
    },
    KeyHint {
        fkey: 6,
        short: "Size",
        long: "recompute the directory size",
    },
    KeyHint {
        fkey: 7,
        short: "",
        long: "",
    },
    KeyHint {
        fkey: 8,
        short: "",
        long: "",
    },
    KeyHint {
        fkey: 9,
        short: "Wizard",
        long: "scan configuration wizard",
    },
    KeyHint {
        fkey: 10,
        short: "",
        long: "",
    },
    KeyHint {
        fkey: 11,
        short: "",
        long: "",
    },
    KeyHint {
        fkey: 12,
        short: "Board",
        long: "Triage Board (file triage)",
    },
];

/// Second-layer F-keys actually handled by `on_shift_fkey`. The bridge between
/// the data (`SECOND_LAYER`) and the dispatcher code; equality is guarded by `keymap_tests`.
const SECOND_LAYER_DISPATCH: [u8; 8] = [1, 2, 3, 4, 5, 6, 9, 12];

fn render_fkeys(frame: &mut Frame, area: Rect, second_layer: bool) {
    // The fill is only on the labels; the F-key digits stay without a fill.
    let fill_style = if second_layer {
        Style::new().fg(Color::Black).bg(Color::Yellow)
    } else {
        Style::new().fg(Color::Black).bg(Color::Cyan)
    };
    let total = area.width as usize;
    let mut spans: Vec<Span<'static>> = Vec::new();
    for index in 0..12 {
        let num = (index + 1).to_string();
        let label = if second_layer {
            SECOND_LAYER[index].short
        } else {
            FIRST_LAYER[index]
        };
        // Equal-width cells across the whole footer line — as in classic two-panel managers.
        let cell = (index + 1) * total / 12 - index * total / 12;
        let label_width = cell.saturating_sub(num.chars().count());
        let label = panel::fit(label, label_width);
        let label_cell = format!("{label:<label_width$}");
        spans.push(Span::raw(num));
        if label.is_empty() {
            spans.push(Span::raw(label_cell));
        } else {
            spans.push(Span::styled(label_cell, fill_style));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Handles a key in commander mode.
pub fn on_key(app: &mut App, key: KeyEvent) {
    // Triage Board is active — all input goes to the Board.
    if app.commander.board_active {
        board::on_key(app, key);
        return;
    }
    // An open overlay intercepts all input.
    if !matches!(app.commander.overlay, Overlay::None) {
        on_key_overlay(app, key);
        return;
    }
    dispatch_key(app, key);
}

/// Key dispatcher for the active commander screen (outside modal overlays).
fn dispatch_key(app: &mut App, key: KeyEvent) {
    // Triage (triage v1) is armed: we await the receiver digit — intercept everything.
    if app.commander.triage.is_some() {
        on_triage_key(app, key);
        return;
    }
    // Shift+F1–F12 — the second layer; a bonus for terminals that pass Shift+F.
    if key.modifiers.contains(KeyModifiers::SHIFT) {
        if let KeyCode::F(n) = key.code {
            app.commander.second_layer = false;
            on_shift_fkey(app, n);
            return;
        }
    }
    // The prefix key ` — arms/disarms the second layer of F-keys. xterm.js
    // (the Proxmox web console) does not pass a held Shift, so layer 2
    // is enabled by a prefix for a single F-key press.
    if key.code == KeyCode::Char('`') {
        app.commander.second_layer = !app.commander.second_layer;
        return;
    }
    // Layer 2 is armed: an F-key runs a layer-2 command, anything else disarms the layer.
    if app.commander.second_layer {
        app.commander.second_layer = false;
        if let KeyCode::F(n) = key.code {
            on_shift_fkey(app, n);
            return;
        }
    }
    match key.code {
        KeyCode::F(1) | KeyCode::Char('?') => app.show_help = true,
        KeyCode::F(2) => scan_active_panel(app),
        KeyCode::F(3) => show_file_info(app),
        KeyCode::F(4) => hash_cursor(app),
        KeyCode::F(9) => app.commander.overlay = Overlay::Menu { cursor: 0 },
        KeyCode::F(10) => app.should_quit = true,
        KeyCode::F(12) => app.open_wizard(Screen::Resume),
        KeyCode::F(5) => mark_cursor(app, Mark::Hardlink),
        KeyCode::F(6) => mark_cursor(app, Mark::Reflink),
        KeyCode::F(7) => mark_cursor(app, Mark::Keeper),
        KeyCode::F(8) => mark_cursor(app, Mark::Delete),
        KeyCode::F(11) => actions::prepare_execution(app),
        KeyCode::Char(' ') => toggle_mark_cursor(app),
        KeyCode::Char('s') | KeyCode::Char('S') => cycle_sort(app),
        KeyCode::Char('v') | KeyCode::Char('V') => cycle_view(app),
        KeyCode::Char(',') => toggle_compare(app),
        KeyCode::Char('m') | KeyCode::Char('M') => begin_triage(app),
        KeyCode::Char('u') | KeyCode::Char('U') => undo_last_move(app),
        KeyCode::Insert => select_toggle_cursor(app),
        KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,
        KeyCode::Tab => app.commander.focus_next(),
        KeyCode::BackTab => app.commander.focus_prev(),
        KeyCode::Left => app.commander.focus_prev(),
        KeyCode::Right => app.commander.focus_next(),
        KeyCode::Up | KeyCode::Char('k') => move_active_cursor(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_active_cursor(app, 1),
        KeyCode::PageUp => move_active_cursor(app, -15),
        KeyCode::PageDown => move_active_cursor(app, 15),
        // Home/End — a large shift, the clamp in move_cursor_within yields the edge of the list.
        KeyCode::Home => move_active_cursor(app, i32::MIN / 2),
        KeyCode::End => move_active_cursor(app, i32::MAX / 2),
        KeyCode::Enter => enter_selected(app),
        KeyCode::Backspace => go_parent(app),
        // The directory of the file under the cursor — into the adjacent right panel.
        KeyCode::Char('o') | KeyCode::Char('O') => jump_to_cursor_dir(app),
        _ => {}
    }
}

/// The mouse double-click recognition window.
const DOUBLE_CLICK: std::time::Duration = std::time::Duration::from_millis(400);

/// Handling of mouse events in commander mode: a left click on
/// a panel entry moves focus and the cursor, a double click on a directory enters
/// it, a click on the footer runs an F-command, the wheel scrolls the panel.
pub fn on_mouse(app: &mut App, mouse: MouseEvent) {
    // Triage Board is active — the Board handles the mouse.
    if app.commander.board_active {
        board::on_mouse(app, mouse);
        return;
    }
    // An open overlay intercepts input — we ignore the mouse over panels.
    if !matches!(app.commander.overlay, Overlay::None) {
        return;
    }
    // Triage is in progress (awaiting the receiver digit) — a click must not knock the cursor/focus off.
    if app.commander.triage.is_some() {
        return;
    }
    let area = Rect::new(0, 0, app.commander.term_width, app.commander.term_height);
    let regions = layout::regions(area);
    let pos = Position {
        x: mouse.column,
        y: mouse.row,
    };
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            // A click on the footer F-key line — run the command.
            if regions.fkeys.contains(pos) && regions.fkeys.width > 0 {
                let rel = mouse.column.saturating_sub(regions.fkeys.x) as usize;
                let n = (rel * 12 / regions.fkeys.width as usize + 1).min(12) as u8;
                let mods = if app.commander.second_layer {
                    KeyModifiers::SHIFT
                } else {
                    KeyModifiers::NONE
                };
                dispatch_key(app, KeyEvent::new(KeyCode::F(n), mods));
                return;
            }
            // A click on a panel entry — focus the panel, cursor on the entry;
            // a repeated click on the same entry within the DOUBLE_CLICK window — enter.
            if let Some((panel_index, Some(entry))) = panel_hit(app, &regions, pos) {
                app.commander.active = panel_index;
                app.commander.panels[panel_index].select(entry);
                let now = std::time::Instant::now();
                let double = app
                    .commander
                    .last_click
                    .map(|(when, panel, row)| {
                        panel == panel_index
                            && row == entry
                            && now.duration_since(when) <= DOUBLE_CLICK
                    })
                    .unwrap_or(false);
                if double {
                    app.commander.last_click = None;
                    open_panel_entry(app, panel_index, entry);
                } else {
                    app.commander.last_click = Some((now, panel_index, entry));
                }
            }
        }
        MouseEventKind::ScrollDown => {
            if let Some((panel_index, _)) = panel_hit(app, &regions, pos) {
                app.commander.active = panel_index;
                move_active_cursor(app, 1);
            }
        }
        MouseEventKind::ScrollUp => {
            if let Some((panel_index, _)) = panel_hit(app, &regions, pos) {
                app.commander.active = panel_index;
                move_active_cursor(app, -1);
            }
        }
        _ => {}
    }
}

/// Which panel (and which of its entries, if the cursor is on an entry row) is under the point.
fn panel_hit(
    app: &App,
    regions: &layout::Regions,
    pos: Position,
) -> Option<(usize, Option<usize>)> {
    if !regions.panels.contains(pos) {
        return None;
    }
    let total = app.commander.panels.len();
    let visible = visible_panel_count(app, regions.panels.width);
    let rects = layout::panel_rects(regions.panels, visible);
    let start = if app.commander.active < visible {
        0
    } else {
        app.commander.active + 1 - visible
    };
    for (slot, rect) in rects.iter().enumerate() {
        let index = start + slot;
        if index >= total {
            break;
        }
        if !rect.contains(pos) {
            continue;
        }
        let panel = &app.commander.panels[index];
        let row_count = panel_row_count(app, index);
        // Entry rows — under the top border, within the inner height.
        let inner_rows = rect.height.saturating_sub(2);
        let entry = pos
            .y
            .checked_sub(rect.y + 1)
            .filter(|row| *row < inner_rows)
            .map(|row| panel.list.offset() + row as usize)
            .filter(|entry| *entry < row_count);
        return Some((index, entry));
    }
    None
}

/// Handling of Shift+F-keys — the second layer of commander commands.
fn on_shift_fkey(app: &mut App, n: u8) {
    // Unassigned second-layer F-keys are ignored — the layout is set by the
    // SECOND_LAYER table, and its correspondence to these arms is guarded by keymap_tests.
    if !SECOND_LAYER_DISPATCH.contains(&n) {
        return;
    }
    match n {
        1 => sync_panels(app),
        2 => compare_panels(app),
        3 => match app.commander.add_panel() {
            Ok(index) => {
                let total = app.commander.panels.len();
                app.commander.status = format!("Panel added · total {total}");
                // Reading the new panel's directory — in the background (otherwise a slow
                // directory hangs the UI when adding a panel).
                reload_panel(app, index);
            }
            Err(message) => app.commander.status = message,
        },
        4 => match app.commander.remove_panel() {
            Ok(()) => {
                app.commander.status =
                    format!("Panel removed · total {}", app.commander.panels.len());
            }
            Err(message) => app.commander.status = message,
        },
        5 => change_panel_root(app),
        6 => recompute_dir_size(app),
        9 => app.open_wizard(Screen::ScanConfig),
        12 => board::toggle(app),
        _ => {}
    }
}

/// Shift+F5: switches the active panel's root to the next ZFS dataset.
fn change_panel_root(app: &mut App) {
    if app.commander.roots.is_empty() {
        app.commander.status = "No ZFS datasets to change the panel root".to_string();
        return;
    }
    let panel_index = app.commander.active;
    let current = app.commander.panels[panel_index].cwd.clone();
    let roots = &app.commander.roots;
    let next = roots
        .iter()
        .position(|root| *root == current)
        .map(|index| (index + 1) % roots.len())
        .unwrap_or(0);
    let target = roots[next].clone();
    navigate_panel(app, panel_index, target.clone());
    app.commander.status = format!("Panel {} → {}", panel_index + 1, target.display());
}

/// Shift+F1: opens the active panel's directory in all the other panels.
fn sync_panels(app: &mut App) {
    let active = app.commander.active;
    let cwd = app.commander.panels[active].cwd.clone();
    let count = app.commander.panels.len();
    for index in 0..count {
        if index != active {
            navigate_panel(app, index, cwd.clone());
        }
    }
    app.commander.status = format!("Panels synchronized: {}", cwd.display());
}

/// Shift+F2: compares the directories of the active and adjacent panels. Covered by a scan —
/// shows the number of matches (files and folders are already highlighted); not covered —
/// scans these directories, the overlay rebuilds in the background on completion.
fn compare_panels(app: &mut App) {
    let _bench = crate::bench::start("compare_panels");
    let total = app.commander.panels.len();
    if total < 2 {
        app.commander.status = "Comparison needs at least two panels".to_string();
        return;
    }
    let active = app.commander.active;
    let other = (active + 1) % total;
    let active_cwd = app.commander.panels[active].cwd.clone();
    let other_cwd = app.commander.panels[other].cwd.clone();
    if app.commander.dedup.is_pending(&active_cwd) || app.commander.dedup.is_pending(&other_cwd) {
        app.commander.status = "Overlay is still loading — retry later".to_string();
        return;
    }
    let covered =
        app.commander.dedup.covered(&active_cwd) && app.commander.dedup.covered(&other_cwd);
    if covered {
        let (files, dirs) = count_panel_matches(
            app.commander.dedup.dir(&active_cwd),
            app.commander.dedup.dir(&other_cwd),
            &app.commander.panels[active],
            &app.commander.panels[other],
        );
        app.commander.status = format!(
            "Panel comparison {}↔{}: matching files {files}, folders {dirs}",
            active + 1,
            other + 1,
        );
    } else {
        app.commander.status = format!(
            "Scanning for comparison: {} ↔ {}",
            active_cwd.display(),
            other_cwd.display(),
        );
        app.commander_scan(vec![active_cwd, other_cwd]);
    }
}

/// Counts matching files and folders between the active and adjacent panels.
fn count_panel_matches(
    active_dedup: Option<&DirDedup>,
    other_dedup: Option<&DirDedup>,
    active: &Panel,
    other: &Panel,
) -> (usize, usize) {
    let mut other_files: HashSet<&str> = HashSet::new();
    let mut other_dirs: HashSet<&str> = HashSet::new();
    for entry in &other.entries {
        match entry.kind {
            EntryKind::File => {
                if let Some(hash) = other_dedup.and_then(|d| d.hash_for(&entry.path)) {
                    other_files.insert(hash);
                }
            }
            EntryKind::Dir => {
                if let Some(sig) = other_dedup.and_then(|d| d.dir_signature(&entry.path)) {
                    other_dirs.insert(sig);
                }
            }
            EntryKind::Parent => {}
        }
    }
    let mut files = 0usize;
    let mut dirs = 0usize;
    for entry in &active.entries {
        match entry.kind {
            EntryKind::File => {
                if active_dedup
                    .and_then(|d| d.hash_for(&entry.path))
                    .is_some_and(|hash| other_files.contains(hash))
                {
                    files += 1;
                }
            }
            EntryKind::Dir => {
                if active_dedup
                    .and_then(|d| d.dir_signature(&entry.path))
                    .is_some_and(|sig| other_dirs.contains(sig))
                {
                    dirs += 1;
                }
            }
            EntryKind::Parent => {}
        }
    }
    (files, dirs)
}

/// The path belongs to a pseudo-FS (/proc, /sys, /dev, /run) — the directory size there
/// is meaningless (virtual files give absurd values) and is not computed.
fn is_pseudo_fs(path: &Path) -> bool {
    ["/proc", "/sys", "/dev", "/run"]
        .iter()
        .any(|&root| path.starts_with(root))
}

/// Total size of all files under the directory. Symlinks are not dereferenced,
/// pseudo-FS and too-deep nesting are skipped.
fn dir_size_recursive(dir: &Path, depth: u32) -> u64 {
    if depth > 64 || is_pseudo_fs(dir) {
        return 0;
    }
    let mut total = 0u64;
    if let Ok(read) = std::fs::read_dir(dir) {
        for entry in read.flatten() {
            // file_type() from dirent does NOT dereference symlinks (metadata()
            // did → the count went beyond the tree / into a loop). We skip the symlink,
            // bringing the code in line with the comment above.
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                total += dir_size_recursive(&entry.path(), depth + 1);
            } else if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            }
        }
    }
    total
}

#[cfg(test)]
mod dir_size_tests {
    use super::dir_size_recursive;
    use std::io::Write as _;

    #[test]
    fn does_not_follow_symlinked_dirs() {
        // hardening: a symlinked directory pointing outward must not enter the size sum.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base =
            std::env::temp_dir().join(format!("dedcom_dirsize_{}_{nanos}", std::process::id()));
        let inside = base.join("inside");
        let outside = base.join("outside");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::File::create(inside.join("real.bin"))
            .unwrap()
            .write_all(&[0u8; 10])
            .unwrap();
        std::fs::File::create(outside.join("big.bin"))
            .unwrap()
            .write_all(&[0u8; 1000])
            .unwrap();
        std::os::unix::fs::symlink(&outside, inside.join("link")).unwrap();

        // Count only the real file (10 B), not the symlink target (1000 B).
        assert_eq!(dir_size_recursive(&inside, 0), 10);

        let _ = std::fs::remove_dir_all(&base);
    }
}

/// Shift+F6: computes the size of the directory under the cursor in the background.
/// The size is computed only by this command — without a greedy background walk
/// that froze the interface; all tasks go through a single worker.
fn recompute_dir_size(app: &mut App) {
    let path = match app.commander.active_panel().selected() {
        Some(entry) if matches!(entry.kind, EntryKind::Dir) => entry.path.clone(),
        _ => {
            app.commander.status = "Not a directory under the cursor".to_string();
            return;
        }
    };
    if is_pseudo_fs(&path) {
        app.commander.status = format!("{} — pseudo-FS, size not computed", path.display());
        return;
    }
    if app.commander.dir_size_pending.contains(&path) {
        app.commander.status = format!("Size already being computed: {}", path.display());
        return;
    }
    app.commander.status = format!("Computing directory size: {}", path.display());
    enqueue_dir_size(app, path);
}

/// Lazily spawns the SINGLE background worker for computing directory sizes:
/// a recursive walk — metadata only — off the UI thread, the result
/// goes out as `AppEvent::CommanderDirSize`.
fn ensure_dir_sizer(app: &mut App) {
    if app.commander.dir_sizer.is_some() {
        return;
    }
    let (tx, rx) = crossbeam_channel::unbounded::<PathBuf>();
    let events = app.events.clone();
    std::thread::spawn(move || {
        while let Ok(dir) = rx.recv() {
            let size = dir_size_recursive(&dir, 0);
            let _ = events.send(AppEvent::CommanderDirSize(dir, size));
        }
    });
    app.commander.dir_sizer = Some(tx);
}

/// Queues directory `path` for a background size recompute: clears the old
/// cache and marks it pending (so render does not show a stale value), then
/// sends it to the worker. Skips pseudo-FS and directories already being computed.
fn enqueue_dir_size(app: &mut App, path: PathBuf) {
    if is_pseudo_fs(&path) || app.commander.dir_size_pending.contains(&path) {
        return;
    }
    ensure_dir_sizer(app);
    app.commander.dir_size_cache.remove(&path);
    app.commander.dir_size_pending.insert(path.clone());
    if let Some(sizer) = &app.commander.dir_sizer {
        let _ = sizer.send(path);
    }
}

/// Action of an F9 menu item.
#[derive(Debug, Clone, Copy)]
enum MenuAction {
    ScanActivePanel,
    WizardScanConfig,
    WizardResume,
    ClearMarks,
    ReloadDedup,
    CycleView,
    Help,
    /// A second-layer command (Shift+F): dispatched through `on_shift_fkey` —
    /// accessible without Shift if the terminal does not pass modified F-keys.
    ShiftLayer(u8),
}

/// Items of the F9 dropdown menu.
const MENU: [(&str, MenuAction); 13] = [
    (
        "Scan the active panel's directory",
        MenuAction::ScanActivePanel,
    ),
    ("Configure and start a scan…", MenuAction::WizardScanConfig),
    ("Sessions and scan results…", MenuAction::WizardResume),
    (
        "Clear all marks of the active panel",
        MenuAction::ClearMarks,
    ),
    ("Reload scan data", MenuAction::ReloadDedup),
    ("Change panel mode (v)", MenuAction::CycleView),
    ("Synchronize panels (Shift+F1)", MenuAction::ShiftLayer(1)),
    ("Compare panels (Shift+F2)", MenuAction::ShiftLayer(2)),
    ("Add a panel (Shift+F3)", MenuAction::ShiftLayer(3)),
    ("Remove a panel (Shift+F4)", MenuAction::ShiftLayer(4)),
    ("Change panel root (Shift+F5)", MenuAction::ShiftLayer(5)),
    (
        "Recompute directory size (Shift+F6)",
        MenuAction::ShiftLayer(6),
    ),
    ("Keyboard help", MenuAction::Help),
];

/// Input while an overlay is open.
fn on_key_overlay(app: &mut App, key: KeyEvent) {
    match app.commander.overlay {
        Overlay::Menu { cursor } => on_key_menu(app, key, cursor),
        Overlay::Confirm { .. } => on_key_confirm(app, key),
        Overlay::FileInfo => {
            if matches!(key.code, KeyCode::Esc | KeyCode::F(3) | KeyCode::Enter) {
                app.commander.overlay = Overlay::None;
            }
        }
        Overlay::ResumeScan => on_key_resume_scan(app, key),
        Overlay::None => {}
    }
}

/// Input in the F2 "resume session?" overlay: R/Enter — resume, N — new scan,
/// Esc — cancel.
fn on_key_resume_scan(app: &mut App, key: KeyEvent) {
    let unfinished = app
        .commander
        .resume_unfinished
        .as_ref()
        .map(|info| info.scan_id);
    let complete = app
        .commander
        .resume_complete
        .as_ref()
        .map(|info| info.scan_id);
    match key.code {
        // Resume the unfinished one (if there is one).
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if let Some(id) = unfinished {
                reset_resume_overlay(app);
                app.commander.pending_scan_roots.clear();
                app.commander_resume(id);
            }
        }
        // Open the completed one = show the LIST of results: fast from
        // materialization, without re-scanning; Esc from the list returns to the commander.
        KeyCode::Char('o') | KeyCode::Char('O') => {
            if let Some(id) = complete {
                reset_resume_overlay(app);
                app.commander.pending_scan_roots.clear();
                app.commander.return_to_commander = true;
                app.results_from_sessions = false; // F2 opens directly → Esc to the commander
                app.spawn_open_completed(id);
            }
        }
        // Enter — resume the unfinished one, otherwise open the completed one.
        KeyCode::Enter => {
            if let Some(id) = unfinished {
                reset_resume_overlay(app);
                app.commander.pending_scan_roots.clear();
                app.commander_resume(id);
            } else if let Some(id) = complete {
                reset_resume_overlay(app);
                app.commander.pending_scan_roots.clear();
                app.commander.return_to_commander = true;
                app.results_from_sessions = false; // F2 opens directly → Esc to the commander
                app.spawn_open_completed(id);
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') => {
            reset_resume_overlay(app);
            let roots = std::mem::take(&mut app.commander.pending_scan_roots);
            app.commander_scan_new(roots);
        }
        KeyCode::Esc => {
            reset_resume_overlay(app);
            app.commander.pending_scan_roots.clear();
            app.commander.status = "Scan cancelled".to_string();
        }
        _ => {}
    }
}

/// Closes the F2 overlay and resets its data.
fn reset_resume_overlay(app: &mut App) {
    app.commander.overlay = Overlay::None;
    app.commander.resume_unfinished = None;
    app.commander.resume_complete = None;
}

/// Input in the F11 confirmation overlay.
fn on_key_confirm(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => actions::confirm_execution(app),
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => actions::cancel_execution(app),
        // Switching the Summary/Commands tab and saving the script.
        KeyCode::Tab => toggle_confirm_tab(app),
        KeyCode::Char('s') | KeyCode::Char('S') => save_confirm_script(app),
        _ => {}
    }
}

/// `Tab` in the F11 confirmation: switches the Summary ↔ Commands tab.
fn toggle_confirm_tab(app: &mut App) {
    if let Overlay::Confirm {
        files,
        reclaim,
        tab,
    } = app.commander.overlay
    {
        let tab = match tab {
            ConfirmTab::Summary => ConfirmTab::Commands,
            ConfirmTab::Commands => ConfirmTab::Summary,
        };
        app.commander.overlay = Overlay::Confirm {
            files,
            reclaim,
            tab,
        };
    }
}

/// `S` in the F11 confirmation: saves the plan's shell script to
/// `<state_dir>/plans/<ts>.sh`. state_dir — the parent of the checkpoint DB file.
fn save_confirm_script(app: &mut App) {
    if app.commander.confirm_script.is_empty() {
        return;
    }
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let dir = app
        .db_path
        .parent()
        .map(|parent| parent.join("plans"))
        .unwrap_or_else(|| PathBuf::from("plans"));
    let path = dir.join(format!("{ts}.sh"));
    let result = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::write(&path, &app.commander.confirm_script));
    app.commander.status = match result {
        Ok(()) => format!("Script saved: {}", path.display()),
        Err(err) => format!("Failed to save script: {err}"),
    };
}

/// Input in the F9 dropdown menu.
fn on_key_menu(app: &mut App, key: KeyEvent, cursor: usize) {
    match key.code {
        KeyCode::Esc | KeyCode::F(9) => app.commander.overlay = Overlay::None,
        KeyCode::Up | KeyCode::Char('k') => {
            let next = if cursor == 0 {
                MENU.len() - 1
            } else {
                cursor - 1
            };
            app.commander.overlay = Overlay::Menu { cursor: next };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.commander.overlay = Overlay::Menu {
                cursor: (cursor + 1) % MENU.len(),
            };
        }
        KeyCode::Enter => {
            app.commander.overlay = Overlay::None;
            run_menu_action(app, MENU[cursor].1);
        }
        _ => {}
    }
}

/// Runs the selected menu item.
fn run_menu_action(app: &mut App, action: MenuAction) {
    match action {
        MenuAction::ScanActivePanel => scan_active_panel(app),
        MenuAction::WizardScanConfig => app.open_wizard(Screen::ScanConfig),
        MenuAction::WizardResume => app.open_wizard(Screen::Resume),
        MenuAction::ClearMarks => {
            app.commander.active_panel_mut().marks.clear();
            app.commander.status = "Active panel marks cleared".to_string();
        }
        MenuAction::ReloadDedup => reload_dedup(app),
        MenuAction::CycleView => cycle_view(app),
        MenuAction::Help => app.show_help = true,
        MenuAction::ShiftLayer(n) => on_shift_fkey(app, n),
    }
}

/// Starts a scan of the active panel's directory.
fn scan_active_panel(app: &mut App) {
    let cwd = app.commander.active_panel().cwd.clone();
    app.commander.status = format!("Scanning: {}", cwd.display());
    app.commander_scan(vec![cwd]);
}

/// Rebuilds the dedup index. Instead of a dumb
/// `spawn_dedup_load(None)` (which took latest_scan_id even if it concerned someone
/// else's part of the tree) we reset the coverage cache and ask `maybe_auto_switch_scan`
/// to pick again via `latest_scan_covering(active panel's cwd)`.
fn reload_dedup(app: &mut App) {
    app.commander.scan_coverage_cache.clear();
    maybe_auto_switch_scan(app);
    app.commander.status = "Refreshing the dedup overlay…".to_string();
}

/// F4: computes the hash of the file under the cursor in a background thread.
fn hash_cursor(app: &mut App) {
    let path = match app.commander.active_panel().selected() {
        Some(entry) if matches!(entry.kind, EntryKind::File) => entry.path.clone(),
        _ => {
            app.commander.status = "Only a file can be hashed".to_string();
            return;
        }
    };
    app.commander.status = format!("Hashing: {}", path.display());
    app.commander_hash(path);
}

/// F3: shows the overlay with details of the file under the cursor.
fn show_file_info(app: &mut App) {
    let entry = match app.commander.active_panel().selected() {
        Some(entry) => entry.clone(),
        None => return,
    };
    let mut lines = vec![
        format!("Name:     {}", entry.name),
        format!("Path:     {}", entry.path.display()),
    ];
    if matches!(entry.kind, EntryKind::File) {
        lines.push(format!("Size:     {}", crate::tui::human_bytes(entry.size)));
        if entry.mtime > 0 {
            lines.push(format!("Modified: {}", panel::short_date(entry.mtime)));
        }
        // The hash comes from the directory cache, otherwise a one-off DB lookup; duplicates —
        // via a one-off `group_files` (we no longer keep all groups in RAM).
        let cwd = app.commander.active_panel().cwd.clone();
        let scan_id = app.commander.dedup_scan_id;
        let mut hash = app
            .commander
            .dedup
            .dir(&cwd)
            .and_then(|d| d.hash_for(&entry.path))
            .map(str::to_string);
        let mut peers: Vec<String> = Vec::new();
        if let (Some(scan_id), Ok(store)) = (scan_id, ScanStore::open(&app.db_path)) {
            if hash.is_none() {
                hash = store
                    .hash_for_path(scan_id, &entry.path)
                    .ok()
                    .flatten()
                    .map(|h| crate::model::duplicate::hex_encode(&h));
            }
            if let Some(hash) = &hash {
                if let Ok(files) = store.group_files(scan_id, hash) {
                    peers = files
                        .iter()
                        .filter(|file| file.path != entry.path)
                        .map(|file| format!("  · {}", file.path.display()))
                        .collect();
                }
            }
        }
        match hash {
            Some(hash) => {
                lines.push(format!("Hash:     {hash}"));
                if peers.is_empty() {
                    lines.push("No duplicates found".to_string());
                } else {
                    lines.push(format!("Duplicates ({}):", peers.len()));
                    lines.extend(peers);
                }
            }
            None => lines.push("Hash:     not computed — F4 to calculate".to_string()),
        }
    }
    app.commander.info_lines = lines;
    app.commander.overlay = Overlay::FileInfo;
}

/// Enter: enters the directory under the cursor.
fn enter_selected(app: &mut App) {
    let index = app.commander.active;
    let target = match app.commander.panels[index].selected() {
        Some(entry) if entry.is_dir() => entry.path.clone(),
        _ => return,
    };
    navigate_panel(app, index, target);
}

/// Backspace: navigates to the parent directory.
fn go_parent(app: &mut App) {
    let index = app.commander.active;
    let parent = match app.commander.panels[index].cwd.parent() {
        Some(parent) => parent.to_path_buf(),
        None => return,
    };
    navigate_panel(app, index, parent);
}

/// Lazily spawns the background worker that reads panel directories.
fn ensure_panel_loader(app: &mut App) {
    if app.commander.panel_loader.is_some() {
        return;
    }
    let (tx, rx) = crossbeam_channel::unbounded::<state::PanelLoadRequest>();
    let events = app.events.clone();
    std::thread::spawn(move || {
        while let Ok(request) = rx.recv() {
            let entries = state::read_panel_dir(&request.dir);
            let _ = events.send(AppEvent::CommanderPanelLoaded {
                target: request.target,
                generation: request.generation,
                entries,
                previous: request.previous,
            });
        }
    });
    app.commander.panel_loader = Some(tx);
}

/// Navigates panel `index` to the directory `target`: reading happens in the background,
/// the panel is marked «loading…», a result stale by `generation` is discarded.
fn navigate_panel(app: &mut App, index: usize, target: PathBuf) {
    ensure_panel_loader(app);
    let panel = &mut app.commander.panels[index];
    let previous = std::mem::replace(&mut panel.cwd, target);
    panel.entries.clear();
    panel.list.select(None);
    panel.loading = true;
    panel.generation += 1;
    let request = state::PanelLoadRequest {
        target: state::LoadTarget::Commander(index),
        generation: panel.generation,
        dir: panel.cwd.clone(),
        previous: Some(previous),
    };
    if let Some(loader) = &app.commander.panel_loader {
        let _ = loader.send(request);
    }
}

/// Async navigation of panel `index` to the directory `target_dir` with the
/// cursor landing on `cursor_file` after loading. Differs from `navigate_panel` only in
/// that it puts the passed file path into `PanelLoadRequest.previous`
/// (not «where we came from»). `apply_panel_load` already knows how to find `previous`
/// among the new `entries` and place the cursor on it (`state.rs:437-440`) — no new
/// load handlers are needed.
fn navigate_panel_with_cursor(
    app: &mut App,
    index: usize,
    target_dir: PathBuf,
    cursor_file: PathBuf,
) {
    ensure_panel_loader(app);
    let panel = &mut app.commander.panels[index];
    panel.cwd = target_dir;
    panel.entries.clear();
    panel.list.select(None);
    panel.loading = true;
    panel.generation += 1;
    let request = state::PanelLoadRequest {
        target: state::LoadTarget::Commander(index),
        generation: panel.generation,
        dir: panel.cwd.clone(),
        previous: Some(cursor_file),
    };
    if let Some(loader) = &app.commander.panel_loader {
        let _ = loader.send(request);
    }
}

/// Re-reads panel `index`'s directory in the background, preserving the cursor position.
pub(crate) fn reload_panel(app: &mut App, index: usize) {
    ensure_panel_loader(app);
    let panel = &mut app.commander.panels[index];
    let previous = panel.selected().map(|entry| entry.path.clone());
    panel.loading = true;
    panel.generation += 1;
    let request = state::PanelLoadRequest {
        target: state::LoadTarget::Commander(index),
        generation: panel.generation,
        dir: panel.cwd.clone(),
        previous,
    };
    if let Some(loader) = &app.commander.panel_loader {
        let _ = loader.send(request);
    }
}

/// Double-click on entry of panel `index`: enters the directory under the entry
/// (for the `..` entry — goes up a level). On a file — nothing.
fn open_panel_entry(app: &mut App, index: usize, entry: usize) {
    let target = match app.commander.panels[index].entries.get(entry) {
        Some(item) if item.is_dir() => item.path.clone(),
        _ => return,
    };
    navigate_panel(app, index, target);
}

/// Key `s`: cycles the active panel's sort key.
fn cycle_sort(app: &mut App) {
    let panel = app.commander.active_panel_mut();
    panel.sort = panel.sort.next();
    let sort = panel.sort;
    let current = panel.selected().map(|entry| entry.path.clone());
    state::sort_entries(&mut panel.entries, sort);
    if let Some(path) = current {
        if let Some(index) = panel.entries.iter().position(|entry| entry.path == path) {
            panel.select(index);
        }
    }
    app.commander.status = format!("Sort: {}", sort.label());
}

/// Length of panel `index`'s navigable list — depends on its mode.
fn panel_row_count(app: &App, index: usize) -> usize {
    let panel = &app.commander.panels[index];
    match panel.view {
        PanelView::Files | PanelView::DirsOnly => panel.entries.len(),
        PanelView::GroupList => app.commander.group_summaries.len(),
        PanelView::GroupFiles => app
            .commander
            .watch_cache
            .get(index)
            .and_then(|entry| entry.as_file_group())
            .map(|group| group.files.len())
            .unwrap_or(0),
        // DuplicatesOfCursor can show a FileGroup, DirGroup or InnerDupes.
        PanelView::DuplicatesOfCursor => match app
            .commander
            .watch_cache
            .get(index)
            .and_then(|entry| entry.result.as_ref())
        {
            Some(WatchResult::FileGroup(g)) => g.files.len(),
            Some(WatchResult::DirGroup(g)) => g.paths.len(),
            Some(WatchResult::InnerDupes(paths)) => paths.len(),
            None => 0,
        },
        PanelView::DirGroupList => app.commander.dir_groups.len(),
        PanelView::DirGroupFiles => app
            .commander
            .watch_dir_cache
            .get(index)
            .and_then(|slot| slot.as_ref())
            .map(|group| group.paths.len())
            .unwrap_or(0),
    }
}

/// Shifts the active panel's cursor, accounting for its mode.
fn move_active_cursor(app: &mut App, delta: i32) {
    let index = app.commander.active;
    let len = panel_row_count(app, index);
    app.commander.panels[index].move_cursor_within(delta, len);
}

/// Key `v`: cycles the active panel's mode.
fn cycle_view(app: &mut App) {
    let index = app.commander.active;
    let panel = &mut app.commander.panels[index];
    panel.view = panel.view.next();
    panel.list.select(None);
    let view = panel.view;
    // hints about the mode's actual requirements, so the user
    // immediately understands WHAT needs to be set up next door instead of hitting a
    // fallback. For `DuplicatesOfCursor` the source is Files/DirsOnly on the left; for
    // `GroupFiles` — `GroupList` on the left; for `DirGroupFiles` — `DirGroupList` on the left.
    let hint: &str = match view {
        PanelView::DuplicatesOfCursor => {
            " · needs «files» or «directories» on the left with the cursor · o — file's directory"
        }
        PanelView::GroupFiles => {
            " · needs «groups» on the left · o — file's directory in the adjacent panel"
        }
        PanelView::DirGroupFiles => " · needs «directory groups» on the left",
        _ => "",
    };
    app.commander.status = format!("Panel mode: {}{}", view.label(), hint);
    // File modes re-read the directory (DirsOnly filters).
    if matches!(view, PanelView::Files | PanelView::DirsOnly) {
        reload_panel(app, index);
    }
}

/// The pure part of the «o» jump: determines `(file, parent)` for the jump or
/// sets the status and returns `None`. No mutations of panels — only status.
/// Tested without `App` (see `jump_tests`).
pub(crate) fn jump_source(commander: &mut CommanderState) -> Option<(PathBuf, PathBuf)> {
    let src = commander.active;
    // We read the source fields up front to release the borrow before mutating status.
    let (src_view, src_cursor) = {
        let panel = &commander.panels[src];
        (panel.view, panel.list.selected())
    };
    let file = match src_view {
        PanelView::GroupFiles | PanelView::DuplicatesOfCursor => {
            let Some(cursor) = src_cursor else {
                commander.status = "No file under the cursor".to_string();
                return None;
            };
            commander
                .watch_cache
                .get(src)
                .and_then(|entry| entry.as_file_group())
                .and_then(|group| group.files.get(cursor))
                .map(|file| file.path.clone())
        }
        _ => {
            commander.status =
                "The «o» key works in the «group files» and «duplicates» modes".to_string();
            return None;
        }
    };
    let Some(file) = file else {
        commander.status = "No file under the cursor".to_string();
        return None;
    };
    let Some(parent) = file.parent().map(|p| p.to_path_buf()) else {
        commander.status = "The file has no parent directory".to_string();
        return None;
    };
    Some((file, parent))
}

/// Post-load check of the «o» jump: called from the
/// `AppEvent::CommanderPanelLoaded` handler after `apply_panel_load` for
/// `LoadTarget::Commander(panel_idx)`. If the pending matched (panel + generation),
/// we check whether the cursor landed on the expected file; a miss → status «not found».
/// A stale response (gen < pending on the same panel) — a silent reset. Tested without `App`.
pub(crate) fn check_jump_landed(commander: &mut CommanderState, panel_idx: usize, generation: u64) {
    let pending = commander
        .pending_jump
        .as_ref()
        .map(|p| (p.panel, p.generation, p.file.clone()));
    let Some((p_panel, p_gen, p_file)) = pending else {
        return;
    };
    if p_panel == panel_idx && p_gen == generation {
        let landed_ok = commander
            .panels
            .get(panel_idx)
            .and_then(|panel| panel.entries.get(panel.cursor()))
            .map(|entry| entry.path == p_file)
            .unwrap_or(false);
        if !landed_ok {
            let name = p_file
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| p_file.display().to_string());
            commander.status = format!(
                "File «{name}» not found in the directory — it may have been moved or deleted"
            );
        }
        commander.pending_jump = None;
    } else if p_gen < generation && p_panel == panel_idx {
        // A stale arrival (a new navigation has already started) — reset silently.
        commander.pending_jump = None;
    }
}

/// Key `o`/`O`: from a file row in `GroupFiles`/`DuplicatesOfCursor`
/// opens that file's parent directory in the adjacent panel on the right (in `Files`
/// mode); the cursor lands on the file via `PanelLoadRequest.previous`. If there is
/// no right panel — tries to add one; a narrow terminal / panel limit →
/// the error text into the status. The «not found» status is set later (see `check_jump_landed`).
fn jump_to_cursor_dir(app: &mut App) {
    let Some((file, parent)) = jump_source(&mut app.commander) else {
        return;
    };
    let src = app.commander.active;
    let total = app.commander.panels.len();
    let dest = if src + 1 < total {
        src + 1
    } else {
        match app.commander.add_panel() {
            Ok(idx) => idx,
            Err(msg) => {
                app.commander.status = msg;
                return;
            }
        }
    };
    // The target mode is Files (otherwise panel_row_count does not read from panel.entries).
    if app.commander.panels[dest].view != PanelView::Files {
        app.commander.panels[dest].view = PanelView::Files;
    }
    navigate_panel_with_cursor(app, dest, parent, file.clone());
    let generation = app.commander.panels[dest].generation;
    app.commander.pending_jump = Some(state::PendingJump {
        panel: dest,
        generation,
        file,
    });
}

/// Key `,`: toggles side-by-side comparison of adjacent panels.
fn toggle_compare(app: &mut App) {
    app.commander.compare_mode = match app.commander.compare_mode {
        CompareMode::Off => CompareMode::SideBySide,
        CompareMode::SideBySide => CompareMode::Off,
    };
    app.commander.status = match app.commander.compare_mode {
        CompareMode::SideBySide => {
            "Panel comparison: on (= identical · ≈ similar · ~ differs · + only here)".to_string()
        }
        CompareMode::Off => "Panel comparison: off".to_string(),
    };
}

/// Resolves the source group for the «watching» panel `i`:
/// GroupFiles takes the group selected in the adjacent GroupList panel on the left.
/// Loads the current scan's group summaries and directory groups into the commander —
/// once per scan, lazily on the first show of any group mode; they are freed on a
/// scan change (`spawn_dedup_load`). On /tank this is tens of MB, not the whole scan.
fn ensure_commander_groups_loaded(app: &mut App) {
    let Some(scan_id) = app.commander.dedup_scan_id else {
        return;
    };
    if app.commander.groups_loaded_for == Some(scan_id) {
        return;
    }
    let needs = app.commander.panels.iter().any(|panel| {
        matches!(
            panel.view,
            PanelView::GroupList
                | PanelView::GroupFiles
                | PanelView::DuplicatesOfCursor
                | PanelView::DirGroupList
                | PanelView::DirGroupFiles
        )
    });
    if !needs {
        return;
    }
    if let Ok(store) = ScanStore::open(&app.db_path) {
        app.commander.group_summaries = store.group_summaries(scan_id).unwrap_or_default();
        app.commander.dir_groups = store.dir_groups(scan_id).unwrap_or_default();
        app.commander.groups_loaded_for = Some(scan_id);
    }
}

/// Resolves the groups of «watching» panels into `watch_cache`/`watch_dir_cache`.
/// The DB is opened ONCE and only when a panel's source (key) changed — render
/// then reads the cache without opening a connection every frame. The key AND the
/// reason for emptiness are passed together via `Result<_, WatchEmpty>`.
fn resolve_watch_groups(app: &mut App) {
    let total = app.commander.panels.len();
    if app.commander.watch_cache.len() != total {
        app.commander.watch_cache = vec![state::WatchEntry::default(); total];
    }
    if app.commander.watch_dir_cache.len() != total {
        app.commander.watch_dir_cache = vec![None; total];
    }
    let scan_id = app.commander.dedup_scan_id;
    // We take the persistent connection from App: open once and return it,
    // rather than `ScanStore::open` in render on every frame — otherwise navigating the
    // commander's groups froze (the same class as the classic Browser freeze).
    let mut store: Option<ScanStore> = app.browse_store.take();
    for i in 0..total {
        let key_res = compute_watch_key(app, i);
        let new_key: Option<state::WatchKey> = key_res.as_ref().ok().cloned();
        let stale = app
            .commander
            .watch_cache
            .get(i)
            .map(|entry| entry.key != new_key)
            .unwrap_or(true);
        if stale {
            // On Err(NoSource) we have no key — we pass the reason straight through;
            // on Ok(key) we go into resolve, which distinguishes NotInScan/NoDuplicates.
            let outcome: Result<state::WatchResult, state::WatchEmpty> = match &key_res {
                Ok(k) => resolve_watch_group(app, scan_id, k, &mut store),
                Err(e) => Err(*e),
            };
            if let Some(entry) = app.commander.watch_cache.get_mut(i) {
                entry.key = new_key;
                match outcome {
                    Ok(result) => {
                        entry.result = Some(result);
                        entry.empty = state::WatchEmpty::default();
                    }
                    Err(reason) => {
                        entry.result = None;
                        entry.empty = reason;
                    }
                }
            }
        }
        let dir_group = resolve_dir_group(app, i);
        if let Some(slot) = app.commander.watch_dir_cache.get_mut(i) {
            *slot = dir_group;
        }
    }
    app.browse_store = store; // return the connection to App for reuse
}

/// The source key of the «watching» panel `i`: GroupFiles takes the
/// selected group of the adjacent GroupList panel on the left; DuplicatesOfCursor — the file
/// under the cursor of the source panel (on the left, for the leftmost one — the active one).
/// `Err(WatchEmpty)` explains WHY there is no key — render shows the specific
/// reason instead of the generic «no source» placeholder.
fn compute_watch_key(app: &App, i: usize) -> Result<state::WatchKey, state::WatchEmpty> {
    let panel = &app.commander.panels[i];
    match panel.view {
        PanelView::GroupFiles => {
            let source = i
                .checked_sub(1)
                .and_then(|j| app.commander.panels.get(j))
                .ok_or(state::WatchEmpty::NoSource)?;
            if source.view != PanelView::GroupList {
                return Err(state::WatchEmpty::NoSource);
            }
            let idx = source.list.selected().ok_or(state::WatchEmpty::NoSource)?;
            Ok(state::WatchKey::Group(idx))
        }
        PanelView::DuplicatesOfCursor => {
            let source = if i > 0 {
                &app.commander.panels[i - 1]
            } else {
                &app.commander.panels[app.commander.active]
            };
            // We allow Files and DirsOnly as the source (there the cursor may be
            // on either a file or a directory).
            if !matches!(source.view, PanelView::Files | PanelView::DirsOnly) {
                return Err(state::WatchEmpty::NoSource);
            }
            let entry = source.selected().ok_or(state::WatchEmpty::NoSource)?;
            match entry.kind {
                EntryKind::File => Ok(state::WatchKey::DupOf(entry.path.clone())),
                EntryKind::Dir => Ok(state::WatchKey::DirOf(entry.path.clone())),
                EntryKind::Parent => Err(state::WatchEmpty::NoSource),
            }
        }
        _ => Err(state::WatchEmpty::NoSource),
    }
}

/// Lazy provision of a DB connection (opened on the first access within a frame).
fn ensure_store<'a>(app: &App, store: &'a mut Option<ScanStore>) -> Option<&'a ScanStore> {
    if store.is_none() {
        *store = ScanStore::open(&app.db_path).ok();
    }
    store.as_ref()
}

/// Resolves the «watching» panel's result for the key `key`. The
/// `WatchResult` type — FileGroup (the old GroupFiles/DupOf), DirGroup (DirOf found
/// twins in `dir_dedup`) or InnerDupes (DirOf — fallback to duplicate files inside).
/// On an empty result we return `Err(WatchEmpty)` so that render
/// distinguishes «out of scan» vs «in scan, but no duplicates».
fn resolve_watch_group(
    app: &App,
    scan_id: Option<i64>,
    key: &state::WatchKey,
    store: &mut Option<ScanStore>,
) -> Result<state::WatchResult, state::WatchEmpty> {
    let scan_id = scan_id.ok_or(state::WatchEmpty::NotInScan)?;
    // If the connection could not be opened — we treat it as «out of scan» (the database
    // is unavailable → this scan has no visible data).
    let store = ensure_store(app, store).ok_or(state::WatchEmpty::NotInScan)?;
    match key {
        state::WatchKey::Group(idx) => {
            // GroupFiles: the group index from the adjacent GroupList panel. If the index
            // is out of the summaries' range — that is not «out of scan» but «no such group»
            // (an unsynchronized UI state) — we treat it as NoDuplicates.
            let hash = app
                .commander
                .group_summaries
                .get(*idx)
                .ok_or(state::WatchEmpty::NoDuplicates)?
                .hash
                .clone();
            let files = store
                .group_files(scan_id, &hash)
                .map_err(|_| state::WatchEmpty::NoDuplicates)?;
            Ok(state::WatchResult::FileGroup(DuplicateGroup {
                id: *idx,
                size_bytes: files.first().map(|file| file.size).unwrap_or(0),
                hash,
                files,
            }))
        }
        state::WatchKey::DupOf(path) => {
            // Hash_for_path = None → the file is not in the scan manifest → NotInScan.
            let hash = match store.hash_for_path(scan_id, path) {
                Ok(Some(h)) => h,
                Ok(None) => return Err(state::WatchEmpty::NotInScan),
                Err(_) => return Err(state::WatchEmpty::NotInScan),
            };
            let hex = crate::model::duplicate::hex_encode(&hash);
            // group_summary_for_hash = None → the file is in the scan, but not in a duplicate group.
            if store
                .group_summary_for_hash(scan_id, &hex)
                .ok()
                .flatten()
                .is_none()
            {
                return Err(state::WatchEmpty::NoDuplicates);
            }
            let files = store
                .group_files(scan_id, &hex)
                .map_err(|_| state::WatchEmpty::NoDuplicates)?;
            Ok(state::WatchResult::FileGroup(DuplicateGroup {
                id: 0,
                size_bytes: files.first().map(|file| file.size).unwrap_or(0),
                hash: hex,
                files,
            }))
        }
        state::WatchKey::DirOf(path) => {
            // First we look for twins in `dir_dedup`.
            if let Ok(Some(twins)) = store.dir_twins(scan_id, path) {
                return Ok(state::WatchResult::DirGroup(twins));
            }
            // Fallback: duplicate files INSIDE the directory.
            let inside = store
                .dup_files_inside(scan_id, path)
                .ok()
                .unwrap_or_default();
            if !inside.is_empty() {
                return Ok(state::WatchResult::InnerDupes(inside));
            }
            // Neither twins nor duplicates inside — we distinguish «out of scan»
            // (the directory was not scanned → hint the user to switch to a
            // covered subdirectory) and «in scan, but no duplicates» (everything is unique).
            if store.is_path_in_scan(scan_id, path).unwrap_or(false) {
                Err(state::WatchEmpty::NoDuplicates)
            } else {
                Err(state::WatchEmpty::NotInScan)
            }
        }
    }
}

/// Resolves the directory group for DirGroupFiles: takes the group
/// selected in the adjacent DirGroupList panel on the left — from the loaded `dir_groups`,
/// without hitting the DB.
fn resolve_dir_group(app: &App, i: usize) -> Option<DirGroup> {
    let panel = &app.commander.panels[i];
    if panel.view != PanelView::DirGroupFiles {
        return None;
    }
    let source = app.commander.panels.get(i.checked_sub(1)?)?;
    if source.view != PanelView::DirGroupList {
        return None;
    }
    let idx = source.list.selected()?;
    app.commander.dir_groups.get(idx).cloned()
}

/// Sets the mark `mark` on the file under the active panel's cursor.
fn mark_cursor(app: &mut App, mark: Mark) {
    if mark == Mark::Reflink && !app.zfs.capabilities.reflink_safe {
        app.commander.status =
            "reflink unavailable — needs ZFS 2.3+ with block cloning enabled".to_string();
        return;
    }
    let panel = app.commander.active_panel_mut();
    let entry = match panel.selected() {
        Some(entry) if matches!(entry.kind, EntryKind::File) => entry.clone(),
        _ => {
            app.commander.status = "A mark can only be set on a file".to_string();
            return;
        }
    };
    panel.marks.insert(entry.path.clone(), mark);
    panel.move_cursor(1);
    persist_mark(app, &entry, Some(mark));
}

/// Space: removes the mark from the entry under the cursor or sets «selected» (a file or
/// directory — for triage; `..` is not selected).
fn toggle_mark_cursor(app: &mut App) {
    let panel = app.commander.active_panel_mut();
    let entry = match panel.selected() {
        Some(entry) if matches!(entry.kind, EntryKind::File | EntryKind::Dir) => entry.clone(),
        _ => return,
    };
    let new_mark = if panel.marks.remove(&entry.path).is_some() {
        None
    } else {
        panel.marks.insert(entry.path.clone(), Mark::Selected);
        Some(Mark::Selected)
    };
    panel.move_cursor(1);
    persist_mark(app, &entry, new_mark);
}

/// Insert: selects/deselects the entry under the cursor into the batch (`Mark::Selected`) and
/// steps down — multiple batch selection. A file or directory
/// (folder triage); `..` is skipped. Selected is ephemeral (not in the DB); we do not touch
/// action marks (D/H/C/K).
fn select_toggle_cursor(app: &mut App) {
    let panel = app.commander.active_panel_mut();
    let entry = match panel.selected() {
        Some(entry) if matches!(entry.kind, EntryKind::File | EntryKind::Dir) => entry.clone(),
        _ => return,
    };
    match panel.marks.get(&entry.path) {
        Some(Mark::Selected) => {
            panel.marks.remove(&entry.path);
        }
        Some(_) => {}
        None => {
            panel.marks.insert(entry.path.clone(), Mark::Selected);
        }
    }
    panel.move_cursor(1);
}

/// Panel entries (files and directories) marked `Selected`, in display order;
/// if there are none — the single entry under the cursor (a file or directory, not `..`).
fn collect_source_batch(panel: &Panel) -> Vec<PathBuf> {
    let selected: Vec<PathBuf> = panel
        .entries
        .iter()
        .filter(|entry| matches!(entry.kind, EntryKind::File | EntryKind::Dir))
        .filter(|entry| matches!(panel.marks.get(&entry.path), Some(Mark::Selected)))
        .map(|entry| entry.path.clone())
        .collect();
    if !selected.is_empty() {
        return selected;
    }
    match panel.selected() {
        Some(entry) if matches!(entry.kind, EntryKind::File | EntryKind::Dir) => {
            vec![entry.path.clone()]
        }
        _ => Vec::new(),
    }
}

/// `m`: starts triage — fixes the source batch, awaits the receiver digit.
fn begin_triage(app: &mut App) {
    let active = app.commander.active;
    let sources = collect_source_batch(&app.commander.panels[active]);
    if sources.is_empty() {
        app.commander.status = "No file under the cursor or selection to move".to_string();
        return;
    }
    app.commander.triage = Some(TriagePending {
        sources,
        source_panel: active,
    });
}

/// Input during triage: a digit 1-4 — the receiver, Esc — cancel, everything else is swallowed.
fn on_triage_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.commander.triage = None;
            app.commander.status = "Move cancelled".to_string();
        }
        KeyCode::Char(c @ '1'..='4') => {
            let target = (c as u8 - b'1') as usize;
            perform_triage_move(app, target);
        }
        _ => {}
    }
}

/// Moves the source batch into panel `target`'s directory in the BACKGROUND (the UI is not
/// blocked): the snapshot safeguard runs once per dataset synchronously, then
/// move/dedup/hash/copy — in a separate thread; the result is applied on `CommanderMoveDone`.
fn perform_triage_move(app: &mut App, target: usize) {
    // We read the source WITHOUT taking triage out: on a cancel (snapshot/validation failure)
    // the state stays intact and the operation can be retried (P0).
    let (source_panel, sources) = match app.commander.triage.as_ref() {
        Some(pending) => (pending.source_panel, pending.sources.clone()),
        None => return,
    };
    let total = app.commander.panels.len();
    if target >= total {
        app.commander.status = format!("No panel {}", target + 1);
        return;
    }
    if target == source_panel {
        app.commander.status = "The target matches the source".to_string();
        return;
    }
    // P0: the safeguard snapshot BEFORE any destructive changes; a failure → cancel,
    // triage and marks intact.
    if let Err(msg) = ensure_source_snapshots(app, &sources) {
        app.commander.status = msg;
        return;
    }
    let Some(pending) = app.commander.triage.take() else {
        return;
    };
    // We remove the Selected marks — the move goes to the background.
    for src in &pending.sources {
        app.commander.panels[pending.source_panel].marks.remove(src);
    }
    let dest_dir = app.commander.panels[target].cwd.clone();
    let keep = next_survivor(
        &app.commander.panels[pending.source_panel],
        &pending.sources,
    );
    let reload = vec![
        (state::LoadTarget::Commander(pending.source_panel), keep),
        (state::LoadTarget::Commander(target), None),
    ];
    spawn_move(
        app,
        pending.sources,
        dest_dir,
        reload,
        format!("panel {}", target + 1),
    );
}

/// Starts the background move batch `sources` → `dest_dir` (the UI is not blocked).
/// IMPORTANT: the snapshot safeguard is done by the CALLER via
/// `ensure_source_snapshots` BEFORE clearing marks/triage and BEFORE this call; on a
/// snapshot failure the caller cancels the move and does not enter here. `spawn_move` only
/// queues the task to the background worker. `reload` — which panels to re-read and where
/// to put the cursor after completion; `label` — for the status line.
pub(crate) fn spawn_move(
    app: &mut App,
    sources: Vec<PathBuf>,
    dest_dir: PathBuf,
    reload: Vec<(state::LoadTarget, Option<PathBuf>)>,
    label: String,
) {
    if app.deny_if_read_only("moving files") {
        return;
    }
    if sources.is_empty() {
        return;
    }
    let scan_id = app.commander.dedup_scan_id;
    ensure_move_worker(app);
    app.commander.move_pending += 1;
    app.commander.status = format!("→ {label}: moving {}…", sources.len());
    let request = state::MoveRequest {
        sources,
        dest_dir,
        scan_id,
        reload,
        label,
    };
    if let Some(worker) = &app.commander.move_worker {
        let _ = worker.send(request);
    }
}

/// Lazily spawns the SINGLE background move worker: processes
/// `MoveRequest`s one at a time → serialization (parallel copies do not thrash the disk, no
/// races between batches). The worker is self-contained — db_path + events from the closure,
/// without `CommanderState`.
fn ensure_move_worker(app: &mut App) {
    if app.commander.move_worker.is_some() {
        return;
    }
    let (tx, rx) = crossbeam_channel::unbounded::<state::MoveRequest>();
    let db_path = app.db_path.clone();
    let events = app.events.clone();
    std::thread::spawn(move || {
        while let Ok(request) = rx.recv() {
            let mut outcome = move_batch::run_batch(
                &db_path,
                &request.sources,
                &request.dest_dir,
                request.scan_id,
            );
            outcome.reload = request.reload;
            outcome.label = request.label;
            let _ = events.send(AppEvent::CommanderMoveDone(Box::new(outcome)));
        }
    });
    app.commander.move_worker = Some(tx);
}

/// Applies the background move batch's result to the UI: Undo log,
/// hash index, hashing of unknowns, status and re-reading of panels.
pub(crate) fn apply_move_outcome(app: &mut App, outcome: move_batch::MoveBatchOutcome) {
    app.commander.move_pending = app.commander.move_pending.saturating_sub(1);
    // The sizes of the source and receiver directories are now stale.
    let affected: Vec<PathBuf> = outcome
        .moved
        .iter()
        .flat_map(|(from, to)| [from.clone(), to.clone()])
        .collect();
    invalidate_dir_sizes(app, &affected);
    if !outcome.moved.is_empty() {
        app.commander.move_log.push(MoveRecord {
            items: outcome.moved.clone(),
        });
    }
    for (path, hash) in &outcome.hashes {
        app.commander.dedup.insert_hash(path.clone(), *hash);
    }
    if !outcome.to_hash.is_empty() {
        app.commander_hash_cache_batch(outcome.to_hash);
    }
    let moved = outcome.moved.len();
    let dup_note = if outcome.dups > 0 {
        format!(" · duplicates: {}", outcome.dups)
    } else {
        String::new()
    };
    app.commander.status = if outcome.failed == 0 {
        format!("→ {}: moved {moved}{dup_note}", outcome.label)
    } else {
        // The reasons (including a refused cross-dataset move with the rsync hint,
        // hardening) are written to dedcom.log — the status line is one line, it won't fit all.
        format!(
            "→ {}: moved {moved}, errors {} (reasons in dedcom.log){dup_note}",
            outcome.label, outcome.failed
        )
    };
    // Explicit re-reads (source + receiver-target) — carry the cursor hint.
    let explicit: Vec<state::LoadTarget> =
        outcome.reload.iter().map(|(target, _)| *target).collect();
    for (target, keep) in outcome.reload {
        reload_target(app, target, keep);
    }
    // Bug 9.11: any OTHER open panel showing a directory touched by the move
    // (e.g. a second receiver in the same folder) did not see the files that appeared
    // until a manual leave-and-enter — we re-read it too.
    reload_touched_panels(app, &outcome.moved, &explicit);
    // Bug 9.11: the size of a visible folder into which contents were poured (a merge),
    // was shown from the frozen scan snapshot and «stood still» — recompute it in the background.
    refresh_affected_dir_sizes(app, &affected);
}

/// Re-reads every OPEN panel (Board source/receivers or commander panels)
/// whose `cwd` is the direct parent of a moved item, except those already
/// re-read explicitly (`already`). This way a second panel open on the same folder
/// immediately sees the files that appeared/disappeared (bug 9.11).
fn reload_touched_panels(
    app: &mut App,
    moved: &[(PathBuf, PathBuf)],
    already: &[state::LoadTarget],
) {
    let mut child_dirs: Vec<PathBuf> = Vec::new();
    for (from, to) in moved {
        for parent in [from.parent(), to.parent()].into_iter().flatten() {
            let dir = parent.to_path_buf();
            if !child_dirs.contains(&dir) {
                child_dirs.push(dir);
            }
        }
    }
    let mut targets: Vec<state::LoadTarget> = Vec::new();
    if let Some(board) = app.commander.board.as_ref() {
        if child_dirs.contains(&board.source.cwd) {
            targets.push(state::LoadTarget::BoardSource);
        }
        for (i, receiver) in board.receivers.iter().enumerate() {
            if child_dirs.contains(&receiver.cwd) {
                targets.push(state::LoadTarget::BoardReceiver(i));
            }
        }
    }
    for (i, panel) in app.commander.panels.iter().enumerate() {
        if child_dirs.contains(&panel.cwd) {
            targets.push(state::LoadTarget::Commander(i));
        }
    }
    for target in targets {
        if !already.contains(&target) {
            reload_target(app, target, None);
        }
    }
}

/// Recomputes in the background the size of every CURRENTLY VISIBLE folder-entry into
/// which something moved in/out. Otherwise its size is taken from the frozen scan snapshot
/// (`dedup.dir_size`) and does not change after a merge (bug 9.11). The walk — metadata
/// only and only over the folders on screen (cheap, metadata is hot in the ARC).
fn refresh_affected_dir_sizes(app: &mut App, affected: &[PathBuf]) {
    fn collect(panel: &Panel, affected: &[PathBuf], out: &mut Vec<PathBuf>) {
        for entry in &panel.entries {
            if matches!(entry.kind, EntryKind::Dir)
                && affected.iter().any(|path| path.starts_with(&entry.path))
                && !out.contains(&entry.path)
            {
                out.push(entry.path.clone());
            }
        }
    }
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(board) = app.commander.board.as_ref() {
        collect(&board.source, affected, &mut dirs);
        for receiver in &board.receivers {
            collect(receiver, affected, &mut dirs);
        }
    }
    for panel in &app.commander.panels {
        collect(panel, affected, &mut dirs);
    }
    for dir in dirs {
        enqueue_dir_size(app, dir);
    }
}

/// Re-reads a panel (commander or Board) by its target in the background, placing the cursor on
/// `keep` (if found), otherwise preserving the current position.
pub(crate) fn reload_target(app: &mut App, target: state::LoadTarget, keep: Option<PathBuf>) {
    ensure_panel_loader(app);
    let panel: &mut Panel = match target {
        state::LoadTarget::Commander(i) => match app.commander.panels.get_mut(i) {
            Some(panel) => panel,
            None => return,
        },
        state::LoadTarget::BoardSource => match app.commander.board.as_mut() {
            Some(board) => &mut board.source,
            None => return,
        },
        state::LoadTarget::BoardReceiver(i) => {
            match app
                .commander
                .board
                .as_mut()
                .and_then(|b| b.receivers.get_mut(i))
            {
                Some(panel) => panel,
                None => return,
            }
        }
    };
    let previous = keep.or_else(|| panel.selected().map(|entry| entry.path.clone()));
    panel.loading = true;
    panel.generation += 1;
    let request = state::PanelLoadRequest {
        target,
        generation: panel.generation,
        dir: panel.cwd.clone(),
        previous,
    };
    if let Some(loader) = &app.commander.panel_loader {
        let _ = loader.send(request);
    }
}

/// Reads panel `target`'s directory dedup attributes from the DB in the background and puts
/// them into the cache by its `cwd`. Called on a panel directory load and on setting
/// `dedup_scan_id`. Without a scan — does nothing; a repeated fetch of the same cwd
/// is suppressed by the pending flag. Heavy lookups go in the background — the UI is not blocked.
pub(crate) fn fetch_panel_dedup(app: &mut App, target: state::LoadTarget) {
    let Some(scan_id) = app.commander.dedup_scan_id else {
        return;
    };
    let panel: &Panel = match target {
        state::LoadTarget::Commander(i) => match app.commander.panels.get(i) {
            Some(panel) => panel,
            None => return,
        },
        state::LoadTarget::BoardSource => match app.commander.board.as_ref() {
            Some(board) => &board.source,
            None => return,
        },
        state::LoadTarget::BoardReceiver(i) => {
            match app
                .commander
                .board
                .as_ref()
                .and_then(|b| b.receivers.get(i))
            {
                Some(panel) => panel,
                None => return,
            }
        }
    };
    let cwd = panel.cwd.clone();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    for entry in &panel.entries {
        match entry.kind {
            EntryKind::File => files.push(entry.path.clone()),
            EntryKind::Dir => dirs.push(entry.path.clone()),
            EntryKind::Parent => {}
        }
    }
    app.commander.dedup.mark_pending(cwd.clone());
    let db_path = app.db_path.clone();
    let events = app.events.clone();
    std::thread::spawn(move || {
        let dir = match ScanStore::open(&db_path) {
            Ok(store) => {
                let rows = store.dir_dedup_status(scan_id, &files).unwrap_or_default();
                let mut status = HashMap::new();
                let mut hashes = HashMap::new();
                for (path, row) in &rows {
                    status.insert(path.clone(), DedupStatus::classify(row));
                    if let Some(hash) = &row.hashed {
                        hashes.insert(path.clone(), hash.clone());
                    }
                }
                // The live sig must be computed with the same algorithm as the
                // persisted dir_dedup of this scan — otherwise the hex will diverge.
                let algo = store
                    .load_config(scan_id)
                    .map(|c| c.dir_sig_algo)
                    .unwrap_or_default();
                DirDedup {
                    status,
                    hashes,
                    dir_sizes: store.dir_sizes_under(scan_id, &dirs).unwrap_or_default(),
                    dir_signatures: store
                        .dir_signatures_under(scan_id, &dirs, algo)
                        .unwrap_or_default(),
                }
            }
            Err(_) => DirDedup::default(),
        };
        let _ = events.send(AppEvent::CommanderDirDedup { cwd, dir });
    });
}

/// The path of the entry the `panel` cursor will land on after moving `moved`: the first
/// surviving item (file or directory) from the cursor downward, otherwise upward; otherwise None.
pub(crate) fn next_survivor(panel: &Panel, moved: &[PathBuf]) -> Option<PathBuf> {
    let entries = &panel.entries;
    let cursor = panel.cursor().min(entries.len());
    let moved_set: HashSet<&PathBuf> = moved.iter().collect();
    let survives = |entry: &PanelEntry| {
        !matches!(entry.kind, EntryKind::Parent) && !moved_set.contains(&entry.path)
    };
    if let Some(entry) = entries.iter().skip(cursor).find(|e| survives(e)) {
        return Some(entry.path.clone());
    }
    entries[..cursor]
        .iter()
        .rev()
        .find(|e| survives(e))
        .map(|entry| entry.path.clone())
}

/// Returns a moved item from the path `to` back to `from` (for Undo):
/// a directory — via `move_dir`, a file — via `move_file`.
pub(crate) fn restore_one(to: &Path, from: &Path) -> crate::error::Result<PathBuf> {
    // The source directory may have been removed during a merge — we recreate it,
    // otherwise move_to will reject a non-existent destination.
    if let Some(parent) = from.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let is_dir = std::fs::symlink_metadata(to)
        .map(|meta| meta.is_dir())
        .unwrap_or(false);
    if is_dir {
        crate::actions::move_dir::move_dir_to(to, from)
    } else {
        crate::actions::move_file::move_to(to, from)
    }
}

/// Resets the directory-size cache (Shift+F6) for every affected path and
/// ALL its ancestors: after a file move/delete/undo, the sizes of
/// the parent directories become stale, otherwise the panel shows the old volume.
pub(crate) fn invalidate_dir_sizes(app: &mut App, paths: &[PathBuf]) {
    for path in paths {
        let mut node: Option<&Path> = Some(path.as_path());
        while let Some(dir) = node {
            app.commander.dir_size_cache.remove(dir);
            app.commander.dir_size_pending.remove(dir);
            node = dir.parent();
        }
    }
}

/// `u`: undoes the last move — returns files to their original paths.
fn undo_last_move(app: &mut App) {
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
        format!("Undone: restored {restored}")
    } else {
        format!("Partially undone: restored {restored}, errors {failed}")
    };
    let affected: Vec<PathBuf> = record
        .items
        .iter()
        .flat_map(|(from, to)| [from.clone(), to.clone()])
        .collect();
    invalidate_dir_sizes(app, &affected);
    let count = app.commander.panels.len();
    for index in 0..count {
        reload_panel(app, index);
    }
}

/// A safeguard ZFS snapshot of every affected source dataset — once per
/// run. A source NOT on a ZFS dataset → skip (a snapshot is inapplicable). The dataset
/// was found, but `zfs snapshot` failed → `Err`: the caller MUST cancel the move
/// (P0 — previously the data moved anyway «because there is Undo»; but
/// Undo does not cover a partial cross-dataset copy, a crash, a reboot, races, permissions).
pub(crate) fn ensure_source_snapshots(app: &mut App, sources: &[PathBuf]) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let datasets: Vec<crate::model::dataset::Dataset> = app
        .zfs
        .pools
        .iter()
        .flat_map(|pool| pool.datasets.iter().cloned())
        .collect();
    // Names of datasets requiring a snapshot (sources on ZFS, in order, without duplicates).
    let mut targets: Vec<String> = Vec::new();
    for src in sources {
        let Ok(meta) = std::fs::symlink_metadata(src) else {
            continue;
        };
        let device = meta.dev();
        let Some(dataset) = datasets.iter().find(|ds| ds.device_id == Some(device)) else {
            continue;
        };
        if !targets.contains(&dataset.name) {
            targets.push(dataset.name.clone());
        }
    }
    run_source_snapshots(&targets, &mut app.commander.snapshotted, |dataset| {
        // The same process counter as apply_batch (snapshot_suffix) —
        // otherwise two edits in the same second produced an identical snapshot name
        // (`zfs snapshot` → «already exists» → a false move refusal).
        let suffix = crate::actions::snapshot_suffix();
        crate::zfs::snapshots::create_snapshot(dataset, &suffix).map_err(|err| err.to_string())
    })
}

/// The pure core of the snapshot policy (testable without `zfs`): snapshots in order
/// each not-yet-snapshotted entry in `targets`; on the FIRST failure returns `Err` — the move
/// is cancelled. A success is marked in `already` so as not to duplicate within a run.
fn run_source_snapshots(
    targets: &[String],
    already: &mut std::collections::HashSet<String>,
    mut create: impl FnMut(&str) -> Result<String, String>,
) -> Result<(), String> {
    for dataset in targets {
        if already.contains(dataset) {
            continue;
        }
        match create(dataset) {
            Ok(_) => {
                already.insert(dataset.clone());
            }
            Err(err) => {
                return Err(format!(
                    "Snapshot {dataset} not created ({err}) — move cancelled"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod snapshot_tests {
    use super::run_source_snapshots;
    use std::collections::HashSet;

    #[test]
    fn aborts_on_first_failure_and_marks_only_successes() {
        let mut already: HashSet<String> = HashSet::new();
        let mut attempted: Vec<String> = Vec::new();
        let targets = vec![
            "pool/a".to_string(),
            "pool/b".to_string(),
            "pool/c".to_string(),
        ];
        let res = run_source_snapshots(&targets, &mut already, |ds| {
            attempted.push(ds.to_string());
            if ds == "pool/b" {
                Err("zfs snapshot failed".to_string())
            } else {
                Ok(format!("{ds}@snap"))
            }
        });
        assert!(
            res.is_err(),
            "a snapshot failure must return Err (the move is cancelled)"
        );
        assert_eq!(
            attempted,
            ["pool/a", "pool/b"],
            "stop on the first failure, did not reach c"
        );
        assert!(
            already.contains("pool/a"),
            "the successful snapshot is marked"
        );
        assert!(!already.contains("pool/b"), "the failed one is NOT marked");
    }

    #[test]
    fn empty_targets_is_ok_without_calling_create() {
        // Sources not on ZFS → targets is empty → Ok (a snapshot is inapplicable, the move proceeds).
        let mut already: HashSet<String> = HashSet::new();
        let res = run_source_snapshots(&[], &mut already, |_| -> Result<String, String> {
            panic!("create must not be called with empty targets")
        });
        assert!(res.is_ok());
    }

    #[test]
    fn already_snapshotted_dataset_is_skipped() {
        let mut already: HashSet<String> = HashSet::new();
        already.insert("pool/a".to_string());
        let mut calls = 0usize;
        let targets = vec!["pool/a".to_string()];
        let res = run_source_snapshots(&targets, &mut already, |_| {
            calls += 1;
            Ok("x".to_string())
        });
        assert!(res.is_ok());
        assert_eq!(
            calls, 0,
            "we do not touch again a dataset already snapshotted within the run"
        );
    }
}

/// Files of directory `dir` with a size of exactly `size` — a cheap duplicate pre-filter
/// (metadata only, without reading the contents).
fn same_size_files(dir: &Path, size: u64) -> Vec<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    let Ok(read) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in read.flatten() {
        if let Ok(meta) = entry.metadata() {
            if meta.is_file() && meta.size() == size {
                out.push(entry.path());
            }
        }
    }
    out
}

/// The first free name `{stem}.dup{N}{.ext}` in directory `dir` for the duplicate `src`.
fn dup_dest(dir: &Path, src: &Path) -> PathBuf {
    let stem = src
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = src.extension().map(|e| e.to_string_lossy().into_owned());
    let mut n = 1u32;
    loop {
        let name = match &ext {
            Some(ext) => format!("{stem}.dup{n}.{ext}"),
            None => format!("{stem}.dup{n}"),
        };
        let candidate = dir.join(name);
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// Persists the file's mark to the DB, if the file belongs to the current scan.
fn persist_mark(app: &mut App, entry: &PanelEntry, mark: Option<Mark>) {
    let Some(scan_id) = app.commander.dedup_scan_id else {
        return;
    };
    let file = FileEntry {
        path: entry.path.clone(),
        size: entry.size,
        mtime: entry.mtime,
        device: entry.device,
        inode: entry.inode,
        is_keeper: mark == Some(Mark::Keeper),
        action: mark.and_then(|mark| mark.action()),
    };
    if let Ok(mut store) = ScanStore::open(&app.db_path) {
        // We write the mark only for a file that is part of the scan (a pinpoint DB lookup
        // instead of reading the RAM index).
        match store.is_in_manifest(scan_id, &entry.path) {
            Ok(true) => {
                if let Err(err) = store.save_marks(scan_id, std::iter::once(&file)) {
                    tracing::warn!("commander: failed to save mark: {err}");
                }
            }
            Ok(false) => {}
            Err(err) => tracing::warn!("commander: manifest check failed: {err}"),
        }
    }
}

/// The commander's help overlay.
pub fn render_help(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 76, 42);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from(""),
        Line::from("  Multi-panel mode (commander)".bold()),
        Line::from(""),
        Line::from("  Navigation and panel view".bold()),
        Line::from("    ↑↓ / j k        cursor in the panel"),
        Line::from("    Tab / ← →       switch the active panel"),
        Line::from("    Enter           enter a directory"),
        Line::from("    Backspace       up a level"),
        Line::from("    PgUp PgDn Home End   fast movement"),
        Line::from("    Mouse           click — cursor/focus · 2×click — open · wheel"),
        Line::from("    s               sort: name / size / type / date"),
        Line::from("    v               mode: files / directories / groups / duplicates"),
        Line::from("    o               file's directory in the adjacent panel (in group modes)"),
        Line::from(""),
        Line::from("  Manual triage across directories".bold()),
        Line::from("    Insert          select a file into the batch"),
        Line::from("    m + 1-4         move the selection/file into panel #'s directory"),
        Line::from("    u               undo the last move"),
        Line::from(""),
        Line::from("  Function keys".bold()),
        Line::from("    F1 Help     F2 Scan     F3 File     F4 Hash"),
        Line::from("    F5 Hardlink F6 Reflink  F7 Keeper   F8 Delete"),
        Line::from("    F9 Menu     F10 Exit    F11 Execute  F12 Sessions"),
        Line::from(""),
        Line::from("  Second layer of F-keys".bold()),
        Line::from("    `           prefix: layer 2 for a single F-key press"),
    ];
    // Second-layer commands — from the single source SECOND_LAYER:
    // the footer and this help cannot diverge.
    for hint in SECOND_LAYER.iter().filter(|h| !h.long.is_empty()) {
        lines.push(Line::from(format!(
            "    ` F{:<2}       {}",
            hint.fkey, hint.long
        )));
    }
    lines.push(Line::from(
        "    (Shift+F also works, if the terminal passes it)",
    ));
    lines.push(Line::from(""));
    lines.push(Line::from("  Host (in full — in the log)".bold()));
    lines.push(Line::from(format!("    {}", app.host.summary_line())));
    lines.push(Line::from(""));
    lines.push(Line::from(format!("  DedupCommando {}", crate::version())));
    lines.push(Line::from("  [F1] or [Esc] — close".dim()));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(Block::default().borders(Borders::ALL).title(" Help ")),
        area,
    );
}

#[cfg(test)]
mod keymap_tests {
    use super::{FIRST_LAYER, SECOND_LAYER, SECOND_LAYER_DISPATCH};

    #[test]
    fn layers_have_twelve_entries() {
        assert_eq!(FIRST_LAYER.len(), 12);
        assert_eq!(SECOND_LAYER.len(), 12);
    }

    #[test]
    fn second_layer_fkeys_are_1_to_12_in_order() {
        for (index, hint) in SECOND_LAYER.iter().enumerate() {
            assert_eq!(
                hint.fkey as usize,
                index + 1,
                "second-layer F-numbers — in order"
            );
        }
    }

    #[test]
    fn second_layer_short_and_long_assigned_together() {
        // An assigned key must have BOTH a footer label AND a help description —
        // otherwise the footer and the help diverge.
        for hint in SECOND_LAYER.iter() {
            assert_eq!(
                hint.short.is_empty(),
                hint.long.is_empty(),
                "F{}: short and long are assigned together",
                hint.fkey
            );
        }
    }

    #[test]
    fn assigned_second_layer_matches_dispatch() {
        // The table (data) and on_shift_fkey (code) must not diverge: what is promised
        // in the footer/help is what the dispatcher handles.
        let assigned: Vec<u8> = SECOND_LAYER
            .iter()
            .filter(|hint| !hint.short.is_empty())
            .map(|hint| hint.fkey)
            .collect();
        assert_eq!(
            assigned,
            SECOND_LAYER_DISPATCH.to_vec(),
            "SECOND_LAYER and SECOND_LAYER_DISPATCH diverged — update both"
        );
    }
}

#[cfg(test)]
mod triage_tests {
    use super::*;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "dedcom_triage_{tag}_{}_{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn dup_dest_numbers_sequentially() {
        let dir = temp_dir("dup");
        let src = PathBuf::from("/somewhere/photo.jpg");
        let first = dup_dest(&dir, &src);
        assert_eq!(first, dir.join("photo.dup1.jpg"));
        fs::write(&first, b"x").unwrap();
        assert_eq!(dup_dest(&dir, &src), dir.join("photo.dup2.jpg"));
        // Without an extension.
        assert_eq!(dup_dest(&dir, Path::new("/s/data")), dir.join("data.dup1"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_size_files_filters_by_size() {
        let dir = temp_dir("size");
        fs::write(dir.join("a.bin"), b"12345").unwrap(); // 5 bytes
        fs::write(dir.join("b.bin"), b"12345").unwrap(); // 5 bytes
        fs::write(dir.join("c.bin"), b"123").unwrap(); // 3 bytes
        fs::create_dir(dir.join("sub")).unwrap(); // directory — ignored
        let mut got = same_size_files(&dir, 5);
        got.sort();
        assert_eq!(got, vec![dir.join("a.bin"), dir.join("b.bin")]);
        assert!(same_size_files(&dir, 999).is_empty());
        fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod jump_tests {
    //! Pure tests of the «o» jump (jump_source + check_jump_landed) on
    //! `CommanderState`, without `App` and async loading. The real end-to-end path
    //! (`jump_to_cursor_dir` → `navigate_panel_with_cursor`) is covered by a manual
    //! smoke on a synthetic tempdir — see the plan.

    use super::*;
    use crate::model::duplicate::{DuplicateGroup, FileEntry};
    use std::path::PathBuf;

    fn make_commander() -> CommanderState {
        CommanderState::new(&[PathBuf::from("/a"), PathBuf::from("/b")])
    }

    fn make_file_entry(path: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size: 100,
            mtime: 0,
            device: 1,
            inode: 1,
            is_keeper: false,
            action: None,
        }
    }

    fn make_panel_entry(path: &str) -> PanelEntry {
        let p = PathBuf::from(path);
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        PanelEntry {
            path: p,
            name,
            kind: EntryKind::File,
            size: 0,
            mtime: 0,
            device: 0,
            inode: 0,
        }
    }

    // --- jump_source ---

    #[test]
    fn jump_source_no_op_in_files_view_sets_status() {
        let mut commander = make_commander();
        commander.panels[0].view = PanelView::Files;
        commander.active = 0;
        let result = jump_source(&mut commander);
        assert!(result.is_none());
        assert!(
            commander.status.contains("modes"),
            "status: {}",
            commander.status
        );
    }

    #[test]
    fn jump_source_no_cursor_in_groupfiles_sets_status() {
        let mut commander = make_commander();
        commander.panels[0].view = PanelView::GroupFiles;
        commander.panels[0].list.select(None);
        commander.active = 0;
        let result = jump_source(&mut commander);
        assert!(result.is_none());
        assert!(
            commander.status.contains("No file under the cursor"),
            "status: {}",
            commander.status
        );
    }

    #[test]
    fn jump_source_returns_file_and_parent_from_watch_cache() {
        let mut commander = make_commander();
        commander.panels[0].view = PanelView::GroupFiles;
        commander.panels[0].list.select(Some(0));
        commander.active = 0;
        let entry = state::WatchEntry {
            result: Some(state::WatchResult::FileGroup(DuplicateGroup {
                id: 0,
                size_bytes: 100,
                hash: "abc".to_string(),
                files: vec![make_file_entry("/tmp/dir/foo.bin")],
            })),
            ..Default::default()
        };
        commander.watch_cache = vec![entry, state::WatchEntry::default()];
        let (file, parent) = jump_source(&mut commander).expect("the file should be found");
        assert_eq!(file, PathBuf::from("/tmp/dir/foo.bin"));
        assert_eq!(parent, PathBuf::from("/tmp/dir"));
    }

    // --- check_jump_landed ---

    #[test]
    fn check_jump_landed_clears_pending_when_file_at_cursor() {
        let mut commander = make_commander();
        commander.panels[0].entries = vec![make_panel_entry("/tmp/dir/foo.bin")];
        commander.panels[0].list.select(Some(0));
        commander.pending_jump = Some(state::PendingJump {
            panel: 0,
            generation: 1,
            file: PathBuf::from("/tmp/dir/foo.bin"),
        });
        let status_before = commander.status.clone();
        check_jump_landed(&mut commander, 0, 1);
        assert!(commander.pending_jump.is_none(), "pending reset");
        assert_eq!(
            commander.status, status_before,
            "status does not change on a hit"
        );
    }

    #[test]
    fn check_jump_landed_sets_status_when_file_missing() {
        let mut commander = make_commander();
        commander.panels[0].entries = vec![make_panel_entry("/tmp/dir/other.bin")];
        commander.panels[0].list.select(Some(0));
        commander.pending_jump = Some(state::PendingJump {
            panel: 0,
            generation: 1,
            file: PathBuf::from("/tmp/dir/foo.bin"),
        });
        check_jump_landed(&mut commander, 0, 1);
        assert!(commander.pending_jump.is_none(), "pending reset");
        assert!(
            commander.status.contains("not found"),
            "status: {}",
            commander.status
        );
        assert!(
            commander.status.contains("foo.bin"),
            "file name in status: {}",
            commander.status
        );
    }

    #[test]
    fn check_jump_landed_drops_stale_silently() {
        let mut commander = make_commander();
        commander.pending_jump = Some(state::PendingJump {
            panel: 0,
            generation: 1,
            file: PathBuf::from("/tmp/dir/foo.bin"),
        });
        let status_before = commander.status.clone();
        // generation=2 arrived, but pending was waiting for 1 — this is a stale response.
        check_jump_landed(&mut commander, 0, 2);
        assert!(commander.pending_jump.is_none(), "pending reset");
        assert_eq!(
            commander.status, status_before,
            "status does not change on stale"
        );
    }

    #[test]
    fn check_jump_landed_keeps_pending_for_other_panel() {
        let mut commander = make_commander();
        commander.pending_jump = Some(state::PendingJump {
            panel: 1,
            generation: 1,
            file: PathBuf::from("/tmp/dir/foo.bin"),
        });
        // A response arrived for another panel (0) — pending should remain.
        check_jump_landed(&mut commander, 0, 1);
        assert!(
            commander.pending_jump.is_some(),
            "we do not touch pending for another panel"
        );
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn humanize_ago_just_now_under_a_minute() {
        // < 60 sec → "just now".
        let now = chrono::Local::now().naive_local();
        let stamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
        assert_eq!(humanize_ago(&stamp), "just now");
    }

    #[test]
    fn humanize_ago_minutes_then_hours_then_days() {
        // We check the «N min» / «N h» / «N d» branches.
        let now = chrono::Local::now().naive_local();
        let mk = |secs: i64| -> String {
            (now - chrono::Duration::seconds(secs))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        assert!(humanize_ago(&mk(120)).contains("min"));
        assert!(humanize_ago(&mk(3 * 3600)).contains("h ago"));
        assert!(humanize_ago(&mk(2 * 24 * 3600)).contains("d ago"));
    }

    #[test]
    fn humanize_ago_old_falls_back_to_date() {
        // > 7 days → a concrete date YYYY-MM-DD.
        let old = chrono::Local::now().naive_local() - chrono::Duration::days(30);
        let stamp = old.format("%Y-%m-%d %H:%M:%S").to_string();
        let out = humanize_ago(&stamp);
        // Should be of the form YYYY-MM-DD (10 characters, two hyphens).
        assert_eq!(out.len(), 10);
        assert_eq!(out.chars().filter(|c| *c == '-').count(), 2);
    }

    #[test]
    fn humanize_ago_garbage_string_returns_long_ago() {
        // A broken string from the DB (old records / a manual
        // edit) → "long ago". We do not panic.
        assert_eq!(humanize_ago("not a date"), "long ago");
        assert_eq!(humanize_ago(""), "long ago");
    }
}
