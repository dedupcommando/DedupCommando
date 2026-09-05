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
use crate::error::AppError;
use crate::model::duplicate::FileEntry;
use crate::tui::centered;
use crate::tui::event::AppEvent;

use self::dedup::DirDedup;
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
    let cross = cross_panel_keys(app);
    // Hybrid B — on a cwd change of the active panel pick the freshest completed scan whose
    // roots cover the cwd. If the active one already covers it — noop; otherwise the answer
    // opens that scan, or clears the overlay.
    maybe_auto_switch_scan(app);
    // The summaries and the directory groups are already here: the browsing actor's `Open`
    // installed them whole. What remains is asking, once per source change, what each
    // «watching» panel points at.
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
        let dedup_error = app.commander.dedup.error(&app.commander.panels[index].cwd);
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
            dedup_error,
            &cross,
            &app.commander.dir_size_cache,
            &app.commander.group_summaries,
            &app.commander.dir_group_summaries,
            app.commander.dir_groups_error.as_deref(),
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
        Overlay::Confirm { tab } => overlay::render_confirm(
            frame,
            tab,
            &app.commander.confirm_script,
            &app.commander.confirm_digest,
            &mut app.commander.confirm_scroll,
        ),
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

/// The published groups and the trusted folder signatures that appear in two or more panels —
/// cross-panel matches for bright highlighting.
///
/// Files are keyed by the IDENTITY of the group the authority published, never by a digest: two
/// verified populations may legitimately share one digest, and keying on it would light them up
/// as one match. A row with no membership — unhashed, unpublished, inconsistent or verification-
/// rejected — contributes no key at all.
pub(crate) fn cross_panel_keys(app: &App) -> HashSet<MatchKey> {
    let mut seen: HashMap<MatchKey, usize> = HashMap::new();
    for panel in app.commander.panels.iter() {
        // Dedup data of the panel's directory; not in cache → panel does not participate.
        let Some(dir) = app.commander.dedup.dir(&panel.cwd) else {
            continue;
        };
        // A key is counted once per panel — even if there are several matches.
        let mut panel_keys: HashSet<MatchKey> = HashSet::new();
        for entry in &panel.entries {
            match entry.kind {
                EntryKind::File => {
                    if let Some(id) = dir.group_of(&entry.path) {
                        panel_keys.insert(MatchKey::Group(id));
                    }
                }
                EntryKind::Dir => {
                    // Trusted only: an untrusted signature must never make two panels claim an
                    // exact directory match.
                    if let Some(sig) = dir.trusted_dir_signature(&entry.path) {
                        panel_keys.insert(MatchKey::Directory(sig.to_string()));
                    }
                }
                EntryKind::Parent => {}
            }
        }
        for key in panel_keys {
            *seen.entry(key).or_insert(0) += 1;
        }
    }
    seen.into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(key, _)| key)
        .collect()
}

/// What two panels have to agree on for a row to light up as an exact cross-panel match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum MatchKey {
    /// The same published group — identity, not content.
    Group(crate::model::plan::GroupId),
    /// The same trusted directory signature.
    Directory(String),
}

/// Map of panel `panel_index`'s files for side-by-side comparison: file name → size/mtime plus
/// the published identity of its group. Built into an owning structure so as to outlive the
/// mutable borrow of panels in the render loop.
///
/// The identity is what decides «identical»; the digest travels only as the fallback heuristic
/// for rows the authority says nothing about.
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
                group: dir.and_then(|d| d.group_of(&entry.path)),
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

/// `created_at` of the active scan for the header.
///
/// Read from the one `Open` payload the browsing actor installed, not from the database: the
/// header renders every frame, and it used to open a connection each time.
fn scan_created_at(app: &App, _scan_id: i64) -> Option<String> {
    app.commander.scan_created_at.clone()
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
    // Cache miss — ask the actor ONCE. The reply fills the cache and applies the switch; until
    // it arrives this directory is simply not decided, and the frame renders without opening
    // anything.
    app.request_covering_scan(cwd);
}

/// Applies the auto-switch result. If `target ==
/// dedup_scan_id` (including both None) — nothing. Otherwise we update the overlay: a new id
/// → `spawn_dedup_load(Some(id))` (full background load); None → we reset the
/// active scan manually, WITHOUT a fallback to `latest_scan_id` (that was the root
/// bug previously — `spawn_dedup_load(None)` drags in any latest scan, even
/// if it concerns someone else's part of the tree).
pub(crate) fn apply_auto_switch(app: &mut App, cwd: &Path, target: Option<i64>) {
    if target == app.commander.dedup_scan_id {
        return;
    }
    match target {
        Some(id) => {
            // The creation time comes with the payload that installs the scan, so the status
            // says «activating» now and the header states the age once it is installed.
            app.commander.status = format!("Scan #{id} activated");
            app.spawn_dedup_load(Some(id));
        }
        None => {
            app.commander.status = format!("No scan for {} · F12 — select", cwd.display());
            app.commander.dedup = dedup::DedupCache::default();
            app.commander.dedup_scan_id = None;
            app.commander.group_summaries = Vec::new();
            app.commander.candidates = None;
            app.commander.scan_created_at = None;
            app.commander.dir_group_summaries = Vec::new();
            app.commander.dir_groups_error = None;
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
    // A running auto-select owns Esc: the sweep is the thing the operator is stopping.
    if key.code == KeyCode::Esc && app.cancel_auto_select() {
        return;
    }
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

/// Keys whose handlers read `entries[cursor]` (U-1 gated set).
fn is_entries_row_command(code: KeyCode) -> bool {
    matches!(
        code,
        KeyCode::F(3..=8)
            | KeyCode::Char(' ')
            | KeyCode::Insert
            | KeyCode::Enter
            | KeyCode::Char('m' | 'M')
    )
}

/// The prefix key followed by the digit row reaches a FIRST-layer F-key: 1-9 → F1-F9, 0 → F10,
/// `-` → F11, `=` → F12, in the order the keys sit above the letters. Terminals swallow F10
/// (menu) and F11 (fullscreen) before the application ever sees them, and Execute lived on F11
/// alone.
fn first_layer_key(code: KeyCode) -> Option<u8> {
    match code {
        KeyCode::Char(digit @ '1'..='9') => Some(digit as u8 - b'0'),
        KeyCode::Char('0') => Some(10),
        KeyCode::Char('-') => Some(11),
        KeyCode::Char('=') => Some(12),
        _ => None,
    }
}

/// Views whose rows come from `entries`; group views draw groups instead (U-1).
fn view_exposes_entries(view: PanelView) -> bool {
    matches!(view, PanelView::Files | PanelView::DirsOnly)
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
    // Layer 2 is armed: an F-key runs a layer-2 command; a digit runs the FIRST-layer command of
    // that number, because F10/F11 are exactly the keys GUI terminals keep for themselves.
    // Anything else disarms the layer and goes on to be handled normally.
    if app.commander.second_layer {
        app.commander.second_layer = false;
        if let KeyCode::F(n) = key.code {
            on_shift_fkey(app, n);
            return;
        }
        if let Some(n) = first_layer_key(key.code) {
            dispatch_key(app, KeyEvent::new(KeyCode::F(n), KeyModifiers::NONE));
            return;
        }
    }
    // U-1: block row commands in views that don't display `entries`.
    if is_entries_row_command(key.code) && !view_exposes_entries(app.commander.active_panel().view)
    {
        app.commander.status =
            "Row commands need «files» or «directories» view (press v)".to_string();
        return;
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
        // `x` is the way in that no terminal can take away: F11 is fullscreen in GNOME Terminal,
        // Konsole, Windows Terminal and xfce4-terminal, and it used to be the only one.
        KeyCode::F(11) | KeyCode::Char('x') | KeyCode::Char('X') => actions::prepare_execution(app),
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
        // Entry rows — under the top border, within the inner height. A file-group entry is two
        // rows tall (its reclaim claim has a line of its own), so the click maps by that height
        // rather than one row per entry.
        let rows_per_entry = rows_per_entry(panel.view, rect.width).max(1) as usize;
        let inner_rows = rect.height.saturating_sub(2);
        let entry = pos
            .y
            .checked_sub(rect.y + 1)
            .filter(|row| *row < inner_rows)
            .map(|row| panel.list.offset() + row as usize / rows_per_entry)
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
                if let Some(sig) = other_dedup.and_then(|d| d.trusted_dir_signature(&entry.path)) {
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
                    .and_then(|d| d.trusted_dir_signature(&entry.path))
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
    Execute,
    ClearMarks,
    ReloadDedup,
    CycleView,
    Help,
    /// A second-layer command (Shift+F): dispatched through `on_shift_fkey` —
    /// accessible without Shift if the terminal does not pass modified F-keys.
    ShiftLayer(u8),
}

/// Items of the F9 dropdown menu.
const MENU: [(&str, MenuAction); 14] = [
    (
        "Scan the active panel's directory",
        MenuAction::ScanActivePanel,
    ),
    ("Configure and start a scan…", MenuAction::WizardScanConfig),
    ("Sessions and scan results…", MenuAction::WizardResume),
    ("Execute marked actions (F11 or x)", MenuAction::Execute),
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
    let tab = match app.commander.overlay {
        Overlay::Confirm { tab, .. } => tab,
        _ => return,
    };
    match key.code {
        // Y only. Enter is the key people press to dismiss a dialog they have not read, and
        // this dialog starts a destructive batch — it must cost a deliberate keystroke.
        KeyCode::Char('y') | KeyCode::Char('Y') => actions::confirm_execution(app),
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => actions::cancel_execution(app),
        // Switching the Summary/Commands tab and saving the script.
        KeyCode::Tab => toggle_confirm_tab(app),
        KeyCode::Char('s') | KeyCode::Char('S') => save_confirm_script(app),
        // Movement belongs to the Commands tab; Summary has nothing to scroll.
        _ if matches!(tab, ConfirmTab::Commands) => scroll_confirm_commands(app, key.code),
        _ => {}
    }
}

/// Scrolling the Commands tab of the F11 confirmation.
fn scroll_confirm_commands(app: &mut App, code: KeyCode) {
    let scroll = &mut app.commander.confirm_scroll;
    let page = crate::tui::screens::browser::page_step(scroll.rows, 1);
    match code {
        KeyCode::Up => scroll.scroll_by(-1),
        KeyCode::Down => scroll.scroll_by(1),
        KeyCode::PageUp => scroll.scroll_by(-page),
        KeyCode::PageDown => scroll.scroll_by(page),
        KeyCode::Home => scroll.offset = 0,
        KeyCode::End => scroll.offset = scroll.max_offset(),
        _ => {}
    }
}

/// `Tab` in the F11 confirmation: switches the Summary ↔ Commands tab.
fn toggle_confirm_tab(app: &mut App) {
    if let Overlay::Confirm { tab } = app.commander.overlay {
        let tab = match tab {
            ConfirmTab::Summary => ConfirmTab::Commands,
            ConfirmTab::Commands => ConfirmTab::Summary,
        };
        app.commander.overlay = Overlay::Confirm { tab };
    }
}

/// `S` in the F11 confirmation: saves the plan's shell script to
/// `<state_dir>/plans/<ts>.sh`. state_dir — the parent of the checkpoint DB file.
fn save_confirm_script(app: &mut App) {
    // Only a seat that may still be executed may be saved: writing the script of an
    // invalidated plan would put a file on disk that describes a batch nobody may run.
    let Some(script) = app.commander.confirm_script.ready().map(str::to_owned) else {
        if let Some(reason) = app.commander.confirm_script.invalidated() {
            app.commander.status =
                format!("The script was not saved — the confirmation is no longer valid: {reason}");
        }
        return;
    };
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let dir = app
        .db_path
        .parent()
        .map(|parent| parent.join("plans"))
        .unwrap_or_else(|| PathBuf::from("plans"));
    let path = dir.join(format!("{ts}.sh"));
    let result = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&path, &script));
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
        MenuAction::Execute => actions::prepare_execution(app),
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
        // The membership half comes from the authority, in one bounded answer: presence, the
        // digest it recorded and the peers of the group it belongs to — capped, with the real
        // total beside them. Nothing here opens a connection of its own.
        app.request_file_info_overlay(entry.path.clone(), lines);
        return;
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
    // U-1: double-click is mouse Enter; skip it where `entries` isn't shown.
    if !view_exposes_entries(app.commander.panels[index].view) {
        return;
    }
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

/// Terminal rows one entry of a panel occupies at this panel width. Only the file-group list is
/// taller than a row: its reclaim claim gets lines of its own so the post-purge qualifier and its
/// number cannot be cut off — and at 40 columns, which is what an 80-column terminal gives two
/// panels, that takes two lines rather than one.
fn rows_per_entry(view: PanelView, width: u16) -> u16 {
    match view {
        PanelView::GroupList => crate::tui::screens::browser::group_rows(width),
        _ => 1,
    }
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
            Some(WatchResult::FileGroup(g, _)) => g.files.len(),
            Some(WatchResult::DirGroup(g)) => g.group.paths.len(),
            Some(WatchResult::InnerDupes { paths, .. })
            | Some(WatchResult::InnerCandidates { paths, .. }) => paths.len(),
            None => 0,
        },
        PanelView::DirGroupList => app.commander.dir_group_summaries.len(),
        PanelView::DirGroupFiles => app
            .commander
            .watch_dir_cache
            .get(index)
            .and_then(|slot| slot.as_ref())
            .map(|group| group.group.paths.len())
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

/// Dispatches one request per «watching» panel whose source changed.
///
/// The summaries and directory groups themselves are not loaded here at all: the browsing
/// actor's `Open` installed them whole, so entering a group mode costs no query. What remains
/// is resolving what each watching panel points AT, and that is asked once per source change —
/// never per frame. The answers arrive as `BrowseEvent`s and fill `watch_cache`.
fn resolve_watch_groups(app: &mut App) {
    let total = app.commander.panels.len();
    if app.commander.watch_cache.len() != total {
        app.commander.watch_cache = vec![state::WatchEntry::default(); total];
    }
    if app.commander.watch_dir_cache.len() != total {
        app.commander.watch_dir_cache = vec![None; total];
    }
    for i in 0..total {
        let key_res = compute_watch_key(app, i);
        let new_key: Option<state::WatchKey> = key_res.as_ref().ok().cloned();
        let stale = app
            .commander
            .watch_cache
            .get(i)
            .map(|entry| entry.key != new_key)
            .unwrap_or(true);
        if !stale {
            continue;
        }
        // The key is recorded BEFORE the request goes out, so the same source is asked once and
        // the reply has a place to land.
        if let Some(entry) = app.commander.watch_cache.get_mut(i) {
            entry.key = new_key.clone();
            entry.result = None;
            entry.empty = state::WatchEmpty::default();
            entry.unavailable = None;
        }
        match &key_res {
            Ok(key) => request_watch_group(app, i, key),
            Err(reason) => {
                if let Some(entry) = app.commander.watch_cache.get_mut(i) {
                    entry.empty = *reason;
                }
            }
        }
    }
    // A DirGroupFiles panel opens the group its neighbour selected — one request per change.
    if app.commander.watch_dir_keys.len() != total {
        app.commander.watch_dir_keys = vec![None; total];
    }
    for i in 0..total {
        resolve_dir_group(app, i);
    }
}

/// Asks the actor what panel `i`'s source resolves to.
fn request_watch_group(app: &mut App, panel: usize, key: &state::WatchKey) {
    if app.commander.dedup_scan_id.is_none() {
        if let Some(entry) = app.commander.watch_cache.get_mut(panel) {
            entry.empty = state::WatchEmpty::NotInScan;
        }
        return;
    }
    match key {
        // The identity is already known — it came with the summaries — so the group is opened
        // directly, with no digest anywhere on the path.
        state::WatchKey::Group(index) => {
            let Some(id) = app.commander.group_summaries.get(*index).map(|(id, _)| *id) else {
                if let Some(entry) = app.commander.watch_cache.get_mut(panel) {
                    entry.empty = state::WatchEmpty::NoDuplicates;
                }
                return;
            };
            app.request_watch_group_open(panel, id);
        }
        // A file cursor: the typed file answer separates «outside the scan» from «in the scan,
        // in no group», and carries the identity when there IS one.
        state::WatchKey::DupOf(path) => app.request_watch_file_info(panel, path.clone()),
        state::WatchKey::DirOf(path) => app.request_watch_dir_group(panel, path.clone()),
    }
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

/// Resolves the directory group for DirGroupFiles: the group selected in the adjacent
/// DirGroupList panel on the left, opened by SIGNATURE through the actor and revalidated
/// against the current ledger — so a member the ledger has suppressed since publication is
/// gone rather than remembered. Asked once per selection change, never per frame.
fn resolve_dir_group(app: &mut App, i: usize) {
    let wanted = wanted_dir_signature(app, i);
    let known = app.commander.watch_dir_keys.get(i).cloned().flatten();
    if known == wanted {
        return;
    }
    if let Some(slot) = app.commander.watch_dir_keys.get_mut(i) {
        *slot = wanted.clone();
    }
    if let Some(slot) = app.commander.watch_dir_cache.get_mut(i) {
        *slot = None;
    }
    if let Some(signature) = wanted {
        app.request_open_dir_group(i, signature);
    }
}

/// Which directory-group signature panel `i` should be showing, if any.
fn wanted_dir_signature(app: &App, i: usize) -> Option<String> {
    let panel = &app.commander.panels[i];
    if panel.view != PanelView::DirGroupFiles {
        return None;
    }
    let source = app.commander.panels.get(i.checked_sub(1)?)?;
    if source.view != PanelView::DirGroupList {
        return None;
    }
    let idx = source.list.selected()?;
    app.commander
        .dir_group_summaries
        .get(idx)
        .map(|summary| summary.signature.clone())
}

/// Sets the mark `mark` on the file under the active panel's cursor.
fn mark_cursor(app: &mut App, mark: Mark) {
    // Marks are what the operator's deletion plan is built from — an observer must not set them.
    if app.deny_if_read_only("marking files") {
        return;
    }
    if mark == Mark::Reflink && !app.zfs.capabilities.reflink_safe {
        app.commander.status =
            "reflink unavailable — needs ZFS 2.3+ with block cloning enabled".to_string();
        return;
    }
    // One unacknowledged durable write at a time. Refused HERE, before the row is touched and
    // before the cursor moves: a second keystroke that left an optimistic glyph behind would put
    // a mark on screen that no answer is coming for, and the operator would have no way to tell
    // which of the two the database actually holds.
    if let Some(waiting) = single_flight_refusal(app) {
        app.commander.status = waiting;
        return;
    }
    let active = app.commander.active;
    let panel = app.commander.active_panel_mut();
    let entry = match panel.selected() {
        Some(entry) if matches!(entry.kind, EntryKind::File) => entry.clone(),
        _ => {
            app.commander.status = "A mark can only be set on a file".to_string();
            return;
        }
    };
    let previous = panel.marks.insert(entry.path.clone(), mark);
    panel.move_cursor(1);
    if let Err(err) = persist_mark(app, active, &entry, Some(mark), previous) {
        // The database refused, so the panel does not get to claim it. The cursor goes back too:
        // the operator has to see the row their keystroke did not change.
        let panel = app.commander.active_panel_mut();
        match previous {
            Some(previous) => {
                panel.marks.insert(entry.path.clone(), previous);
            }
            None => {
                panel.marks.remove(&entry.path);
            }
        }
        panel.move_cursor(-1);
        app.commander.status = format!("The mark was not saved: {err}");
    }
}

/// Space: removes the mark from the entry under the cursor or sets «selected» (a file or
/// directory — for triage; `..` is not selected).
fn toggle_mark_cursor(app: &mut App) {
    // Space clears an action mark or sets «selected» — the first of those is a persisted write.
    if app.deny_if_read_only("marking files") {
        return;
    }
    let active = app.commander.active;
    let (entry, standing) = {
        let panel = app.commander.active_panel_mut();
        let entry = match panel.selected() {
            Some(entry) if matches!(entry.kind, EntryKind::File | EntryKind::Dir) => entry.clone(),
            _ => return,
        };
        let standing = panel.marks.get(&entry.path).copied();
        (entry, standing)
    };
    // Only CLEARING a durable mark is a database write; setting or dropping a triage selection
    // never leaves the panel. The single flight therefore gates the former and must not touch the
    // latter — an operator sorting rows with Space has no reason to wait for someone else's write.
    if matches!(
        standing,
        Some(Mark::Keeper | Mark::Delete | Mark::Hardlink | Mark::Reflink)
    ) {
        if let Some(waiting) = single_flight_refusal(app) {
            app.commander.status = waiting;
            return;
        }
    }
    let panel = app.commander.active_panel_mut();
    let previous = panel.marks.remove(&entry.path);
    let new_mark = if previous.is_some() {
        None
    } else {
        panel.marks.insert(entry.path.clone(), Mark::Selected);
        Some(Mark::Selected)
    };
    panel.move_cursor(1);
    if let Err(err) = persist_mark(app, active, &entry, new_mark, previous) {
        // Clearing a mark is a durable write like setting one: if it did not land, the panel
        // still holds what the database still holds.
        let panel = app.commander.active_panel_mut();
        match previous {
            Some(previous) => {
                panel.marks.insert(entry.path.clone(), previous);
            }
            None => {
                panel.marks.remove(&entry.path);
            }
        }
        panel.move_cursor(-1);
        app.commander.status = format!("The mark was not cleared: {err}");
    }
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
    spawn_move_worker(events, rx, move |request| {
        move_batch::run_batch(
            &db_path,
            &request.sources,
            &request.dest_dir,
            request.scan_id,
        )
    });
    app.commander.move_worker = Some(tx);
}

/// The worker loop itself: one request at a time, each one contained. `ensure_move_worker` gives
/// it the real batch; the tests give it a job that panics. A panic must neither swallow the
/// request — only `CommanderMoveDone` releases `move_pending` and writes the Undo entry — nor take
/// the worker down, or every later move would vanish silently.
fn spawn_move_worker<F>(
    events: crossbeam_channel::Sender<AppEvent>,
    requests: crossbeam_channel::Receiver<state::MoveRequest>,
    job: F,
) where
    F: Fn(&state::MoveRequest) -> move_batch::MoveBatchOutcome + Send + 'static,
{
    std::thread::spawn(move || {
        while let Ok(request) = requests.recv() {
            let mut outcome = match crate::panics::guard_value("the move worker", || job(&request))
            {
                Ok(outcome) => outcome,
                Err(err) => move_batch::MoveBatchOutcome {
                    failed: request.sources.len(),
                    error: Some(err),
                    ..Default::default()
                },
            };
            outcome.reload = request.reload;
            outcome.label = request.label;
            let _ = events.send(AppEvent::CommanderMoveDone(Box::new(outcome)));
        }
    });
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
    app.commander.status = if let Some(err) = &outcome.error {
        // The batch never returned, so there is no per-item breakdown to show.
        format!("→ {}: move failed — {err}", outcome.label)
    } else if outcome.failed == 0 {
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

/// Asks the browsing actor for panel `target`'s dedup attributes and puts the answer into the
/// cache by its `cwd`. Called on a panel directory load and when a scan is installed. Without a
/// scan — does nothing; a repeated fetch of the same cwd is suppressed by the pending flag. The
/// work happens on the actor's thread, so the UI is not blocked and no second connection exists.
pub(crate) fn fetch_panel_dedup(app: &mut App, target: state::LoadTarget) {
    if app.commander.dedup_scan_id.is_none() {
        return;
    }
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
    // ONE request for the whole panel — the membership of every file, the sizes and the
    // signatures of every subdirectory — answered from one snapshot. It does not grow with the
    // number of rows: the batch travels as a single JSON array, so a panel of 40 costs the same
    // statements as a panel of 1. The signature algorithm is the one cached at `Open`, so it
    // cannot diverge from the persisted `dir_dedup` of this scan.
    app.request_panel_data(target, cwd, files, dirs);
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
mod move_worker_tests {
    use super::*;

    fn request(label: &str) -> state::MoveRequest {
        state::MoveRequest {
            sources: vec![PathBuf::from("/nonexistent/a.bin")],
            dest_dir: PathBuf::from("/nonexistent/dest"),
            scan_id: None,
            reload: Vec::new(),
            label: label.to_string(),
        }
    }

    /// A panicking batch must still come back as `CommanderMoveDone`: that event is the only thing
    /// that releases `move_pending` and tells the operator the move did not happen. And the worker
    /// has to survive it — it is a single long-lived thread, so its death would silently swallow
    /// every later move.
    #[test]
    fn a_panicking_move_reports_and_the_worker_survives() {
        let _lock = crate::panics::test_lock();
        let (events_tx, events_rx) = crossbeam_channel::unbounded();
        let (requests_tx, requests_rx) = crossbeam_channel::unbounded();
        spawn_move_worker(events_tx, requests_rx, |request| {
            if request.label == "first" {
                panic!("boom in the move");
            }
            move_batch::MoveBatchOutcome::default()
        });

        requests_tx.send(request("first")).unwrap();
        let outcome = recv_move_done(&events_rx);
        assert_eq!(outcome.label, "first");
        let err = outcome
            .error
            .expect("a panicking batch must report an error");
        assert!(
            err.contains("boom in the move"),
            "the status must show what happened: {err}"
        );
        assert_eq!(outcome.failed, 1, "nothing of the request was moved");

        requests_tx.send(request("second")).unwrap();
        let outcome = recv_move_done(&events_rx);
        assert_eq!(outcome.label, "second", "the worker must still be alive");
        assert!(outcome.error.is_none());
    }

    fn recv_move_done(
        events: &crossbeam_channel::Receiver<AppEvent>,
    ) -> move_batch::MoveBatchOutcome {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match events.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(AppEvent::CommanderMoveDone(outcome)) => return *outcome,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        panic!("CommanderMoveDone must arrive");
    }
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
/// (metadata only, without reading the contents) — or the error that stopped the directory
/// being read.
///
/// The `Result` is the point. The caller reads an empty answer as "nothing here duplicates it"
/// and files the file under its own name; a directory that could not be read produces that same
/// empty answer while establishing nothing. Swallowing the error therefore turned a transient
/// failure on the destination — descriptors exhausted on a large batch, `EIO`, permissions
/// changed underfoot — into a duplicate silently filed as a fresh file, with `duplicate = false`
/// recorded for it in the `move_event` journal.
///
/// `NotFound` on one entry is deliberately NOT such a failure: an entry can be unlinked between
/// `read_dir` and the stat, and something that is no longer there duplicates nothing — a complete
/// answer rather than a missing one. Making that race fatal would fail a move for a file the batch
/// never had to look at.
///
/// Symlinks never reach that arm. `DirEntry::metadata` does NOT follow them — it is the `lstat`
/// form — so even a link with no target comes back `Ok` and is dropped by `is_file` below, and a
/// link pointing AT an identical file is not a duplicate candidate either. That is the behaviour
/// this function always had; it is written down because swapping to `fs::metadata(entry.path())`
/// would silently turn every broken link in the destination into a `NotFound` this arm swallows.
///
/// The result is sorted by the raw bytes of the file name, like the walk and the merge. The
/// caller stops at the first match, so which candidate it reads — and, when one of them cannot
/// be read, which one it names in the log — would otherwise be `readdir`'s choice.
///
/// One failing entry costs every move into this directory, not only the files of its size: the
/// size filter is applied AFTER the stat, so an entry that will not stat stops the listing before
/// anything has been filtered. That is the intended trade — a directory only partly read cannot
/// answer "nothing here duplicates it" for anyone — but the blast radius is the whole destination,
/// and a batch will report one failure per file moved into it.
///
/// Both stat arms are reached through the injection seam below: the tests run as root in a
/// container, where a permission change refuses nothing, and no fixture can unlink an entry
/// between `read_dir` and the stat on cue. `WalkFault::Metadata` stands in for `NotFound`,
/// the arm that CONTINUES; `WalkFault::MetadataRefused` for `PermissionDenied`, the arm that
/// returns. Each has a test of its own in `move_batch`, and the returning arm one more here, on
/// the listing itself. The `?` on `read_dir` is covered by
/// `a_destination_that_will_not_open_is_an_error`, which uses real refusals and no seam.
fn same_size_files(dir: &Path, size: u64) -> std::io::Result<Vec<PathBuf>> {
    use std::os::unix::fs::MetadataExt;
    // Test-only: the `read_dir` failure a directory has no way to produce on demand. Absent from
    // every non-test build.
    #[cfg(test)]
    if crate::testfixtures::take_walk_fault(dir) {
        return Err(std::io::Error::other("injected read_dir fault"));
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // Test-only: the entry unlinked between `read_dir` and the stat, a race no fixture can
        // stage, or a stat refused outright, which a fixture running as root cannot produce on
        // cue by changing permissions. Absent from every non-test build.
        #[cfg(test)]
        let stat = if crate::testfixtures::take_metadata_fault(&entry.path()) {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        } else if crate::testfixtures::take_metadata_refusal(&entry.path()) {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        } else {
            entry.metadata()
        };
        #[cfg(not(test))]
        let stat = entry.metadata();
        let meta = match stat {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        if meta.is_file() && meta.size() == size {
            out.push(entry.path());
        }
    }
    out.sort_by(|a, b| {
        use std::os::unix::ffi::OsStrExt;
        let key = |p: &Path| p.file_name().map_or(&[][..], |n| n.as_bytes()).to_vec();
        key(a).cmp(&key(b))
    });
    Ok(out)
}

/// The first free name `{stem}.dup{N}{.ext}` in directory `dir` for the duplicate `src`.
///
/// Assembled from the name's raw bytes, never from a `String`. A Unix filename is arbitrary
/// non-NUL bytes, and going through `to_string_lossy` would corrupt two ways at once: it renames
/// the survivor, so `b"\x80.bin"` lands as `"\u{FFFD}.dup1.bin"` — bytes the operator never chose,
/// with no way back to the original from the name alone — and it collapses distinct names onto one
/// stem, so `b"\x80.bin"` and `b"\xff.bin"` moved into the same directory would queue up as
/// `.dup1` and `.dup2` of a stem neither of them ever had.
fn dup_dest(dir: &Path, src: &Path) -> PathBuf {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let stem = src.file_stem().map(OsStr::as_bytes).unwrap_or_default();
    let ext = src.extension().map(OsStr::as_bytes);
    let mut n = 1u32;
    loop {
        let marker = format!(".dup{n}");
        let mut name =
            Vec::with_capacity(stem.len() + marker.len() + ext.map_or(0, |ext| 1 + ext.len()));
        name.extend_from_slice(stem);
        name.extend_from_slice(marker.as_bytes());
        if let Some(ext) = ext {
            name.push(b'.');
            name.extend_from_slice(ext);
        }
        let candidate = dir.join(OsString::from_vec(name));
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// Persists the file's mark to the DB. `Err` — the panel must not keep it.
///
/// Fail-closed, in both directions: a mark and an unmark are the same write, and a panel that
/// shows DELETE over a database that never accepted it is a window the plan cannot be built from.
/// A pathname outside the scan's manifest is refused rather than ignored — it used to keep a
/// pretend mark that nothing durable stood behind.
fn persist_mark(
    app: &mut App,
    panel: usize,
    entry: &PanelEntry,
    mark: Option<Mark>,
    previous: Option<Mark>,
) -> crate::error::Result<()> {
    // `Selected` and «no mark» both mean the database holds nothing for this pathname. Without a
    // loaded scan there is nothing durable to clear, so the panel's own selection stays a panel
    // matter; a mark that WOULD have to be durable is refused instead.
    let durable = matches!(
        mark,
        Some(Mark::Keeper | Mark::Delete | Mark::Hardlink | Mark::Reflink)
    );
    if app.commander.dedup_scan_id.is_none() {
        if durable {
            return Err(AppError::msg(
                "no scan is loaded — load one (F2/F12) before marking files",
            ));
        }
        return Ok(());
    }
    // Clearing a selection that was never durable writes nothing: the database holds no row for
    // it, and asking it to delete one would be a write nobody needs.
    if !durable
        && !matches!(
            previous,
            Some(Mark::Keeper | Mark::Delete | Mark::Hardlink | Mark::Reflink)
        )
    {
        return Ok(());
    }
    // The store persists path/is_keeper/action; the rest of the identity is not known here and
    // is deliberately left at its default rather than half-filled. A pathname outside the scan's
    // manifest is refused by the store itself — typed, before anything is written.
    let file = FileEntry {
        path: entry.path.clone(),
        size: entry.size,
        mtime: entry.mtime,
        device: entry.device,
        inode: entry.inode,
        is_keeper: mark == Some(Mark::Keeper),
        action: mark.and_then(|mark| mark.action()),
        ..Default::default()
    };
    app.send_commander_mark(panel, file, previous, mark)
}

/// Why a durable mark keystroke must wait, if it must.
///
/// The Commander allows exactly one unacknowledged durable write. While one is in flight the
/// operator gets a sentence that names both states they care about — the one they are in, and the
/// one they are waiting for — so the wait is a fence they can see rather than a duration they
/// have to guess.
fn single_flight_refusal(app: &App) -> Option<String> {
    if !app.pending_marks.is_empty() {
        return Some("Mark still saving — wait for Mark saved before marking again".to_string());
    }
    None
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
        Line::from("  When the terminal eats an F-key".bold()),
        Line::from("    x           Execute marked actions (same as F11)"),
        Line::from("    ` then 1-9  F1-F9;  ` 0 → F10,  ` - → F11,  ` = → F12"),
        Line::from("    F9 menu     Execute is available there too"),
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

/// The F9 menu as the manual draws it, held to the menu the code builds.
///
/// The keymap tests above check the tables against each other; these check them against the
/// chapter a user reads. Adding an entry shifts every number below it, and the manual numbers them
/// twice — once in the drawn menu, once in the prose underneath. Both are held here.
#[cfg(test)]
mod manual_tests {
    use super::{MenuAction, MENU};
    use crate::testfixtures::manual;

    /// The drawn menu block of `05-commando.md`, as (number, label) pairs.
    fn drawn_menu(doc: &str) -> Vec<(usize, String)> {
        doc.lines()
            .skip_while(|line| !line.starts_with("┌─ Menu — F9"))
            .take_while(|line| !line.starts_with('└'))
            .filter_map(|line| {
                let body = line.strip_prefix('│')?.trim_end_matches(['│', ' ']).trim();
                let (number, label) = body.split_once(". ")?;
                Some((number.trim().parse().ok()?, label.trim().to_string()))
            })
            .collect()
    }

    #[test]
    fn manual_draws_the_menu_the_code_builds() {
        let drawn = drawn_menu(&manual("05-commando.md"));
        assert_eq!(
            drawn.len(),
            MENU.len(),
            "the manual draws {} menu entries, the code builds {}",
            drawn.len(),
            MENU.len()
        );
        for (index, (number, label)) in drawn.iter().enumerate() {
            assert_eq!(*number, index + 1, "the drawn menu skips a number");
            assert_eq!(
                label,
                MENU[index].0,
                "menu entry {} — the manual says {label:?}, the code says {:?}",
                index + 1,
                MENU[index].0
            );
        }
    }

    /// The prose under the drawn menu names entries by number. The one that runs the batch is the
    /// only entry whose misnumbering costs data, so it is the one pinned here — by the position the
    /// code gives it, not by a number written into this test.
    #[test]
    fn manual_names_the_executing_entry_by_its_own_number() {
        let position = MENU
            .iter()
            .position(|(_, action)| matches!(action, MenuAction::Execute))
            .expect("the F9 menu has an Execute entry")
            + 1;
        let claim = format!("item {position} executes");
        assert!(
            manual("05-commando.md").contains(&claim),
            "Execute is menu entry {position}; the manual must say {claim:?} where it lists the \
             entries by number"
        );
    }
}

/// U-4b: the Commands tab printed the first screenful and a «… N more lines» note, so the
/// audit view of a plan could not be audited past its first screen.
#[cfg(test)]
mod u4b_commands_scroll_tests {
    use super::state::ConfirmScroll;
    use super::*;

    /// An app with the F11 confirmation open on `tab` over a script of `lines` lines, as the
    /// first frame would leave it: `rows` measured, window at the top.
    fn confirming(tab: ConfirmTab, lines: usize, rows: u16) -> App {
        let (mut app, _rx) = crate::app::test_app();
        app.commander.confirm_script = state::ConfirmScript::Ready(
            (1..=lines)
                .map(|n| format!("echo line{n}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        app.commander.confirm_scroll = ConfirmScroll {
            offset: 0,
            total: lines,
            rows,
        };
        app.commander.overlay = Overlay::Confirm { tab };
        app
    }

    fn press(app: &mut App, code: KeyCode) {
        on_key(app, KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn the_commands_tab_scrolls_line_page_and_end() {
        let mut app = confirming(ConfirmTab::Commands, 100, 10);

        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.commander.confirm_scroll.offset, 2);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.commander.confirm_scroll.offset, 1);

        press(&mut app, KeyCode::PageDown);
        assert_eq!(
            app.commander.confirm_scroll.offset, 10,
            "a page is the window minus one line of overlap"
        );
        press(&mut app, KeyCode::PageUp);
        assert_eq!(app.commander.confirm_scroll.offset, 1);

        press(&mut app, KeyCode::End);
        assert_eq!(
            app.commander.confirm_scroll.offset, 90,
            "End parks the last line at the bottom of the window, not past it"
        );
        press(&mut app, KeyCode::Home);
        assert_eq!(app.commander.confirm_scroll.offset, 0);
    }

    #[test]
    fn the_window_never_leaves_the_script() {
        let mut app = confirming(ConfirmTab::Commands, 100, 10);
        for _ in 0..40 {
            press(&mut app, KeyCode::PageDown);
        }
        assert_eq!(app.commander.confirm_scroll.offset, 90);
        for _ in 0..40 {
            press(&mut app, KeyCode::PageUp);
        }
        assert_eq!(app.commander.confirm_scroll.offset, 0);
    }

    /// A script that fits has nothing to scroll — the window must not drift off its only page.
    #[test]
    fn a_script_shorter_than_the_window_does_not_move() {
        for lines in [0usize, 1, 5] {
            let mut app = confirming(ConfirmTab::Commands, lines, 10);
            for code in [KeyCode::Down, KeyCode::PageDown, KeyCode::End] {
                press(&mut app, code);
                assert_eq!(
                    app.commander.confirm_scroll.offset, 0,
                    "{lines} lines, {code:?}"
                );
            }
        }
    }

    /// Summary has nothing to scroll, and movement must not leak into it.
    #[test]
    fn the_summary_tab_ignores_movement() {
        let mut app = confirming(ConfirmTab::Summary, 100, 10);
        for code in [
            KeyCode::Down,
            KeyCode::PageDown,
            KeyCode::End,
            KeyCode::Up,
            KeyCode::Home,
        ] {
            press(&mut app, code);
            assert_eq!(app.commander.confirm_scroll.offset, 0, "{code:?}");
        }
    }

    /// The modal owns the keyboard: movement must not reach the panels underneath, and the
    /// decision keys must keep working from the Commands tab.
    #[test]
    fn the_modal_intercepts_movement_and_still_answers() {
        let mut app = confirming(ConfirmTab::Commands, 100, 10);
        let cursor = app.commander.panels[0].list.selected();

        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::End);

        assert_eq!(
            app.commander.panels[0].list.selected(),
            cursor,
            "the panel cursor must not move while a confirmation is open"
        );
        assert!(matches!(
            app.commander.overlay,
            Overlay::Confirm {
                tab: ConfirmTab::Commands,
                ..
            }
        ));

        press(&mut app, KeyCode::Tab);
        assert!(
            matches!(
                app.commander.overlay,
                Overlay::Confirm {
                    tab: ConfirmTab::Summary,
                    ..
                }
            ),
            "Tab still switches tabs"
        );

        press(&mut app, KeyCode::Esc);
        assert!(
            matches!(app.commander.overlay, Overlay::None),
            "Esc still cancels"
        );
    }

    /// `S` writes the plan, not the part of it that happens to be on screen.
    #[test]
    fn saving_writes_the_whole_script_after_scrolling() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("dedcom_u4b_save_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();

        let mut app = confirming(ConfirmTab::Commands, 100, 10);
        app.db_path = dir.join("dedcom.db");
        let whole = app
            .commander
            .confirm_script
            .ready()
            .expect("the seat holds an executable script")
            .to_string();

        press(&mut app, KeyCode::End);
        press(&mut app, KeyCode::Char('s'));

        let saved: Vec<_> = std::fs::read_dir(dir.join("plans"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert_eq!(
            saved.len(),
            1,
            "one script written: {}",
            app.commander.status
        );
        let written = std::fs::read_to_string(saved[0].path()).unwrap();
        assert_eq!(written, whole, "the .sh must not be cut down to the window");
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// R2D-C5-2: a mark the database did not take must not stay in a panel. The plan is built from
/// the database, so a panel that disagrees with it is a screen describing a plan that will not run.
#[cfg(test)]
mod mark_is_fail_closed_tests {
    use super::*;
    use crate::testfixtures::PlanScenario;
    use crate::tui::event::AppEvent;
    use crossbeam_channel::Receiver;

    /// A commander whose active panel holds `path` under the cursor.
    fn panel_over(app: &mut App, path: &Path) {
        let panel = app.commander.active_panel_mut();
        panel.entries = vec![PanelEntry {
            path: path.to_path_buf(),
            name: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            kind: EntryKind::File,
            size: 0,
            mtime: 0,
            device: 0,
            inode: 0,
        }];
        panel.list.select(Some(0));
    }

    /// The scenario, its scan, and one of its files.
    fn scenario_with_scan(tag: &str) -> (PlanScenario, i64, PathBuf) {
        let scenario = PlanScenario::new(tag);
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper, twin.clone()]);
        drop(store);
        (scenario, scan_id, twin)
    }

    /// A commander with the scenario's scan opened through the actor — the only way it has a
    /// browsing store to write a mark through.
    fn commander_on(scenario: &PlanScenario, scan_id: i64) -> (App, Receiver<AppEvent>) {
        let (mut app, rx) = crate::app::test_app_with_db(scenario.db_path.clone());
        crate::app::open_and_settle(&mut app, &rx, scan_id, crate::app::OpenIntent::Commander);
        assert_eq!(
            app.commander.dedup_scan_id,
            Some(scan_id),
            "the fixture's scan must open: {}",
            app.commander.status
        );
        crate::app::drain(&mut app, &rx);
        (app, rx)
    }

    /// Presses the key and carries the actor's acknowledgement back, so what the panel shows is
    /// what the database answered — not the optimistic row the keystroke drew.
    fn settle_mark(app: &mut App, rx: &Receiver<AppEvent>) {
        crate::app::pump_until(app, rx, "the mark acknowledgement", |app| {
            app.pending_marks.is_empty()
        });
    }

    /// Submitted is not saved. The keystroke draws its optimistic row and says so in those exact
    /// words, with exactly one write in flight and no claim that anything landed.
    #[test]
    fn an_enqueued_mark_says_saving_and_never_saved() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_saving");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);

        mark_cursor(&mut app, Mark::Keeper);

        assert_eq!(
            app.pending_marks.len(),
            1,
            "exactly one durable write is in flight"
        );
        assert!(
            app.commander.status.starts_with("Saving mark"),
            "the operator is told the write was submitted: {}",
            app.commander.status
        );
        assert!(
            !app.commander.status.starts_with("Mark saved"),
            "nothing may claim the database accepted it yet: {}",
            app.commander.status
        );
        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&twin),
            Some(&Mark::Keeper),
            "the optimistic row is drawn — it is the claim of durability that is withheld"
        );
        settle_mark(&mut app, &rx);
        let _ = &rx;
    }

    /// The one positive fence: after the real acknowledgement, and only then, the status names the
    /// pathname and the durable meaning the DATABASE returned.
    #[test]
    fn a_settled_mark_reports_the_meaning_the_database_returned() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_saved");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);

        mark_cursor(&mut app, Mark::Keeper);
        settle_mark(&mut app, &rx);

        assert!(
            app.pending_marks.is_empty(),
            "the flight is over before anything is called saved"
        );
        assert!(
            app.commander.status.starts_with("Mark saved"),
            "the positive acknowledgement is what the operator waits for: {}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains("keeper"),
            "and it states the durable meaning the after-image carried: {}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains(&twin.display().to_string()),
            "naming the pathname it settled: {}",
            app.commander.status
        );
        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&twin),
            Some(&Mark::Keeper),
            "and the row now agrees with the database"
        );
    }

    /// A second durable keystroke while one is unacknowledged changes nothing on screen: no
    /// request, no optimistic row, no cursor movement — only a sentence naming the fence.
    #[test]
    fn a_second_mark_is_refused_before_it_touches_the_panel() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_single_flight");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);

        mark_cursor(&mut app, Mark::Keeper);
        let cursor_before = app.commander.active_panel().list.selected();
        let marks_before = app.commander.panels[app.commander.active].marks.clone();
        assert_eq!(app.pending_marks.len(), 1, "one write is in flight");

        mark_cursor(&mut app, Mark::Delete);

        assert_eq!(
            app.pending_marks.len(),
            1,
            "the second keystroke sent nothing"
        );
        assert!(
            app.commander.status.starts_with("Mark still saving"),
            "and it names the state the operator is in: {}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains("Mark saved"),
            "and the state they are waiting for: {}",
            app.commander.status
        );
        assert_eq!(
            app.commander.active_panel().list.selected(),
            cursor_before,
            "the cursor did not move"
        );
        assert_eq!(
            app.commander.panels[app.commander.active].marks, marks_before,
            "and no optimistic row was left behind"
        );
        settle_mark(&mut app, &rx);
    }

    /// Clearing is a durable write too: it reports `cleared`, and only after settlement.
    #[test]
    fn clearing_a_mark_reports_cleared_after_settlement() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_cleared");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);

        mark_cursor(&mut app, Mark::Delete);
        settle_mark(&mut app, &rx);
        assert!(app.commander.status.starts_with("Mark saved"));

        app.commander.active_panel_mut().list.select(Some(0));
        panel_over(&mut app, &twin);
        toggle_mark_cursor(&mut app);
        assert!(
            app.commander.status.starts_with("Saving mark"),
            "the clear is submitted, not yet saved: {}",
            app.commander.status
        );
        settle_mark(&mut app, &rx);

        assert!(
            app.commander.status.starts_with("Mark saved")
                && app.commander.status.contains("cleared"),
            "and settles as `cleared`: {}",
            app.commander.status
        );
    }

    /// The `Unreadable` acknowledgement in full — the refusal an operator actually meets, since
    /// the settled writer refuses before it writes and so carries no after-image at all.
    ///
    /// It may restore the row, it must say why, and it may never borrow the success prefix.
    #[test]
    fn a_refused_mark_restores_the_row_and_never_renders_the_success_prefix() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_refused_prefix");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);
        mark_cursor(&mut app, Mark::Keeper);
        settle_mark(&mut app, &rx);
        assert!(
            app.commander.status.starts_with("Mark saved"),
            "the durable keeper is what the row must fall back to: {}",
            app.commander.status
        );

        // The manifest row leaves, so the next write is refused with nothing readable behind it.
        drop_from_manifest(&scenario, &twin);
        app.commander.active_panel_mut().list.select(Some(0));
        mark_cursor(&mut app, Mark::Delete);
        assert!(
            app.commander.status.starts_with("Saving mark"),
            "the keystroke was submitted like any other: {}",
            app.commander.status
        );
        settle_mark(&mut app, &rx);

        assert!(
            !app.commander.status.starts_with("Mark saved"),
            "a refusal that reads as success is the whole failure mode: {}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains("not part of the loaded scan"),
            "and it names what was refused: {}",
            app.commander.status
        );
        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&twin),
            Some(&Mark::Keeper),
            "the row is back to the last thing the database confirmed, not the refused delete"
        );
    }

    /// The database file the view was opened over is replaced while a mark is in flight. The
    /// acknowledgement is a typed refusal: browsing is uninstalled, the optimistic row goes back,
    /// and nothing anywhere reads as saved.
    #[test]
    fn a_replaced_database_refuses_the_mark_and_never_says_saved() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_path_changed");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);

        // Class B: the configured path now carries something that is not the checkpoint.
        std::fs::remove_file(&scenario.db_path).unwrap();
        std::fs::create_dir(&scenario.db_path).unwrap();

        mark_cursor(&mut app, Mark::Keeper);
        assert_eq!(
            app.pending_marks.len(),
            1,
            "the window cannot know yet, so the keystroke is submitted"
        );
        settle_mark(&mut app, &rx);

        assert!(
            !app.commander.status.starts_with("Mark saved"),
            "a replaced checkpoint cannot produce a saved mark: {}",
            app.commander.status
        );
        assert!(
            app.commander.dedup_scan_id.is_none(),
            "and the scan it was marked over is uninstalled: {}",
            app.commander.status
        );
        assert!(
            !app.commander.panels[app.commander.active]
                .marks
                .contains_key(&twin),
            "the optimistic row went back to nothing"
        );
    }

    /// Every line of a rendered frame, so a status assertion reads what the terminal shows rather
    /// than the string the code meant to show.
    fn rendered_lines(app: &mut App, term_width: u16) -> Vec<String> {
        use ratatui::{backend::TestBackend, Terminal};
        let mut terminal = Terminal::new(TestBackend::new(term_width, 20)).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let area = *buffer.area();
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect()
    }

    /// The verdict must survive the narrowest supported terminal. Only the detail may be clipped —
    /// a status whose prefix is cut off is a fence the operator cannot read.
    #[test]
    fn the_three_lifecycle_states_are_readable_at_36_columns() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_36col");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);

        mark_cursor(&mut app, Mark::Keeper);
        assert!(
            rendered_lines(&mut app, 36)
                .iter()
                .any(|line| line.contains("Saving mark")),
            "«Saving mark» must be readable at 36 columns"
        );

        mark_cursor(&mut app, Mark::Delete);
        assert!(
            rendered_lines(&mut app, 36)
                .iter()
                .any(|line| line.contains("Mark still saving")),
            "«Mark still saving» must be readable at 36 columns"
        );

        settle_mark(&mut app, &rx);
        assert!(
            rendered_lines(&mut app, 36)
                .iter()
                .any(|line| line.contains("Mark saved")),
            "«Mark saved» must be readable at 36 columns"
        );
    }

    /// The fence guards the database, not the keyboard. A triage selection writes nothing, so it
    /// keeps working while somebody else's durable write is still in flight.
    #[test]
    fn a_triage_selection_is_not_blocked_by_a_pending_write() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_selected_free");
        let (mut app, rx) = commander_on(&scenario, scan_id);

        // A durable write on one pathname, deliberately left unacknowledged.
        panel_over(&mut app, &twin);
        mark_cursor(&mut app, Mark::Keeper);
        assert_eq!(app.pending_marks.len(), 1, "one durable write is in flight");

        // Space on a DIFFERENT row: panel-local, nothing durable, nothing to wait for.
        let other = scenario.outside.join("selectable.bin");
        std::fs::write(&other, b"panel-local only").unwrap();
        panel_over(&mut app, &other);
        toggle_mark_cursor(&mut app);

        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&other),
            Some(&Mark::Selected),
            "the selection landed even though a durable write is pending: {}",
            app.commander.status
        );
        assert!(
            !app.commander.status.starts_with("Mark still saving"),
            "a panel-local selection must not be fenced: {}",
            app.commander.status
        );
        // Cursor movement is deliberately not asserted here: `move_cursor(1)` clamps at the end of
        // the list, so on a short listing «advanced» and «clamped» are the same index and the
        // assertion would prove nothing about the fence.
        assert_eq!(
            app.pending_marks.len(),
            1,
            "while sending nothing of its own"
        );

        // Clearing that same selection is still panel-local, so it is still free.
        panel_over(&mut app, &other);
        toggle_mark_cursor(&mut app);
        assert!(
            !app.commander.panels[app.commander.active]
                .marks
                .contains_key(&other),
            "and dropping it is equally free: {}",
            app.commander.status
        );

        settle_mark(&mut app, &rx);
    }

    /// Clearing a DURABLE mark is a write, so it does queue behind the flight — refused before the
    /// row changes and before the cursor moves.
    #[test]
    fn clearing_a_durable_mark_is_fenced_by_the_pending_write() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_clear_fenced");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);
        mark_cursor(&mut app, Mark::Delete);
        settle_mark(&mut app, &rx);

        // A second durable write elsewhere, left in flight.
        let second = scenario.outside.join("second.bin");
        std::fs::write(&second, b"second").unwrap();
        panel_over(&mut app, &twin);
        mark_cursor(&mut app, Mark::Keeper);
        assert_eq!(app.pending_marks.len(), 1);

        panel_over(&mut app, &twin);
        let cursor_before = app.commander.active_panel().list.selected();
        let marks_before = app.commander.panels[app.commander.active].marks.clone();
        toggle_mark_cursor(&mut app);

        assert!(
            app.commander.status.starts_with("Mark still saving"),
            "clearing a durable mark is a write and waits its turn: {}",
            app.commander.status
        );
        assert_eq!(
            app.commander.active_panel().list.selected(),
            cursor_before,
            "the cursor did not move"
        );
        assert_eq!(
            app.commander.panels[app.commander.active].marks, marks_before,
            "and the row was not touched"
        );
        settle_mark(&mut app, &rx);
    }

    /// The plan gate is unchanged: nothing may be built while a write is unacknowledged.
    #[test]
    fn a_plan_cannot_be_built_while_a_mark_is_in_flight() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_plan_gate");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);

        mark_cursor(&mut app, Mark::Keeper);
        assert!(
            app.plan_gate_refusal().is_some(),
            "an unacknowledged mark still refuses a plan"
        );
        settle_mark(&mut app, &rx);
    }

    /// A pathname the loaded scan never saw cannot acquire a mark that looks durable.
    #[test]
    fn a_pathname_outside_the_scan_cannot_be_marked() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, _twin) = scenario_with_scan("commander_outside");
        let stranger = scenario.outside.join("stranger.bin");
        std::fs::write(&stranger, b"not in this scan").unwrap();

        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &stranger);

        mark_cursor(&mut app, Mark::Delete);
        settle_mark(&mut app, &rx);

        assert!(
            !app.commander.panels[app.commander.active]
                .marks
                .contains_key(&stranger),
            "a pretend durable mark is exactly what this refuses"
        );
        assert!(
            app.commander.status.contains("not part of the loaded scan")
                && app
                    .commander
                    .status
                    .contains(&stranger.display().to_string()),
            "and it says why, naming the pathname: {}",
            app.commander.status
        );
        assert!(
            !app.commander.status.contains("browsing is not available"),
            "the refusal came from the store, not from an absent browsing surface: {}",
            app.commander.status
        );
    }

    /// A refused write leaves the panel showing what the database still holds — the exact
    /// before-image, restored from the ticket the actor handed back.
    #[test]
    fn a_refused_mark_is_not_kept_in_the_panel() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_mark_refused");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);
        // A durable KEEPER first, so the refusal below has a real before-image to restore rather
        // than the absence of one.
        mark_cursor(&mut app, Mark::Keeper);
        settle_mark(&mut app, &rx);
        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&twin),
            Some(&Mark::Keeper),
            "the fixture only means something if the first mark landed: {}",
            app.commander.status
        );

        // The pathname leaves the manifest under the open view: the next write is refused.
        drop_from_manifest(&scenario, &twin);
        app.commander.active_panel_mut().list.select(Some(0));
        mark_cursor(&mut app, Mark::Delete);
        settle_mark(&mut app, &rx);

        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&twin),
            Some(&Mark::Keeper),
            "the panel must show the exact mark the database still holds"
        );
        assert!(
            app.commander.status.contains("not saved"),
            "{}",
            app.commander.status
        );
    }

    /// Clearing a mark is the same durable write, and fails closed the same way.
    #[test]
    fn a_refused_unmark_leaves_the_mark_in_place() {
        let _role = crate::state::store::role_guard();
        let (scenario, scan_id, twin) = scenario_with_scan("commander_unmark_refused");
        let (mut app, rx) = commander_on(&scenario, scan_id);
        panel_over(&mut app, &twin);
        mark_cursor(&mut app, Mark::Delete);
        settle_mark(&mut app, &rx);
        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&twin),
            Some(&Mark::Delete),
            "the fixture only means something if the mark landed: {}",
            app.commander.status
        );

        // Now the pathname leaves the manifest and the operator presses Space.
        drop_from_manifest(&scenario, &twin);
        app.commander.active_panel_mut().list.select(Some(0));
        toggle_mark_cursor(&mut app);
        settle_mark(&mut app, &rx);

        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&twin),
            Some(&Mark::Delete),
            "the DELETE the database still holds stays on screen"
        );
        assert!(
            app.commander.status.contains("not saved")
                || app.commander.status.contains("not cleared"),
            "{}",
            app.commander.status
        );
    }

    /// Takes `path` out of the manifest under a live view, so the next durable write on it is
    /// refused by the store itself — typed, named, and with nothing written.
    fn drop_from_manifest(scenario: &PlanScenario, path: &Path) {
        let conn = rusqlite::Connection::open(&scenario.db_path).expect("the scenario database");
        let removed = conn
            .execute(
                "DELETE FROM file WHERE path = ?1",
                rusqlite::params![path.to_string_lossy()],
            )
            .expect("the manifest row leaves");
        assert_eq!(removed, 1, "the fixture must remove exactly one row");
    }
}

/// U-4c: Enter used to mean Y. The one irreversible step in the tool was reachable by the key
/// people press to get a dialog off the screen.
#[cfg(test)]
mod u4c_enter_is_not_execute_tests {
    use super::state::ConfirmScroll;
    use super::*;

    /// An app with the F11 confirmation open over a two-action plan.
    fn confirming(tab: ConfirmTab) -> App {
        let (mut app, _rx) = crate::app::test_app();
        app.commander.pending_plan = crate::app::test_plan(2);
        app.commander.confirm_script =
            state::ConfirmScript::Ready("echo one\necho two".to_string());
        app.commander.confirm_scroll = ConfirmScroll {
            offset: 0,
            total: 2,
            rows: 1,
        };
        app.commander.overlay = Overlay::Confirm { tab };
        app
    }

    fn press(app: &mut App, code: KeyCode) {
        on_key(app, KeyEvent::new(code, KeyModifiers::NONE));
    }

    /// The point of U-4c. Enter must leave the operator exactly where they were.
    #[test]
    fn enter_does_not_execute_on_either_tab() {
        for tab in [ConfirmTab::Summary, ConfirmTab::Commands] {
            let mut app = confirming(tab);

            press(&mut app, KeyCode::Enter);
            press(&mut app, KeyCode::Enter);

            assert!(
                matches!(app.commander.overlay, Overlay::Confirm { .. }),
                "{tab:?}: the confirmation must stay open"
            );
            assert_eq!(
                app.commander
                    .pending_plan
                    .as_ref()
                    .map(|plan| plan.actions().len()),
                Some(2),
                "{tab:?}: the plan must be untouched"
            );
            assert!(app.apply.is_none(), "{tab:?}: no batch may have started");
            assert_eq!(
                app.screen,
                Screen::ScanConfig,
                "{tab:?}: the wizard must not have been entered"
            );
        }
    }

    /// Y is still the way through — and it hands over the exact plan that was pending.
    #[test]
    fn y_still_executes_the_pending_plan() {
        for code in [KeyCode::Char('y'), KeyCode::Char('Y')] {
            let mut app = confirming(ConfirmTab::Summary);

            press(&mut app, code);

            // The handover is synchronous; the batch itself has its own tests.
            assert!(matches!(app.commander.overlay, Overlay::None), "{code:?}");
            assert!(
                app.commander.pending_plan.is_none(),
                "{code:?}: the plan was taken"
            );
            assert_eq!(app.applying.total, 2, "{code:?}: both actions handed over");
            assert_eq!(app.screen, Screen::Applying, "{code:?}");
            assert!(app.apply.is_some(), "{code:?}: the worker was started");
        }
    }

    #[test]
    fn n_and_esc_still_cancel() {
        for code in [KeyCode::Char('n'), KeyCode::Char('N'), KeyCode::Esc] {
            let mut app = confirming(ConfirmTab::Commands);

            press(&mut app, code);

            assert!(matches!(app.commander.overlay, Overlay::None), "{code:?}");
            assert!(app.commander.pending_plan.is_none(), "{code:?}");
            assert!(app.apply.is_none(), "{code:?}: cancelling starts nothing");
        }
    }

    /// Dropping Enter must not disturb the keys U-4a and U-4b put on this overlay.
    #[test]
    fn tab_scroll_and_save_still_work() {
        let mut app = confirming(ConfirmTab::Summary);

        press(&mut app, KeyCode::Tab);
        assert!(matches!(
            app.commander.overlay,
            Overlay::Confirm {
                tab: ConfirmTab::Commands,
                ..
            }
        ));

        press(&mut app, KeyCode::Down);
        assert_eq!(app.commander.confirm_scroll.offset, 1, "Commands scrolls");
        press(&mut app, KeyCode::Home);
        assert_eq!(app.commander.confirm_scroll.offset, 0);

        // `S` writes next to the checkpoint DB — point it somewhere disposable so the test
        // asserts a real save instead of an error string.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("dedcom_u4c_save_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        app.db_path = dir.join("dedcom.db");

        press(&mut app, KeyCode::Char('s'));

        assert!(
            app.commander.status.starts_with("Script saved"),
            "S still reaches save: {}",
            app.commander.status
        );
        let saved = std::fs::read_dir(dir.join("plans")).unwrap().count();
        assert_eq!(saved, 1, "the script was written");
        assert!(
            matches!(app.commander.overlay, Overlay::Confirm { .. }),
            "and none of this closed the confirmation"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// F11 was the only way into Execute, and GNOME Terminal, Konsole, Windows Terminal and
/// xfce4-terminal all keep it for themselves — the operator marked files and had nothing to press.
#[cfg(test)]
mod u2_execute_reachability_tests {
    use super::*;

    /// `prepare_execution` ran and found nothing marked. Any other outcome (empty status, an
    /// overlay) means the key never reached it.
    const NOTHING_MARKED: &str = "No marked files (F5/F6/F7/F8)";

    fn commander_app() -> App {
        let (app, _rx) = crate::app::test_app();
        app
    }

    fn press(app: &mut App, code: KeyCode) {
        dispatch_key(app, KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn the_letter_alias_reaches_execute() {
        for code in [KeyCode::Char('x'), KeyCode::Char('X')] {
            let mut app = commander_app();
            press(&mut app, code);
            assert_eq!(app.commander.status, NOTHING_MARKED, "{code:?}");
        }
    }

    #[test]
    fn the_prefix_and_a_digit_reach_the_first_layer() {
        // ` then `-` is F11 — the whole point: Execute without pressing F11.
        let mut app = commander_app();
        press(&mut app, KeyCode::Char('`'));
        press(&mut app, KeyCode::Char('-'));
        assert_eq!(app.commander.status, NOTHING_MARKED);
        assert!(
            !app.commander.second_layer,
            "the layer disarms after the key"
        );

        // ` then `0` is F10 — quit, and it proves the mapping is not Execute-specific.
        let mut app = commander_app();
        press(&mut app, KeyCode::Char('`'));
        press(&mut app, KeyCode::Char('0'));
        assert!(app.should_quit);

        // A plain digit without the prefix is not a command.
        let mut app = commander_app();
        press(&mut app, KeyCode::Char('0'));
        assert!(!app.should_quit);
        assert!(app.commander.status.is_empty());
    }

    #[test]
    fn the_prefix_still_reaches_the_second_layer() {
        // The digits must not have taken the F-key meaning away: ` then F12 is Shift+F12.
        let mut app = commander_app();
        press(&mut app, KeyCode::Char('`'));
        press(&mut app, KeyCode::F(12));
        assert!(app.commander.board_active, "` F12 opens the Triage Board");
    }

    #[test]
    fn the_menu_offers_execute() {
        let index = MENU
            .iter()
            .position(|(_, action)| matches!(action, MenuAction::Execute))
            .expect("the F9 menu must offer Execute");
        assert!(
            MENU[index].0.contains("Execute"),
            "the label says what it does: {}",
            MENU[index].0
        );

        let mut app = commander_app();
        run_menu_action(&mut app, MENU[index].1);
        assert_eq!(app.commander.status, NOTHING_MARKED);
    }

    #[test]
    fn every_first_layer_key_is_reachable_by_a_digit() {
        let expected: Vec<(KeyCode, u8)> = (1..=9)
            .map(|n| {
                (
                    KeyCode::Char(char::from_digit(u32::from(n), 10).unwrap()),
                    n,
                )
            })
            .chain([
                (KeyCode::Char('0'), 10),
                (KeyCode::Char('-'), 11),
                (KeyCode::Char('='), 12),
            ])
            .collect();
        for (code, fkey) in expected {
            assert_eq!(first_layer_key(code), Some(fkey), "{code:?}");
        }
        assert_eq!(first_layer_key(KeyCode::Char('q')), None);
    }
}

#[cfg(test)]
mod u1_guard_tests {
    // U-1 matrix: row commands gated outside Files/DirsOnly; nav never gated.
    use super::*;

    const VIEWS: &[PanelView] = &[
        PanelView::Files,
        PanelView::DirsOnly,
        PanelView::GroupList,
        PanelView::GroupFiles,
        PanelView::DuplicatesOfCursor,
        PanelView::DirGroupList,
        PanelView::DirGroupFiles,
    ];

    const ROW_COMMANDS: &[KeyCode] = &[
        KeyCode::F(3),
        KeyCode::F(4),
        KeyCode::F(5),
        KeyCode::F(6),
        KeyCode::F(7),
        KeyCode::F(8),
        KeyCode::Char(' '),
        KeyCode::Insert,
        KeyCode::Char('m'),
        KeyCode::Enter,
    ];

    const NON_ROW_COMMANDS: &[KeyCode] = &[
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Char('v'),
        KeyCode::Char('s'),
        KeyCode::Char(','),
        KeyCode::Char('o'),
        KeyCode::Char('u'),
        KeyCode::Backspace,
        KeyCode::F(1),
        KeyCode::F(2),
        KeyCode::F(9),
        KeyCode::F(11),
    ];

    // independent oracle
    fn expected_entries_backed(view: PanelView) -> bool {
        matches!(view, PanelView::Files | PanelView::DirsOnly)
    }

    fn blocked(view: PanelView, code: KeyCode) -> bool {
        is_entries_row_command(code) && !view_exposes_entries(view)
    }

    #[test]
    fn row_commands_blocked_only_outside_entries_views() {
        for &view in VIEWS {
            for &code in ROW_COMMANDS {
                assert!(
                    is_entries_row_command(code),
                    "{code:?} must be recognised as a row command"
                );
                assert_eq!(
                    blocked(view, code),
                    !expected_entries_backed(view),
                    "{code:?} in {view:?}: must be blocked iff the view is not files/directories"
                );
            }
        }
    }

    #[test]
    fn navigation_and_view_commands_never_blocked() {
        for &view in VIEWS {
            for &code in NON_ROW_COMMANDS {
                assert!(
                    !is_entries_row_command(code),
                    "{code:?} must not be a row command"
                );
                assert!(
                    !blocked(view, code),
                    "{code:?} must stay enabled in {view:?}"
                );
            }
        }
    }

    #[test]
    fn uppercase_m_is_also_gated() {
        assert!(is_entries_row_command(KeyCode::Char('M')));
    }

    #[test]
    fn exactly_files_and_dirsonly_expose_entries() {
        assert!(view_exposes_entries(PanelView::Files));
        assert!(view_exposes_entries(PanelView::DirsOnly));
        for &view in &[
            PanelView::GroupList,
            PanelView::GroupFiles,
            PanelView::DuplicatesOfCursor,
            PanelView::DirGroupList,
            PanelView::DirGroupFiles,
        ] {
            assert!(
                !view_exposes_entries(view),
                "{view:?} must not expose entries"
            );
        }
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

    /// A duplicate whose name is not valid UTF-8 keeps its own bytes. Assembled through
    /// `to_string_lossy` the name came back with U+FFFD in place of every byte the decoder
    /// refused, so the file landed under a name the operator never selected — and one nothing
    /// can read back to the original.
    #[test]
    fn dup_dest_preserves_non_utf8_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = temp_dir("dup_bytes");

        // An invalid stem, carrying a valid extension.
        let src = PathBuf::from(OsStr::from_bytes(b"/somewhere/\x80.bin"));
        assert_eq!(
            dup_dest(&dir, &src),
            dir.join(OsStr::from_bytes(b"\x80.dup1.bin"))
        );

        // An invalid extension survives just as literally.
        let src = PathBuf::from(OsStr::from_bytes(b"/somewhere/photo.\xff"));
        assert_eq!(
            dup_dest(&dir, &src),
            dir.join(OsStr::from_bytes(b"photo.dup1.\xff"))
        );

        // And an invalid name with no extension at all.
        let src = PathBuf::from(OsStr::from_bytes(b"/somewhere/\x80"));
        assert_eq!(
            dup_dest(&dir, &src),
            dir.join(OsStr::from_bytes(b"\x80.dup1"))
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// Two names that differ only outside UTF-8 keep their own slots. Lossy conversion mapped
    /// `\x80` and `\xff` alike onto U+FFFD, so the second file was filed as `.dup2` of the first
    /// one's stem: two unrelated files sharing a stem neither of them ever had. Within one source
    /// directory stems are unique, so that collapse was in fact the main way `.dup2` was reached.
    #[test]
    fn dup_dest_does_not_collapse_distinct_non_utf8_names() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = temp_dir("dup_collapse");

        // The premise first, so the test proves what it claims rather than assuming it: the two
        // names differ as bytes, yet `to_string_lossy` maps them onto ONE string. Any name built
        // through a `String` is therefore blind to the difference between them.
        let a = OsStr::from_bytes(b"\x80.bin");
        let b = OsStr::from_bytes(b"\xff.bin");
        assert_ne!(a, b, "the two names are distinct on disk");
        assert_eq!(
            a.to_string_lossy(),
            b.to_string_lossy(),
            "but lossy conversion collapses them onto one string"
        );

        let first = dup_dest(&dir, Path::new(OsStr::from_bytes(b"/a/\x80.bin")));
        assert_eq!(first, dir.join(OsStr::from_bytes(b"\x80.dup1.bin")));
        fs::write(&first, b"x").unwrap();

        // The second name is a stem of its own, so it takes its own `.dup1`.
        let second = dup_dest(&dir, Path::new(OsStr::from_bytes(b"/a/\xff.bin")));
        assert_eq!(second, dir.join(OsStr::from_bytes(b"\xff.dup1.bin")));
        assert_ne!(first, second, "distinct names do not share a slot");
        fs::write(&second, b"y").unwrap();

        assert!(first.is_file(), "the first name is still its own file");
        assert!(second.is_file(), "and the second landed beside it");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_size_files_filters_by_size() {
        let dir = temp_dir("size");
        fs::write(dir.join("a.bin"), b"12345").unwrap(); // 5 bytes
        fs::write(dir.join("b.bin"), b"12345").unwrap(); // 5 bytes
        fs::write(dir.join("c.bin"), b"123").unwrap(); // 3 bytes
        fs::create_dir(dir.join("sub")).unwrap(); // directory — ignored
        let got = same_size_files(&dir, 5).expect("the directory reads");
        assert_eq!(
            got,
            vec![dir.join("a.bin"), dir.join("b.bin")],
            "and comes back sorted by name, not in readdir order"
        );
        assert!(same_size_files(&dir, 999)
            .expect("the directory reads")
            .is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    /// A directory that will not open is an error, not an empty answer.
    ///
    /// This is the `?` on `read_dir` itself, and it needs a test that does NOT go through the
    /// injection seam: the seam returns before `read_dir` is ever called, so it proves how the
    /// CALLER treats an error and nothing about where the error comes from. Both cases here are
    /// real refusals from the filesystem — no fixture, no seam, nothing to keep in step.
    #[test]
    fn a_destination_that_will_not_open_is_an_error() {
        let dir = temp_dir("unopenable");
        let not_a_dir = dir.join("plain.bin");
        fs::write(&not_a_dir, b"12345").unwrap();

        let err = same_size_files(&not_a_dir, 5).expect_err("a regular file is not a directory");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "ENOTDIR, not a missing path: {err}"
        );

        let missing = dir.join("no_such_dir");
        let err = same_size_files(&missing, 5).expect_err("a missing directory is an error too");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");

        fs::remove_dir_all(&dir).ok();
    }

    /// A stat that is refused fails the listing, the whole of it, not just its entry.
    ///
    /// The refusal lands on one of two same-size files, so the two outcomes are told apart: an
    /// arm that skipped the entry would still answer `Ok` with the other file in it, a listing
    /// short by one that the caller cannot tell from a complete one. The kind is checked too:
    /// what to do with a `PermissionDenied` is the caller's decision, so it must not arrive
    /// relabelled.
    #[test]
    fn a_refused_stat_fails_the_listing_not_only_its_entry() {
        let dir = temp_dir("refused");
        let refused = dir.join("a.bin");
        fs::write(&refused, b"12345").unwrap();
        fs::write(dir.join("b.bin"), b"12345").unwrap();

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            refused,
            crate::testfixtures::WalkFault::MetadataRefused,
        )]);
        let listing = same_size_files(&dir, 5);

        assert!(
            faults.pending().is_empty(),
            "the fault must have fired: an unfired one means the entry was never stat'ed"
        );
        let err = listing.expect_err("a refused stat is an error, not a listing short by one");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");

        fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod live_trust_tests {
    //! R3D: only a `Trusted` live signature may enter the cross-panel exact-match set or the
    //! match counters. An `Unknown` scan's signatures are inspectable, never exact-looking.

    use super::*;
    use crate::model::duplicate::DirTrust;
    use crate::state::LiveDirSignature;
    use crate::tui::commander::dedup::DirDedup;

    fn dir_entry(path: &str) -> state::PanelEntry {
        state::PanelEntry {
            path: PathBuf::from(path),
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            kind: EntryKind::Dir,
            size: 0,
            mtime: 0,
            device: 0,
            inode: 0,
        }
    }

    fn dedup_with(sig_path: &str, signature: &str, trust: DirTrust) -> DirDedup {
        let mut dedup = DirDedup::default();
        dedup.dir_signatures.insert(
            PathBuf::from(sig_path),
            LiveDirSignature {
                signature: signature.to_string(),
                trust,
            },
        );
        dedup
    }

    /// Two panels holding the same signature: trusted on both sides → a cross match; untrusted
    /// on either side → no match, no count, nothing exact-looking.
    #[test]
    fn cross_panel_matching_and_counts_are_trusted_only() {
        let (mut app, _events) = crate::app::test_app();
        app.commander.panels[0].cwd = PathBuf::from("/d1");
        app.commander.panels[0].entries = vec![dir_entry("/d1/x")];
        app.commander.panels[1].cwd = PathBuf::from("/d2");
        app.commander.panels[1].entries = vec![dir_entry("/d2/y")];

        app.commander.dedup.insert_dir(
            PathBuf::from("/d1"),
            Ok(dedup_with("/d1/x", "S", DirTrust::Trusted)),
        );
        app.commander.dedup.insert_dir(
            PathBuf::from("/d2"),
            Ok(dedup_with("/d2/y", "S", DirTrust::Untrusted)),
        );
        assert!(
            cross_panel_keys(&app).is_empty(),
            "an untrusted signature must not complete an exact match"
        );
        let (files, dirs) = count_panel_matches(
            app.commander.dedup.dir(Path::new("/d1")),
            app.commander.dedup.dir(Path::new("/d2")),
            &app.commander.panels[0],
            &app.commander.panels[1],
        );
        assert_eq!((files, dirs), (0, 0), "and must not count as one either");

        app.commander.dedup.insert_dir(
            PathBuf::from("/d2"),
            Ok(dedup_with("/d2/y", "S", DirTrust::Trusted)),
        );
        assert!(
            cross_panel_keys(&app).contains(&MatchKey::Directory("S".to_string())),
            "both sides trusted → the match is real"
        );
        let (_, dirs) = count_panel_matches(
            app.commander.dedup.dir(Path::new("/d1")),
            app.commander.dedup.dir(Path::new("/d2")),
            &app.commander.panels[0],
            &app.commander.panels[1],
        );
        assert_eq!(dirs, 1);
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
            device: 1,
            inode: 1,
            nlink: 1,
            ..Default::default()
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
            result: Some(state::WatchResult::FileGroup(
                DuplicateGroup {
                    id: 0,
                    size_bytes: 100,
                    hash: "abc".to_string(),
                    files: vec![make_file_entry("/tmp/dir/foo.bin")],
                },
                crate::state::GroupClaim {
                    reclaim: crate::model::reclaim::ReclaimEstimate::exact(100),
                    links: crate::state::GroupLinks {
                        observed: 1,
                        total: crate::model::reclaim::LinkCount::Known(1),
                    },
                },
            )),
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
mod group_panel_tests {
    //! The commander's own view of the file-group list: the width it really gets on an 80-column
    //! terminal, and the click mapping that has to follow the entry height.

    use super::*;
    use crate::model::reclaim::ReclaimEstimate;
    use crate::state::GroupSummary;
    use crate::tui::screens::browser::tests::entry_text;
    use ratatui::layout::Position;
    use ratatui::{backend::TestBackend, Terminal};
    use std::path::PathBuf;

    /// Three groups with DIFFERENT figures, so no row can stand in for another's number: if the
    /// exact entry loses its own `4.0 KiB` it cannot borrow one, because nothing else on screen
    /// says `4.0 KiB`.
    fn summaries() -> Vec<(crate::model::plan::GroupId, GroupSummary)> {
        [
            ReclaimEstimate::exact(4096),
            ReclaimEstimate::upper_bound(9 * 1024 * 1024),
            ReclaimEstimate::unknown(),
        ]
        .into_iter()
        .enumerate()
        .map(|(rank, reclaim)| {
            (
                crate::model::plan::GroupId {
                    scan_id: 1,
                    rank: rank as i64,
                    generation: 1,
                },
                GroupSummary {
                    rank: rank as i64,
                    hash: format!("h{rank}"),
                    file_count: 3,
                    size_bytes: 4096,
                    object_count: 2,
                    reclaim,
                },
            )
        })
        .collect()
    }

    /// A commander with two panels, the first showing the group list.
    fn app_with_group_panel() -> (
        App,
        crossbeam_channel::Receiver<crate::tui::event::AppEvent>,
    ) {
        let (mut app, events) = crate::app::test_app();
        app.commander = CommanderState::new(&[PathBuf::from("/a"), PathBuf::from("/b")]);
        app.commander.panels[0].view = PanelView::GroupList;
        app.commander.panels[0].list.select(Some(0));
        app.commander.group_summaries = summaries();
        (app, events)
    }

    /// The acceptance condition C4b claimed and did not test: a REAL 80-column commander, which
    /// draws two panels of 40, must show every claim complete — qualifier and figure both.
    ///
    /// Each claim is read out of its OWN entry's rows and columns. C4b1 searched the whole screen
    /// for the claim's words in order, which let the exact row — rendered with its figure cut
    /// off — pass by finding a `4.0 KiB` that belonged to the row below it.
    #[test]
    fn an_eighty_column_two_panel_commander_shows_every_claim_in_its_own_entry() {
        assert_eq!(
            layout::max_panels(80),
            2,
            "the layout this test exists for: 80 columns is two panels"
        );
        let (mut app, _events) = app_with_group_panel();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer().clone();

        let regions = layout::regions(Rect::new(0, 0, 80, 24));
        let rects = layout::panel_rects(regions.panels, visible_panel_count(&app, 80));
        assert_eq!(rects.len(), 2, "two panels must be on screen");
        assert_eq!(rects[0].width, 40, "the width this defect lives at");
        let panel = rects[0];
        let rows = crate::tui::screens::browser::group_rows(panel.width);

        let claims: Vec<String> = app
            .commander
            .group_summaries
            .iter()
            .map(|(_, group)| crate::tui::reclaim_cell(group.reclaim))
            .collect();
        // Every figure on screen is distinct, so a borrowed number cannot satisfy a check.
        assert_eq!(
            claims
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            claims.len(),
            "the fixture must not repeat a claim"
        );

        for (entry, claim) in claims.iter().enumerate() {
            let text = entry_text(&buffer, panel, entry, rows);
            assert!(
                text.contains(claim.as_str()),
                "entry {entry} must state «{claim}» in its own rows: {text}"
            );
        }
        // The second panel is still a panel — a test that passed by collapsing the commander to
        // one wide column would prove nothing about the width that failed.
        assert!(
            (0..24).any(|y| {
                (rects[1].x..(rects[1].x + rects[1].width))
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .contains("2 · ")
            }),
            "the second panel's title must still be drawn"
        );
    }

    /// The row-local reading is what makes the test above mean anything, so it is itself checked:
    /// an entry's text must not contain a neighbour's claim.
    #[test]
    fn an_entrys_text_stops_at_its_own_rows() {
        let (mut app, _events) = app_with_group_panel();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let regions = layout::regions(Rect::new(0, 0, 80, 24));
        let panel = layout::panel_rects(regions.panels, 2)[0];
        let rows = crate::tui::screens::browser::group_rows(panel.width);

        let first = entry_text(&buffer, panel, 0, rows);
        let second = crate::tui::reclaim_cell(app.commander.group_summaries[1].1.reclaim);
        assert!(
            first.contains("4.0 KiB"),
            "the first entry keeps its own figure: {first}"
        );
        assert!(
            !first.contains(&second),
            "the first entry must not reach into the second: {first}"
        );
    }

    /// Three groups whose allocation counts all differ, the first one as the v3 migration leaves
    /// it: `object_count == 0` with nothing established about the row.
    fn summaries_with_a_migrated_row() -> Vec<(crate::model::plan::GroupId, GroupSummary)> {
        [
            (0u64, ReclaimEstimate::unknown()),
            (5, ReclaimEstimate::unknown()),
            (2, ReclaimEstimate::exact(4096)),
        ]
        .into_iter()
        .enumerate()
        .map(|(rank, (object_count, reclaim))| {
            (
                crate::model::plan::GroupId {
                    scan_id: 1,
                    rank: rank as i64,
                    generation: 1,
                },
                GroupSummary {
                    rank: rank as i64,
                    hash: format!("h{rank}"),
                    file_count: 3,
                    size_bytes: 4096,
                    object_count,
                    reclaim,
                },
            )
        })
        .collect()
    }

    /// The migrated sentinel in the layout that is hardest on it: an 80-column commander draws two
    /// panels of 40, and the counters line is cut there rather than wrapped. Every row is read
    /// from its own rows and columns, and no two rows count the same, so nothing can be borrowed.
    #[test]
    fn an_eighty_column_commander_says_a_migrated_groups_count_is_unknown() {
        let (mut app, _events) = app_with_group_panel();
        app.commander.group_summaries = summaries_with_a_migrated_row();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer().clone();

        let regions = layout::regions(Rect::new(0, 0, 80, 24));
        let rects = layout::panel_rects(regions.panels, visible_panel_count(&app, 80));
        assert_eq!(rects[0].width, 40, "the width this wording has to fit");
        let panel = rects[0];
        let rows = crate::tui::screens::browser::group_rows(panel.width);

        for (entry, phrase) in ["? objects", "5 objects", "2 objects"].iter().enumerate() {
            let text = entry_text(&buffer, panel, entry, rows);
            assert!(
                text.contains(*phrase),
                "entry {entry} must count its allocations as «{phrase}» in its own rows: {text}"
            );
            assert!(
                !text.contains("0 objects"),
                "entry {entry} must not report zero allocations: {text}"
            );
        }
    }

    /// Every visual line of a group entry selects that same entry — the click must not depend on
    /// which line of the entry the pointer landed on.
    #[test]
    fn every_line_of_a_group_entry_hits_the_same_entry() {
        let (app, _events) = app_with_group_panel();
        let area = Rect::new(0, 0, 80, 24);
        let regions = layout::regions(area);
        let rects = layout::panel_rects(regions.panels, 2);
        let panel = rects[0];
        let rows = crate::tui::screens::browser::group_rows(panel.width) as usize;
        assert_eq!(rows, 3, "40 columns wraps the claim onto a second line");

        for entry in 0..app.commander.group_summaries.len() {
            for line in 0..rows {
                let y = panel.y + 1 + (entry * rows + line) as u16;
                let hit = panel_hit(&app, &regions, Position { x: panel.x + 2, y });
                assert_eq!(
                    hit,
                    Some((0, Some(entry))),
                    "line {line} of entry {entry} must hit entry {entry}"
                );
            }
        }

        // Below the last entry there is nothing to hit.
        let past = panel.y + 1 + (app.commander.group_summaries.len() * rows) as u16;
        assert_eq!(
            panel_hit(
                &app,
                &regions,
                Position {
                    x: panel.x + 2,
                    y: past
                }
            ),
            Some((0, None)),
            "a click past the last entry selects nothing"
        );
    }

    /// Only the group list is taller than a row. Every other view keeps one entry per line, so
    /// this change cannot have moved anyone else's cursor.
    #[test]
    fn other_panel_views_are_still_one_row_per_entry() {
        for view in [
            PanelView::Files,
            PanelView::DirsOnly,
            PanelView::GroupFiles,
            PanelView::DuplicatesOfCursor,
            PanelView::DirGroupList,
            PanelView::DirGroupFiles,
        ] {
            assert_eq!(rows_per_entry(view, 40), 1, "{view:?} must stay one row");
        }
        assert_eq!(rows_per_entry(PanelView::GroupList, 52), 3);
        assert_eq!(rows_per_entry(PanelView::GroupList, 40), 3);
        assert_eq!(
            rows_per_entry(PanelView::GroupList, 96),
            2,
            "a panel wide enough for the widest claim spends one line on it"
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

#[cfg(test)]
mod dir_watch_tests {
    //! The `DuplicatesOfCursor` panel over a DIRECTORY cursor, driven end to end: a real database
    //! file, the real `resolve_watch_groups` cache and the real commander render. A store helper
    //! test alone would not show that the panel stops resurrecting a suppressed member, because
    //! the resurrection lived in the route, not in the query.

    use super::*;
    use crate::model::duplicate::{DirGroup, DirTrust};
    use crate::model::omission::{OmissionCounts, OmissionReason, PathKey};
    use crate::model::scan::{ScanConfig, ScanStatus};
    use crate::state::ScanStore;
    use ratatui::{backend::TestBackend, Terminal};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// A unique database path for one test — the commander opens the store by path, so these
    /// cases cannot share an in-memory connection the way the store's own tests do.
    fn db_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("dedcom_watch_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("dedcom.db")
    }

    /// One root's ledger from `(directory, reason)` events.
    fn one_root(
        root: &str,
        events: &[(&str, OmissionReason)],
    ) -> BTreeMap<PathKey, OmissionCounts> {
        let mut counts = OmissionCounts::new();
        for (dir, reason) in events {
            counts
                .bump(
                    PathKey::new(Path::new(dir)).expect("a keyable path"),
                    *reason,
                )
                .unwrap();
        }
        BTreeMap::from([(
            PathKey::new(Path::new(root)).expect("a keyable root"),
            counts,
        )])
    }

    /// A completed scan over `/tank`: three twin directories in `dir_dedup`, one file each in the
    /// manifest so «is this path in the scan» has a truthful answer, and a committed empty ledger
    /// — every member trusted until a test says otherwise.
    fn seeded_db(tag: &str) -> (PathBuf, i64) {
        let db = db_path(tag);
        let mut store = ScanStore::open(&db).unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &["/tank/t1/f", "/tank/t2/f", "/tank/t3/f"]
                    .iter()
                    .enumerate()
                    .map(|(i, path)| crate::state::ManifestRow {
                        path: PathBuf::from(path),
                        size: 10,
                        mtime: 0,
                        device: 1,
                        inode: i as u64 + 1,
                        nlink: 1,
                        ..Default::default()
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        store
            .record_dir_groups(
                scan_id,
                &[DirGroup {
                    id: 0,
                    signature: "TRIO".to_string(),
                    paths: vec![
                        PathBuf::from("/tank/t1"),
                        PathBuf::from("/tank/t2"),
                        PathBuf::from("/tank/t3"),
                    ],
                    file_count: 1,
                    size_per_dir: 10,
                }],
            )
            .unwrap();
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        store.set_status(scan_id, ScanStatus::Complete).unwrap();
        (db, scan_id)
    }

    fn panel_entry(path: &str, kind: EntryKind) -> PanelEntry {
        let p = PathBuf::from(path);
        PanelEntry {
            name: p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            path: p,
            kind,
            size: 0,
            mtime: 0,
            device: 0,
            inode: 0,
        }
    }

    fn dir_entry(path: &str) -> PanelEntry {
        panel_entry(path, EntryKind::Dir)
    }

    /// A two-panel commander over `db`, without a scan: a `directories` panel whose cursor stands
    /// on `cursor`, and the watching `DuplicatesOfCursor` panel beside it.
    fn panels_only(
        db: &Path,
        cursor: &str,
    ) -> (
        App,
        crossbeam_channel::Receiver<crate::tui::event::AppEvent>,
    ) {
        let (mut app, events) = crate::app::test_app_with_db(db.to_path_buf());
        app.commander = CommanderState::new(&[PathBuf::from("/")]);
        let mut source = state::Panel::empty(PathBuf::from("/tank"));
        source.loading = false;
        source.view = PanelView::DirsOnly;
        source.entries = vec![dir_entry(cursor)];
        source.list.select(Some(0));
        let mut watch = state::Panel::empty(PathBuf::from("/tank"));
        watch.loading = false;
        watch.view = PanelView::DuplicatesOfCursor;
        app.commander.panels = vec![source, watch];
        app.commander.active = 0;
        (app, events)
    }

    /// The same commander with the scan OPENED through the actor — since R4B-2c the only thing
    /// that gives the commander a scan to watch, and the only place a browsing store is opened.
    ///
    /// Every fixture below that wants a read to fail therefore breaks the database AFTER this
    /// point: that is the real sequence — the operator is browsing a healthy checkpoint, and a
    /// read fails under them.
    fn app_watching(
        db: &Path,
        scan_id: i64,
        cursor: &str,
    ) -> (
        App,
        crossbeam_channel::Receiver<crate::tui::event::AppEvent>,
    ) {
        let (mut app, events) = panels_only(db, cursor);
        crate::app::open_and_settle(
            &mut app,
            &events,
            scan_id,
            crate::app::OpenIntent::Commander,
        );
        assert_eq!(
            app.commander.dedup_scan_id,
            Some(scan_id),
            "the fixture's scan must open: {}",
            app.commander.status
        );
        crate::app::drain(&mut app, &events);
        (app, events)
    }

    /// Sends the watch requests and carries the actor's answers back.
    ///
    /// `resolve_watch_groups` no longer computes anything: it asks. Each watching panel owes
    /// exactly one reply, and the cache holds a verdict only once that reply has been installed.
    fn resolve_and_settle(
        app: &mut App,
        rx: &crossbeam_channel::Receiver<crate::tui::event::AppEvent>,
    ) {
        resolve_watch_groups(app);
        crate::app::pump_until(app, rx, "the watch answers", |app| {
            app.routes.groups.is_empty()
                && app.routes.infos.is_empty()
                && app.routes.dirs_at.is_empty()
                && app.routes.dir_opens.is_empty()
        });
    }

    /// Re-resolves the watch panels from scratch — the same invalidation `apply_auto_switch` does
    /// when the active scan changes, and the only way to see a ledger written after the first
    /// resolve (the cache key, the cursor path, has not moved).
    fn re_resolve(app: &mut App, rx: &crossbeam_channel::Receiver<crate::tui::event::AppEvent>) {
        app.commander.watch_cache = Vec::new();
        resolve_and_settle(app, rx);
    }

    fn watch_entry(app: &App) -> &state::WatchEntry {
        app.commander
            .watch_cache
            .get(1)
            .expect("the watching panel")
    }

    /// The rows of panel `index` on the rendered screen, as plain text lines.
    fn panel_lines(buffer: &ratatui::buffer::Buffer, area: Rect) -> Vec<String> {
        (area.y..(area.y + area.height))
            .map(|y| {
                (area.x..(area.x + area.width))
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    /// Renders the commander at `term_width` and returns the watching panel's lines together with
    /// the width that panel actually received. A render proof about a narrow panel is worth
    /// nothing if the panel quietly came out wide, so the width is returned to be asserted.
    fn render_watch_panel_at(app: &mut App, term_width: u16) -> (Vec<String>, u16) {
        let mut terminal = Terminal::new(TestBackend::new(term_width, 20)).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let regions = layout::regions(Rect::new(0, 0, term_width, 20));
        let rects = layout::panel_rects(regions.panels, visible_panel_count(app, term_width));
        assert!(rects.len() >= 2, "the watching panel must be on screen");
        (panel_lines(&buffer, rects[1]), rects[1].width)
    }

    /// Renders the commander and returns the watching panel's lines.
    fn render_watch_panel(app: &mut App) -> Vec<String> {
        render_watch_panel_at(app, 120).0
    }

    /// The whole point of C1: the ledger written AFTER materialization decides what the watch
    /// panel shows. A member suppressed since then is gone, and a suppressed CURSOR gets no group
    /// at all — the survivors are not «duplicates of this cursor».
    #[test]
    fn the_watch_panel_obeys_the_current_ledger() {
        let (db, scan_id) = seeded_db("ledger");
        let (mut app, events) = app_watching(&db, scan_id, "/tank/t1");

        resolve_and_settle(&mut app, &events);
        let group = match &watch_entry(&app).result {
            Some(state::WatchResult::DirGroup(group)) => group.clone(),
            other => panic!("a clean ledger answers the cursor's group: {other:?}"),
        };
        assert_eq!(group.trust, DirTrust::Trusted);
        assert_eq!(group.group.paths.len(), 3);

        // A later walk finds an omission inside one TWIN: it leaves the membership, the cursor stays.
        let mut store = ScanStore::open(&db).unwrap();
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/t3/inner", OmissionReason::NonUtf8)]),
            )
            .unwrap();
        drop(store);
        re_resolve(&mut app, &events);
        match &watch_entry(&app).result {
            Some(state::WatchResult::DirGroup(group)) => assert_eq!(
                group.group.paths,
                vec![PathBuf::from("/tank/t1"), PathBuf::from("/tank/t2")],
                "the suppressed twin left the panel"
            ),
            other => panic!("the cursor and one twin survive: {other:?}"),
        }

        // Now the omission is at the CURSOR itself.
        let mut store = ScanStore::open(&db).unwrap();
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/t1", OmissionReason::MetadataError)]),
            )
            .unwrap();
        drop(store);
        re_resolve(&mut app, &events);
        let entry = watch_entry(&app);
        assert!(
            entry.result.is_none(),
            "a suppressed cursor has no group: {:?}",
            entry.result
        );
        assert!(entry.unavailable.is_none(), "this is a legitimate absence");
        assert_eq!(
            entry.empty,
            state::WatchEmpty::NoDuplicates,
            "the cursor is in the scan and simply has nothing to show"
        );
    }

    /// A ledger this build cannot read is not «no duplicates»: it is visible, and it enters
    /// neither the inner-dupes fallback nor either empty verdict.
    #[test]
    fn a_hard_snapshot_failure_is_visible_and_enters_no_fallback() {
        let (db, scan_id) = seeded_db("corrupt");
        // A real ledger row first — an empty ledger has nothing to corrupt.
        let mut store = ScanStore::open(&db).unwrap();
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/other", OmissionReason::MinSize)]),
            )
            .unwrap();
        drop(store);

        // The view opens over a healthy checkpoint; the ledger is corrupted under it, with a
        // reason no build of this schema knows — how the store's own hard-error tests seed it.
        let (mut app, events) = app_watching(&db, scan_id, "/tank/t1");
        let conn = rusqlite::Connection::open(&db).unwrap();
        let corrupted = conn
            .execute(
                "UPDATE dir_omission SET reason = 'quota_error' WHERE scan_id = ?1",
                rusqlite::params![scan_id],
            )
            .unwrap();
        assert_eq!(corrupted, 1, "the corruption must actually land on a row");
        drop(conn);

        resolve_and_settle(&mut app, &events);
        let entry = watch_entry(&app);
        let failure = entry
            .unavailable
            .as_ref()
            .expect("the failure to read the ledger is the answer");
        assert_eq!(
            failure.subject,
            state::WatchSubject::DirectoryGroup,
            "the accepted directory subject is unchanged"
        );
        assert!(
            failure.detail.contains("does not know"),
            "{}",
            failure.detail
        );
        assert!(entry.result.is_none(), "no group is claimed");
        assert_ne!(entry.empty, state::WatchEmpty::NoDuplicates);
        assert_ne!(entry.empty, state::WatchEmpty::NotInScan);

        let lines = render_watch_panel(&mut app);
        let text = lines.join("\n");
        assert!(
            text.contains("directory group unavailable:"),
            "the panel says why it is empty: {text}"
        );
        assert!(
            !text.contains("no dupes at the cursor") && !text.contains("out of scan"),
            "a broken checkpoint must not be reported as a clean result: {text}"
        );
    }

    /// The other two reads of the `DirOf` branch lost their `.ok()`/`unwrap_or` sinks as well: with
    /// the manifest column renamed away, `dup_files_inside` fails — and the panel says so instead
    /// of answering «no dupes at the cursor».
    #[test]
    fn a_failed_inner_dupes_read_is_visible_too() {
        let (db, scan_id) = seeded_db("inner");
        // The cursor is a directory of the scan that is in NO dir_dedup group, so the branch
        // reaches the inner-dupes fallback; the manifest read it makes is then broken — after
        // the view is already open over the healthy checkpoint.
        let (mut app, events) = app_watching(&db, scan_id, "/tank/solo");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("ALTER TABLE file RENAME COLUMN path TO path_gone")
            .unwrap();
        drop(conn);

        resolve_and_settle(&mut app, &events);
        let entry = watch_entry(&app);
        assert!(
            entry.unavailable.is_some(),
            "a failed manifest read is not an empty result: {:?}",
            entry.empty
        );
        assert!(entry.result.is_none());
    }

    /// The frozen wording of an unverified watch answer: it says exactly what it is, marks every
    /// member with the `?` the rest of the UI uses, and claims no twin, no duplicate and no bytes.
    /// The trusted rendering above it is left byte for byte as it was.
    #[test]
    fn an_unverified_watch_group_claims_nothing_on_screen() {
        let (db, scan_id) = seeded_db("render");
        let (mut app, events) = app_watching(&db, scan_id, "/tank/t1");
        resolve_and_settle(&mut app, &events);

        let trusted = render_watch_panel(&mut app).join("\n");
        assert!(
            trusted.contains(" 2 · duplicates "),
            "a trusted group keeps the mode's own title: {trusted}"
        );
        assert!(
            trusted.contains("★ /tank/t1") && !trusted.contains('?'),
            "no member of a trusted group is marked unverified: {trusted}"
        );

        // The authority is gone: the same three directories, nothing vouching for them.
        let mut store = ScanStore::open(&db).unwrap();
        store.clear_scan_omissions(scan_id).unwrap();
        drop(store);
        re_resolve(&mut app, &events);
        match &watch_entry(&app).result {
            Some(state::WatchResult::DirGroup(group)) => {
                assert_eq!(group.trust, DirTrust::Untrusted)
            }
            other => panic!("an unverified group stays inspectable: {other:?}"),
        }

        let (wide_lines, wide_width) = render_watch_panel_at(&mut app, 120);
        assert_eq!(wide_width, 60, "two panels across 120 columns");
        let unverified = wide_lines.join("\n");
        assert!(
            unverified.contains("unverified candidate — rescan required"),
            "the frozen qualifier must be visible: {unverified}"
        );
        assert!(
            unverified.contains("★?/tank/t1") && unverified.contains("? /tank/t2"),
            "every member carries the unverified marker: {unverified}"
        );
        for forbidden in ["twin", "duplicate", "dupes", "KiB", "MiB", " B "] {
            assert!(
                !unverified.contains(forbidden),
                "an unverified answer may not claim «{forbidden}»: {unverified}"
            );
        }
    }

    /// The same answer at the SUPPORTED FLOOR. 36 columns leave 34 title cells against the wide
    /// wording's 44, so ten are clipped: the tail ` required ` goes whole and the title stops
    /// after `rescan`, losing the only part that says what to do about it. The compact title
    /// keeps both facts inside the floor.
    #[test]
    fn the_unverified_remedy_survives_the_narrow_panel() {
        let (db, scan_id) = seeded_db("narrow");
        let (mut app, events) = app_watching(&db, scan_id, "/tank/t1");
        let mut store = ScanStore::open(&db).unwrap();
        store.clear_scan_omissions(scan_id).unwrap();
        drop(store);
        re_resolve(&mut app, &events);

        let (lines, width) = render_watch_panel_at(&mut app, 72);
        assert_eq!(
            width,
            layout::MIN_PANEL_WIDTH,
            "72 columns is exactly two panels at the supported floor"
        );
        let narrow = lines.join("\n");
        assert!(
            narrow.contains("unverified · rescan required"),
            "the remedy may not be the part that gets clipped: {narrow}"
        );
        assert!(
            narrow.contains("★?/tank/t1") && narrow.contains("? /tank/t2"),
            "every member still carries the unverified marker: {narrow}"
        );
        for forbidden in ["twin", "duplicate", "dupes", "KiB", "MiB", " B "] {
            assert!(
                !narrow.contains(forbidden),
                "an unverified answer may not claim «{forbidden}»: {narrow}"
            );
        }
    }

    /// A checkpoint `ScanStore::open` refuses outright: the schema is stamped newer than this
    /// build supports. The panel keeps pointing at the scan because its cwd coverage was cached
    /// while the database was healthy — the shape a swapped or upgraded checkpoint leaves behind.
    fn unopenable_db(tag: &str) -> (PathBuf, i64) {
        let (db, scan_id) = seeded_db(tag);
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.pragma_update(None, "user_version", 9999i64).unwrap();
        drop(conn);
        // Evidence is worthless if the fixture accidentally opens (or creates) a usable database.
        assert!(
            ScanStore::open(&db).is_err(),
            "the fixture must really fail in ScanStore::open"
        );
        (db, scan_id)
    }

    /// A commander whose coverage cache still points at `scan_id`, so a failure is met on the
    /// watch path rather than at the auto-switch that runs before it.
    fn app_over_watched_db(
        db: &Path,
        scan_id: i64,
        cursor: &str,
    ) -> (
        App,
        crossbeam_channel::Receiver<crate::tui::event::AppEvent>,
    ) {
        let (mut app, events) = app_watching(db, scan_id, cursor);
        app.commander
            .scan_coverage_cache
            .insert(PathBuf::from("/tank"), Some(scan_id));
        (app, events)
    }

    /// A failed directory-group read is not «out of scan»: it must be said out loud, with the
    /// directory subject and the concrete error the read produced.
    ///
    /// This replaces `a_failed_database_open_is_visible_for_a_directory_cursor`, which met the
    /// failure at an open the watch path performed itself. Since R4B-2c the watch path opens
    /// nothing — the actor holds the one connection for its life — so the failure is injected
    /// where a real one now happens: in the read, under a view that is already open. The
    /// unopenable-checkpoint half of that old test is proved below, at the one place an open
    /// still exists.
    #[test]
    fn a_failed_directory_group_read_is_visible_for_a_directory_cursor() {
        let (db, scan_id) = seeded_db("dir_read");
        let (mut app, events) = app_over_watched_db(&db, scan_id, "/tank/t1");
        break_column(&db, "dir_dedup", "size_per_dir");

        resolve_and_settle(&mut app, &events);
        let entry = watch_entry(&app);
        let failure = entry.unavailable.as_ref().unwrap_or_else(|| {
            panic!(
                "an unreadable checkpoint is not «out of scan»: empty={:?}, result={:?}",
                entry.empty, entry.result
            )
        });
        assert_eq!(failure.subject, state::WatchSubject::DirectoryGroup);
        assert!(
            failure.detail.contains("size_per_dir"),
            "the real error is preserved, not a generic one: {}",
            failure.detail
        );
        assert!(entry.result.is_none(), "no group is claimed");
        assert_ne!(entry.empty, state::WatchEmpty::NotInScan);
        assert_ne!(entry.empty, state::WatchEmpty::NoDuplicates);

        let (lines, _) = render_watch_panel_at(&mut app, 120);
        let text = lines.join("\n");
        assert!(
            text.contains("directory group unavailable:"),
            "the panel says why it is empty: {text}"
        );
        for forbidden in ["out of scan", "no dupes", "no scan data", "dupes inside"] {
            assert!(
                !text.contains(forbidden),
                "a broken checkpoint must not read as «{forbidden}»: {text}"
            );
        }
    }

    /// The unopenable checkpoint, met where the only remaining open is: the actor's own `Open`.
    ///
    /// This is what `a_failed_open_is_visible_for_a_file_cursor` and
    /// `..._for_a_group_cursor` proved — that an open failure is never translated into an empty
    /// result — folded into one, because the three sinks they covered were three separate opens
    /// and there is now one. The subject-typed FILE failures those two also carried are proved,
    /// unchanged, by the member/claim/hash sinks below.
    #[test]
    fn an_unopenable_checkpoint_is_refused_at_the_open_and_claims_nothing() {
        let (db, scan_id) = unopenable_db("open_refused");
        let (mut app, events) = panels_only(&db, "/tank/t1");
        app.commander
            .scan_coverage_cache
            .insert(PathBuf::from("/tank"), Some(scan_id));

        crate::app::open_and_settle(
            &mut app,
            &events,
            scan_id,
            crate::app::OpenIntent::Commander,
        );

        assert!(
            app.current_scan_id.is_none() && app.commander.dedup_scan_id.is_none(),
            "nothing may be installed from a checkpoint nobody could open"
        );
        assert!(
            app.commander.status.contains("could not be opened")
                && app.commander.status.contains("newer version"),
            "the real open error is preserved, not a generic one: {}",
            app.commander.status
        );
        assert!(
            app.commander.group_summaries.is_empty() && app.commander.candidates.is_none(),
            "and no presentation is invented for it"
        );

        // The watch panel claims nothing either, at either supported width.
        resolve_and_settle(&mut app, &events);
        assert!(watch_entry(&app).result.is_none(), "no group is claimed");
        for width in [120, 72] {
            let (lines, _) = render_watch_panel_at(&mut app, width);
            let text = lines.join("\n");
            for forbidden in ["dupes inside", "★", "twin"] {
                assert!(
                    !text.contains(forbidden),
                    "a checkpoint nobody opened may not draw «{forbidden}» ({width}): {text}"
                );
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // R4-C0: every hard store failure of the FILE-group watch flow is visible, subject-typed and
    // cached, and no legitimate absence changes meaning. Fixtures are real schema failures — a
    // renamed column that `CREATE TABLE IF NOT EXISTS` cannot restore — never asserted wording.
    // ---------------------------------------------------------------------------------------

    /// A completed scan holding one real file group of two allocations.
    fn file_group_db(tag: &str) -> (PathBuf, i64) {
        let db = db_path(tag);
        let mut store = ScanStore::open(&db).unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &["/tank/a.bin", "/tank/b.bin"]
                    .iter()
                    .enumerate()
                    .map(|(i, path)| crate::state::ManifestRow {
                        path: PathBuf::from(path),
                        size: 4096,
                        mtime: 0,
                        device: 1,
                        inode: i as u64 + 1,
                        nlink: 1,
                        ..Default::default()
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let digest = [7u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/tank/a.bin"), digest),
                    (PathBuf::from("/tank/b.bin"), digest),
                ],
            )
            .unwrap();
        store
            .publish_results(scan_id, crate::state::PublishMode::Derived)
            .unwrap();
        store.set_status(scan_id, ScanStatus::Complete).unwrap();
        (db, scan_id)
    }

    /// A commander whose watching panel resolves `WatchKey::Group(0)`.
    ///
    /// The group list is not injected any more: opening the scan through the actor is what puts
    /// it in RAM, which is also the real sequence — the list is installed while the database is
    /// healthy, and only then does a read fail.
    fn app_watching_group(
        db: &Path,
        scan_id: i64,
    ) -> (
        App,
        crossbeam_channel::Receiver<crate::tui::event::AppEvent>,
    ) {
        let (mut app, events) = app_over_watched_db(db, scan_id, "/tank/a.bin");
        assert_eq!(
            app.commander.group_summaries.len(),
            1,
            "the open must have installed the fixture's one group"
        );
        app.commander.panels[0].view = PanelView::GroupList;
        app.commander.panels[0].list.select(Some(0));
        app.commander.panels[1].view = PanelView::GroupFiles;
        (app, events)
    }

    /// A commander whose watching panel resolves `WatchKey::DupOf("/tank/a.bin")`.
    fn app_watching_file(
        db: &Path,
        scan_id: i64,
    ) -> (
        App,
        crossbeam_channel::Receiver<crate::tui::event::AppEvent>,
    ) {
        let (mut app, events) = app_over_watched_db(db, scan_id, "/tank/a.bin");
        app.commander.panels[0].entries = vec![panel_entry("/tank/a.bin", EntryKind::File)];
        app.commander.panels[0].list.select(Some(0));
        (app, events)
    }

    /// Renames a column away, so the exact statement that reads it fails for real.
    fn break_column(db: &Path, table: &str, column: &str) {
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute_batch(&format!(
            "ALTER TABLE {table} RENAME COLUMN {column} TO {column}_gone"
        ))
        .unwrap();
    }

    /// The whole R4-C0 contract for one sink: file subject, a concrete detail, cached, no result
    /// and no empty reason left standing.
    fn assert_file_unavailable(app: &App, expect_detail: &str) {
        let entry = watch_entry(app);
        let failure = entry.unavailable.as_ref().unwrap_or_else(|| {
            panic!(
                "a store failure is not an empty state: empty={:?}, result={:?}",
                entry.empty, entry.result
            )
        });
        assert_eq!(
            failure.subject,
            state::WatchSubject::FileGroup,
            "a file-key failure must not call itself a directory one"
        );
        assert!(
            failure.detail.contains(expect_detail),
            "the concrete error is preserved: {}",
            failure.detail
        );
        assert!(entry.result.is_none(), "no group is claimed");
        assert_eq!(
            entry.empty,
            state::WatchEmpty::NoSource,
            "no empty reason survives beside a failure"
        );
    }

    /// Sink 2 — `Group`, failed member read. Only that statement joins `file_mark`.
    #[test]
    fn a_failed_group_member_read_is_visible() {
        let (db, scan_id) = file_group_db("grp_files");
        let (mut app, events) = app_watching_group(&db, scan_id);
        break_column(&db, "file_mark", "is_keeper");
        resolve_and_settle(&mut app, &events);
        assert_file_unavailable(&app, "is_keeper");
    }

    /// Sink 3 — `Group`, failed claim read. Only that statement reads `file_group`.
    #[test]
    fn a_failed_group_claim_read_is_visible() {
        let (db, scan_id) = file_group_db("grp_claim");
        let (mut app, events) = app_watching_group(&db, scan_id);
        break_column(&db, "file_group", "reclaim");
        resolve_and_settle(&mut app, &events);
        assert_file_unavailable(&app, "reclaim");
    }

    /// Sink 4 — `DupOf`, failed cursor-hash read, the first read of the branch.
    #[test]
    fn a_failed_cursor_hash_read_is_visible() {
        let (db, scan_id) = file_group_db("dup_hash");
        let (mut app, events) = app_watching_file(&db, scan_id);
        break_column(&db, "file", "hash");
        resolve_and_settle(&mut app, &events);
        assert_file_unavailable(&app, "hash");
    }

    /// Sink 5 — `DupOf`, failed claim read, after a successful hash read.
    #[test]
    fn a_failed_cursor_claim_read_is_visible() {
        let (db, scan_id) = file_group_db("dup_claim");
        let (mut app, events) = app_watching_file(&db, scan_id);
        break_column(&db, "file_group", "reclaim");
        resolve_and_settle(&mut app, &events);
        assert_file_unavailable(&app, "reclaim");
    }

    /// Sink 6 — `DupOf`, failed member read, after hash and claim both succeeded.
    #[test]
    fn a_failed_cursor_member_read_is_visible() {
        let (db, scan_id) = file_group_db("dup_files");
        let (mut app, events) = app_watching_file(&db, scan_id);
        break_column(&db, "file_mark", "is_keeper");
        resolve_and_settle(&mut app, &events);
        assert_file_unavailable(&app, "is_keeper");
    }

    /// The legitimate absences keep their own meanings: `Ok(None)` is not a failure, and nothing
    /// about them may acquire an unavailable state.
    #[test]
    fn legitimate_absences_keep_their_own_meaning() {
        // A hashed file that belongs to no published group → NoDuplicates.
        let (db, scan_id) = file_group_db("ok_none_claim");
        let (mut app, events) = app_watching_file(&db, scan_id);
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute("DELETE FROM file_group WHERE scan_id = ?1", [scan_id])
            .unwrap();
        drop(conn);
        re_resolve(&mut app, &events);
        let entry = watch_entry(&app);
        assert!(entry.unavailable.is_none(), "an absence is not a failure");
        assert_eq!(entry.empty, state::WatchEmpty::NoDuplicates);

        // A path with no manifest row at all → NotInScan.
        let (db2, scan_id2) = file_group_db("ok_none_hash");
        let (mut app2, events2) = app_over_watched_db(&db2, scan_id2, "/tank/a.bin");
        app2.commander.panels[0].entries = vec![panel_entry("/tank/missing.bin", EntryKind::File)];
        app2.commander.panels[0].list.select(Some(0));
        resolve_and_settle(&mut app2, &events2);
        let entry2 = watch_entry(&app2);
        assert!(entry2.unavailable.is_none(), "an absence is not a failure");
        assert_eq!(entry2.empty, state::WatchEmpty::NotInScan);
    }

    /// The unavailable state survives a re-resolve of the same key: it is cached like any other
    /// answer, so the panel does not flicker back to a clean empty message.
    #[test]
    fn a_file_failure_stays_cached_across_a_re_resolve() {
        let (db, scan_id) = file_group_db("cached");
        let (mut app, events) = app_watching_file(&db, scan_id);
        break_column(&db, "file_mark", "is_keeper");
        resolve_and_settle(&mut app, &events);
        assert_file_unavailable(&app, "is_keeper");
        re_resolve(&mut app, &events);
        assert_file_unavailable(&app, "is_keeper");
    }

    /// What the operator actually reads, at the widest and at the supported floor: the complete
    /// subject phrase, never truncated away, and never the directory wording.
    #[test]
    fn a_file_failure_names_its_subject_at_every_supported_width() {
        let (db, scan_id) = file_group_db("render_file");
        let (mut app, events) = app_watching_file(&db, scan_id);
        break_column(&db, "file_mark", "is_keeper");
        resolve_and_settle(&mut app, &events);

        let (wide_lines, wide_width) = render_watch_panel_at(&mut app, 120);
        assert_eq!(wide_width, 60, "two panels across 120 columns");
        let wide = wide_lines.join("\n");
        assert!(
            wide.contains("file group unavailable:"),
            "the panel names what failed: {wide}"
        );
        assert!(
            !wide.contains("directory group unavailable"),
            "a file failure must not borrow the directory wording: {wide}"
        );
        for forbidden in ["no dupes at the cursor", "out of scan", "no scan data"] {
            assert!(
                !wide.contains(forbidden),
                "a failure must not read as «{forbidden}»: {wide}"
            );
        }

        let (narrow_lines, narrow_width) = render_watch_panel_at(&mut app, 72);
        assert_eq!(
            narrow_width,
            layout::MIN_PANEL_WIDTH,
            "72 columns is exactly two panels at the supported floor"
        );
        let narrow = narrow_lines.join("\n");
        assert!(
            narrow.contains("file group unavailable:"),
            "the subject survives the floor whole — `unavailable` is never truncated: {narrow}"
        );
    }
}
