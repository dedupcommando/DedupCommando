// SPDX-License-Identifier: Apache-2.0
//! Rendering of a single commander panel.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::PathStyle;
use crate::model::duplicate::DirGroup;
use crate::state::GroupSummary;
use crate::tui::human_bytes_parts;
use crate::tui::screens::browser;

use super::dedup::{DedupStatus, DirDedup};
use super::state::{
    EntryKind, Mark, Panel, PanelEntry, PanelView, WatchEmpty, WatchEntry, WatchResult,
};

/// Info about a neighboring panel's file for side-by-side comparison.
/// Map key — the file name; value — what we compare content against.
pub struct ComparePeer {
    pub size: u64,
    pub mtime: i64,
    pub hash: Option<String>,
}

/// Draws panel `panel` (numbered `index`) in area `area`.
/// `source` carries BOTH the result AND the reason for emptiness — render can
/// distinguish "no source" / "out of scan #N" / "no dupes"; `scan_id` (optional) goes
/// into the "#N" label when the result is empty due to NotInScan.
#[allow(clippy::too_many_arguments)]
pub fn render_panel(
    frame: &mut Frame,
    area: Rect,
    panel: &mut Panel,
    dedup: Option<&DirDedup>,
    cross: &HashSet<String>,
    dir_sizes: &HashMap<PathBuf, u64>,
    group_summaries: &[GroupSummary],
    dir_groups: &[DirGroup],
    source: Option<&WatchEntry>,
    source_dir_group: Option<&DirGroup>,
    compare_peer: Option<&HashMap<String, ComparePeer>>,
    scan_id: Option<i64>,
    index: usize,
    focused: bool,
    label: Option<&str>,
) {
    let source_result = source.and_then(|e| e.result.as_ref());
    let source_empty = source.map(|e| e.empty).unwrap_or_default();
    let border = if focused {
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let title_width = area.width.saturating_sub(24) as usize;
    // Title: for Board — the passed label (source/receiver), otherwise the panel
    // number of the old commander.
    let head = match label {
        Some(text) => text.to_string(),
        None => (index + 1).to_string(),
    };
    let mut title_spans = vec![Span::raw(format!(
        " {} · {} · {} ",
        head,
        ellipsize_left(&panel.cwd.display().to_string(), title_width),
        panel.sort.label(),
    ))];
    // Confidence percentage: share of files with a known hash.
    if let Some(percent) = confidence_percent(panel, dedup) {
        let color = if percent < 30 {
            Color::Red
        } else if percent < 80 {
            Color::Yellow
        } else {
            Color::Green
        };
        title_spans.push(Span::styled(
            format!("· conf {percent}% "),
            Style::new().fg(color),
        ));
    }
    // Side-by-side: share of files matching the neighboring panel.
    if let Some(peer) = compare_peer {
        if let Some(percent) = compare_match_percent(panel, peer, dedup) {
            title_spans.push(Span::styled(
                format!("· match {percent}% "),
                Style::new().fg(Color::Cyan),
            ));
        }
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Line::from(title_spans));

    // Directory is still being read in the background — placeholder instead of the list.
    if panel.loading {
        let para = Paragraph::new("  loading…")
            .style(Style::new().fg(Color::DarkGray))
            .block(block);
        frame.render_widget(para, area);
        return;
    }

    // Group modes are drawn by reusable functions of the Browser screen.
    match panel.view {
        PanelView::Files | PanelView::DirsOnly => {}
        PanelView::GroupList => {
            if group_summaries.is_empty() {
                // Fallback via the unified helper — title with the mode, not cwd.
                render_view_fallback(
                    frame,
                    area,
                    border,
                    index,
                    panel.view,
                    "no scan data — run a scan (F2)",
                );
            } else {
                let title = format!(" {} · groups (by savings) ", index + 1);
                browser::render_group_list(
                    frame,
                    area,
                    group_summaries,
                    &mut panel.list,
                    focused,
                    ratatui::text::Line::from(title),
                );
            }
            return;
        }
        PanelView::GroupFiles | PanelView::DuplicatesOfCursor => {
            // GroupFiles always shows a FileGroup. DuplicatesOfCursor — a dispatcher
            // over WatchResult: FileGroup for the cursor file, DirGroup for
            // a twin directory, InnerDupes — fallback for a directory WITHOUT a twin.
            // When there's no result — a targeted message keyed by empty.
            let title = format!(" {} · {} ", index + 1, panel.view.label());
            match (panel.view, source_result) {
                (_, Some(WatchResult::FileGroup(group))) => {
                    let colors = browser::name_palette(group);
                    browser::render_group_files(
                        frame,
                        area,
                        Some(group),
                        &colors,
                        &mut panel.list,
                        PathStyle::NameFirst,
                        focused,
                        &title,
                    );
                }
                (PanelView::DuplicatesOfCursor, Some(WatchResult::DirGroup(group))) => {
                    browser::render_dir_group_files(
                        frame,
                        area,
                        Some(group),
                        &mut panel.list,
                        focused,
                        &title,
                    );
                }
                (PanelView::DuplicatesOfCursor, Some(WatchResult::InnerDupes(paths))) => {
                    render_inner_dupes(frame, area, paths, &mut panel.list, focused, &title);
                }
                (panel_view, _) => {
                    let message: String = if matches!(panel_view, PanelView::GroupFiles) {
                        group_files_empty_message(source_empty).to_string()
                    } else {
                        duplicates_of_cursor_empty_message(source_empty, scan_id)
                    };
                    render_view_fallback(frame, area, border, index, panel_view, &message);
                }
            }
            return;
        }
        PanelView::DirGroupList => {
            if dir_groups.is_empty() {
                render_view_fallback(
                    frame,
                    area,
                    border,
                    index,
                    panel.view,
                    "no directory groups — run a scan (F2)",
                );
            } else {
                let title = format!(" {} · directory groups (by savings) ", index + 1);
                browser::render_dir_group_list(
                    frame,
                    area,
                    dir_groups,
                    &mut panel.list,
                    focused,
                    &title,
                );
            }
            return;
        }
        PanelView::DirGroupFiles => {
            match source_dir_group {
                Some(group) => {
                    let title = format!(" {} · directories of group ", index + 1);
                    browser::render_dir_group_files(
                        frame,
                        area,
                        Some(group),
                        &mut panel.list,
                        focused,
                        &title,
                    );
                }
                None => {
                    render_view_fallback(
                        frame,
                        area,
                        border,
                        index,
                        panel.view,
                        "no source — need a «directory groups» panel on the left",
                    );
                }
            }
            return;
        }
    }

    let inner_width = area.width.saturating_sub(2);
    // Virtualization: we process/format only the visible entries — on a
    // directory with tens of thousands of files it would otherwise be O(n) per frame
    // (panel freeze). At the same time we skip expensive dedup lookups for invisible rows.
    let rows = (area.height as usize).saturating_sub(2);
    let (start, local_sel) = crate::tui::visible_window(&mut panel.list, panel.entries.len(), rows);
    let end = (start + rows).min(panel.entries.len());
    let items: Vec<ListItem> = panel.entries[start..end]
        .iter()
        .map(|entry| {
            let status = if matches!(entry.kind, EntryKind::File) {
                dedup.map_or(DedupStatus::NotInScan, |d| d.status_for(&entry.path))
            } else {
                DedupStatus::NotInScan
            };
            let mark = panel.marks.get(&entry.path).copied();
            // Cross-panel match: for a file — by hash, for a directory —
            // by content signature.
            let is_cross = match entry.kind {
                EntryKind::File => dedup
                    .and_then(|d| d.hash_for(&entry.path))
                    .map(|hash| cross.contains(hash))
                    .unwrap_or(false),
                EntryKind::Dir => dedup
                    .and_then(|d| d.dir_signature(&entry.path))
                    .map(|sig| cross.contains(sig))
                    .unwrap_or(false),
                EntryKind::Parent => false,
            };
            // Directory size: the background computation takes priority over the scan overlay
            // (the background one runs only for directories not covered by a scan, or via F6).
            let dir_size = dir_sizes
                .get(&entry.path)
                .copied()
                .or_else(|| dedup.and_then(|d| d.dir_size(&entry.path)));
            // Comparison glyph against the neighboring panel — only in
            // SideBySide mode (when the neighbor's map is passed).
            let compare_mark = compare_peer.map(|peer| compare_glyph(entry, peer, dedup));
            let item = ListItem::new(entry_line(
                entry,
                inner_width,
                status,
                mark,
                is_cross,
                dir_size,
                compare_mark,
            ));
            if is_cross {
                item.style(Style::new().fg(Color::Black).bg(Color::Yellow))
            } else {
                item
            }
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    let mut local = ListState::default();
    local.select(local_sel);
    frame.render_stateful_widget(list, area, &mut local);
}

/// Builds an entry row: mark, name, size, date, dedup status.
fn entry_line(
    entry: &PanelEntry,
    width: u16,
    status: DedupStatus,
    mark: Option<Mark>,
    is_cross: bool,
    dir_size: Option<u64>,
    compare_mark: Option<(char, Color)>,
) -> Line<'static> {
    let width = width as usize;
    let size_col = 10usize;
    let date_col = 10usize;
    let ext_col = 5usize;
    // Comparison column: space + glyph — reserved for all
    // panel rows while SideBySide mode is on, otherwise width 0.
    let compare_w = if compare_mark.is_some() { 2 } else { 0 };
    // mark(1) space name space ext space size space date space status(1)
    let fixed = 1 + 1 + 1 + ext_col + 1 + size_col + 1 + date_col + 1 + 1 + compare_w;
    let name_col = width.saturating_sub(fixed).max(4);

    let (mark_glyph, mark_color) = match mark {
        Some(mark) => (mark.glyph(), mark_color_for(mark)),
        None => (' ', Color::Reset),
    };

    // Name and extension — as separate columns.
    let (display_name, extension) = match entry.kind {
        EntryKind::File => match entry.name.rsplit_once('.') {
            // Non-empty stem — otherwise it's a dot-file (.bashrc), not an extension.
            Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), ext.to_string()),
            _ => (entry.name.clone(), String::new()),
        },
        EntryKind::Dir => (format!("{}/", entry.name), String::new()),
        EntryKind::Parent => (entry.name.clone(), String::new()),
    };
    let name = fit(&display_name, name_col);
    let extension = fit(&extension, ext_col);

    // Size: number and unit in fixed fields — digits under digits,
    // units under units.
    let size_text = match entry.kind {
        EntryKind::Parent => String::new(),
        EntryKind::Dir => match dir_size {
            Some(bytes) => size_cell(bytes),
            None => "<DIR>".to_string(),
        },
        EntryKind::File => size_cell(entry.size),
    };
    let date_text = if entry.mtime > 0 {
        short_date(entry.mtime)
    } else {
        String::new()
    };

    let name_color = if is_cross {
        Color::Black
    } else {
        name_color_for(entry, status, mark)
    };
    let aux_color = if is_cross {
        Color::Black
    } else {
        Color::DarkGray
    };
    let status_color = if is_cross {
        Color::Black
    } else {
        status_color_for(status)
    };

    let mut name_style = Style::new().fg(name_color);
    if entry.is_dir() {
        name_style = name_style.add_modifier(Modifier::BOLD);
    } else if matches!(status, DedupStatus::Unhashed) && !is_cross {
        name_style = name_style.add_modifier(Modifier::DIM);
    }

    let status_glyph = if matches!(entry.kind, EntryKind::File) {
        status.glyph()
    } else {
        ' '
    };

    let mut spans = vec![
        Span::styled(
            mark_glyph.to_string(),
            Style::new().fg(mark_color).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(format!("{name:<name_col$}"), name_style),
        Span::raw(" "),
        Span::styled(format!("{extension:<ext_col$}"), Style::new().fg(aux_color)),
        Span::raw(" "),
        Span::styled(
            format!("{size_text:>size_col$}"),
            Style::new().fg(aux_color),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{date_text:>date_col$}"),
            Style::new().fg(aux_color),
        ),
        Span::raw(" "),
        Span::styled(status_glyph.to_string(), Style::new().fg(status_color)),
    ];
    if let Some((glyph, color)) = compare_mark {
        // On the cross-panel highlight (black on yellow) a colored glyph is unreadable —
        // we print it black, like the row's other columns.
        let color = if is_cross { Color::Black } else { color };
        spans.push(Span::raw(" "));
        spans.push(Span::styled(glyph.to_string(), Style::new().fg(color)));
    }
    Line::from(spans)
}

/// File name color by status and mark (the mark takes priority over the status).
fn name_color_for(entry: &PanelEntry, status: DedupStatus, mark: Option<Mark>) -> Color {
    if entry.is_dir() {
        return Color::Blue;
    }
    match mark {
        Some(Mark::Delete) => return Color::Red,
        Some(Mark::Hardlink) | Some(Mark::Reflink) => return Color::Cyan,
        Some(Mark::Keeper) | Some(Mark::Selected) => return Color::Green,
        None => {}
    }
    match status {
        DedupStatus::VerifiedDup => Color::Yellow,
        DedupStatus::DangerousDup => Color::Red,
        DedupStatus::LikelyDuplicate => Color::Rgb(255, 140, 0),
        DedupStatus::HashedUnique => Color::Gray,
        DedupStatus::Unhashed => Color::DarkGray,
        DedupStatus::NotInScan => Color::Reset,
    }
}

/// Mark glyph color.
fn mark_color_for(mark: Mark) -> Color {
    match mark {
        Mark::Delete => Color::Red,
        Mark::Hardlink | Mark::Reflink => Color::Cyan,
        Mark::Keeper | Mark::Selected => Color::Green,
    }
}

/// Share of panel files with a known hash (unique/dup) — the machine's
/// "confidence". `None` — the panel has no files.
fn confidence_percent(panel: &Panel, dedup: Option<&DirDedup>) -> Option<u8> {
    let mut files = 0u32;
    let mut hashed = 0u32;
    for entry in &panel.entries {
        if !matches!(entry.kind, EntryKind::File) {
            continue;
        }
        files += 1;
        let status = dedup.map_or(DedupStatus::NotInScan, |d| d.status_for(&entry.path));
        if matches!(
            status,
            DedupStatus::HashedUnique | DedupStatus::VerifiedDup | DedupStatus::DangerousDup
        ) {
            hashed += 1;
        }
    }
    (files > 0).then(|| (hashed * 100 / files) as u8)
}

/// Comparison glyph of file `entry` against the neighboring panel, diff comparison colors.
/// Non-files return an empty glyph — the column is reserved for alignment.
fn compare_glyph(
    entry: &PanelEntry,
    peer: &HashMap<String, ComparePeer>,
    dedup: Option<&DirDedup>,
) -> (char, Color) {
    if !matches!(entry.kind, EntryKind::File) {
        return (' ', Color::Reset);
    }
    let Some(other) = peer.get(&entry.name) else {
        // The name is absent in the neighboring panel — the file exists only here.
        return ('+', Color::Blue);
    };
    match (
        dedup.and_then(|d| d.hash_for(&entry.path)),
        other.hash.as_deref(),
    ) {
        // Both hashed — exact content comparison.
        (Some(a), Some(b)) if a == b => ('=', Color::Green),
        (Some(_), Some(_)) => ('~', Color::Yellow),
        // At least one not hashed — heuristic by size+mtime (like the F4 semaphore).
        _ if entry.size == other.size && entry.mtime == other.mtime => {
            ('≈', Color::Rgb(255, 140, 0))
        }
        _ => ('~', Color::Yellow),
    }
}

/// Share of panel files for which an identical (`=`) or similar (`≈`) file was
/// found in the neighboring panel. `None` — the panel has no files.
fn compare_match_percent(
    panel: &Panel,
    peer: &HashMap<String, ComparePeer>,
    dedup: Option<&DirDedup>,
) -> Option<u8> {
    let mut files = 0u32;
    let mut matched = 0u32;
    for entry in &panel.entries {
        if !matches!(entry.kind, EntryKind::File) {
            continue;
        }
        files += 1;
        if matches!(compare_glyph(entry, peer, dedup).0, '=' | '≈') {
            matched += 1;
        }
    }
    (files > 0).then(|| (matched * 100 / files) as u8)
}

/// Dedup status glyph color.
fn status_color_for(status: DedupStatus) -> Color {
    match status {
        DedupStatus::VerifiedDup => Color::Yellow,
        DedupStatus::DangerousDup => Color::Red,
        DedupStatus::LikelyDuplicate => Color::Rgb(255, 140, 0),
        DedupStatus::HashedUnique => Color::Gray,
        DedupStatus::Unhashed => Color::DarkGray,
        DedupStatus::NotInScan => Color::DarkGray,
    }
}

/// File date in YYYY-MM-DD format.
pub fn short_date(mtime: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(mtime, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d").to_string(),
        None => String::new(),
    }
}

/// Truncates a string to `width` characters, appending «…».
pub fn fit(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        text.to_string()
    } else if width == 0 {
        String::new()
    } else {
        let mut out: String = text.chars().take(width - 1).collect();
        out.push('…');
        out
    }
}

/// Truncates a string on the left to `width` characters (the right part of the path stays visible).
pub fn ellipsize_left(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        text.to_string()
    } else if width <= 1 {
        "…".to_string()
    } else {
        let tail: String = text.chars().skip(count - (width - 1)).collect();
        format!("…{tail}")
    }
}

/// Fixed-width size cell: number right-aligned in 6,
/// unit left-aligned in 3 — digits align by column, units under units.
fn size_cell(bytes: u64) -> String {
    let (num, unit) = human_bytes_parts(bytes);
    format!("{num:>6} {unit:<3}")
}

/// Unified panel fallback rendering in the mode views. Title — the mode
/// label (not cwd/sort: for an empty panel those are useless and confusing —
/// from the header the user understands "which mode am I in?"). Body — a targeted message from
/// the caller (see `duplicates_of_cursor_empty_message`/`group_files_empty_message`
/// or just a literal for GroupList/DirGroupList/DirGroupFiles).
fn render_view_fallback(
    frame: &mut Frame,
    area: Rect,
    border: Style,
    index: usize,
    view: PanelView,
    message: &str,
) {
    let title = format!(" {} · «{}» ", index + 1, view.label());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(title);
    let para = Paragraph::new(format!("  {message}"))
        .style(Style::new().fg(Color::DarkGray))
        .block(block);
    frame.render_widget(para, area);
}

/// Message for the `DuplicatesOfCursor` fallback keyed by the reason for emptiness —
/// distinguishes "no source" / "out of scan #N" / "no dupes". Before 6b everything
/// merged into a single message, which was misleading when the source and
/// the cursor exist, but under the cursor is a directory not covered by a scan.
pub(crate) fn duplicates_of_cursor_empty_message(
    empty: WatchEmpty,
    scan_id: Option<i64>,
) -> String {
    match empty {
        WatchEmpty::NoSource => {
            "no source — need a «files» or «directories» panel with a cursor on the left"
                .to_string()
        }
        WatchEmpty::NotInScan => match scan_id {
            Some(id) => format!("under the cursor — out of scan #{id}"),
            None => "under the cursor — no scan data".to_string(),
        },
        WatchEmpty::NoDuplicates => "no dupes at the cursor".to_string(),
    }
}

/// Same for `GroupFiles` — but there the source = the neighboring `GroupList`,
/// and the NotInScan/NoDuplicates variants are theoretical (the selected group's index
/// or its hash wasn't found — a synchronization glitch).
pub(crate) fn group_files_empty_message(empty: WatchEmpty) -> &'static str {
    match empty {
        WatchEmpty::NoSource => "no source — need a «groups» panel on the left",
        WatchEmpty::NotInScan => "group selected, but it's not in the scan",
        WatchEmpty::NoDuplicates => "group has no files",
    }
}

/// Renders the list of duplicate files inside the dir cursor (when the
/// directory has no twin, but inside there are files with dupes somewhere else in the scan).
fn render_inner_dupes(
    frame: &mut Frame,
    area: Rect,
    paths: &[PathBuf],
    state: &mut ratatui::widgets::ListState,
    focused: bool,
    title: &str,
) {
    use ratatui::widgets::{List, ListItem};
    let border = if focused {
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let title_with_hint = format!("{title}· dupes inside (no twin directory)");
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(title_with_hint);
    if paths.is_empty() {
        let para = Paragraph::new("  empty")
            .style(Style::new().fg(Color::DarkGray))
            .block(block);
        frame.render_widget(para, area);
        return;
    }
    let items: Vec<ListItem> = paths
        .iter()
        .map(|p| ListItem::new(format!("  {}", p.display())))
        .collect();
    let list = List::new(items)
        .block(block)
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, area, state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_of_cursor_no_source_says_what_is_missing() {
        // For NoSource we give a concrete hint "Files/DirsOnly on the left"
        // — not the generic "no source", from which the user went off to check the obvious.
        let msg = duplicates_of_cursor_empty_message(WatchEmpty::NoSource, Some(6));
        assert!(msg.contains("files"));
        assert!(msg.contains("directories"));
        // We do NOT mention the scan number for NoSource (no source → the scan is irrelevant).
        assert!(!msg.contains('#'));
    }

    #[test]
    fn duplicates_of_cursor_not_in_scan_names_scan_id() {
        // The main fix — on /tank the user saw the "no source" placeholder
        // when the directory wasn't covered by the active scan. Now the message is explicit and
        // includes the scan number.
        let msg = duplicates_of_cursor_empty_message(WatchEmpty::NotInScan, Some(6));
        assert!(msg.contains("out of scan"));
        assert!(msg.contains("#6"));
    }

    #[test]
    fn duplicates_of_cursor_not_in_scan_without_id_omits_hash() {
        // If there's no scan_id (None), we don't write "#None" — a softer wording.
        let msg = duplicates_of_cursor_empty_message(WatchEmpty::NotInScan, None);
        assert!(!msg.contains('#'));
        assert!(msg.contains("no scan data"));
    }

    #[test]
    fn duplicates_of_cursor_no_duplicates_is_short_positive() {
        // "in the scan, no dupes" — this is not an error but a normal result
        // (everything is unique). A short positive message, without the word "source".
        let msg = duplicates_of_cursor_empty_message(WatchEmpty::NoDuplicates, Some(6));
        assert!(msg.contains("no dupes"));
        assert!(!msg.contains("source"));
    }

    #[test]
    fn group_files_no_source_points_to_group_list() {
        // For GroupFiles the source is `GroupList` on the left, not Files.
        let msg = group_files_empty_message(WatchEmpty::NoSource);
        assert!(msg.contains("groups"));
        assert!(!msg.contains("file"));
    }

    #[test]
    fn group_files_messages_cover_all_empty_variants() {
        // Contract — every WatchEmpty variant has its own text
        // (the test catches "forgot to add a branch" when extending the enum).
        for variant in [
            WatchEmpty::NoSource,
            WatchEmpty::NotInScan,
            WatchEmpty::NoDuplicates,
        ] {
            assert!(!group_files_empty_message(variant).is_empty());
            assert!(!duplicates_of_cursor_empty_message(variant, Some(1)).is_empty());
        }
    }
}
