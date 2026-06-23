// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use std::collections::HashMap;

use crate::app::{App, PathStyle};
use crate::model::action::ActionKind;
use crate::model::duplicate::{DirGroup, DuplicateGroup};
use crate::state::{DirGroupSummary, GroupSummary};
use crate::tui::human_bytes;

/// Active browser tab: `Files` —
/// groups of identical files "by payoff", `Dirs` — groups of twin folders.
/// Switching — the `1` (Folders) / `2` (Files) keys, or a mouse click on the tab
/// in the left panel's title.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrowserTab {
    #[default]
    Files,
    Dirs,
}

/// Duplicate-browsing screen: a groups panel + a files panel. The header is as in
/// (brand + ` Duplicates ` in the frame title); the `[1] Folders` /
/// `[2] Files` tabs are embedded in the left panel's title.
pub fn render(frame: &mut Frame, app: &mut App) {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(4),
    ])
    .split(frame.area());

    // The header is as in a brand stripe `bg=Blue, fg=White, BOLD` in the title +
    // ` Duplicates ` without a fill. The header content is dynamic per tab:
    // on `[2] Files` — file statistics, on `[1] Folders` — dir statistics
    // (the group count and "Will free" are their own; "Scanned" and "Marked" are shared,
    // from the scan, not the tab).
    let title = Line::from(vec![
        Span::styled(
            format!(" DedupCommando v{} ", crate::version()),
            Style::new()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Duplicates "),
    ]);
    let header_text = match app.browser.tab {
        BrowserTab::Files => format!(
            " Groups: {}   Scanned: {}   Will free: {}   Marked: {} ",
            app.browser.group_summaries.len(),
            app.browser.summary.files_scanned,
            human_bytes(app.browser.reclaim_total),
            app.browser.marked_count,
        ),
        BrowserTab::Dirs => format!(
            " Groups: {}   Scanned: {}   Will free: {}   Marked: {} ",
            app.browser.dir_group_summaries.len(),
            app.browser.summary.files_scanned,
            human_bytes(app.browser.dir_groups_reclaim_total),
            app.browser.marked_count,
        ),
    };
    let header = Paragraph::new(Line::from(header_text))
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(header, rows[0]);

    // The left panel — a fixed width of 52; the right one stretches to fit.
    let panes = Layout::horizontal([Constraint::Length(52), Constraint::Min(0)]).split(rows[1]);

    // We remember each panel's visible row height —
    // browser_page (PgUp/PgDn) computes the page step from this number, browser_end
    // knows which index to scroll to. -2 for the frame. And the Rects themselves — for
    // mapping a mouse click in `App::browser_mouse_click`.
    app.browser.group_visible_rows = panes[0].height.saturating_sub(2);
    app.browser.files_visible_rows = panes[1].height.saturating_sub(2);
    app.browser.groups_area = Some(panes[0]);
    app.browser.files_area = Some(panes[1]);

    // The coordinates of the `[1] Folders` / `[2] Files` tabs
    // in the top border of the left panel — for mouse clicks. The title is drawn in
    // `panes[0]` with offset 1 (after `┌`); the spans in `groups_panel_title` come
    // sequentially. The prefix ` Groups ` = 8 chars → `[1] Folders` starts
    // at `panes[0].x + 1 + 8 = +9`. The length of `[1] Folders` = 11 chars + 1 space
    // → `[2] Files` starts at `+21`.
    app.browser.tab_dirs_area = Some(Rect {
        x: panes[0].x.saturating_add(9),
        y: panes[0].y,
        width: 11,
        height: 1,
    });
    app.browser.tab_files_area = Some(Rect {
        x: panes[0].x.saturating_add(21),
        y: panes[0].y,
        width: 9,
        height: 1,
    });

    match app.browser.tab {
        BrowserTab::Files => render_files_tab(frame, panes, app),
        BrowserTab::Dirs => render_dirs_tab(frame, panes, app),
    }

    let footer = "1=Folders 2=Files · Tab · ↑↓/PgUp·PgDn/g·G · LMB·wheel · Enter=keeper · d/h/c=mark · Space=unmark · a=auto · v=view · r=review · ?=help";
    crate::tui::render_footer(frame, rows[2], &app.status, footer);
}

/// Title of the browser's left panel with embedded tabs:
/// `Groups [1] Folders [2] Files (by payoff)`. The active tab — `BOLD`,
/// the inactive one — `DIM`. No colors. The tab coordinates for mouse clicks are
/// fixed (see `render`).
fn groups_panel_title(active: BrowserTab) -> Line<'static> {
    let style_active = Style::new().add_modifier(Modifier::BOLD);
    let style_dim = Style::new().add_modifier(Modifier::DIM);
    Line::from(vec![
        Span::raw(" Groups "),
        Span::styled(
            "[1] Folders",
            if active == BrowserTab::Dirs {
                style_active
            } else {
                style_dim
            },
        ),
        Span::raw(" "),
        Span::styled(
            "[2] Files",
            if active == BrowserTab::Files {
                style_active
            } else {
                style_dim
            },
        ),
        Span::raw(" (by payoff) "),
    ])
}

/// Renders the panels of the `[2] Files` tab.
fn render_files_tab(frame: &mut Frame, panes: std::rc::Rc<[ratatui::layout::Rect]>, app: &mut App) {
    render_group_list(
        frame,
        panes[0],
        &app.browser.group_summaries,
        &mut app.browser.group_state,
        !app.browser.focus_files,
        groups_panel_title(BrowserTab::Files),
    );

    // Right panel title: ` Group files · view: {path_style} `. Without the counter
    // `{shown}/{total}` and the `↓ load more` indicator (user feedback: a
    // counter here was never wanted). The lazy-loading
    // mechanism itself (`maybe_load_more_files`) works, the title just doesn't reflect it.
    let path_style = app.browser.path_style;
    let files_title = format!(" Group files · view: {} ", path_style.label());
    render_group_files(
        frame,
        panes[1],
        app.browser.open_group.as_ref(),
        &app.browser.open_group_colors,
        &mut app.browser.file_state,
        path_style,
        app.browser.focus_files,
        &files_title,
    );
}

/// Renders the panels of the `[1] Folders` tab.
fn render_dirs_tab(frame: &mut Frame, panes: std::rc::Rc<[ratatui::layout::Rect]>, app: &mut App) {
    render_dir_group_summary_list(
        frame,
        panes[0],
        &app.browser.dir_group_summaries,
        &mut app.browser.dir_group_state,
        !app.browser.focus_files,
        groups_panel_title(BrowserTab::Dirs),
    );

    // Right panel title: ` Group folders ` without counters.
    render_dir_group_files_with_keeper(
        frame,
        panes[1],
        app.browser.open_dir_group.as_ref(),
        app.browser.dir_keeper_index,
        &mut app.browser.dir_file_state,
        app.browser.focus_files,
        " Group folders ",
    );
}

/// PgUp/PgDn page step in the browser: `visible_rows - 1`
/// entries in the `delta_pages` direction — "a page of what you see" (classic
/// two-panel file managers). Fallback 20 when `visible_rows == 0` (there hasn't been
/// a first frame yet after opening the browser). Minimum step 1, otherwise on a tiny window
/// a PgDn press would do nothing.
pub(crate) fn page_step(visible_rows: u16, delta_pages: i32) -> i32 {
    let effective = if visible_rows == 0 { 20 } else { visible_rows };
    let step = (effective.saturating_sub(1) as i32).max(1);
    step * delta_pages
}

/// Step of the visual separators in the browser lists:
/// every `SEPARATOR_EVERY` entries a ` N -------…` line is inserted
/// (see `separator_line`), helping the user gauge their position in a long list.
/// The separator is purely visual, not selectable by the cursor.
pub(crate) const SEPARATOR_EVERY: usize = 25;

/// Separator text: `<N> <----...>` (1-based entry number, a space, dashes to
/// the right edge — WITHOUT a leading indent, so the number is visible as an ordinary
/// column). `inner_width` — the panel's inner width (without the frame). If the prefix
/// is longer than the width — no dashes are added.
pub(crate) fn separator_text(global_pos: usize, inner_width: usize) -> String {
    let prefix = format!("{global_pos} ");
    let dashes = inner_width.saturating_sub(prefix.chars().count());
    format!("{prefix}{}", "-".repeat(dashes))
}

/// Separator line as a ListItem (DarkGray) — a wrapper over `separator_text`.
pub(crate) fn separator_line(global_pos: usize, inner_width: usize) -> ListItem<'static> {
    ListItem::new(separator_text(global_pos, inner_width)).style(Style::new().fg(Color::DarkGray))
}

/// Reverse mapping of a visual index → the real entry index (for mouse
/// clicks): we walk from `start` over the real indices, for
/// each accounting for a separator after `(idx+1) % SEPARATOR_EVERY == 0 && idx+1 < total`.
/// If the visual row landed on a separator — we return `None` (a click on
/// a separator does not select). If the row is outside the list — also `None`.
pub(crate) fn visual_to_real_index(start: usize, visual_row: usize, total: usize) -> Option<usize> {
    let mut visual = 0usize;
    let mut idx = start;
    while idx < total {
        if visual == visual_row {
            return Some(idx);
        }
        visual += 1;
        let next_global = idx + 1;
        if next_global % SEPARATOR_EVERY == 0 && next_global < total {
            if visual == visual_row {
                return None; // the click landed on a separator line
            }
            visual += 1;
        }
        idx += 1;
    }
    None
}

/// How many separators lie INSIDE the window `[start, cursor)` — for recomputing
/// `local_sel` under virtualization. A separator is inserted
/// AFTER the entry with index `i`, where `(i+1) % SEPARATOR_EVERY == 0` and
/// `i+1 < total`; in this helper the `<total` check isn't needed — `cursor`
/// is already `< total` by the caller's contract.
pub(crate) fn separators_before_cursor(start: usize, cursor: usize) -> usize {
    if cursor <= start {
        return 0;
    }
    (start..cursor)
        .filter(|i| (i + 1) % SEPARATOR_EVERY == 0)
        .count()
}

/// Builds a `Vec<ListItem>` from the slice `items_iter` over indices `start..end` plus
/// separators every `SEPARATOR_EVERY` entries (after indices `25k-1`, except
/// the very last entry of the list). Shared by group_list / group_files / dir_*.
fn items_with_separators<'a, T, F>(
    start: usize,
    end: usize,
    total: usize,
    inner_width: usize,
    source: &'a [T],
    mut make_item: F,
) -> Vec<ListItem<'a>>
where
    F: FnMut(&'a T) -> ListItem<'a>,
{
    let mut out: Vec<ListItem<'a>> = Vec::with_capacity(end - start);
    for (idx, item) in source.iter().enumerate().take(end).skip(start) {
        out.push(make_item(item));
        let next_global = idx + 1;
        if next_global % SEPARATOR_EVERY == 0 && next_global < total {
            out.push(separator_line(next_global, inner_width));
        }
    }
    out
}

/// Draws the list of duplicate groups — reused by the
/// Browser screen and the commander panels in GroupList mode. Separators every 25 are NOT
/// drawn (user feedback 2026-05-28: in the group-summary list `#N` already gives
/// global numbering — separators are redundant; they're only needed in the window with
/// concrete file paths, where there's no `#`).
pub(crate) fn render_group_list(
    frame: &mut Frame,
    area: Rect,
    groups: &[GroupSummary],
    state: &mut ListState,
    focused: bool,
    title: Line<'static>,
) {
    // Virtualization: we build ListItems only for the visible window — on /tank hundreds
    // of thousands of groups would otherwise be formatted every frame and the UI starves for input.
    let rows = (area.height as usize).saturating_sub(2);
    let (start, local_sel) = crate::tui::visible_window(state, groups.len(), rows);
    let end = (start + rows).min(groups.len());
    let items: Vec<ListItem> = groups[start..end]
        .iter()
        .map(|group| {
            ListItem::new(format!(
                "#{:<4} {} files · {} · free {}",
                group.rank,
                group.file_count,
                human_bytes(group.size_bytes),
                human_bytes(group.reclaim_bytes),
            ))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(focus_style(focused)),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut local = ListState::default();
    local.select(local_sel);
    frame.render_stateful_widget(list, area, &mut local);
}

/// Draws the file list of group `group` — reused by the
/// Browser screen and the commander panels (GroupFiles / DuplicatesOfCursor).
#[allow(clippy::too_many_arguments)] // render function: 8 list-drawing parameters
pub(crate) fn render_group_files(
    frame: &mut Frame,
    area: Rect,
    group: Option<&DuplicateGroup>,
    name_colors: &HashMap<String, Color>,
    state: &mut ListState,
    path_style: PathStyle,
    focused: bool,
    title: &str,
) {
    // Virtualization: we build ListItems ONLY for the visible window. On /tank the top
    // "by payoff" groups are tens of thousands of files; building them all + O(N²) name_palette on
    // EVERY frame starved input (freeze per move). Mirror of render_group_list (browser.rs:76).
    let rows = (area.height as usize).saturating_sub(2);
    let inner_width = (area.width as usize).saturating_sub(2);
    let (local_sel, file_items, window_start): (Option<usize>, Vec<ListItem>, usize) = match group {
        Some(group) => {
            let (start, local_sel) = crate::tui::visible_window(state, group.files.len(), rows);
            let end = (start + rows).min(group.files.len());
            let keeper = group.files.iter().find(|file| file.is_keeper);
            let items = items_with_separators(
                start,
                end,
                group.files.len(),
                inner_width,
                &group.files,
                |file| {
                    let hardlinked = !file.is_keeper
                        && keeper
                            .map(|keeper| file.same_physical(keeper))
                            .unwrap_or(false);
                    let (prefix, prefix_color) = if file.is_keeper {
                        ("★ ", Color::Green)
                    } else if hardlinked {
                        ("= ", Color::DarkGray)
                    } else {
                        match file.action {
                            Some(ActionKind::Delete) => ("x ", Color::Red),
                            Some(ActionKind::Hardlink) => ("h ", Color::Cyan),
                            Some(ActionKind::Reflink) => ("c ", Color::Cyan),
                            None => ("  ", Color::Reset),
                        }
                    };
                    let (suffix, suffix_color) = if file.is_keeper {
                        ("  (keeper)".to_string(), Color::Green)
                    } else if hardlinked {
                        ("  (already linked — 0 payoff)".to_string(), Color::DarkGray)
                    } else if let Some(kind) = file.action {
                        let color = match kind {
                            ActionKind::Delete => Color::Red,
                            ActionKind::Hardlink | ActionKind::Reflink => Color::Cyan,
                        };
                        (format!("  -> {}", kind.label()), color)
                    } else {
                        (String::new(), Color::Reset)
                    };

                    let path = file.path.display().to_string();
                    let (_, name) = split_path(&path);
                    let name_color = name_colors.get(name).copied();

                    let mut spans: Vec<Span<'static>> = Vec::new();
                    spans.push(Span::styled(
                        prefix,
                        Style::new().fg(prefix_color).add_modifier(Modifier::BOLD),
                    ));
                    spans.extend(path_spans(&path, path_style, name_color));
                    if !suffix.is_empty() {
                        spans.push(Span::styled(suffix, Style::new().fg(suffix_color)));
                    }

                    let line = Line::from(spans);
                    if hardlinked {
                        ListItem::new(line).style(Style::new().add_modifier(Modifier::DIM))
                    } else {
                        ListItem::new(line)
                    }
                },
            );
            (local_sel, items, start)
        }
        None => {
            *state.offset_mut() = 0;
            (None, Vec::new(), 0)
        }
    };
    let list = List::new(file_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string())
                .border_style(focus_style(focused)),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut local = ListState::default();
    local.select(
        local_sel.map(|sel| sel + separators_before_cursor(window_start, window_start + sel)),
    );
    frame.render_stateful_widget(list, area, &mut local);
}

/// Draws the list of duplicate-directory groups — for the
/// commander panel in DirGroupList mode (summaries from the commander's DB cache).
pub(crate) fn render_dir_group_list(
    frame: &mut Frame,
    area: Rect,
    groups: &[DirGroup],
    state: &mut ListState,
    focused: bool,
    title: &str,
) {
    // Virtualization — as in render_group_list. Separators every 25 are
    // NOT drawn: the dir-group list is the same summaries with `#N`, separators are redundant.
    let rows = (area.height as usize).saturating_sub(2);
    let (start, local_sel) = crate::tui::visible_window(state, groups.len(), rows);
    let end = (start + rows).min(groups.len());
    let items: Vec<ListItem> = groups[start..end]
        .iter()
        .map(|group| {
            ListItem::new(format!(
                "#{:<4} {} directories · {} files · {} · free {}",
                group.id,
                group.paths.len(),
                group.file_count,
                human_bytes(group.size_per_dir),
                human_bytes(group.reclaimable_bytes()),
            ))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string())
                .border_style(focus_style(focused)),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut local = ListState::default();
    local.select(local_sel);
    frame.render_stateful_widget(list, area, &mut local);
}

/// Draws the directory paths of group `group` — for the commander panel
/// in DirGroupFiles mode. The first directory is marked as the "keeper" (★).
pub(crate) fn render_dir_group_files(
    frame: &mut Frame,
    area: Rect,
    group: Option<&DirGroup>,
    state: &mut ListState,
    focused: bool,
    title: &str,
) {
    let items: Vec<ListItem> = match group {
        Some(group) => group
            .paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let (prefix, color) = if index == 0 {
                    ("★ ", Color::Green)
                } else {
                    ("  ", Color::Reset)
                };
                let line = Line::from(vec![
                    Span::styled(prefix, Style::new().fg(color).add_modifier(Modifier::BOLD)),
                    Span::raw(path.display().to_string()),
                ]);
                ListItem::new(line)
            })
            .collect(),
        None => Vec::new(),
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string())
                .border_style(focus_style(focused)),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, area, state);
}

/// Draws the list of dir-group summaries for the browser
/// `[2] Directories` tab. Analogous to `render_group_list`, but reads `DirGroupSummary`
/// (without `paths` in RAM) — on /tank there can be several thousand dir-groups, but we're
/// consistent with the file tab: the left panel holds only summaries, paths are read on
/// entering the group (`store::dir_group_paths`). Without separators every 25
/// (per user feedback 2026-05-28).
pub(crate) fn render_dir_group_summary_list(
    frame: &mut Frame,
    area: Rect,
    groups: &[DirGroupSummary],
    state: &mut ListState,
    focused: bool,
    title: Line<'static>,
) {
    // Virtualization — as in `render_group_list`.
    let rows = (area.height as usize).saturating_sub(2);
    let (start, local_sel) = crate::tui::visible_window(state, groups.len(), rows);
    let end = (start + rows).min(groups.len());
    let items: Vec<ListItem> = groups[start..end]
        .iter()
        .map(|group| {
            ListItem::new(format!(
                "#{:<4} {} dirs · {} files · free {}",
                group.rank,
                group.dir_count,
                group.file_count,
                human_bytes(group.reclaim_bytes()),
            ))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(focus_style(focused)),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut local = ListState::default();
    local.select(local_sel);
    frame.render_stateful_widget(list, area, &mut local);
}

/// Draws the directory paths of a group with a configurable
/// `keeper_index` (★ versus the fixed 0 in `render_dir_group_files` —
/// which remains for the commander DirGroupFiles, so as not to break its UX).
pub(crate) fn render_dir_group_files_with_keeper(
    frame: &mut Frame,
    area: Rect,
    group: Option<&DirGroup>,
    keeper_index: usize,
    state: &mut ListState,
    focused: bool,
    title: &str,
) {
    let items: Vec<ListItem> = match group {
        Some(group) => group
            .paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let is_keeper = index == keeper_index;
                let (prefix, color, suffix, suffix_color) = if is_keeper {
                    ("★ ", Color::Green, "  (keeper)".to_string(), Color::Green)
                } else {
                    ("  ", Color::Reset, String::new(), Color::Reset)
                };
                let mut spans: Vec<Span<'static>> = vec![
                    Span::styled(prefix, Style::new().fg(color).add_modifier(Modifier::BOLD)),
                    Span::raw(path.display().to_string()),
                ];
                if !suffix.is_empty() {
                    spans.push(Span::styled(suffix, Style::new().fg(suffix_color)));
                }
                ListItem::new(Line::from(spans))
            })
            .collect(),
        None => Vec::new(),
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string())
                .border_style(focus_style(focused)),
        )
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, area, state);
}

fn focus_style(focused: bool) -> Style {
    if focused {
        Style::new().fg(Color::Cyan)
    } else {
        Style::new()
    }
}

/// Splits a path into the directory (with a trailing `/`) and the file name.
fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(index) => (&path[..=index], &path[index + 1..]),
        None => ("", path),
    }
}

/// Path spans for the "Group files" panel according to the selected mode.
fn path_spans(path: &str, style: PathStyle, name_color: Option<Color>) -> Vec<Span<'static>> {
    let (dir, name) = split_path(path);
    let dim = Style::new().fg(Color::DarkGray);
    let name_style = match name_color {
        Some(color) => Style::new().fg(color).add_modifier(Modifier::BOLD),
        None => Style::new().add_modifier(Modifier::BOLD),
    };
    match style {
        PathStyle::DimDir => vec![
            Span::styled(dir.to_string(), dim),
            Span::styled(name.to_string(), name_style),
        ],
        PathStyle::NameFirst => vec![
            Span::styled(name.to_string(), name_style),
            Span::styled("  ·  ", dim),
            Span::styled(dir.trim_end_matches('/').to_string(), dim),
        ],
        PathStyle::TreeGraded => {
            const PALETTE: [Color; 4] = [Color::Cyan, Color::Blue, Color::Green, Color::Magenta];
            let mut spans: Vec<Span<'static>> = Vec::new();
            let mut depth = 0usize;
            let mut start = 0usize;
            for (index, ch) in dir.char_indices() {
                if ch == '/' {
                    if start < index {
                        spans.push(Span::styled(
                            dir[start..index].to_string(),
                            Style::new().fg(PALETTE[depth % PALETTE.len()]),
                        ));
                        depth += 1;
                    }
                    spans.push(Span::styled("/", dim));
                    start = index + 1;
                }
            }
            spans.push(Span::styled(name.to_string(), name_style));
            spans
        }
    }
}

/// A "file name → color" map for a group. Empty if all names match —
/// then the name is drawn bright by default. O(N): dedup via a HashMap, not
/// `Vec::any` in a loop. Computed ONCE when the group loads (Browser caches it in
/// `BrowserState::open_group_colors`), rendering only reads — it doesn't recompute per frame.
pub(crate) fn name_palette(group: &DuplicateGroup) -> HashMap<String, Color> {
    const PALETTE: [Color; 5] = [
        Color::Yellow,
        Color::Magenta,
        Color::Cyan,
        Color::Green,
        Color::Blue,
    ];
    // The color is assigned in the order of the name's FIRST appearance (as before): the index = the current
    // map size at the moment of insertion.
    let mut colors: HashMap<String, Color> = HashMap::new();
    for file in &group.files {
        let path = file.path.display().to_string();
        let (_, name) = split_path(&path);
        if !colors.contains_key(name) {
            let color = PALETTE[colors.len() % PALETTE.len()];
            colors.insert(name.to_string(), color);
        }
    }
    if colors.len() < 2 {
        return HashMap::new();
    }
    colors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::duplicate::FileEntry;
    use std::path::PathBuf;

    fn group_with_names(names: &[&str]) -> DuplicateGroup {
        DuplicateGroup {
            id: 0,
            size_bytes: 100,
            hash: "h".into(),
            files: names
                .iter()
                .enumerate()
                .map(|(n, name)| FileEntry {
                    path: PathBuf::from(format!("/dir{n}/{name}")),
                    size: 100,
                    mtime: 0,
                    device: 0,
                    inode: n as u64,
                    is_keeper: false,
                    action: None,
                })
                .collect(),
        }
    }

    #[test]
    fn name_palette_empty_when_all_names_equal() {
        // The same name in different directories → nothing to color.
        let group = group_with_names(&["backup.tar", "backup.tar", "backup.tar"]);
        assert!(name_palette(&group).is_empty());
    }

    #[test]
    fn name_palette_colors_by_first_appearance() {
        // Three distinct names → colors in order of first appearance (like the old O(N²) path).
        let group = group_with_names(&["a", "b", "a", "c"]);
        let palette = name_palette(&group);
        assert_eq!(palette.len(), 3, "three distinct names");
        assert_eq!(palette.get("a"), Some(&Color::Yellow));
        assert_eq!(palette.get("b"), Some(&Color::Magenta));
        assert_eq!(palette.get("c"), Some(&Color::Cyan));
    }

    // ---- Separators every 25 ----

    #[test]
    fn separator_text_starts_with_number_then_dashes_to_width() {
        // Inner width 20: "25 " (3 chars) → 17 dashes. WITHOUT a leading indent
        // (user feedback 2026-05-28): the number right at the left edge, like a column.
        assert_eq!(separator_text(25, 20), "25 -----------------");
        // Narrow panel: prefix longer than the width → 0 dashes (no panic, edge case).
        assert_eq!(separator_text(100, 3), "100 ");
    }

    #[test]
    fn separators_before_cursor_zero_in_first_block() {
        // Cursor within the first block of 25 — there are no separators before it.
        assert_eq!(separators_before_cursor(0, 0), 0);
        assert_eq!(separators_before_cursor(0, 24), 0);
    }

    #[test]
    fn separators_before_cursor_counts_each_25_crossed() {
        // At index 24 (the 25th entry) the separator is AFTER — before cursor=25 it already exists.
        assert_eq!(separators_before_cursor(0, 25), 1);
        assert_eq!(separators_before_cursor(0, 49), 1);
        assert_eq!(separators_before_cursor(0, 50), 2);
        // start>0: separators INSIDE the window — at indices 24,49,...,
        // if start=10, cursor=30 → only idx=24 falls in → 1 separator.
        assert_eq!(separators_before_cursor(10, 30), 1);
        // The window starts AFTER the first separator — we count nothing until the second.
        assert_eq!(separators_before_cursor(26, 48), 0);
        assert_eq!(separators_before_cursor(26, 50), 1);
    }

    #[test]
    fn items_with_separators_inserts_after_each_25th_except_last() {
        // A simple array of 60 elements — separators are expected after positions 25 and 50.
        let data: Vec<u32> = (0..60).collect();
        let items = items_with_separators(0, 60, 60, 50, &data, |&_| ListItem::new("x"));
        // 60 elements + 2 separators (after the 25th and 50th; the 60th is last, without one).
        assert_eq!(items.len(), 62);
    }

    #[test]
    fn items_with_separators_skips_separator_when_25th_is_last() {
        // Exactly 25 elements: the 25th is the last entry of the list, there is NO separator.
        let data: Vec<u32> = (0..25).collect();
        let items = items_with_separators(0, 25, 25, 50, &data, |&_| ListItem::new("x"));
        assert_eq!(items.len(), 25);
    }

    #[test]
    fn items_with_separators_in_offset_window_inserts_only_relevant() {
        // 100 elements, window [20..40): crosses index 24 → 1 separator.
        let data: Vec<u32> = (0..100).collect();
        let items = items_with_separators(20, 40, 100, 50, &data, |&_| ListItem::new("x"));
        assert_eq!(items.len(), 21); // 20 elements + 1 separator.
    }

    // ---- page_step (PgUp/PgDn in browser) ----

    #[test]
    fn page_step_uses_visible_rows_minus_one() {
        // visible_rows=10 → step 9 ("a page of what you see", as in classic
        // two-panel shells).
        assert_eq!(page_step(10, 1), 9);
        assert_eq!(page_step(10, -1), -9);
        assert_eq!(page_step(25, 2), 48);
    }

    #[test]
    fn page_step_falls_back_to_20_when_zero_rows() {
        // visible_rows=0 (there hasn't been a first frame yet) → fallback 20 → step 19.
        assert_eq!(page_step(0, 1), 19);
        assert_eq!(page_step(0, -1), -19);
    }

    #[test]
    fn page_step_clamps_to_at_least_one_on_tiny_window() {
        // visible_rows=1 → step 1, not 0. Otherwise PgDn on a tiny window would be a no-op.
        assert_eq!(page_step(1, 1), 1);
        assert_eq!(page_step(2, 1), 1);
        assert_eq!(page_step(1, -1), -1);
    }

    // ---- visual_to_real_index (mouse click) ----

    #[test]
    fn visual_to_real_index_simple_no_separators_in_window() {
        // Window from 0, 24 elements total — no separator appears (it would come after the 25th).
        assert_eq!(visual_to_real_index(0, 0, 24), Some(0));
        assert_eq!(visual_to_real_index(0, 23, 24), Some(23));
        // Beyond the list — None.
        assert_eq!(visual_to_real_index(0, 24, 24), None);
    }

    #[test]
    fn visual_to_real_index_skips_separator_after_25th() {
        // Large list — after the 25th (idx=24) comes a separator at visual=25.
        assert_eq!(visual_to_real_index(0, 24, 100), Some(24)); // 25th entry
        assert_eq!(visual_to_real_index(0, 25, 100), None); // separator
        assert_eq!(visual_to_real_index(0, 26, 100), Some(25)); // 26th entry
    }

    #[test]
    fn visual_to_real_index_handles_offset_start() {
        // The window starts at idx=20, the first separator is at visual=4.
        assert_eq!(visual_to_real_index(20, 0, 100), Some(20));
        assert_eq!(visual_to_real_index(20, 4, 100), Some(24));
        assert_eq!(visual_to_real_index(20, 5, 100), None); // separator after idx=24
        assert_eq!(visual_to_real_index(20, 6, 100), Some(25));
    }

    #[test]
    fn visual_to_real_index_no_separator_for_last_record() {
        // total=25 exactly — the 25th entry (idx=24) is the last, there is no separator.
        assert_eq!(visual_to_real_index(0, 24, 25), Some(24));
        // visual=25 is already outside the list.
        assert_eq!(visual_to_real_index(0, 25, 25), None);
    }
}
