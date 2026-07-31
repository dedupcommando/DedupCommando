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
use crate::state::{DirGroupSummary, GroupClaim, GroupSummary};
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
        // Four, not three: the reclaim statement gets its own line rather than being clipped off
        // the end of a counters row. What a figure means is not an optional part of it.
        Constraint::Length(4),
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
    // The file tab states the scan's own reclaim through the shared formatter; the folder tab
    // keeps its own arithmetic, which this change does not touch. `already linked sets` belongs to
    // the scan, so both tabs show it.
    let header_lines = match app.browser.tab {
        BrowserTab::Files => vec![
            format!(
                " Groups: {}   Scanned: {}   Marked: {} ",
                app.browser.group_summaries.len(),
                app.browser.summary.files_scanned,
                app.browser.marked_count,
            ),
            format!(
                " {}   already linked sets: {} ",
                crate::tui::reclaim_phrase(app.browser.summary.reclaim),
                app.browser.summary.already_linked_sets,
            ),
        ],
        BrowserTab::Dirs => vec![
            format!(
                " Groups: {}   Scanned: {}   Will free: {}   Marked: {} ",
                app.browser.dir_group_summaries.len(),
                app.browser.summary.files_scanned,
                human_bytes(app.browser.dir_groups_reclaim_total),
                app.browser.marked_count,
            ),
            format!(
                " already linked sets: {} ",
                app.browser.summary.already_linked_sets
            ),
        ],
    };
    let header = Paragraph::new(
        header_lines
            .into_iter()
            .map(Line::from)
            .collect::<Vec<Line>>(),
    )
    .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(header, rows[0]);

    // The left panel — a fixed width of 52; the right one stretches to fit.
    let panes = Layout::horizontal([Constraint::Length(52), Constraint::Min(0)]).split(rows[1]);

    // We remember each panel's visible row height —
    // browser_page (PgUp/PgDn) computes the page step from this number, browser_end
    // knows which index to scroll to. -2 for the frame. And the Rects themselves — for
    // mapping a mouse click in `App::browser_mouse_click`.
    // In entries, not terminal rows: a file group takes two rows, a folder group one, and PgUp/
    // PgDn steps by entries. Measuring this in rows would page twice as far on the Files tab.
    app.browser.group_visible_rows = match app.browser.tab {
        BrowserTab::Files => groups_that_fit(panes[0]) as u16,
        BrowserTab::Dirs => panes[0].height.saturating_sub(2),
    };
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
        app.browser.open_group_claim,
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

/// Indent that marks the reclaim claim as a continuation of the counters above it.
pub(crate) const CLAIM_INDENT: &str = "  ";

/// Columns a list panel spends before any item text: two borders and the highlight symbol, which
/// `List` reserves on every row whether or not the row is selected.
const LIST_CHROME: usize = 4;

/// The largest reclaim figure this program can be asked to display.
///
/// It is the persisted domain, not an environment: `file_group.reclaim` and
/// `scan_stats.reclaimable_bytes` are SQLite's signed integers, so every value through `i64::MAX`
/// is one the store accepts and hands back. A sparse file, or a row seeded straight into a valid
/// database, is not bounded by what a pool happens to hold today — reasoning from storage capacity
/// is how the previous constant came to be `1023 TiB`, one line short of `8388608.0 TiB`, and how
/// a 52-column panel came to drop the unit off the end of its own claim.
const WIDEST_FIGURE: u64 = i64::MAX as u64;

/// Columns the reclaim claim gets on a line of its own in a list panel this wide.
pub(crate) fn claim_columns(width: u16) -> usize {
    (width as usize).saturating_sub(LIST_CHROME + CLAIM_INDENT.len())
}

/// Terminal rows one entry of the file-group list occupies at this panel width: the counters, plus
/// however many lines the widest possible claim needs beneath them.
///
/// Width alone, never content. Every group in one rendered list is the same height, so a click at
/// row `n` maps to an entry without knowing what any row says — and two rows is not always enough:
/// an 80-column commander draws two panels of 40, where the exact claim does not fit on one line.
pub(crate) fn group_rows(width: u16) -> u16 {
    use crate::model::reclaim::ReclaimEstimate;
    let columns = claim_columns(width);
    // Every state at the widest figure the columns accept, not just the exact one: the reserve has
    // to hold whichever of them a row turns out to carry, and «the longest string must wrap into
    // the most lines» is an argument, not a measurement.
    let lines = [
        ReclaimEstimate::exact(WIDEST_FIGURE),
        ReclaimEstimate::upper_bound(WIDEST_FIGURE),
        ReclaimEstimate::unknown(),
    ]
    .into_iter()
    .map(|state| wrap_words(&crate::tui::reclaim_cell(state), columns).len())
    .max()
    .unwrap_or(1);
    1 + lines as u16
}

/// How many groups fit in a panel of this size — the borders, then `group_rows` each. At least
/// one, so a window too short to hold a whole entry still shows the selected one rather than
/// nothing.
pub(crate) fn groups_that_fit(area: Rect) -> usize {
    (area.height.saturating_sub(2) / group_rows(area.width)).max(1) as usize
}

/// Greedy word wrap. A word wider than the column count gets a line of its own and is left to the
/// terminal to clip — there is nothing better to do with it, and it cannot happen to the claim,
/// whose longest word is `quarantine`.
pub(crate) fn wrap_words(text: &str, columns: usize) -> Vec<String> {
    if columns == 0 {
        return vec![text.to_string()];
    }
    let mut lines: Vec<String> = Vec::new();
    for word in text.split(' ') {
        match lines.last_mut() {
            Some(line) if line.chars().count() + 1 + word.chars().count() <= columns => {
                line.push(' ');
                line.push_str(word);
            }
            _ => lines.push(word.to_string()),
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
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
    // Each group occupies `GROUP_ROWS` terminal rows, so the window is measured in groups, not in
    // rows; `ListState` counts items, which is why selection and paging stay group-based.
    let rows = groups_that_fit(area);
    let (start, local_sel) = crate::tui::visible_window(state, groups.len(), rows);
    let end = (start + rows).min(groups.len());
    // Every entry is the same height, whatever its own claim needs: the claim is wrapped into the
    // lines this width reserves and short ones are padded. A list whose rows varied in height
    // would make a click's meaning depend on what the rows above it happened to say.
    let claim_lines = group_rows(area.width).saturating_sub(1) as usize;
    let columns = claim_columns(area.width);
    let items: Vec<ListItem> = groups[start..end]
        .iter()
        .map(|group| {
            // The counters first: pathnames and allocations are different questions — «6 files»
            // is what the operator sees, «3 objects» is what the filesystem frees. The claim gets
            // the lines below to itself rather than being the thing that gets cut, because a
            // number whose qualifier fell off the right edge is the defect, not the layout.
            let mut lines = vec![Line::from(format!(
                "#{:<4} {} files · {} · {}",
                group.rank,
                group.file_count,
                crate::tui::objects_cell(group.object_count, group.reclaim),
                human_bytes(group.size_bytes),
            ))];
            let wrapped = wrap_words(&crate::tui::reclaim_cell(group.reclaim), columns);
            for index in 0..claim_lines {
                let text = wrapped.get(index).map(String::as_str).unwrap_or("");
                lines.push(Line::from(Span::styled(
                    format!("{CLAIM_INDENT}{text}"),
                    Style::new().add_modifier(Modifier::DIM),
                )));
            }
            ListItem::new(lines)
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
#[allow(clippy::too_many_arguments)] // render function: 9 list-drawing parameters
pub(crate) fn render_group_files(
    frame: &mut Frame,
    area: Rect,
    group: Option<&DuplicateGroup>,
    claim: Option<GroupClaim>,
    name_colors: &HashMap<String, Color>,
    state: &mut ListState,
    path_style: PathStyle,
    focused: bool,
    title: &str,
) {
    // The block is drawn here rather than by the List, so the group's own claim gets a line inside
    // it. That line is the group's full statement — the list row next door has room for three
    // words, this one has room for what those three words mean.
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_string())
        .border_style(focus_style(focused));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let (claim_area, list_area) = match claim {
        Some(_) if inner.height > 1 => {
            let split = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);
            (Some(split[0]), split[1])
        }
        _ => (None, inner),
    };
    if let (Some(claim_area), Some(claim)) = (claim_area, claim) {
        frame.render_widget(
            Paragraph::new(Line::from(format!(
                "{} · {}",
                crate::tui::reclaim_phrase(claim.reclaim),
                crate::tui::links_phrase(claim.links)
            )))
            .style(Style::new().add_modifier(Modifier::DIM)),
            claim_area,
        );
    }

    // Virtualization: we build ListItems ONLY for the visible window. On /tank the top
    // "by payoff" groups are tens of thousands of files; building them all + O(N²) name_palette on
    // EVERY frame starved input (freeze per move). Mirror of render_group_list (browser.rs:76).
    let rows = list_area.height as usize;
    let inner_width = inner.width as usize;
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
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut local = ListState::default();
    local.select(
        local_sel.map(|sel| sel + separators_before_cursor(window_start, window_start + sel)),
    );
    frame.render_stateful_widget(list, list_area, &mut local);
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
pub(crate) mod tests {
    use super::*;
    use crate::model::duplicate::FileEntry;
    use crate::model::reclaim::{LinkCount, ReclaimEstimate};
    use crate::state::GroupLinks;
    use ratatui::{backend::TestBackend, Terminal};
    use std::path::PathBuf;

    /// Everything drawn into a fixed-size buffer, as one string.
    fn drawn(width: u16, height: u16, draw: impl FnOnce(&mut Frame)) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(draw).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    fn summary_row(rank: i64, reclaim: ReclaimEstimate) -> GroupSummary {
        GroupSummary {
            rank,
            hash: format!("h{rank}"),
            file_count: 3,
            size_bytes: 4096,
            object_count: 2,
            reclaim,
        }
    }

    /// The list row shows both counts and never labels a ceiling as freed. This is the row the
    /// classic browser and the commander's group panel both draw.
    #[test]
    fn a_group_row_shows_allocations_and_refuses_to_call_a_bound_free() {
        let groups = vec![
            summary_row(0, ReclaimEstimate::exact(4096)),
            summary_row(1, ReclaimEstimate::upper_bound(4096)),
            summary_row(2, ReclaimEstimate::unknown()),
        ];
        let mut state = ListState::default();
        let rendered = drawn(70, 10, |frame| {
            render_group_list(
                frame,
                frame.area(),
                &groups,
                &mut state,
                true,
                Line::from(" groups "),
            );
        });
        assert!(
            rendered.contains("3 files · 2 objects"),
            "pathnames and allocations are different questions: {rendered}"
        );
        assert!(
            rendered.contains("guaranteed after quarantine purge: 4.0 KiB"),
            "{rendered}"
        );
        assert!(
            rendered.contains("up to 4.0 KiB after quarantine purge"),
            "{rendered}"
        );
        assert!(rendered.contains("rescan required"), "{rendered}");
        assert!(
            !rendered.contains("free"),
            "nothing is free before the quarantine is purged: {rendered}"
        );
    }

    /// One entry of a rendered group list, as one normalised string: its own rows, its own
    /// columns, and nothing else.
    ///
    /// Row-local on purpose. A search over the whole rendered screen let a truncated row borrow
    /// the number it was missing from the row below it — the exact claim's absent `4.0 KiB` was
    /// satisfied by the upper-bound row underneath, and the test that was named «shows every claim
    /// in full» reported it as present.
    pub(crate) fn entry_text(
        buffer: &ratatui::buffer::Buffer,
        panel: Rect,
        entry: usize,
        rows: u16,
    ) -> String {
        let first = panel.y + 1 + entry as u16 * rows;
        let mut text = String::new();
        for y in first..(first + rows).min(panel.y + panel.height - 1) {
            for x in (panel.x + 1)..(panel.x + panel.width - 1) {
                text.push_str(buffer[(x, y)].symbol());
            }
            // A claim wrapped onto the next line is still one claim: joining the entry's rows with
            // a single space is what lets the whole string be asserted as a substring.
            text.push(' ');
        }
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// One group list drawn into a frame of exactly this size.
    fn drawn_list(area: Rect, groups: &[GroupSummary]) -> ratatui::buffer::Buffer {
        let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
        let mut list = ListState::default();
        terminal
            .draw(|frame| {
                render_group_list(
                    frame,
                    frame.area(),
                    groups,
                    &mut list,
                    true,
                    Line::from(" groups "),
                );
            })
            .unwrap();
        terminal.backend().buffer().clone()
    }

    /// The same, for a list rendered into the whole frame.
    fn drawn_entry(width: u16, entry: usize, groups: &[GroupSummary]) -> String {
        let area = Rect::new(0, 0, width, 12);
        entry_text(&drawn_list(area, groups), area, entry, group_rows(width))
    }

    /// Every entry of one list, each read from its own rows. The frame is made tall enough for the
    /// whole fixture, so a case cannot pass by being scrolled out of the window instead of drawn.
    pub(crate) fn drawn_entries(width: u16, groups: &[GroupSummary]) -> Vec<String> {
        let rows = group_rows(width);
        let area = Rect::new(0, 0, width, 2 + rows * groups.len() as u16);
        let buffer = drawn_list(area, groups);
        (0..groups.len())
            .map(|entry| entry_text(&buffer, area, entry, rows))
            .collect()
    }

    /// The claims a row can carry, at a figure the caller chooses.
    pub(crate) fn claims_of(bytes: u64) -> [(&'static str, ReclaimEstimate, String); 3] {
        [
            (
                "exact",
                ReclaimEstimate::exact(bytes),
                crate::tui::reclaim_cell(ReclaimEstimate::exact(bytes)),
            ),
            (
                "upper bound",
                ReclaimEstimate::upper_bound(bytes),
                crate::tui::reclaim_cell(ReclaimEstimate::upper_bound(bytes)),
            ),
            (
                "unknown",
                ReclaimEstimate::unknown(),
                crate::tui::reclaim_cell(ReclaimEstimate::unknown()),
            ),
        ]
    }

    /// The panel the classic browser draws is 52 columns wide whatever the terminal is, and two
    /// panels of an 80-column commander are 40. The qualifier has to survive BOTH together with
    /// its number — hiding it past the right edge would be the same lie in a different place.
    #[test]
    fn the_post_purge_qualifier_survives_every_panel_width_in_use() {
        for width in [52, 40, 36] {
            for (name, state, claim) in claims_of(4096) {
                let text = drawn_entry(width, 0, &[summary_row(0, state)]);
                assert!(
                    text.contains(&claim),
                    "the {name} claim must read in full at {width} columns: {text}"
                );
            }
        }
    }

    /// The figure the persisted columns really accept, in the panel that reserves the fewest
    /// lines. `8388608.0 TiB` is what `i64::MAX` prints as, and its unit used to fall off the end.
    #[test]
    fn the_largest_persisted_figure_reads_in_full_at_every_width() {
        let widest = i64::MAX as u64;
        assert_eq!(
            crate::tui::human_bytes(widest),
            "8388608.0 TiB",
            "the domain's widest figure, as the formatter prints it"
        );
        for width in [52, 40, 36] {
            for (name, state, claim) in claims_of(widest) {
                let text = drawn_entry(width, 0, &[summary_row(0, state)]);
                assert!(
                    text.contains(&claim),
                    "the {name} claim at the persisted maximum must read in full at {width}                      columns: {text}"
                );
            }
        }
    }

    /// A group row whose counts and claim are chosen per case.
    fn counted_row(
        rank: i64,
        file_count: u64,
        object_count: u64,
        size_bytes: u64,
        reclaim: ReclaimEstimate,
    ) -> GroupSummary {
        GroupSummary {
            rank,
            hash: format!("h{rank}"),
            file_count,
            size_bytes,
            object_count,
            reclaim,
        }
    }

    /// The four rows the count wording has to tell apart, with every number distinct: a row that
    /// lost its own text cannot be rescued by a neighbour's. `object_count == 0` is the migrated
    /// sentinel only where nothing about the row is established — the second row has a real count
    /// and an untrusted figure, and keeps its number.
    fn count_cases() -> [(&'static str, GroupSummary, &'static str); 4] {
        [
            (
                "migrated legacy",
                counted_row(0, 3, 0, 4096, ReclaimEstimate::unknown()),
                "? objects",
            ),
            (
                "unknown with a recorded count",
                counted_row(1, 7, 5, 8192, ReclaimEstimate::unknown()),
                "5 objects",
            ),
            (
                "exact",
                counted_row(2, 9, 2, 12288, ReclaimEstimate::exact(12288)),
                "2 objects",
            ),
            (
                "upper bound",
                counted_row(
                    3,
                    6,
                    4,
                    16384,
                    ReclaimEstimate::upper_bound(9 * 1024 * 1024),
                ),
                "4 objects",
            ),
        ]
    }

    /// `object_count == 0` on a migrated row means the allocations were never counted, and a
    /// browseable duplicate group cannot hold none — so the row says the count is missing rather
    /// than printing a zero the operator would read as a measurement. Every row that does have a
    /// count still prints it, and the rest of the row is untouched.
    #[test]
    fn a_migrated_group_counts_its_objects_as_unknown_and_the_rest_keep_theirs() {
        let cases = count_cases();
        let groups: Vec<GroupSummary> = cases.iter().map(|(_, row, _)| row.clone()).collect();
        for width in [52, 40] {
            let entries = drawn_entries(width, &groups);
            for (entry, (name, group, phrase)) in cases.iter().enumerate() {
                let text = &entries[entry];
                assert!(
                    text.contains(*phrase),
                    "the {name} row must count its allocations as «{phrase}» at {width} columns: {text}"
                );
                assert!(
                    !text.contains("0 objects"),
                    "no browseable duplicate group holds zero allocations ({name}, {width} columns): {text}"
                );
                // The rest of the row is the point of the wording: the claim, the size and the
                // pathname count all have to survive the phrase that replaced the number.
                let claim = crate::tui::reclaim_cell(group.reclaim);
                assert!(
                    text.contains(&claim),
                    "the {name} row must still state «{claim}» at {width} columns: {text}"
                );
                assert!(
                    text.contains(&human_bytes(group.size_bytes)),
                    "the {name} row must still show its size at {width} columns: {text}"
                );
                assert!(
                    text.contains(&format!("{} files", group.file_count)),
                    "the {name} row must still show its pathnames at {width} columns: {text}"
                );
            }
        }
    }

    /// The counters line is cut at the panel edge, not wrapped, so the missing count is worded to
    /// occupy exactly the columns the number it replaces would have. `objects unknown` costs six
    /// more: rendered on this fixture it cuts the size to `4.` at 40 columns, and at 36 takes the
    /// size and its separator off the row altogether.
    #[test]
    fn the_unknown_count_costs_no_more_columns_than_the_number_it_replaces() {
        let legacy = counted_row(0, 3, 0, 4096, ReclaimEstimate::unknown());
        let counted = counted_row(0, 3, 7, 4096, ReclaimEstimate::unknown());
        for width in [52, 40, 36] {
            let sentinel = drawn_entries(width, std::slice::from_ref(&legacy));
            let known = drawn_entries(width, std::slice::from_ref(&counted));
            let (sentinel, known) = (&sentinel[0], &known[0]);
            assert!(
                sentinel.contains("? objects"),
                "the sentinel row at {width} columns: {sentinel}"
            );
            assert_eq!(
                sentinel.chars().count(),
                known.chars().count(),
                "the missing count must occupy the columns «7 objects» would at {width} columns: {sentinel} / {known}"
            );
        }
    }

    /// The height rule is a function of the panel width and nothing else — the same for every row
    /// of a list, so a click at a given row means one thing however the rows above it read. And it
    /// has to hold over the whole byte domain, not over the figures a test happened to pick.
    #[test]
    fn the_entry_height_holds_every_claim_at_every_width_in_use() {
        assert_eq!(
            [group_rows(36), group_rows(40), group_rows(52)],
            [3, 3, 3],
            "the persisted maximum wraps onto a second claim line at all three widths"
        );
        assert_eq!(
            group_rows(96),
            2,
            "a panel wide enough for the widest claim spends one line on it"
        );
        // Boundaries of `human_bytes` plus the ends of the domain: every state at every width must
        // fit the lines that width reserves.
        let figures = [
            0,
            1,
            1023,
            1024,
            1024 * 1024 - 1,
            1024 * 1024,
            1023 * 1024 * 1024 * 1024,
            1u64 << 40,
            (1u64 << 40) + 1,
            i64::MAX as u64 - 1,
            i64::MAX as u64,
        ];
        for width in [36, 40, 52, 96] {
            let reserved = group_rows(width) - 1;
            for bytes in figures {
                for (name, _, claim) in claims_of(bytes) {
                    let lines = wrap_words(&claim, claim_columns(width)).len() as u16;
                    assert!(
                        lines <= reserved,
                        "{name} of {bytes} needs {lines} lines at {width} columns,                          {reserved} reserved: {claim}"
                    );
                }
            }
        }
    }

    /// The window is measured in groups, so a panel tall enough for four rows shows one whole
    /// group, not two half-drawn ones — and paging steps by the same number.
    #[test]
    fn the_group_window_counts_groups_not_terminal_rows() {
        let wide = |height| Rect::new(0, 0, 52, height);
        assert_eq!(group_rows(52), 3, "the rule these numbers follow");
        assert_eq!(groups_that_fit(wide(5)), 1, "5 rows: 2 borders, 1 group");
        assert_eq!(groups_that_fit(wide(11)), 3);
        assert_eq!(
            groups_that_fit(wide(3)),
            1,
            "a window too short for a whole entry still shows the selected one"
        );
        assert_eq!(groups_that_fit(wide(0)), 1);
        // A wider panel spends fewer lines on each claim, so the same height holds more groups.
        assert_eq!(groups_that_fit(Rect::new(0, 0, 96, 11)), 4);
    }

    /// Word wrapping is what keeps the claim complete; a word that cannot fit is left whole rather
    /// than broken in the middle.
    #[test]
    fn wrapping_breaks_on_spaces_only() {
        assert_eq!(wrap_words("a bb ccc", 6), vec!["a bb", "ccc"]);
        assert_eq!(wrap_words("quarantine", 4), vec!["quarantine"]);
        assert_eq!(wrap_words("", 10), vec![""]);
        assert_eq!(wrap_words("x y", 0), vec!["x y"], "no width, no wrapping");
    }

    /// The open group states its own claim in full, with the link evidence behind it — the same
    /// panel the commander draws for GroupFiles and DuplicatesOfCursor.
    #[test]
    fn an_open_group_states_its_claim_and_the_links_behind_it() {
        let group = group_with_names(&["a.bin", "b.bin"]);
        let claim = crate::state::GroupClaim {
            reclaim: ReclaimEstimate::upper_bound(4096),
            links: GroupLinks {
                observed: 2,
                total: LinkCount::Known(3),
            },
        };
        let colors = HashMap::new();
        let mut state = ListState::default();
        let rendered = drawn(100, 8, |frame| {
            render_group_files(
                frame,
                frame.area(),
                Some(&group),
                Some(claim),
                &colors,
                &mut state,
                PathStyle::NameFirst,
                true,
                " Group files ",
            );
        });
        assert!(
            rendered.contains("guaranteed after quarantine purge: 0 B"),
            "{rendered}"
        );
        assert!(
            rendered.contains("up to 4.0 KiB after quarantine purge"),
            "{rendered}"
        );
        assert!(rendered.contains("links seen 2/3"), "{rendered}");
        assert!(
            rendered.contains("a.bin") && rendered.contains("b.bin"),
            "the claim line must not cost the panel its files: {rendered}"
        );
    }

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
                    inode: n as u64,
                    nlink: 1,
                    ..Default::default()
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
