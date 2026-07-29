// SPDX-License-Identifier: Apache-2.0
//! Modal overlays of the commander — drawn on top of the panels.

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use super::panel::ellipsize_left;
use super::state::{ConfirmScroll, ConfirmTab, PlanDigest};
use crate::model::scan::ResumeInfo;
use crate::tui::{centered, human_bytes};

/// Draws the F9 dropdown menu; the cursor is on item `cursor`.
pub fn render_menu(frame: &mut Frame, cursor: usize, labels: &[&str]) {
    let width = labels
        .iter()
        .map(|label| label.chars().count())
        .max()
        .unwrap_or(20) as u16
        + 6;
    let height = labels.len() as u16 + 2;
    let area = centered(frame.area(), width, height);
    frame.render_widget(Clear, area);

    let items: Vec<ListItem> = labels
        .iter()
        .map(|label| ListItem::new(Line::from(format!("  {label}  "))))
        .collect();
    let mut state = ListState::default();
    state.select(Some(cursor.min(labels.len().saturating_sub(1))));

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Menu — F9 "))
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, area, &mut state);
}

/// Draws the F11 confirmation overlay with two tabs:
/// "Summary" (what and how much) and "Commands" (the plan's full shell-script).
pub fn render_confirm(
    frame: &mut Frame,
    files: usize,
    reclaim: u64,
    tab: ConfirmTab,
    script: &str,
    digest: &PlanDigest,
    scroll: &mut ConfirmScroll,
) {
    let tabs = Line::from(vec![
        Span::raw("  "),
        tab_span("Summary", matches!(tab, ConfirmTab::Summary)),
        Span::raw("  "),
        tab_span("Commands", matches!(tab, ConfirmTab::Commands)),
    ]);

    let (area, body, gaps, hint, title): (Rect, Vec<Line>, bool, Vec<Line>, String) = match tab {
        ConfirmTab::Summary => {
            let hint = vec![Line::from(SUMMARY_HINT)];
            // Borders, the tab strip and the key hint are never given up: a confirmation
            // whose [Y]/[N] line has fallen off the bottom is worse than one that says
            // less. The two blank separators go first, then the body sheds itself.
            let avail = frame.area().height as usize;
            let fixed = CHROME_FIXED + hint.len();
            let gaps = avail >= fixed + 2 + SUMMARY_MIN_BODY;
            let chrome = fixed + if gaps { 2 } else { 0 };
            let lines = summary_lines(files, reclaim, digest, avail.saturating_sub(chrome));
            let height = (lines.len() + chrome) as u16;
            let body: Vec<Line> = lines.into_iter().map(Line::from).collect();
            (
                centered(frame.area(), SUMMARY_WIDTH, height),
                body,
                gaps,
                hint,
                CONFIRM_TITLE.to_string(),
            )
        }
        ConfirmTab::Commands => {
            let avail = frame.area();
            let width = avail.width.saturating_sub(4).clamp(40, 110);
            // The box never exceeds the terminal — the old floor of 10 rows is what let the
            // key hint fall off a small window. Above the cap the script simply scrolls.
            let box_rows = avail.height.min(COMMANDS_MAX_ROWS);
            // The scrolling hint is the first thing to give up; the decision hint is not.
            let mut hint = vec![Line::from(COMMANDS_SCROLL_HINT), Line::from(COMMANDS_HINT)];
            while hint.len() > 1 && box_rows < (CHROME_FIXED + hint.len()) as u16 {
                hint.remove(0);
            }
            let fixed = (CHROME_FIXED + hint.len()) as u16;
            let gaps = box_rows >= fixed + 3;
            let chrome = fixed + if gaps { 2 } else { 0 };
            let body_rows = box_rows.saturating_sub(chrome);

            scroll.rows = body_rows;
            scroll.clamp();
            // Only the visible window is formatted: the script of a large plan is thousands
            // of lines and this overlay redraws on every frame.
            let body: Vec<Line> = script
                .lines()
                .skip(scroll.offset)
                .take(body_rows as usize)
                .map(|line| Line::from(format!(" {line}")))
                .collect();
            let title = match scroll.visible_range() {
                Some((first, last)) => {
                    format!("{CONFIRM_TITLE}· lines {first}-{last} of {} ", scroll.total)
                }
                None => format!("{CONFIRM_TITLE}· no script lines "),
            };
            (
                centered(avail, width, chrome + body_rows),
                body,
                gaps,
                hint,
                title,
            )
        }
    };

    frame.render_widget(Clear, area);
    let mut content = vec![tabs];
    if gaps {
        content.push(Line::from(""));
    }
    content.extend(body);
    if gaps {
        content.push(Line::from(""));
    }
    content.extend(hint);
    frame.render_widget(
        Paragraph::new(Text::from(content))
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

/// Box width of the Summary tab.
const SUMMARY_WIDTH: u16 = 66;

/// Overlay title; both tabs share the stem, Commands appends its line range.
const CONFIRM_TITLE: &str = " Confirmation — F11 ";

/// Rows every confirmation box spends before any hint line: two borders and the tab strip.
const CHROME_FIXED: usize = 3;

/// Key hint of the Summary tab.
const SUMMARY_HINT: &str = "  [Tab] tab  [S] save .sh  [Y] execute  [N]/[Esc] cancel";

/// Key hints of the Commands tab. The scrolling line is dropped before the decision line on a
/// window too small for both — the operator must always be able to read their way out.
const COMMANDS_SCROLL_HINT: &str = "  ↑↓ · PgUp/PgDn · Home/End — scroll";
const COMMANDS_HINT: &str =
    "  [Tab] tab  [S] save .sh (whole script)  [Y] execute  [N]/[Esc] cancel";

/// The Commands box stops growing here; beyond it the script scrolls.
const COMMANDS_MAX_ROWS: u16 = 44;

/// Body rows that survive every shrink — the count, the composition, and the admission of
/// what is not being shown. Below this the blank separators are dropped first.
const SUMMARY_MIN_BODY: usize = 3;

/// Width left for a path once `  ` + the padded action label have been printed.
const SUMMARY_PATH: usize = SUMMARY_WIDTH as usize - 2 - 12;

/// What the Summary body has given up so far, in the order it is given up.
#[derive(Debug, Clone, Copy)]
struct Shed {
    /// Quoted target paths still shown.
    samples: usize,
    /// Blank separators still shown.
    spacing: bool,
    /// The snapshot reassurance still shown.
    note: bool,
    /// The reclaim estimate still shown.
    size: bool,
}

impl Shed {
    fn new(samples: usize) -> Self {
        Self {
            samples,
            spacing: true,
            note: true,
            size: true,
        }
    }

    /// Gives up the next least-needed thing; `false` when only the essentials are left.
    fn shrink(&mut self) -> bool {
        if self.samples > 0 {
            self.samples -= 1;
        } else if self.spacing {
            self.spacing = false;
        } else if self.note {
            self.note = false;
        } else if self.size {
            self.size = false;
        } else {
            return false;
        }
        true
    }
}

/// Text of the Summary tab, shrunk to `max_rows`. Pure, so what the operator is told can be
/// asserted without a terminal.
///
/// The [Y]/[N] hint is not part of this body and is never shed — the operator has to be able
/// to read their way out of a confirmation they did not mean to open. What goes, in order:
/// the quoted paths, then the blank spacing, then the snapshot note, then the size estimate.
/// The count, the `By type` composition and «… and N more» are what remain.
fn summary_lines(files: usize, reclaim: u64, digest: &PlanDigest, max_rows: usize) -> Vec<String> {
    let mut shed = Shed::new(digest.samples.len());
    let mut lines = compose(files, reclaim, digest, shed);
    while lines.len() > max_rows && shed.shrink() {
        lines = compose(files, reclaim, digest, shed);
    }
    // Below the essentials there is nothing left to trade; cut rather than push the hint off.
    lines.truncate(max_rows);
    lines
}

/// The Summary body at one particular level of shedding.
fn compose(files: usize, reclaim: u64, digest: &PlanDigest, shed: Shed) -> Vec<String> {
    let mut lines = vec![format!("  Actions to be executed: {files}")];
    if !digest.counts.is_empty() {
        let by_kind: Vec<String> = digest
            .counts
            .iter()
            .map(|(kind, count)| format!("{} {count}", kind.label().to_lowercase()))
            .collect();
        lines.push(format!("  By type: {}", by_kind.join(" · ")));
    }
    if shed.size {
        lines.push(format!("  Approximately freed: {}", human_bytes(reclaim)));
    }

    let shown = digest.samples.len().min(shed.samples);
    if shown > 0 {
        if shed.spacing {
            lines.push(String::new());
        }
        for (kind, target) in digest.samples.iter().take(shown) {
            lines.push(format!(
                "  {:9} {}",
                kind.label(),
                ellipsize_left(&target.display().to_string(), SUMMARY_PATH),
            ));
        }
    }
    // Everything the plan holds that this screen is not showing by name.
    let unnamed = digest.hidden + (digest.samples.len() - shown);
    if unnamed > 0 {
        lines.push(format!("  … and {unnamed} more"));
    }

    if shed.note {
        if shed.spacing {
            lines.push(String::new());
        }
        lines.push("  A ZFS snapshot for rollback is created before changes.".to_string());
    }
    lines
}

/// Tab-label span of the confirmation overlay; the active one is inverted.
fn tab_span(label: &str, active: bool) -> Span<'static> {
    let text = format!(" {label} ");
    if active {
        Span::styled(
            text,
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(text, Style::new().fg(Color::DarkGray))
    }
}

/// Draws the F2 overlay: a summary by roots — an unfinished session and/or
/// the last completed scan with dates and progress — plus a recommendation and a choice.
pub fn render_resume_scan(
    frame: &mut Frame,
    root: &str,
    unfinished: Option<&ResumeInfo>,
    complete: Option<&ResumeInfo>,
) {
    let mut body = vec![Line::from(""), Line::from(format!("  Root: {root}"))];
    if let Some(u) = unfinished {
        // % by candidate volume — the same denominator as in the F12 list,
        // so both screens show the same progress for the same scan.
        let percent = u
            .cand_bytes_hashed
            .saturating_mul(100)
            .checked_div(u.cand_bytes_total)
            .unwrap_or(0)
            .min(100);
        body.push(Line::from(format!(
            "  Unfinished scan from {} · progress {percent}%",
            u.created_at
        )));
    }
    if let Some(c) = complete {
        body.push(Line::from(format!(
            "  Last completed from {} · files {} · frees {}",
            c.created_at,
            c.files_scanned,
            crate::tui::human_bytes(c.reclaimable_bytes),
        )));
    }
    body.push(Line::from(""));
    body.push(Line::from(format!(
        "  {}",
        resume_recommendation(unfinished, complete)
    )));
    body.push(Line::from(""));
    let mut opts: Vec<&str> = Vec::new();
    if unfinished.is_some() {
        opts.push("[R]/[Enter] resume");
    }
    if complete.is_some() {
        opts.push("[O] open completed");
    }
    opts.push("[N] new scan");
    opts.push("[Esc] cancel");
    body.push(Line::from(format!("  {}", opts.join(" · "))));

    let height = body.len() as u16 + 2;
    let area = centered(frame.area(), 74, height);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(Text::from(body)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Scan roots — F2 "),
        ),
        area,
    );
}

/// Recommendation for the F2 overlay — a pure function of the presence
/// of an unfinished/completed session and which is newer (by `created_at`;
/// the `%Y-%m-%d %H:%M:%S` format sorts lexicographically).
fn resume_recommendation(
    unfinished: Option<&ResumeInfo>,
    complete: Option<&ResumeInfo>,
) -> &'static str {
    match (unfinished, complete) {
        (Some(u), Some(c)) if u.created_at < c.created_at => {
            "Recommended: [O] open the completed one (current) or [N] new; [R] is usually not needed"
        }
        (Some(_), _) => "Recommended: [R] resume — hashes are inherited, the disk is barely read",
        (None, Some(_)) => "Recommended: [O] open results or [N] new scan",
        (None, None) => "",
    }
}

#[cfg(test)]
mod resume_tests {
    use super::resume_recommendation;
    use crate::model::scan::{ResumeInfo, ScanStatus};
    use std::path::PathBuf;

    fn info(created: &str, status: ScanStatus) -> ResumeInfo {
        ResumeInfo {
            scan_id: 1,
            created_at: created.to_string(),
            status,
            roots: vec![PathBuf::from("/x")],
            files_total: 10,
            files_hashed: 2,
            cand_bytes_total: 1000,
            cand_bytes_hashed: 200,
            files_scanned: 100,
            reclaimable_bytes: 4096,
        }
    }

    #[test]
    fn recommends_open_when_unfinished_older_than_complete() {
        let u = info("2026-05-01 10:00:00", ScanStatus::Hashing);
        let c = info("2026-05-02 10:00:00", ScanStatus::Complete);
        assert!(resume_recommendation(Some(&u), Some(&c)).contains("[O]"));
    }

    #[test]
    fn recommends_resume_when_unfinished_newest() {
        let u = info("2026-05-03 10:00:00", ScanStatus::Hashing);
        let c = info("2026-05-02 10:00:00", ScanStatus::Complete);
        assert!(resume_recommendation(Some(&u), Some(&c)).contains("[R]"));
    }

    #[test]
    fn recommends_open_or_new_when_only_complete() {
        let c = info("2026-05-02 10:00:00", ScanStatus::Complete);
        let r = resume_recommendation(None, Some(&c));
        assert!(r.contains("[O]") || r.contains("[N]"));
    }
}

/// Draws the file-info overlay (F3).
pub fn render_info(frame: &mut Frame, lines: &[String]) {
    let height = (lines.len() as u16 + 2).clamp(5, frame.area().height);
    let width = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(40)
        .clamp(40, 100) as u16
        + 4;
    let area = centered(frame.area(), width, height);
    frame.render_widget(Clear, area);
    let text: Vec<Line> = lines
        .iter()
        .map(|line| Line::from(format!(" {line}")))
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(text)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" File — F3 · Esc to close "),
        ),
        area,
    );
}

#[cfg(test)]
mod confirm_summary_tests {
    use super::*;
    use crate::model::action::{ActionKind, PlannedAction};
    use ratatui::{backend::TestBackend, Terminal};
    use std::path::PathBuf;

    fn digest_of(actions: &[(ActionKind, &str)]) -> PlanDigest {
        let plan: Vec<PlannedAction> = actions
            .iter()
            .map(|(kind, target)| PlannedAction {
                kind: *kind,
                target: PathBuf::from(target),
                keeper: PathBuf::from("/tank/keeper.bin"),
                target_device: 1,
                keeper_device: 1,
                size: 1024,
                expected_hash: String::new(),
            })
            .collect();
        PlanDigest::of(&plan)
    }

    /// The Summary body with room to spare — what a normal terminal shows.
    fn joined(digest: &PlanDigest, rows: usize) -> String {
        summary_lines(digest.samples.len() + digest.hidden, 1024, digest, rows).join("\n")
    }

    /// Everything actually painted by `render_confirm` on a `width`x`height` terminal.
    fn drawn(digest: &PlanDigest, width: u16, height: u16) -> String {
        let files = digest.samples.len() + digest.hidden;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut scroll = ConfirmScroll::default();
        terminal
            .draw(|frame| {
                render_confirm(
                    frame,
                    files,
                    1024,
                    ConfirmTab::Summary,
                    "",
                    digest,
                    &mut scroll,
                )
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn long_plan(count: usize) -> PlanDigest {
        let paths: Vec<String> = (0..count).map(|i| format!("/tank/f{i}.bin")).collect();
        let actions: Vec<(ActionKind, &str)> = paths
            .iter()
            .map(|path| (ActionKind::Delete, path.as_str()))
            .collect();
        digest_of(&actions)
    }

    /// What the operator is shown on a normal terminal, and the whole point of U-4a: the
    /// batch is described by kind and by path, not by a bare total.
    #[test]
    fn the_summary_names_the_kinds_and_the_paths() {
        let digest = digest_of(&[
            (ActionKind::Delete, "/tank/photos/IMG_4421.HEIC"),
            (ActionKind::Hardlink, "/tank/dup/a.bin"),
            (ActionKind::Hardlink, "/tank/dup/b.bin"),
        ]);
        let text = joined(&digest, 20);

        assert!(
            text.contains("By type: delete 1 · hardlink 2"),
            "the composition has to be spelled out:\n{text}"
        );
        assert!(
            text.contains("DELETE") && text.contains("IMG_4421.HEIC"),
            "the deletion the operator did not mean must be named:\n{text}"
        );
        assert!(!text.contains("more"), "a 3-action plan is quoted whole");
    }

    /// A plan longer than the quota says so, instead of quietly showing five of five hundred.
    #[test]
    fn a_long_plan_admits_what_it_is_not_showing() {
        let text = joined(&long_plan(12), 20);

        assert!(text.contains("By type: delete 12"));
        assert!(text.contains("/tank/f0.bin") && text.contains("/tank/f4.bin"));
        assert!(!text.contains("/tank/f5.bin"), "only five are quoted");
        assert!(text.contains("… and 7 more"), "{text}");
    }

    /// The box is 66 wide, so a deep path has to lose its head — the file name is the part
    /// that identifies it.
    #[test]
    fn a_deep_path_keeps_its_tail() {
        let digest = digest_of(&[(
            ActionKind::Delete,
            "/tank/backups/2019/january/photos/family/holiday/IMG_4421_original_copy.HEIC",
        )]);
        let text = joined(&digest, 20);

        assert!(
            text.contains("IMG_4421_original_copy.HEIC"),
            "the name identifies the file:\n{text}"
        );
        assert!(text.contains('…'), "and the head is elided:\n{text}");
        for line in text.lines() {
            assert!(
                line.chars().count() <= SUMMARY_WIDTH as usize - 2,
                "line overflows the box: {line}"
            );
        }
    }

    /// The order the body gives things up in as the budget tightens: quoted paths, then the
    /// blank spacing, then the snapshot note, then the size — never the count, the
    /// composition, or the admission of what is not shown.
    #[test]
    fn the_body_sheds_paths_before_prose() {
        let digest = long_plan(12);

        let roomy = joined(&digest, 20);
        assert!(roomy.contains("/tank/f0.bin") && roomy.contains("A ZFS snapshot"));

        let tight = joined(&digest, 5);
        assert!(!tight.contains("/tank/f0.bin"), "paths go first:\n{tight}");
        assert!(
            tight.contains("A ZFS snapshot"),
            "prose outlives them:\n{tight}"
        );

        let tighter = joined(&digest, 4);
        assert!(
            !tighter.contains("A ZFS snapshot"),
            "then the note:\n{tighter}"
        );
        assert!(tighter.contains("Approximately freed"));

        let essentials = joined(&digest, 3);
        assert_eq!(
            essentials, "  Actions to be executed: 12\n  By type: delete 12\n  … and 12 more",
            "what is left is what the operator cannot decide without"
        );
    }

    /// The defect this amend fixes: the body alone was fitted to the terminal, but
    /// `render_confirm` then wrapped it in chrome that pushed the key hint off an 80x10
    /// screen. The operator could see a destructive batch and not the way to refuse it.
    #[test]
    fn a_ten_row_terminal_still_shows_the_way_out() {
        let screen = drawn(&long_plan(12), 80, 10);

        assert!(
            screen.contains("[Y] execute") && screen.contains("[N]/[Esc] cancel"),
            "the decision hint must survive:\n{screen}"
        );
        assert!(screen.contains("Actions to be executed: 12"), "{screen}");
        assert!(screen.contains("By type: delete 12"), "{screen}");
        assert!(
            screen.contains("… and 12 more"),
            "nothing is quoted, and the screen owns up to it:\n{screen}"
        );
        assert!(
            !screen.contains("DELETE "),
            "no room for quoted paths here:\n{screen}"
        );
    }

    /// A script long enough that the tail starts off-screen, one command per line.
    fn script(lines: usize) -> String {
        (1..=lines)
            .map(|n| format!("echo line{n}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The Commands tab as actually painted, with the scroll state the frame leaves behind.
    fn drawn_commands(text: &str, scroll: &mut ConfirmScroll, width: u16, height: u16) -> String {
        let digest = PlanDigest::default();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| {
                render_confirm(frame, 1, 1024, ConfirmTab::Commands, text, &digest, scroll)
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn commands_scroll(total: usize) -> ConfirmScroll {
        ConfirmScroll {
            offset: 0,
            total,
            rows: 0,
        }
    }

    /// The defect U-4b names: the tab printed the head of the script and a note about the
    /// rest, so the tail of a plan could never be read on screen.
    #[test]
    fn the_commands_tail_can_be_scrolled_into_view() {
        let text = script(60);
        let mut scroll = commands_scroll(60);

        let first = drawn_commands(&text, &mut scroll, 100, 24);
        assert!(first.contains("echo line1 "), "the head is shown:\n{first}");
        assert!(
            !first.contains("echo line60"),
            "the fixture only means something if the tail starts off-screen:\n{first}"
        );
        assert!(
            first.contains("lines 1-"),
            "the range says where we are:\n{first}"
        );
        assert!(first.contains("of 60"), "{first}");

        scroll.offset = scroll.max_offset();
        let last = drawn_commands(&text, &mut scroll, 100, 24);
        assert!(
            last.contains("echo line60"),
            "the last line must be reachable and rendered:\n{last}"
        );
        assert!(
            last.contains("lines 44-60 of 60"),
            "and the range must say so:\n{last}"
        );

        scroll.offset = 0;
        let home = drawn_commands(&text, &mut scroll, 100, 24);
        assert!(home.contains("echo line1 ") && !home.contains("echo line60"));
        assert!(home.contains("lines 1-17 of 60"), "{home}");
    }

    /// A page moves by the window minus one line of overlap, the same step the browser uses.
    #[test]
    fn a_page_moves_the_rendered_range_consistently() {
        let text = script(60);
        let mut scroll = commands_scroll(60);
        drawn_commands(&text, &mut scroll, 100, 24);
        assert_eq!(scroll.rows, 17, "17 body rows on a 24-row terminal");

        scroll.scroll_by(crate::tui::screens::browser::page_step(scroll.rows, 1));
        let paged = drawn_commands(&text, &mut scroll, 100, 24);
        assert!(paged.contains("lines 17-33 of 60"), "{paged}");
        assert!(paged.contains("echo line17") && paged.contains("echo line33"));
    }

    /// A resize grows the window under an offset that was valid for the smaller one; the
    /// window has to come back inside the script instead of trailing blank rows.
    #[test]
    fn growing_the_terminal_pulls_the_window_back_inside() {
        let text = script(30);
        let mut scroll = commands_scroll(30);
        drawn_commands(&text, &mut scroll, 100, 12);
        scroll.offset = scroll.max_offset();
        let small = drawn_commands(&text, &mut scroll, 100, 12);
        assert!(small.contains("echo line30"), "{small}");

        let big = drawn_commands(&text, &mut scroll, 100, 40);
        assert!(
            big.contains("echo line30") && big.contains("echo line1 "),
            "the whole script fits now, so the window must sit at the top:\n{big}"
        );
        assert_eq!(scroll.offset, 0, "clamped back to the only page");
        assert!(big.contains("lines 1-30 of 30"), "{big}");
    }

    /// Nothing to show must still render, and say so, rather than print `lines 1-0 of 0`.
    #[test]
    fn an_empty_or_single_line_script_renders_safely() {
        let mut empty = commands_scroll(0);
        let screen = drawn_commands("", &mut empty, 100, 24);
        assert!(screen.contains("no script lines"), "{screen}");
        assert!(screen.contains("[Y] execute"), "{screen}");

        let mut one = commands_scroll(1);
        let screen = drawn_commands("echo only", &mut one, 100, 24);
        assert!(screen.contains("echo only"), "{screen}");
        assert!(screen.contains("lines 1-1 of 1"), "{screen}");
    }

    /// The Commands tab inherits U-4a's rule: whatever the terminal size, the operator can
    /// still read how to refuse, and the tail stays reachable.
    #[test]
    fn a_small_terminal_keeps_the_decision_hint() {
        let text = script(60);
        for height in 6..=20u16 {
            let mut scroll = commands_scroll(60);
            let screen = drawn_commands(&text, &mut scroll, 100, height);
            assert!(
                screen.contains("[Y] execute") && screen.contains("[N]/[Esc] cancel"),
                "height {height} lost the decision hint:\n{screen}"
            );

            scroll.offset = scroll.max_offset();
            let tail = drawn_commands(&text, &mut scroll, 100, height);
            assert!(
                tail.contains("echo line60"),
                "height {height} cannot reach the last line:\n{tail}"
            );
            assert!(
                tail.contains("[Y] execute"),
                "height {height} lost the hint at the tail:\n{tail}"
            );
        }
    }

    /// Below what the essentials need there is nothing left to trade, and the hint is still
    /// the last line standing.
    #[test]
    fn the_hint_outlives_every_other_line() {
        for height in 6..=16u16 {
            let screen = drawn(&long_plan(12), 80, height);
            assert!(
                screen.contains("[Y] execute"),
                "height {height} lost the hint:\n{screen}"
            );
            assert!(
                screen.contains("Actions to be executed: 12"),
                "height {height} lost the count:\n{screen}"
            );
        }
    }

    /// The composition has to survive the trip to the screen, not just the string builder.
    #[test]
    fn the_overlay_draws_the_composition() {
        let digest = digest_of(&[
            (ActionKind::Delete, "/tank/photos/IMG_4421.HEIC"),
            (ActionKind::Hardlink, "/tank/dup/a.bin"),
        ]);
        let screen = drawn(&digest, 100, 30);

        assert!(
            screen.contains("By type: delete 1 · hardlink 1"),
            "{screen}"
        );
        assert!(screen.contains("IMG_4421.HEIC"), "{screen}");
        assert!(
            screen.contains("[Y] execute"),
            "the hint stays visible:\n{screen}"
        );
    }
}
