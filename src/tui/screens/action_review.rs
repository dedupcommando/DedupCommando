// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::App;
use crate::model::plan::PlanSummary;
use crate::tui::screens::browser::wrap_words;
use crate::tui::{centered, human_bytes};

/// Action review screen: dry-run list + confirmation modal.
///
/// Every figure comes out of the owning plan — the action count, the number of allocations at least
/// one pathname of which is being removed, the guaranteed/potential state and the warnings. Nothing
/// on this screen sums file sizes of its own, which is what let a review claim one allocation's
/// worth of space once per alias.
pub fn render(frame: &mut Frame, app: &mut App) {
    // The actions that cannot run where their files are: how many, and the first one.
    let unrun = app
        .review
        .plan
        .as_ref()
        .and_then(|plan| plan.unrunnable_head())
        .map(|(count, first, reason)| Unrun {
            count,
            first: first.to_path_buf(),
            reason: reason.to_string(),
        });
    let footer_rows = if unrun.is_some() { 7 } else { 6 };
    let rows =
        Layout::vertical([Constraint::Min(0), Constraint::Length(footer_rows)]).split(frame.area());

    // The key handler needs the window height for PageUp/PageDown; it is only known here.
    let visible = rows[0].height.saturating_sub(2);
    app.review.visible_rows = visible;
    // Virtualization, as in the browser lists: a plan can hold every duplicate of a scan,
    // and formatting all of them every frame starves the UI thread for input.
    let empty = Vec::new();
    let actions = app
        .review
        .plan
        .as_ref()
        .map_or(&empty[..], |plan| plan.actions());
    let count = actions.len();
    let (start, local_sel) =
        crate::tui::visible_window(&mut app.review.list, count, visible as usize);
    let end = (start + visible as usize).min(count);

    // Position is read back from the window, not from `list.selected()`: an out-of-range
    // cursor is clamped in there, and the counter must name the row actually highlighted.
    // No selection (an empty plan) reads as `0 of 0` rather than panicking on `+ 1`.
    let position = local_sel.map_or(0, |local| start + local + 1);

    let plan = app.review.plan.as_ref();
    let items: Vec<ListItem> = actions[start..end]
        .iter()
        .enumerate()
        .map(|(offset, action)| {
            let kind = action.kind().label();
            let target = crate::textsan::path(action.target());
            let size = human_bytes(action.size());
            let reason = plan.and_then(|plan| plan.unrunnable_reason(start + offset));
            let reason = reason.map(crate::textsan::terminal);
            ListItem::new(review_row(kind, &target, &size, reason.as_deref()))
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Action review — dry-run, nothing executed yet · {position} of {count} "
        )))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    let mut local = ListState::default();
    local.select(local_sel);
    frame.render_stateful_widget(list, rows[0], &mut local);

    // Worked out when the review was seated: what cannot run is set aside there, once.
    let summary = plan.map(|plan| app.review.claim.as_ref().unwrap_or(plan.summary()));
    let counts = summary.map_or_else(
        || " Operations: 0 · allocations: 0 ".to_string(),
        |summary| {
            let planned = unrun.as_ref().map(|unrun| summary.actions() + unrun.count);
            format!(
                " {} ",
                review_counts(summary.actions(), planned, summary.covered_objects())
            )
        },
    );
    // Its own line, as everywhere else the claim is printed: the qualifier is what makes the
    // number true, so it is not the part a narrow terminal may drop.
    let claim = summary.map_or_else(String::new, |summary| {
        format!(" {} ", crate::tui::reclaim_phrase(summary.estimate()))
    });
    let third = match summary.map(|summary| summary.warnings()) {
        // The pathname is already in the list above; what a fixed-height footer must not lose is
        // the clause that explains the zero.
        Some(warnings) if !warnings.is_empty() => {
            let more = warnings.len() - 1;
            let mut line = format!(" {} ", warnings[0].reason());
            if more > 0 {
                line.push_str(&format!("· and {more} more "));
            }
            line
        }
        _ => format!(" {} ", crate::tui::status_shown(&app.status)),
    };
    let mut footer = vec![Line::from(counts), Line::from(claim)];
    // Its own line, above the warnings: it is why the count and the figure are less than marked.
    if let Some(unrun) = &unrun {
        footer.push(Line::from(format!(
            " {} ",
            crate::tui::cannot_run_phrase(unrun.count, &unrun.reason)
        )));
    }
    footer.push(Line::from(third));
    footer.push(Line::from(
        " ↑↓/PgUp/PgDn/Home/End scroll · [Y] execute · [Esc] back to browser ".dim(),
    ));
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
        rows[1],
    );

    if app.review.confirming {
        if let Some(summary) = summary {
            render_confirm(frame, summary, unrun.as_ref());
        }
    }
}

/// The actions of the plan that cannot run where their files are: how many, and the first one
/// with its reason.
struct Unrun {
    count: usize,
    first: std::path::PathBuf,
    reason: String,
}

/// One row of the review. An action that cannot run where its file is carries the mark where the
/// eye starts and the reason after the size: on a narrow terminal the end of a long row is what
/// gets cut, and the footer names the reason too. The manual quotes it.
fn review_row(kind: &str, target: &str, size: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("{kind:9}✗ {target}   ({size})   {reason}"),
        None => format!("{kind:9}  {target}   ({size})"),
    }
}

/// The footer's count: the actions that run — of how many were planned, when some cannot — and
/// the allocations they remove a pathname of. The manual quotes it.
fn review_counts(actions: usize, planned: Option<usize>, covered: usize) -> String {
    match planned {
        Some(planned) => format!("Operations: {actions} of {planned} · allocations: {covered}"),
        None => format!("Operations: {actions} · allocations: {covered}"),
    }
}

/// The confirmation's question, in the same terms. The manual quotes it.
fn confirm_head(actions: usize, planned: Option<usize>, covered: usize) -> String {
    match planned {
        Some(planned) => {
            format!("Execute {actions} of {planned} action(s) over {covered} allocation(s)?")
        }
        None => format!("Execute {actions} action(s) over {covered} allocation(s)?"),
    }
}

/// The [Y]/[N] line, which no shrink may ever take away.
const CONFIRM_DECISION: &str = "            [Y] yes        [N] no";

/// The box will not grow past this, however wide the terminal is: a claim that runs the full width
/// of a 200-column terminal is one line the eye has to track across the whole screen.
const CONFIRM_MAX_WIDTH: u16 = 72;

/// The last destructive question, quoted from the plan itself.
///
/// It states what the review states — how many actions, how many allocations, the complete
/// post-purge claim and the reason behind a zero — because this modal, not the screen behind it, is
/// what the operator is looking at when they decide. The box is sized to the terminal and the text
/// wraps inside it: the previous fixed 56×8 box cut `up to 4.0 KiB after quarantine purge` off at
/// `up to 4.0 K`, which reads as a smaller number rather than as a truncated one.
fn render_confirm(frame: &mut Frame, summary: &PlanSummary, unrun: Option<&Unrun>) {
    let screen = frame.area();
    let width = screen
        .width
        .saturating_sub(4)
        .clamp(24, CONFIRM_MAX_WIDTH.max(24));
    let inner = width.saturating_sub(4).max(8) as usize;
    // Two borders, the decision line, and at least the two lines that state what is about to run.
    let body_budget = screen.height.saturating_sub(3).max(2) as usize;
    let body = confirm_body(summary, unrun, inner, body_budget);

    let height = (body.len() + 3) as u16;
    let area = centered(screen, width, height.min(screen.height));
    frame.render_widget(Clear, area);

    let mut text: Vec<Line> = body.into_iter().map(Line::from).collect();
    text.push(Line::from(CONFIRM_DECISION));
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Confirmation "),
        ),
        area,
    );
}

/// The modal's body, in priority order, wrapped to `inner` and cut to `budget` lines.
///
/// What goes first is the reassurance about snapshots; then the warnings past the first, replaced
/// by `… and N more`. The count line and the complete claim are given up last — they are what the
/// answer depends on; the line about what cannot run comes right after them, and the pathname of
/// the first of those goes before any of them.
fn confirm_body(
    summary: &PlanSummary,
    unrun: Option<&Unrun>,
    inner: usize,
    budget: usize,
) -> Vec<String> {
    let indent = |line: &str| format!("  {line}");
    let planned = unrun.map(|unrun| summary.actions() + unrun.count);
    let head = confirm_head(summary.actions(), planned, summary.covered_objects());
    let mut essential: Vec<String> = wrap_words(&head, inner).iter().map(|l| indent(l)).collect();
    essential.extend(
        wrap_words(&crate::tui::reclaim_phrase(summary.estimate()), inner)
            .iter()
            .map(|l| indent(l)),
    );
    if let Some(unrun) = unrun {
        let line = crate::tui::cannot_run_phrase(unrun.count, &unrun.reason);
        essential.extend(wrap_words(&line, inner).iter().map(|l| indent(l)));
    }
    // The first of what cannot run, last of the essentials: a short terminal cuts it first.
    // Shortened from the left, so the name of the file stays.
    if let Some(unrun) = unrun {
        let first = crate::tui::commander::panel::ellipsize_left(
            &crate::textsan::path(&unrun.first),
            inner.saturating_sub("first: ".len()),
        );
        essential.push(indent(&format!("first: {first}")));
    }

    let warnings = summary.warnings();
    let mut optional: Vec<String> = Vec::new();
    if let Some(first) = warnings.first() {
        optional.extend(wrap_words(&first.reason(), inner).iter().map(|l| indent(l)));
        if warnings.len() > 1 {
            optional.push(indent(&format!("… and {} more", warnings.len() - 1)));
        }
    }
    let note = "A snapshot + quarantine are created — reversible until purge.";
    let reassurance: Vec<String> = wrap_words(note, inner).iter().map(|l| indent(l)).collect();

    // Fill from the essentials outwards, so a short terminal loses the reassurance and then the
    // extra warning lines rather than the numbers the decision rests on.
    let mut lines = essential;
    for extra in [optional, reassurance] {
        if lines.len() + extra.len() <= budget {
            lines.extend(extra);
        }
    }
    lines.truncate(budget.max(1));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{test_app, test_plan, AppMode, Screen};
    use crate::tui::event::AppEvent;
    use ratatui::crossterm::event::{KeyCode, KeyEvent};
    use ratatui::{backend::TestBackend, Terminal};

    /// Everything the operator can actually read on a `width`x`height` terminal.
    fn screen_text(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
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

    /// An app parked on ActionReview over `count` planned actions, cursor at the top.
    fn review_app(count: usize) -> (App, crossbeam_channel::Receiver<AppEvent>) {
        let (mut app, rx) = test_app();
        app.show_disclaimer = false;
        app.mode = AppMode::Wizard;
        app.screen = Screen::ActionReview;
        app.review.plan = test_plan(count);
        if count > 0 {
            app.review.list.select(Some(0));
        }
        (app, rx)
    }

    fn press(app: &mut App, code: KeyCode) {
        app.handle_event(AppEvent::Key(KeyEvent::from(code)));
    }

    /// What the operator reads, with the box drawing and the line breaks taken out: a sentence
    /// wrapped inside a modal is still one sentence, and the defect this guards against is a
    /// sentence that simply stops.
    fn visible_prose(screen: &str) -> String {
        let text: String = screen
            .chars()
            .map(|ch| {
                if ch.is_ascii_graphic() || ch.is_alphanumeric() {
                    ch
                } else {
                    ' '
                }
            })
            .collect();
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The defect U-3 names: a plan longer than the window used to end at the first
    /// screenful, so the operator confirmed actions they had no way to look at.
    #[test]
    fn the_tail_of_the_plan_can_be_scrolled_into_view() {
        let (mut app, _rx) = review_app(50);

        let before = screen_text(&mut app, 80, 16);
        assert!(before.contains("dup00.bin"), "the plan starts at the top");
        assert!(
            before.contains("1 of 50"),
            "the counter opens at the top:\n{before}"
        );
        assert!(
            !before.contains("dup49.bin"),
            "the fixture is only meaningful if the tail starts off-screen"
        );

        press(&mut app, KeyCode::End);

        let after = screen_text(&mut app, 80, 16);
        assert!(
            after.contains("dup49.bin"),
            "End must bring the last planned action onto the screen:\n{after}"
        );
        assert!(
            after.contains("50 of 50"),
            "and the counter must say so:\n{after}"
        );
    }

    /// The counter is the only thing telling the operator where they are in a long plan,
    /// so it has to answer every way of moving — not just the arrows.
    #[test]
    fn the_counter_follows_paging() {
        let (mut app, _rx) = review_app(50);
        // One frame first: PageDown steps by the window the last frame measured.
        let first = screen_text(&mut app, 80, 16);
        assert!(first.contains("1 of 50"));

        press(&mut app, KeyCode::PageDown);
        let paged = screen_text(&mut app, 80, 16);
        assert!(
            paged.contains("8 of 50"),
            "8 rows fit on an 80x16 screen, so a page is 7 rows of movement:\n{paged}"
        );

        press(&mut app, KeyCode::PageUp);
        assert!(screen_text(&mut app, 80, 16).contains("1 of 50"));

        press(&mut app, KeyCode::Down);
        assert!(screen_text(&mut app, 80, 16).contains("2 of 50"));
    }

    /// A resize re-lays the window out under a cursor that has not moved. The counter must
    /// keep naming the highlighted row — the tempting `start + 1` would follow the window
    /// instead and report a different action at every size.
    #[test]
    fn the_counter_names_the_cursor_not_the_window_top() {
        let (mut app, _rx) = review_app(50);
        screen_text(&mut app, 80, 16);
        press(&mut app, KeyCode::End);

        let short = screen_text(&mut app, 80, 16);
        assert!(short.contains("50 of 50"), "{short}");
        assert!(
            !short.contains("dup18.bin"),
            "8 rows fit here, so the window starts at dup42:\n{short}"
        );

        let tall = screen_text(&mut app, 80, 40);
        assert!(
            tall.contains("dup18.bin") && tall.contains("dup49.bin"),
            "32 rows fit now — the window really did grow:\n{tall}"
        );
        assert!(
            tall.contains("50 of 50"),
            "yet the cursor never moved, so the counter must not either:\n{tall}"
        );

        let tiny = screen_text(&mut app, 80, 10);
        assert!(
            tiny.contains("50 of 50"),
            "shrinking keeps the cursor too, it does not reset to the top:\n{tiny}"
        );
    }

    /// R2D-C5-2a, blocker C: the last destructive question has to carry the whole plan, and on the
    /// terminals the tool supports it has to be READABLE — the fixed 56×8 box cut
    /// `up to 4.0 KiB after quarantine purge` off at `up to 4.0 K`, which reads as a smaller
    /// number rather than as a truncated one.
    #[test]
    fn the_confirmation_quotes_the_whole_plan_at_every_supported_size() {
        let _role = crate::state::store::role_guard();
        let scenario = crate::testfixtures::PlanScenario::new("confirm_parity");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let _outside = scenario.outside_link(&twin, "elsewhere.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &twin,
            false,
            Some(crate::model::action::ActionKind::Delete),
        );
        drop(store);

        let (mut app, _rx) = test_app();
        app.review.plan = Some(crate::actions::tests::plan_of(&scenario, scan_id));
        app.review.confirming = true;

        for (width, height) in [(80u16, 12u16), (120, 30), (60, 14)] {
            let screen = screen_text(&mut app, width, height);
            // The box wraps, so the phrase is read across the line break. What must never happen —
            // and is what the red showed — is a phrase that simply stops.
            let prose = visible_prose(&screen);
            assert!(
                prose.contains("up to 4.0 KiB after quarantine purge"),
                "{width}x{height}: the claim must be readable in full:\n{screen}"
            );
            assert!(
                prose.contains("guaranteed after quarantine purge: 0 B"),
                "{width}x{height}: including the guarantee:\n{screen}"
            );
            assert!(
                prose.contains("1 allocation(s)") && prose.contains("1 action(s)"),
                "{width}x{height}: with the counts the answer rests on:\n{screen}"
            );
            assert!(
                prose.contains("outside this scan"),
                "{width}x{height}: and the reason the guarantee is zero:\n{screen}"
            );
            assert!(
                prose.contains("[Y] yes") && prose.contains("[N] no"),
                "{width}x{height}: the way out is never shed:\n{screen}"
            );
        }
    }

    /// An action that cannot run where its file is: marked in the list with its reason, counted
    /// apart in the footer, left out of the figure — and named in the confirmation, which asks
    /// about the rest only.
    #[test]
    fn the_review_names_what_cannot_run_and_leaves_it_out() {
        let _role = crate::state::store::role_guard();
        let scenario = crate::testfixtures::PlanScenario::new("review_unrunnable");
        let keeper = scenario.file("keeper.bin");
        let here = scenario.file("here.bin");
        let there = scenario.file("there.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), here.clone(), there.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        for twin in [&here, &there] {
            scenario.mark(
                &mut store,
                scan_id,
                twin,
                false,
                Some(crate::model::action::ActionKind::Delete),
            );
        }
        drop(store);
        let plan = crate::actions::tests::plan_of(&scenario, scan_id);
        let mut reasons = vec![None; plan.actions().len()];
        let blocked = plan
            .actions()
            .iter()
            .position(|action| action.target() == there)
            .unwrap();
        reasons[blocked] = Some("read-only filesystem (tank/a)".to_string());

        let (mut app, _rx) = review_app(0);
        app.review = crate::app::ReviewState::seat(
            plan.with_unrunnable(crate::model::plan::Unrunnable::new(reasons)),
        );

        let screen = screen_text(&mut app, 120, 20);
        assert!(
            screen.contains("Operations: 1 of 2 · allocations: 1"),
            "{screen}"
        );
        assert!(
            screen.contains("1 cannot run here — read-only filesystem (tank/a)"),
            "{screen}"
        );
        let row = format!("DELETE   ✗ {}", there.display());
        assert!(screen.contains(&row), "the row carries its mark:\n{screen}");
        let wide = screen_text(&mut app, 220, 20);
        assert!(
            wide.contains("(4.0 KiB)   read-only filesystem (tank/a)"),
            "and says why where there is room:\n{wide}"
        );
        assert!(
            screen.contains("guaranteed after quarantine purge: 4.0 KiB"),
            "one twin's worth, not two:\n{screen}"
        );

        app.review.confirming = true;
        for (width, height) in [(80u16, 16u16), (120, 30)] {
            let prose = visible_prose(&screen_text(&mut app, width, height));
            assert!(
                prose.contains("Execute 1 of 2 action(s) over 1 allocation(s)?"),
                "{width}x{height}: {prose}"
            );
            assert!(
                prose.contains("1 cannot run here read-only filesystem (tank/a)"),
                "{width}x{height}: {prose}"
            );
            // The path is cut on the left, so the name of the file is what stays.
            assert!(
                prose.contains("first:") && prose.contains("/there.bin"),
                "{width}x{height}: {prose}"
            );
            assert!(
                prose.contains("guaranteed after quarantine purge: 4.0 KiB"),
                "{width}x{height}: {prose}"
            );
        }
        // A short terminal gives up the path before the figure — and, shorter still, the line
        // about what cannot run before it too.
        for height in [8u16, 5] {
            let short = visible_prose(&screen_text(&mut app, 80, height));
            assert!(
                short.contains("guaranteed after quarantine purge: 4.0 KiB"),
                "80x{height}: {short}"
            );
        }
    }

    /// The footer's count and the confirmation's question, with some actions set aside, as the
    /// manual quotes them.
    #[test]
    fn the_manual_quotes_the_review_counts() {
        let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let quote =
            |text: String| words(&text.replace('7', "N").replace('8', "M").replace('9', "K"));
        let head = quote(confirm_head(7, Some(8), 9));
        let counts = quote(review_counts(7, Some(8), 9));
        let counts = counts.split(" ·").next().unwrap().to_string();
        assert_eq!(head, "Execute N of M action(s) over K allocation(s)?");
        assert_eq!(counts, "Operations: N of M");
        for (chapter, quotes) in [
            ("06-classic.md", vec![&head, &counts]),
            ("08-actions.md", vec![&head]),
        ] {
            let text = words(&crate::testfixtures::manual(chapter));
            for quoted in quotes {
                assert!(
                    text.contains(quoted.as_str()),
                    "{chapter} must quote: {quoted}"
                );
            }
        }
        assert_eq!(
            confirm_head(3, None, 2),
            "Execute 3 action(s) over 2 allocation(s)?"
        );
        assert_eq!(review_counts(3, None, 2), "Operations: 3 · allocations: 2");
    }

    /// A row that cannot run, as the manual shows one.
    #[test]
    fn the_manual_quotes_a_row_that_cannot_run() {
        let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let row = review_row(
            "DELETE",
            "/tank/ro/a.bin",
            "4.0 KiB",
            Some("read-only filesystem (tank/ro)"),
        );
        assert_eq!(
            row,
            "DELETE   ✗ /tank/ro/a.bin   (4.0 KiB)   read-only filesystem (tank/ro)"
        );
        let chapter = words(&crate::testfixtures::manual("06-classic.md"));
        assert!(
            chapter.contains(&words(&row)),
            "06-classic.md must quote: {row}"
        );
        assert_eq!(
            review_row("DELETE", "/tank/a.bin", "4.0 KiB", None),
            "DELETE     /tank/a.bin   (4.0 KiB)"
        );
    }

    /// A terminal too short for everything still shows the numbers and the way out.
    #[test]
    fn a_very_short_terminal_keeps_the_numbers_and_the_answer() {
        let (mut app, _rx) = review_app(3);
        app.review.confirming = true;
        let screen = screen_text(&mut app, 80, 8);
        assert!(
            screen.contains("3 action(s) over 3 allocation(s)"),
            "{screen}"
        );
        assert!(
            screen.contains("guaranteed after quarantine purge"),
            "{screen}"
        );
        assert!(
            screen.contains("[Y] yes") && screen.contains("[N] no"),
            "{screen}"
        );
    }

    /// `open_action_review` refuses an empty plan, but `ReviewState::default()` is empty and
    /// the screen is reachable with it — the counter must not index its way into a panic.
    #[test]
    fn an_empty_plan_renders_safely() {
        let (mut app, _rx) = review_app(0);
        let text = screen_text(&mut app, 80, 16);
        assert!(text.contains("0 of 0"), "empty reads as 0 of 0:\n{text}");
        press(&mut app, KeyCode::End);
        press(&mut app, KeyCode::PageDown);
        assert!(screen_text(&mut app, 80, 16).contains("0 of 0"));
    }
}
