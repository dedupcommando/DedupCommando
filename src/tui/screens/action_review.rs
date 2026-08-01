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
    let rows = Layout::vertical([Constraint::Min(0), Constraint::Length(6)]).split(frame.area());

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

    let items: Vec<ListItem> = actions[start..end]
        .iter()
        .map(|action| {
            ListItem::new(format!(
                "{:9}  {}   ({})",
                action.kind().label(),
                action.target().display(),
                human_bytes(action.size()),
            ))
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

    let summary = app.review.plan.as_ref().map(|plan| plan.summary());
    let counts = summary.map_or_else(
        || " Operations: 0 · allocations: 0 ".to_string(),
        |summary| {
            format!(
                " Operations: {} · allocations: {} ",
                summary.actions(),
                summary.covered_objects()
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
        _ => format!(" {} ", app.status),
    };
    let footer = vec![
        Line::from(counts),
        Line::from(claim),
        Line::from(third),
        Line::from(" ↑↓/PgUp/PgDn/Home/End scroll · [Y] execute · [Esc] back to browser ".dim()),
    ];
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
        rows[1],
    );

    if app.review.confirming {
        if let Some(summary) = summary {
            render_confirm(frame, summary);
        }
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
fn render_confirm(frame: &mut Frame, summary: &PlanSummary) {
    let screen = frame.area();
    let width = screen
        .width
        .saturating_sub(4)
        .clamp(24, CONFIRM_MAX_WIDTH.max(24));
    let inner = width.saturating_sub(4).max(8) as usize;
    // Two borders, the decision line, and at least the two lines that state what is about to run.
    let body_budget = screen.height.saturating_sub(3).max(2) as usize;
    let body = confirm_body(summary, inner, body_budget);

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
/// by `… and N more`. The count line and the complete claim are never given up — they are the two
/// things the answer depends on.
fn confirm_body(summary: &PlanSummary, inner: usize, budget: usize) -> Vec<String> {
    let indent = |line: &str| format!("  {line}");
    let head = format!(
        "Execute {} action(s) over {} allocation(s)?",
        summary.actions(),
        summary.covered_objects()
    );
    let mut essential: Vec<String> = wrap_words(&head, inner).iter().map(|l| indent(l)).collect();
    essential.extend(
        wrap_words(&crate::tui::reclaim_phrase(summary.estimate()), inner)
            .iter()
            .map(|l| indent(l)),
    );

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
