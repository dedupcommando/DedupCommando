// SPDX-License-Identifier: Apache-2.0
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::App;
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
        let claim = summary.map_or_else(String::new, |summary| {
            crate::tui::reclaim_phrase(summary.estimate())
        });
        render_confirm(frame, count, &claim);
    }
}

fn render_confirm(frame: &mut Frame, count: usize, claim: &str) {
    let area = centered(frame.area(), 56, 8);
    frame.render_widget(Clear, area);

    let text = vec![
        Line::from(""),
        Line::from(format!("  Execute {count} operations?").bold()),
        Line::from("  A snapshot + quarantine are created — actions"),
        Line::from("  are reversible until purge."),
        Line::from(format!("  {claim}")),
        Line::from("            [Y] yes        [N] no"),
    ];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Confirmation "),
        ),
        area,
    );
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
