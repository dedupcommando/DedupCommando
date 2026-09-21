// SPDX-License-Identifier: Apache-2.0
//! Test support for the one rule every screen shares: a file name is data, and nothing in it may
//! reach the terminal as a control character.
//!
//! On Linux a name is any bytes but `/` and NUL, so a directory somebody else filled can hold
//! `ESC ] 0 ; … BEL` (retitle the window), `ESC [ 2 J` (clear it), or the 8-bit forms of the same.
//! Why they reach the terminal at all is told in `textsan`; the check here is made where the
//! terminal would see them, on the cells of the drawn frame.

use std::path::PathBuf;

use ratatui::{backend::TestBackend, buffer::Buffer, Frame, Terminal};

use crate::tui::commander::state::{EntryKind, PanelEntry};

/// Retitles the terminal window.
pub(crate) const RETITLE: &str = "\u{1b}]0;PWNED\u{7}evil.bin";
/// What `RETITLE` has to look like once it is safe to print.
pub(crate) const RETITLE_SHOWN: &str = "\\u{1b}]0;PWNED\\u{7}evil.bin";
/// Clears the screen.
pub(crate) const CLEAR: &str = "wipe\u{1b}[2Jme.txt";
/// The same two through the 8-bit controls U+009B and U+009D, which need no ESC at all.
pub(crate) const EIGHT_BIT: &str = "8bit\u{9b}2J\u{9d}0;PWNED\u{9c}.dat";
/// Cursor movement: CR, LF, TAB, BS and DEL.
pub(crate) const MOTION: &str = "cr\rlf\ntab\tbs\u{8}del\u{7f}.log";
/// Every fixture above; a surface is fed all of them.
pub(crate) const NAMES: [&str; 4] = [RETITLE, CLEAR, EIGHT_BIT, MOTION];
/// A name that must come through untouched: Cyrillic, spaces, an apostrophe, a backslash.
pub(crate) const ORDINARY: &str = "отчёт о'нил \\2024.txt";

/// A panel entry for `path`, named the way `read_panel_dir` names one.
pub(crate) fn entry(path: PathBuf, kind: EntryKind) -> PanelEntry {
    PanelEntry {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path,
        kind,
        size: 4096,
        mtime: 1_700_000_000,
        device: 1,
        inode: 7,
    }
}

/// Fails if `text` — a status line, an overlay line — holds a control character.
pub(crate) fn assert_text_inert(text: &str, what: &str) {
    assert!(
        !text.chars().any(char::is_control),
        "{what} holds a control character: {text:?}"
    );
}

/// Draws into a frame of exactly this size and hands back its cells.
pub(crate) fn frame_of(width: u16, height: u16, draw: impl FnOnce(&mut Frame)) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(draw).unwrap();
    terminal.backend().buffer().clone()
}

/// The rows of a drawn frame, top to bottom.
pub(crate) fn rows(buffer: &Buffer) -> Vec<String> {
    let area = *buffer.area();
    (area.top()..area.bottom())
        .map(|y| {
            (area.left()..area.right())
                .map(|x| buffer[(x, y)].symbol())
                .collect()
        })
        .collect()
}

/// The whole frame as one string, rows joined by a newline.
pub(crate) fn text(buffer: &Buffer) -> String {
    rows(buffer).join("\n")
}

/// Every cell that would hand the terminal a control character, as `(column, row, symbol)`.
pub(crate) fn live_cells(buffer: &Buffer) -> Vec<(u16, u16, String)> {
    let area = *buffer.area();
    let mut found = Vec::new();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let symbol = buffer[(x, y)].symbol();
            if symbol.chars().any(char::is_control) {
                found.push((x, y, symbol.escape_debug().to_string()));
            }
        }
    }
    found
}

/// Fails, naming the surface and the cells, if the frame carries a control character.
pub(crate) fn assert_inert(buffer: &Buffer, surface: &str) {
    let live = live_cells(buffer);
    assert!(
        live.is_empty(),
        "{surface}: {} cell(s) would reach the terminal as control characters: {:?}\n{}",
        live.len(),
        live,
        text(buffer).escape_debug()
    );
}

/// Draws, requires the frame to be inert, and returns its text for the caller's own assertions.
pub(crate) fn inert_text(
    width: u16,
    height: u16,
    surface: &str,
    draw: impl FnOnce(&mut Frame),
) -> String {
    let buffer = frame_of(width, height, draw);
    assert_inert(&buffer, surface);
    text(&buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{
        text::Line,
        widgets::{Block, Borders, List, ListItem, Paragraph},
    };

    /// The premise of every other test here, pinned so that a ratatui upgrade that starts to drop
    /// control characters on these paths is noticed rather than silently making the suite
    /// vacuous: a raw name drawn the way the screens draw it does put ESC into a cell. The three
    /// widgets are the three the screens use, and each goes through code of its own.
    #[test]
    fn a_raw_name_reaches_the_cells_through_every_widget_the_screens_use() {
        let drawn = [
            (
                "Paragraph",
                frame_of(40, 1, |frame| {
                    frame.render_widget(Paragraph::new(Line::from(RETITLE)), frame.area());
                }),
            ),
            (
                "List",
                frame_of(40, 1, |frame| {
                    frame.render_widget(List::new([ListItem::new(RETITLE)]), frame.area());
                }),
            ),
            (
                "Block title",
                frame_of(40, 3, |frame| {
                    let block = Block::default().borders(Borders::ALL).title(RETITLE);
                    frame.render_widget(block, frame.area());
                }),
            ),
        ];
        for (widget, buffer) in drawn {
            let live = live_cells(&buffer);
            assert!(
                live.iter().any(|(_, _, symbol)| symbol == "\\u{1b}"),
                "{widget}: ESC was expected in a cell of its own, got {live:?}"
            );
        }
    }

    #[test]
    fn every_fixture_name_carries_a_control_character_and_the_ordinary_one_does_not() {
        for name in NAMES {
            assert!(name.chars().any(char::is_control), "{name:?}");
            assert!(
                !name.contains('/'),
                "a file name cannot hold a slash: {name:?}"
            );
        }
        assert!(!ORDINARY.chars().any(char::is_control));
        assert_eq!(crate::textsan::terminal(RETITLE), RETITLE_SHOWN);
    }
}
