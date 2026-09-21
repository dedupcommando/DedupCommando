// SPDX-License-Identifier: Apache-2.0
//! Path sanitizers: what a file name may look like in the shell script, in the log, on headless
//! stdout and on the screen.
//!
//! File names in Unix may contain any bytes except `/` and NUL. Without sanitization such a
//! name breaks various text contexts:
//! - in the `.sh` plan a newline terminates the comment, and a single quote escapes out of
//!   `echo '…'` → command injection as root;
//! - in the log and headless output ANSI/OSC escapes execute on `cat`/`tail`/printing to
//!   the terminal (OSC 52 — write to the clipboard);
//! - in the interface they execute as the frame is written. ratatui 0.29 drops control
//!   characters in `Buffer::set_string` and nowhere else. Every `Line`, `Paragraph`, `List` and
//!   `Block` title is drawn through a `Span`, which keeps them, a cell each, and the backend
//!   prints a cell as it is. The screens draw nothing any other way.
//!
//! So a pathname reaches the screen through `path`/`os_str`, and text that may quote one (an
//! error message, a line of the script) through `terminal`. The code that draws the interface
//! may not turn a pathname into text itself; `the_interface_never_shows_a_path_by_hand` below
//! holds it to that.

/// Path label for bash comments and `echo '…'` messages in the `.sh` plan.
///
/// Replaces control bytes (including `\n`/`\r`/`\t`) and the single quote with `?`, so a file
/// name cannot terminate a comment or escape out of the `echo` single quote. Applied
/// ONLY to displayed substitutions — the real command arguments (`mv`/`ln`/`cp`) go
/// through `sh_quote`, where a newline inside `'…'` stays a literal and is safe.
pub(crate) fn shell_label(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() || c == '\'' { '?' } else { c })
        .collect()
}

/// Path version for the log (`dedcom.log`) and headless output to the terminal.
///
/// Escapes control characters (C0 `\0`..`\x1f` + DEL/C1 `\x7f`..`\x9f`, which include
/// `ESC` and `OSC`) into the visible `escape_default` form (`\n`, `\u{1b}`, etc.), so
/// ANSI/OSC sequences from a file name do not reach the terminal raw and are not
/// executed on printing or `cat dedcom.log`. Printable characters,
/// including Cyrillic and spaces, stay as they are. Unlike `shell_label`, the apostrophe
/// is NOT touched — it is safe in the terminal.
pub(crate) fn terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// A pathname as the interface shows it.
///
/// Some lists are rebuilt on every frame, row by row, so the ordinary name — the one with
/// nothing to escape — is handed back as it came, without a second pass and a second allocation.
pub(crate) fn path(path: &std::path::Path) -> String {
    let raw = path.display().to_string();
    if raw.contains(char::is_control) {
        terminal(&raw)
    } else {
        raw
    }
}

/// One component of a pathname (a file name, an extension) as the interface shows it.
pub(crate) fn os_str(text: &std::ffi::OsStr) -> String {
    let raw = text.to_string_lossy();
    if raw.contains(char::is_control) {
        terminal(&raw)
    } else {
        raw.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_label_strips_control_bytes() {
        assert_eq!(shell_label("a\nb"), "a?b");
        assert_eq!(shell_label("a\rb\tc"), "a?b?c");
        assert_eq!(shell_label("x\u{1b}[31m"), "x?[31m");
    }

    #[test]
    fn shell_label_strips_single_quote() {
        assert_eq!(shell_label("a'b"), "a?b");
    }

    #[test]
    fn shell_label_keeps_normal_path() {
        // Spaces and ordinary characters are not touched.
        assert_eq!(
            shell_label("/tank/обычный файл.bin"),
            "/tank/обычный файл.bin"
        );
    }

    #[test]
    fn terminal_escapes_ansi_and_osc() {
        // ESC (\x1b) and C1-OSC (\u{9d}) are escaped, not delivered raw.
        assert_eq!(terminal("x\u{1b}[31mred"), "x\\u{1b}[31mred");
        assert_eq!(terminal("a\u{9d}0;evil\u{7}"), "a\\u{9d}0;evil\\u{7}");
        assert_eq!(terminal("a\nb\tc"), "a\\nb\\tc");
    }

    #[test]
    fn terminal_keeps_printable_and_cyrillic() {
        // Cyrillic, spaces and the apostrophe are safe in the terminal — keep them as is.
        assert_eq!(
            terminal("/tank/обычный 'файл'.bin"),
            "/tank/обычный 'файл'.bin"
        );
    }

    /// What the interface calls. A name that is not UTF-8 at all still comes out printable.
    #[test]
    fn a_path_and_a_name_are_shown_escaped() {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::OsStr::from_bytes(b"bad\xff\x1b[2J.bin");
        assert_eq!(os_str(name), "bad\u{fffd}\\u{1b}[2J.bin");
        assert_eq!(
            path(std::path::Path::new("/tank/a\u{7}b/обычный файл")),
            "/tank/a\\u{7}b/обычный файл"
        );
    }

    /// Every control character there is, not a sample of them: C0, DEL and C1. Some terminals in
    /// UTF-8 mode act on U+009B and U+009D exactly as they do on `ESC [` and `ESC ]`.
    #[test]
    fn terminal_leaves_no_control_character_of_any_kind() {
        let every: String = (0u32..=0x9f).filter_map(char::from_u32).collect();
        assert_eq!(every.chars().filter(|c| c.is_control()).count(), 65);
        let shown = terminal(&every);
        assert!(
            !shown.chars().any(char::is_control),
            "{}",
            shown.escape_debug()
        );
        // Nothing printable was lost on the way: the ASCII letters are all still there.
        assert!(shown.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }

    /// Whatever is not a control character comes back exactly as it went in: wide characters,
    /// an emoji joined from several, a combining mark, a backslash.
    #[test]
    fn terminal_leaves_everything_printable_alone() {
        for name in [
            "日本語 ファイル.txt",
            "family 👨\u{200d}👩\u{200d}👧.jpg",
            "e\u{301}te\u{301}.doc",
            "back\\slash and 'quotes' and \"more\"",
        ] {
            assert_eq!(terminal(name), name);
            assert_eq!(path(std::path::Path::new(name)), name);
            assert_eq!(os_str(std::ffi::OsStr::new(name)), name);
        }
    }

    /// Several status lines print a refusal with `{:?}` and are left as they are, because `Debug`
    /// escapes what it quotes. This is what they rest on.
    #[test]
    fn debug_formatting_escapes_a_pathname_by_itself() {
        let quoted = format!(
            "{:?}",
            std::path::Path::new("/tank/a\u{1b}]0;x\u{7}\u{9b}b")
        );
        assert!(!quoted.chars().any(char::is_control), "{quoted}");
    }

    /// Escaping twice changes nothing, so a caller that cannot know whether a text was already
    /// made safe may do it again.
    #[test]
    fn terminal_is_idempotent() {
        let once = terminal("a\u{1b}]0;x\u{7}\u{9b}2J\r\n\t\u{7f}я");
        assert_eq!(terminal(&once), once);
    }

    /// Two names that differ only in a control character stay different on screen. Telling files
    /// apart is what this tool is for, which is why a control character is spelled out and not
    /// replaced by one placeholder.
    #[test]
    fn terminal_keeps_names_that_differ_in_a_control_character_apart() {
        assert_ne!(terminal("a\u{1b}b"), terminal("a\u{7}b"));
        assert_ne!(terminal("a\u{1b}b"), terminal("ab"));
    }

    // ---- The interface shows a path only through this module ----

    /// Every way a pathname becomes text. A method call and a function path both contain one of
    /// these: `.to_string_lossy()` and `.map(OsStr::to_string_lossy)`, `.display()` and
    /// `Path::display(p)`.
    const BY_HAND_TOKENS: [&str; 6] = [
        "to_string_lossy",
        "display(",
        "::display",
        ".to_str()",
        "from_utf8_lossy",
        "into_string()",
    ];

    /// Where `src/tui/` and `app.rs` may still turn a pathname into text by hand, and why:
    /// `(file, the whole line, reason)`. Everything else goes through `path`/`os_str`, and a line
    /// that is not listed here fails `the_interface_never_shows_a_path_by_hand`.
    const BY_HAND: &[(&str, &str, &str)] = &[
        (
            "src/tui/commander/state.rs",
            "name: entry.file_name().to_string_lossy().into_owned(),",
            "the panel's model: sorted, searched and looked up across panels by this exact text, \
             escaped where a row is drawn",
        ),
        (
            "src/tui/commander/state.rs",
            ".map(|ext| ext.to_string_lossy().to_ascii_lowercase())",
            "a sort key, never shown",
        ),
    ];

    /// The lines of a source file that are compiled into the binary: everything outside an item
    /// marked `#[cfg(test)]`. Leans on the tree being rustfmt-formatted, which CI enforces:
    /// an item ends with its closing brackets alone on a line, at the indentation its attribute
    /// stands at.
    ///
    /// It fails closed. Inside an item, a line that is not indented deeper than the attribute has
    /// to be that closing line or a recognised continuation of the item's head (`} else {`,
    /// `) -> T {`, `where`, `{`). Anything else is refused, because the other way to be wrong is
    /// to go on skipping shipped code until some later brace happens to line up.
    fn shipped_lines(source: &str) -> Result<Vec<(usize, &str)>, String> {
        let is_closer = |tail: &str| {
            let brackets = tail.trim_end_matches([';', ',']);
            !brackets.is_empty()
                && tail.len() - brackets.len() <= 1
                && brackets.chars().all(|c| matches!(c, '}' | ')' | ']' | '>'))
        };
        let mut shipped = Vec::new();
        let mut lines = source.lines().enumerate();
        while let Some((index, line)) = lines.next() {
            if line.trim() != "#[cfg(test)]" {
                shipped.push((index + 1, line));
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            let mut in_item = false;
            let mut closed = false;
            for (at, next) in lines.by_ref() {
                let text = next.trim();
                if !in_item {
                    // Further attributes and doc comments still belong to the same item.
                    if text.starts_with("#[") || text.starts_with("//") {
                        continue;
                    }
                    in_item = true;
                    let one_line = text.ends_with(';')
                        || text.ends_with(',')
                        || (text.ends_with('}')
                            && text.matches('{').count() == text.matches('}').count());
                    if one_line {
                        closed = true;
                        break;
                    }
                    continue;
                }
                if text.is_empty() || next.len() - next.trim_start().len() > indent {
                    continue;
                }
                if next.len() - next.trim_start().len() == indent {
                    if is_closer(text) {
                        closed = true;
                        break;
                    }
                    if text.starts_with(['}', ')', ']']) || text == "where" || text == "{" {
                        continue;
                    }
                }
                return Err(format!(
                    "line {}: `{text}` is neither inside the `#[cfg(test)]` item of line {} nor \
                     its end",
                    at + 1,
                    index + 1
                ));
            }
            if !closed {
                return Err(format!(
                    "line {}: a `#[cfg(test)]` item never closes",
                    index + 1
                ));
            }
        }
        Ok(shipped)
    }

    #[test]
    fn shipped_lines_leaves_out_test_items_of_every_shape_and_nothing_else() {
        let source = "\
fn shipped_one() {}
#[cfg(test)]
pub(crate) mod support;
#[cfg(test)]
const LIMIT: usize = 1;
fn shipped_two() {
    shipped_body();
}
impl Thing {
    #[cfg(test)]
    /// Doc.
    #[allow(dead_code)]
    fn hidden_method(&self) {
        hidden_body();
    }
    fn shipped_three(&self) {}
    #[cfg(test)]
    fn hidden_empty() {}
    fn shipped_four(&self) {}
    #[cfg(test)]
    fn hidden_generic<T>(
        hidden_argument: T,
    ) -> T
    where
        T: Clone,
    {
        hidden_argument
    }
}
#[cfg(test)]
mod tests {
    fn hidden_helper() {
        if x {
            hidden_nested();
        } else {
            hidden_other();
        }
    }
}
#[cfg(test)]
const HIDDEN_TABLE: &[&str] = &[
    \"hidden_entry\",
];
#[cfg(test)]
static HIDDEN_LAZY: Lazy<Thing> = Lazy::new(|| {
    hidden_build()
});
fn shipped_five() {
    #[cfg(test)]
    let hidden_seam = take_fault(
        hidden_argument,
    );
    shipped_tail();
}
";
        let kept: Vec<&str> = shipped_lines(source)
            .expect("every shape above is one rustfmt produces")
            .into_iter()
            .map(|(_, line)| line.trim())
            .filter(|line| line.contains("shipped") || line.contains("hidden"))
            .collect();
        assert_eq!(
            kept,
            [
                "fn shipped_one() {}",
                "fn shipped_two() {",
                "shipped_body();",
                "fn shipped_three(&self) {}",
                "fn shipped_four(&self) {}",
                "fn shipped_five() {",
                "shipped_tail();",
            ]
        );
    }

    /// The other half: a shape the filter does not know is an error, never a longer skip.
    #[test]
    fn shipped_lines_refuses_what_it_cannot_place() {
        let runs_on = "\
#[cfg(test)]
fn hidden()
    -> usize
fn shipped() {}
";
        let refusal = shipped_lines(runs_on).expect_err("the item's end was never seen");
        assert!(refusal.contains("line 4"), "{refusal}");

        let never_closes = "#[cfg(test)]\nmod tests {\n    fn hidden() {}\n";
        assert!(shipped_lines(never_closes).is_err());
    }

    fn rust_files_under(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
            .map(|entry| entry.expect("a directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                rust_files_under(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }

    /// A source file of this crate, by its path from the crate root.
    fn source_of(root: &std::path::Path, file: &std::path::Path) -> (String, String) {
        let name = file
            .strip_prefix(root)
            .expect("a file of this crate")
            .to_string_lossy()
            .replace('\\', "/");
        let source =
            std::fs::read_to_string(file).unwrap_or_else(|err| panic!("cannot read {name}: {err}"));
        (name, source)
    }

    /// The boundary holds only if a new screen cannot step around it. In the code that draws the
    /// interface, nothing that turns a pathname into text may appear outside the list above. The
    /// list is checked the other way too, so an exception cannot outlive the line it was written
    /// for.
    #[test]
    fn the_interface_never_shows_a_path_by_hand() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = vec![root.join("src/app.rs")];
        rust_files_under(&root.join("src/tui"), &mut files);
        assert!(files.len() > 15, "the interface is more than {files:?}");

        let mut excused = vec![0usize; BY_HAND.len()];
        let mut unlisted = Vec::new();
        for file in &files {
            let (name, source) = source_of(root, file);
            // Whole files of tests: their parent declares them `#[cfg(test)] mod …;`.
            if name.ends_with("_tests.rs") || name.ends_with("/hostile.rs") {
                continue;
            }
            let shipped = shipped_lines(&source).unwrap_or_else(|why| panic!("{name}: {why}"));
            for (number, line) in shipped {
                // A comment may name what the code next to it avoids.
                if line.trim_start().starts_with("//")
                    || !BY_HAND_TOKENS.iter().any(|token| line.contains(token))
                {
                    continue;
                }
                let listed = BY_HAND
                    .iter()
                    .position(|(listed, text, _)| *listed == name && line.trim() == *text);
                match listed {
                    Some(index) => excused[index] += 1,
                    None => unlisted.push(format!("{name}:{number}: {}", line.trim())),
                }
            }
        }

        assert!(
            unlisted.is_empty(),
            "a pathname is turned into text by hand; show it through `textsan::path` or \
             `textsan::os_str`:\n{}",
            unlisted.join("\n")
        );
        for ((file, text, reason), seen) in BY_HAND.iter().zip(excused) {
            assert_eq!(
                seen, 1,
                "{file}: `{text}` ({reason}) is listed as an exception and was found {seen} time(s)"
            );
        }
    }

    /// `tui::draw` is the screens plus the guard behind them, and `main` is the only caller. The
    /// screens' own `render` functions are public to each other, so nothing but this stops a new
    /// loop in `main` from drawing one of them directly.
    #[test]
    fn main_draws_frames_through_the_guard_only() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let (name, source) = source_of(root, &root.join("src/main.rs"));
        let shipped = shipped_lines(&source).unwrap_or_else(|why| panic!("{name}: {why}"));
        let draws: Vec<&str> = shipped
            .iter()
            .map(|(_, line)| line.trim())
            .filter(|line| line.contains(".draw(|"))
            .collect();
        assert!(!draws.is_empty(), "main draws somewhere");
        for line in draws {
            assert!(
                line.contains("tui::draw(frame") || line.contains("tui::render_splash(frame"),
                "{name} draws past the guard: {line}"
            );
        }
    }
}
