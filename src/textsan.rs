// SPDX-License-Identifier: Apache-2.0
//! Path sanitizers for contexts OUTSIDE ratatui (shell script, log, headless stdout).
//!
//! File names in Unix may contain any bytes except `/` and NUL. Without sanitization such a
//! name breaks various text contexts:
//! - in the `.sh` plan a newline terminates the comment, and a single quote escapes out of
//!   `echo '…'` → command injection as root;
//! - in the log and headless output ANSI/OSC escapes execute on `cat`/`tail`/printing to
//!   the terminal (OSC 52 — write to the clipboard).
//!
//! ratatui itself clips control bytes per cell, so paths in the TUI do NOT pass through here —
//! only what is printed/logged/written into a script.

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
}
