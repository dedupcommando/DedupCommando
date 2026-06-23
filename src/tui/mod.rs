// SPDX-License-Identifier: Apache-2.0
use std::io::{self, Stdout};

use ratatui::{
    backend::CrosstermBackend,
    crossterm::{
        event::{
            DisableMouseCapture, EnableMouseCapture, KeyboardEnhancementFlags,
            PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
        },
        execute,
        terminal::{
            disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement, EnterAlternateScreen,
            LeaveAlternateScreen,
        },
    },
    layout::{Alignment, Rect},
    style::Stylize,
    text::{Line, Text},
    widgets::{Block, Borders, Clear, ListState, Paragraph},
    Frame, Terminal,
};

use crate::app::{App, AppMode, ConfirmAction, Screen};

pub mod commander;
pub mod event;
pub mod screens;

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Owns the terminal in raw + alternate-screen mode; restores it on Drop.
pub struct TerminalGuard {
    terminal: Tui,
    /// Whether the keyboard enhancement protocol is enabled — so it can be correctly disabled on Drop.
    keyboard_enhanced: bool,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Self {
            terminal,
            keyboard_enhanced: false,
        })
    }

    pub fn terminal(&mut self) -> &mut Tui {
        &mut self.terminal
    }

    /// Enables the keyboard enhancement protocol if the terminal supports it:
    /// reliable modified keys (Shift+F) and Press/Release events
    /// (the footer reacts to Shift). Call BEFORE starting the input-reading thread —
    /// the support query itself reads the terminal's reply from stdin.
    pub fn enable_keyboard_enhancement(&mut self) {
        if supports_keyboard_enhancement().unwrap_or(false) {
            let flags = KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                | KeyboardEnhancementFlags::REPORT_EVENT_TYPES
                | KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES;
            if execute!(io::stdout(), PushKeyboardEnhancementFlags(flags)).is_ok() {
                self.keyboard_enhanced = true;
            }
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.keyboard_enhanced {
            let _ = execute!(self.terminal.backend_mut(), PopKeyboardEnhancementFlags);
        }
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = self.terminal.show_cursor();
    }
}

/// Restores the terminal BEFORE the panic prints its message.
pub fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let mut out = io::stdout();
        let _ = execute!(
            out,
            PopKeyboardEnhancementFlags,
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        original(info);
    }));
}

/// Render dispatcher by current screen; on top — the help overlay.
pub fn render(frame: &mut Frame, app: &mut App) {
    match app.mode {
        AppMode::Commander => commander::render(frame, app),
        AppMode::Wizard => match app.screen {
            Screen::ScanConfig => screens::scan_config::render(frame, app),
            Screen::FolderPicker => screens::folder_picker::render(frame, app),
            Screen::Resume => screens::resume::render(frame, app),
            Screen::Scanning => screens::scanning::render(frame, app),
            Screen::Applying => screens::applying::render(frame, app),
            Screen::Browser => screens::browser::render(frame, app),
            Screen::ActionReview => screens::action_review::render(frame, app),
            Screen::Summary => screens::summary::render(frame, app),
            Screen::ScanDiff => screens::scan_diff::render(frame, app),
            Screen::Trash => screens::trash::render(frame, app),
        },
    }
    // Process RAM/CPU indicator — top-right corner.
    render_resource_badge(frame, app.resource.latest(), app.read_only);
    // "Read-only" banner — over the UI, beneath modal overlays.
    if app.read_only {
        render_readonly_badge(frame);
    }
    // Modal confirmation — over the screen.
    if let Some(action) = app.confirm {
        render_confirm_modal(frame, action);
    }
    // Loading animation for a finished scan's result (E2E feedback) — while it loads in the background.
    if app.opening_started.is_some() {
        render_opening_overlay(frame, app);
    }
    if app.show_help {
        match app.mode {
            AppMode::Commander => commander::render_help(frame, app),
            AppMode::Wizard => render_help(frame),
        }
    }
    // Startup role-selection overlay when a live operator is present (ask policy).
    if app.concurrency_prompt.is_some() {
        render_concurrency(frame, app);
    }
    // Startup disclaimer gate — over everything, until consent.
    if app.show_disclaimer {
        render_disclaimer(frame, app);
    }
}

/// "Read-only" mode label. The resource indicator accounts for its width so the
/// badges don't overlap in the top-right corner — single source of truth.
const READONLY_LABEL: &str = " ● READ-ONLY ";

/// "Read-only" mode banner: a compact label in the top-right
/// corner — a constant signal that this is an observer and operations are disabled.
fn render_readonly_badge(frame: &mut Frame) {
    let w = READONLY_LABEL.chars().count() as u16;
    let area = frame.area();
    if area.width <= w + 1 || area.height == 0 {
        return;
    }
    let rect = Rect {
        x: area.width - w - 1,
        y: 0,
        width: w,
        height: 1,
    };
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(Line::from(READONLY_LABEL.black().on_yellow().bold())),
        rect,
    );
}

/// Process RAM/CPU indicator — top-right corner. If the "read-only"
/// banner is active (it sits at the very edge), we position left of it, without overlap.
fn render_resource_badge(
    frame: &mut Frame,
    sample: crate::sysmon::ResourceSample,
    read_only: bool,
) {
    let label = format!(
        " RAM {} · CPU {:>3.0}% ",
        human_bytes(sample.rss_bytes),
        sample.cpu_percent
    );
    let w = label.chars().count() as u16;
    let area = frame.area();
    let readonly_w = if read_only {
        READONLY_LABEL.chars().count() as u16 + 1
    } else {
        0
    };
    let right_limit = area.width.saturating_sub(readonly_w);
    if right_limit <= w + 1 || area.height == 0 {
        return;
    }
    let rect = Rect {
        x: right_limit - w - 1,
        y: 0,
        width: w,
        height: 1,
    };
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(Line::from(label.white().on_blue())), rect);
}

/// Modal confirmation window — yes/no for a reversible (trash) and
/// an irreversible (purge) action on sessions.
fn render_confirm_modal(frame: &mut Frame, action: ConfirmAction) {
    let (title, body) = match action {
        ConfirmAction::TrashScan(_) => (
            " Move to trash? ",
            "The session will be moved to the trash — it can be restored (t).",
        ),
        ConfirmAction::PurgeScan(_) => (
            " Purge from trash? ",
            "The session will be deleted PERMANENTLY — this is irreversible.",
        ),
    };
    let area = centered(frame.area(), 64, 7);
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from(""),
        Line::from(format!("  {body}")),
        Line::from(""),
        Line::from("  [Y] yes    ·    [N] no".bold()),
    ];
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

/// Background loading animation for a finished scan's result (E2E feedback): "Opening
/// result" runs rightward by +1 character every 0.5 s and bounces back at 5 positions —
/// a live signal that the tool is working (the first open of an old scan can be slow).
fn render_opening_overlay(frame: &mut Frame, app: &App) {
    let Some(started) = app.opening_started else {
        return;
    };
    let step = (started.elapsed().as_millis() / 500) as u64;
    // Triangle wave 0..5..0 — the string "bounces" off the edge.
    let s = step % 10;
    let offset = if s <= 5 { s } else { 10 - s } as usize;
    let text = format!("{}Opening result…", " ".repeat(offset));
    let area = centered(frame.area(), 48, 5);
    frame.render_widget(Clear, area);
    let lines = vec![Line::from(""), Line::from(format!("  {text}"))];
    frame.render_widget(
        Paragraph::new(Text::from(lines)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Please wait "),
        ),
        area,
    );
}

/// Startup role-selection overlay when a live operator is present (ask policy):
/// safe observer `[R]`, forced operator `[F]`, or exit `Esc`.
fn render_concurrency(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 68, 15);
    frame.render_widget(Clear, area);
    let who = match &app.concurrency_prompt {
        Some(h) => format!("PID {}, since {}", h.pid, h.since),
        None => "unknown".to_string(),
    };
    let lines = vec![
        Line::from("  Another running instance detected".bold()),
        Line::from(""),
        Line::from(format!("  Operator: {who}")),
        Line::from(""),
        Line::from("  Working on the same state with two operators may"),
        Line::from("  corrupt data. Choose a launch mode:"),
        Line::from(""),
        Line::from("  [R] Read-only — observe the map and progress (safe)"),
        Line::from("  [F] Become operator — DANGEROUS if that process is still alive"),
        Line::from("  [Esc] Exit"),
    ];
    frame.render_widget(
        Paragraph::new(Text::from(lines)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Concurrent launch "),
        ),
        area,
    );
}

/// Startup consent disclaimer gate: a notice about responsibility
/// and the single-user model + two checkboxes. Intercepts all input until
/// consent is checked and Enter is pressed (see `App::on_key_disclaimer`).
fn render_disclaimer(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 72, 22);
    frame.render_widget(Clear, area);

    let d = &app.disclaimer;
    let checkbox = |on: bool| if on { "[x]" } else { "[ ]" };
    let cursor = |focused: bool| if focused { "▸ " } else { "  " };

    let agree = Line::from(format!(
        "  {}{} I have read and agree (required)",
        cursor(d.focus == 0),
        checkbox(d.agreed)
    ));
    let agree = if d.focus == 0 { agree.bold() } else { agree };
    let suppress = Line::from(format!(
        "  {}{} Don't show this at startup again",
        cursor(d.focus == 1),
        checkbox(d.suppress)
    ));
    let suppress = if d.focus == 1 {
        suppress.bold()
    } else {
        suppress
    };
    let enter_hint = if d.agreed {
        Line::from("  [Enter] continue".to_string())
    } else {
        Line::from("  [Enter] unavailable — check the consent box".dim())
    };

    let lines = vec![
        Line::from(format!("  DedupCommando {}", crate::version()).bold()),
        Line::from(""),
        Line::from("  Notice and consent".bold()),
        Line::from(""),
        Line::from("  The tool works with real data of a ZFS pool."),
        Line::from("  Moving, deletion and deduplication are irreversible —"),
        Line::from("  responsibility for the outcome lies with the user."),
        Line::from("  Make backups and test on a test pool first."),
        Line::from(""),
        Line::from("  The version is designed for a single user: simultaneous"),
        Line::from("  launch on the same state is not supported."),
        Line::from(""),
        agree,
        suppress,
        Line::from(""),
        enter_hint,
        Line::from("  [Space] check   [Tab] switch focus   [Esc] exit".dim()),
    ];
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(Block::default().borders(Borders::ALL).title(" Notice ")),
        area,
    );
}

fn render_help(frame: &mut Frame) {
    let area = centered(frame.area(), 64, 27);
    frame.render_widget(Clear, area);

    let lines = vec![
        Line::from(format!("  DedupCommando {}", crate::version()).bold()),
        Line::from(""),
        Line::from("  Navigation".bold()),
        Line::from("    ↑↓ / j k       move through the list"),
        Line::from("    Tab            switch panel (groups / files)"),
        Line::from(""),
        Line::from("  Selection".bold()),
        Line::from("    Space          mark dataset / unmark file"),
        Line::from("    Enter          assign the group's keeper file"),
        Line::from(""),
        Line::from("  Actions on duplicates".bold()),
        Line::from("    d              deletion (move to quarantine)"),
        Line::from("    h              hardlink"),
        Line::from("    c              reflink (ZFS clone)"),
        Line::from("    a              auto-select across all groups"),
        Line::from("    r              review actions (dry-run)"),
        Line::from(""),
        Line::from("  Other".bold()),
        Line::from("    s              start scanning"),
        Line::from("    f              add an arbitrary folder (config screen)"),
        Line::from("    Esc            back / stop scan"),
        Line::from("    ?              this help        q   exit"),
        Line::from(""),
        Line::from("  [Esc] close".dim()),
    ];
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(Block::default().borders(Borders::ALL).title(" Help ")),
        area,
    );
}

/// Initialization splash screen — drawn right after entering the TUI, while
/// the ZFS environment is detected in the background. The spinner turns by `tick` —
/// a "program is alive" signal, no black screen during a long startup.
pub fn render_splash(frame: &mut Frame, tick: u64) {
    const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" DedupCommando ");
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);

    let spin = SPINNER[(tick % SPINNER.len() as u64) as usize];
    let lines = vec![
        Line::from(""),
        Line::from("██████   DedupCommando   ██████".bold()),
        Line::from(""),
        Line::from("multi-panel ZFS deduplicator".dim()),
        Line::from(""),
        Line::from(format!("{spin}  detecting ZFS environment…")),
    ];
    let box_area = centered(inner, 52, lines.len() as u16);
    frame.render_widget(
        Paragraph::new(Text::from(lines)).alignment(Alignment::Center),
        box_area,
    );
}

/// A `width`×`height` rectangle, centered in `area`.
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

/// Visible list window for VIRTUALIZATION: keeps `selected` within a window
/// of height `rows`, writes the window start into `state.offset`, and returns
/// `(start, local selected within the window)`. The caller builds `ListItem` ONLY for
/// the `groups[start..start+rows]` slice and renders with a temporary `ListState` (offset 0) —
/// otherwise, on large lists (hundreds of thousands of rows), building all items every frame
/// starves the UI thread (freeze of the groups window / panels).
pub(crate) fn visible_window(
    state: &mut ListState,
    total: usize,
    rows: usize,
) -> (usize, Option<usize>) {
    if total == 0 || rows == 0 {
        *state.offset_mut() = 0;
        return (0, None);
    }
    let selected = state.selected().unwrap_or(0).min(total - 1);
    let mut start = state.offset().min(total - 1);
    if selected < start {
        start = selected;
    } else if selected >= start + rows {
        start = selected + 1 - rows;
    }
    let max_start = total.saturating_sub(rows);
    if start > max_start {
        start = max_start;
    }
    *state.offset_mut() = start;
    (start, Some(selected - start))
}

/// Human-readable size: 1536 -> "1.5 KiB".
pub fn human_bytes(bytes: u64) -> String {
    let (value, unit) = human_bytes_parts(bytes);
    format!("{value} {unit}")
}

/// Size split apart — number and unit, for column alignment
/// (digits under digits): 1536 -> ("1.5", "KiB"), 512 -> ("512", "B").
pub fn human_bytes_parts(bytes: u64) -> (String, &'static str) {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        (bytes.to_string(), UNITS[0])
    } else {
        (format!("{value:.1}"), UNITS[unit])
    }
}

/// Human-readable duration: 134 s -> "2m14s", 3725 s -> "1h02m", 9 s -> "9s".
pub fn format_duration(seconds: f64) -> String {
    let total = seconds.max(0.0) as u64;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let secs = total % 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}m")
    } else if minutes > 0 {
        format!("{minutes}m{secs:02}s")
    } else {
        format!("{secs}s")
    }
}

/// Hashing speed in MiB/s: "47.0 MiB/s"; "—" if the time is unknown. MiB/s (not
/// GiB/s) is readable on production HDD pools (~40–60 MiB/s): GiB/s gave "0.04 GiB/s".
pub fn format_speed(bytes: u64, seconds: f64) -> String {
    if seconds <= 0.0 || bytes == 0 {
        return "—".to_string();
    }
    let mib_per_sec = bytes as f64 / seconds / (1024.0 * 1024.0);
    format!("{mib_per_sec:.1} MiB/s")
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn speed_is_mib_per_sec() {
        assert_eq!(format_speed(47 * 1024 * 1024, 1.0), "47.0 MiB/s");
        assert_eq!(format_speed(0, 1.0), "—", "zero bytes → dash");
        assert_eq!(format_speed(1024 * 1024, 0.0), "—", "zero time → dash");
    }
}

/// Two-line footer: status (if non-empty) and the always-visible key hints.
pub fn render_footer(frame: &mut Frame, area: Rect, status: &str, hints: &str) {
    let lines = Text::from(vec![
        Line::from(status.to_string()),
        Line::from(hints.dim()),
    ]);
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
        area,
    );
}
