// SPDX-License-Identifier: Apache-2.0
//! Panic containment for the background workers.
//!
//! A panic in a worker thread does not kill the process: that thread unwinds alone, its terminal
//! event is never sent, and whatever waits for that event waits forever. Applying is the worst
//! case — the screen deliberately has no exit key, only Esc, which merely asks the worker to stop.
//! The move and purge workers strand a counter instead: `move_pending` and `purge_pending` are
//! released only by `CommanderMoveDone` and `SessionDeleted`, and a shutdown waits on both. So a
//! worker catches the panic and reports it as the very event it would have sent anyway.
//!
//! The terminal is the second casualty. The panic hook hands it back to the shell — raw mode off,
//! alternate screen left — while the main loop happily keeps drawing frames over the panic
//! message. The hook therefore also marks the TUI dead, and the loop stops drawing and shuts down
//! the way it does on a signal: finish the current action, then leave.

use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};

/// Raised by the panic hook once the terminal belongs to the shell again.
static TUI_DEAD: AtomicBool = AtomicBool::new(false);

/// Runs `job` so that a panic comes back as an error instead of a lost event. `what` names the
/// worker in the text the operator ends up seeing.
pub fn guard_value<T>(what: &str, job: impl FnOnce() -> T) -> std::result::Result<T, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)) {
        Ok(value) => Ok(value),
        Err(payload) => {
            let text = format!("{what} panicked: {}", message(&*payload));
            tracing::error!("{text}");
            Err(text)
        }
    }
}

/// The same, for a job that already has an error of its own: both failures reach the caller as
/// one string, because both end up in the same status line.
pub fn guard<T, E: std::fmt::Display>(
    what: &str,
    job: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, String> {
    guard_value(what, job)?.map_err(|err| err.to_string())
}

/// Text of a caught payload — what `panic!` was given, when it was given a string at all.
fn message(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "no message".to_string()
    }
}

/// Called from the panic hook: the TUI no longer owns the terminal.
pub fn mark_tui_dead() {
    TUI_DEAD.store(true, Ordering::SeqCst);
}

/// Whether a panic has already taken the terminal away from the TUI.
pub fn tui_dead() -> bool {
    TUI_DEAD.load(Ordering::SeqCst)
}

/// Panics and the hook are process-wide, so every test that raises one takes this lock first —
/// the same arrangement the signal tests use.
#[cfg(test)]
pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Forgets an earlier panic, so a test can watch the flag being raised.
#[cfg(test)]
pub fn clear_tui_dead() {
    TUI_DEAD.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_becomes_an_error_that_still_names_it() {
        let _lock = test_lock();
        // `panic!("literal")` leaves a &str payload, a formatted one leaves a String.
        let literal = guard("the worker", || -> crate::error::Result<()> {
            panic!("plain boom")
        });
        assert_eq!(literal.unwrap_err(), "the worker panicked: plain boom");

        let formatted = guard("the worker", || -> crate::error::Result<()> {
            panic!("boom at index {}", 7)
        });
        assert_eq!(
            formatted.unwrap_err(),
            "the worker panicked: boom at index 7"
        );
    }

    #[test]
    fn a_job_that_returns_keeps_its_own_result() {
        let ok = guard("the worker", || -> crate::error::Result<u8> { Ok(7) });
        assert_eq!(ok.unwrap(), 7);

        let failed = guard("the worker", || -> crate::error::Result<u8> {
            Err(crate::error::AppError::msg("no snapshot"))
        });
        assert_eq!(failed.unwrap_err(), "no snapshot");
    }
}
