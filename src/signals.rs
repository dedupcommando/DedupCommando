// SPDX-License-Identifier: Apache-2.0
//! Shutdown signals wired to the cancellation the rest of the code already implements.
//!
//! The failure this exists for is mundane: an SSH session to the Proxmox host drops, the shell
//! sends SIGHUP, and without a handler the process dies wherever it happens to be — between the
//! quarantine evacuation and the publish of a hardlink, halfway through a directory merge in the
//! move worker, mid-`purge_scan`. Snapshots and quarantine keep the outcome recoverable, but the
//! `BatchResult` is lost, so the operator who reconnects cannot tell what actually applied.
//!
//! `ApplyShared::cancel` and `ScanHandle::cancel` already mean «finish the current action, then
//! stop». A signal now arms exactly those, so there is no second, separate shutdown path.
//!
//! `libc` directly rather than a signal crate, for the reason given in `lock`: the project is
//! Linux-only and already depends on `libc`. The handler does the one thing that is safe inside
//! a signal handler — store to an atomic. Everything else happens on the normal threads.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Armed by the handler; read by the scan/apply cancellation checks.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// How many shutdown signals have arrived. The second one means the operator is no longer
/// willing to wait for a graceful stop, so the TUI stops waiting for the worker.
static COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn handler(_signal: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
    COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Installs the handler for SIGINT, SIGTERM and SIGHUP.
///
/// `SA_RESTART` on purpose: an interrupted `read` should resume rather than fail, so a signal
/// during hashing does not surface as a spurious I/O error. Cancellation is noticed at the
/// action boundary, which is where it is safe.
pub fn install() {
    // SAFETY: `handler` only stores to atomics, `act` is fully initialised before use, and the
    // old-action pointer is null because we do not chain to a previous handler.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut act.sa_mask);
        act.sa_flags = libc::SA_RESTART;
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            if libc::sigaction(signal, &act, std::ptr::null_mut()) != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!("cannot install the handler for signal {signal}: {err}");
            }
        }
    }
}

/// Whether a shutdown signal has arrived.
pub fn requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Number of shutdown signals so far. `> 1` — stop waiting for the current action.
pub fn count() -> usize {
    COUNT.load(Ordering::SeqCst)
}

/// The flag itself, for the cancellation checks that already take an `&AtomicBool`
/// (`pipeline::run_scan` in headless mode watches this instead of a flag nobody ever armed).
pub fn shutdown_flag() -> &'static AtomicBool {
    &SHUTDOWN
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signals are process-wide, so the tests that raise them share one lock and put the state
    /// back afterwards.
    static SIGNAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() {
        SHUTDOWN.store(false, Ordering::SeqCst);
        COUNT.store(0, Ordering::SeqCst);
    }

    /// Current disposition of `signal`: `true` when it is still the default, i.e. nothing in
    /// this process intercepts it.
    fn is_default_disposition(signal: libc::c_int) -> bool {
        // SAFETY: querying only — the new-action pointer is null.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut current), 0);
            current.sa_sigaction == libc::SIG_DFL
        }
    }

    /// Puts the default disposition back, so a test that installs handlers does not leave the
    /// process intercepting signals for the tests that follow.
    fn restore_default_disposition() {
        // SAFETY: `act` is fully initialised; SIG_DFL is always a valid disposition.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut act.sa_mask);
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                assert_eq!(libc::sigaction(signal, &act, std::ptr::null_mut()), 0);
            }
        }
    }

    /// A mode that does not check the cancel flag must NOT end up with our handler: catching a
    /// signal there would swallow it and leave the process unkillable by SIGTERM. Interception
    /// only ever comes from an explicit `install()`, which is why it is called per mode rather
    /// than once in `main`.
    #[test]
    fn interception_only_happens_on_an_explicit_install() {
        let _lock = SIGNAL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        restore_default_disposition();
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            assert!(
                is_default_disposition(signal),
                "signal {signal} must be left alone until install() is called"
            );
        }
        install();
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            assert!(
                !is_default_disposition(signal),
                "install() must take over signal {signal}"
            );
        }
        restore_default_disposition();
        reset();
    }

    #[test]
    fn a_signal_arms_the_flag_the_scan_already_watches() {
        let _lock = SIGNAL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reset();
        install();
        assert!(!requested(), "nothing has arrived yet");

        // SIGHUP is the SSH-drop case. Without the handler this would kill the test process,
        // which is itself the point of the fix.
        assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        assert!(
            requested(),
            "the flag the cancellation checks read is armed"
        );
        assert_eq!(count(), 1);
        // The headless scan watches this very flag.
        assert!(shutdown_flag().load(Ordering::SeqCst));

        reset();
    }

    #[test]
    fn a_second_signal_is_counted_separately() {
        let _lock = SIGNAL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reset();
        install();
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert_eq!(count(), 1, "the first asks for a graceful stop");
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert_eq!(count(), 2, "the second stops waiting for the worker");
        reset();
    }

    /// The caller path, not just the flag: a headless scan hands `shutdown_flag()` to
    /// `run_scan`, so an arrived signal must actually end it as `Cancelled`. Before this fix
    /// headless passed a freshly created flag that nothing ever armed.
    #[test]
    fn an_arrived_signal_cancels_a_headless_scan() {
        let _lock = SIGNAL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reset();

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("dedcom_sig_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.bin"), b"same contents").unwrap();
        std::fs::write(root.join("b.bin"), b"same contents").unwrap();

        let mut store = crate::state::ScanStore::open_in_memory().unwrap();
        let config = crate::model::scan::ScanConfig::new(vec![root.clone()]);

        install();
        // Every shutdown signal must do it: SIGHUP is the dropped SSH session, SIGINT is Ctrl+C
        // in the foreground, SIGTERM is a service stop.
        for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
            reset();
            assert_eq!(unsafe { libc::raise(signal) }, 0);
            let outcome = crate::pipeline::run_scan(
                &mut store,
                &config,
                None,
                false,
                shutdown_flag(),
                |_| {},
            )
            .unwrap();
            // `Cancelled` is exactly what makes headless print "Scan cancelled." and keep the
            // scan resumable.
            assert!(
                matches!(outcome, crate::pipeline::ScanOutcome::Cancelled),
                "signal {signal} must stop the scan"
            );
        }

        std::fs::remove_dir_all(&root).ok();
        restore_default_disposition();
        reset();
    }

    #[test]
    fn installing_twice_is_harmless() {
        let _lock = SIGNAL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reset();
        install();
        install();
        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
        assert_eq!(count(), 1, "the handler is still installed exactly once");
        reset();
    }
}
