// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crossbeam_channel::Sender;

use crate::error::Result;
use crate::model::scan::ScanConfig;
use crate::panics;
use crate::pipeline::{self, ScanOutcome};
use crate::state::ScanStore;
use crate::tui::event::AppEvent;

/// Control of a running scan.
pub struct ScanHandle {
    cancel: Arc<AtomicBool>,
}

impl ScanHandle {
    /// Asks the worker to stop. The checkpoint is already on disk — the scan is resumable.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Starts the scan in a background thread. Progress and result go to `events`.
pub fn spawn(
    db_path: PathBuf,
    config: ScanConfig,
    resume: Option<i64>,
    verify: bool,
    events: Sender<AppEvent>,
) -> ScanHandle {
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();

    spawn_job(events, move |events| {
        run(db_path, config, resume, verify, &worker_cancel, events)
    });

    ScanHandle { cancel }
}

/// The worker itself: panic containment and the terminal event. `spawn` hands it the real scan;
/// the tests hand it a job that panics. Without containment the panic loses `ScanFinished`, so the
/// screen keeps a progress bar that will never move again and a shutdown waits for a scan that is
/// already over.
fn spawn_job<F>(events: Sender<AppEvent>, job: F)
where
    F: FnOnce(&Sender<AppEvent>) -> Result<ScanOutcome> + Send + 'static,
{
    thread::spawn(move || {
        let outcome = panics::guard("the scan worker", || job(&events));
        // The grouping phase freed large Vecs, but glibc malloc keeps the pages held by the
        // process (the RSS badge sticks; on a host with VMs — RAM wasted for nothing). Return
        // them to the OS from THIS thread (its arena holds them), while the result is not yet
        // drawn. Best-effort.
        release_heap_to_os();
        let _ = events.send(AppEvent::ScanFinished(outcome));
    });
}

/// Returns freed heap memory to the operating system after the heavy scan phase.
/// glibc-only (`malloc_trim`); under other allocators/targets — no-op.
#[cfg(target_env = "gnu")]
fn release_heap_to_os() {
    // SAFETY: `malloc_trim` has no preconditions — it only returns free heap pages to the OS.
    unsafe {
        libc::malloc_trim(0);
    }
}

#[cfg(not(target_env = "gnu"))]
fn release_heap_to_os() {}

fn run(
    db_path: PathBuf,
    config: ScanConfig,
    resume: Option<i64>,
    verify: bool,
    cancel: &Arc<AtomicBool>,
    events: &Sender<AppEvent>,
) -> Result<ScanOutcome> {
    let mut store = ScanStore::open(&db_path)?;
    let progress_sink = events.clone();
    pipeline::run_scan(
        &mut store,
        &config,
        resume,
        verify,
        cancel,
        move |progress| {
            let _ = progress_sink.send(AppEvent::ScanProgress(progress));
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panicking scan must still report: `on_finished` is what clears `app.scan` and takes the
    /// wizard off the scanning screen, and nothing else sends it.
    #[test]
    fn a_panicking_scan_still_reports_finished() {
        let _lock = crate::panics::test_lock();
        let (tx, rx) = crossbeam_channel::unbounded();
        spawn_job(tx, |_events| panic!("boom in the scan"));

        let event = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("ScanFinished must arrive even when the scan panics");
        match event {
            AppEvent::ScanFinished(Err(err)) => assert!(
                err.contains("boom in the scan"),
                "the screen must show what happened: {err}"
            ),
            _ => panic!("the scan must report an error, not a result"),
        }
    }
}
