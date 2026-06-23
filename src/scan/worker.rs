// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crossbeam_channel::Sender;

use crate::error::Result;
use crate::model::scan::ScanConfig;
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

    thread::spawn(move || {
        let outcome = run(db_path, config, resume, verify, &worker_cancel, &events);
        // The grouping phase freed large Vecs, but glibc malloc keeps the pages held by the
        // process (the RSS badge sticks; on a host with VMs — RAM wasted for nothing). Return
        // them to the OS from THIS thread (its arena holds them), while the result is not yet
        // drawn. Best-effort.
        release_heap_to_os();
        let _ = events.send(AppEvent::ScanFinished(
            outcome.map_err(|err| err.to_string()),
        ));
    });

    ScanHandle { cancel }
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
