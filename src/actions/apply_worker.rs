// SPDX-License-Identifier: Apache-2.0
//! Background application of a batch of actions (mirror of `scan/worker.rs`): the UI doesn't freeze.
//! The worker thread calls [`apply_batch`], a separate poller sends `ApplyProgress` ~6/s,
//! at the end — `ApplyFinished` with `BatchResult`. Cancellation (Esc) is a flag in `ApplyShared`,
//! checked at the action boundary: the snapshot is already made, what was applied is in quarantine.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossbeam_channel::Sender;

use crate::model::action::{PlannedAction, RevalidationMode};
use crate::model::dataset::Dataset;
use crate::tui::event::AppEvent;

use super::{apply_batch, ApplyPhase, ApplyShared};

/// Control over a running apply: cancellation at the action boundary.
pub struct ApplyHandle {
    shared: Arc<ApplyShared>,
}

impl ApplyHandle {
    /// Asks the worker to stop after the current action. The snapshot is already made, and
    /// the already-applied actions lie in quarantine — the partial result is reversible.
    pub fn cancel(&self) {
        self.shared.cancel.store(true, Ordering::Relaxed);
    }
}

/// Starts applying a batch in the background. Progress and result go to `events`.
pub fn spawn(
    plan: Vec<PlannedAction>,
    datasets: Vec<Dataset>,
    reflink_safe: bool,
    mode: RevalidationMode,
    events: Sender<AppEvent>,
) -> ApplyHandle {
    let shared = Arc::new(ApplyShared::default());

    // Poller: ~6 progress snapshots per second, until the phase is Done. A separate thread —
    // apply_batch is a tight loop without a natural callback (unlike run_scan).
    let poll_shared = shared.clone();
    let poll_events = events.clone();
    thread::spawn(move || loop {
        let snapshot = poll_shared.snapshot();
        let done = snapshot.phase == ApplyPhase::Done;
        let _ = poll_events.send(AppEvent::ApplyProgress(snapshot));
        if done {
            break;
        }
        thread::sleep(Duration::from_millis(150));
    });

    // Worker thread: applies the batch and sends the result.
    let work_shared = shared.clone();
    thread::spawn(move || {
        let result = apply_batch(&plan, &datasets, reflink_safe, &work_shared, mode)
            .map_err(|err| err.to_string());
        // We guarantee the Done phase even if apply_batch exited with an error BEFORE it
        // (for example, a snapshot failure) — otherwise the poller would spin forever.
        work_shared.set_phase(ApplyPhase::Done);
        let _ = events.send(AppEvent::ApplyFinished(result));
    });

    ApplyHandle { shared }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::action::{BatchResult, RevalidationMode};

    /// spawn → applying an empty plan → `ApplyFinished(Ok(BatchResult))` arrives.
    /// (An empty plan doesn't touch the FS/ZFS — safe in Docker without a pool.)
    #[test]
    fn spawn_empty_plan_sends_finished() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let _handle = spawn(Vec::new(), Vec::new(), false, RevalidationMode::Hybrid, tx);

        let mut finished: Option<std::result::Result<BatchResult, String>> = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(AppEvent::ApplyFinished(result)) => {
                    finished = Some(result);
                    break;
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        let result = finished.expect("ApplyFinished must arrive");
        let batch = result.expect("empty plan — Ok");
        assert_eq!(batch.outcomes.len(), 0);
    }

    /// Progress arrives and the phase reaches Done (the poller sends at least one snapshot).
    #[test]
    fn progress_reaches_done() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let _handle = spawn(Vec::new(), Vec::new(), false, RevalidationMode::Hybrid, tx);

        let mut saw_done = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(AppEvent::ApplyProgress(p)) if p.phase == ApplyPhase::Done => {
                    saw_done = true;
                    break;
                }
                Ok(AppEvent::ApplyFinished(_)) => {
                    // The result arrived — the Done snapshot may have preceded it or come right after;
                    // we read out the remaining events until the deadline.
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        assert!(saw_done, "the poller must reach the Done phase");
    }
}
