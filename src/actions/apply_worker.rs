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

use crate::error::Result;
use crate::model::action::{BatchResult, RevalidationMode};
use crate::model::dataset::Dataset;
use crate::model::plan::ActionPlan;
use crate::panics;
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

/// Starts applying a plan in the background. Progress and result go to `events`.
///
/// The worker takes the whole owning [`ActionPlan`], not a vector of actions: the evidence that
/// justifies an action is what the preflights, the ledger and the post-run accounting all read, and
/// a worker handed the actions alone could not check any of it.
pub fn spawn(
    plan: ActionPlan,
    datasets: Vec<Dataset>,
    reflink_safe: bool,
    mode: RevalidationMode,
    events: Sender<AppEvent>,
) -> ApplyHandle {
    spawn_job(events, move |shared| {
        apply_batch(&plan, &datasets, reflink_safe, shared, mode)
    })
}

/// The worker itself: poller, panic containment, terminal event. `spawn` hands it the real batch;
/// the tests hand it a job that panics, which is the only way in to the containment.
fn spawn_job<F>(events: Sender<AppEvent>, job: F) -> ApplyHandle
where
    F: FnOnce(&ApplyShared) -> Result<BatchResult> + Send + 'static,
{
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

    // Worker thread: applies the batch and sends the result. A panic used to unwind it alone —
    // no ApplyFinished, and the Applying screen has no other way out.
    let work_shared = shared.clone();
    thread::spawn(move || {
        let result = panics::guard("the apply worker", || job(&work_shared));
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
    use crate::model::action::{ActionKind, BatchResult, RevalidationMode};
    use crate::testfixtures::PlanScenario;

    /// A real one-action plan over real files. Handed no datasets, so the action is refused for
    /// want of a mountpoint and nothing on the filesystem is touched — safe in Docker without a
    /// pool, while still exercising the whole preflight/ledger path.
    fn one_action_plan(tag: &str) -> (PlanScenario, ActionPlan) {
        let scenario = PlanScenario::new(tag);
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        drop(store);
        let plan = crate::actions::tests::plan_of(&scenario, scan_id);
        (scenario, plan)
    }

    /// spawn → applying a plan → `ApplyFinished(Ok(BatchResult))` arrives.
    #[test]
    fn spawn_sends_finished() {
        let (_scenario, plan) = one_action_plan("worker_finished");
        let (tx, rx) = crossbeam_channel::unbounded();
        let _handle = spawn(plan, Vec::new(), false, RevalidationMode::Hybrid, tx);

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
        let batch = result.expect("a plan the preflight accepts — Ok");
        assert_eq!(batch.outcomes.len(), 1);
        assert_eq!(batch.failed(), 1, "no dataset, so nothing is applied");
    }

    /// Progress arrives and the phase reaches Done (the poller sends at least one snapshot).
    #[test]
    fn progress_reaches_done() {
        let (_scenario, plan) = one_action_plan("worker_progress");
        let (tx, rx) = crossbeam_channel::unbounded();
        let _handle = spawn(plan, Vec::new(), false, RevalidationMode::Hybrid, tx);

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

    /// A panicking batch must still report. Without containment the thread unwinds without
    /// `ApplyFinished`, the poller spins on a phase that never becomes Done, and the Applying
    /// screen — which has no exit key of its own — waits for that event forever.
    #[test]
    fn a_panicking_batch_still_reports_finished() {
        let _lock = crate::panics::test_lock();
        let (tx, rx) = crossbeam_channel::unbounded();
        let _handle = spawn_job(tx, |_shared| panic!("boom in the batch"));

        let mut finished: Option<std::result::Result<BatchResult, String>> = None;
        let mut saw_done = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline && (finished.is_none() || !saw_done) {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(AppEvent::ApplyFinished(result)) => finished = Some(result),
                Ok(AppEvent::ApplyProgress(p)) if p.phase == ApplyPhase::Done => saw_done = true,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        let err = finished
            .expect("ApplyFinished must arrive even when the batch panics")
            .expect_err("a panic is an error, not a result");
        assert!(
            err.contains("boom in the batch"),
            "the screen must show what happened: {err}"
        );
        assert!(saw_done, "the poller must reach Done and stop");
    }
}
