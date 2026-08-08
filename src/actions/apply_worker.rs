// SPDX-License-Identifier: Apache-2.0
//! Background application of a batch of actions (mirror of `scan/worker.rs`): the UI doesn't freeze.
//! The worker thread enters through the GUARDED boundary — [`apply_guarded_with`] opens its own
//! apply lease, revalidates the plan's witness against the live membership and holds the lease
//! across the whole batch — a separate poller sends `ApplyProgress` ~6/s, at the end —
//! `ApplyFinished` with the typed [`ApplyOutcome`]. Cancellation (Esc) is a flag in
//! `ApplyShared`, checked at the action boundary: the snapshot is already made, what was applied
//! is in quarantine.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossbeam_channel::Sender;

use crate::model::action::RevalidationMode;
use crate::model::dataset::Dataset;
use crate::model::plan::ActionPlan;
use crate::panics;
use crate::tui::event::AppEvent;

use super::{apply_guarded_with, ApplyOutcome, ApplyPhase, ApplyShared, GuardedApply, RealOps};

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

/// Starts applying a plan in the background, through the guarded boundary. Progress and the
/// typed outcome go to `events`.
///
/// The worker takes the whole owning [`ActionPlan`]: the witness it owns is what the lease
/// revalidates, and a refusal hands exactly this plan back to its window inside
/// [`ApplyOutcome::Refused`] with zero filesystem work done.
pub fn spawn(
    db_path: PathBuf,
    plan: ActionPlan,
    datasets: Vec<Dataset>,
    reflink_safe: bool,
    mode: RevalidationMode,
    events: Sender<AppEvent>,
) -> ApplyHandle {
    spawn_job(events, move |shared| {
        match apply_guarded_with(
            &RealOps,
            &db_path,
            &plan,
            &datasets,
            reflink_safe,
            shared,
            mode,
        ) {
            GuardedApply::Refused(refusal) => ApplyOutcome::Refused {
                refusal,
                plan: Box::new(plan),
            },
            GuardedApply::Ran(Ok(batch)) => ApplyOutcome::Finished(batch),
            GuardedApply::Ran(Err(err)) => ApplyOutcome::Failed(err.to_string()),
        }
    })
}

/// The worker itself: poller, panic containment, terminal event. `spawn` hands it the real
/// guarded batch; the tests hand it a job that panics, which is the only way in to the
/// containment.
fn spawn_job<F>(events: Sender<AppEvent>, job: F) -> ApplyHandle
where
    F: FnOnce(&ApplyShared) -> ApplyOutcome + Send + 'static,
{
    let shared = Arc::new(ApplyShared::default());

    // Poller: ~6 progress snapshots per second, until the phase is Done. A separate thread —
    // the batch is a tight loop without a natural callback (unlike run_scan).
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

    // Worker thread: applies the batch and sends the outcome. A panic used to unwind it alone —
    // no ApplyFinished, and the Applying screen has no other way out.
    let work_shared = shared.clone();
    thread::spawn(move || {
        let outcome = match panics::guard_value("the apply worker", || job(&work_shared)) {
            Ok(outcome) => outcome,
            Err(text) => ApplyOutcome::Failed(text),
        };
        // We guarantee the Done phase even if the batch exited with an error BEFORE it
        // (for example, a snapshot failure) — otherwise the poller would spin forever.
        work_shared.set_phase(ApplyPhase::Done);
        let _ = events.send(AppEvent::ApplyFinished(Box::new(outcome)));
    });

    ApplyHandle { shared }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::action::{ActionKind, RevalidationMode};
    use crate::state::store::role_guard;
    use crate::testfixtures::PlanScenario;

    /// A real one-action plan over real files, published and planned through the production
    /// authority. Handed no datasets, so the action is refused for want of a mountpoint and
    /// nothing on the filesystem is touched — safe in Docker without a pool, while still
    /// exercising the whole lease/preflight/ledger path.
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

    fn recv_outcome(rx: &crossbeam_channel::Receiver<AppEvent>) -> ApplyOutcome {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(AppEvent::ApplyFinished(outcome)) => return *outcome,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        panic!("ApplyFinished must arrive");
    }

    /// spawn → the guarded batch runs → `ApplyFinished(Finished(BatchResult))` arrives.
    #[test]
    fn spawn_sends_finished() {
        let _role = role_guard();
        let (scenario, plan) = one_action_plan("worker_finished");
        let (tx, rx) = crossbeam_channel::unbounded();
        let _handle = spawn(
            scenario.db_path.clone(),
            plan,
            Vec::new(),
            false,
            RevalidationMode::Hybrid,
            tx,
        );

        match recv_outcome(&rx) {
            ApplyOutcome::Finished(batch) => {
                assert_eq!(batch.outcomes.len(), 1);
                assert_eq!(batch.failed(), 1, "no dataset, so nothing is applied");
            }
            ApplyOutcome::Refused { refusal, .. } => {
                panic!("a fresh plan over its own publication must not refuse: {refusal:?}")
            }
            ApplyOutcome::Failed(err) => panic!("the batch must run: {err}"),
        }
    }

    /// The worker catches membership drift with zero filesystem work: a republication after
    /// planning refuses the batch and hands the exact plan back.
    #[test]
    fn a_republished_membership_refuses_before_any_work() {
        use crate::state::PublishMode;
        let _role = role_guard();
        let (scenario, plan) = one_action_plan("worker_stale");
        {
            let mut store = scenario.store();
            let scan_id = plan.scan_id();
            store
                .publish_results(scan_id, PublishMode::Derived)
                .unwrap();
        }
        let expected = plan.clone();
        let (tx, rx) = crossbeam_channel::unbounded();
        let _handle = spawn(
            scenario.db_path.clone(),
            plan,
            Vec::new(),
            false,
            RevalidationMode::Hybrid,
            tx,
        );

        match recv_outcome(&rx) {
            ApplyOutcome::Refused { refusal, plan } => {
                assert!(
                    matches!(refusal, crate::actions::ApplyRefusal::Stale { .. }),
                    "generation drift is the typed reason: {refusal:?}"
                );
                assert_eq!(*plan, expected, "the exact plan comes back to its window");
            }
            ApplyOutcome::Finished(_) => panic!("a stale witness must never enter the batch"),
            ApplyOutcome::Failed(err) => panic!("a refusal is typed, not a failure: {err}"),
        }
    }

    /// Progress arrives and the phase reaches Done (the poller sends at least one snapshot).
    #[test]
    fn progress_reaches_done() {
        let _role = role_guard();
        let (scenario, plan) = one_action_plan("worker_progress");
        let (tx, rx) = crossbeam_channel::unbounded();
        let _handle = spawn(
            scenario.db_path.clone(),
            plan,
            Vec::new(),
            false,
            RevalidationMode::Hybrid,
            tx,
        );

        let mut saw_done = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(AppEvent::ApplyProgress(p)) if p.phase == ApplyPhase::Done => {
                    saw_done = true;
                    break;
                }
                Ok(AppEvent::ApplyFinished(_)) => {
                    // The outcome arrived — the Done snapshot may have preceded it or come right
                    // after; we read out the remaining events until the deadline.
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

        let mut finished: Option<ApplyOutcome> = None;
        let mut saw_done = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline && (finished.is_none() || !saw_done) {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(AppEvent::ApplyFinished(outcome)) => finished = Some(*outcome),
                Ok(AppEvent::ApplyProgress(p)) if p.phase == ApplyPhase::Done => saw_done = true,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        match finished.expect("ApplyFinished must arrive even when the batch panics") {
            ApplyOutcome::Failed(err) => assert!(
                err.contains("boom in the batch"),
                "the screen must show what happened: {err}"
            ),
            other => panic!(
                "a panic is a failure, not a result: {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert!(saw_done, "the poller must reach Done and stop");
    }
}
