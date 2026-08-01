// SPDX-License-Identifier: Apache-2.0
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::error::{AppError, Result};
use crate::model::action::{
    ActionKind, ActionOutcome, BatchResult, FileIdentity, RevalidationMode,
};
use crate::model::dataset::Dataset;
use crate::model::plan::{ActionPlan, ActionResult, PlanAction, PlanResult, RuntimeLedger};
use crate::pipeline::hash;
use crate::zfs::snapshots;

pub mod apply_worker;
pub mod delete;
pub mod hardlink;
pub mod meta;
pub mod move_dir;
pub mod move_file;
pub mod quarantine;
pub mod reflink;
pub mod script_preview;

/// Batch apply phase — for the background worker's progress bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ApplyPhase {
    /// Creating safety ZFS snapshots of the affected datasets.
    #[default]
    Snapshots = 0,
    /// Re-checking content and moving/linking actions.
    Applying = 1,
    /// Apply finished (success or error) — the poller stops.
    Done = 2,
}

impl ApplyPhase {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => ApplyPhase::Applying,
            2 => ApplyPhase::Done,
            _ => ApplyPhase::Snapshots,
        }
    }
}

/// Apply progress snapshot for the UI (sent by the worker poller ~6/s).
#[derive(Debug, Clone, Copy)]
pub struct ApplyProgress {
    pub phase: ApplyPhase,
    /// Index of the current action (0-based) — for highlighting/bar by action count.
    pub index: usize,
    /// Accumulated volume of re-checked bytes (filled during the Hybrid/Strict phase).
    pub bytes_done: u64,
}

/// Shared apply state: atomic progress counters + cancel flag.
/// The worker thread writes, the poller reads snapshots, the UI thread requests cancel (Esc).
#[derive(Default)]
pub struct ApplyShared {
    phase: AtomicU8,
    index: AtomicUsize,
    bytes_done: AtomicU64,
    cancel: AtomicBool,
}

impl ApplyShared {
    fn set_phase(&self, phase: ApplyPhase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Snapshot of the current progress — for sending to the UI as `ApplyProgress`.
    pub fn snapshot(&self) -> ApplyProgress {
        ApplyProgress {
            phase: ApplyPhase::from_u8(self.phase.load(Ordering::Relaxed)),
            index: self.index.load(Ordering::Relaxed),
            bytes_done: self.bytes_done.load(Ordering::Relaxed),
        }
    }
}

/// The operations a batch performs on things it does not own — the pool and the moment between
/// evacuating an original and publishing its replacement.
///
/// Production uses [`RealOps`]. A test substitutes its own so a drift can be injected at an exact
/// point in the sequence: what a batch does between two syscalls is not something a sleep or a
/// second thread can pin down, and a race that reproduces most of the time is not evidence.
pub trait ApplyOps {
    /// The safety snapshot of one dataset.
    fn create_snapshot(&self, dataset: &str, suffix: &str) -> Result<String>;

    /// Runs once after every snapshot exists and before the second whole-plan preflight.
    fn after_snapshots(&self) {}

    /// Runs before an action's ledger check, so a test can move the ground under it.
    fn before_action(&self, _index: usize) {}

    /// Runs after an original has been evacuated to quarantine and before its replacement takes
    /// the freed slot.
    fn before_publication(&self, _target: &Path, _replacement: &Path) {}
}

/// The real thing: a `zfs snapshot`, and no interference anywhere else.
pub struct RealOps;

impl ApplyOps for RealOps {
    fn create_snapshot(&self, dataset: &str, suffix: &str) -> Result<String> {
        snapshots::create_snapshot(dataset, suffix)
    }
}

/// What became of the original pathname, as the code that moved it knows it.
///
/// Typed rather than a message, because the caller has to decide what the allocation is worth and
/// where a recovery has to look — and «read the rollback state out of an error string» is how a
/// stranded original gets reported as a plain failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publication {
    /// The replacement is in place; the original is at this exact quarantine path.
    Published { quarantined: PathBuf },
    /// The original was never moved.
    NotMoved { detail: String },
    /// The original was evacuated, publication failed, and the original is back in its slot.
    RolledBack { detail: String },
    /// The original was evacuated, publication failed and so did the restore: it is still at this
    /// exact quarantine path and nothing is in its slot.
    Stranded {
        quarantined: PathBuf,
        detail: String,
    },
}

impl Publication {
    /// The message the operator reads, and the outcome the accounting reads, from one value.
    fn split(self) -> (Option<PathBuf>, ActionResult, Result<()>) {
        match self {
            Self::Published { quarantined } => (Some(quarantined), ActionResult::Removed, Ok(())),
            Self::NotMoved { detail } => (
                None,
                ActionResult::Refused { rolled_back: false },
                Err(AppError::msg(detail)),
            ),
            Self::RolledBack { detail } => (
                None,
                ActionResult::Refused { rolled_back: true },
                Err(AppError::msg(detail)),
            ),
            Self::Stranded {
                quarantined,
                detail,
            } => (
                Some(quarantined.clone()),
                ActionResult::Stranded {
                    quarantine: quarantined,
                    detail: detail.clone(),
                },
                Err(AppError::msg(detail)),
            ),
        }
    }
}

/// Unique snapshot/quarantine suffix: second-granularity timestamp +
/// nanoseconds + PID + per-process counter. This only MINIMIZES collisions (including
/// cross-process ones); the cross-process GUARANTEE of snapshot-name uniqueness is the
/// atomic create-and-retry in `zfs::snapshots::create_snapshot`. Shared between snapshot
/// names and quarantine directories.
pub(crate) fn snapshot_suffix() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let now = chrono::Local::now();
    format!(
        "{}-{:09}-{}-{seq}",
        now.format("%Y%m%d-%H%M%S"),
        now.timestamp_subsec_nanos(),
        std::process::id()
    )
}

/// Applies a plan: preflight -> snapshot the affected datasets -> preflight again -> apply.
pub fn apply_batch(
    plan: &ActionPlan,
    datasets: &[Dataset],
    reflink_safe: bool,
    shared: &ApplyShared,
    mode: RevalidationMode,
) -> Result<BatchResult> {
    apply_batch_with(&RealOps, plan, datasets, reflink_safe, shared, mode)
}

/// The batch itself, over an injectable set of outside operations.
///
/// The two whole-plan preflights are the shape of this function. The first runs before anything at
/// all exists, so a plan that no longer describes the disk costs nothing; the second runs after the
/// snapshots and immediately before the first mutation, because that is the last moment at which a
/// claim spanning several pathnames can still be checked as a whole. The second one is also what
/// the runtime ledger starts from — a scan-time row is stale the moment it is written.
pub fn apply_batch_with(
    ops: &dyn ApplyOps,
    plan: &ActionPlan,
    datasets: &[Dataset],
    reflink_safe: bool,
    shared: &ApplyShared,
    mode: RevalidationMode,
) -> Result<BatchResult> {
    let timestamp = snapshot_suffix();

    // 1. Structural preflight over the whole plan. Before the first snapshot, so a refusal here
    //    leaves the pool exactly as it was.
    shared.set_phase(ApplyPhase::Snapshots);
    plan.preflight()?;

    // 2. Affected datasets — by the device of each target allocation.
    let mut affected: Vec<&Dataset> = Vec::new();
    for action in plan.actions() {
        let device = plan.target_object_of(action).key().device;
        if let Some(dataset) = dataset_by_device(datasets, device) {
            if !affected.iter().any(|known| known.name == dataset.name) {
                affected.push(dataset);
            }
        }
    }

    // 3. Safety snapshots. A failure before the first one is an ordinary error; a failure after it
    //    still has to hand back the names of the snapshots that DO exist, or nobody can clean them
    //    up.
    let mut snapshots_made = Vec::new();
    for dataset in &affected {
        match ops.create_snapshot(&dataset.name, &timestamp) {
            Ok(name) => snapshots_made.push(name),
            Err(err) => {
                let detail = format!(
                    "failed to create snapshot {}: {err}; batch of actions cancelled",
                    dataset.name
                );
                if snapshots_made.is_empty() {
                    return Err(AppError::msg(detail));
                }
                return aborted_batch(plan, snapshots_made, detail);
            }
        }
    }

    ops.after_snapshots();

    // 4. The same structural check again, now that the snapshots exist — the last look before the
    //    first mutation. Its reading opens the ledger.
    let live = match plan.preflight() {
        Ok(live) => live,
        Err(refusal) => return aborted_batch(plan, snapshots_made, refusal.to_string()),
    };

    // 5. Applying actions. Cancellation (Esc) is checked at the action BOUNDARY — the snapshot
    //    already exists, what was applied to quarantine is reversible, the partial result is
    //    consistent.
    shared.set_phase(ApplyPhase::Applying);
    let mut batch = Batch {
        ops,
        plan,
        datasets,
        timestamp,
        reflink_safe,
        mode,
        verified: HashMap::new(),
        quarantine_dirs: Vec::new(),
        ledger: RuntimeLedger::open(live),
    };
    let mut outcomes = Vec::new();
    let mut results: Vec<ActionResult> = Vec::new();
    let mut cancelled = false;
    for index in 0..plan.actions().len() {
        if shared.is_cancelled() {
            // The rest of the batch was never attempted. Reported as such, so the caller does not
            // read a partial run as a finished one and throw the remaining marks away.
            cancelled = true;
            break;
        }
        shared.index.store(index, Ordering::Relaxed);
        let (outcome, result) = batch.apply_one(index, &shared.bytes_done);
        outcomes.push(outcome);
        results.push(result);
    }

    shared.set_phase(ApplyPhase::Done);
    let (realized, realized_summary) = plan.realize(&results)?;
    Ok(BatchResult {
        outcomes,
        snapshots: snapshots_made,
        quarantine_dirs: batch.quarantine_dirs,
        planned: plan.actions().len(),
        cancelled,
        aborted: None,
        plan: plan.summary().clone(),
        realized,
        realized_summary,
        bytes_read: shared.bytes_done.load(Ordering::Relaxed),
    })
}

/// A batch that stopped as a whole once the snapshots existed: nothing was applied, and every
/// snapshot already made is named so it can be cleaned up.
fn aborted_batch(plan: &ActionPlan, snapshots: Vec<String>, detail: String) -> Result<BatchResult> {
    let (realized, realized_summary) = plan.realize(&[])?;
    Ok(BatchResult {
        outcomes: Vec::new(),
        snapshots,
        quarantine_dirs: Vec::new(),
        planned: plan.actions().len(),
        cancelled: false,
        aborted: Some(detail),
        plan: plan.summary().clone(),
        realized,
        realized_summary,
        bytes_read: 0,
    })
}

/// Everything one running batch carries between its actions.
struct Batch<'a> {
    ops: &'a dyn ApplyOps,
    plan: &'a ActionPlan,
    datasets: &'a [Dataset],
    timestamp: String,
    reflink_safe: bool,
    mode: RevalidationMode,
    /// Per-batch cache of re-checked files (Hybrid): the keeper is hashed once per batch, the
    /// repeat check is a re-stat by `FileIdentity` (we don't re-read).
    verified: HashMap<PathBuf, FileIdentity>,
    quarantine_dirs: Vec<PathBuf>,
    ledger: RuntimeLedger,
}

impl Batch<'_> {
    fn apply_one(
        &mut self,
        index: usize,
        bytes_progress: &AtomicU64,
    ) -> (ActionOutcome, ActionResult) {
        self.ops.before_action(index);
        let action = &self.plan.actions()[index];
        // The ledger first: both allocations must still be the ones the batch has been driving.
        // The keeper as well as the target — a keeper somebody replaced underneath us is what a
        // per-target check cannot see.
        if let Err(refusal) = self
            .ledger
            .check(action.target_object())
            .and_then(|()| self.ledger.check(action.keeper_object()))
        {
            return refused(action, refusal.to_string());
        }
        // Final content re-check: if the file changed after the scan —
        // we do not perform the action, otherwise we would destroy current data.
        if let Err(err) = revalidate(action, self.mode, &mut self.verified, bytes_progress) {
            return refused(action, err.to_string());
        }
        match action.kind() {
            ActionKind::Delete => self.apply_delete(action),
            ActionKind::Hardlink => self.apply_hardlink(action),
            ActionKind::Reflink => self.apply_reflink(action),
        }
    }

    fn apply_delete(&mut self, action: &PlanAction) -> (ActionOutcome, ActionResult) {
        let Some(dataset) = self.target_dataset(action) else {
            return refused(
                action,
                "target file's dataset could not be determined".to_string(),
            );
        };
        let dir = quarantine::quarantine_dir(&dataset.mountpoint, &self.timestamp);
        let moved = match delete::delete_to_quarantine(action.target(), &dataset.mountpoint, &dir) {
            Ok(path) => path,
            Err(err) => return refused(action, err.to_string()),
        };
        self.note_quarantine(dir);
        self.after_move(action, &moved, None)
    }

    fn apply_hardlink(&mut self, action: &PlanAction) -> (ActionOutcome, ActionResult) {
        if self.plan.target_object_of(action).key().device
            != self.plan.keeper_object_of(action).key().device
        {
            return refused(
                action,
                "cross-dataset hardlink is impossible — files are in different datasets"
                    .to_string(),
            );
        }
        // Without an identified ZFS dataset there will be neither a snapshot nor a quarantine to
        // evacuate the original into — we refuse (symmetric to the Delete branch).
        let Some(dataset) = self.target_dataset(action) else {
            return refused(
                action,
                "target file's dataset could not be determined — hardlink is not performed without a ZFS snapshot".to_string(),
            );
        };
        let dir = quarantine::quarantine_dir(&dataset.mountpoint, &self.timestamp);
        let mountpoint = dataset.mountpoint.clone();
        let published = hardlink::hardlink(
            self.ops,
            action.target(),
            action.keeper(),
            &mountpoint,
            &dir,
        );
        self.finish_publication(action, dir, published, Linkage::Hardlink)
    }

    fn apply_reflink(&mut self, action: &PlanAction) -> (ActionOutcome, ActionResult) {
        if !self.reflink_safe {
            return refused(
                action,
                "reflink is unavailable on this host — needs ZFS 2.3+ with block cloning enabled"
                    .to_string(),
            );
        }
        let target_dataset = self.target_dataset(action);
        let target_pool = target_dataset.map(|dataset| dataset.pool_name().to_string());
        let keeper_pool = dataset_by_device(
            self.datasets,
            self.plan.keeper_object_of(action).key().device,
        )
        .map(|dataset| dataset.pool_name().to_string());
        let same_pool = target_pool.is_some() && target_pool == keeper_pool;
        let Some(dataset) = target_dataset.filter(|_| same_pool) else {
            return refused(
                action,
                "reflink is impossible — files are in different ZFS pools".to_string(),
            );
        };
        let dir = quarantine::quarantine_dir(&dataset.mountpoint, &self.timestamp);
        let mountpoint = dataset.mountpoint.clone();
        let published = reflink::reflink(
            self.ops,
            action.target(),
            action.keeper(),
            &mountpoint,
            &dir,
        );
        self.finish_publication(action, dir, published, Linkage::Reflink)
    }

    /// The common tail of hardlink/reflink: record the quarantine directory, then let the ledger
    /// adopt exactly the transition the kernel performed.
    fn finish_publication(
        &mut self,
        action: &PlanAction,
        dir: PathBuf,
        published: Publication,
        linkage: Linkage,
    ) -> (ActionOutcome, ActionResult) {
        let quarantined = match &published {
            Publication::Published { quarantined } | Publication::Stranded { quarantined, .. } => {
                Some(quarantined.clone())
            }
            _ => None,
        };
        if quarantined.is_some() {
            self.note_quarantine(dir);
        }
        match (&published, quarantined) {
            (Publication::Published { .. }, Some(moved)) => {
                self.after_move(action, &moved, Some(linkage))
            }
            _ => {
                // The attempt failed, but it still ran: the keeper's `ctime` moved when the
                // temporary link was made and unmade, and a rolled-back original's moved when it
                // went to quarantine and back. Those are this batch's own marks; adopting them is
                // what keeps the NEXT action on those allocations from being refused for a change
                // nobody outside made. A settle that does NOT add up is not swallowed: the
                // allocation stops being trusted and the operator is told, in the same message.
                let target_settle = match &published {
                    Publication::Stranded { quarantined, .. } => self.ledger.quarantined(
                        action.target_object(),
                        action.target(),
                        quarantined,
                    ),
                    _ => self.ledger.settled(action.target_object(), action.target()),
                };
                let unaccounted = self.settle_or_poison(action.target_object(), target_settle);
                let keeper_settle = self.ledger.settled(action.keeper_object(), action.keeper());
                let unaccounted = unaccounted
                    .or_else(|| self.settle_or_poison(action.keeper_object(), keeper_settle));
                let (quarantine, result, outcome) = published.split();
                let mut detail = outcome.err().map(|err| err.to_string()).unwrap_or_default();
                if let Some(extra) = unaccounted {
                    detail.push_str(&format!("; {extra}"));
                }
                (
                    ActionOutcome {
                        kind: action.kind(),
                        target: action.target().to_path_buf(),
                        quarantine,
                        result: Err(detail),
                    },
                    result,
                )
            }
        }
    }

    /// The ledger transitions of one successful action, in the order the kernel made them.
    fn after_move(
        &mut self,
        action: &PlanAction,
        moved: &Path,
        linkage: Option<Linkage>,
    ) -> (ActionOutcome, ActionResult) {
        let transition = self
            .ledger
            .quarantined(action.target_object(), action.target(), moved)
            .and_then(|()| match linkage {
                None => Ok(()),
                Some(Linkage::Hardlink) => {
                    self.ledger
                        .linked(action.keeper_object(), action.keeper(), action.target())
                }
                Some(Linkage::Reflink) => self.ledger.cloned(
                    action.keeper_object(),
                    action.keeper(),
                    action.target(),
                    self.plan.target_object_of(action).key().device,
                ),
            });
        // The pathname moved, and yet the reading that would justify a claim is the one that
        // disagreed. Calling this `Removed` is how a batch promised an allocation's worth of space
        // that a late outside link was quietly holding: the syscall succeeded, so the old code
        // folded `Completed` while the ledger was saying it could not tell what had happened.
        // Neither allocation is trusted again, and the object claims nothing.
        match transition {
            Ok(()) => (
                ActionOutcome {
                    kind: action.kind(),
                    target: action.target().to_path_buf(),
                    quarantine: Some(moved.to_path_buf()),
                    result: Ok(()),
                },
                ActionResult::Removed,
            ),
            Err(refusal) => {
                self.ledger.poison(action.target_object());
                self.ledger.poison(action.keeper_object());
                let detail = refusal.to_string();
                (
                    ActionOutcome {
                        kind: action.kind(),
                        target: action.target().to_path_buf(),
                        quarantine: Some(moved.to_path_buf()),
                        result: Err(detail.clone()),
                    },
                    ActionResult::Unsettled {
                        quarantine: moved.to_path_buf(),
                        detail,
                    },
                )
            }
        }
    }

    /// Records a settle attempt: on failure the allocation is poisoned and the reason returned so
    /// the caller can put it in front of the operator. Never discarded.
    fn settle_or_poison(&mut self, object: usize, outcome: PlanResult<()>) -> Option<String> {
        match outcome {
            Ok(()) => None,
            Err(refusal) => {
                self.ledger.poison(object);
                Some(refusal.to_string())
            }
        }
    }

    fn target_dataset(&self, action: &PlanAction) -> Option<&'_ Dataset> {
        dataset_by_device(
            self.datasets,
            self.plan.target_object_of(action).key().device,
        )
    }

    fn note_quarantine(&mut self, dir: PathBuf) {
        if !self.quarantine_dirs.contains(&dir) {
            self.quarantine_dirs.push(dir);
        }
    }
}

/// Which kind of replacement was published into the freed slot.
#[derive(Debug, Clone, Copy)]
enum Linkage {
    Hardlink,
    Reflink,
}

/// An action that never moved anything.
fn refused(action: &PlanAction, detail: String) -> (ActionOutcome, ActionResult) {
    (
        ActionOutcome {
            kind: action.kind(),
            target: action.target().to_path_buf(),
            quarantine: None,
            result: Err(detail),
        },
        ActionResult::Refused { rolled_back: false },
    )
}

/// Safe publication of a `target` replacement (hardlink/reflink) WITHOUT destroy-in-place.
/// Previously hardlink/reflink did `fs::rename(temp, target)` and overwrote the target —
/// a change to `target` after the safety snapshot was lost irrecoverably (only
/// delete was safe, via quarantine). Now: (1) build the replacement under a temporary
/// name (`build`); (2) evacuate the current `target` to quarantine atomically (like
/// delete — the original is recoverable, not overwritten); (3) publish the replacement into
/// the freed slot. If publication fails (the slot is occupied/disappeared between steps),
/// the original is restored from quarantine.
///
/// Every arm is a typed [`Publication`]: where the original is, and whether it moved at all, is not
/// something the caller should have to read out of a sentence.
fn evacuate_then_publish(
    ops: &dyn ApplyOps,
    target: &Path,
    build: impl FnOnce(&Path) -> Result<()>,
    mountpoint: &Path,
    quarantine_dir: &Path,
) -> Publication {
    let Some(parent) = target.parent() else {
        return Publication::NotMoved {
            detail: "target file has no parent directory".to_string(),
        };
    };
    let temp = move_file::staging_path(parent, target.file_name());
    // (1) Build the replacement under a temporary name; on error — target is untouched.
    if let Err(err) = build(&temp) {
        let _ = std::fs::remove_file(&temp);
        return Publication::NotMoved {
            detail: err.to_string(),
        };
    }
    // (2) Evacuate the current target to quarantine (atomically); on error — target is untouched.
    let evacuated = match delete::delete_to_quarantine(target, mountpoint, quarantine_dir) {
        Ok(path) => path,
        Err(err) => {
            let _ = std::fs::remove_file(&temp);
            return Publication::NotMoved {
                detail: err.to_string(),
            };
        }
    };
    ops.before_publication(target, &temp);
    // (3) Publish the replacement into the freed target slot.
    match move_file::rename_noreplace(&temp, target) {
        Ok(()) => Publication::Published {
            quarantined: evacuated,
        },
        Err(_) => {
            // The target slot is occupied/disappeared between evacuation and publication — we roll
            // back: return the original from quarantine, delete the temp replacement.
            let _ = std::fs::remove_file(&temp);
            if move_file::rename_noreplace(&evacuated, target).is_ok() {
                Publication::RolledBack {
                    detail: format!(
                        "{} changed at the moment of applying — action cancelled, original restored",
                        target.display()
                    ),
                }
            } else {
                Publication::Stranded {
                    detail: format!(
                        "{} occupied during publication — original preserved in quarantine: {}",
                        target.display(),
                        evacuated.display()
                    ),
                    quarantined: evacuated,
                }
            }
        }
    }
}

fn dataset_by_device(datasets: &[Dataset], device: u64) -> Option<&Dataset> {
    datasets
        .iter()
        .find(|dataset| dataset.device_id == Some(device))
}

/// Final re-check before a destructive action: `target` and `keeper`
/// must still have the hash `expected_hash`. Without it a file changed after
/// the scan would be overwritten (data loss).
///
/// TOCTOU: operations go by PATH, not by fd, so the "check→action" window
/// exists. Mitigated in layers: the batch's two structural preflights and its safety ZFS snapshot,
/// the runtime ledger, atomic publication via `renameat2(RENAME_NOREPLACE)`
/// (`evacuate_then_publish`), a repeated symlink check at the moment of the action, and evacuation
/// of the original to quarantine (recoverable). Fully closing it (opening by fd + `O_NOFOLLOW`) is
/// a separate large rework; for the "one admin on their own pool" model it is deliberately
/// deferred.
fn revalidate(
    action: &PlanAction,
    mode: RevalidationMode,
    verified: &mut HashMap<PathBuf, FileIdentity>,
    bytes_progress: &AtomicU64,
) -> Result<()> {
    verify_file(
        action.target(),
        action.size(),
        action.expected_hash(),
        "target",
        mode,
        verified,
        bytes_progress,
    )?;
    verify_file(
        action.keeper(),
        action.size(),
        action.expected_hash(),
        "keeper",
        mode,
        verified,
        bytes_progress,
    )?;
    Ok(())
}

/// Checks that `path` is not a symbolic link and still has size
/// `expected_size` and blake3 hash `expected_hash`. `role` — for the error text.
///
/// Symlink and size checks are done ALWAYS (cheap). Content hash: in Strict —
/// every time; in Hybrid — skipped if the file has already been re-checked in this batch and
/// has not changed since (`verified[path] == current FileIdentity`, re-stat-guard).
/// Read bytes accumulate in `bytes_progress` (the batch's shared counter) — for the bar.
#[allow(clippy::too_many_arguments)]
fn verify_file(
    path: &Path,
    expected_size: u64,
    expected_hash: &str,
    role: &str,
    mode: RevalidationMode,
    verified: &mut HashMap<PathBuf, FileIdentity>,
    bytes_progress: &AtomicU64,
) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|err| AppError::msg(format!("{role} {}: {err}", path.display())))?;
    if meta.file_type().is_symlink() {
        return Err(AppError::msg(format!(
            "{role} {} — symbolic link; action cancelled",
            path.display()
        )));
    }
    if meta.len() != expected_size {
        return Err(AppError::msg(format!(
            "{role} {} changed after the scan (size) — action cancelled",
            path.display()
        )));
    }
    let current = FileIdentity::from_metadata(&meta);
    // Hybrid: the file has already been re-checked in THIS batch and has not changed since (re-stat) —
    // the content is already confirmed by the hash; we don't re-read (saving on the keeper).
    if mode != RevalidationMode::Strict {
        if let Some(prev) = verified.get(path) {
            if *prev == current {
                return Ok(());
            }
        }
    }
    let digest = hash::hash_file(path, bytes_progress)
        .map_err(|err| AppError::msg(format!("{role} {}: {err}", path.display())))?;
    if hex32(&digest) != expected_hash {
        return Err(AppError::msg(format!(
            "{role} {} changed after the scan (content) — action cancelled",
            path.display()
        )));
    }
    // Remember the identity for reuse within the batch (Hybrid).
    if mode != RevalidationMode::Strict {
        verified.insert(path.to_path_buf(), current);
    }
    Ok(())
}

/// How many bytes the batch re-validation will read — for the apply progress bar.
/// Strict: 2×size per action (target+keeper read every time). Hybrid/Fast:
/// each target + each UNIQUE keeper once (per-batch cache).
pub fn verify_bytes_total(plan: &ActionPlan, mode: RevalidationMode) -> u64 {
    let actions = plan.actions();
    if mode == RevalidationMode::Strict {
        return actions
            .iter()
            .map(|action| action.size().saturating_mul(2))
            .sum();
    }
    let targets: u64 = actions.iter().map(|action| action.size()).sum();
    let mut seen: HashSet<&Path> = HashSet::new();
    let keepers: u64 = actions
        .iter()
        .filter(|action| seen.insert(action.keeper()))
        .map(|action| action.size())
        .sum();
    targets.saturating_add(keepers)
}

/// hex-encoding of a 32-byte hash.
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::plan::{ObjectRealization, ZeroReason};
    use crate::testfixtures::PlanScenario;
    use std::cell::RefCell;
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt;

    /// Unique temporary directory for the test.
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "dedcom_actions_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, content: &[u8]) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(content).unwrap();
    }

    /// A scripted stand-in for the pool and for the instant between evacuation and publication.
    ///
    /// Nothing here waits on anything: the hooks fire at exactly one point in the sequence, so a
    /// drift injected by one of them is injected at that point every single run.
    /// Fires before an action's ledger check, with the action's index.
    type ActionHook = Option<Box<dyn FnMut(usize)>>;
    /// Fires between the evacuation and the publication, with the target and the replacement.
    type PublicationHook = Option<Box<dyn FnMut(&Path, &Path)>>;

    pub(crate) struct FakeOps {
        snapshots: RefCell<Vec<String>>,
        /// The snapshot of this dataset fails.
        refuse: Option<String>,
        after_snapshots: RefCell<Option<Box<dyn FnOnce()>>>,
        before_action: RefCell<ActionHook>,
        before_publication: RefCell<PublicationHook>,
    }

    impl FakeOps {
        pub(crate) fn new() -> Self {
            Self {
                snapshots: RefCell::new(Vec::new()),
                refuse: None,
                after_snapshots: RefCell::new(None),
                before_action: RefCell::new(None),
                before_publication: RefCell::new(None),
            }
        }

        pub(crate) fn refusing(mut self, dataset: &str) -> Self {
            self.refuse = Some(dataset.to_string());
            self
        }

        pub(crate) fn on_after_snapshots(self, hook: impl FnOnce() + 'static) -> Self {
            *self.after_snapshots.borrow_mut() = Some(Box::new(hook));
            self
        }

        pub(crate) fn on_before_action(self, hook: impl FnMut(usize) + 'static) -> Self {
            *self.before_action.borrow_mut() = Some(Box::new(hook));
            self
        }

        pub(crate) fn on_before_publication(
            self,
            hook: impl FnMut(&Path, &Path) + 'static,
        ) -> Self {
            *self.before_publication.borrow_mut() = Some(Box::new(hook));
            self
        }

        pub(crate) fn made(&self) -> Vec<String> {
            self.snapshots.borrow().clone()
        }
    }

    impl ApplyOps for FakeOps {
        fn create_snapshot(&self, dataset: &str, suffix: &str) -> Result<String> {
            if self.refuse.as_deref() == Some(dataset) {
                return Err(AppError::msg("no pool here"));
            }
            let name = format!("{dataset}@dedcom-{suffix}");
            self.snapshots.borrow_mut().push(name.clone());
            Ok(name)
        }

        fn after_snapshots(&self) {
            if let Some(hook) = self.after_snapshots.borrow_mut().take() {
                hook();
            }
        }

        fn before_action(&self, index: usize) {
            if let Some(hook) = self.before_action.borrow_mut().as_mut() {
                hook(index);
            }
        }

        fn before_publication(&self, target: &Path, replacement: &Path) {
            if let Some(hook) = self.before_publication.borrow_mut().as_mut() {
                hook(target, replacement);
            }
        }
    }

    /// A dataset covering the scenario's root, so the batch can find a mountpoint to quarantine
    /// into without a pool.
    pub(crate) fn dataset_over(root: &Path, name: &str) -> Dataset {
        Dataset {
            name: name.to_string(),
            mountpoint: root.to_path_buf(),
            device_id: Some(std::fs::symlink_metadata(root).unwrap().dev()),
            snapdir_visible: false,
        }
    }

    fn run(ops: &dyn ApplyOps, plan: &ActionPlan, datasets: &[Dataset]) -> Result<BatchResult> {
        apply_batch_with(
            ops,
            plan,
            datasets,
            true,
            &ApplyShared::default(),
            RevalidationMode::Hybrid,
        )
    }

    /// The plan the store builds for `scenario` from the marks already persisted in it.
    pub(crate) fn plan_of(scenario: &PlanScenario, scan_id: i64) -> ActionPlan {
        scenario
            .store()
            .build_action_plan(scan_id, &[])
            .expect("the scenario's marks make a plan")
    }

    /// Two independent twins, one deleted: the plain case every other one is measured against.
    #[test]
    fn a_covered_twin_is_completed_for_its_own_size() {
        let scenario = PlanScenario::new("realize_twin");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        let ops = FakeOps::new();
        let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();

        assert_eq!(batch.succeeded(), 1, "{:?}", batch.outcomes);
        assert_eq!(batch.realized_summary.completed_objects(), 1);
        assert_eq!(
            batch.realized_summary.guaranteed_bytes(),
            std::fs::metadata(&keeper).unwrap().size(),
            "one allocation really goes"
        );
        assert!(!twin.exists(), "the target moved to quarantine");
        assert_eq!(batch.quarantined_paths().len(), 1);
    }

    /// The C5 defect in the accounting: two pathnames of ONE allocation are one allocation's worth,
    /// and if only one of them goes the allocation is worth nothing at all.
    #[test]
    fn two_aliases_are_one_allocation_and_a_partial_one_is_zero() {
        let scenario = PlanScenario::new("realize_alias");
        let keeper = scenario.file("keeper.bin");
        let alias_a = scenario.file("alias_a.bin");
        let alias_b = scenario.link(&alias_a, "alias_b.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_a.clone(), alias_b.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_a,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &alias_b,
            false,
            Some(ActionKind::Delete),
        );
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        assert_eq!(plan.actions().len(), 2, "two pathnames are removed");
        assert_eq!(plan.summary().covered_objects(), 1, "of one allocation");

        let ops = FakeOps::new();
        let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();
        assert_eq!(batch.succeeded(), 2);
        assert_eq!(
            batch.realized_summary.guaranteed_bytes(),
            std::fs::metadata(&keeper).unwrap().size(),
            "one allocation, counted once — not once per pathname"
        );
    }

    /// A pathname of the allocation that the plan never covered keeps every block, so the plan is
    /// worth nothing however well it runs.
    #[test]
    fn an_uncovered_alias_realizes_zero() {
        let scenario = PlanScenario::new("realize_uncovered");
        let keeper = scenario.file("keeper.bin");
        let alias_a = scenario.file("alias_a.bin");
        let alias_b = scenario.link(&alias_a, "alias_b.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), alias_a.clone(), alias_b]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_a,
            false,
            Some(ActionKind::Delete),
        );
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        assert_eq!(plan.summary().guaranteed_bytes(), 0);

        let ops = FakeOps::new();
        let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();
        assert_eq!(batch.succeeded(), 1, "the action itself is fine");
        assert_eq!(batch.realized_summary.guaranteed_bytes(), 0);
        assert!(
            matches!(
                batch.realized.first().map(|(_, state)| state),
                Some(ObjectRealization::Zero {
                    reason: ZeroReason::NotFullyCovered
                })
            ),
            "{:?}",
            batch.realized
        );
    }

    /// A link this scan never saw keeps the allocation alive: the ceiling stays, the guarantee is
    /// zero, and the batch says so afterwards too.
    #[test]
    fn an_external_link_realizes_zero_with_the_ceiling_intact() {
        let scenario = PlanScenario::new("realize_external");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let _outside = scenario.outside_link(&twin, "elsewhere.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        let size = std::fs::metadata(&keeper).unwrap().size();
        assert_eq!(plan.summary().guaranteed_bytes(), 0);
        assert_eq!(plan.summary().potential_bytes(), Some(size));

        let ops = FakeOps::new();
        let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();
        assert_eq!(batch.realized_summary.guaranteed_bytes(), 0);
        assert!(
            matches!(
                batch.realized.first().map(|(_, state)| state),
                Some(ObjectRealization::Zero {
                    reason: ZeroReason::ExternalLinks
                })
            ),
            "{:?}",
            batch.realized
        );
    }

    /// The first preflight is the one that costs nothing: a covered pathname that vanished between
    /// the confirmation and [Y] stops the batch before a snapshot exists.
    #[test]
    fn a_vanished_alias_stops_the_batch_before_the_first_snapshot() {
        let scenario = PlanScenario::new("preflight_first");
        let keeper = scenario.file("keeper.bin");
        let alias_a = scenario.file("alias_a.bin");
        let alias_b = scenario.link(&alias_a, "alias_b.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_a.clone(), alias_b.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_a,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &alias_b,
            false,
            Some(ActionKind::Delete),
        );
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        // The plan is confirmed; then the second alias goes away behind our back.
        std::fs::remove_file(&alias_b).unwrap();

        let ops = FakeOps::new();
        let err = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")])
            .expect_err("the plan no longer describes the disk");
        // Unlinking one pathname of an allocation is visible on its siblings too — the inode's
        // link count and `ctime` both move — so the refusal names the first member of that
        // allocation the preflight reaches.
        assert!(
            err.to_string().contains(&alias_a.display().to_string()),
            "the refusal names the pathname: {err}"
        );
        assert!(ops.made().is_empty(), "no snapshot was created");
        assert!(alias_a.exists(), "and nothing was moved");
        assert!(
            !scenario
                .root
                .join(crate::model::scan::QUARANTINE_DIR_NAME)
                .exists(),
            "no quarantine was created either"
        );
    }

    /// Without a safety snapshot nothing is applied at all — the batch fails before it starts.
    #[test]
    fn a_refused_snapshot_applies_nothing() {
        let scenario = PlanScenario::new("snapshot_refused");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        let ops = FakeOps::new().refusing("tank/test");
        let err = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")])
            .expect_err("no snapshot, no batch");
        assert!(err.to_string().contains("tank/test"), "{err}");
        assert!(twin.exists(), "nothing was moved");
    }

    #[test]
    fn snapshot_suffix_is_unique_per_call() {
        // hardening: the counter makes suffixes different even within the same second.
        assert_ne!(snapshot_suffix(), snapshot_suffix());
    }

    /// The second preflight is the one that has to hand its snapshots back: drift found after they
    /// exist must not become an error string with the names inside it.
    #[test]
    fn drift_after_the_snapshots_aborts_and_still_reports_them() {
        let scenario = PlanScenario::new("preflight_second");
        let keeper = scenario.file("keeper.bin");
        let alias_a = scenario.file("alias_a.bin");
        let alias_b = scenario.link(&alias_a, "alias_b.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_a.clone(), alias_b.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_a,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &alias_b,
            false,
            Some(ActionKind::Delete),
        );
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        let doomed = alias_b.clone();
        let ops = FakeOps::new().on_after_snapshots(move || {
            std::fs::remove_file(&doomed).unwrap();
        });
        let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();

        assert_eq!(ops.made().len(), 1, "the snapshot really was taken");
        assert_eq!(
            batch.snapshots,
            ops.made(),
            "and the result names it so it can be destroyed"
        );
        let aborted = batch.aborted.expect("the batch refused itself");
        assert!(
            aborted.contains(&alias_a.display().to_string()),
            "naming what moved: {aborted}"
        );
        assert!(batch.outcomes.is_empty(), "no action ran");
        assert!(alias_a.exists(), "nothing was moved");
    }

    /// The ledger's whole purpose: action 1's OWN effect on the keeper is accepted by action 2,
    /// while the identical change made by somebody else is refused.
    #[test]
    fn the_ledger_accepts_its_own_hardlink_and_refuses_an_outsider() {
        for outsider in [false, true] {
            let tag = if outsider { "ledger_out" } else { "ledger_own" };
            let scenario = PlanScenario::new(tag);
            let keeper = scenario.file("keeper.bin");
            let twin_a = scenario.file("twin_a.bin");
            let twin_b = scenario.file("twin_b.bin");
            let mut store = scenario.store();
            let scan_id = scenario.seed(
                &mut store,
                &[keeper.clone(), twin_a.clone(), twin_b.clone()],
            );
            scenario.mark(&mut store, scan_id, &keeper, true, None);
            scenario.mark(
                &mut store,
                scan_id,
                &twin_a,
                false,
                Some(ActionKind::Hardlink),
            );
            scenario.mark(
                &mut store,
                scan_id,
                &twin_b,
                false,
                Some(ActionKind::Hardlink),
            );
            drop(store);

            let plan = plan_of(&scenario, scan_id);
            let ops = FakeOps::new();
            // The outsider links the keeper somewhere of their own between the two actions — the
            // same nlink and ctime move the tool itself makes one line earlier, from a source the
            // ledger never saw.
            let intruder = scenario.outside.join("intruder.bin");
            let keeper_for_hook = keeper.clone();
            let ops = if outsider {
                ops.on_before_action(move |index| {
                    if index == 1 {
                        std::fs::hard_link(&keeper_for_hook, &intruder).unwrap();
                    }
                })
            } else {
                ops
            };
            let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();

            if outsider {
                assert_eq!(
                    batch.failed(),
                    1,
                    "the second action must refuse a keeper somebody else linked: {:?}",
                    batch.outcomes
                );
                let message = batch.outcomes[1].result.as_ref().unwrap_err();
                assert!(
                    message.contains("moved while the batch was running")
                        && message.contains("keeper.bin"),
                    "and say what it found: {message}"
                );
            } else {
                assert_eq!(
                    batch.failed(),
                    0,
                    "the tool's own link count and ctime must be accepted: {:?}",
                    batch.outcomes
                );
                assert_eq!(batch.realized_summary.completed_objects(), 2);
            }
        }
    }

    /// A publication that fails after the original is evacuated: restored is a plain zero, and
    /// stranded is an unknown that names the exact quarantine path.
    #[test]
    fn a_failed_publication_is_zero_when_restored_and_unknown_when_not() {
        for stranded in [false, true] {
            let tag = if stranded { "pub_strand" } else { "pub_back" };
            let scenario = PlanScenario::new(tag);
            let keeper = scenario.file("keeper.bin");
            let twin = scenario.file("twin.bin");
            let mut store = scenario.store();
            let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
            scenario.mark(&mut store, scan_id, &keeper, true, None);
            scenario.mark(
                &mut store,
                scan_id,
                &twin,
                false,
                Some(ActionKind::Hardlink),
            );
            drop(store);

            let plan = plan_of(&scenario, scan_id);
            let ops = FakeOps::new().on_before_publication(move |target, temp| {
                // Losing the replacement leaves the slot free, so the original goes back. Occupying
                // the slot as well leaves nowhere to put it back to.
                std::fs::remove_file(temp).unwrap();
                if stranded {
                    std::fs::write(target, b"squatter").unwrap();
                }
            });
            let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();

            assert_eq!(batch.failed(), 1);
            let (_, state) = &batch.realized[0];
            if stranded {
                let ObjectRealization::Unknown { quarantine, .. } = state else {
                    panic!("a stranded original is not a plain zero: {state:?}");
                };
                let quarantine = quarantine.as_ref().expect("the exact path is the recovery");
                assert!(quarantine.exists(), "{}", quarantine.display());
            } else {
                assert!(
                    matches!(
                        state,
                        ObjectRealization::Zero {
                            reason: ZeroReason::RolledBack
                        }
                    ),
                    "{state:?}"
                );
                assert!(twin.exists(), "the original is back in its slot");
            }
        }
    }

    /// Anything named `name` under `dir`, however deep — the quarantine mirrors the source tree.
    fn find_under(dir: &Path, name: &std::ffi::OsStr) -> Option<PathBuf> {
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = find_under(&path, name) {
                    return Some(found);
                }
            } else if path.file_name() == Some(name) {
                return Some(path);
            }
        }
        None
    }

    /// The C5-2a defect: the syscall succeeded, the ledger could not account for what it left, and
    /// the accounting folded the allocation as fully released anyway.
    ///
    /// While the hardlink is being published, the ORIGINAL — already in quarantine — is given a
    /// second pathname outside the scan. Purging the quarantine now releases nothing, because that
    /// outside link holds every block. The action must not report a completed allocation, and the
    /// allocations it touched must stop authorizing later work.
    #[test]
    fn a_late_outside_link_realizes_unknown_and_poisons_the_allocations() {
        let _role = crate::state::store::role_guard();
        let scenario = PlanScenario::new("late_outside_link");
        let keeper = scenario.file("keeper.bin");
        let first = scenario.file("twin_a.bin");
        let second = scenario.file("twin_b.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), first.clone(), second.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &first,
            false,
            Some(ActionKind::Hardlink),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &second,
            false,
            Some(ActionKind::Hardlink),
        );
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        let outside = scenario.outside.join("late.bin");
        let quarantine_root = scenario.root.join(crate::model::scan::QUARANTINE_DIR_NAME);
        let ops = FakeOps::new().on_before_publication(move |target, _temp| {
            if outside.exists() {
                return;
            }
            let name = target.file_name().expect("a target has a name");
            let evacuated = find_under(&quarantine_root, name).expect("the evacuated original");
            std::fs::hard_link(&evacuated, &outside).unwrap();
        });
        let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();

        assert_eq!(
            batch.realized_summary.guaranteed_bytes(),
            0,
            "an outside link holds the allocation, so nothing is released: {:?}",
            batch.realized
        );
        assert_eq!(batch.realized_summary.completed_objects(), 0);
        assert_eq!(batch.realized_summary.unknown_objects(), 1);
        let unknown = batch.unknown_objects();
        let (_, quarantine) = unknown.first().expect("the unsettled allocation");
        let quarantine = quarantine.expect("recovery needs the exact path");
        assert!(quarantine.exists(), "{}", quarantine.display());
        assert_eq!(quarantine.file_name(), first.file_name());

        // And the keeper it touched is no longer trusted, so the second action on it is refused
        // rather than authorized from a reading nobody can vouch for.
        assert_eq!(batch.failed(), 2, "{:?}", batch.outcomes);
        let second_message = batch.outcomes[1].result.as_ref().unwrap_err();
        assert!(
            second_message.contains("cannot account for"),
            "the later action must be refused by the ledger: {second_message}"
        );
    }

    /// Each ledger transition refuses the shape it is supposed to refuse, and each refusal is the
    /// one the batch turns into an unknown allocation.
    #[test]
    fn every_transition_refuses_what_it_cannot_account_for() {
        let scenario = PlanScenario::new("transitions");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        drop(store);
        let plan = plan_of(&scenario, scan_id);
        let action = &plan.actions()[0];
        let (target, keeper_object) = (action.target_object(), action.keeper_object());
        let device = plan.target_object_of(action).key().device;

        // `quarantined`: the pathname the batch says it moved is not the allocation it moved.
        let mut ledger = RuntimeLedger::open(plan.preflight().unwrap());
        let err = ledger
            .quarantined(target, &twin, &keeper)
            .expect_err("that is the keeper, not the moved original");
        assert!(err.to_string().contains("inode"), "{err}");

        // `linked`: the published pathname is not the keeper's allocation.
        let mut ledger = RuntimeLedger::open(plan.preflight().unwrap());
        let err = ledger
            .linked(keeper_object, &keeper, &twin)
            .expect_err("twin.bin is its own allocation");
        assert!(err.to_string().contains("moved while the batch"), "{err}");

        // `cloned`: a published pathname that shares the keeper's inode is a hardlink, not a clone.
        let mut ledger = RuntimeLedger::open(plan.preflight().unwrap());
        let err = ledger
            .cloned(keeper_object, &keeper, &keeper, device)
            .expect_err("a clone is never the keeper itself");
        assert!(err.to_string().contains("inode"), "{err}");
        // And one on the wrong device is refused too.
        let mut ledger = RuntimeLedger::open(plan.preflight().unwrap());
        let err = ledger
            .cloned(keeper_object, &keeper, &twin, device + 1)
            .expect_err("the clone must land on the target's own device");
        assert!(err.to_string().contains("device"), "{err}");
    }

    /// One allocation failing must not take another one's figure with it.
    #[test]
    fn a_completed_allocation_keeps_its_figure_when_another_fails() {
        let scenario = PlanScenario::new("realize_mixed");
        let keeper = scenario.file("keeper.bin");
        let good = scenario.file("good.bin");
        let doomed = scenario.file("doomed.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), good.clone(), doomed.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &good, false, Some(ActionKind::Delete));
        scenario.mark(
            &mut store,
            scan_id,
            &doomed,
            false,
            Some(ActionKind::Hardlink),
        );
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        let ops = FakeOps::new().on_before_publication(|_target, temp| {
            std::fs::remove_file(temp).unwrap();
        });
        let batch = run(&ops, &plan, &[dataset_over(&scenario.root, "tank/test")]).unwrap();

        assert_eq!(batch.succeeded(), 1);
        assert_eq!(batch.failed(), 1);
        assert_eq!(
            batch.realized_summary.completed_objects(),
            1,
            "the unrelated allocation kept its own figure: {:?}",
            batch.realized
        );
        assert_eq!(batch.realized_summary.unknown_objects(), 0);
        assert_eq!(
            batch.realized_summary.guaranteed_bytes(),
            std::fs::metadata(&keeper).unwrap().size()
        );
        assert_eq!(batch.realized_summary.zero_objects(), 1);
    }

    /// Esc mid-batch must not come back looking like a completed run: the caller decides from
    /// `cancelled` whether the marks of the untouched rest of the plan may be thrown away.
    #[test]
    fn a_cancelled_batch_says_so_and_counts_the_whole_plan() {
        let scenario = PlanScenario::new("cancelled");
        let keeper = scenario.file("keeper.bin");
        let first = scenario.file("first.bin");
        let second = scenario.file("second.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), first.clone(), second.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &first, false, Some(ActionKind::Delete));
        scenario.mark(
            &mut store,
            scan_id,
            &second,
            false,
            Some(ActionKind::Delete),
        );
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        let shared = ApplyShared::default();
        // Cancelled before the first action: the flag is read at the action boundary, so nothing
        // is attempted and nothing on disk is touched.
        shared.cancel.store(true, Ordering::Relaxed);
        let ops = FakeOps::new();
        let batch = apply_batch_with(
            &ops,
            &plan,
            &[dataset_over(&scenario.root, "tank/test")],
            true,
            &shared,
            RevalidationMode::Hybrid,
        )
        .unwrap();

        assert!(batch.cancelled, "a stopped batch is not a finished one");
        assert!(batch.outcomes.is_empty(), "nothing was attempted");
        assert_eq!(batch.planned, 2, "«applied 0 of 2» needs the whole plan");
        assert_eq!(batch.realized_summary.guaranteed_bytes(), 0);
        assert_eq!(batch.realized_summary.zero_objects(), 2);
    }

    #[test]
    fn revalidate_passes_for_unchanged_files() {
        let scenario = PlanScenario::new("reval_ok");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        assert!(revalidate(
            &plan.actions()[0],
            RevalidationMode::Hybrid,
            &mut verified,
            &counter
        )
        .is_ok());
    }

    #[test]
    fn revalidate_fails_when_target_content_changed() {
        let scenario = PlanScenario::new("reval_bad");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        drop(store);

        let plan = plan_of(&scenario, scan_id);
        // Content swapped after the plan (same length — the hash check triggers).
        let size = std::fs::metadata(&twin).unwrap().size() as usize;
        std::fs::write(&twin, vec![9u8; size]).unwrap();
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        assert!(revalidate(
            &plan.actions()[0],
            RevalidationMode::Hybrid,
            &mut verified,
            &counter
        )
        .is_err());
    }

    // ---- F2: safe publication of hardlink/reflink via evacuation to quarantine ----

    /// `true` if any staging temp files (`.dedcom-tmp-…`) remain in the directory.
    fn has_tmp_leftovers(dir: &Path) -> bool {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".dedcom-tmp-"))
    }

    #[test]
    fn delete_to_quarantine_returns_path_and_suffixes_on_collision() {
        let root = temp_dir("del_q");
        let mount = root.join("mount");
        std::fs::create_dir_all(&mount).unwrap();
        let q = quarantine::quarantine_dir(&mount, "ts");

        // First file → to quarantine under its original relative path, the path is returned.
        let t1 = mount.join("a.bin");
        write_file(&t1, b"one");
        let p1 = delete::delete_to_quarantine(&t1, &mount, &q).unwrap();
        assert_eq!(p1, q.join("a.bin"));
        assert!(!t1.exists(), "original moved, not copied");
        assert_eq!(std::fs::read(&p1).unwrap(), b"one");

        // Second file with the same relative path → collision suffix, the first is intact.
        let t2 = mount.join("a.bin");
        write_file(&t2, b"two");
        let p2 = delete::delete_to_quarantine(&t2, &mount, &q).unwrap();
        assert_eq!(p2, q.join("a.bin.1"));
        assert_eq!(
            std::fs::read(&p1).unwrap(),
            b"one",
            "first one in quarantine not overwritten"
        );
        assert_eq!(std::fs::read(&p2).unwrap(), b"two");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn hardlink_evacuates_target_to_quarantine() {
        let root = temp_dir("hl_evac");
        let mount = root.join("mount");
        std::fs::create_dir_all(&mount).unwrap();
        let keeper = mount.join("keeper.bin");
        let target = mount.join("target.bin");
        write_file(&keeper, b"KEEP");
        write_file(&target, b"ORIG"); // differs from keeper — we verify the original is preserved
        let q = quarantine::quarantine_dir(&mount, "ts");

        let published = hardlink::hardlink(&RealOps, &target, &keeper, &mount, &q);
        assert!(
            matches!(published, Publication::Published { .. }),
            "{published:?}"
        );

        // target is now a hard link to keeper (same inode, keeper's content).
        assert_eq!(std::fs::read(&target).unwrap(), b"KEEP");
        let ino_t = std::fs::metadata(&target).unwrap().ino();
        let ino_k = std::fs::metadata(&keeper).unwrap().ino();
        assert_eq!(ino_t, ino_k, "target is a hard link to keeper");
        // The original bytes of target are evacuated to quarantine, NOT overwritten by publication.
        let evac = q.join("target.bin");
        assert_eq!(
            std::fs::read(&evac).unwrap(),
            b"ORIG",
            "original target preserved in quarantine"
        );
        assert!(
            !has_tmp_leftovers(&mount),
            "temp file published, not left behind"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn hardlink_missing_target_says_nothing_moved() {
        let root = temp_dir("hl_missing");
        let mount = root.join("mount");
        std::fs::create_dir_all(&mount).unwrap();
        let keeper = mount.join("keeper.bin");
        write_file(&keeper, b"KEEP");
        let target = mount.join("missing.bin"); // does not exist
        let q = quarantine::quarantine_dir(&mount, "ts");

        let published = hardlink::hardlink(&RealOps, &target, &keeper, &mount, &q);
        assert!(
            matches!(published, Publication::NotMoved { .. }),
            "no target → nothing moved: {published:?}"
        );
        assert!(
            !target.exists(),
            "target not created (no publication happened)"
        );
        assert!(!has_tmp_leftovers(&mount), "temp file removed on error");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn evacuate_then_publish_restores_original_when_publish_fails() {
        let root = temp_dir("evac_restore");
        let mount = root.join("mount");
        std::fs::create_dir_all(&mount).unwrap();
        let target = mount.join("t.bin");
        write_file(&target, b"ORIG");
        let q = quarantine::quarantine_dir(&mount, "ts");

        // A `build` that creates NOTHING at the temp path → publication (rename
        // temp→target) fails (ENOENT) AFTER the original is evacuated → the
        // restore branch returns the original from quarantine into the target slot.
        let published = evacuate_then_publish(&RealOps, &target, |_temp| Ok(()), &mount, &q);
        assert!(
            matches!(published, Publication::RolledBack { .. }),
            "{published:?}"
        );
        assert!(target.exists(), "original restored into the target slot");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"ORIG",
            "exactly the original bytes were restored"
        );
        assert!(!has_tmp_leftovers(&mount), "no leftovers remained");

        std::fs::remove_dir_all(&root).ok();
    }

    // ---- Hybrid/Strict re-validation ----

    /// Keeper + two twins, planned — the fixture the per-batch cache is measured on.
    fn group_of_three(tag: &str) -> (PlanScenario, ActionPlan, u64) {
        let scenario = PlanScenario::new(tag);
        let keeper = scenario.file("keeper.bin");
        let first = scenario.file("t1.bin");
        let second = scenario.file("t2.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), first.clone(), second.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &first, false, Some(ActionKind::Delete));
        scenario.mark(
            &mut store,
            scan_id,
            &second,
            false,
            Some(ActionKind::Delete),
        );
        drop(store);
        let plan = plan_of(&scenario, scan_id);
        let size = std::fs::metadata(&keeper).unwrap().size();
        (scenario, plan, size)
    }

    #[test]
    fn hybrid_reads_keeper_once_per_batch() {
        let (_scenario, plan, size) = group_of_three("hybrid_once");
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        for action in plan.actions() {
            revalidate(action, RevalidationMode::Hybrid, &mut verified, &counter).unwrap();
        }
        // t1 + keeper(1×) + t2 = 3×size: keeper NOT re-read in the second action.
        assert_eq!(counter.load(Ordering::Relaxed), 3 * size);
    }

    #[test]
    fn strict_rehashes_keeper_each_action() {
        let (_scenario, plan, size) = group_of_three("strict_each");
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        for action in plan.actions() {
            revalidate(action, RevalidationMode::Strict, &mut verified, &counter).unwrap();
        }
        // (t1+keeper) + (t2+keeper) = 4×size: keeper re-hashed every time.
        assert_eq!(counter.load(Ordering::Relaxed), 4 * size);
    }

    #[test]
    fn hybrid_restat_catches_keeper_change_midbatch() {
        let (_scenario, plan, size) = group_of_three("hybrid_restat");
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        // The first action caches keeper by FileIdentity.
        revalidate(
            &plan.actions()[0],
            RevalidationMode::Hybrid,
            &mut verified,
            &counter,
        )
        .unwrap();
        // keeper was changed (same size, different content) — re-stat (ctime/mtime) gives
        // a cache miss → re-hash → mismatch → error (the change is NOT skipped).
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(plan.actions()[0].keeper(), vec![3u8; size as usize]).unwrap();
        let res = revalidate(
            &plan.actions()[1],
            RevalidationMode::Hybrid,
            &mut verified,
            &counter,
        );
        assert!(
            res.is_err(),
            "a keeper change within the batch must be caught by re-stat"
        );
    }
}
