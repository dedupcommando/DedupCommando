// SPDX-License-Identifier: Apache-2.0
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::error::{AppError, Result};
use crate::model::action::{
    ActionKind, ActionOutcome, BatchResult, FileIdentity, PlannedAction, RevalidationMode,
};
use crate::model::dataset::Dataset;
use crate::model::duplicate::DuplicateGroup;
use crate::pipeline::hash;
use crate::state::ScanStore;
use crate::zfs::snapshots;

pub mod apply_worker;
pub mod delete;
pub mod hardlink;
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

/// Builds the list of planned actions from the marked files of the groups.
pub fn plan_actions(groups: &[DuplicateGroup]) -> Vec<PlannedAction> {
    let mut plan = Vec::new();
    for group in groups {
        let keeper = match group.files.iter().find(|file| file.is_keeper) {
            Some(keeper) => keeper,
            None => continue,
        };
        for file in &group.files {
            if file.is_keeper {
                continue;
            }
            if let Some(kind) = file.action {
                plan.push(PlannedAction {
                    kind,
                    target: file.path.clone(),
                    keeper: keeper.path.clone(),
                    target_device: file.device,
                    keeper_device: keeper.device,
                    size: file.size,
                    expected_hash: group.hash.clone(),
                });
            }
        }
    }
    plan
}

/// Builds the action plan DIRECTLY from the DB (`file` + `file_mark`), without
/// materializing all groups in RAM. Exactly mirrors the pair selection
/// of `plan_actions`: the target is a non-keeper marked for action, the keeper is
/// the deterministic single one (first by path). Targets without a keeper are
/// discarded in `planned_action_rows` (fail-safe). Same `expected_hash` (hex) as
/// `plan_actions`, so `revalidate` before a destructive action is unchanged.
pub fn plan_actions_from_db(store: &ScanStore, scan_id: i64) -> Result<Vec<PlannedAction>> {
    let rows = store.planned_action_rows(scan_id)?;
    let mut plan = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(kind) = ActionKind::parse(&row.action) else {
            continue;
        };
        plan.push(PlannedAction {
            kind,
            target: row.target,
            keeper: row.keeper,
            target_device: row.target_device,
            keeper_device: row.keeper_device,
            size: row.size,
            expected_hash: row.expected_hash,
        });
    }
    Ok(plan)
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

/// Applies a batch of actions: snapshot the affected datasets -> apply.
/// Failure to create any snapshot cancels the whole batch — no action is
/// performed without a safety net.
pub fn apply_batch(
    actions: &[PlannedAction],
    datasets: &[Dataset],
    reflink_safe: bool,
    shared: &ApplyShared,
    mode: RevalidationMode,
) -> Result<BatchResult> {
    if actions.is_empty() {
        return Ok(BatchResult::default());
    }
    let timestamp = snapshot_suffix();

    // 1. Affected datasets — by the device of the target files.
    let mut affected: Vec<&Dataset> = Vec::new();
    for action in actions {
        if let Some(dataset) = dataset_by_device(datasets, action.target_device) {
            if !affected.iter().any(|known| known.name == dataset.name) {
                affected.push(dataset);
            }
        }
    }

    // 2. Safety snapshots. Failure of any -> the whole batch is cancelled.
    shared.set_phase(ApplyPhase::Snapshots);
    let mut snapshots_made = Vec::new();
    for dataset in &affected {
        match snapshots::create_snapshot(&dataset.name, &timestamp) {
            Ok(name) => snapshots_made.push(name),
            Err(err) => {
                return Err(AppError::msg(format!(
                    "failed to create snapshot {}: {err}; batch of actions cancelled",
                    dataset.name
                )));
            }
        }
    }

    // 3. Applying actions. Cancellation (Esc) is checked at the action BOUNDARY —
    // the snapshot already exists, what was applied to quarantine is reversible, the partial result is consistent.
    shared.set_phase(ApplyPhase::Applying);
    let mut outcomes = Vec::new();
    let mut quarantine_dirs: Vec<PathBuf> = Vec::new();
    // Per-batch cache of re-checked files (Hybrid): the keeper is hashed once per
    // batch, the repeat check is a re-stat by `FileIdentity` (we don't re-read).
    let mut verified: HashMap<PathBuf, FileIdentity> = HashMap::new();
    for (index, action) in actions.iter().enumerate() {
        if shared.is_cancelled() {
            break;
        }
        shared.index.store(index, Ordering::Relaxed);
        outcomes.push(apply_one(
            action,
            datasets,
            &timestamp,
            reflink_safe,
            &mut quarantine_dirs,
            mode,
            &mut verified,
            &shared.bytes_done,
        ));
    }

    shared.set_phase(ApplyPhase::Done);
    Ok(BatchResult {
        outcomes,
        snapshots: snapshots_made,
        quarantine_dirs,
        bytes_planned: actions.iter().map(|action| action.size).sum(),
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_one(
    action: &PlannedAction,
    datasets: &[Dataset],
    timestamp: &str,
    reflink_safe: bool,
    quarantine_dirs: &mut Vec<PathBuf>,
    mode: RevalidationMode,
    verified: &mut HashMap<PathBuf, FileIdentity>,
    bytes_progress: &AtomicU64,
) -> ActionOutcome {
    // Final content re-check: if the file changed after the scan —
    // we do not perform the action, otherwise we would destroy current data.
    if let Err(err) = revalidate(action, mode, verified, bytes_progress) {
        return ActionOutcome {
            kind: action.kind,
            target: action.target.clone(),
            bytes: 0,
            result: Err(err.to_string()),
        };
    }
    let result: Result<()> = match action.kind {
        ActionKind::Delete => match dataset_by_device(datasets, action.target_device) {
            Some(dataset) => {
                let dir = quarantine::quarantine_dir(&dataset.mountpoint, timestamp);
                let outcome =
                    delete::delete_to_quarantine(&action.target, &dataset.mountpoint, &dir);
                if outcome.is_ok() && !quarantine_dirs.contains(&dir) {
                    quarantine_dirs.push(dir);
                }
                outcome.map(|_| ())
            }
            None => Err(AppError::msg(
                "target file's dataset could not be determined",
            )),
        },
        ActionKind::Hardlink => {
            if action.target_device != action.keeper_device {
                Err(AppError::msg(
                    "cross-dataset hardlink is impossible — files are in different datasets",
                ))
            } else {
                match dataset_by_device(datasets, action.target_device) {
                    Some(dataset) => {
                        let dir = quarantine::quarantine_dir(&dataset.mountpoint, timestamp);
                        let outcome = hardlink::hardlink(
                            &action.target,
                            &action.keeper,
                            &dataset.mountpoint,
                            &dir,
                        );
                        if outcome.is_ok() && !quarantine_dirs.contains(&dir) {
                            quarantine_dirs.push(dir);
                        }
                        outcome
                    }
                    // Without an identified ZFS dataset there will be neither a snapshot nor a quarantine
                    // to evacuate the original into — we refuse (symmetric to the Delete branch).
                    None => Err(AppError::msg(
                        "target file's dataset could not be determined — hardlink is not performed without a ZFS snapshot",
                    )),
                }
            }
        }
        ActionKind::Reflink => {
            if !reflink_safe {
                Err(AppError::msg(
                    "reflink is unavailable on this host — needs ZFS 2.3+ with block cloning enabled",
                ))
            } else {
                let target_dataset = dataset_by_device(datasets, action.target_device);
                let target_pool = target_dataset.map(|dataset| dataset.pool_name().to_string());
                let keeper_pool = dataset_by_device(datasets, action.keeper_device)
                    .map(|dataset| dataset.pool_name().to_string());
                if let (Some(dataset), true) = (
                    target_dataset,
                    target_pool.is_some() && target_pool == keeper_pool,
                ) {
                    let dir = quarantine::quarantine_dir(&dataset.mountpoint, timestamp);
                    let outcome =
                        reflink::reflink(&action.target, &action.keeper, &dataset.mountpoint, &dir);
                    if outcome.is_ok() && !quarantine_dirs.contains(&dir) {
                        quarantine_dirs.push(dir);
                    }
                    outcome
                } else {
                    Err(AppError::msg(
                        "reflink is impossible — files are in different ZFS pools",
                    ))
                }
            }
        }
    };

    ActionOutcome {
        kind: action.kind,
        target: action.target.clone(),
        bytes: if result.is_ok() { action.size } else { 0 },
        result: result.map_err(|err| err.to_string()),
    }
}

/// Safe publication of a `target` replacement (hardlink/reflink) WITHOUT destroy-in-place.
/// Previously hardlink/reflink did `fs::rename(temp, target)` and overwrote the target —
/// a change to `target` after the safety snapshot was lost irrecoverably (only
/// delete was safe, via quarantine). Now: (1) build the replacement under a temporary
/// name (`build`); (2) evacuate the current `target` to quarantine atomically (like
/// delete — the original is recoverable, not overwritten); (3) publish the replacement into
/// the freed slot. If publication fails (the slot is occupied/disappeared between steps),
/// the original is restored from quarantine. Returns the quarantine directory — for tracking
/// in the batch's `quarantine_dirs`.
fn evacuate_then_publish(
    target: &Path,
    build: impl FnOnce(&Path) -> Result<()>,
    mountpoint: &Path,
    quarantine_dir: &Path,
) -> Result<PathBuf> {
    let parent = target
        .parent()
        .ok_or_else(|| AppError::msg("target file has no parent directory"))?;
    let temp = move_file::staging_path(parent, target.file_name());
    // (1) Build the replacement under a temporary name; on error — target is untouched.
    if let Err(err) = build(&temp) {
        let _ = std::fs::remove_file(&temp);
        return Err(err);
    }
    // (2) Evacuate the current target to quarantine (atomically); on error — target is untouched.
    let evacuated = match delete::delete_to_quarantine(target, mountpoint, quarantine_dir) {
        Ok(path) => path,
        Err(err) => {
            let _ = std::fs::remove_file(&temp);
            return Err(err);
        }
    };
    // (3) Publish the replacement into the freed target slot.
    match move_file::rename_noreplace(&temp, target) {
        Ok(()) => Ok(quarantine_dir.to_path_buf()),
        Err(_) => {
            // The target slot is occupied/disappeared between evacuation and publication — we roll back:
            // return the original from quarantine, delete the temp replacement.
            let _ = std::fs::remove_file(&temp);
            if move_file::rename_noreplace(&evacuated, target).is_ok() {
                Err(AppError::msg(format!(
                    "{} changed at the moment of applying — action cancelled, original restored",
                    target.display()
                )))
            } else {
                Err(AppError::msg(format!(
                    "{} occupied during publication — original preserved in quarantine: {}",
                    target.display(),
                    evacuated.display()
                )))
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
/// exists. Mitigated in layers: the batch's safety ZFS snapshot, atomic publication via
/// `renameat2(RENAME_NOREPLACE)` (`evacuate_then_publish`), a repeated symlink check at
/// the moment of the action, and evacuation of the original to quarantine (recoverable). Fully
/// closing it (opening by fd + `O_NOFOLLOW`) is a separate large rework; for the "one admin
/// on their own pool" model it is deliberately deferred.
fn revalidate(
    action: &PlannedAction,
    mode: RevalidationMode,
    verified: &mut HashMap<PathBuf, FileIdentity>,
    bytes_progress: &AtomicU64,
) -> Result<()> {
    verify_file(
        &action.target,
        action.size,
        &action.expected_hash,
        "target",
        mode,
        verified,
        bytes_progress,
    )?;
    verify_file(
        &action.keeper,
        action.size,
        &action.expected_hash,
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
pub fn verify_bytes_total(actions: &[PlannedAction], mode: RevalidationMode) -> u64 {
    if mode == RevalidationMode::Strict {
        return actions
            .iter()
            .map(|action| action.size.saturating_mul(2))
            .sum();
    }
    let targets: u64 = actions.iter().map(|action| action.size).sum();
    let mut seen: HashSet<&Path> = HashSet::new();
    let keepers: u64 = actions
        .iter()
        .filter(|action| seen.insert(action.keeper.as_path()))
        .map(|action| action.size)
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
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn snapshot_suffix_is_unique_per_call() {
        // hardening: the counter makes suffixes different even within the same second.
        assert_ne!(snapshot_suffix(), snapshot_suffix());
    }

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

    fn planned(target: &Path, keeper: &Path, size: u64, hash: &str) -> PlannedAction {
        PlannedAction {
            kind: ActionKind::Delete,
            target: target.to_path_buf(),
            keeper: keeper.to_path_buf(),
            target_device: 0,
            keeper_device: 0,
            size,
            expected_hash: hash.to_string(),
        }
    }

    #[test]
    fn revalidate_passes_for_unchanged_files() {
        let dir = temp_dir("ok");
        let target = dir.join("target.bin");
        let keeper = dir.join("keeper.bin");
        let content = b"duplicate content";
        write_file(&target, content);
        write_file(&keeper, content);
        let progress = AtomicU64::new(0);
        let hash = hex32(&hash::hash_file(&target, &progress).unwrap());

        let action = planned(&target, &keeper, content.len() as u64, &hash);
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        assert!(revalidate(&action, RevalidationMode::Hybrid, &mut verified, &counter).is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn revalidate_fails_when_target_content_changed() {
        let dir = temp_dir("changed");
        let target = dir.join("target.bin");
        let keeper = dir.join("keeper.bin");
        let content = b"duplicate content";
        write_file(&target, content);
        write_file(&keeper, content);
        let progress = AtomicU64::new(0);
        let hash = hex32(&hash::hash_file(&target, &progress).unwrap());
        let action = planned(&target, &keeper, content.len() as u64, &hash);

        // Content swapped after the scan (same length — the hash check triggers).
        write_file(&target, b"tampered content!");
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        assert!(revalidate(&action, RevalidationMode::Hybrid, &mut verified, &counter).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    use crate::model::duplicate::FileEntry;
    use crate::model::scan::ScanConfig;
    use crate::state::ManifestRow;

    fn mrow(path: &str, size: u64, inode: u64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size,
            mtime: 0,
            device: 1,
            inode,
            ..Default::default()
        }
    }

    /// File mark for save_marks (uses only path/is_keeper/action).
    fn mark(path: &str, keeper: bool, action: Option<ActionKind>) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size: 0,
            mtime: 0,
            device: 0,
            inode: 0,
            is_keeper: keeper,
            action,
        }
    }

    /// Scan with one group /x/a,/x/b,/x/c (shared hash) + unique /x/u.
    fn store_with_group() -> (ScanStore, i64) {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &[
                    mrow("/x/a", 100, 1),
                    mrow("/x/b", 100, 2),
                    mrow("/x/c", 100, 3),
                    mrow("/x/u", 200, 4),
                ],
            )
            .unwrap();
        let h = [7u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/a"), h),
                    (PathBuf::from("/x/b"), h),
                    (PathBuf::from("/x/c"), h),
                ],
            )
            .unwrap();
        (store, scan_id)
    }

    fn sort_plan(plan: &mut [PlannedAction]) {
        plan.sort_by(|a, b| a.target.cmp(&b.target));
    }

    /// CENTRAL safety test: plan from DB == plan from RAM (same target→keeper
    /// pairs, hashes, sizes, devices) on one fixture.
    #[test]
    fn plan_from_db_equals_plan_from_ram() {
        let (mut store, scan_id) = store_with_group();
        // keeper=/x/a; /x/b and /x/c — for deletion.
        store
            .save_marks(
                scan_id,
                [
                    mark("/x/a", true, None),
                    mark("/x/b", false, Some(ActionKind::Delete)),
                    mark("/x/c", false, Some(ActionKind::Delete)),
                ]
                .iter(),
            )
            .unwrap();

        let groups = store.duplicate_groups(scan_id).unwrap();
        let mut from_ram = plan_actions(&groups);
        let mut from_db = plan_actions_from_db(&store, scan_id).unwrap();
        sort_plan(&mut from_ram);
        sort_plan(&mut from_db);

        assert_eq!(from_ram.len(), 2, "two targets (b, c)");
        assert_eq!(from_ram.len(), from_db.len(), "action count matches");
        for (r, d) in from_ram.iter().zip(&from_db) {
            assert_eq!(r.kind, d.kind);
            assert_eq!(r.target, d.target);
            assert_eq!(r.keeper, d.keeper);
            assert_eq!(r.target_device, d.target_device);
            assert_eq!(r.keeper_device, d.keeper_device);
            assert_eq!(r.size, d.size);
            assert_eq!(r.expected_hash, d.expected_hash);
        }
    }

    /// Two keeper marks in a group → exactly one deterministic keeper in the plan
    /// (first by path), and the plan from DB matches the plan from RAM.
    #[test]
    fn plan_from_db_single_keeper_when_two_marked() {
        let (mut store, scan_id) = store_with_group();
        // BOTH /x/a AND /x/b are marked keeper; /x/c — for deletion.
        store
            .save_marks(
                scan_id,
                [
                    mark("/x/a", true, None),
                    mark("/x/b", true, None),
                    mark("/x/c", false, Some(ActionKind::Delete)),
                ]
                .iter(),
            )
            .unwrap();

        let from_db = plan_actions_from_db(&store, scan_id).unwrap();
        assert_eq!(from_db.len(), 1, "one target (/x/c)");
        assert_eq!(from_db[0].target, PathBuf::from("/x/c"));
        assert_eq!(
            from_db[0].keeper,
            PathBuf::from("/x/a"),
            "deterministic keeper — first by path"
        );

        // The RAM plan agrees (same keeper choice).
        let groups = store.duplicate_groups(scan_id).unwrap();
        let from_ram = plan_actions(&groups);
        assert_eq!(from_ram.len(), 1);
        assert_eq!(from_ram[0].keeper, PathBuf::from("/x/a"));
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
        use std::os::unix::fs::MetadataExt;
        let root = temp_dir("hl_evac");
        let mount = root.join("mount");
        std::fs::create_dir_all(&mount).unwrap();
        let keeper = mount.join("keeper.bin");
        let target = mount.join("target.bin");
        write_file(&keeper, b"KEEP");
        write_file(&target, b"ORIG"); // differs from keeper — we verify the original is preserved
        let q = quarantine::quarantine_dir(&mount, "ts");

        hardlink::hardlink(&target, &keeper, &mount, &q).unwrap();

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
    fn hardlink_missing_target_errs_without_publish() {
        let root = temp_dir("hl_missing");
        let mount = root.join("mount");
        std::fs::create_dir_all(&mount).unwrap();
        let keeper = mount.join("keeper.bin");
        write_file(&keeper, b"KEEP");
        let target = mount.join("missing.bin"); // does not exist
        let q = quarantine::quarantine_dir(&mount, "ts");

        let res = hardlink::hardlink(&target, &keeper, &mount, &q);
        assert!(res.is_err(), "no target → error");
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
        let res = evacuate_then_publish(&target, |_temp| Ok(()), &mount, &q);
        assert!(res.is_err(), "publication failed");
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

    /// Group of duplicates: keeper + 2 targets with identical 16-byte content.
    fn group_of_three(tag: &str) -> (PathBuf, Vec<PlannedAction>, u64) {
        let dir = temp_dir(tag);
        let keeper = dir.join("keeper.bin");
        let t1 = dir.join("t1.bin");
        let t2 = dir.join("t2.bin");
        let content = b"0123456789abcdef"; // 16 bytes
        write_file(&keeper, content);
        write_file(&t1, content);
        write_file(&t2, content);
        let counter = AtomicU64::new(0);
        let hash = hex32(&hash::hash_file(&keeper, &counter).unwrap());
        let size = content.len() as u64;
        let actions = vec![
            planned(&t1, &keeper, size, &hash),
            planned(&t2, &keeper, size, &hash),
        ];
        (dir, actions, size)
    }

    #[test]
    fn hybrid_reads_keeper_once_per_batch() {
        let (dir, actions, size) = group_of_three("hybrid_once");
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        for action in &actions {
            revalidate(action, RevalidationMode::Hybrid, &mut verified, &counter).unwrap();
        }
        // t1 + keeper(1×) + t2 = 3×size: keeper NOT re-read in the second action.
        assert_eq!(counter.load(Ordering::Relaxed), 3 * size);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn strict_rehashes_keeper_each_action() {
        let (dir, actions, size) = group_of_three("strict_each");
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        for action in &actions {
            revalidate(action, RevalidationMode::Strict, &mut verified, &counter).unwrap();
        }
        // (t1+keeper) + (t2+keeper) = 4×size: keeper re-hashed every time.
        assert_eq!(counter.load(Ordering::Relaxed), 4 * size);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hybrid_restat_catches_keeper_change_midbatch() {
        let (dir, actions, _size) = group_of_three("hybrid_restat");
        let mut verified = HashMap::new();
        let counter = AtomicU64::new(0);
        // The first action caches keeper by FileIdentity.
        revalidate(
            &actions[0],
            RevalidationMode::Hybrid,
            &mut verified,
            &counter,
        )
        .unwrap();
        // keeper was changed (same size, different content) — re-stat (ctime/mtime) gives
        // a cache miss → re-hash → mismatch → error (the change is NOT skipped).
        std::thread::sleep(std::time::Duration::from_millis(10));
        write_file(&actions[0].keeper, b"FEDCBA9876543210"); // 16 bytes, different content
        let res = revalidate(
            &actions[1],
            RevalidationMode::Hybrid,
            &mut verified,
            &counter,
        );
        assert!(
            res.is_err(),
            "a keeper change within the batch must be caught by re-stat"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
