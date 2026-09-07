// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::model::plan::{ObjectRealization, PlanObjectKey, PlanSummary, RealizedSummary};

/// Type of action on a duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Delete,
    Hardlink,
    Reflink,
}

impl ActionKind {
    pub fn label(self) -> &'static str {
        match self {
            ActionKind::Delete => "DELETE",
            ActionKind::Hardlink => "HARDLINK",
            ActionKind::Reflink => "REFLINK",
        }
    }

    /// Stable identifier for storage in the DB.
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Delete => "delete",
            ActionKind::Hardlink => "hardlink",
            ActionKind::Reflink => "reflink",
        }
    }

    /// Parse an identifier read from the DB.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "delete" => Some(ActionKind::Delete),
            "hardlink" => Some(ActionKind::Hardlink),
            "reflink" => Some(ActionKind::Reflink),
            _ => None,
        }
    }
}

/// Outcome of a single applied action.
///
/// It carries no byte figure. One file size per successful pathname is exactly the claim R2D exists
/// to remove: a pathname is not an allocation, and two aliases of one inode would be counted twice.
/// What space was really released is decided per allocation, in `BatchResult::realized`.
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub kind: ActionKind,
    pub target: PathBuf,
    /// Where the original went, when it was moved. The exact path, because it is what a recovery
    /// needs — a directory name is not enough to find one file among a batch of them.
    pub quarantine: Option<PathBuf>,
    pub result: std::result::Result<(), String>,
}

/// Result of applying a batch of actions.
#[derive(Debug, Clone, Default)]
pub struct BatchResult {
    pub outcomes: Vec<ActionOutcome>,
    pub snapshots: Vec<String>,
    pub quarantine_dirs: Vec<PathBuf>,
    /// How many actions the batch set out to apply. With `cancelled` it is the other half of
    /// «applied N of M» — `outcomes` only ever holds the ones that were reached.
    pub planned: usize,
    /// The operator stopped the batch (Esc, or a shutdown signal) before it ran out of actions.
    /// A partial result is not a finished one, and the untouched marks must survive it.
    pub cancelled: bool,
    /// The batch refused itself as a whole after the safety snapshots existed — the second
    /// whole-plan preflight found the plan no longer described the disk. No action ran; the
    /// snapshots above are still there and still have to be reported.
    pub aborted: Option<String>,
    /// What the plan promised, carried from the `ActionPlan` the batch was given.
    pub plan: PlanSummary,
    /// What each covered allocation is actually worth now.
    pub realized: Vec<(PlanObjectKey, ObjectRealization)>,
    pub realized_summary: RealizedSummary,
    /// Bytes re-read during revalidation. A progress metric for the bar, never a reclaim figure.
    pub bytes_read: u64,
}

impl BatchResult {
    pub fn succeeded(&self) -> usize {
        self.outcomes.iter().filter(|o| o.result.is_ok()).count()
    }

    pub fn failed(&self) -> usize {
        self.outcomes.iter().filter(|o| o.result.is_err()).count()
    }

    /// Every exact quarantine path this batch produced, in the order the actions ran — the list a
    /// recovery works from.
    pub fn quarantined_paths(&self) -> Vec<&PathBuf> {
        self.outcomes
            .iter()
            .filter_map(|outcome| outcome.quarantine.as_ref())
            .collect()
    }

    /// The allocations whose final state could not be settled, with where their original is.
    pub fn unknown_objects(&self) -> Vec<(&String, Option<&PathBuf>)> {
        self.realized
            .iter()
            .filter_map(|(_, state)| match state {
                ObjectRealization::Unknown { reason, quarantine } => {
                    Some((reason, quarantine.as_ref()))
                }
                _ => None,
            })
            .collect()
    }
}

/// A manual-triage event (triage v1) — the "trash bin" journal and the fact of a
/// duplicate created on disk for a future dedup pass.
#[derive(Debug, Clone)]
pub struct MoveEvent {
    pub created_at: String,
    /// The loaded scan at the moment of the move (for correlation); may be absent.
    pub scan_id: Option<i64>,
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    /// blake3 of the moved file, if it was computed/known.
    pub hash: Option<[u8; 32]>,
    /// `true` if the destination already had an identical copy (a duplicate was created).
    pub duplicate: bool,
}

/// Whether a stored `move_event` row's two pathnames are the exact bytes the move handled.
///
/// `Exact` says exactly that and nothing more: not that every move is in the journal (the writer
/// is best-effort, see `move_batch::record`), and not proof that the move took place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFidelity {
    /// Carried over from the v5 TEXT journal by the schema v6 migration: whatever bytes the old
    /// writer's `to_string_lossy` left, with no claim that they are the pathname's own.
    CarriedFromText,
    /// The raw bytes of both pathnames, as a v6 writer bound them.
    Exact,
}

impl PathFidelity {
    /// The value the `path_fidelity` column stores for this fidelity. Both writers of that column
    /// — the v6 journal writer and the migration's copy of the v5 rows — take it from here, so
    /// the column's domain and this type cannot drift apart.
    pub const fn stored(self) -> i64 {
        match self {
            PathFidelity::CarriedFromText => 0,
            PathFidelity::Exact => 1,
        }
    }

    /// The fidelity a stored value stands for; `None` outside the column's domain. Test-only with
    /// its one caller, the journal reader.
    #[cfg(test)]
    pub fn from_stored(value: i64) -> Option<Self> {
        [PathFidelity::CarriedFromText, PathFidelity::Exact]
            .into_iter()
            .find(|fidelity| fidelity.stored() == value)
    }
}

/// One row of the move journal as it is read back: the event and the fidelity of its pathnames.
/// Test-only for the same reason as its one reader, `ScanStore::move_events`: no production
/// code reads the journal yet, and this loses `cfg(test)` together with that reader.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct MoveEventRow {
    pub event: MoveEvent,
    pub path_fidelity: PathFidelity,
}

/// Mode for re-validating contents before a destructive action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevalidationMode {
    /// Re-hash target AND keeper before EVERY action. A keeper in a group of N is
    /// read N−1 times. The legacy behavior; enabled by the `--strict-verify` flag.
    Strict,
    /// Default: each DISTINCT file is hashed once per batch (per-batch cache);
    /// a re-stat-guard on `FileIdentity` catches a file change between actions.
    /// Safety ≈ Strict, only eliminates re-reading the keeper.
    #[default]
    Hybrid,
    /// Trust the scan's fingerprint without reading, if `stat` has not changed. NOT
    /// implemented (unreachable: `main` only emits Strict|Hybrid) — groundwork for a
    /// possible future fast-revalidation mode.
    #[allow(dead_code)]
    Fast,
}

/// File identity by `stat` — the re-stat-guard within an apply batch:
/// if a file has not changed between actions, we do not re-hash it (Hybrid). The full
/// set of fields (incl. `ctime`/`mode`) is groundwork for the deferred Fast research.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub mode: u32,
}

impl FileIdentity {
    /// Captures the identity from metadata (Unix `stat`).
    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        FileIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            mode: meta.mode(),
        }
    }

    /// Whether a fingerprint is recorded (`ctime != 0`). Reserved for the Fast research
    /// (scan-time fp from the DB); previously the fp is captured live, so it is unused.
    #[allow(dead_code)]
    pub fn recorded(&self) -> bool {
        self.ctime_sec != 0
    }
}
