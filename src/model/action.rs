// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

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

/// A planned action — pure data; nothing happens until it is applied.
#[derive(Debug, Clone)]
pub struct PlannedAction {
    pub kind: ActionKind,
    /// The file being deleted/replaced.
    pub target: PathBuf,
    /// The keeper file (for hardlink/reflink).
    pub keeper: PathBuf,
    pub target_device: u64,
    pub keeper_device: u64,
    pub size: u64,
    /// blake3 hash of the duplicate group in hex — for the final re-check of the
    /// contents of `target`/`keeper` before the destructive action.
    pub expected_hash: String,
}

/// Outcome of a single applied action.
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub kind: ActionKind,
    pub target: PathBuf,
    pub bytes: u64,
    pub result: std::result::Result<(), String>,
}

/// Result of applying a batch of actions.
#[derive(Debug, Clone, Default)]
pub struct BatchResult {
    pub outcomes: Vec<ActionOutcome>,
    pub snapshots: Vec<String>,
    pub quarantine_dirs: Vec<PathBuf>,
    pub bytes_planned: u64,
}

impl BatchResult {
    pub fn succeeded(&self) -> usize {
        self.outcomes.iter().filter(|o| o.result.is_ok()).count()
    }

    pub fn failed(&self) -> usize {
        self.outcomes.iter().filter(|o| o.result.is_err()).count()
    }

    pub fn bytes_reclaimed(&self) -> u64 {
        self.outcomes
            .iter()
            .filter(|o| o.result.is_ok())
            .map(|o| o.bytes)
            .sum()
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
