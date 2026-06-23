// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::duplicate::DirSigAlgo;
use crate::state::GroupSummary;

/// Quarantine directory name (excluded from scanning).
pub const QUARANTINE_DIR_NAME: &str = ".dedcom-quarantine";

/// Default exclusion globs: ZFS snapshots and quarantine.
pub fn default_excludes() -> Vec<String> {
    vec![
        "**/.zfs/**".to_string(),
        format!("**/{QUARANTINE_DIR_NAME}/**"),
    ]
}

/// Hashing intensity profile (Resource Governor).
/// Controls the number of read threads and CPU/IO priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HashProfile {
    /// All cores, disk at full bandwidth — "the pool is mine, I'm in a hurry".
    Turbo,
    /// 2 threads, no seek-thrash on an HDD-RAIDZ — a universal compromise.
    #[default]
    Balanced,
    /// 1 thread + nice 19 + ionice idle — "VMs/backups are running, don't steal the disk".
    Idle,
}

impl HashProfile {
    pub fn label(self) -> &'static str {
        match self {
            HashProfile::Turbo => "Turbo",
            HashProfile::Balanced => "Balanced",
            HashProfile::Idle => "Idle",
        }
    }

    /// A short hint for the selection UI.
    pub fn hint(self) -> &'static str {
        match self {
            HashProfile::Turbo => "all cores, disk at full — the pool is mine, I'm in a hurry",
            HashProfile::Balanced => "2 threads, no seek-thrash — a compromise",
            HashProfile::Idle => "1 thread, nice+ionice idle — don't disturb the VM/backup",
        }
    }

    /// The next profile in the cycle — for toggling in the UI.
    pub fn next(self) -> Self {
        match self {
            HashProfile::Turbo => HashProfile::Balanced,
            HashProfile::Balanced => HashProfile::Idle,
            HashProfile::Idle => HashProfile::Turbo,
        }
    }
}

/// Configuration of a single scan. Serialized into the checkpoint DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub roots: Vec<PathBuf>,
    pub exclude_globs: Vec<String>,
    pub min_size: u64,
    pub max_size: Option<u64>,
    pub follow_symlinks: bool,
    /// Include filter by extensions (normalized: lowercase, no dot).
    /// Empty = all files are scanned.
    #[serde(default)]
    pub include_extensions: Vec<String>,
    /// Manual override of the storage type (the `--storage-type` flag).
    /// `None` = the storage type is determined automatically.
    #[serde(default)]
    pub storage_type_override: Option<String>,
    /// Reuse hashes of unchanged files from past scans (the hash cache).
    /// `new()` → `true`; `#[serde(default)]` (→ false) is safe for old
    /// checkpoints without this field — there was no cache there anyway.
    #[serde(default)]
    pub reuse_hashes: bool,
    /// Hashing intensity profile. `#[serde(default)]` →
    /// Balanced for old checkpoints without the field.
    #[serde(default)]
    pub hash_profile: HashProfile,
    /// Directory signature algorithm. `#[serde(default)]` → `Old` for
    /// old checkpoints without the field. CLI `--merkle-dirs` sets `Merkle` at the start
    /// of a new scan; on resume the value is read from the DB (the CLI flag is ignored,
    /// like for `hash_profile`).
    #[serde(default)]
    pub dir_sig_algo: DirSigAlgo,
}

impl ScanConfig {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            exclude_globs: default_excludes(),
            min_size: 4096,
            max_size: None,
            follow_symlinks: false,
            include_extensions: Vec::new(),
            storage_type_override: None,
            reuse_hashes: true,
            hash_profile: HashProfile::Balanced,
            dir_sig_algo: DirSigAlgo::Old,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_config_dir_sig_algo_defaults_to_old_on_old_checkpoint_json() {
        // An old JSON checkpoint without the dir_sig_algo field — #[serde(default)] → Old.
        let json = r#"{"roots":["/x"],"exclude_globs":[],"min_size":0,"max_size":null,"follow_symlinks":false}"#;
        let cfg: ScanConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.dir_sig_algo, DirSigAlgo::Old);
    }

    #[test]
    fn scan_config_dir_sig_algo_persists_through_roundtrip() {
        // Persist Merkle into the checkpoint → resume computes with the same algorithm.
        let mut cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        cfg.dir_sig_algo = DirSigAlgo::Merkle;
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: ScanConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.dir_sig_algo, DirSigAlgo::Merkle);
    }

    #[test]
    fn is_completed_true_for_both_complete_variants() {
        // Completed = Complete OR CompleteWithWarnings.
        assert!(ScanStatus::Complete.is_completed());
        assert!(ScanStatus::CompleteWithWarnings.is_completed());
        assert!(!ScanStatus::Walking.is_completed());
        assert!(!ScanStatus::Hashing.is_completed());
        assert!(!ScanStatus::Aborted.is_completed());
    }

    #[test]
    fn completed_scans_are_not_resumable() {
        // A completed scan (with or without warnings) is NOT resumable — it opens as a
        // result, rather than being hashed further. Only walking/hashing are resumable.
        assert!(!ScanStatus::Complete.is_resumable());
        assert!(!ScanStatus::CompleteWithWarnings.is_resumable());
        assert!(ScanStatus::Walking.is_resumable());
        assert!(ScanStatus::Hashing.is_resumable());
        assert!(!ScanStatus::Aborted.is_resumable());
    }

    #[test]
    fn scan_status_str_roundtrip_all_variants() {
        for st in [
            ScanStatus::Walking,
            ScanStatus::Hashing,
            ScanStatus::Complete,
            ScanStatus::CompleteWithWarnings,
            ScanStatus::Aborted,
        ] {
            assert_eq!(ScanStatus::parse(st.as_str()), Some(st), "roundtrip {st:?}");
        }
        // The new variant is a separate DB string, it does not merge with "complete".
        assert_eq!(
            ScanStatus::CompleteWithWarnings.as_str(),
            "complete_with_warnings"
        );
    }

    #[test]
    fn on_completion_maps_failures_to_status() {
        // 0 failures → Complete; any >0 → CompleteWithWarnings.
        assert_eq!(ScanStatus::on_completion(0), ScanStatus::Complete);
        assert_eq!(
            ScanStatus::on_completion(1),
            ScanStatus::CompleteWithWarnings
        );
        assert_eq!(
            ScanStatus::on_completion(9999),
            ScanStatus::CompleteWithWarnings
        );
    }
}

/// Scan status in the checkpoint DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Walking,
    Hashing,
    Complete,
    /// The scan finished, but some candidates were left without a committed hash (hardening:
    /// read errors / identity-mismatch). A full-fledged completed status: `is_completed()`
    /// true, `is_resumable()` false — it opens as a result, covers cwd in the commander,
    /// and is counted by retention as Complete. It differs from `Complete` only by a warning
    /// (the `hash_failures` counter). The status is set at completion time; here — only plumbing.
    CompleteWithWarnings,
    Aborted,
}

impl ScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanStatus::Walking => "walking",
            ScanStatus::Hashing => "hashing",
            ScanStatus::Complete => "complete",
            ScanStatus::CompleteWithWarnings => "complete_with_warnings",
            ScanStatus::Aborted => "aborted",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "walking" => Some(ScanStatus::Walking),
            "hashing" => Some(ScanStatus::Hashing),
            "complete" => Some(ScanStatus::Complete),
            "complete_with_warnings" => Some(ScanStatus::CompleteWithWarnings),
            "aborted" => Some(ScanStatus::Aborted),
            _ => None,
        }
    }

    /// The scan can be continued (the walk or hashing is not finished).
    pub fn is_resumable(self) -> bool {
        matches!(self, ScanStatus::Walking | ScanStatus::Hashing)
    }

    /// The scan is finished — with warnings (`CompleteWithWarnings`) or without (`Complete`).
    /// A finished scan is NOT resumable (`is_resumable()` false for both): it opens as a
    /// result, covers cwd in the commander, and is counted by retention as a full-fledged one.
    pub fn is_completed(self) -> bool {
        matches!(
            self,
            ScanStatus::Complete | ScanStatus::CompleteWithWarnings
        )
    }

    /// The final status of a finished scan by the number of uncommitted candidates:
    /// `>0` → `CompleteWithWarnings` (a visible warning + the `hash_failures` counter),
    /// otherwise `Complete`. The single decision point — called in `run_phases` at the finish.
    pub fn on_completion(hash_failures: u64) -> ScanStatus {
        if hash_failures > 0 {
            ScanStatus::CompleteWithWarnings
        } else {
            ScanStatus::Complete
        }
    }
}

/// Sub-stage of the walk phase (UX cosmetics). Before this, on
/// "Phase 1/3" the same counter "Walked: X entries · Y files" in a row
/// showed TWO different processes (the real FS walk → batch-insert of the manifest
/// into SQLite), and the file counter climbed 0→N twice — the user saw "two passes over
/// the disk", even though the disk was read once. Now the header names the sub-stage directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkStage {
    /// Step A — the real filesystem walk (`ignore::WalkBuilder` + lstat
    /// + filters by size/extension/non-UTF8 guard). Heavy: reads the disk.
    Scanning,
    /// Step B — writing the accumulated manifest into SQLite in `WALK_BATCH` batches.
    /// Light: iterates over a `Vec` in RAM, the disk is touched only for WAL commits.
    Persisting,
}

/// Pipeline phase — for displaying progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Walking(WalkStage),
    Hashing,
    Grouping,
}

/// A progress event from the scan worker to the UI.
#[derive(Debug, Clone)]
pub enum ScanProgress {
    Phase(ScanPhase),
    /// A text notification for the scan screen and the log: e.g. an estimate of the
    /// peak memory of the grouping phase and a comparison with free RAM before phase 3/3.
    Notice(String),
    Walked {
        /// Total FS entries seen during the walk (directories + files) — grows monotonically.
        entries: u64,
        /// Files that passed the filters (size, extensions) — will go into the manifest.
        files: u64,
        /// The current walk path — for the scan screen.
        current_path: Option<PathBuf>,
    },
    Hashing {
        files_done: u64,
        files_total: u64,
        bytes_done: u64,
        bytes_total: u64,
        /// Progress of the current hashing batch — for a timely Esc.
        chunk_done: u64,
        chunk_total: u64,
        /// A representative path of the current hashing batch — for the scan screen.
        current_path: Option<PathBuf>,
        /// Measured read speed, bytes/s (EMA).
        rate_bytes_per_sec: u64,
        /// Estimate of the remaining time, seconds (0 — not estimated yet).
        eta_secs: u64,
        /// Candidates that have not received a hash by this point (read error / identity-mismatch),
        /// for the "Failed to hash: N" line on the scan screen. Cumulative over the session.
        hash_failures: u64,
    },
    Done(ScanSummary),
}

/// Summary of a finished scan.
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    pub files_scanned: u64,
    pub groups_found: usize,
    pub total_reclaimable_bytes: u64,
    /// Total volume of hashed files.
    pub bytes_hashed: u64,
    /// Accumulated active scan time, seconds.
    pub elapsed_seconds: f64,
    /// Candidates without a committed hash at the moment of completion. 0 → status
    /// `Complete`; >0 → `CompleteWithWarnings`. Counted in; here always 0.
    pub hash_failures: u64,
}

/// Scan result: lightweight group summaries + the scan summary. Full
/// `DuplicateGroup`s are no longer returned to the UI (on /tank — gigabytes); group
/// members are read from the DB on demand (`store::group_files`).
#[derive(Debug, Clone)]
pub struct ScanResults {
    /// The result's scan_id — so that action marks are saved to the right scan.
    pub scan_id: i64,
    /// Lightweight group summaries "by benefit" (read from `file_group` after materialization).
    pub summaries: Vec<GroupSummary>,
    pub summary: ScanSummary,
}

/// Details about a found unfinished/past scan — for the Resume screen.
#[derive(Debug, Clone)]
pub struct ResumeInfo {
    pub scan_id: i64,
    pub created_at: String,
    pub status: ScanStatus,
    pub roots: Vec<PathBuf>,
    /// Hashing candidates (files with a duplicated size), NOT the whole manifest —
    /// an honest denominator: by the manifest a finished scan came out to "23%".
    pub files_total: u64,
    pub files_hashed: u64,
    /// Candidate volume in bytes — an honest % of the hashing phase (files are too varied
    /// in size to judge progress by their count).
    pub cand_bytes_total: u64,
    pub cand_bytes_hashed: u64,
    /// The finished scan's result from `scan_stats` — for the session list: how many files
    /// were scanned and how much space will be reclaimed (for unfinished ones = 0).
    pub files_scanned: u64,
    pub reclaimable_bytes: u64,
}

/// The environment in which the scan ran — for statistics and comparing runs.
#[derive(Debug, Clone, Default)]
pub struct ScanEnvironment {
    /// Storage type: `hdd` / `ssd` / `nvme` / `mixed` / `unknown`.
    pub storage_type: String,
    /// Pool layout: `raidz1` / `raidz2` / `raidz3` / `mirror` / `stripe` / `mixed` / `unknown`.
    pub pool_layout: String,
    /// OpenZFS version (for example "2.3.1").
    pub zfs_version: String,
}

/// A statistics row for a single scan — for the `--stats` report.
#[derive(Debug, Clone)]
pub struct ScanStatsRow {
    pub scan_id: i64,
    pub created_at: String,
    pub status: String,
    pub roots: Vec<PathBuf>,
    pub elapsed_seconds: f64,
    pub storage_type: String,
    pub pool_layout: String,
    pub zfs_version: String,
    pub files_scanned: u64,
    pub bytes_hashed: u64,
    pub groups_found: u64,
    pub reclaimable_bytes: u64,
    /// Candidates without a committed hash at the moment of completion. Read in
    /// the `--stats` output (`list_stats` → the session table).
    pub hash_failures: u64,
}
