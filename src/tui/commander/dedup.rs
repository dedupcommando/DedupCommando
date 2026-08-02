// SPDX-License-Identifier: Apache-2.0
//! Panel dedup overlay: a cache keyed by the panel's current directory, read from the DB
//! on demand. The former `DedupIndex` kept the ENTIRE scan in RAM (a HashMap
//! by_path/by_hash/groups/… over all files — ~7 GiB on /tank); now only the file
//! attributes of visible directories live in memory (a `DirDedup` per panel cwd),
//! while summaries/group members are read from `store` on entry.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::model::duplicate::{hex_encode, DirTrust};
use crate::state::{DedupRow, LiveDirSignature};

/// File status with respect to deduplication (color semaphore).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupStatus {
    /// The file is not in the manifest of the last scan.
    NotInScan,
    /// In the manifest, but not yet hashed.
    Unhashed,
    /// Hashed, no duplicates.
    HashedUnique,
    /// Not hashed, but size+mtime matched another — a likely duplicate (F4 needed).
    LikelyDuplicate,
    /// Hashed, a byte-for-byte duplicate confirmed.
    VerifiedDup,
    /// Hash matched, but the devices differ — a hardlink is impossible (caution).
    DangerousDup,
}

impl DedupStatus {
    /// Status glyph for the panel column.
    pub fn glyph(self) -> char {
        match self {
            DedupStatus::NotInScan => '·',
            DedupStatus::Unhashed => '?',
            DedupStatus::HashedUnique => '-',
            DedupStatus::LikelyDuplicate => '≈',
            DedupStatus::VerifiedDup => '=',
            DedupStatus::DangerousDup => '⚠',
        }
    }

    /// Pure classification of the dedup status from a DB row. 6 semaphore branches;
    /// `NotInScan` is returned by the caller when the file is not in the map (no row at all).
    pub fn classify(row: &DedupRow) -> DedupStatus {
        match &row.hashed {
            // Not hashed: size+mtime matched another → a likely duplicate (F4).
            None => {
                if row.size_mtime_count >= 2 {
                    DedupStatus::LikelyDuplicate
                } else {
                    DedupStatus::Unhashed
                }
            }
            // Hashed: a duplicate by hash; the devices differ → a hardlink is impossible.
            Some(_) => {
                if row.dup_count >= 2 {
                    if row.distinct_devices > 1 {
                        DedupStatus::DangerousDup
                    } else {
                        DedupStatus::VerifiedDup
                    }
                } else {
                    DedupStatus::HashedUnique
                }
            }
        }
    }
}

/// Dedup attributes of a SINGLE panel directory: the status and hash of each
/// file, the size and typed signature of each subdirectory. Tens-hundreds of entries — not the
/// whole scan.
#[derive(Debug, Default, Clone)]
pub struct DirDedup {
    /// file path → dedup status.
    pub status: HashMap<PathBuf, DedupStatus>,
    /// file path → hex hash (hashed only).
    pub hashes: HashMap<PathBuf, String>,
    /// subdirectory path → total size of scan files under it.
    pub dir_sizes: HashMap<PathBuf, u64>,
    /// subdirectory path → content signature WITH the trust the ledger vouched at read time.
    /// A suppressed directory is absent. The untyped string accessor is gone on purpose: whoever
    /// wants a signature must decide what its trust means, and only `Trusted` may look exact.
    pub dir_signatures: HashMap<PathBuf, LiveDirSignature>,
}

impl DirDedup {
    /// Status of file `path` (not in the map → NotInScan).
    pub fn status_for(&self, path: &Path) -> DedupStatus {
        self.status
            .get(path)
            .copied()
            .unwrap_or(DedupStatus::NotInScan)
    }

    /// hex hash of file `path`, if it is hashed.
    pub fn hash_for(&self, path: &Path) -> Option<&str> {
        self.hashes.get(path).map(String::as_str)
    }

    /// Total size of scan files under subdirectory `path`.
    pub fn dir_size(&self, path: &Path) -> Option<u64> {
        self.dir_sizes.get(path).copied()
    }

    /// The TRUSTED content signature of subdirectory `path` — the only form that may enter a
    /// cross-panel exact-match set, a match count or bright highlighting.
    pub fn trusted_dir_signature(&self, path: &Path) -> Option<&str> {
        self.dir_signatures
            .get(path)
            .filter(|live| live.trust == DirTrust::Trusted)
            .map(|live| live.signature.as_str())
    }

    /// The signature and trust of subdirectory `path`, for rendering the explicit unverified
    /// state. Never feeds a match set.
    pub fn dir_signature_state(&self, path: &Path) -> Option<(&str, DirTrust)> {
        self.dir_signatures
            .get(path)
            .map(|live| (live.signature.as_str(), live.trust))
    }
}

/// Dedup cache keyed by the directories of visible panels. Replaces the global
/// `DedupIndex`: memory is bounded by the number of panels (`prune` discards directories
/// that are not in any panel). Filled in the background when a panel's cwd changes
/// (`fetch_panel_dedup` → `AppEvent::CommanderDirDedup`).
///
/// A failed load is cached as its error rather than as an empty `DirDedup`: an empty entry
/// renders as «nothing here is in the scan», and a store failure must never wear that costume.
#[derive(Debug, Default)]
pub struct DedupCache {
    by_cwd: HashMap<PathBuf, Result<DirDedup, String>>,
    /// cwd with a started but unfinished background request — we don't duplicate the fetch.
    pending: HashSet<PathBuf>,
}

impl DedupCache {
    /// Dedup data of directory `cwd`, if already loaded successfully. A failed load answers
    /// `None` here — fail-closed: no statuses, no signatures, no highlight.
    pub fn dir(&self, cwd: &Path) -> Option<&DirDedup> {
        match self.by_cwd.get(cwd) {
            Some(Ok(dir)) => Some(dir),
            _ => None,
        }
    }

    /// The load error for directory `cwd`, if its background read failed.
    pub fn error(&self, cwd: &Path) -> Option<&str> {
        match self.by_cwd.get(cwd) {
            Some(Err(message)) => Some(message.as_str()),
            _ => None,
        }
    }

    /// A background request is running for directory `cwd` (still loading).
    pub fn is_pending(&self, cwd: &Path) -> bool {
        self.pending.contains(cwd)
    }

    /// Directory `cwd` is covered by the scan — there are scan files under it (directly in
    /// the directory or in subdirectories). Corresponds to the former "dir is an ancestor
    /// of a scan file".
    pub fn covered(&self, cwd: &Path) -> bool {
        self.dir(cwd)
            .map(|dir| !dir.status.is_empty() || !dir.dir_sizes.is_empty())
            .unwrap_or(false)
    }

    /// Marks `cwd` as "fetch started".
    pub fn mark_pending(&mut self, cwd: PathBuf) {
        self.pending.insert(cwd);
    }

    /// Places the result of a directory's background request into the cache (clears pending).
    pub fn insert_dir(&mut self, cwd: PathBuf, dir: Result<DirDedup, String>) {
        self.pending.remove(&cwd);
        self.by_cwd.insert(cwd, dir);
    }

    /// Discards the cache of directories not in `keep` (the panels' current cwds) —
    /// keeps memory at the level of the number of open panels.
    pub fn prune(&mut self, keep: &HashSet<PathBuf>) {
        self.by_cwd.retain(|cwd, _| keep.contains(cwd));
    }

    /// Adds a hash computed on demand for a file into its directory's cache (F4/after a
    /// move). A duplicate is determined within the same directory: entering a group for
    /// the authoritative picture still reads the DB. If the directory is not yet in the
    /// cache — creates a lightweight entry with just this file. Fresh information supersedes a
    /// cached error: the hash was just computed, so the entry restarts from it.
    pub fn insert_hash(&mut self, path: PathBuf, hash: [u8; 32]) {
        let Some(parent) = path.parent().map(Path::to_path_buf) else {
            return;
        };
        let hex = hex_encode(&hash);
        let slot = self
            .by_cwd
            .entry(parent)
            .or_insert_with(|| Ok(DirDedup::default()));
        if slot.is_err() {
            *slot = Ok(DirDedup::default());
        }
        let dir = slot.as_mut().expect("just replaced any error");
        dir.hashes.insert(path, hex.clone());
        let same: Vec<PathBuf> = dir
            .hashes
            .iter()
            .filter(|(_, h)| **h == hex)
            .map(|(p, _)| p.clone())
            .collect();
        let status = if same.len() >= 2 {
            DedupStatus::VerifiedDup
        } else {
            DedupStatus::HashedUnique
        };
        for peer in same {
            dir.status.insert(peer, status);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(hashed: Option<&str>, dup: u32, devices: u32, sm: u32) -> DedupRow {
        DedupRow {
            hashed: hashed.map(str::to_string),
            dup_count: dup,
            distinct_devices: devices,
            size_mtime_count: sm,
        }
    }

    #[test]
    fn classify_covers_six_variants() {
        // Not hashed, size is unique → just Unhashed.
        assert_eq!(
            DedupStatus::classify(&row(None, 0, 0, 1)),
            DedupStatus::Unhashed
        );
        // Not hashed, size+mtime repeats → a likely duplicate.
        assert_eq!(
            DedupStatus::classify(&row(None, 0, 0, 2)),
            DedupStatus::LikelyDuplicate
        );
        // Hashed, only one such → unique.
        assert_eq!(
            DedupStatus::classify(&row(Some("aa"), 1, 1, 0)),
            DedupStatus::HashedUnique
        );
        // Hashed, a duplicate, one device → a confirmed duplicate.
        assert_eq!(
            DedupStatus::classify(&row(Some("aa"), 2, 1, 0)),
            DedupStatus::VerifiedDup
        );
        // Hashed, a duplicate, different devices → dangerous (no hardlink possible).
        assert_eq!(
            DedupStatus::classify(&row(Some("aa"), 2, 2, 0)),
            DedupStatus::DangerousDup
        );
        // NotInScan — not from classify: DirDedup returns it when the file is not in the map.
        assert_eq!(
            DirDedup::default().status_for(Path::new("/none")),
            DedupStatus::NotInScan
        );
    }

    #[test]
    fn insert_hash_marks_same_dir_duplicate() {
        let mut cache = DedupCache::default();
        cache.insert_hash(PathBuf::from("/d/x"), [9u8; 32]);
        assert_eq!(
            cache
                .dir(Path::new("/d"))
                .unwrap()
                .status_for(Path::new("/d/x")),
            DedupStatus::HashedUnique
        );
        // A second file with the same hash in the same directory → both VerifiedDup.
        cache.insert_hash(PathBuf::from("/d/y"), [9u8; 32]);
        let dir = cache.dir(Path::new("/d")).unwrap();
        assert_eq!(dir.status_for(Path::new("/d/x")), DedupStatus::VerifiedDup);
        assert_eq!(dir.status_for(Path::new("/d/y")), DedupStatus::VerifiedDup);
        assert_eq!(
            dir.hash_for(Path::new("/d/x")),
            dir.hash_for(Path::new("/d/y"))
        );
    }

    #[test]
    fn prune_drops_unkept_cwds() {
        let mut cache = DedupCache::default();
        cache.insert_dir(PathBuf::from("/a"), Ok(DirDedup::default()));
        cache.insert_dir(PathBuf::from("/b"), Ok(DirDedup::default()));
        let keep: HashSet<PathBuf> = [PathBuf::from("/a")].into_iter().collect();
        cache.prune(&keep);
        assert!(cache.dir(Path::new("/a")).is_some());
        assert!(cache.dir(Path::new("/b")).is_none());
    }

    /// A failed load is an error state, never an empty directory: `dir()` answers nothing (so no
    /// status, signature or highlight can be built from it) and the message stays readable until
    /// fresh information supersedes it.
    #[test]
    fn a_failed_load_is_an_error_not_an_empty_directory() {
        let mut cache = DedupCache::default();
        cache.mark_pending(PathBuf::from("/a"));
        cache.insert_dir(PathBuf::from("/a"), Err("boom".to_string()));
        assert!(cache.dir(Path::new("/a")).is_none(), "fail-closed");
        assert!(!cache.covered(Path::new("/a")));
        assert!(!cache.is_pending(Path::new("/a")));
        assert_eq!(cache.error(Path::new("/a")), Some("boom"));
        // A hash computed on demand is fresh information and restarts the entry.
        cache.insert_hash(PathBuf::from("/a/x"), [9u8; 32]);
        assert!(cache.error(Path::new("/a")).is_none());
        assert!(cache.dir(Path::new("/a")).is_some());
    }

    /// Only a `Trusted` live signature may look exact; the untrusted one stays inspectable with
    /// its trust beside it.
    #[test]
    fn only_a_trusted_signature_feeds_exact_matching() {
        let mut dir = DirDedup::default();
        dir.dir_signatures.insert(
            PathBuf::from("/d/trusted"),
            LiveDirSignature {
                signature: "aa".into(),
                trust: DirTrust::Trusted,
            },
        );
        dir.dir_signatures.insert(
            PathBuf::from("/d/unknown"),
            LiveDirSignature {
                signature: "bb".into(),
                trust: DirTrust::Untrusted,
            },
        );
        assert_eq!(
            dir.trusted_dir_signature(Path::new("/d/trusted")),
            Some("aa")
        );
        assert_eq!(
            dir.trusted_dir_signature(Path::new("/d/unknown")),
            None,
            "an untrusted signature must never enter a match set"
        );
        assert_eq!(
            dir.dir_signature_state(Path::new("/d/unknown")),
            Some(("bb", DirTrust::Untrusted)),
            "but it stays inspectable, with its trust beside it"
        );
    }
}
