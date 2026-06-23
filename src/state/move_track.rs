// SPDX-License-Identifier: Apache-2.0
//! Diff between two scans of the same root: what stayed unchanged,
//! moved (by inode or by hash), changed, was deleted, appeared — and
//! separately «a duplicate arrived» (a new file whose hash was already seen in the old
//! scan). Movement is determined by an inode→hash fallback.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::error::Result;
use crate::state::ScanStore;

/// A file row from the scan manifest.
#[derive(Debug, Clone)]
pub struct FileRow {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    pub device: u64,
    pub inode: u64,
    pub hash: Option<[u8; 32]>,
}

/// Category of a file's change between the old and new scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileChange {
    Modified {
        old_path: PathBuf,
        new_path: PathBuf,
    },
    MovedByInode {
        from: PathBuf,
        to: PathBuf,
    },
    MovedByHash {
        from: PathBuf,
        to: PathBuf,
    },
    Deleted {
        path: PathBuf,
    },
    New {
        path: PathBuf,
    },
    /// A new file whose hash was already seen in the old scan — «a duplicate arrived».
    NewDupCandidate {
        path: PathBuf,
        peers_in_old: Vec<PathBuf>,
    },
}

/// Summary of a two-scan diff by category.
#[derive(Debug, Clone, Default)]
pub struct DiffReport {
    pub old_scan_id: i64,
    pub new_scan_id: i64,
    pub root: PathBuf,
    pub unchanged_count: u64,
    pub modified: Vec<FileChange>,
    pub moved_inode: Vec<FileChange>,
    pub moved_hash: Vec<FileChange>,
    pub deleted: Vec<FileChange>,
    pub new: Vec<FileChange>,
    pub new_dup_candidates: Vec<FileChange>,
    pub elapsed_ms: u64,
}

/// Compares scan `old_scan_id` and `new_scan_id` under the common root `root`.
pub fn diff(
    store: &ScanStore,
    old_scan_id: i64,
    new_scan_id: i64,
    root: &Path,
) -> Result<DiffReport> {
    let mut bench = crate::bench::start("diff_scans").attach_dir(root);
    let start = Instant::now();

    // The directory boundary is a component-wise `Path::starts_with` (not a string LIKE):
    // `/x` does NOT catch `/x2`, and `%`/`_` in a path do not act as wildcards.
    let old_rows: Vec<FileRow> = store
        .files_for_scan(old_scan_id)?
        .into_iter()
        .filter(|row| row.path.starts_with(root))
        .collect();
    let new_rows: Vec<FileRow> = store
        .files_for_scan(new_scan_id)?
        .into_iter()
        .filter(|row| row.path.starts_with(root))
        .collect();
    bench.set_entries((old_rows.len() + new_rows.len()) as u64);

    // Indexes over the new scan for matching.
    let mut new_by_path: HashMap<&Path, &FileRow> = HashMap::new();
    let mut new_by_inode: HashMap<(u64, u64), Vec<&FileRow>> = HashMap::new();
    let mut new_by_hash: HashMap<[u8; 32], Vec<&FileRow>> = HashMap::new();
    for row in &new_rows {
        new_by_path.insert(row.path.as_path(), row);
        new_by_inode
            .entry((row.device, row.inode))
            .or_default()
            .push(row);
        if let Some(hash) = row.hash {
            new_by_hash.entry(hash).or_default().push(row);
        }
    }
    // Hashes of the old scan — for detecting «a duplicate arrived».
    let mut old_by_hash: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();
    for row in &old_rows {
        if let Some(hash) = row.hash {
            old_by_hash.entry(hash).or_default().push(row.path.clone());
        }
    }

    let mut report = DiffReport {
        old_scan_id,
        new_scan_id,
        root: root.to_path_buf(),
        ..Default::default()
    };
    // Paths of the new scan already matched to the old one (as unchanged/modified/
    // a moved target) — do not count them as «new».
    let mut matched_new: HashSet<PathBuf> = HashSet::new();

    for old in &old_rows {
        // 1. The same path exists in the new scan.
        if let Some(nr) = new_by_path.get(old.path.as_path()) {
            matched_new.insert(nr.path.clone());
            if nr.size == old.size && nr.mtime == old.mtime {
                report.unchanged_count += 1;
            } else {
                report.modified.push(FileChange::Modified {
                    old_path: old.path.clone(),
                    new_path: nr.path.clone(),
                });
            }
            continue;
        }
        // 2. The path disappeared — look for a move by inode (same device+inode, size).
        if let Some(candidates) = new_by_inode.get(&(old.device, old.inode)) {
            if let Some(target) = candidates
                .iter()
                .find(|nr| nr.size == old.size && !matched_new.contains(&nr.path))
            {
                matched_new.insert(target.path.clone());
                report.moved_inode.push(FileChange::MovedByInode {
                    from: old.path.clone(),
                    to: target.path.clone(),
                });
                continue;
            }
        }
        // 3. Otherwise — a move by content (same hash, different path).
        if let Some(hash) = old.hash {
            if let Some(candidates) = new_by_hash.get(&hash) {
                if let Some(target) = candidates
                    .iter()
                    .find(|nr| nr.path != old.path && !matched_new.contains(&nr.path))
                {
                    matched_new.insert(target.path.clone());
                    report.moved_hash.push(FileChange::MovedByHash {
                        from: old.path.clone(),
                        to: target.path.clone(),
                    });
                    continue;
                }
            }
        }
        // 4. Found nothing — the file was deleted.
        report.deleted.push(FileChange::Deleted {
            path: old.path.clone(),
        });
    }

    // New files — those not matched to any old row.
    for nr in &new_rows {
        if matched_new.contains(&nr.path) {
            continue;
        }
        // «A duplicate arrived»: the new file's hash was already seen in the old scan.
        if let Some(hash) = nr.hash {
            if let Some(peers) = old_by_hash.get(&hash) {
                report.new_dup_candidates.push(FileChange::NewDupCandidate {
                    path: nr.path.clone(),
                    peers_in_old: peers.clone(),
                });
                continue;
            }
        }
        report.new.push(FileChange::New {
            path: nr.path.clone(),
        });
    }

    report.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::scan::ScanConfig;
    use crate::state::ManifestRow;

    fn row(path: &str, size: u64, inode: u64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size,
            mtime: 100,
            device: 1,
            inode,
            ..Default::default()
        }
    }

    fn setup() -> ScanStore {
        ScanStore::open_in_memory().unwrap()
    }

    #[test]
    fn move_by_inode_detects_rename() {
        let mut store = setup();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let old = store.begin_scan(&cfg).unwrap();
        store.record_files(old, &[row("/x/a.txt", 10, 7)]).unwrap();
        let new = store.begin_scan(&cfg).unwrap();
        // Same inode+device+size, new path → move by inode.
        store.record_files(new, &[row("/x/b.txt", 10, 7)]).unwrap();

        let report = diff(&store, old, new, Path::new("/x")).unwrap();
        assert_eq!(report.moved_inode.len(), 1);
        assert_eq!(report.deleted.len(), 0);
        assert_eq!(report.new.len(), 0);
        assert!(matches!(
            &report.moved_inode[0],
            FileChange::MovedByInode { from, to }
                if from == Path::new("/x/a.txt") && to == Path::new("/x/b.txt")
        ));
    }

    #[test]
    fn move_by_hash_detects_cross_device() {
        let mut store = setup();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let old = store.begin_scan(&cfg).unwrap();
        store.record_files(old, &[row("/x/a.bin", 10, 1)]).unwrap();
        store
            .record_hashes(old, &[(PathBuf::from("/x/a.bin"), [9u8; 32])])
            .unwrap();
        let new = store.begin_scan(&cfg).unwrap();
        // Different inode (cross-device), but the same hash → move by content.
        let mut moved = row("/x/sub/a.bin", 10, 999);
        moved.device = 2;
        store.record_files(new, &[moved]).unwrap();
        store
            .record_hashes(new, &[(PathBuf::from("/x/sub/a.bin"), [9u8; 32])])
            .unwrap();

        let report = diff(&store, old, new, Path::new("/x")).unwrap();
        assert_eq!(report.moved_hash.len(), 1, "{report:?}");
        assert_eq!(report.deleted.len(), 0);
        assert_eq!(report.new.len(), 0);
    }

    #[test]
    fn new_file_with_known_hash_is_dup_candidate() {
        let mut store = setup();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let old = store.begin_scan(&cfg).unwrap();
        store
            .record_files(old, &[row("/x/keep.bin", 10, 1)])
            .unwrap();
        store
            .record_hashes(old, &[(PathBuf::from("/x/keep.bin"), [5u8; 32])])
            .unwrap();
        let new = store.begin_scan(&cfg).unwrap();
        // /x/keep.bin stays + /x/copy.bin appears with the same hash.
        store
            .record_files(new, &[row("/x/keep.bin", 10, 1), row("/x/copy.bin", 10, 2)])
            .unwrap();
        store
            .record_hashes(
                new,
                &[
                    (PathBuf::from("/x/keep.bin"), [5u8; 32]),
                    (PathBuf::from("/x/copy.bin"), [5u8; 32]),
                ],
            )
            .unwrap();

        let report = diff(&store, old, new, Path::new("/x")).unwrap();
        assert_eq!(report.unchanged_count, 1);
        assert_eq!(report.new_dup_candidates.len(), 1, "{report:?}");
        if let FileChange::NewDupCandidate { path, peers_in_old } = &report.new_dup_candidates[0] {
            assert_eq!(path, Path::new("/x/copy.bin"));
            assert_eq!(peers_in_old, &[PathBuf::from("/x/keep.bin")]);
        } else {
            panic!("expected NewDupCandidate");
        }
    }

    #[test]
    fn deleted_only_when_no_match() {
        let mut store = setup();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let old = store.begin_scan(&cfg).unwrap();
        store
            .record_files(old, &[row("/x/gone.txt", 10, 1)])
            .unwrap();
        let new = store.begin_scan(&cfg).unwrap();
        store
            .record_files(new, &[row("/x/other.txt", 20, 2)])
            .unwrap();

        let report = diff(&store, old, new, Path::new("/x")).unwrap();
        assert_eq!(report.deleted.len(), 1);
        assert_eq!(report.new.len(), 1);
        assert_eq!(report.moved_inode.len(), 0);
        assert_eq!(report.moved_hash.len(), 0);
    }

    #[test]
    fn diff_excludes_sibling_prefix() {
        // The root /x must not capture the neighbouring /x2 (previously SQL LIKE '/x%' caught
        // both → the neighbour from /x2 was falsely considered deleted from /x).
        let mut store = setup();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let old = store.begin_scan(&cfg).unwrap();
        store
            .record_files(
                old,
                &[row("/x/a.txt", 10, 1), row("/x2/sibling.txt", 10, 2)],
            )
            .unwrap();
        let new = store.begin_scan(&cfg).unwrap();
        store.record_files(new, &[row("/x/a.txt", 10, 1)]).unwrap();

        let report = diff(&store, old, new, Path::new("/x")).unwrap();
        assert_eq!(
            report.deleted.len(),
            0,
            "neighbour /x2 does not belong to root /x"
        );
        assert_eq!(report.new.len(), 0);
        assert_eq!(report.unchanged_count, 1);
    }
}
