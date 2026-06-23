// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::model::action::ActionKind;

/// A file that is part of a duplicate group.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    pub device: u64,
    pub inode: u64,
    /// The "keeper" file — it remains, no action is applied to it.
    pub is_keeper: bool,
    /// The planned action on the file (if marked by the user).
    pub action: Option<ActionKind>,
}

impl FileEntry {
    /// Files with identical (device, inode) are the same physical file
    /// (already hardlinked): deleting one will not free any space.
    pub fn same_physical(&self, other: &FileEntry) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

/// A group of byte-for-byte identical files.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    pub id: usize,
    /// The size of one file (the same for all in the group).
    pub size_bytes: u64,
    /// blake3 hash of the contents in hex.
    pub hash: String,
    pub files: Vec<FileEntry>,
}

impl DuplicateGroup {
    /// How much space is freed if one file from the group is kept.
    pub fn reclaimable_bytes(&self) -> u64 {
        let extra = self.files.len().saturating_sub(1) as u64;
        self.size_bytes * extra
    }
}

/// Sorts groups by descending reclaimable space and reassigns `id`
/// in display order.
pub fn sort_groups_by_benefit(groups: &mut [DuplicateGroup]) {
    groups.sort_by_key(|group| std::cmp::Reverse(group.reclaimable_bytes()));
    for (index, group) in groups.iter_mut().enumerate() {
        group.id = index;
    }
}

/// A group of directories with matching SCANNED contents. The signature is the blake3 of the sorted list (relative path, file hash)
/// over all files under the directory; the same for directories with the same tree. It is emitted ONLY
/// for COMPLETE directories (every file under them has a hash) — a directory with an unhashed
/// (unique-size / failure) file is suppressed, so that an extra such file does not produce a false twin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirGroup {
    pub id: u32,
    pub signature: String,
    pub paths: Vec<PathBuf>,
    /// Files in one directory of the group (the same for all — same signature).
    pub file_count: u32,
    /// Total size of files in one directory (the same for all in the group).
    pub size_per_dir: u64,
}

impl DirGroup {
    /// How much space is freed if one directory from the group is kept.
    pub fn reclaimable_bytes(&self) -> u64 {
        let extra = self.paths.len().saturating_sub(1) as u64;
        self.size_per_dir.saturating_mul(extra)
    }
}

/// Sorts directory groups by descending benefit and reassigns `id`.
pub fn sort_dir_groups_by_benefit(groups: &mut [DirGroup]) {
    groups.sort_by(|a, b| {
        b.reclaimable_bytes()
            .cmp(&a.reclaimable_bytes())
            .then_with(|| a.signature.cmp(&b.signature))
    });
    for (index, group) in groups.iter_mut().enumerate() {
        group.id = index as u32;
    }
}

/// hex-encoding of hash bytes (the single source for the whole project).
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The signature of a directory's contents: blake3 of the SORTED list
/// `(relative path, file hex hash)`. Two directories with the same tree
/// (same relative paths and hashes) get the same signature. A pure
/// function — the single core for `build_dir_groups` and `store::dir_signatures_under`.
pub fn signature_of(entries: &[(String, String)]) -> String {
    let mut entries = entries.to_vec();
    entries.sort();
    let mut hasher = blake3::Hasher::new();
    for (rel, hash) in &entries {
        hasher.update(rel.as_bytes());
        hasher.update(&[0]);
        hasher.update(hash.as_bytes());
        hasher.update(&[0]);
    }
    hasher.finalize().to_hex().to_string()
}

/// Builds groups of duplicate directories from a list of hashed files
/// `(path, size, hex hash)`. A directory gets a signature from its subtree;
/// directories with the same signature and count >= 2 form a group.
/// A pure function — tested without a DB.
pub fn build_dir_groups(files: &[(PathBuf, u64, Option<String>)]) -> Vec<DirGroup> {
    use std::collections::HashMap;

    // Directory → (list of (rel_path, hash), total size, file count, INCOMPLETENESS).
    // A directory is INCOMPLETE if (recursively) under it there is a scanned
    // regular file without a committed hash — unique-size (not hashed) OR a hash failure.
    // Incomplete directories do NOT get a signature and are not grouped: otherwise an extra
    // unique-size file is invisible to the signature, and two directories differing only by it
    // would produce a false "twin" (the original defect — the input took only `hash IS NOT NULL`).
    type DirAccum = (Vec<(String, String)>, u64, u32, bool);
    let mut by_dir: HashMap<PathBuf, DirAccum> = HashMap::new();
    for (path, size, hash) in files {
        for dir in path.ancestors().skip(1) {
            if let Ok(rel) = path.strip_prefix(dir) {
                let entry = by_dir.entry(dir.to_path_buf()).or_default();
                match hash {
                    Some(h) => {
                        entry
                            .0
                            .push((rel.to_string_lossy().into_owned(), h.clone()));
                        entry.1 += size;
                        entry.2 += 1;
                    }
                    // A file without a hash makes THIS directory (and, via the ancestors loop, all
                    // ancestors) incomplete.
                    None => entry.3 = true,
                }
            }
        }
    }

    // Directory signature → list of (path, size, file count). Incomplete ones — we skip.
    let mut by_sig: HashMap<String, Vec<(PathBuf, u64, u32)>> = HashMap::new();
    for (dir, (entries, total, count, incomplete)) in by_dir {
        if incomplete {
            continue;
        }
        let sig = signature_of(&entries);
        by_sig.entry(sig).or_default().push((dir, total, count));
    }

    let mut groups: Vec<DirGroup> = by_sig
        .into_iter()
        .filter(|(_, dirs)| dirs.len() >= 2)
        .map(|(signature, dirs)| {
            // For all directories in the group the size and file count are identical.
            let size_per_dir = dirs[0].1;
            let file_count = dirs[0].2;
            let mut paths: Vec<PathBuf> = dirs.into_iter().map(|(dir, _, _)| dir).collect();
            paths.sort();
            DirGroup {
                id: 0,
                signature,
                paths,
                file_count,
                size_per_dir,
            }
        })
        .collect();
    sort_dir_groups_by_benefit(&mut groups);
    groups
}

/// Directory-signature algorithm (the `ScanConfig.dir_sig_algo` field).
/// `Old` — the current top-down `build_dir_groups` (the default). `Merkle` —
/// a streaming walk with O(depth) memory (see `build_dir_signatures_streaming`).
/// Both produce IDENTICAL equivalence classes (group memberships); per-row
/// hex values differ. `#[serde(other)]` is NOT needed — for old
/// checkpoints `#[serde(default)]` on the `ScanConfig.dir_sig_algo` field will kick in
/// (→ `Old`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DirSigAlgo {
    /// Default: top-down — `build_dir_groups` collects all `(rel_path, file_hash)`
    /// under each directory and hashes them. Peak memory ≈ 2.5 KiB/file × depth.
    #[default]
    Old,
    /// Opt-in (the `--merkle-dirs` flag): streaming bottom-up Merkle — memory
    /// O(depth × width of the current path). See `build_dir_signatures_streaming`.
    Merkle,
}

/// Streaming bottom-up Merkle dir-signatures. Reads `files` in
/// path-sorted order (ASC by `path`); keeps a stack of open
/// ancestors (one entry per level); emit is called on the CLOSING of a
/// directory (when the cursor leaves its subtree) and at EOF.
///
/// Each directory's signature = `signature_of(sorted [(basename(child), child_sig)])`,
/// where `child_sig` = `file_hash_hex` for a file, `MerkleSig` for a subdirectory.
/// The group membership is identical to `build_dir_groups`. The per-row hex values
/// differ (Merkle vs top-down).
///
/// Memory: the stack is O(depth); each frame holds the `(basename, hash)` of its DIRECT
/// children. At EOF the stack is merged bottom-up.
///
/// `emit(path, sig, total_size, file_count)` — a callback: called on the CLOSING of
/// each directory; the caller usually streams into `materialize_dir_groups`.
/// Errors from `emit` are propagated.
pub fn build_dir_signatures_streaming<I, F>(files: I, mut emit: F) -> Result<()>
where
    I: IntoIterator<Item = (PathBuf, u64, Option<String>)>,
    F: FnMut(PathBuf, String, u64, u32) -> Result<()>,
{
    struct Frame {
        path: PathBuf,
        entries: Vec<(String, String)>,
        size: u64,
        count: u32,
        // The directory is incomplete — under it there is a file without a hash (unique-size / failure).
        // An incomplete frame is NOT emitted, and on closing it marks the parent incomplete (ancestors too).
        incomplete: bool,
    }
    let mut stack: Vec<Frame> = Vec::new();

    // Closing a frame (shared code for closings during the walk and at EOF): an incomplete
    // directory is NOT emitted and marks the parent incomplete (this is how incompleteness rises to
    // ancestors); a complete one — emits the signature and mixes `(basename, sig)` into the parent.
    let mut close = |stack: &mut Vec<Frame>, popped: Frame| -> Result<()> {
        if popped.incomplete {
            if let Some(parent) = stack.last_mut() {
                parent.incomplete = true;
            }
            return Ok(());
        }
        let sig = signature_of(&popped.entries);
        emit(popped.path.clone(), sig.clone(), popped.size, popped.count)?;
        if let Some(parent) = stack.last_mut() {
            let basename = popped
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            parent.entries.push((basename, sig));
            parent.size += popped.size;
            parent.count += popped.count;
        }
        Ok(())
    };

    for (path, size, hash_hex) in files {
        // Close frames that are NOT ancestors of the current file. Lexicographic vs.
        // component-order of paths: `Path::starts_with` checks component-wise,
        // and `/a/b0/foo` does not start_with `/a/b` — the frame `/a/b` closes correctly.
        while let Some(top) = stack.last() {
            if path.starts_with(&top.path) {
                break;
            }
            let popped = stack.pop().expect("non-empty by the while condition");
            close(&mut stack, popped)?;
        }
        // Open the missing ancestors (from the root downward).
        let parent_dirs: Vec<PathBuf> = path
            .ancestors()
            .skip(1) // the file itself is not a directory
            .map(|p| p.to_path_buf())
            .collect::<Vec<_>>()
            .into_iter()
            .rev() // root first
            .collect();
        for dir in parent_dirs {
            if stack.iter().any(|frame| frame.path == dir) {
                continue;
            }
            stack.push(Frame {
                path: dir,
                entries: Vec::new(),
                size: 0,
                count: 0,
                incomplete: false,
            });
        }
        // The file — into the top frame. Without a hash (unique-size / failure) — the frame is incomplete,
        // we do not add it to entries (the signature of such a directory is not emitted anyway).
        if let Some(top) = stack.last_mut() {
            match hash_hex {
                Some(h) => {
                    let basename = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    top.entries.push((basename, h));
                    top.size += size;
                    top.count += 1;
                }
                None => top.incomplete = true,
            }
        }
    }
    // EOF: merge the stack bottom-up (from the top frame — that is, the deepest — to the root).
    while let Some(popped) = stack.pop() {
        close(&mut stack, popped)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn group(id: usize, size: u64, files: usize) -> DuplicateGroup {
        DuplicateGroup {
            id,
            size_bytes: size,
            hash: format!("h{id}"),
            files: (0..files)
                .map(|n| FileEntry {
                    path: PathBuf::from(format!("/f{id}_{n}")),
                    size,
                    mtime: 0,
                    device: 0,
                    inode: n as u64,
                    is_keeper: false,
                    action: None,
                })
                .collect(),
        }
    }

    #[test]
    fn sort_groups_by_benefit_orders_by_reclaim_desc_and_reids() {
        // benefit = size * (files-1): g0=10*1=10, g1=100*2=200, g2=50*0=0.
        let mut groups = vec![group(0, 10, 2), group(1, 100, 3), group(2, 50, 1)];
        sort_groups_by_benefit(&mut groups);
        let reclaim: Vec<u64> = groups.iter().map(|g| g.reclaimable_bytes()).collect();
        assert_eq!(reclaim, [200, 10, 0], "by descending benefit");
        let ids: Vec<usize> = groups.iter().map(|g| g.id).collect();
        assert_eq!(ids, [0, 1, 2], "ids reassigned in display order");
    }

    #[test]
    fn dir_group_reclaimable() {
        let g = DirGroup {
            id: 0,
            signature: "s".into(),
            paths: vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c"),
            ],
            file_count: 4,
            size_per_dir: 100,
        };
        // keep one of three → free 2 × 100.
        assert_eq!(g.reclaimable_bytes(), 200);
    }

    #[test]
    fn build_dir_groups_finds_identical_trees() {
        // /x/a and /x/b — identical contents (f1,f2 with the same hashes);
        // /x/c — an extra file, a different signature.
        let files = vec![
            (PathBuf::from("/x/a/f1"), 100, Some("h1".to_string())),
            (PathBuf::from("/x/a/f2"), 200, Some("h2".to_string())),
            (PathBuf::from("/x/b/f1"), 100, Some("h1".to_string())),
            (PathBuf::from("/x/b/f2"), 200, Some("h2".to_string())),
            (PathBuf::from("/x/c/f1"), 100, Some("h1".to_string())),
        ];
        let groups = build_dir_groups(&files);
        // There should be at least the group {/x/a, /x/b}. /x (the root) contains
        // the whole tree and is unique, /x/c is unique.
        let ab = groups
            .iter()
            .find(|g| g.paths.contains(&PathBuf::from("/x/a")))
            .expect("group with /x/a");
        assert!(ab.paths.contains(&PathBuf::from("/x/b")));
        assert_eq!(ab.file_count, 2);
        assert_eq!(ab.size_per_dir, 300);
        assert_eq!(ab.reclaimable_bytes(), 300);
        // /x/c must not end up in any group with /x/a.
        assert!(!ab.paths.contains(&PathBuf::from("/x/c")));
    }

    // === Merkle streaming tests ===

    #[test]
    fn merkle_sig_matches_old_sig_for_leaf_only_dir() {
        // Induction base: a directory with file children on one level produces the SAME
        // hex in Old and Merkle (entries are the same `(basename, file_hash)` pairs).
        let files = vec![
            (PathBuf::from("/d/a"), 10, Some("AAA".to_string())),
            (PathBuf::from("/d/b"), 20, Some("BBB".to_string())),
        ];
        // The old path will not return a group for /d (needs ≥2 directories), but the signature
        // of /d we can compute directly via signature_of — it should match.
        let expected = signature_of(&[
            ("a".to_string(), "AAA".to_string()),
            ("b".to_string(), "BBB".to_string()),
        ]);
        let mut got: Option<String> = None;
        build_dir_signatures_streaming(files, |path, sig, _, _| {
            if path == Path::new("/d") {
                got = Some(sig);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(got.as_deref(), Some(expected.as_str()), "/d: Merkle == Old");
    }

    #[test]
    fn merkle_equivalence_with_build_dir_groups_on_synthetic_tree() {
        // Plan §A equivalence: both algorithms produce the SAME group membership
        // (sorted path-sets). The per-row hex may differ.
        let files = vec![
            (PathBuf::from("/a/x.bin"), 10, Some("H1".to_string())),
            (PathBuf::from("/a/y.bin"), 20, Some("H2".to_string())),
            (PathBuf::from("/b/x.bin"), 10, Some("H1".to_string())),
            (PathBuf::from("/b/y.bin"), 20, Some("H2".to_string())),
            (PathBuf::from("/c/z.bin"), 5, Some("H3".to_string())),
        ];
        // Old: only groups ≥2.
        let old_groups = build_dir_groups(&files);
        let mut old_membership: Vec<Vec<PathBuf>> = old_groups
            .iter()
            .map(|g| {
                let mut paths = g.paths.clone();
                paths.sort();
                paths
            })
            .collect();
        old_membership.sort();
        // Merkle: collect all sigs, group by signature, filter count>=2.
        let mut rows: Vec<(PathBuf, String)> = Vec::new();
        build_dir_signatures_streaming(files, |path, sig, _, _| {
            rows.push((path, sig));
            Ok(())
        })
        .unwrap();
        let mut by_sig: std::collections::HashMap<String, Vec<PathBuf>> =
            std::collections::HashMap::new();
        for (path, sig) in rows {
            by_sig.entry(sig).or_default().push(path);
        }
        let mut merkle_membership: Vec<Vec<PathBuf>> = by_sig
            .into_values()
            .filter(|paths| paths.len() >= 2)
            .map(|mut paths| {
                paths.sort();
                paths
            })
            .collect();
        merkle_membership.sort();
        assert_eq!(
            merkle_membership, old_membership,
            "group membership must match: Merkle={:?} vs Old={:?}",
            merkle_membership, old_membership
        );
    }

    #[test]
    fn merkle_root_level_file_emits_sig_for_slash() {
        let files = vec![(PathBuf::from("/foo.bin"), 10, Some("H".to_string()))];
        let mut order: Vec<PathBuf> = Vec::new();
        build_dir_signatures_streaming(files, |path, _, _, _| {
            order.push(path);
            Ok(())
        })
        .unwrap();
        assert_eq!(order, vec![PathBuf::from("/")]);
    }

    #[test]
    fn merkle_lcp_churn_basic() {
        // /x/y/* come in a row (close once together), then /x/z/3 → /x/y closes,
        // /x/z opens; at EOF /x/z and /x and / merge.
        let files = vec![
            (PathBuf::from("/x/y/1"), 1, Some("A".to_string())),
            (PathBuf::from("/x/y/2"), 1, Some("B".to_string())),
            (PathBuf::from("/x/z/3"), 1, Some("C".to_string())),
        ];
        let mut order: Vec<PathBuf> = Vec::new();
        build_dir_signatures_streaming(files, |path, _, _, _| {
            order.push(path);
            Ok(())
        })
        .unwrap();
        // /x/y closed first (when /x/z arrived), then /x/z, /x, / at EOF.
        assert_eq!(
            order,
            vec![
                PathBuf::from("/x/y"),
                PathBuf::from("/x/z"),
                PathBuf::from("/x"),
                PathBuf::from("/"),
            ]
        );
    }

    #[test]
    fn merkle_single_file_dir_emits_sig() {
        // A directory with a single child is still emitted; the count>=2 filter is on the
        // materialize_dir_groups side, not here.
        let files = vec![(PathBuf::from("/lonely/only.bin"), 1, Some("H".to_string()))];
        let mut sigs: Vec<(PathBuf, u64, u32)> = Vec::new();
        build_dir_signatures_streaming(files, |path, _, size, count| {
            sigs.push((path, size, count));
            Ok(())
        })
        .unwrap();
        let lonely = sigs.iter().find(|(p, _, _)| p == Path::new("/lonely"));
        assert!(lonely.is_some(), "/lonely is emitted");
        let (_, size, count) = lonely.unwrap();
        assert_eq!(*size, 1);
        assert_eq!(*count, 1);
    }

    // === The completeness rule for dir-signatures ===
    // A `None` hash in the model represents ANY scanned file without a committed
    // hash: unique-size (not hashed) OR a hash failure. Both reasons suppress
    // a directory the same way.

    /// Old group membership (sorted path-sets) — for cross-checking with Merkle.
    fn membership_old(files: &[(PathBuf, u64, Option<String>)]) -> Vec<Vec<PathBuf>> {
        let mut m: Vec<Vec<PathBuf>> = build_dir_groups(files)
            .iter()
            .map(|g| {
                let mut p = g.paths.clone();
                p.sort();
                p
            })
            .collect();
        m.sort();
        m
    }

    /// Merkle group membership (≥2 directories with one signature) — for cross-checking with Old.
    fn membership_merkle(files: Vec<(PathBuf, u64, Option<String>)>) -> Vec<Vec<PathBuf>> {
        use std::collections::HashMap;
        let mut sorted = files;
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut rows: Vec<(PathBuf, String)> = Vec::new();
        build_dir_signatures_streaming(sorted, |path, sig, _, _| {
            rows.push((path, sig));
            Ok(())
        })
        .unwrap();
        let mut by_sig: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for (path, sig) in rows {
            by_sig.entry(sig).or_default().push(path);
        }
        let mut m: Vec<Vec<PathBuf>> = by_sig
            .into_values()
            .filter(|p| p.len() >= 2)
            .map(|mut p| {
                p.sort();
                p
            })
            .collect();
        m.sort();
        m
    }

    #[test]
    fn unique_size_extra_file_suppresses_false_dir_twin() {
        // (6a) ORIGINAL DEFECT: /x/a and /x/b have identical HASHED contents
        // (f1,f2); /x/b ADDITIONALLY contains a unique-size file z without a hash. Before the fix z was
        // invisible to the signature → sig(/x/a) == sig(/x/b) → a FALSE twin. Now /x/b
        // is incomplete and suppressed — there is no false group.
        let files = vec![
            (PathBuf::from("/x/a/f1"), 100, Some("h1".to_string())),
            (PathBuf::from("/x/a/f2"), 200, Some("h2".to_string())),
            (PathBuf::from("/x/b/f1"), 100, Some("h1".to_string())),
            (PathBuf::from("/x/b/f2"), 200, Some("h2".to_string())),
            (PathBuf::from("/x/b/z"), 7, None), // unique-size: not hashed
        ];
        let groups = build_dir_groups(&files);
        assert!(
            !groups
                .iter()
                .any(|g| g.paths.contains(&PathBuf::from("/x/b"))),
            "/x/b is incomplete (unique-size z) → suppressed, no false twin"
        );
        assert!(
            !groups
                .iter()
                .any(|g| g.paths.contains(&PathBuf::from("/x/a"))),
            "/x/a without a complete pair → not in a group"
        );
        // Control: REMOVE z — /x/a and /x/b become complete and form a group.
        let complete = &files[..4];
        let g = build_dir_groups(complete);
        assert!(
            g.iter().any(|g| g.paths.contains(&PathBuf::from("/x/a"))
                && g.paths.contains(&PathBuf::from("/x/b"))),
            "(6b) without unique-size — an exact pair produces a group"
        );
    }

    #[test]
    fn nested_unhashed_file_invalidates_all_ancestors() {
        // (6d) an unhashed file DEEP DOWN makes ALL ancestor directories incomplete.
        // /p/a contains a deep file without a hash → /p/a, /p/a/sub and /p are incomplete and suppressed;
        // the complete neighbor /p/b is emitted. Old and Merkle are consistent.
        let files = vec![
            (PathBuf::from("/p/a/x"), 10, Some("h".to_string())),
            (PathBuf::from("/p/a/sub/deep"), 20, None), // deep, without a hash
            (PathBuf::from("/p/b/x"), 10, Some("h".to_string())),
        ];
        // Old: /p/a is suppressed.
        let groups = build_dir_groups(&files);
        assert!(
            !groups
                .iter()
                .any(|g| g.paths.contains(&PathBuf::from("/p/a"))),
            "Old: /p/a is incomplete (a nested file without a hash)"
        );
        // Merkle: /p/a, /p/a/sub, /p are suppressed; /p/b is emitted.
        let mut sorted = files.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut emitted: Vec<PathBuf> = Vec::new();
        build_dir_signatures_streaming(sorted, |path, _, _, _| {
            emitted.push(path);
            Ok(())
        })
        .unwrap();
        for suppressed in ["/p/a", "/p/a/sub", "/p"] {
            assert!(
                !emitted.contains(&PathBuf::from(suppressed)),
                "Merkle: {suppressed} is suppressed"
            );
        }
        assert!(
            emitted.contains(&PathBuf::from("/p/b")),
            "Merkle: /p/b is complete → emitted"
        );
    }

    #[test]
    fn old_and_merkle_agree_with_incomplete_dirs() {
        // (6e) with incomplete directories Old and Merkle produce the SAME group membership.
        let files = vec![
            // Complete pair /t/a ≡ /t/b.
            (PathBuf::from("/t/a/p"), 10, Some("H1".to_string())),
            (PathBuf::from("/t/a/q"), 20, Some("H2".to_string())),
            (PathBuf::from("/t/b/p"), 10, Some("H1".to_string())),
            (PathBuf::from("/t/b/q"), 20, Some("H2".to_string())),
            // /t/c looks like a twin, but has a unique-size file without a hash → incomplete.
            (PathBuf::from("/t/c/p"), 10, Some("H1".to_string())),
            (PathBuf::from("/t/c/q"), 20, Some("H2".to_string())),
            (PathBuf::from("/t/c/u"), 7, None),
        ];
        let old = membership_old(&files);
        let merkle = membership_merkle(files.clone());
        assert_eq!(
            merkle, old,
            "Old and Merkle are consistent with incomplete directories"
        );
        assert!(
            !old.iter().flatten().any(|p| p == &PathBuf::from("/t/c")),
            "/t/c is suppressed (incomplete) — not a false twin"
        );
        assert!(
            old.iter()
                .any(|g| g.contains(&PathBuf::from("/t/a")) && g.contains(&PathBuf::from("/t/b"))),
            "complete pair {{/t/a,/t/b}} — a group"
        );
    }
}
