// SPDX-License-Identifier: Apache-2.0
//! Background move batch — runs OUTSIDE the UI thread so that a heavy
//! move (blake3 hash of candidates, cross-dataset copy) does not freeze the interface.
//!
//! Self-contained: only `db_path` + FS, without `App`/`CommanderState`. Files are
//! dedup-aware (duplicate → `name.dupN`); directories are a plain move without dedup.
//! The result goes out to the main thread via `AppEvent::CommanderMoveDone` and is
//! applied in `super::apply_move_outcome` (Undo log, hash index, re-read).

use std::path::{Path, PathBuf};

use crate::model::action::MoveEvent;
use crate::state::ScanStore;

use super::state::LoadTarget;

/// Result of the background move batch — applied to the UI on the main thread.
#[derive(Default)]
pub struct MoveBatchOutcome {
    /// Pairs (from, to) for the Undo log.
    pub moved: Vec<(PathBuf, PathBuf)>,
    /// Known hashes of moved files — into the in-memory index.
    pub hashes: Vec<(PathBuf, [u8; 32])>,
    /// Moved files without a known hash — hash them in the background (growing the index).
    pub to_hash: Vec<PathBuf>,
    /// How many items failed to move.
    pub failed: usize,
    /// How many were moved as duplicates (name `name.dupN`).
    pub dups: usize,
    /// Which panels to re-read and where to put the cursor (filled in by `spawn_move`).
    pub reload: Vec<(LoadTarget, Option<PathBuf>)>,
    /// Label for the status line (e.g. «receiver 2» / «panel 2»).
    pub label: String,
}

/// Moves the batch `sources` into the directory `dest_dir`. Files are dedup-aware,
/// directories are moved whole. Writes the `move_event` log and the hash cache to the DB.
/// The UI is not involved here.
pub fn run_batch(
    db_path: &Path,
    sources: &[PathBuf],
    dest_dir: &Path,
    scan_id: Option<i64>,
) -> MoveBatchOutcome {
    let mut out = MoveBatchOutcome::default();
    let mut store = ScanStore::open(db_path).ok();
    for src in sources {
        move_item(&mut store, scan_id, src, dest_dir, &mut out);
    }
    out
}

/// Moves a single item `src` into the directory `dest_dir`: a file is dedup-aware, a
/// directory — on a name collision MERGES the contents, otherwise moves it whole. Recursive.
fn move_item(
    store: &mut Option<ScanStore>,
    scan_id: Option<i64>,
    src: &Path,
    dest_dir: &Path,
    out: &mut MoveBatchOutcome,
) {
    let meta = match std::fs::symlink_metadata(src) {
        Ok(meta) => meta,
        Err(_) => {
            out.failed += 1;
            return;
        }
    };
    if meta.file_type().is_symlink() {
        out.failed += 1;
        return;
    }
    if meta.is_dir() {
        move_dir_item(store, scan_id, src, dest_dir, out);
    } else {
        move_file_item(store, scan_id, src, meta.len(), dest_dir, out);
    }
}

/// Directory: if `dest_dir` already has a directory with the same name — MERGE the
/// contents, otherwise move it whole (rename | recursive copy). Without
/// merging, a `name.1` used to appear alongside — now the contents are poured into the existing one.
fn move_dir_item(
    store: &mut Option<ScanStore>,
    scan_id: Option<i64>,
    src: &Path,
    dest_dir: &Path,
    out: &mut MoveBatchOutcome,
) {
    let name = match src.file_name() {
        Some(name) => name,
        None => {
            out.failed += 1;
            return;
        }
    };
    let target = dest_dir.join(name);
    if target.is_dir() {
        merge_dir(store, scan_id, src, &target, out);
    } else {
        match crate::actions::move_dir::move_dir_into(src, dest_dir) {
            Ok(final_dest) => {
                record(store.as_mut(), scan_id, src, &final_dest, None, false);
                out.moved.push((src.to_path_buf(), final_dest));
            }
            Err(err) => fail(out, src, &err),
        }
    }
}

/// Records a move failure: the reason goes to `dedcom.log` (previously `Err(_) =>
/// failed += 1` silently lost it, including the `rsync` hint for a cross-dataset move).
fn fail(out: &mut MoveBatchOutcome, src: &Path, err: &crate::error::AppError) {
    // Both src and {err} (cross_device_error embeds raw src/dest)
    // may carry control bytes — we sanitize the whole string before logging.
    tracing::warn!(
        "{}",
        crate::textsan::terminal(&format!("move failed: {} — {err}", src.display()))
    );
    out.failed += 1;
}

/// Merges the contents of `src` into the existing directory `target_dir`: each item
/// is moved inside (files dedup-aware, subdirectories — recursively), then the
/// emptied `src` is removed. If something failed to move, `src` will remain.
fn merge_dir(
    store: &mut Option<ScanStore>,
    scan_id: Option<i64>,
    src: &Path,
    target_dir: &Path,
    out: &mut MoveBatchOutcome,
) {
    let children: Vec<PathBuf> = match std::fs::read_dir(src) {
        Ok(read) => read.flatten().map(|entry| entry.path()).collect(),
        Err(_) => {
            out.failed += 1;
            return;
        }
    };
    for child in &children {
        move_item(store, scan_id, child, target_dir, out);
    }
    // We remove the emptied source; if any items remained un-moved — remove_dir will not succeed.
    let _ = std::fs::remove_dir(src);
}

/// File — dedup-aware move into `dest_dir`: pre-filter by size, blake3 only of
/// candidates of the same size; duplicate → `name.dupN`, otherwise move_into_dir.
fn move_file_item(
    store: &mut Option<ScanStore>,
    scan_id: Option<i64>,
    src: &Path,
    size: u64,
    dest_dir: &Path,
    out: &mut MoveBatchOutcome,
) {
    use std::os::unix::fs::MetadataExt;
    let candidates = super::same_size_files(dest_dir, size);
    let mut dup = false;
    let mut hash: Option<[u8; 32]> = None;
    if !candidates.is_empty() {
        if let Some(h) = hash_of(store.as_ref(), src) {
            hash = Some(h);
            dup = candidates
                .iter()
                .any(|cand| hash_of(store.as_ref(), cand) == Some(h));
        }
    }
    let final_dest = if dup {
        crate::actions::move_file::move_to(src, &super::dup_dest(dest_dir, src))
    } else {
        crate::actions::move_file::move_into_dir(src, dest_dir)
    };
    let final_dest = match final_dest {
        Ok(path) => path,
        Err(err) => {
            fail(out, src, &err);
            return;
        }
    };
    record(store.as_mut(), scan_id, src, &final_dest, hash, dup);
    match hash {
        // A known hash we store under the NEW identity (without reading the file).
        Some(h) => {
            if let (Some(store), Ok(meta)) =
                (store.as_mut(), std::fs::symlink_metadata(&final_dest))
            {
                let _ = store.upsert_hash(meta.dev(), meta.ino(), meta.size(), meta.mtime(), &h);
            }
            out.hashes.push((final_dest.clone(), h));
        }
        // Unknown — gets hashed in the background on the main thread (growing the index).
        None => out.to_hash.push(final_dest.clone()),
    }
    if dup {
        out.dups += 1;
    }
    out.moved.push((src.to_path_buf(), final_dest));
}

/// Writes a move event to the «trash» log (best-effort).
fn record(
    store: Option<&mut ScanStore>,
    scan_id: Option<i64>,
    src: &Path,
    dest: &Path,
    hash: Option<[u8; 32]>,
    duplicate: bool,
) {
    if let Some(store) = store {
        let event = MoveEvent {
            created_at: chrono::Local::now().to_rfc3339(),
            scan_id,
            source_path: src.to_path_buf(),
            target_path: dest.to_path_buf(),
            hash,
            duplicate,
        };
        let _ = store.record_move_event(&event);
    }
}

/// File hash without UI: identity cache (`hash_cache`/past scans), otherwise compute it.
fn hash_of(store: Option<&ScanStore>, path: &Path) -> Option<[u8; 32]> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    if let Some(store) = store {
        if let Ok(Some(h)) =
            store.hash_by_identity(meta.dev(), meta.ino(), meta.size(), meta.mtime())
        {
            return Some(h);
        }
    }
    crate::pipeline::hash::hash_file(path, &std::sync::atomic::AtomicU64::new(0)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_batch_{tag}_{}_{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, content: &[u8]) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(content).unwrap();
    }

    #[test]
    fn dir_into_existing_name_merges_contents() {
        let root = temp_dir("merge");
        let db = root.join("scan.db");
        let src_foto = root.join("src").join("foto");
        fs::create_dir_all(&src_foto).unwrap();
        write(&src_foto.join("a.txt"), b"aaa");
        let dest = root.join("dest");
        let dest_foto = dest.join("foto");
        fs::create_dir_all(&dest_foto).unwrap();
        write(&dest_foto.join("b.txt"), b"bbb");

        let out = run_batch(&db, std::slice::from_ref(&src_foto), &dest, None);

        // The contents merged into the existing dest/foto, without foto.1.
        assert!(
            dest_foto.join("a.txt").exists(),
            "a.txt poured into the existing foto"
        );
        assert!(dest_foto.join("b.txt").exists(), "b.txt in place");
        assert!(!dest.join("foto.1").exists(), "foto.1 not created");
        assert!(!src_foto.exists(), "emptied source removed");
        assert_eq!(out.failed, 0);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn dir_without_collision_moves_whole() {
        let root = temp_dir("whole");
        let db = root.join("scan.db");
        let src_x = root.join("src").join("x");
        fs::create_dir_all(&src_x).unwrap();
        write(&src_x.join("f.txt"), b"f");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let out = run_batch(&db, std::slice::from_ref(&src_x), &dest, None);

        assert!(dest.join("x").join("f.txt").exists());
        assert!(!src_x.exists());
        assert_eq!(out.failed, 0);

        fs::remove_dir_all(&root).ok();
    }
}
