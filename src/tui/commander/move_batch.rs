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
    /// Which panels to re-read (filled in by the worker from the request).
    pub reload: Vec<LoadTarget>,
    /// Label for the status line (e.g. «receiver 2» / «panel 2»).
    pub label: String,
    /// The batch died instead of returning — a panic in the worker. Nothing was reported item by
    /// item, so this is all the operator gets besides the log.
    pub error: Option<String>,
}

/// Moves the batch `sources` into the directory `dest_dir`. Files are dedup-aware,
/// directories are moved whole. Records each move it completes in the `move_event` journal and
/// feeds the hash cache, both best-effort: a refused open or a failed insert is not reported
/// here. The UI is not involved here.
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
    let meta = match looked_at(src) {
        Ok(meta) => meta,
        Err(err) => {
            fail(out, src, &err);
            return;
        }
    };
    // A file of the database this process has open, or a directory that database lies in, is
    // not moved. The rename would refuse it by itself; it is refused here first, before anything
    // else is asked about it. Whether a file duplicates something at the destination takes a
    // read of it, and that read is refused in words of its own, which say nothing of a move. And
    // a directory that is merged is taken apart child by child: the three files would be refused
    // one by one, and everything else in the state directory would be gone from it.
    //
    // The lock file of the state directory, and a directory it lies in, are not moved either,
    // and are refused here for the second of those reasons: no database need be open for a
    // merge to take the state directory apart around its lock file.
    if let Some(refusal) = refused_at_once(src) {
        fail(out, src, &refusal);
        return;
    }
    if meta.is_dir() {
        move_dir_item(store, scan_id, src, dest_dir, out);
    } else {
        move_file_item(store, scan_id, src, meta.len(), dest_dir, out);
    }
}

/// The look a batch takes at `src` first — what is there, or why it is nothing a batch moves:
/// a name that cannot be looked at, or a symbolic link.
///
/// The reason is handed back, to be written to `dedcom.log`, and not just counted: the status
/// line sends the operator there for it, and a link that was not moved is still under the
/// cursor, to be asked about again.
fn looked_at(src: &Path) -> crate::error::Result<std::fs::Metadata> {
    let meta = std::fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        return Err(crate::error::AppError::msg(
            crate::actions::move_file::SYMLINK_MOVE_REFUSAL,
        ));
    }
    Ok(meta)
}

/// What stops `src` before anything else is asked about it, as the batch reports it.
fn refused_at_once(src: &Path) -> Option<crate::error::AppError> {
    crate::actions::move_file::refuse_open_database_move(src)
        .and_then(|()| crate::actions::move_file::refuse_lock_move(src))
        .err()
        .map(crate::actions::move_file::rename_failure)
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

/// Moves a duplicate into `dest_dir` under `{stem}.dupN{.ext}`.
fn move_duplicate(src: &Path, dest_dir: &Path) -> crate::error::Result<PathBuf> {
    crate::actions::move_file::move_to(src, &super::dup_dest(dest_dir, src))
        .map_err(|err| dup_marker_too_long(src, err))
}

/// A name near the limit has no room for the `.dupN` marker. «File name too long» alone blamed the
/// file; it is the marker that does not fit.
fn dup_marker_too_long(src: &Path, err: crate::error::AppError) -> crate::error::AppError {
    match &err {
        crate::error::AppError::Io(io) if crate::actions::move_file::is_name_too_long(io) => {
            crate::error::AppError::msg(format!(
                "{} duplicates a file already there, and its name has no room for the «.dupN» \
                 marker under {} — rename it first ({io})",
                crate::textsan::path(src),
                crate::actions::move_file::NAME_LIMIT
            ))
        }
        _ => err,
    }
}

/// Records a move failure: the reason goes to `dedcom.log` (previously `Err(_) =>
/// failed += 1` silently lost it, including the `rsync` hint for a cross-dataset move).
fn fail(out: &mut MoveBatchOutcome, src: &Path, err: &crate::error::AppError) {
    tracing::warn!("{}", failure_line(src, err));
    out.failed += 1;
}

/// The line a move that failed leaves in `dedcom.log`.
fn failure_line(src: &Path, err: &crate::error::AppError) -> String {
    // Both src and {err} (cross_device_error embeds raw src/dest)
    // may carry control bytes — we sanitize the whole string before logging.
    crate::textsan::terminal(&format!(
        "move failed: {} — {err}",
        crate::textsan::path(src)
    ))
}

/// Merges the contents of `src` into the existing directory `target_dir`: each item
/// is moved inside (files dedup-aware, subdirectories — recursively), then the
/// emptied `src` is removed. If something failed to move, `src` will remain.
///
/// The children are merged in one canonical order — see [`file_name_bytes`] — and not in the
/// order `readdir` hands them back. The difference is observable on disk: of several children
/// with equal content, whichever is moved FIRST finds no twin waiting for it and keeps its own
/// name, while each later one is recognised as a duplicate and lands as `name.dupN`. Left to
/// `readdir`, which child keeps its name is a property of the filesystem, so the same tree merged
/// on two machines came out under two different sets of names.
fn merge_dir(
    store: &mut Option<ScanStore>,
    scan_id: Option<i64>,
    src: &Path,
    target_dir: &Path,
    out: &mut MoveBatchOutcome,
) {
    let read = match std::fs::read_dir(src) {
        Ok(read) => read,
        Err(err) => {
            // Counted AND named. The source was not opened at all, so nothing under it moved and
            // the whole subtree stays where it is — a single number in the status line does not
            // say which directory that was.
            // `src` comes from the operator's tree and may carry control bytes — sanitize first.
            tracing::warn!(
                "{}",
                crate::textsan::terminal(&format!(
                    "merge: {} could not be opened; nothing under it was moved — {err}",
                    crate::textsan::path(src)
                ))
            );
            out.failed += 1;
            return;
        }
    };
    let failed_before = out.failed;
    let mut children: Vec<PathBuf> = Vec::new();
    for entry in read {
        match entry {
            // Test-only: take the same handler the `Err` arm takes, for a nominated child and
            // without a filesystem that has to misbehave. It does NOT go through that arm — the
            // arm's own `Err` is what a real `read_dir` produces, and nothing here fakes one.
            // Absent from every non-test build.
            #[cfg(test)]
            Ok(ref child) if crate::testfixtures::take_walk_fault(&child.path()) => {
                unreadable_child(out, src, &std::io::Error::other("injected read_dir fault"));
            }
            Ok(child) => children.push(child.path()),
            Err(err) => unreadable_child(out, src, &err),
        }
    }
    children.sort_by(|a, b| file_name_bytes(a).cmp(file_name_bytes(b)));
    for child in &children {
        move_item(store, scan_id, child, target_dir, out);
    }
    // The emptied source goes. A refusal here means something is still inside it, and the batch
    // may not report a clean merge over a directory that is still standing: the operator would
    // read `moved` and never learn that anything stayed.
    //
    // Only counted when no child of this directory failed already. A child that could not be
    // moved was counted where it failed, and it is the very reason `remove_dir` now refuses —
    // counting the refusal too would report one loss twice. What this catches is the case with no
    // such child: a new entry created under `src` after the listing, or a removal denied on its
    // own (permissions, I/O), both of which would otherwise pass silently.

    // Test-only: a removal that refuses although every child moved — an entry created under `src`
    // between the listing and here. Keyed on `src`, which for a TOP-level merge no other seam
    // touches; inside a nested merge the parent's listing sees this same path as its child and
    // takes the fault first, so a fault armed on a subdirectory tests that branch, not this one.
    #[cfg(test)]
    let removal = if crate::testfixtures::take_walk_fault(src) {
        Err(std::io::Error::other("injected remove_dir fault"))
    } else {
        std::fs::remove_dir(src)
    };
    #[cfg(not(test))]
    let removal = std::fs::remove_dir(src);
    if let Err(err) = removal {
        // Logged unconditionally, counted conditionally. A child that failed was already counted
        // where it failed, so adding the refusal would report one loss twice — but the refusal can
        // also have a cause of its own (an entry created after the listing, a denied removal),
        // and a child that failed WITHOUT staying behind, such as one unlinked by someone else
        // mid-batch, leaves that cause invisible. The line always goes to the log.
        // `src` comes from the operator's tree and may carry control bytes — sanitize first.
        tracing::warn!(
            "{}",
            crate::textsan::terminal(&format!(
                "merge: {} is still there after the merge — {err}",
                crate::textsan::path(src)
            ))
        );
        if out.failed == failed_before {
            out.failed += 1;
        }
    }
}

/// A child `read_dir` refused to hand over mid-iteration: counted as a failure, never dropped.
///
/// It used to go out with `.flatten()`, which discards `Err` without a trace: the child was never
/// moved, `out.failed` stayed where it was, and the `remove_dir` of the emptied source failed
/// quietly on a directory that was not empty — so the batch reported a clean merge over a file
/// still sitting in the source. The iterator's `Err` names no child, so all that can be reported
/// is the directory it stayed in; the pathname genuinely is not available and is not invented.
///
/// It also reports MORE than one child. `ReadDir` stops at its first error — the iterator marks
/// itself ended and yields `None` from then on — so a directory of five hundred entries that
/// fails after a hundred leaves four hundred unlisted, and this single count stands for all of
/// them. That is why the log line says the listing stopped rather than naming one bad entry, and
/// why the source directory is left standing: `remove_dir` then refuses, and that refusal is the
/// second signal the operator gets.
fn unreadable_child(out: &mut MoveBatchOutcome, src: &Path, err: &std::io::Error) {
    // `src` comes from the operator's tree and may carry control bytes — sanitize before logging.
    tracing::warn!(
        "{}",
        crate::textsan::terminal(&format!(
            "merge: listing {} stopped on an error; whatever it had not reached stays there — {err}",
            crate::textsan::path(src)
        ))
    );
    out.failed += 1;
}

/// Whether this file duplicates something in the destination could not be established.
///
/// Raised at either step that can answer the question — listing the destination, and hashing the
/// file or a same-size candidate. `what` names whichever of the three could not be read.
///
/// The two answers put the file on disk under different names — its own, or `name.dupN` — and
/// write different `duplicate` flags into the `move_event` journal, so neither may be picked by
/// default. The file is left where the operator put it and counted as failed, which is what
/// `merge_dir` does with a child it cannot read.
fn undetermined_duplicate(out: &mut MoveBatchOutcome, what: &Path, err: &std::io::Error) {
    // `what` comes from the operator's tree and may carry control bytes — sanitize first.
    tracing::warn!(
        "{}",
        crate::textsan::terminal(&format!(
            "move skipped: cannot tell whether it is a duplicate, {} could not be read — {err}",
            crate::textsan::path(what)
        ))
    );
    out.failed += 1;
}

/// Raw bytes of a path's final component — the merge's sort key.
///
/// Raw bytes and not `to_string_lossy`: lossy conversion maps every byte that is not valid UTF-8
/// to the same U+FFFD, so two names that differ on disk can compare equal and the ordering stops
/// being total — exactly the non-determinism the sort is there to remove. `read_dir` never yields
/// an entry without a final component, so the empty fallback is unreachable rather than a policy.
fn file_name_bytes(path: &Path) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    path.file_name().map_or(&[][..], |name| name.as_bytes())
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
    let candidates = match super::same_size_files(dest_dir, size) {
        Ok(candidates) => candidates,
        Err(err) => {
            undetermined_duplicate(out, dest_dir, &err);
            return;
        }
    };
    let mut dup = false;
    let mut hash: Option<[u8; 32]> = None;
    // An empty candidate list settles the question on its own: nothing there is even the right
    // size. Once there IS a candidate, the answer needs hashes, and a hash that cannot be taken
    // leaves the question open — it must not quietly read as "different".
    if !candidates.is_empty() {
        let own = match hash_of(store.as_ref(), src) {
            Ok(own) => own,
            Err(err) => {
                undetermined_duplicate(out, src, &err);
                return;
            }
        };
        hash = Some(own);
        // A candidate that cannot be read is remembered, not acted on: a twin found later settles
        // the question no matter what else was unreadable, so only the ABSENCE of a match leaves it
        // open. Returning at the first error instead would make the outcome depend on which
        // candidate came first — that is `readdir`'s order, the very thing this file takes away
        // from the filesystem everywhere else.
        let mut unread: Option<(PathBuf, std::io::Error)> = None;
        for candidate in &candidates {
            match hash_of(store.as_ref(), candidate) {
                Ok(other) if other == own => {
                    dup = true;
                    break;
                }
                Ok(_) => {}
                // Gone between the listing and the read: it is no longer a candidate, and that is
                // an answer. Anything else means this candidate's content is unknown, so whether
                // the file duplicates it is unknown too.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    if unread.is_none() {
                        unread = Some((candidate.clone(), err));
                    }
                }
            }
        }
        // No twin was found, and at least one candidate could not be read: the file may or may not
        // duplicate that one, and the two answers name it differently on disk.
        if !dup {
            if let Some((candidate, err)) = unread {
                undetermined_duplicate(out, &candidate, &err);
                return;
            }
        }
    }
    let final_dest = if dup {
        move_duplicate(src, dest_dir)
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

/// Records one completed move in the `move_event` journal, best-effort: with no store there is
/// no record, and a failed insert is not reported — the move itself has already happened.
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
///
/// The error is returned rather than folded into "no hash". A caller comparing hashes reads a
/// missing one as "these two differ", so an unreadable file used to answer the duplicate question
/// with "no" — the same fail-open shape `same_size_files` had, one layer further in. A cache miss
/// is not an error and still costs a read; only a stat or a read that actually failed is.
fn hash_of(store: Option<&ScanStore>, path: &Path) -> std::io::Result<[u8; 32]> {
    use std::os::unix::fs::MetadataExt;
    // Test-only: a file whose content will not be read, on a filesystem with no way to refuse a
    // root process. Absent from every non-test build.
    #[cfg(test)]
    if crate::testfixtures::take_content_fault(path) {
        return Err(std::io::Error::other("injected content read fault"));
    }
    let meta = std::fs::symlink_metadata(path)?;
    if let Some(store) = store {
        if let Ok(Some(h)) =
            store.hash_by_identity(meta.dev(), meta.ino(), meta.size(), meta.mtime())
        {
            return Ok(h);
        }
    }
    crate::pipeline::hash::hash_file(path, &std::sync::atomic::AtomicU64::new(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
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

    /// One file to move, and a destination already holding a byte-identical twin. Returns the root
    /// (to remove), the source file and the destination directory.
    fn one_and_its_twin(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = temp_dir(tag);
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let file = src.join("photo.bin");
        write(&file, b"the very same bytes in both of them");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();
        write(
            &dest.join("twin.bin"),
            b"the very same bytes in both of them",
        );
        (root, file, dest)
    }

    /// A duplicate whose name has no room for `.dupN` is refused with that said, and stays put.
    #[test]
    fn a_duplicate_without_room_for_its_marker_is_named() {
        let root = temp_dir("dup_long");
        let src = root.join("src");
        let dest = root.join("dest");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&dest).unwrap();
        // Three bytes short of the limit: the name fits, `.dup1` does not.
        let stem = "p".repeat(crate::testfixtures::name_max(&root) - 3 - ".bin".len());
        let file = src.join(format!("{stem}.bin"));
        write(&file, b"twin");
        write(&dest.join("twin.bin"), b"twin");

        let err = move_duplicate(&file, &dest)
            .expect_err("`.dup1` takes the name past the limit")
            .to_string();
        assert!(
            err.contains("«.dupN»") && err.contains(crate::actions::move_file::NAME_LIMIT),
            "{err}"
        );
        let too_long = std::io::Error::from_raw_os_error(libc::ENAMETOOLONG).to_string();
        assert!(err.contains(&too_long), "the OS's words: {err}");
        assert!(file.exists(), "the file stays put");
        fs::remove_dir_all(&root).ok();
    }

    /// A destination that cannot be read must not pass for a destination with no duplicates.
    ///
    /// `same_size_files` used to answer a failed `read_dir` with an empty vector, and an empty
    /// vector is how the caller learns "nothing here duplicates it". So a transient failure on the
    /// destination — descriptors exhausted mid-batch, `EIO`, permissions changed underfoot — filed
    /// a duplicate under its own name and recorded `dup = false` for it, with nothing anywhere
    /// saying the question had never been answered. Now the file is not moved at all.
    #[test]
    fn an_unreadable_destination_does_not_pass_for_no_duplicates() {
        let _role = crate::state::store::role_guard();
        let (root, file, dest) = one_and_its_twin("undetermined");
        let db = root.join("scan.db");

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            dest.clone(),
            crate::testfixtures::WalkFault::Iterator,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&file), &dest, None);

        assert!(
            faults.pending().is_empty(),
            "the fault must have fired: an unfired one means the destination was never read"
        );
        assert_eq!(out.failed, 1, "the item is counted as failed");
        assert!(out.moved.is_empty(), "and nothing was moved");
        assert_eq!(out.dups, 0, "nor classified either way");
        assert!(
            file.exists(),
            "the file stays where the operator left it, undamaged"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// An entry unlinked between `read_dir` and the stat is skipped, and the rest is still read.
    ///
    /// This is the one arm of `same_size_files` that answers an error with "not a candidate"
    /// instead of failing, so it needs a guard of its own. The fault lands on a same-size decoy
    /// rather than on the twin: if that arm aborted the read instead of skipping the entry, the
    /// twin would never be found and the file would land under its own name — so this fails in the
    /// same direction as the real defect, not merely somewhere.
    #[test]
    fn an_entry_that_vanishes_mid_scan_is_skipped_not_fatal() {
        let _role = crate::state::store::role_guard();
        let (root, file, dest) = one_and_its_twin("vanishing");
        let db = root.join("scan.db");
        let decoy = dest.join("decoy.bin");
        // Same 35 bytes long as the twin, so it really is a candidate the size filter keeps.
        write(&decoy, b"a different string of thirty-five!!");

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            decoy.clone(),
            crate::testfixtures::WalkFault::Metadata,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&file), &dest, None);

        assert!(
            faults.pending().is_empty(),
            "the fault must have fired: an unfired one means the entry was never stat'ed"
        );
        assert_eq!(out.failed, 0, "a vanished entry is not a failure");
        assert_eq!(out.dups, 1, "and the rest of the directory was still read");
        assert!(
            dest.join("photo.dup1.bin").exists(),
            "so the twin was found and this is its duplicate"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// A stat that is refused is not a vanished entry: the move fails instead of guessing.
    ///
    /// This is the other arm of `same_size_files`, the one that RETURNS the error, and it needs
    /// a guard of its own because the arm beside it skips. The fault lands on the twin itself:
    /// skipped like a `NotFound`, the twin would drop out of the listing, the destination would
    /// answer "nothing here duplicates it", and the file would be filed under its own name with
    /// `duplicate = false` in the journal, the misfiling this arm exists to refuse. So a wrong
    /// turn here fails in the direction of the real defect, not merely somewhere.
    #[test]
    fn an_entry_whose_stat_is_refused_is_fatal_not_skipped() {
        let _role = crate::state::store::role_guard();
        let (root, file, dest) = one_and_its_twin("refused");
        let db = root.join("scan.db");

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            dest.join("twin.bin"),
            crate::testfixtures::WalkFault::MetadataRefused,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&file), &dest, None);

        assert!(
            faults.pending().is_empty(),
            "the fault must have fired: an unfired one means the twin was never stat'ed"
        );
        assert_eq!(
            out.failed, 1,
            "a refused stat fails the move instead of being skipped like a vanished entry"
        );
        assert!(out.moved.is_empty(), "nothing was moved");
        assert_eq!(out.dups, 0, "nor classified either way");
        assert!(
            file.exists(),
            "the file stays where the operator left it, undamaged"
        );
        assert!(
            !dest.join("photo.bin").exists() && !dest.join("photo.dup1.bin").exists(),
            "and nothing under either name appeared in the destination"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// A file whose content will not read is not thereby "not a duplicate".
    ///
    /// The destination lists cleanly and holds a same-size twin, so the question is live and only
    /// the hashes can answer it. Before this, an unreadable file answered it with silence:
    /// `hash_of` folded the error into `None`, the caller read that as "no hash, so no match", and
    /// the file moved under its own name with `duplicate = false` journalled for it.
    #[test]
    fn a_file_that_cannot_be_hashed_is_not_moved_as_a_fresh_file() {
        let _role = crate::state::store::role_guard();
        let (root, file, dest) = one_and_its_twin("unhashable_src");
        let db = root.join("scan.db");

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            file.clone(),
            crate::testfixtures::WalkFault::Content,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&file), &dest, None);

        assert!(
            faults.pending().is_empty(),
            "the fault must have fired: an unfired one means no hash was ever taken"
        );
        assert_eq!(out.failed, 1, "the item is counted as failed");
        assert!(out.moved.is_empty(), "and nothing was moved");
        assert!(file.exists(), "the file stays where the operator left it");

        fs::remove_dir_all(&root).ok();
    }

    /// An unreadable candidate does not hide a twin that IS readable.
    ///
    /// The decoy is named to sort before the twin, so the loop meets it first. Stopping there
    /// would make the outcome depend on which candidate came first — and until `same_size_files`
    /// sorts them, that is `readdir`'s order: the same tree would classify differently in two
    /// destination directories on the same disk. A twin that was found settles the question; only
    /// the absence of one leaves it open.
    #[test]
    fn an_unreadable_candidate_does_not_hide_a_readable_twin() {
        let _role = crate::state::store::role_guard();
        let (root, file, dest) = one_and_its_twin("decoy");
        let db = root.join("scan.db");
        // Same 35 bytes as the twin, so the size filter keeps it, and byte-lower than "twin.bin".
        let decoy = dest.join("aaa.bin");
        write(&decoy, b"the very same length, other bytes!!");

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            decoy.clone(),
            crate::testfixtures::WalkFault::Content,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&file), &dest, None);

        assert!(
            faults.pending().is_empty(),
            "the decoy must have been reached: an unfired fault means the loop never got to it"
        );
        assert_eq!(
            out.failed, 0,
            "an unreadable candidate is not a failure once a twin is found"
        );
        assert_eq!(out.dups, 1, "the twin settles the question");
        assert!(
            dest.join("photo.dup1.bin").exists(),
            "so the file lands as the twin's duplicate"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// The same, one layer out: the CANDIDATE is the file that will not read.
    ///
    /// Its own hash is unknown, so whether the file being moved equals it is unknown, and "not
    /// equal" is not the safe default — it is the one that renames the file. A separate test from
    /// the one above because it is a separate branch: the source hashed perfectly well here.
    #[test]
    fn a_candidate_that_cannot_be_hashed_leaves_the_question_open() {
        let _role = crate::state::store::role_guard();
        let (root, file, dest) = one_and_its_twin("unhashable_cand");
        let db = root.join("scan.db");
        let twin = dest.join("twin.bin");

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            twin.clone(),
            crate::testfixtures::WalkFault::Content,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&file), &dest, None);

        assert!(
            faults.pending().is_empty(),
            "the fault must have fired: an unfired one means the candidate was never hashed"
        );
        assert_eq!(out.failed, 1, "the item is counted as failed");
        assert!(out.moved.is_empty(), "and nothing was moved");
        assert!(twin.exists(), "the unreadable candidate is left alone too");

        fs::remove_dir_all(&root).ok();
    }

    /// A merge that leaves the source directory standing is not a clean merge.
    ///
    /// Every child moved, so nothing was counted along the way; then the removal refused — an
    /// entry appeared under the source after the listing, or the removal was denied on its own.
    /// The result of `remove_dir` used to be discarded outright, so the batch reported `moved`
    /// over a directory that is still there with something inside it.
    #[test]
    fn a_source_that_survives_the_merge_is_counted() {
        let _role = crate::state::store::role_guard();
        let root = temp_dir("leftover");
        let db = root.join("scan.db");
        let src_photos = root.join("src").join("photos");
        fs::create_dir_all(&src_photos).unwrap();
        write(&src_photos.join("a.bin"), b"content of the only child");
        let dest = root.join("dest");
        fs::create_dir_all(dest.join("photos")).unwrap();

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            src_photos.clone(),
            crate::testfixtures::WalkFault::Iterator,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&src_photos), &dest, None);

        assert!(faults.pending().is_empty(), "the fault must have fired");
        assert_eq!(out.moved.len(), 1, "the child itself moved");
        assert_eq!(
            out.failed, 1,
            "and the source that stayed behind is counted, not swallowed"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// The child that failed is counted once, not twice.
    ///
    /// A child that could not be moved is the very reason `remove_dir` then refuses, so counting
    /// the refusal as well would report one loss as two. The guard is `out.failed` being unchanged
    /// across the children, and this is what fails if that guard is dropped.
    #[test]
    fn a_failed_child_is_not_counted_a_second_time_by_the_removal() {
        let _role = crate::state::store::role_guard();
        let root = temp_dir("nodouble");
        let db = root.join("scan.db");
        let src_photos = root.join("src").join("photos");
        fs::create_dir_all(&src_photos).unwrap();
        let child = src_photos.join("a.bin");
        write(&child, b"content of the only child");
        let dest = root.join("dest");
        fs::create_dir_all(dest.join("photos")).unwrap();
        // A same-size twin waiting in the destination is what makes the hash necessary at all;
        // without it there are no candidates, nothing is hashed and the fault never fires.
        write(
            &dest.join("photos").join("twin.bin"),
            b"content of the only child",
        );

        // The child cannot be hashed, so it is refused and counted — and stays, so the removal
        // refuses too. Exactly one failure may come out of that.
        let faults = crate::testfixtures::WalkFaults::arm(&[(
            child.clone(),
            crate::testfixtures::WalkFault::Content,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&src_photos), &dest, None);

        assert!(faults.pending().is_empty(), "the fault must have fired");
        assert!(out.moved.is_empty(), "nothing moved");
        assert_eq!(out.failed, 1, "one loss, counted once");
        assert!(child.exists(), "the child is still in the source");

        fs::remove_dir_all(&root).ok();
    }

    /// A symlink in the destination is never a duplicate candidate — not even to an identical file.
    ///
    /// `DirEntry::metadata` does NOT follow links (it is the `lstat` form), so a link comes back
    /// `Ok` with `is_file() == false` and the type filter drops it; a link with no target does the
    /// same and raises no error at all. Pinned because the opposite is easy to assume: an earlier
    /// draft of the fix above justified its `NotFound` arm by broken symlinks, which never reach
    /// it. Swapping to `fs::metadata(entry.path())` would change both halves of this at once.
    #[test]
    fn symlinks_in_the_destination_are_not_duplicate_candidates() {
        let _role = crate::state::store::role_guard();
        let (root, file, dest) = one_and_its_twin("symlinks");
        let db = root.join("scan.db");
        // The twin leaves the destination and stays reachable there only through a link.
        fs::rename(dest.join("twin.bin"), root.join("twin.bin")).unwrap();
        std::os::unix::fs::symlink(root.join("twin.bin"), dest.join("twin.bin")).unwrap();
        std::os::unix::fs::symlink(dest.join("gone.bin"), dest.join("broken.bin")).unwrap();

        let out = run_batch(&db, std::slice::from_ref(&file), &dest, None);

        assert_eq!(out.failed, 0, "neither link is an error");
        assert_eq!(out.moved.len(), 1, "the file moved");
        assert_eq!(
            out.dups, 0,
            "the identical file behind a link is not a candidate"
        );
        assert!(
            dest.join("photo.bin").exists(),
            "so it lands under its own name"
        );

        fs::remove_dir_all(&root).ok();
    }

    fn write(path: &Path, content: &[u8]) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(content).unwrap();
    }

    #[test]
    fn dir_into_existing_name_merges_contents() {
        let _role = crate::state::store::role_guard();
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

    /// Builds `src/photos` holding `names` — created in exactly that order, all byte-identical —
    /// next to an already-existing `dest/photos`, then merges the one into the other. Returns the
    /// root (to remove), the destination directory and the outcome.
    fn merge_identical(tag: &str, names: &[&OsStr]) -> (PathBuf, PathBuf, MoveBatchOutcome) {
        let root = temp_dir(tag);
        let db = root.join("scan.db");
        let src_photos = root.join("src").join("photos");
        fs::create_dir_all(&src_photos).unwrap();
        for name in names {
            write(
                &src_photos.join(name),
                b"the very same bytes in every one of them",
            );
        }
        let dest = root.join("dest");
        let dest_photos = dest.join("photos");
        fs::create_dir_all(&dest_photos).unwrap();

        let out = run_batch(&db, std::slice::from_ref(&src_photos), &dest, None);
        (root, dest_photos, out)
    }

    /// Of several equal-content children, the one merged FIRST finds no twin waiting and keeps its
    /// own name; every later one is recognised as a duplicate and lands as `name.dup1`. So the
    /// merge order is legible in the names left on disk, and the canonical order is asserted
    /// outright — the byte-lowest name is the survivor. The source is built twice, in opposite
    /// creation orders, which keeps the assertion honest on a filesystem that does return
    /// `readdir` entries in creation order; on one that does not, the assertion is no weaker,
    /// because it names the expected outcome instead of comparing two runs against each other.
    #[test]
    fn merge_moves_children_in_file_name_order() {
        let _role = crate::state::store::role_guard();
        let forward: Vec<&OsStr> = [
            "a.bin", "b.bin", "c.bin", "d.bin", "e.bin", "f.bin", "g.bin", "h.bin",
        ]
        .iter()
        .map(OsStr::new)
        .collect();
        let mut reverse = forward.clone();
        reverse.reverse();

        for (tag, order) in [("fwd", &forward), ("rev", &reverse)] {
            let (root, dest_photos, out) = merge_identical(tag, order);

            assert!(
                dest_photos.join("a.bin").is_file(),
                "[{tag}] the byte-lowest name kept its own name"
            );
            assert!(
                !dest_photos.join("a.dup1.bin").exists(),
                "[{tag}] and was never the duplicate"
            );
            for stem in ["b", "c", "d", "e", "f", "g", "h"] {
                assert!(
                    dest_photos.join(format!("{stem}.dup1.bin")).is_file(),
                    "[{tag}] {stem}.bin landed as a duplicate of a.bin"
                );
                assert!(
                    !dest_photos.join(format!("{stem}.bin")).exists(),
                    "[{tag}] {stem}.bin did not keep its own name"
                );
            }
            assert_eq!(out.failed, 0, "[{tag}] nothing failed");
            assert_eq!(out.dups, 7, "[{tag}] seven of the eight were duplicates");

            fs::remove_dir_all(&root).ok();
        }
    }

    /// The sort key is the raw bytes of the name, so the ordering stays total over names that are
    /// not valid UTF-8. `0x80` is an invalid byte; `À` is `0xC3 0x80`. By raw bytes the first
    /// sorts ahead (`0x80 < 0xC3`); under `to_string_lossy` the two compare the other way round
    /// (`U+00C0 < U+FFFD`), and every distinct invalid byte would collapse onto that one U+FFFD,
    /// leaving names that differ on disk comparing equal.
    ///
    /// What the assertion reads is the expectation below, which is a literal: it holds whatever
    /// order the filesystem lists these two in. The creation order is deliberately not the
    /// expected one, but no claim is made about which listing order that produces — that varies
    /// by filesystem, mount option and kernel, and nothing here depends on it.
    #[test]
    fn merge_order_is_total_over_non_utf8_names() {
        let _role = crate::state::store::role_guard();
        use std::os::unix::ffi::OsStrExt;
        let invalid = OsStr::from_bytes(b"\x80.bin");
        let accented = OsStr::new("À.bin");

        let (root, dest_photos, out) = merge_identical("nonutf8", &[accented, invalid]);

        assert!(
            dest_photos.join(invalid).is_file(),
            "the byte-lowest name kept its own name"
        );
        assert!(
            dest_photos.join("À.dup1.bin").is_file(),
            "the later one landed as a duplicate"
        );
        assert_eq!(out.failed, 0);
        assert_eq!(out.dups, 1);

        fs::remove_dir_all(&root).ok();
    }

    /// The journal holds the exact bytes of the names the batch put on disk: two files whose
    /// names differ only outside UTF-8 become two rows, and each row's target is byte for byte one
    /// of the names `read_dir` now lists in the destination. The contents differ, so neither file
    /// is the other's duplicate and both keep their own names.
    #[test]
    fn a_batch_journals_the_exact_bytes_of_the_names_it_put_on_disk() {
        let _role = crate::state::store::role_guard();
        use crate::model::action::PathFidelity;
        use std::collections::BTreeSet;
        use std::os::unix::ffi::OsStrExt;

        let root = temp_dir("journal_bytes");
        let db = root.join("scan.db");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let mut sources = Vec::new();
        for (name, content) in [
            (OsStr::from_bytes(b"\x80.bin"), &b"first"[..]),
            (OsStr::from_bytes(b"\xff.bin"), &b"second, and longer"[..]),
        ] {
            let path = src.join(name);
            write(&path, content);
            sources.push(path);
        }
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let out = run_batch(&db, &sources, &dest, None);

        assert_eq!(out.failed, 0);
        assert_eq!(out.moved.len(), 2);
        let on_disk: BTreeSet<Vec<u8>> = fs::read_dir(&dest)
            .unwrap()
            .map(|entry| entry.unwrap().path().as_os_str().as_bytes().to_vec())
            .collect();
        assert_eq!(on_disk.len(), 2, "both files landed under their own names");

        let store = ScanStore::open(&db).unwrap();
        let rows = store.move_events().unwrap();
        assert_eq!(rows.len(), 2, "one row per file");
        let journaled: BTreeSet<Vec<u8>> = rows
            .iter()
            .map(|row| row.event.target_path.as_os_str().as_bytes().to_vec())
            .collect();
        assert_eq!(
            journaled, on_disk,
            "each target is byte for byte a name read_dir lists"
        );
        for row in &rows {
            assert_eq!(row.path_fidelity, PathFidelity::Exact);
        }

        fs::remove_dir_all(&root).ok();
    }

    /// A child `read_dir` refuses to hand over is counted, not dropped. It used to leave through
    /// `.flatten()`: the file stayed in the source, `failed` stayed at zero, the `remove_dir` of
    /// the "emptied" source failed quietly, and the batch reported a clean merge over a file that
    /// had never moved.
    #[test]
    fn unreadable_child_is_counted_not_dropped() {
        let _role = crate::state::store::role_guard();
        let root = temp_dir("unreadable");
        let db = root.join("scan.db");
        let src_photos = root.join("src").join("photos");
        fs::create_dir_all(&src_photos).unwrap();
        write(&src_photos.join("kept.txt"), b"kept");
        write(&src_photos.join("lost.txt"), b"lost");
        let dest = root.join("dest");
        let dest_photos = dest.join("photos");
        fs::create_dir_all(&dest_photos).unwrap();

        let faults = crate::testfixtures::WalkFaults::arm(&[(
            src_photos.join("lost.txt"),
            crate::testfixtures::WalkFault::Iterator,
        )]);
        let out = run_batch(&db, std::slice::from_ref(&src_photos), &dest, None);

        assert!(faults.pending().is_empty(), "the fault was consumed");
        assert_eq!(faults.fired().len(), 1, "and consumed exactly once");
        assert!(
            dest_photos.join("kept.txt").is_file(),
            "the readable child still moved"
        );
        assert!(
            src_photos.join("lost.txt").is_file(),
            "the unreadable one stayed behind"
        );
        assert_eq!(out.moved.len(), 1, "one move to undo, not two");
        assert_eq!(
            out.failed, 1,
            "the child that stayed behind is counted, not silently dropped"
        );
        assert!(
            src_photos.is_dir(),
            "the source survives, still holding what did not move"
        );

        drop(faults);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn dir_without_collision_moves_whole() {
        let _role = crate::state::store::role_guard();
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

    /// A session with one scan on record: its state directory under a fresh root, the database
    /// in it with a store open — the connection a running dedcom keeps — and a directory beside
    /// the state directory to move things to. Returns the root (to remove), the database, the
    /// destination and the store.
    fn a_session_with_one_scan(tag: &str) -> (PathBuf, PathBuf, PathBuf, ScanStore) {
        a_session_with_one_scan_in(tag, "state")
    }

    /// The same, with the state directory at `state` under the root, however deep that is.
    fn a_session_with_one_scan_in(
        tag: &str,
        state: &str,
    ) -> (PathBuf, PathBuf, PathBuf, ScanStore) {
        let root = temp_dir(tag);
        let state = root.join(state);
        let dest = root.join("dest");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&dest).unwrap();
        let db = state.join("dedcom.db");
        let mut store = ScanStore::open_writable(&db).expect("the session opens its database");
        store
            .begin_scan(&crate::model::scan::ScanConfig::new(vec![root.clone()]))
            .expect("and records a scan");
        (root, db, dest, store)
    }

    /// The name of the file of `db` that carries `suffix`.
    fn beside(db: &Path, suffix: &str) -> PathBuf {
        let mut name = db.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    }

    /// The database a running dedcom has open is not moved from under it.
    ///
    /// Red on the parent: the file went to the destination like any other. The next thing to
    /// open the database by its name to write — any later batch does, as here — found the name
    /// free, made an empty database there, and SQLite deleted the journal beside it: the scan the
    /// session had on record was in neither file.
    #[test]
    fn the_open_database_is_not_moved_and_its_scans_stay() {
        use crate::testfixtures::{outside, Errand};
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) = a_session_with_one_scan("own_db_move");

        let out = run_batch(&db, std::slice::from_ref(&db), &dest, None);
        drop(ScanStore::open(&db).expect("the next batch opens the database"));

        let scans = outside(Errand::CountScans, &db);
        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                dest.join("dedcom.db").exists(),
                scans.as_str()
            ),
            (0, 1, false, "1"),
            "moved, failed, at the destination, scans a reader finds afterwards"
        );
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// Nor is its journal.
    ///
    /// Red on the parent: with `dedcom.db-wal` gone from its name, a reader in another process
    /// was sent by the journal's index to frames in a file that was not there.
    #[test]
    fn the_open_journal_is_not_moved_and_a_reader_still_reads() {
        use crate::testfixtures::{outside, Errand};
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) = a_session_with_one_scan("own_wal_move");
        let journal = beside(&db, "-wal");

        let out = run_batch(&db, std::slice::from_ref(&journal), &dest, None);

        let scans = outside(Errand::CountScans, &db);
        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                dest.join("dedcom.db-wal").exists(),
                scans.as_str()
            ),
            (0, 1, false, "1"),
            "moved, failed, at the destination, scans a reader finds afterwards"
        );
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// Nor the index of the journal.
    ///
    /// Red on the parent: with `dedcom.db-shm` gone from its name, the next program to write made
    /// an index of its own, and neither writer saw where the other's frames ended. A scan a
    /// second dedcom recorded was overwritten by the session's next one — committed, and gone.
    #[test]
    fn the_open_journal_index_is_not_moved_and_no_scan_is_lost() {
        use crate::testfixtures::{outside, Errand};
        let _role = crate::state::store::role_guard();
        let (root, db, dest, mut store) = a_session_with_one_scan("own_shm_move");
        let index = beside(&db, "-shm");

        let out = run_batch(&db, std::slice::from_ref(&index), &dest, None);
        assert_eq!(outside(Errand::RecordAScan, &db), "recorded");
        store
            .begin_scan(&crate::model::scan::ScanConfig::new(vec![root.clone()]))
            .expect("the session records another scan");

        let scans = outside(Errand::CountScans, &db);
        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                dest.join("dedcom.db-shm").exists(),
                scans.as_str()
            ),
            (0, 1, false, "3"),
            "moved, failed, at the destination, scans a reader finds afterwards: the session's \
             two and the second dedcom's one"
        );
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// The refusal comes before anything else is asked about the file: the destination is not
    /// even listed for a file of its size. Otherwise a destination that happens to hold one sends
    /// the move off to hash the database, and what the log then carries is the refusal of a read.
    #[test]
    fn a_file_of_the_open_database_is_refused_before_the_destination_is_read() {
        use crate::testfixtures::{WalkFault, WalkFaults};
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) = a_session_with_one_scan("own_db_first");
        let index = beside(&db, "-shm");
        let listing = (dest.clone(), WalkFault::Iterator);
        let faults = WalkFaults::arm(std::slice::from_ref(&listing));

        let out = run_batch(&db, std::slice::from_ref(&index), &dest, None);

        assert_eq!(
            (out.moved.len(), out.failed, index.is_file()),
            (0, 1, true),
            "moved, failed, still there"
        );
        assert_eq!(
            faults.pending(),
            vec![listing],
            "the destination was listed before the refusal"
        );
        drop(faults);
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// A hard link to the database is the database under another name, wherever it lies: the
    /// refusal is of the file, and says so.
    #[test]
    fn a_hard_link_to_the_open_database_is_not_moved_either() {
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) = a_session_with_one_scan("own_db_link");
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let link = elsewhere.join("a-copy-that-is-not-one.db");
        fs::hard_link(&db, &link).unwrap();

        let out = run_batch(&db, std::slice::from_ref(&link), &dest, None);

        assert_eq!(
            (out.moved.len(), out.failed, link.is_file()),
            (0, 1, true),
            "moved, failed, still there"
        );
        assert_eq!(
            crate::actions::move_file::refuse_open_database_move(&link)
                .map_err(|err| err.to_string()),
            Err(crate::actions::move_file::OPEN_DATABASE_MOVE_REFUSAL.to_string()),
            "and it is as a file of the database that it is refused"
        );
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// What `dedcom.log` is given for a refused item: the path, then the refusal in its own
    /// words with nothing in front of them — the line the manual shows an operator.
    #[test]
    fn the_log_line_of_a_refused_move_is_the_one_the_manual_shows() {
        use crate::actions::move_file::{
            OPEN_DATABASE_FOLDER_MOVE_REFUSAL, OPEN_DATABASE_MOVE_REFUSAL,
        };
        let _role = crate::state::store::role_guard();
        let (root, db, _dest, store) = a_session_with_one_scan("own_db_line");
        let state = db.parent().expect("the state directory").to_path_buf();
        // What the batch itself says of the item, and the line it would write of it.
        let line = |src: &Path| {
            let refusal = refused_at_once(src).expect("part of the open database");
            failure_line(src, &refusal)
        };

        assert_eq!(
            line(&db),
            format!(
                "move failed: {} — {OPEN_DATABASE_MOVE_REFUSAL}",
                db.display()
            )
        );
        assert_eq!(
            line(&state),
            format!(
                "move failed: {} — {OPEN_DATABASE_FOLDER_MOVE_REFUSAL}",
                state.display()
            )
        );
        let chapter = crate::testfixtures::manual("13-troubleshooting.md");
        for words in [
            OPEN_DATABASE_MOVE_REFUSAL,
            OPEN_DATABASE_FOLDER_MOVE_REFUSAL,
        ] {
            let shown = format!("move failed: <path> — {words}");
            assert!(
                chapter.contains(&shown),
                "13-troubleshooting.md must show: {shown}"
            );
        }
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// A folder is not moved with the open database in it. The three files would keep their names
    /// inside it; what goes wrong is every later opening by the path the program knows.
    ///
    /// Red on the parent: the state directory went to the destination whole, and the session
    /// could not open its database again — the path to it was gone.
    #[test]
    fn a_folder_that_holds_the_open_database_is_not_moved() {
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) = a_session_with_one_scan("own_dir_move");
        let state = db.parent().expect("the state directory").to_path_buf();

        let out = run_batch(&db, std::slice::from_ref(&state), &dest, None);

        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                state.is_dir(),
                dest.join("state").exists(),
                ScanStore::open(&db).is_ok()
            ),
            (0, 1, true, false, true),
            "moved, failed, still there, at the destination, the database opens by its path"
        );
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// Nor is a folder further up: whatever lies on the way to the database stays where it is.
    #[test]
    fn nor_is_a_folder_further_up_from_the_open_database() {
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) =
            a_session_with_one_scan_in("own_dir_above", "home/user/state");
        let home = root.join("home");

        let out = run_batch(&db, std::slice::from_ref(&home), &dest, None);

        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                db.is_file(),
                dest.join("home").exists()
            ),
            (0, 1, true, false),
            "moved, failed, the database at its name, the folder at the destination"
        );
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// A merge does not go into such a folder either. Taken apart file by file, the state
    /// directory would lose everything but the three files, which are refused one by one.
    ///
    /// Red on the parent: all four went, the database among them.
    #[test]
    fn a_merge_stays_out_of_the_folder_of_the_open_database() {
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) = a_session_with_one_scan("own_dir_merge");
        let state = db.parent().expect("the state directory").to_path_buf();
        write(&state.join("config.json"), b"{}");
        fs::create_dir_all(dest.join("state")).unwrap();

        let out = run_batch(&db, std::slice::from_ref(&state), &dest, None);

        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                crate::testfixtures::names_in(&dest.join("state")).len(),
                state.join("config.json").is_file(),
                db.is_file()
            ),
            (0, 1, 0, true, true),
            "moved, failed, entries poured into the destination, the settings and the database \
             where they were"
        );
        drop(store);
        fs::remove_dir_all(&root).ok();
    }

    /// What is refused is a database that is OPEN. The session's connection alone is enough —
    /// this batch keeps its own journal elsewhere — and once nothing has the database open, its
    /// folder is a folder like any other.
    #[test]
    fn the_folder_moves_once_nothing_has_its_database_open() {
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) = a_session_with_one_scan("own_dir_closed");
        let state = db.parent().expect("the state directory").to_path_buf();
        let journal = root.join("batch.db");

        let out = run_batch(&journal, std::slice::from_ref(&state), &dest, None);
        assert_eq!(
            (out.moved.len(), out.failed, state.is_dir()),
            (0, 1, true),
            "held by the session alone: moved, failed, still there"
        );

        drop(store);
        let out = run_batch(&journal, std::slice::from_ref(&state), &dest, None);
        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                dest.join("state").join("dedcom.db").is_file()
            ),
            (1, 0, true),
            "nobody holds it: moved, failed, the database at the destination"
        );
        fs::remove_dir_all(&root).ok();
    }

    /// And so is its file.
    #[test]
    fn the_database_file_moves_once_nothing_has_it_open() {
        let _role = crate::state::store::role_guard();
        let (root, db, dest, store) = a_session_with_one_scan("own_db_closed");
        let journal = root.join("batch.db");

        let out = run_batch(&journal, std::slice::from_ref(&db), &dest, None);
        assert_eq!(
            (out.moved.len(), out.failed, db.is_file()),
            (0, 1, true),
            "held by the session alone: moved, failed, still there"
        );

        drop(store);
        let out = run_batch(&journal, std::slice::from_ref(&db), &dest, None);
        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                dest.join("dedcom.db").is_file()
            ),
            (1, 0, true),
            "nobody holds it: moved, failed, the database at the destination"
        );
        fs::remove_dir_all(&root).ok();
    }

    /// A state directory under a fresh root with the lock in it taken — as an operator keeps it
    /// for the whole run — and NO database open: the settings and a log beside the lock file,
    /// and a directory beside the state directory to move things to. This batch keeps its own
    /// journal elsewhere. Returns the root (to remove), the state directory, the destination,
    /// the batch's journal and the lock.
    fn an_operator_with_no_database_open(
        tag: &str,
    ) -> (
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        crate::lock::InstanceLock,
    ) {
        let root = temp_dir(tag);
        let state = root.join("state");
        let dest = root.join("dest");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&dest).unwrap();
        let held = match crate::lock::try_acquire(&state).unwrap() {
            crate::lock::Acquire::Operator(lock) => lock,
            crate::lock::Acquire::Busy(_) => panic!("a fresh directory's lock is free"),
        };
        write(&state.join("config.json"), b"{}");
        write(&state.join("dedcom.log"), b"a line\n");
        (root.clone(), state, dest, root.join("batch.db"), held)
    }

    /// What another dedcom that asks for the lock in `state` gets.
    fn another_dedcom(state: &Path) -> &'static str {
        match crate::lock::try_acquire(state) {
            Ok(crate::lock::Acquire::Operator(_)) => "becomes an operator",
            Ok(crate::lock::Acquire::Busy(_)) => "is turned away",
            Err(_) => "finds no state directory to ask in",
        }
    }

    /// Everything in the state directory selected at once: the lock file stays, and what was
    /// selected beside it goes, as it did.
    ///
    /// Red on the parent: the lock file went with the rest, still locked, and the name it left
    /// was free — another dedcom took a lock of its own and ran as a second operator.
    #[test]
    fn the_lock_file_stays_when_everything_beside_it_is_moved() {
        let _role = crate::state::store::role_guard();
        let (root, state, dest, journal, held) =
            an_operator_with_no_database_open("own_lock_selection");
        let lock = crate::lock::lock_path(&state);
        let selected = [
            state.join("config.json"),
            lock.clone(),
            state.join("dedcom.log"),
        ];

        let out = run_batch(&journal, &selected, &dest, None);

        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                lock.is_file(),
                dest.join("dedcom.lock").exists(),
                another_dedcom(&state)
            ),
            (2, 1, true, false, "is turned away"),
            "moved, failed, the lock file at its name, at the destination, another dedcom"
        );
        drop(held);
        fs::remove_dir_all(&root).ok();
    }

    /// A folder the lock file lies in is not moved, nor one further up — with no database open:
    /// the lock is held for the whole run, a connection only now and then.
    ///
    /// Red on the parent: the folder went whole, the held lock file in it, and another dedcom
    /// started an empty state directory where the old one was and ran as an operator.
    #[test]
    fn a_folder_that_holds_the_lock_file_is_not_moved() {
        let _role = crate::state::store::role_guard();
        let (root, state, dest, journal, held) =
            an_operator_with_no_database_open("own_lock_folder");

        let out = run_batch(&journal, std::slice::from_ref(&state), &dest, None);

        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                state.is_dir(),
                dest.join("state").exists(),
                another_dedcom(&state)
            ),
            (0, 1, true, false, "is turned away"),
            "moved, failed, still there, at the destination, another dedcom"
        );
        drop(held);
        fs::remove_dir_all(&root).ok();
    }

    /// A merge does not go into such a folder either: taken apart file by file, the state
    /// directory would lose everything but the lock file.
    ///
    /// Red on the parent: all three went, the lock file among them.
    #[test]
    fn a_merge_stays_out_of_the_folder_of_the_lock_file() {
        let _role = crate::state::store::role_guard();
        let (root, state, dest, journal, held) =
            an_operator_with_no_database_open("own_lock_merge");
        fs::create_dir_all(dest.join("state")).unwrap();

        let out = run_batch(&journal, std::slice::from_ref(&state), &dest, None);

        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                crate::testfixtures::names_in(&dest.join("state")).len(),
                state.join("config.json").is_file(),
                crate::lock::lock_path(&state).is_file(),
                another_dedcom(&state)
            ),
            (0, 1, 0, true, true, "is turned away"),
            "moved, failed, entries poured into the destination, the settings and the lock file \
             where they were, another dedcom"
        );
        drop(held);
        fs::remove_dir_all(&root).ok();
    }

    /// What is refused is a lock file whose lock is HELD: once the operator has let go of it,
    /// the file and its folder are a file and a folder like any other.
    #[test]
    fn the_lock_file_and_its_folder_move_once_the_lock_is_let_go_of() {
        let _role = crate::state::store::role_guard();
        let (root, state, dest, journal, held) =
            an_operator_with_no_database_open("own_lock_let_go");
        let lock = crate::lock::lock_path(&state);
        drop(held);

        let out = run_batch(&journal, std::slice::from_ref(&lock), &dest, None);
        assert_eq!(
            (
                out.moved.len(),
                out.failed,
                dest.join("dedcom.lock").is_file()
            ),
            (1, 0, true),
            "the file: moved, failed, at the destination"
        );
        let out = run_batch(&journal, std::slice::from_ref(&state), &dest, None);
        assert_eq!(
            (out.moved.len(), out.failed, dest.join("state").is_dir()),
            (1, 0, true),
            "the folder: moved, failed, at the destination"
        );
        fs::remove_dir_all(&root).ok();
    }

    /// What `dedcom.log` is given for a refused lock file, and for a folder it lies in: the
    /// path, then the refusal in its own words with nothing in front of them — the two lines the
    /// manual shows an operator.
    #[test]
    fn the_log_line_of_a_refused_lock_file_is_the_one_the_manual_shows() {
        use crate::actions::move_file::{LOCK_FILE_MOVE_REFUSAL, LOCK_FOLDER_MOVE_REFUSAL};
        let (root, state, _dest, _journal, held) =
            an_operator_with_no_database_open("own_lock_line");
        let lock = crate::lock::lock_path(&state);
        // What the batch itself says of the item, and the line it would write of it.
        let line = |src: &Path| {
            let refusal = refused_at_once(src).expect("part of the lock file's place");
            failure_line(src, &refusal)
        };

        assert_eq!(
            line(&lock),
            format!("move failed: {} — {LOCK_FILE_MOVE_REFUSAL}", lock.display())
        );
        assert_eq!(
            line(&state),
            format!(
                "move failed: {} — {LOCK_FOLDER_MOVE_REFUSAL}",
                state.display()
            )
        );
        let chapter = crate::testfixtures::manual("13-troubleshooting.md");
        for words in [LOCK_FILE_MOVE_REFUSAL, LOCK_FOLDER_MOVE_REFUSAL] {
            let shown = format!("move failed: <path> — {words}");
            assert!(
                chapter.lines().any(|line| line == shown),
                "13-troubleshooting.md must show, as a line: {shown}"
            );
        }
        drop(held);
        fs::remove_dir_all(&root).ok();
    }

    /// A symbolic link, and a name that cannot be looked at, are not moved, and `dedcom.log`
    /// says why — of the link, in the line the manual shows. The status line sends the operator
    /// to the log for the reason.
    ///
    /// On the parent the batch counted both and wrote of neither.
    #[test]
    fn the_log_says_why_a_symbolic_link_or_a_name_it_cannot_look_at_is_not_moved() {
        use crate::actions::move_file::SYMLINK_MOVE_REFUSAL;
        let root = temp_dir("not_moved_line");
        let missing = root.join("nowhere");
        let link = root.join("a.link");
        std::os::unix::fs::symlink(&missing, &link).unwrap();

        // What the batch itself says of the item, and the line it would write of it.
        let of_the_link = looked_at(&link).expect_err("a link is nothing a batch moves");
        assert_eq!(
            failure_line(&link, &of_the_link),
            format!("move failed: {} — {SYMLINK_MOVE_REFUSAL}", link.display())
        );
        let unseen = looked_at(&missing).expect_err("there is nothing to look at");
        assert!(
            matches!(&unseen, crate::error::AppError::Io(err)
                if err.kind() == std::io::ErrorKind::NotFound),
            "what the system said stays what it said: {unseen}"
        );
        assert!(
            failure_line(&missing, &unseen)
                .starts_with(&format!("move failed: {} — I/O: ", missing.display())),
            "and is written after the path like any other reason"
        );
        assert!(
            looked_at(&root).is_ok_and(|meta| meta.is_dir()),
            "while a folder is looked at and handed on"
        );
        let shown = format!("move failed: <path> — {SYMLINK_MOVE_REFUSAL}");
        assert!(
            crate::testfixtures::manual("13-troubleshooting.md")
                .lines()
                .any(|line| line == shown),
            "13-troubleshooting.md must show, as a line: {shown}"
        );
        fs::remove_dir_all(&root).ok();
    }

    /// What a batch leaves at its names: a file that moved and a folder a merge emptied and
    /// removed are gone from theirs; a symbolic link is not moved, and a folder with one inside
    /// is left standing by the merge, the link in it — as the manual says of both. A panel that
    /// is re-read afterwards lists exactly this, whatever the batch counted, and its cursor goes
    /// by that list: the tests of a merged folder in the commander and on the Board show it.
    #[test]
    fn a_batch_leaves_a_link_and_a_folder_with_one_inside_at_their_names() {
        let _role = crate::state::store::role_guard();
        let root = temp_dir("left_at_names");
        let src = root.join("src");
        let dest = root.join("dest");
        for dir in [
            src.join("emptied"),
            src.join("standing"),
            dest.join("emptied"),
            dest.join("standing"),
        ] {
            fs::create_dir_all(&dir).unwrap();
        }
        write(&src.join("moved.bin"), b"moved");
        write(&src.join("emptied").join("child.bin"), b"child");
        write(&src.join("standing").join("child.bin"), b"another child");
        // A symbolic link is not moved: as a source it stays, and as a child it keeps its
        // folder standing after the merge.
        std::os::unix::fs::symlink(src.join("moved.bin"), src.join("stays.link")).unwrap();
        std::os::unix::fs::symlink(src.join("moved.bin"), src.join("standing").join("a.link"))
            .unwrap();
        let names = ["moved.bin", "stays.link", "emptied", "standing"];
        let sources = names.map(|name| src.join(name));

        let out = run_batch(&root.join("batch.db"), &sources, &dest, None);

        let at_its_name = |path: PathBuf| fs::symlink_metadata(path).is_ok();
        let left: Vec<&str> = names
            .into_iter()
            .filter(|name| at_its_name(src.join(name)))
            .collect();
        assert_eq!(
            (out.moved.len(), out.failed, left),
            (3, 2, vec!["stays.link", "standing"]),
            "moved, failed, and what is still at its name"
        );
        assert!(
            at_its_name(src.join("standing").join("a.link")),
            "the link inside the folder the merge left standing"
        );
        fs::remove_dir_all(&root).ok();
    }

    /// Of a folder that holds both — the open database and the lock file, as the state
    /// directory of a running operator does — the batch names the database, in the wording the
    /// manual has for such a folder; with no connection open it names the lock file.
    #[test]
    fn of_a_folder_that_holds_both_the_batch_names_the_database_while_it_is_open() {
        use crate::actions::move_file::{
            LOCK_FOLDER_MOVE_REFUSAL, OPEN_DATABASE_FOLDER_MOVE_REFUSAL,
        };
        let _role = crate::state::store::role_guard();
        let (root, state, _dest, _journal, held) =
            an_operator_with_no_database_open("own_lock_and_db");
        let said = || {
            refused_at_once(&state)
                .expect("a folder that is not moved")
                .to_string()
        };

        let store = ScanStore::open_writable(&state.join("dedcom.db")).unwrap();
        let with_the_database_open = said();
        drop(store);

        assert_eq!(
            (with_the_database_open.as_str(), said().as_str()),
            (OPEN_DATABASE_FOLDER_MOVE_REFUSAL, LOCK_FOLDER_MOVE_REFUSAL),
            "the database open, and closed again"
        );
        drop(held);
        fs::remove_dir_all(&root).ok();
    }
}
