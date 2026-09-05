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
    /// The batch died instead of returning — a panic in the worker. Nothing was reported item by
    /// item, so this is all the operator gets besides the log.
    pub error: Option<String>,
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
                    src.display()
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
                src.display()
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
            src.display()
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
            what.display()
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

    /// A destination that cannot be read must not pass for a destination with no duplicates.
    ///
    /// `same_size_files` used to answer a failed `read_dir` with an empty vector, and an empty
    /// vector is how the caller learns "nothing here duplicates it". So a transient failure on the
    /// destination — descriptors exhausted mid-batch, `EIO`, permissions changed underfoot — filed
    /// a duplicate under its own name and recorded `dup = false` for it, with nothing anywhere
    /// saying the question had never been answered. Now the file is not moved at all.
    #[test]
    fn an_unreadable_destination_does_not_pass_for_no_duplicates() {
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

    /// A child `read_dir` refuses to hand over is counted, not dropped. It used to leave through
    /// `.flatten()`: the file stayed in the source, `failed` stayed at zero, the `remove_dir` of
    /// the "emptied" source failed quietly, and the batch reported a clean merge over a file that
    /// had never moved.
    #[test]
    fn unreadable_child_is_counted_not_dropped() {
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
