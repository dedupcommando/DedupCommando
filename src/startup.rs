// SPDX-License-Identifier: Apache-2.0
//! The checkpoint's startup work, in one thread and one order.
//!
//! Startup used to hand the same `dedcom.db` to three openers at once — the deferred auto-VACUUM,
//! the results preparation and the wizard's eager session load — and each of them runs the shape
//! guard and then the migration. Two things went wrong with that, and both cost the operator the
//! same thing:
//!
//!   * the migration is one transaction, but reading it was not, so an opener could see the stamp
//!     of the version it arrived at together with the names of the version another thread had just
//!     migrated to, and refuse a checkpoint that had never been anything but ours;
//!   * a VACUUM and a preparation that reach the file together are two writers, and SQLite hands
//!     one of them `database is locked` without waiting — a busy timeout does not cover a lock
//!     upgrade that would deadlock.
//!
//! Either way the results preparation gave up, `scan_stats.results_materialized` stayed 0, and a
//! completed scan the operator already owned came back as «rescan required», explained only by a
//! detached warning in the log.
//!
//! So the checkpoint's startup work is sequential and belongs to one thread: settle it, vacuum it
//! if that is due, prepare its completed scans, and only then let anything else open it.
//! [`CheckpointSettled`] states the last part to the compiler instead of to the reader — and it is
//! minted only when the settling actually succeeded, so a checkpoint this build refuses stops the
//! startup work at its first step and travels out as the run's error.

use std::path::Path;

use crate::error::Result;
use crate::maint;
use crate::state::ScanStore;

/// Proof that the checkpoint has been settled on this thread: for an operator, opened, recognised
/// and migrated to the current schema; for an observer, deliberately left alone — a read-only open
/// neither migrates nor runs the shape guard, so an observer has nothing to settle and nothing to
/// race with.
///
/// Zero-sized and `Copy`, so it costs nothing to carry. Only [`settle_checkpoint`] mints one, and
/// the work that must not run before the migration takes one, so what holds the ordering is the
/// compiler and not the order the lines happen to be written in.
#[derive(Clone, Copy, Debug)]
pub struct CheckpointSettled(());

impl CheckpointSettled {
    /// Runs `f` against a settled checkpoint. The parameter is the whole point: a caller that
    /// cannot produce the proof cannot call this at all.
    pub fn after<T>(self, f: impl FnOnce() -> T) -> T {
        f()
    }
}

/// Opens, recognises and migrates the checkpoint ONCE, on the calling thread, before anything else
/// in this process has it open.
///
/// The role is passed in rather than inferred: the caller has just taken the instance lock and
/// decided it, and `set_observer_role` has already been told, so `ScanStore::open` hands back the
/// same connection the rest of the run will get.
///
/// Fail-closed: a checkpoint that would not open mints NO token, and the refusal is returned as it
/// came out of the store, byte for byte. The token means «this file is at the current schema», and
/// there is no honest way to say that about a database this build has just refused — the work
/// downstream would then be running on a claim nobody checked.
pub fn settle_checkpoint(db_path: &Path, read_only: bool) -> Result<CheckpointSettled> {
    if read_only {
        return Ok(CheckpointSettled(()));
    }
    // Dropped as soon as it is open. The migration was the errand; holding the connection for the
    // rest of the run would keep a reader alive against every later writer for nothing.
    ScanStore::open(db_path).map(|store| {
        drop(store);
        CheckpointSettled(())
    })
}

/// The whole of the checkpoint's startup work, in order, on the calling thread.
///
/// Settle, then the deferred auto-VACUUM if config.json says it is due, then the results
/// preparation. Sequential rather than spawned: these two are the writers, and running them
/// together is what left a completed scan unprepared. Their diagnostics are unchanged — each one
/// is advisory and reports itself.
///
/// The caller runs this on the boot thread, so the splash is already on screen while it works and
/// nothing else in the process opens the checkpoint until it returns.
///
/// Fail-closed at the first step: if the checkpoint does not settle, neither the VACUUM nor the
/// preparation runs, and the refusal travels out as the run's error. A refused file is opened
/// exactly once — nothing retries it under another name, and nothing writes to it.
pub fn settle_and_maintain(
    db_path: &Path,
    state_dir: &Path,
    read_only: bool,
) -> Result<CheckpointSettled> {
    let settled = settle_checkpoint(db_path, read_only)?;
    if read_only {
        // An observer writes nothing: no VACUUM, no preparation. Both are the operator's.
        return Ok(settled);
    }
    // Deferred auto-VACUUM: operator only, at startup, if config.json says it is time (default
    // every 120 h, 0 = off). First of the two, and alone with the file — a VACUUM is the one
    // operation that wants the whole database to itself.
    if maint::should_auto_vacuum(state_dir) {
        settled.after(|| match maint::vacuum_only(db_path, state_dir) {
            Ok(()) => tracing::info!("auto-VACUUM completed"),
            Err(err) => tracing::warn!("auto-VACUUM not completed: {err}"),
        });
    }
    // Results are prepared by the WRITER: the operator brings every completed scan that predates
    // the marker up to date at startup, so an observer only ever reads.
    settled.after(|| {
        match ScanStore::open(db_path).and_then(|mut store| store.prepare_completed_scans()) {
            Ok(0) => {}
            Ok(n) => tracing::info!("prepared results of {n} completed scan(s)"),
            Err(err) => tracing::warn!("preparing completed scans failed: {err}"),
        }
    });
    Ok(settled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::store::{open_ledger, role_guard, set_observer_role};
    use crate::testfixtures::{genuine_checkpoint, ScratchDir};

    /// The ordering claim itself: the checkpoint is opened by one thread at a time, the settling
    /// open is the only one that may find a legacy stamp, and everything after it finds the
    /// migration committed.
    #[test]
    fn nothing_opens_the_checkpoint_before_the_migration_has_committed() {
        let _role = role_guard();
        set_observer_role(false);
        let dir = ScratchDir::new("startup-order");
        let db = genuine_checkpoint(dir.path(), 0);

        let recording = open_ledger::Recording::of(&db);
        settle_and_maintain(&db, dir.path(), false).expect("a checkpoint of ours settles");

        let seen = recording.versions();
        assert!(
            seen.len() >= 2,
            "the settling open and the preparation must both be recorded: {seen:?}"
        );
        assert_eq!(
            seen[0], 0,
            "the first opener is the one that settles the checkpoint, and it finds the legacy stamp"
        );
        assert!(
            seen[1..]
                .iter()
                .all(|version| *version == crate::state::schema::SCHEMA_VERSION),
            "everything after it must find the migration committed: {seen:?}"
        );
    }

    /// The regression the integration gate caught, on a checkpoint of the product's own first
    /// shape: once startup is over the legacy scan is migrated AND prepared, with nothing left
    /// pending for the next start to try again.
    #[test]
    fn a_legacy_checkpoint_is_migrated_and_its_completed_scan_prepared() {
        let _role = role_guard();
        set_observer_role(false);
        let dir = ScratchDir::new("startup-floor-v0");
        let db = genuine_checkpoint(dir.path(), 0);

        settle_and_maintain(&db, dir.path(), false).expect("a checkpoint of ours settles");

        let conn = rusqlite::Connection::open(&db).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            version,
            crate::state::schema::SCHEMA_VERSION,
            "the checkpoint is migrated"
        );
        let materialized: i64 = conn
            .query_row(
                "SELECT results_materialized FROM scan_stats WHERE scan_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            materialized, 1,
            "the completed scan's results were prepared, not abandoned"
        );
        drop(conn);

        let store = ScanStore::open(&db).unwrap();
        assert!(
            store.unprepared_completed_scans().unwrap().is_empty(),
            "nothing is left pending for the next start to try again"
        );
    }

    /// The same checkpoint, over and over. The two writers used to be two threads, and which of
    /// them lost `database is locked` was the scheduler's business; sequential, the answer is the
    /// same every time.
    #[test]
    fn the_startup_work_prepares_the_scan_on_every_run() {
        let _role = role_guard();
        set_observer_role(false);
        for run in 0..16 {
            let dir = ScratchDir::new(&format!("startup-repeat-{run}"));
            let db = genuine_checkpoint(dir.path(), 0);

            settle_and_maintain(&db, dir.path(), false).expect("a checkpoint of ours settles");

            let conn = rusqlite::Connection::open(&db).unwrap();
            let materialized: i64 = conn
                .query_row(
                    "SELECT results_materialized FROM scan_stats WHERE scan_id = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(materialized, 1, "run {run} left the scan unprepared");
        }
    }

    /// The gate's failure itself, at the exact site, deterministically.
    ///
    /// A checkpoint of the product's own first shape; the results preparation opens it; and while
    /// its shape guard holds the stamp it read, a SECOND connection migrates the same file and
    /// commits. That is what three threads racing on one `dedcom.db` produced: the preparation
    /// refused with «`file_scan_identity` belongs to schema v3, but this checkpoint declares v0»
    /// and the operator was left with a completed scan nothing had prepared. The barrier is a
    /// seam, not a sleep, so this either holds or it does not.
    #[test]
    fn the_results_preparation_survives_a_migration_committing_underneath_its_open() {
        let _role = role_guard();
        set_observer_role(false);
        let dir = ScratchDir::new("startup-barrier");
        let db = genuine_checkpoint(dir.path(), 0);
        // WAL: the mode every opener flips the checkpoint to, and the one the incident happened in
        // — under WAL a writer does not wait for a reader, which is how a migration got in between
        // two of the guard's reads in the first place.
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            let _: String = conn
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
                .unwrap();
        }

        let migrating = db.clone();
        let race = crate::state::schema::ShapeGuardRace::armed(move || {
            let conn = rusqlite::Connection::open(&migrating).unwrap();
            conn.execute_batch("PRAGMA busy_timeout=5000;").unwrap();
            crate::state::schema::migrate(&conn).expect("the other opener migrates the checkpoint");
        });

        let prepared = ScanStore::open(&db).and_then(|mut store| store.prepare_completed_scans());

        assert!(
            race.fired(),
            "the barrier was never reached — the test proved nothing"
        );
        assert_eq!(
            prepared.expect("a checkpoint migrated underneath the open is still ours"),
            1,
            "the one completed scan is prepared, not abandoned"
        );
        let conn = rusqlite::Connection::open(&db).unwrap();
        let materialized: i64 = conn
            .query_row(
                "SELECT results_materialized FROM scan_stats WHERE scan_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(materialized, 1, "and the marker says so on disk");
    }

    /// An observer settles nothing and writes nothing: it may not, so there is no migration for
    /// anybody to race with.
    #[test]
    fn an_observer_writes_nothing_at_startup() {
        let _role = role_guard();
        set_observer_role(false);
        let dir = ScratchDir::new("startup-observer");
        let db = genuine_checkpoint(dir.path(), 0);
        let before = std::fs::read(&db).unwrap();
        set_observer_role(true);

        settle_and_maintain(&db, dir.path(), true)
            .expect("an observer settles nothing and fails at nothing");

        set_observer_role(false);
        assert_eq!(
            std::fs::read(&db).unwrap(),
            before,
            "an observer leaves the checkpoint byte for byte as it found it"
        );
    }

    /// Bytes, mtime, the declared version and the sidecar census — everything a refusal has to
    /// leave exactly as it found it. Reading `PRAGMA user_version` through a bare connection
    /// writes nothing, which is why the mtime below is a real assertion and not a tautology.
    fn census(db: &Path) -> (Vec<u8>, std::time::SystemTime, i64, Vec<String>) {
        let bytes = std::fs::read(db).unwrap();
        let mtime = std::fs::metadata(db).unwrap().modified().unwrap();
        let conn = rusqlite::Connection::open(db).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        drop(conn);
        let mut siblings: Vec<String> = std::fs::read_dir(db.parent().unwrap())
            .unwrap()
            .filter_map(|entry| {
                entry
                    .ok()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
            })
            .filter(|name| name != "dedcom.db")
            .collect();
        siblings.sort();
        (bytes, mtime, version, siblings)
    }

    /// A database this build refuses stops the startup work at its first step.
    ///
    /// Two shapes that must both be refused: one written by a newer build, and one that was never
    /// ours at all. For each, the refusal is the store's own sentence, the file is opened EXACTLY
    /// once, neither the VACUUM nor the preparation nor the session load runs, and the file keeps
    /// its bytes, its mtime, its stamp and its sidecar census. A second opener would be a second
    /// entry in the ledger; a VACUUM that ran would leave `config.json` behind.
    #[test]
    fn a_refused_checkpoint_is_the_runs_error_and_nothing_else_happens() {
        let _role = role_guard();
        set_observer_role(false);

        for (tag, build, expected) in [
            (
                "future",
                (|dir: &Path| {
                    let db = genuine_checkpoint(dir, 0);
                    let conn = rusqlite::Connection::open(&db).unwrap();
                    conn.pragma_update(
                        None,
                        "user_version",
                        crate::state::schema::SCHEMA_VERSION + 1,
                    )
                    .unwrap();
                    db
                }) as fn(&Path) -> std::path::PathBuf,
                "newer version",
            ),
            (
                "foreign",
                (|dir: &Path| {
                    let db = dir.join("dedcom.db");
                    let conn = rusqlite::Connection::open(&db).unwrap();
                    conn.execute_batch(
                        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
                         INSERT INTO users (id, name) VALUES (1, 'someone else');",
                    )
                    .unwrap();
                    db
                }) as fn(&Path) -> std::path::PathBuf,
                "not a checkpoint this build can upgrade",
            ),
        ] {
            let dir = ScratchDir::new(&format!("startup-refused-{tag}"));
            let db = build(dir.path());
            let before = census(&db);

            let recording = open_ledger::Recording::of(&db);
            let settled = settle_and_maintain(&db, dir.path(), false);
            let opens = recording.versions();
            drop(recording);

            let err = settled
                .as_ref()
                .err()
                .unwrap_or_else(|| panic!("{tag}: this database must be refused"))
                .to_string();
            assert!(
                err.contains(expected),
                "{tag}: the refusal is the store's own: {err}"
            );
            assert_eq!(
                opens.len(),
                1,
                "{tag}: a refused checkpoint must be opened exactly once, not {}: {opens:?}",
                opens.len()
            );

            // No token, so the session load cannot even be reached — the boot thread chains it on
            // this very result.
            let mut load_ran = false;
            let sessions: Result<Vec<u8>> = settled.and_then(|token| {
                token.after(|| {
                    load_ran = true;
                    Ok(Vec::new())
                })
            });
            assert!(!load_ran, "{tag}: the session load must not run");
            assert!(sessions.is_err(), "{tag}: the refusal is the run's error");

            let after = census(&db);
            assert_eq!(before.0, after.0, "{tag}: the bytes changed");
            assert_eq!(before.1, after.1, "{tag}: the mtime changed");
            assert_eq!(before.2, after.2, "{tag}: the stamp changed");
            assert_eq!(before.3, after.3, "{tag}: the sidecar census changed");
            assert!(
                !dir.path().join("config.json").exists(),
                "{tag}: an auto-VACUUM ran and recorded itself"
            );

            // The sentence is the store's own, byte for byte — this probe is deliberately AFTER
            // the census comparison above, which has already proved that opening a refused file
            // changes nothing.
            let direct = ScanStore::open(&db)
                .err()
                .unwrap_or_else(|| panic!("{tag}: the store itself must refuse it too"))
                .to_string();
            assert_eq!(
                err, direct,
                "{tag}: the refusal was reworded on the way out"
            );
        }
    }
}
