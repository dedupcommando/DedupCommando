// SPDX-License-Identifier: Apache-2.0
use rusqlite::Connection;

use crate::error::{AppError, Result};

/// Checkpoint DB schema. `scan` — a single scan; `file` — the file manifest with hashes;
/// `scan_stats` — time, environment and metrics (1:1 with `scan`); `file_mark` —
/// saved user action marks.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scan (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    status      TEXT NOT NULL,
    config_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS file (
    scan_id INTEGER NOT NULL,
    path    TEXT NOT NULL,
    size    INTEGER NOT NULL,
    mtime   INTEGER NOT NULL,
    -- Full temporal identity. Second-granularity mtime is not enough — an edit in the same
    -- second of the same length would inherit the old hash. identity_version=1 is set
    -- ONLY by fd-verified hashing (see record_hashes_verified); legacy and
    -- move/apply-path hashes stay 0 and are NEVER a source of inheritance.
    mtime_nsec       INTEGER NOT NULL DEFAULT 0,
    ctime_sec        INTEGER NOT NULL DEFAULT 0,
    ctime_nsec       INTEGER NOT NULL DEFAULT 0,
    identity_version INTEGER NOT NULL DEFAULT 0,
    device  INTEGER NOT NULL,
    inode   INTEGER NOT NULL,
    hash    BLOB,
    PRIMARY KEY (scan_id, path)
);
CREATE INDEX IF NOT EXISTS file_size ON file(scan_id, size);
CREATE INDEX IF NOT EXISTS file_hash ON file(scan_id, hash);
CREATE INDEX IF NOT EXISTS file_content ON file(device, inode, size, mtime);
-- Hash reuse by path: identity (path,size,mtime)
-- is resilient to ZFS st_dev changing across reboots, unlike device/inode.
CREATE INDEX IF NOT EXISTS file_path_content ON file(path, size, mtime);
-- Cheap sorting of a group's files by path for
-- paged loading of the panel (`group_files_page` with LIMIT/OFFSET on this
-- index — without an expensive sort of 2.19M rows just for the top-N). Existing
-- DBs create the index automatically on the next open.
CREATE INDEX IF NOT EXISTS file_hash_path ON file(scan_id, hash, path);
CREATE TABLE IF NOT EXISTS scan_stats (
    scan_id           INTEGER PRIMARY KEY,
    elapsed_seconds   REAL NOT NULL DEFAULT 0,
    storage_type      TEXT,
    pool_layout       TEXT,
    zfs_version       TEXT,
    files_scanned     INTEGER NOT NULL DEFAULT 0,
    bytes_hashed      INTEGER NOT NULL DEFAULT 0,
    groups_found      INTEGER NOT NULL DEFAULT 0,
    reclaimable_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS file_mark (
    scan_id   INTEGER NOT NULL,
    path      TEXT NOT NULL,
    is_keeper INTEGER NOT NULL DEFAULT 0,
    action    TEXT,
    PRIMARY KEY (scan_id, path)
);
CREATE TABLE IF NOT EXISTS dir_dedup (
    scan_id      INTEGER NOT NULL,
    signature    TEXT NOT NULL,
    path         TEXT NOT NULL,
    file_count   INTEGER NOT NULL,
    size_per_dir INTEGER NOT NULL,
    PRIMARY KEY (scan_id, signature, path)
);
CREATE INDEX IF NOT EXISTS dir_dedup_by_scan_sig ON dir_dedup(scan_id, signature);
-- Materialized result of file groups: opening a finished scan is
-- a cheap read, without correlated subqueries over the whole manifest.
-- `file_group` — a lightweight summary (one row per group), `rank` fixes the «by
-- benefit» order at the moment of completion. `file_dedup` (membership) IS NO LONGER WRITTEN —
-- group members are read from the `file` manifest by hash (store::group_files); the table
-- is kept defined for compatibility (DELETE in purge_scan/record_file_results).
CREATE TABLE IF NOT EXISTS file_group (
    scan_id    INTEGER NOT NULL,
    rank       INTEGER NOT NULL,
    hash       TEXT    NOT NULL,
    file_count INTEGER NOT NULL,
    size       INTEGER NOT NULL,
    reclaim    INTEGER NOT NULL,
    PRIMARY KEY (scan_id, rank)
);
-- Lookup of a group summary by hash: commander DuplicatesOfCursor resolves
-- the group of the file under the cursor — without an index this is a scan of 645k rows per move.
CREATE INDEX IF NOT EXISTS file_group_hash ON file_group(scan_id, hash);
CREATE TABLE IF NOT EXISTS file_dedup (
    scan_id INTEGER NOT NULL,
    hash    TEXT    NOT NULL,
    path    TEXT    NOT NULL,
    size    INTEGER NOT NULL,
    mtime   INTEGER NOT NULL,
    device  INTEGER NOT NULL,
    inode   INTEGER NOT NULL,
    PRIMARY KEY (scan_id, hash, path)
);
CREATE INDEX IF NOT EXISTS file_dedup_by_scan_hash ON file_dedup(scan_id, hash);
CREATE TABLE IF NOT EXISTS hash_cache (
    device     INTEGER NOT NULL,
    inode      INTEGER NOT NULL,
    size       INTEGER NOT NULL,
    mtime      INTEGER NOT NULL,
    hash       BLOB    NOT NULL,
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (device, inode, size, mtime)
);
CREATE TABLE IF NOT EXISTS move_event (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    scan_id     INTEGER,
    source_path TEXT NOT NULL,
    target_path TEXT NOT NULL,
    hash        BLOB,
    duplicate   INTEGER NOT NULL
);
";

/// Current on-disk schema version, stamped into `PRAGMA user_version`. Bump this (and add a
/// migration step) whenever the schema changes in a way an older build cannot read. A DB from
/// before versioning reports 0; its schema equals v1, so it is stamped on first open.
///
/// v2 adds `scan_stats.results_materialized`. An older build would not see the marker and would
/// fall back to «is file_group empty?», which re-derives results `--verify` had rejected — so v2
/// is deliberately not readable by a v1 build.
pub const SCHEMA_VERSION: i64 = 2;

/// Refuses a DB written by a newer build. Reads `PRAGMA user_version` and errors if it is above
/// what this build knows; otherwise does nothing. Must run before any write so a future DB is
/// left untouched.
pub fn ensure_version_supported(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(AppError::msg(format!(
            "dedcom.db was created by a newer version (schema v{version}; this build supports v{SCHEMA_VERSION}). Upgrade dedcom, or move the old dedcom.db aside."
        )));
    }
    Ok(())
}

/// Refuses a DB older than this build when we cannot migrate it. Migration needs a writer, and
/// an observer holding a read-only connection would otherwise fail later, deep inside a query,
/// with «no such column».
pub fn ensure_migrated(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < SCHEMA_VERSION {
        return Err(AppError::msg(format!(
            "dedcom.db uses an older schema (v{version}; this build needs v{SCHEMA_VERSION}) and read-only mode cannot upgrade it. Start dedcom once as the operator."
        )));
    }
    Ok(())
}

pub fn migrate(conn: &Connection) -> Result<()> {
    // The migration is transactional and idempotent — either it all applies,
    // or the DB stays in its previous state (no half-added columns).
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(SCHEMA)?;
    // Additive candidate-progress columns in scan_stats. `CREATE TABLE IF
    // NOT EXISTS` does NOT add columns to an already existing table in a production DB — hence
    // guarded `ALTER ADD COLUMN` (idempotent, without DROP/rewrite — we do not rewrite the checkpoint).
    for column in [
        "cand_files_total",
        "cand_bytes_total",
        "cand_files_hashed",
        "cand_bytes_hashed",
    ] {
        add_column_if_missing(&tx, "scan_stats", column, "INTEGER NOT NULL DEFAULT 0")?;
    }
    // The number of candidates without a committed hash at the moment the
    // scan completes. Idempotently into the production scan_stats without DROP/rewrite; written in record_scan_result,
    // read in scan_summary/list_stats.
    add_column_if_missing(
        &tx,
        "scan_stats",
        "hash_failures",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    // Explicit «the results have been prepared by a writer» marker. An EMPTY file_group is a
    // legitimate final state (no duplicates at all, or --verify rejected every group), so
    // emptiness cannot serve as «not materialized yet». Legacy rows default to 0 and are
    // prepared once by the operator. Additive for an existing DB, but it carries the schema to
    // v2: a build that cannot see this column falls back to the broken emptiness test.
    add_column_if_missing(
        &tx,
        "scan_stats",
        "results_materialized",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    // Soft delete: a trash bin instead of an immediate DELETE — `trashed=1`
    // hides the session from the list, cleanup/restore are separate operations.
    add_column_if_missing(&tx, "scan", "trashed", "INTEGER NOT NULL DEFAULT 0")?;
    // Safe temporal identity into the production `file` without DROP/rewrite.
    // Legacy rows get DEFAULT 0 → identity_version=0 → not reused.
    for column in ["mtime_nsec", "ctime_sec", "ctime_nsec", "identity_version"] {
        add_column_if_missing(&tx, "file", column, "INTEGER NOT NULL DEFAULT 0")?;
    }
    // The reuse-key index — strictly AFTER adding the columns: on a production DB
    // with the old schema, CREATE INDEX on identity_version would otherwise fail (the column does not exist yet).
    // dev/inode are NOT in the key (ZFS changes them after import/reboot).
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS file_reuse_identity
             ON file(path, size, mtime, mtime_nsec, ctime_sec, ctime_nsec, identity_version);",
    )?;
    // Stamp the current schema version (also upgrades a pre-versioning DB from 0).
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}

/// Adds a column to a table if it does not exist yet (idempotent migration of a production DB without
/// DROP/rewrite). The names are internal constants, not user input.
fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let present = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .any(|name| name == column);
    drop(stmt);
    if !present {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn migrate_stamps_current_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn migrate_twice_keeps_current_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn ensure_version_supported_refuses_future_db() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(ensure_version_supported(&conn).is_err());
    }

    #[test]
    fn ensure_version_supported_allows_unversioned_and_current() {
        let conn = Connection::open_in_memory().unwrap();
        // A fresh/legacy DB is at user_version 0.
        assert!(ensure_version_supported(&conn).is_ok());
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .unwrap();
        assert!(ensure_version_supported(&conn).is_ok());
    }

    /// Migration of a production DB with the OLD `file` schema (without identity columns)
    /// is transactional and idempotent — adds columns with DEFAULT 0, preserves data,
    /// a repeat run breaks nothing. Legacy rows → identity_version=0.
    #[test]
    fn migrate_adds_identity_columns_to_legacy_file_table() {
        let conn = Connection::open_in_memory().unwrap();
        // Production schema BEFORE hardening: without mtime_nsec/ctime_*/identity_version.
        conn.execute_batch(
            "CREATE TABLE file (
                 scan_id INTEGER NOT NULL,
                 path    TEXT NOT NULL,
                 size    INTEGER NOT NULL,
                 mtime   INTEGER NOT NULL,
                 device  INTEGER NOT NULL,
                 inode   INTEGER NOT NULL,
                 hash    BLOB,
                 PRIMARY KEY (scan_id, path)
             );
             INSERT INTO file(scan_id, path, size, mtime, device, inode, hash)
             VALUES (1, '/tank/foo', 100, 42, 10, 5, X'00112233');",
        )
        .unwrap();

        // Twice — checking idempotency.
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();

        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(file)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        for c in ["mtime_nsec", "ctime_sec", "ctime_nsec", "identity_version"] {
            assert!(
                cols.contains(&c.to_string()),
                "no column {c} after migration"
            );
        }

        // Legacy data is intact; identity_version=0 (never a source of inheritance).
        let (size, mtime, idv): (i64, i64, i64) = conn
            .query_row(
                "SELECT size, mtime, identity_version FROM file WHERE path = '/tank/foo'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((size, mtime, idv), (100, 42, 0));
    }

    /// Migration of a production `scan_stats` with the OLD schema (without
    /// `hash_failures`) adds the column idempotently with DEFAULT 0, preserving existing
    /// rows. A repeat run breaks nothing. Mirror of the identity test above.
    #[test]
    fn migrate_adds_hash_failures_to_legacy_scan_stats_idempotently() {
        let conn = Connection::open_in_memory().unwrap();
        // Production scan_stats BEFORE hardening: the base 9 columns, without hash_failures (and without
        // the cand_* columns — the migration will add those too, but hash_failures is what matters to us).
        conn.execute_batch(
            "CREATE TABLE scan_stats (
                 scan_id           INTEGER PRIMARY KEY,
                 elapsed_seconds   REAL NOT NULL DEFAULT 0,
                 storage_type      TEXT,
                 pool_layout       TEXT,
                 zfs_version       TEXT,
                 files_scanned     INTEGER NOT NULL DEFAULT 0,
                 bytes_hashed      INTEGER NOT NULL DEFAULT 0,
                 groups_found      INTEGER NOT NULL DEFAULT 0,
                 reclaimable_bytes INTEGER NOT NULL DEFAULT 0
             );
             INSERT INTO scan_stats(scan_id, files_scanned) VALUES (7, 123);",
        )
        .unwrap();

        // Twice — checking idempotency.
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();

        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(scan_stats)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            cols.contains(&"hash_failures".to_string()),
            "no column hash_failures after migration"
        );

        // The existing row is intact; hash_failures = DEFAULT 0 for legacy data.
        let (files, hf): (i64, i64) = conn
            .query_row(
                "SELECT files_scanned, hash_failures FROM scan_stats WHERE scan_id = 7",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((files, hf), (123, 0));
    }

    /// A v1 DB (schema stamped, no `results_materialized`) migrates to v2: the column appears
    /// with DEFAULT 0, the stamp moves to 2, and existing rows survive.
    #[test]
    fn migrate_v1_to_v2_adds_results_materialized_and_restamps() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        // Rewind to a v1 DB: drop the v2 column (SQLite 3.35+ supports DROP COLUMN) and restamp.
        conn.execute_batch("ALTER TABLE scan_stats DROP COLUMN results_materialized")
            .unwrap();
        conn.execute_batch("INSERT INTO scan_stats(scan_id, groups_found) VALUES (7, 4)")
            .unwrap();
        conn.pragma_update(None, "user_version", 1i64).unwrap();

        // A v1 DB is readable by this build, and migrating brings it to v2.
        assert!(ensure_version_supported(&conn).is_ok());
        migrate(&conn).unwrap();
        migrate(&conn).unwrap(); // idempotent

        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(scan_stats)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            cols.contains(&"results_materialized".to_string()),
            "no column results_materialized after the v1→v2 migration"
        );
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION, "the stamp must move to v2");
        // The legacy row survives and defaults to «not prepared».
        let (groups, prepared): (i64, i64) = conn
            .query_row(
                "SELECT groups_found, results_materialized FROM scan_stats WHERE scan_id = 7",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((groups, prepared), (4, 0));
    }

    #[test]
    fn a_v2_db_is_refused_by_a_v1_build() {
        // Guard on the bump itself: the marker is invisible to a v1 build, which would fall back
        // to «is file_group empty?» and re-derive verify-rejected results.
        assert_eq!(SCHEMA_VERSION, 2);
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let stamped: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stamped, 2);
    }
}
