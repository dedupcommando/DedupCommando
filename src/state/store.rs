// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::error::{AppError, Result};
use crate::model::action::{ActionKind, MoveEvent};
use crate::model::duplicate::{
    build_dir_signatures_streaming, hex_encode, signature_of, DirGroup, DirSigAlgo, DuplicateGroup,
    FileEntry,
};
use crate::model::scan::{
    ResumeInfo, ScanConfig, ScanEnvironment, ScanStatsRow, ScanStatus, ScanSummary,
};

use super::schema;

/// A manifest row — a file awaiting hashing.
///
/// Carries the full temporal identity (`mtime` + `mtime_nsec` + `ctime`),
/// so that an open descriptor can be compared with the manifest and hash reuse
/// can be tied to it. `Default` — so that test literals do not have to enumerate all fields.
#[derive(Debug, Clone, Default)]
pub struct ManifestRow {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub device: u64,
    pub inode: u64,
}

/// Statistics on hashing candidates — for progress and resume.
#[derive(Debug, Clone, Copy, Default)]
pub struct CandidateStats {
    pub total_files: u64,
    pub total_bytes: u64,
    pub hashed_files: u64,
    pub hashed_bytes: u64,
}

/// The result of a `record_hashes_verified` checkpoint: the rows ACTUALLY committed. Progress
/// of the hashing phase advances by this persisted delta, not by the batch size — without calling
/// `candidate_stats` on every chunk (on /tank that would be tens of thousands of heavy GROUP BYs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistedHashes {
    pub files: u64,
    pub bytes: u64,
}

/// Summary of the checkpoint DB's contents — for `--stats`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DbCounts {
    /// Total sessions in the `scan` table (including the trash bin).
    pub scans: u64,
    /// Of them, in the trash bin (`trashed=1`).
    pub trashed: u64,
    /// Rows in the `file` manifest — the main contributor to the DB size.
    pub file_rows: u64,
}

/// Dedup attributes of a SINGLE file in a panel directory — input for the pure
/// `DedupStatus::classify`. For hashed files `dup_count`/
/// `distinct_devices` matter; for unhashed ones — `size_mtime_count` (a duplicate candidate
/// before hashing). Replaces the global RAM maps of the former `DedupIndex`.
#[derive(Debug, Clone)]
pub struct DedupRow {
    /// hex hash of the file; `None` — the file is in the manifest but not yet hashed.
    pub hashed: Option<String>,
    /// How many files of the scan share this hash (only for hashed ones).
    pub dup_count: u32,
    /// How many distinct devices the files with this hash have (cross-device → dangerous).
    pub distinct_devices: u32,
    /// How many files of the scan share the same (size, mtime) — for LikelyDuplicate.
    pub size_mtime_count: u32,
}

/// A lightweight duplicate-group summary — one `file_group` row, without
/// members. Browser holds a Vec of these summaries (645k×~48 B ≈ 31 MiB), and reads a group's
/// files on entry (`group_files`), rather than the whole scan into RAM.
#[derive(Debug, Clone)]
pub struct GroupSummary {
    /// Sequential «by benefit» rank at the moment the scan completed.
    pub rank: i64,
    /// hex hash of the group.
    pub hash: String,
    pub file_count: u64,
    /// Size of a single file in the group.
    pub size_bytes: u64,
    /// Reclaimable = size·(n−1) (independent of the keeper).
    pub reclaim_bytes: u64,
}

/// A lightweight twin-directory group summary — for
/// the `[2] Directories` tab in the browser. Analogous to `GroupSummary` for file groups: a single
/// `dir_group_summaries` query → `Vec<DirGroupSummary>` without `paths`. The directory paths
/// in a group themselves — `store::dir_group_paths(signature)` on entry into the group.
/// Browser does not hold all `paths` in RAM (on /tank there are sometimes several
/// thousand dir-groups, each with 2-20 paths — ~MB of memory, tolerable, but for uniformity with
/// the file-tab we make it lazy).
#[derive(Debug, Clone)]
pub struct DirGroupSummary {
    /// Sequential «by benefit» rank (1-based, for UI `#N`).
    pub rank: u32,
    /// blake3 signature of the directory's contents (hex). The key for `dir_group_paths`.
    pub signature: String,
    /// How many twin directories are in the group (>= 2 by the SQL filter).
    pub dir_count: u32,
    /// Files in a SINGLE directory of the group (the same for all — same signature).
    pub file_count: u32,
    /// Total size of one directory's files (the same for all in the group).
    pub size_per_dir: u64,
}

impl DirGroupSummary {
    /// How much space will be freed if one directory of the group is kept.
    pub fn reclaim_bytes(&self) -> u64 {
        let extra = (self.dir_count.saturating_sub(1)) as u64;
        self.size_per_dir.saturating_mul(extra)
    }
}

/// An action-plan row assembled from the DB (`planned_action_rows`): the target
/// (marked for an action, not a keeper) + the deterministic keeper of its group. Raw material
/// for `actions::plan_actions_from_db` — without materializing all groups into RAM.
#[derive(Debug, Clone)]
pub struct PlannedActionRow {
    /// The action identifier from `file_mark.action` (delete/hardlink/reflink).
    pub action: String,
    pub target: PathBuf,
    pub keeper: PathBuf,
    pub target_device: u64,
    pub keeper_device: u64,
    pub size: u64,
    /// hex hash of the group — for the final re-check (`revalidate`) before the action.
    pub expected_hash: String,
}

/// Checkpoint store: a SQLite DB with the scan state and the file manifest.
pub struct ScanStore {
    conn: Connection,
}

impl ScanStore {
    /// Opens (creates) the DB, enables WAL, applies the schema.
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            // store::open is also called by read-only modes (--stats/--export-csv) WITHOUT the entry-point
            // establish — so we protect the chain here ourselves (no-follow, 0700, fail-closed),
            // not via create_dir_all (it would follow a symlink ancestor). Idempotent.
            crate::paths::establish_state_dir(parent)?;
        }
        // Refuse if the DB file is a symlink (opening by the link would write the target outside
        // the state-dir), and create with 0600. O_NOFOLLOW on the final component.
        crate::paths::prepare_db_file(db_path)?;
        let conn = Connection::open(db_path)?;
        // busy_timeout — the background move worker holds its own connection
        // in parallel with the main one; WAL + waiting on a lock instead of a «locked» error.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;\nPRAGMA busy_timeout=5000;",
        )?;
        schema::migrate(&conn)?;
        // 0600 on the DB file and WAL/SHM (created by enabling WAL above): the contents — the paths of all
        // pool files — are for the owner only (errors are propagated, not best-effort).
        crate::paths::enforce_db_perms_0600(db_path)?;
        Ok(Self { conn })
    }

    /// Opens an in-memory DB — for unit tests.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        schema::migrate(&conn)?;
        Ok(Self { conn })
    }

    /// Path of the DB file — to derive the state_dir for reading config.json.
    pub fn db_path(&self) -> Option<PathBuf> {
        self.conn.path().map(PathBuf::from)
    }

    /// Looks for the most recent scan (to resume or view).
    pub fn find_resumable(&self) -> Result<Option<ResumeInfo>> {
        let row = self.conn.query_row(
            "SELECT id, created_at, status, config_json FROM scan ORDER BY id DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        );

        let (scan_id, created_at, status_text, config_json) = match row {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        let status = ScanStatus::parse(&status_text)
            .ok_or_else(|| AppError::msg(format!("unknown scan status: {status_text}")))?;
        let config: ScanConfig = serde_json::from_str(&config_json)?;
        let stats = self.candidate_stats(scan_id)?;

        Ok(Some(ResumeInfo {
            scan_id,
            created_at,
            status,
            roots: config.roots,
            files_total: stats.total_files,
            files_hashed: stats.hashed_files,
            cand_bytes_total: stats.total_bytes,
            cand_bytes_hashed: stats.hashed_bytes,
            files_scanned: 0,
            reclaimable_bytes: 0,
        }))
    }

    /// Active (NOT trashed) scan sessions, newest first.
    pub fn list_scans(&self) -> Result<Vec<ResumeInfo>> {
        self.scans_filtered(true)
    }

    /// Sessions in the trash bin — for the restore/cleanup screen.
    pub fn list_trashed(&self) -> Result<Vec<ResumeInfo>> {
        self.scans_filtered(false)
    }

    /// Shared reader of the session list. `active=true` — active, `false` — trash bin.
    /// One pass: candidate progress is read from the materialized scan_stats.
    /// PREVIOUSLY there were two COUNT(*) over `file` per EACH scan — on a production DB (millions of rows,
    /// dozens of scans) that is exactly the F12/F2 freeze. COALESCE: old scans without the progress
    /// columns yield 0 (they migrate up on open — see load_or_materialize).
    fn scans_filtered(&self, active: bool) -> Result<Vec<ResumeInfo>> {
        type Raw = (i64, String, String, String, i64, i64, i64, i64, i64, i64);
        let raw: Vec<Raw> = {
            let mut stmt = self.conn.prepare(
                "SELECT s.id, s.created_at, s.status, s.config_json,
                        COALESCE(st.cand_files_total, 0),
                        COALESCE(st.cand_files_hashed, 0),
                        COALESCE(st.cand_bytes_total, 0),
                        COALESCE(st.cand_bytes_hashed, 0),
                        COALESCE(st.files_scanned, 0),
                        COALESCE(st.reclaimable_bytes, 0)
                 FROM scan s
                 LEFT JOIN scan_stats st ON st.scan_id = s.id
                 WHERE COALESCE(s.trashed, 0) = ?1
                 ORDER BY s.id DESC",
            )?;
            // active → trashed=0; trash bin → trashed=1.
            let want_trashed: i64 = if active { 0 } else { 1 };
            let rows = stmt.query_map(params![want_trashed], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };

        let mut scans = Vec::with_capacity(raw.len());
        for (
            scan_id,
            created_at,
            status_text,
            config_json,
            cf_total,
            cf_hashed,
            cb_total,
            cb_hashed,
            fscanned,
            reclaim,
        ) in raw
        {
            let status = ScanStatus::parse(&status_text)
                .ok_or_else(|| AppError::msg(format!("unknown scan status: {status_text}")))?;
            let config: ScanConfig = serde_json::from_str(&config_json)?;
            let (mut files_total, mut files_hashed, mut cand_bytes_total, mut cand_bytes_hashed) = (
                cf_total as u64,
                cf_hashed as u64,
                cb_total as u64,
                cb_hashed as u64,
            );
            // Old unfinished sessions have no materialized
            // candidate progress — we fetch it once via a direct count (there are only a few), so that
            // the list still shows an honest hashing %.
            if status == ScanStatus::Hashing && cand_bytes_total == 0 {
                if let Ok(cs) = self.candidate_stats(scan_id) {
                    files_total = cs.total_files;
                    files_hashed = cs.hashed_files;
                    cand_bytes_total = cs.total_bytes;
                    cand_bytes_hashed = cs.hashed_bytes;
                }
            }
            scans.push(ResumeInfo {
                scan_id,
                created_at,
                status,
                roots: config.roots,
                files_total,
                files_hashed,
                cand_bytes_total,
                cand_bytes_hashed,
                files_scanned: fscanned as u64,
                reclaimable_bytes: reclaim as u64,
            });
        }
        Ok(scans)
    }

    /// A single `list_scans` pass: the newest UNfinished + the newest Complete of the
    /// same roots. Replaces two separate `find_*_for_roots` (each of which called `list_scans`) —
    /// for the background F2 probe (instant response, the heavy query in the background).
    pub fn resume_probe_for_roots(
        &self,
        roots: &[PathBuf],
    ) -> Result<(Option<ResumeInfo>, Option<ResumeInfo>)> {
        let mut unfinished = None;
        let mut complete = None;
        for info in self.list_scans()? {
            if info.roots != roots {
                continue;
            }
            if info.status.is_completed() {
                if complete.is_none() {
                    complete = Some(info);
                }
            } else if unfinished.is_none() {
                unfinished = Some(info);
            }
            if unfinished.is_some() && complete.is_some() {
                break;
            }
        }
        Ok((unfinished, complete))
    }

    /// Retention: on a fresh Complete, marks into the TRASH BIN (not purge!)
    /// completed scans of the same roots BEYOND the newest `keep`, as well as stale
    /// unfinished/aborted ones of the same roots. The just-completed one (`current`) we
    /// do not touch and count toward `keep`. Returns the number moved to the trash bin.
    pub fn apply_retention(&self, roots: &[PathBuf], keep: usize, current: i64) -> Result<usize> {
        let mut kept_complete = 0usize;
        let mut to_trash: Vec<i64> = Vec::new();
        // list_scans is already DESC by id (newest first) and without the trash bin.
        for info in self.list_scans()? {
            if info.roots != roots {
                continue;
            }
            if info.scan_id == current {
                kept_complete += 1;
                continue;
            }
            match info.status {
                ScanStatus::Complete | ScanStatus::CompleteWithWarnings => {
                    kept_complete += 1;
                    if kept_complete > keep {
                        to_trash.push(info.scan_id);
                    }
                }
                // Unfinished/aborted are stale — there is a fresh Complete.
                ScanStatus::Walking | ScanStatus::Hashing | ScanStatus::Aborted => {
                    to_trash.push(info.scan_id);
                }
            }
        }
        for id in &to_trash {
            self.trash_scan(*id)?;
        }
        Ok(to_trash.len())
    }

    /// Marks the session as deleted (trash bin) — instant and reversible.
    pub fn trash_scan(&self, scan_id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE scan SET trashed = 1 WHERE id = ?1",
            params![scan_id],
        )?;
        Ok(())
    }

    /// Returns the session from the trash bin to the active list.
    pub fn restore_scan(&self, scan_id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE scan SET trashed = 0 WHERE id = ?1",
            params![scan_id],
        )?;
        Ok(())
    }

    /// Hard and IRREVERSIBLY deletes the session from ALL scan_id tables:
    /// scan/scan_stats/file/file_mark/dir_dedup/file_group/file_dedup. We do NOT touch `hash_cache`
    /// — it is keyed by (device,inode) and shared across all scans. Metadata ≠ pool data
    /// (recreated by a re-scan). The heavy DELETE over `file` (millions of rows) should be called in the background.
    pub fn purge_scan(&mut self, scan_id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        for table in [
            "scan_stats",
            "file_mark",
            "file",
            "dir_dedup",
            "file_group",
            "file_dedup",
        ] {
            // The table names are internal constants, not user input.
            tx.execute(
                &format!("DELETE FROM {table} WHERE scan_id = ?1"),
                params![scan_id],
            )?;
        }
        tx.execute("DELETE FROM scan WHERE id = ?1", params![scan_id])?;
        tx.commit()?;
        Ok(())
    }

    /// Compacts the DB file (VACUUM) — frees space after emptying the trash bin.
    /// A heavy operation (rewrites the entire file); call in the background/maintenance, not in the UI.
    pub fn vacuum(&self) -> Result<()> {
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }

    /// Begins a new scan: creates a `scan` row and a `scan_stats` row.
    /// Previous sessions are preserved — they can be selected on the sessions screen.
    pub fn begin_scan(&mut self, config: &ScanConfig) -> Result<i64> {
        let config_json = serde_json::to_string(config)?;
        let now = now_string();

        self.conn.execute(
            "INSERT INTO scan(created_at, updated_at, status, config_json)
             VALUES (?1, ?1, ?2, ?3)",
            params![now, ScanStatus::Walking.as_str(), config_json],
        )?;
        let scan_id = self.conn.last_insert_rowid();
        self.conn.execute(
            "INSERT INTO scan_stats(scan_id) VALUES (?1)",
            params![scan_id],
        )?;
        Ok(scan_id)
    }

    /// Loads the scan configuration.
    pub fn load_config(&self, scan_id: i64) -> Result<ScanConfig> {
        let json: String = self.conn.query_row(
            "SELECT config_json FROM scan WHERE id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&json)?)
    }

    /// The current scan status.
    pub fn scan_status(&self, scan_id: i64) -> Result<ScanStatus> {
        let text: String = self.conn.query_row(
            "SELECT status FROM scan WHERE id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        ScanStatus::parse(&text)
            .ok_or_else(|| AppError::msg(format!("unknown scan status: {text}")))
    }

    /// Summary of a completed scan from `scan_stats` — for opening the result
    /// without recomputation (read in `spawn_open_completed`).
    pub fn scan_summary(&self, scan_id: i64) -> Result<ScanSummary> {
        let summary = self.conn.query_row(
            "SELECT files_scanned, bytes_hashed, groups_found, reclaimable_bytes, elapsed_seconds,
                    hash_failures
             FROM scan_stats WHERE scan_id = ?1",
            params![scan_id],
            |row| {
                Ok(ScanSummary {
                    files_scanned: row.get::<_, i64>(0)? as u64,
                    bytes_hashed: row.get::<_, i64>(1)? as u64,
                    groups_found: row.get::<_, i64>(2)? as usize,
                    total_reclaimable_bytes: row.get::<_, i64>(3)? as u64,
                    elapsed_seconds: row.get::<_, f64>(4)?,
                    hash_failures: row.get::<_, i64>(5)? as u64,
                })
            },
        )?;
        Ok(summary)
    }

    /// Changes the scan status.
    pub fn set_status(&self, scan_id: i64, status: ScanStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE scan SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![scan_id, status.as_str(), now_string()],
        )?;
        Ok(())
    }

    /// Deletes the scan's file manifest (before a re-walk).
    pub fn clear_files(&self, scan_id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM file WHERE scan_id = ?1", params![scan_id])?;
        Ok(())
    }

    /// Batch-adds files to the manifest (walk phase). hash = NULL.
    pub fn record_files(&mut self, scan_id: i64, files: &[ManifestRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO file
                     (scan_id, path, size, mtime, mtime_nsec, ctime_sec, ctime_nsec,
                      device, inode, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            )?;
            for file in files {
                let path = file.path.to_string_lossy();
                stmt.execute(params![
                    scan_id,
                    &*path,
                    file.size as i64,
                    file.mtime,
                    file.mtime_nsec,
                    file.ctime_sec,
                    file.ctime_nsec,
                    file.device as i64,
                    file.inode as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Materializes a LIGHTWEIGHT `file_group` summary of file groups (`rank` = the «by
    /// benefit» order of the already-sorted `groups` passed in). Opening a finished
    /// scan reads the summaries from here, and group members — from the `file` manifest by hash
    /// (`group_files`). Overwrites the scan's previous rows (idempotent).
    /// `reclaim = size·(n−1)` is independent of the keeper.
    ///
    /// `file_dedup` (membership) IS NO LONGER WRITTEN — `file` already stores
    /// path/size/mtime/device/inode, there is no point duplicating them (scan.db does not bloat).
    /// The table is kept defined for compatibility; we clean up legacy rows.
    pub fn record_file_results(&mut self, scan_id: i64, groups: &[DuplicateGroup]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM file_group WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM file_dedup WHERE scan_id = ?1",
            params![scan_id],
        )?;
        {
            let mut ins_group = tx.prepare(
                "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for (rank, group) in groups.iter().enumerate() {
                ins_group.execute(params![
                    scan_id,
                    rank as i64,
                    group.hash,
                    group.files.len() as i64,
                    group.size_bytes as i64,
                    group.reclaimable_bytes() as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Materializes LIGHTWEIGHT `file_group` summaries via SQL aggregation — without loading
    /// `Vec<DuplicateGroup>` into RAM (on the 2.2M /tank it cuts the transient peak of the
    /// grouping phase). Result-identical to `record_file_results(&duplicate_groups)` on the path
    /// WITHOUT `--verify`: the same rank/hash/file_count/size/reclaim.
    ///
    /// The rank order is critical: the old path = a STABLE `reclaim DESC` sort on top of
    /// groups in `hash ASC` order (from `duplicate_groups` `ORDER BY f.hash`) → the window
    /// `ORDER BY reclaim DESC, hash ASC`, 0-based `ROW_NUMBER`. `hex_encode` = lower
    /// case → `lower(hex(hash))` (string order == BLOB order). `MIN(size)` — within
    /// a group the size is single (identical content). NOT the write path (apply/revalidate).
    pub fn materialize_file_groups(&mut self, scan_id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM file_group WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM file_dedup WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim)
             SELECT ?1,
                    ROW_NUMBER() OVER (ORDER BY reclaim DESC, hash ASC) - 1,
                    hash, file_count, size, reclaim
             FROM (
                 SELECT lower(hex(hash))          AS hash,
                        COUNT(*)                  AS file_count,
                        MIN(size)                 AS size,
                        MIN(size) * (COUNT(*) - 1) AS reclaim
                 FROM file
                 WHERE scan_id = ?1 AND hash IS NOT NULL
                 GROUP BY hash
                 HAVING COUNT(*) >= 2
             )",
            params![scan_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Saves candidate progress into `scan_stats` — so that the session list
    /// shows honest progress cheaply, without the correlated `candidate_stats` subquery.
    pub fn update_candidate_progress(
        &self,
        scan_id: i64,
        files_total: u64,
        bytes_total: u64,
        files_hashed: u64,
        bytes_hashed: u64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE scan_stats
                SET cand_files_total = ?2, cand_bytes_total = ?3,
                    cand_files_hashed = ?4, cand_bytes_hashed = ?5
              WHERE scan_id = ?1",
            params![
                scan_id,
                files_total as i64,
                bytes_total as i64,
                files_hashed as i64,
                bytes_hashed as i64,
            ],
        )?;
        Ok(())
    }

    /// Files awaiting hashing: hash IS NULL and the size occurs ≥ 2 times.
    pub fn candidate_files(&self, scan_id: i64) -> Result<Vec<ManifestRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, size, mtime, mtime_nsec, ctime_sec, ctime_nsec, device, inode FROM file
             WHERE scan_id = ?1 AND hash IS NULL
               AND size IN (
                   SELECT size FROM file WHERE scan_id = ?1
                   GROUP BY size HAVING COUNT(*) >= 2
               )",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok(ManifestRow {
                path: PathBuf::from(row.get::<_, String>(0)?),
                size: row.get::<_, i64>(1)? as u64,
                mtime: row.get::<_, i64>(2)?,
                mtime_nsec: row.get::<_, i64>(3)?,
                ctime_sec: row.get::<_, i64>(4)?,
                ctime_nsec: row.get::<_, i64>(5)?,
                device: row.get::<_, i64>(6)? as u64,
                inode: row.get::<_, i64>(7)? as u64,
            })
        })?;

        let mut files = Vec::new();
        for row in rows {
            files.push(row?);
        }
        Ok(files)
    }

    /// Statistics on hashing candidates.
    pub fn candidate_stats(&self, scan_id: i64) -> Result<CandidateStats> {
        let stats = self.conn.query_row(
            "SELECT
                 COUNT(*),
                 COALESCE(SUM(size), 0),
                 COUNT(hash),
                 COALESCE(SUM(CASE WHEN hash IS NOT NULL THEN size ELSE 0 END), 0)
             FROM file
             WHERE scan_id = ?1
               AND size IN (
                   SELECT size FROM file WHERE scan_id = ?1
                   GROUP BY size HAVING COUNT(*) >= 2
               )",
            params![scan_id],
            |row| {
                Ok(CandidateStats {
                    total_files: row.get::<_, i64>(0)? as u64,
                    total_bytes: row.get::<_, i64>(1)? as u64,
                    hashed_files: row.get::<_, i64>(2)? as u64,
                    hashed_bytes: row.get::<_, i64>(3)? as u64,
                })
            },
        )?;
        Ok(stats)
    }

    /// Summary of the DB contents: the number of sessions (total/trashed) and
    /// manifest rows — for `--stats` and the F12 header. Cheap: COUNT over indexes/PK.
    pub fn db_counts(&self) -> Result<DbCounts> {
        let (scans, trashed): (i64, i64) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN trashed = 1 THEN 1 ELSE 0 END), 0) FROM scan",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let file_rows: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM file", [], |row| row.get(0))?;
        Ok(DbCounts {
            scans: scans as u64,
            trashed: trashed as u64,
            file_rows: file_rows as u64,
        })
    }

    /// Total number of files in the manifest.
    pub fn manifest_count(&self, scan_id: i64) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM file WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Simple recording of hashes by path (without fd-verification of identity). On the
    /// scan path it was replaced by `record_hashes_verified`; it remains a test helper for
    /// setting hashes by path (move semantics, version=0 → not a source of inheritance).
    #[cfg(test)]
    pub fn record_hashes(&mut self, scan_id: i64, hashes: &[(PathBuf, [u8; 32])]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt =
                tx.prepare("UPDATE file SET hash = ?3 WHERE scan_id = ?1 AND path = ?2")?;
            for (path, hash) in hashes {
                let path = path.to_string_lossy();
                stmt.execute(params![scan_id, &*path, &hash[..]])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// A checkpoint of fd-verified hashes of the scan phase. A conditional UPDATE —
    /// commits the hash ONLY if the row in the DB still carries the same identity that
    /// was verified on the descriptor (size + full time + dev/inode). 0 updated rows
    /// = a race/change, NOT a success (the hash is not committed). `identity_version=1` is set
    /// exclusively here → only these hashes qualify as a source of inheritance.
    /// Returns the rows ACTUALLY committed (count + volume) — drives by them
    /// an honest DB progress via the persisted delta, without `candidate_stats` on each batch.
    pub fn record_hashes_verified(
        &mut self,
        scan_id: i64,
        rows: &[(ManifestRow, [u8; 32])],
    ) -> Result<PersistedHashes> {
        let tx = self.conn.transaction()?;
        let mut persisted = PersistedHashes::default();
        {
            let mut stmt = tx.prepare(
                "UPDATE file SET hash = ?3, identity_version = 1
                 WHERE scan_id = ?1 AND path = ?2 AND hash IS NULL
                   AND size = ?4 AND mtime = ?5 AND mtime_nsec = ?6
                   AND ctime_sec = ?7 AND ctime_nsec = ?8
                   AND device = ?9 AND inode = ?10",
            )?;
            for (row, hash) in rows {
                let path = row.path.to_string_lossy();
                let updated = stmt.execute(params![
                    scan_id,
                    &*path,
                    &hash[..],
                    row.size as i64,
                    row.mtime,
                    row.mtime_nsec,
                    row.ctime_sec,
                    row.ctime_nsec,
                    row.device as i64,
                    row.inode as i64,
                ])?;
                // PK (scan_id,path) → updated ∈ {0,1}. We accumulate bytes only for committed ones.
                if updated > 0 {
                    persisted.files += updated as u64;
                    persisted.bytes += row.size;
                }
            }
        }
        tx.commit()?;
        Ok(persisted)
    }

    /// DISABLED. The former key `(device,inode,size,mtime)` is unsafe —
    /// ZFS changes `device/inode` after import/reboot, and second-granularity `mtime` is not enough
    /// (an edit in the same second of the same length). Always `None`: the move path re-hashes
    /// the file anew (`hash_of`), legacy `hash_cache` entries are NEVER reused.
    pub fn hash_by_identity(
        &self,
        _device: u64,
        _inode: u64,
        _size: u64,
        _mtime: i64,
    ) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }

    /// Saves/updates a file's hash in `hash_cache` by identity.
    pub fn upsert_hash(
        &mut self,
        device: u64,
        inode: u64,
        size: u64,
        mtime: i64,
        hash: &[u8; 32],
    ) -> Result<()> {
        let now = chrono::Local::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO hash_cache (device, inode, size, mtime, hash, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(device, inode, size, mtime)
             DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at",
            params![
                device as i64,
                inode as i64,
                size as i64,
                mtime,
                &hash[..],
                now
            ],
        )?;
        Ok(())
    }

    /// Writes a move event (the «trash bin» journal + the fact of a created duplicate).
    pub fn record_move_event(&mut self, event: &MoveEvent) -> Result<()> {
        let source = event.source_path.to_string_lossy();
        let target = event.target_path.to_string_lossy();
        let hash: Option<&[u8]> = event.hash.as_ref().map(|h| &h[..]);
        self.conn.execute(
            "INSERT INTO move_event
                (created_at, scan_id, source_path, target_path, hash, duplicate)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.created_at,
                event.scan_id,
                &*source,
                &*target,
                hash,
                event.duplicate as i64
            ],
        )?;
        Ok(())
    }

    /// All move events. For now read only by a test; remove `#[cfg(test)]`
    /// when a dedup pass appears that finishes off the marked `.dupN` (round v2).
    #[cfg(test)]
    pub fn move_events(&self) -> Result<Vec<MoveEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT created_at, scan_id, source_path, target_path, hash, duplicate
             FROM move_event ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                PathBuf::from(row.get::<_, String>(2)?),
                PathBuf::from(row.get::<_, String>(3)?),
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (created_at, scan_id, source_path, target_path, hash, duplicate) = row?;
            out.push(MoveEvent {
                created_at,
                scan_id,
                source_path,
                target_path,
                hash: hash.and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok()),
                duplicate: duplicate != 0,
            });
        }
        Ok(out)
    }

    /// Assembles duplicate groups: files with a common hash occurring ≥ 2 times.
    pub fn duplicate_groups(&self, scan_id: i64) -> Result<Vec<DuplicateGroup>> {
        let mut stmt = self.conn.prepare(
            "SELECT f.path, f.size, f.mtime, f.device, f.inode, f.hash,
                    m.is_keeper, m.action
             FROM file f
             LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
             WHERE f.scan_id = ?1 AND f.hash IS NOT NULL
               AND f.hash IN (
                   SELECT hash FROM file WHERE scan_id = ?1 AND hash IS NOT NULL
                   GROUP BY hash HAVING COUNT(*) >= 2
               )
             ORDER BY f.hash, f.path",
        )?;

        let rows = stmt.query_map(params![scan_id], |row| {
            Ok((
                PathBuf::from(row.get::<_, String>(0)?),
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)? as u64,
                row.get::<_, i64>(4)? as u64,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?;

        let mut groups: Vec<DuplicateGroup> = Vec::new();
        for row in rows {
            let (path, size, mtime, device, inode, hash_bytes, is_keeper, action) = row?;
            let hash = hex_encode(&hash_bytes);
            let entry = FileEntry {
                path,
                size,
                mtime,
                device,
                inode,
                is_keeper: is_keeper.unwrap_or(0) != 0,
                action: action.as_deref().and_then(ActionKind::parse),
            };

            let append = matches!(groups.last(), Some(group) if group.hash == hash);
            if append {
                groups.last_mut().expect("checked above").files.push(entry);
            } else {
                let id = groups.len();
                groups.push(DuplicateGroup {
                    id,
                    size_bytes: size,
                    hash,
                    files: vec![entry],
                });
            }
        }
        crate::model::duplicate::sort_groups_by_benefit(&mut groups);
        Ok(groups)
    }

    /// Hash status of all scan files: path, size, hash (`None` — not hashed).
    /// Unlike `duplicate_groups`, it returns both unique and unhashed
    /// files — needed by the commander interface for the «hashed / not» attribute and for
    /// computing the total directory size.
    // (PathBuf, size, optional hash) — a simple row tuple; type_complexity is noise here.
    #[allow(clippy::type_complexity)]
    pub fn file_hash_status(&self, scan_id: i64) -> Result<Vec<(PathBuf, u64, Option<[u8; 32]>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, size, hash FROM file WHERE scan_id = ?1")?;
        let rows = stmt.query_map(params![scan_id], |row| {
            let path = PathBuf::from(row.get::<_, String>(0)?);
            let size = row.get::<_, i64>(1)? as u64;
            let hash: Option<Vec<u8>> = row.get(2)?;
            Ok((path, size, hash))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (path, size, hash) = row?;
            let hash = hash.and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());
            out.push((path, size, hash));
        }
        Ok(out)
    }

    /// All scan files (for diff and building the index). Filtering by root is done by
    /// the CALLER via `Path::starts_with` — SQL `LIKE path%` produced false
    /// matches at the boundary (`/x` caught `/x2`) and treated `%`/`_` in a path as a
    /// wildcard.
    pub fn files_for_scan(&self, scan_id: i64) -> Result<Vec<crate::state::move_track::FileRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, size, mtime, device, inode, hash FROM file
             WHERE scan_id = ?1",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            let hash: Option<Vec<u8>> = row.get(5)?;
            Ok(crate::state::move_track::FileRow {
                path: PathBuf::from(row.get::<_, String>(0)?),
                size: row.get::<_, i64>(1)? as u64,
                mtime: row.get::<_, i64>(2)?,
                device: row.get::<_, i64>(3)? as u64,
                inode: row.get::<_, i64>(4)? as u64,
                hash: hash.and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Writes the scan's duplicate-directory groups.
    pub fn record_dir_groups(&mut self, scan_id: i64, groups: &[DirGroup]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO dir_dedup
                 (scan_id, signature, path, file_count, size_per_dir)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for group in groups {
                for path in &group.paths {
                    stmt.execute(params![
                        scan_id,
                        group.signature,
                        path.to_string_lossy(),
                        group.file_count as i64,
                        group.size_per_dir as i64,
                    ])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Materializes `dir_dedup` via a temporary table — a mirror of
    /// `materialize_file_groups`. `producer` streams `(path, signature, size, file_count)`
    /// into the passed `emit` callback (the source — `build_dir_signatures_streaming` in C3);
    /// after the producer we keep in `dir_dedup` only groups with ≥ 2 directories
    /// (`HAVING COUNT(*) >= 2`). Existing rows of the same `scan_id` are erased.
    /// Used on the Merkle path in `run_phases`.
    pub fn materialize_dir_groups<F>(&mut self, scan_id: i64, producer: F) -> Result<()>
    where
        F: FnOnce(&mut dyn FnMut(PathBuf, String, u64, u32) -> Result<()>) -> Result<()>,
    {
        let tx = self.conn.transaction()?;
        // Per-connection temp table: created once; cleared before each run.
        tx.execute(
            "CREATE TEMP TABLE IF NOT EXISTS tmp_dir_sig (
                path        TEXT PRIMARY KEY,
                signature   TEXT NOT NULL,
                size        INTEGER NOT NULL,
                file_count  INTEGER NOT NULL
            ) WITHOUT ROWID",
            [],
        )?;
        tx.execute("DELETE FROM tmp_dir_sig", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO tmp_dir_sig(path, signature, size, file_count) VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut emit = |path: PathBuf, sig: String, size: u64, count: u32| -> Result<()> {
                stmt.execute(params![
                    path.to_string_lossy(),
                    sig,
                    size as i64,
                    count as i64,
                ])?;
                Ok(())
            };
            producer(&mut emit)?;
        }
        // Replace dir_dedup for this scan; the ≥ 2 group filter is on the SQL side.
        tx.execute("DELETE FROM dir_dedup WHERE scan_id = ?1", params![scan_id])?;
        tx.execute(
            "INSERT INTO dir_dedup(scan_id, signature, path, file_count, size_per_dir)
             SELECT ?1, signature, path, file_count, size FROM tmp_dir_sig
             WHERE signature IN (
                 SELECT signature FROM tmp_dir_sig GROUP BY signature HAVING COUNT(*) >= 2
             )",
            params![scan_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The scan's duplicate-directory groups, sorted by benefit (read in
    /// commander on entering the directory-groups mode).
    pub fn dir_groups(&self, scan_id: i64) -> Result<Vec<DirGroup>> {
        let mut stmt = self.conn.prepare(
            "SELECT signature, path, file_count, size_per_dir FROM dir_dedup
             WHERE scan_id = ?1 ORDER BY signature, path",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                PathBuf::from(row.get::<_, String>(1)?),
                row.get::<_, i64>(2)? as u32,
                row.get::<_, i64>(3)? as u64,
            ))
        })?;

        let mut by_sig: std::collections::HashMap<String, DirGroup> =
            std::collections::HashMap::new();
        let mut order: Vec<String> = Vec::new();
        for row in rows {
            let (sig, path, count, size) = row?;
            let group = by_sig.entry(sig.clone()).or_insert_with(|| {
                order.push(sig.clone());
                DirGroup {
                    id: 0,
                    signature: sig.clone(),
                    paths: Vec::new(),
                    file_count: count,
                    size_per_dir: size,
                }
            });
            group.paths.push(path);
        }
        let mut groups: Vec<DirGroup> = order
            .into_iter()
            .filter_map(|sig| by_sig.remove(&sig))
            .collect();
        crate::model::duplicate::sort_dir_groups_by_benefit(&mut groups);
        Ok(groups)
    }

    /// Saves action marks for the specified scan files (Feature 6B).
    /// A file in the default state (not a keeper, no action) — the row
    /// is deleted; otherwise it is inserted/updated.
    pub fn save_marks<'a>(
        &mut self,
        scan_id: i64,
        files: impl Iterator<Item = &'a FileEntry>,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut upsert = tx.prepare(
                "INSERT OR REPLACE INTO file_mark(scan_id, path, is_keeper, action)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut clear = tx.prepare("DELETE FROM file_mark WHERE scan_id = ?1 AND path = ?2")?;
            for file in files {
                let path = file.path.to_string_lossy();
                if !file.is_keeper && file.action.is_none() {
                    clear.execute(params![scan_id, &*path])?;
                } else {
                    upsert.execute(params![
                        scan_id,
                        &*path,
                        file.is_keeper as i64,
                        file.action.map(|action| action.as_str()),
                    ])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Ensures a `scan_stats` row exists for the scan (for scans
    /// started before the statistics table existed).
    pub fn ensure_scan_stats(&self, scan_id: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO scan_stats(scan_id) VALUES (?1)",
            params![scan_id],
        )?;
        Ok(())
    }

    /// Adds an interval of active scan time (seconds).
    pub fn add_elapsed(&self, scan_id: i64, seconds: f64) -> Result<()> {
        self.conn.execute(
            "UPDATE scan_stats SET elapsed_seconds = elapsed_seconds + ?2 WHERE scan_id = ?1",
            params![scan_id, seconds],
        )?;
        Ok(())
    }

    /// Accumulated active scan time (seconds).
    pub fn elapsed_seconds(&self, scan_id: i64) -> Result<f64> {
        let seconds: f64 = self.conn.query_row(
            "SELECT elapsed_seconds FROM scan_stats WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(seconds)
    }

    /// Records the scan environment: media type, pool layout, ZFS version.
    pub fn record_scan_environment(&self, scan_id: i64, env: &ScanEnvironment) -> Result<()> {
        self.conn.execute(
            "UPDATE scan_stats
                SET storage_type = ?2, pool_layout = ?3, zfs_version = ?4
              WHERE scan_id = ?1",
            params![scan_id, env.storage_type, env.pool_layout, env.zfs_version],
        )?;
        Ok(())
    }

    /// Records the final metrics of a completed scan.
    pub fn record_scan_result(&self, scan_id: i64, summary: &ScanSummary) -> Result<()> {
        self.conn.execute(
            "UPDATE scan_stats
                SET files_scanned = ?2, bytes_hashed = ?3,
                    groups_found = ?4, reclaimable_bytes = ?5, hash_failures = ?6
              WHERE scan_id = ?1",
            params![
                scan_id,
                summary.files_scanned as i64,
                summary.bytes_hashed as i64,
                summary.groups_found as i64,
                summary.total_reclaimable_bytes as i64,
                summary.hash_failures as i64,
            ],
        )?;
        Ok(())
    }

    /// Statistics for all scans (for the `--stats` report), newest first.
    pub fn list_stats(&self) -> Result<Vec<ScanStatsRow>> {
        type Raw = (
            i64,
            String,
            String,
            String,
            f64,
            Option<String>,
            Option<String>,
            Option<String>,
            i64,
            i64,
            i64,
            i64,
            i64,
        );
        let raw: Vec<Raw> = {
            let mut stmt = self.conn.prepare(
                "SELECT s.id, s.created_at, s.status, s.config_json,
                        st.elapsed_seconds, st.storage_type, st.pool_layout, st.zfs_version,
                        st.files_scanned, st.bytes_hashed, st.groups_found, st.reclaimable_bytes,
                        st.hash_failures
                   FROM scan s
                   JOIN scan_stats st ON st.scan_id = s.id
                  ORDER BY s.id DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, f64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };

        let mut stats = Vec::new();
        for (
            id,
            created_at,
            status,
            config_json,
            elapsed,
            storage,
            layout,
            version,
            files,
            bytes,
            groups,
            reclaimable,
            hash_failures,
        ) in raw
        {
            let config: ScanConfig = serde_json::from_str(&config_json)?;
            stats.push(ScanStatsRow {
                scan_id: id,
                created_at,
                status,
                roots: config.roots,
                elapsed_seconds: elapsed,
                storage_type: storage.unwrap_or_default(),
                pool_layout: layout.unwrap_or_default(),
                zfs_version: version.unwrap_or_default(),
                files_scanned: files as u64,
                bytes_hashed: bytes as u64,
                groups_found: groups as u64,
                reclaimable_bytes: reclaimable as u64,
                hash_failures: hash_failures as u64,
            });
        }
        Ok(stats)
    }

    /// Reuses hashes from past scans for unchanged files of the current scan.
    /// «Unchanged» = the key `(path, size, mtime)` matched. Previously the key
    /// was `(device, inode, size, mtime)`, but ZFS `st_dev` is NOT stable across
    /// reboots/pool re-imports — after a reboot the match broke and the scan hashed
    /// «from scratch». The key is the FULL temporal identity
    /// `(path,size,mtime,mtime_nsec,ctime_sec,ctime_nsec)` + source
    /// `identity_version=1` (fd-verified); `dev/inode` are NOT in the key (ZFS changes them).
    /// The inherited row also becomes `version=1` — the chain survives cleanup of
    /// old scans. Returns the number inherited. Index `file_reuse_identity`.
    pub fn inherit_hashes(&mut self, scan_id: i64) -> Result<u64> {
        let updated = self.conn.execute(
            "UPDATE file
                SET hash = (
                        SELECT prev.hash FROM file AS prev
                         WHERE prev.path = file.path AND prev.size = file.size
                           AND prev.mtime = file.mtime AND prev.mtime_nsec = file.mtime_nsec
                           AND prev.ctime_sec = file.ctime_sec
                           AND prev.ctime_nsec = file.ctime_nsec
                           AND prev.identity_version = 1 AND prev.hash IS NOT NULL
                           AND prev.scan_id <> file.scan_id
                         LIMIT 1
                    ),
                    identity_version = 1
              WHERE scan_id = ?1
                AND hash IS NULL
                AND EXISTS (
                        SELECT 1 FROM file AS prev
                         WHERE prev.path = file.path AND prev.size = file.size
                           AND prev.mtime = file.mtime AND prev.mtime_nsec = file.mtime_nsec
                           AND prev.ctime_sec = file.ctime_sec
                           AND prev.ctime_nsec = file.ctime_nsec
                           AND prev.identity_version = 1 AND prev.hash IS NOT NULL
                           AND prev.scan_id <> file.scan_id
                    )",
            params![scan_id],
        )?;
        Ok(updated as u64)
    }

    /// id of the newest scan (by descending id), `None` — there are no scans. A lightweight replacement
    /// for `find_resumable` for the dedup overlay: without `candidate_stats` (a correlated
    /// GROUP BY over the whole manifest — expensive on /tank).
    pub fn latest_scan_id(&self) -> Result<Option<i64>> {
        let row = self
            .conn
            .query_row("SELECT id FROM scan ORDER BY id DESC LIMIT 1", [], |row| {
                row.get::<_, i64>(0)
            });
        match row {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// The scan's `created_at` by id — for the commander header
    /// (`humanize_ago` → «2 h ago»). A point PK lookup, cheap on any DB size.
    pub fn scan_created_at(&self, scan_id: i64) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        let row = self
            .conn
            .query_row(
                "SELECT created_at FROM scan WHERE id = ?1",
                params![scan_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(row)
    }

    /// The most recent **completed** scan whose `roots`
    /// cover `cwd` — either one of the `roots` is an ancestor of `cwd` (cwd inside
    /// the scanned tree), or `cwd` is an ancestor of one of the `roots`
    /// (there is a scanned subdirectory inside cwd). `None` — there are no such scans.
    ///
    /// Why: hybrid B of active-scan auto-switching. On a cwd change of the active
    /// panel in the commander, if the current `dedup_scan_id` does NOT cover cwd —
    /// `maybe_auto_switch_scan` looks here for a suitable one and switches. Before this
    /// `spawn_dedup_load(None)` dumbly took the last completed one, which could
    /// be about a completely unrelated part of the tree.
    pub fn latest_scan_covering(&self, cwd: &Path) -> Result<Option<i64>> {
        // Both completed statuses (Complete and CompleteWithWarnings) cover cwd —
        // otherwise a scan-with-warnings would not be «found» in the commander on auto-switching.
        let mut stmt = self.conn.prepare(
            "SELECT id, config_json FROM scan
             WHERE status IN (?1, ?2)
             ORDER BY id DESC",
        )?;
        let rows = stmt.query_map(
            params![
                ScanStatus::Complete.as_str(),
                ScanStatus::CompleteWithWarnings.as_str()
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;
        for row in rows {
            let (id, json) = row?;
            let config: ScanConfig = match serde_json::from_str(&json) {
                Ok(c) => c,
                Err(_) => continue, // corrupt JSON — skip it, do not litter Err
            };
            for root in &config.roots {
                if cwd.starts_with(root) || root.starts_with(cwd) {
                    return Ok(Some(id));
                }
            }
        }
        Ok(None)
    }

    /// Is the file `path` in the scan manifest? A point PK lookup — for the mark-write
    /// gate (we do not write `file_mark` for files outside the scan).
    pub fn is_in_manifest(&self, scan_id: i64, path: &Path) -> Result<bool> {
        let p = path.to_string_lossy();
        let exists: i64 = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM file WHERE scan_id = ?1 AND path = ?2)",
            params![scan_id, &*p],
            |row| row.get(0),
        )?;
        Ok(exists != 0)
    }

    /// The hash of file `path` in the scan, if it is hashed. A point PK lookup — replaces
    /// reading from the RAM index (commander build_groups / show_file_info).
    pub fn hash_for_path(&self, scan_id: i64, path: &Path) -> Result<Option<[u8; 32]>> {
        let p = path.to_string_lossy();
        let row = self.conn.query_row(
            "SELECT hash FROM file WHERE scan_id = ?1 AND path = ?2",
            params![scan_id, &*p],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        );
        match row {
            Ok(Some(bytes)) => Ok(<[u8; 32]>::try_from(bytes.as_slice()).ok()),
            Ok(None) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Files of the group with hex hash `hash_hex` with FRESH marks (LEFT JOIN
    /// `file_mark`). Reads membership from the `file` manifest (index `file_hash`), not
    /// from `file_dedup` — an opened /tank does not hold all groups in RAM.
    /// Dozens of rows per group — loaded on entry into the group, discarded on exit.
    pub fn group_files(&self, scan_id: i64, hash_hex: &str) -> Result<Vec<FileEntry>> {
        let Some(blob) = hex_decode(hash_hex) else {
            return Ok(Vec::new());
        };
        let mut stmt = self.conn.prepare(
            "SELECT f.path, f.size, f.mtime, f.device, f.inode, m.is_keeper, m.action
             FROM file f
             LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
             WHERE f.scan_id = ?1 AND f.hash = ?2
             ORDER BY f.path",
        )?;
        let rows = stmt.query_map(params![scan_id, blob], |row| {
            Ok(FileEntry {
                path: PathBuf::from(row.get::<_, String>(0)?),
                size: row.get::<_, i64>(1)? as u64,
                mtime: row.get::<_, i64>(2)?,
                device: row.get::<_, i64>(3)? as u64,
                inode: row.get::<_, i64>(4)? as u64,
                is_keeper: row.get::<_, Option<i64>>(5)?.unwrap_or(0) != 0,
                action: row
                    .get::<_, Option<String>>(6)?
                    .as_deref()
                    .and_then(ActionKind::parse),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// A page of a group's files — `[offset..offset+limit]`,
    /// ordered by `path` for a stable order across pages. Previously
    /// `group_files_capped` pulled LIMIT without `ORDER BY` and sorted in RAM — that is
    /// fine for a single page, but adjacent pages could overlap
    /// (index order is not guaranteed by SQLite). Here ORDER BY path is cheap,
    /// because the covering index `file_hash_path` already yields rows in the right
    /// order after `WHERE scan_id=? AND hash=?` — there is no sort in RAM.
    pub fn group_files_page(
        &self,
        scan_id: i64,
        hash_hex: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<FileEntry>> {
        let Some(blob) = hex_decode(hash_hex) else {
            return Ok(Vec::new());
        };
        let mut stmt = self.conn.prepare(
            "SELECT f.path, f.size, f.mtime, f.device, f.inode, m.is_keeper, m.action
             FROM file f
             LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
             WHERE f.scan_id = ?1 AND f.hash = ?2
             ORDER BY f.path
             LIMIT ?3 OFFSET ?4",
        )?;
        let rows = stmt.query_map(params![scan_id, blob, limit as i64, offset as i64], |row| {
            Ok(FileEntry {
                path: PathBuf::from(row.get::<_, String>(0)?),
                size: row.get::<_, i64>(1)? as u64,
                mtime: row.get::<_, i64>(2)?,
                device: row.get::<_, i64>(3)? as u64,
                inode: row.get::<_, i64>(4)? as u64,
                is_keeper: row.get::<_, Option<i64>>(5)?.unwrap_or(0) != 0,
                action: row
                    .get::<_, Option<String>>(6)?
                    .as_deref()
                    .and_then(ActionKind::parse),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// An exact count of a group's files — for displaying «X/Y»
    /// in the panel title and deciding «are there more pages». `summary.file_count` already
    /// carries this number (materialized in `file_group`), but for resilience to
    /// desynchronization (e.g. a manual DB edit) we keep a direct COUNT over
    /// the `file_hash` index — it is fast at any group size.
    pub fn group_files_count(&self, scan_id: i64, hash_hex: &str) -> Result<u64> {
        use rusqlite::OptionalExtension;
        let Some(blob) = hex_decode(hash_hex) else {
            return Ok(0);
        };
        let count: Option<i64> = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM file WHERE scan_id = ?1 AND hash = ?2",
                params![scan_id, blob],
                |row| row.get(0),
            )
            .optional()?;
        Ok(count.unwrap_or(0) as u64)
    }

    /// Dedup status of each file from `paths` (a batch per panel directory):
    /// point PK lookups + for each distinct hash — `COUNT(*)`/`COUNT(DISTINCT
    /// device)` (index `file_hash`), for each (size,mtime) of unhashed ones —
    /// `COUNT(*)` (index `file_size`). Paths outside the manifest do not enter the map
    /// (the caller treats them as NotInScan). Replaces the RAM maps of `DedupIndex`.
    pub fn dir_dedup_status(
        &self,
        scan_id: i64,
        paths: &[PathBuf],
    ) -> Result<HashMap<PathBuf, DedupRow>> {
        // 1. Metadata of each path from the manifest (PK lookup).
        let mut meta: Vec<(PathBuf, Option<Vec<u8>>, u64, i64)> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT size, mtime, hash FROM file WHERE scan_id = ?1 AND path = ?2")?;
            for path in paths {
                let p = path.to_string_lossy();
                let row = stmt.query_row(params![scan_id, &*p], |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                });
                match row {
                    Ok((size, mtime, hash)) => meta.push((path.clone(), hash, size, mtime)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }
        // 2. dup_count + distinct_devices for each distinct hash.
        let mut hash_counts: HashMap<Vec<u8>, (u32, u32)> = HashMap::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT COUNT(*), COUNT(DISTINCT device) FROM file WHERE scan_id = ?1 AND hash = ?2",
            )?;
            for (_, hash, _, _) in &meta {
                if let Some(h) = hash {
                    if !hash_counts.contains_key(h) {
                        let counts = stmt.query_row(params![scan_id, h], |row| {
                            Ok((row.get::<_, i64>(0)? as u32, row.get::<_, i64>(1)? as u32))
                        })?;
                        hash_counts.insert(h.clone(), counts);
                    }
                }
            }
        }
        // 3. size_mtime_count for each distinct (size,mtime) of unhashed ones.
        let mut sm_counts: HashMap<(u64, i64), u32> = HashMap::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT COUNT(*) FROM file WHERE scan_id = ?1 AND size = ?2 AND mtime = ?3",
            )?;
            for (_, hash, size, mtime) in &meta {
                if hash.is_none() && !sm_counts.contains_key(&(*size, *mtime)) {
                    let count = stmt.query_row(params![scan_id, *size as i64, *mtime], |row| {
                        Ok(row.get::<_, i64>(0)? as u32)
                    })?;
                    sm_counts.insert((*size, *mtime), count);
                }
            }
        }
        // 4. Assembling the rows.
        let mut out = HashMap::with_capacity(meta.len());
        for (path, hash, size, mtime) in meta {
            let row = match &hash {
                Some(h) => {
                    let (dup_count, distinct_devices) =
                        hash_counts.get(h).copied().unwrap_or((0, 0));
                    DedupRow {
                        hashed: Some(hex_encode(h)),
                        dup_count,
                        distinct_devices,
                        size_mtime_count: 0,
                    }
                }
                None => DedupRow {
                    hashed: None,
                    dup_count: 0,
                    distinct_devices: 0,
                    size_mtime_count: sm_counts.get(&(size, mtime)).copied().unwrap_or(0),
                },
            };
            out.insert(path, row);
        }
        Ok(out)
    }

    /// The total size of scan files strictly under each directory in `dirs`
    /// (a prefix range over the PK, without `LIKE%`). Directories with no scan files do not
    /// enter the map. A batch over the panel's visible subdirectories.
    pub fn dir_sizes_under(&self, scan_id: i64, dirs: &[PathBuf]) -> Result<HashMap<PathBuf, u64>> {
        let mut out = HashMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT COALESCE(SUM(size), 0) FROM file WHERE scan_id = ?1 AND path >= ?2 AND path < ?3",
        )?;
        for dir in dirs {
            let (lo, hi) = prefix_bounds(dir);
            let total: i64 = stmt.query_row(params![scan_id, lo, hi], |row| row.get(0))?;
            if total > 0 {
                out.insert(dir.clone(), total as u64);
            }
        }
        Ok(out)
    }

    /// The content signature of each directory in `dirs` (a prefix range over the PK + the
    /// `signature_of` core). A signature is produced ONLY for COMPLETE directories —
    /// where every scanned file under it has a hash; a directory with an unhashed
    /// (unique-size / failure) file does NOT enter the map (nor do directories with no files at all).
    /// A match of two directories' signatures = the same SCANNED contents
    /// (cross-panel highlighting).
    ///
    /// `algo` MUST match the one with which this scan's `dir_dedup` was
    /// materialized (see `ScanConfig.dir_sig_algo`), otherwise the hex of live signatures will diverge
    /// from the persisted — cross-panel highlight breaks. The old top-down (`Old`) and the new
    /// streaming-Merkle (`Merkle`) produce identical equivalence CLASSES (the group
    /// compositions are identical), but the per-row hex differs.
    pub fn dir_signatures_under(
        &self,
        scan_id: i64,
        dirs: &[PathBuf],
        algo: DirSigAlgo,
    ) -> Result<HashMap<PathBuf, String>> {
        let mut out = HashMap::new();
        // We take ALL files under the directory (not only `hash IS NOT NULL`).
        // An unhashed file (unique-size / failure) makes the directory INCOMPLETE — a live
        // signature for it is NOT produced (no false cross-panel «twin» highlighting).
        let mut stmt = self.conn.prepare(
            "SELECT path, hash FROM file
             WHERE scan_id = ?1 AND path >= ?2 AND path < ?3
             ORDER BY path",
        )?;
        for dir in dirs {
            let (lo, hi) = prefix_bounds(dir);
            let rows = stmt.query_map(params![scan_id, lo, hi], |row| {
                Ok((
                    PathBuf::from(row.get::<_, String>(0)?),
                    row.get::<_, Option<Vec<u8>>>(1)?,
                ))
            })?;
            match algo {
                DirSigAlgo::Old => {
                    let mut entries: Vec<(String, String)> = Vec::new();
                    let mut complete = true;
                    for row in rows {
                        let (path, hash) = row?;
                        if let Ok(rel) = path.strip_prefix(dir) {
                            match hash {
                                Some(h) => entries
                                    .push((rel.to_string_lossy().into_owned(), hex_encode(&h))),
                                None => complete = false, // unhashed file → incompleteness
                            }
                        }
                    }
                    if complete && !entries.is_empty() {
                        out.insert(dir.clone(), signature_of(&entries));
                    }
                }
                DirSigAlgo::Merkle => {
                    // Gather files under `dir` (size is not needed for sig — 0 placeholder),
                    // run streaming-Merkle; an incomplete `dir` is NOT emitted → no sig.
                    let mut files: Vec<(PathBuf, u64, Option<String>)> = Vec::new();
                    for row in rows {
                        let (path, hash) = row?;
                        files.push((path, 0, hash.map(|h| hex_encode(&h))));
                    }
                    if files.is_empty() {
                        continue;
                    }
                    let mut dir_sig: Option<String> = None;
                    build_dir_signatures_streaming(files, |emitted, sig, _, _| {
                        if emitted.as_path() == dir.as_path() {
                            dir_sig = Some(sig);
                        }
                        Ok(())
                    })?;
                    if let Some(sig) = dir_sig {
                        out.insert(dir.clone(), sig);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Summaries of all twin-directory groups for
    /// the browser tab `[2] Directories`. SQL aggregation over `dir_dedup`: a group =
    /// rows with the same `signature`, filter `COUNT(*) >= 2`, sorted by
    /// descending benefit `(count - 1) * size_per_dir`. Entries in `dir_dedup` are already
    /// ≥2 by themselves (that is how they were written via `record_dir_groups` /
    /// `materialize_dir_groups`); `HAVING` is a safeguard against future migrations.
    /// `rank` is 1-based, set in code after the fetch.
    ///
    pub fn dir_group_summaries(&self, scan_id: i64) -> Result<Vec<DirGroupSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT signature,
                    CAST(COUNT(*) AS INTEGER)          AS dir_count,
                    CAST(MIN(file_count) AS INTEGER)   AS file_count,
                    CAST(MIN(size_per_dir) AS INTEGER) AS size_per_dir
             FROM dir_dedup
             WHERE scan_id = ?1
             GROUP BY signature
             HAVING COUNT(*) >= 2
             ORDER BY (CAST(COUNT(*) AS INTEGER) - 1) * CAST(MIN(size_per_dir) AS INTEGER) DESC,
                      signature ASC",
        )?;
        let rows = stmt.query_map(params![scan_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u32,
                r.get::<_, i64>(2)? as u32,
                r.get::<_, i64>(3)? as u64,
            ))
        })?;
        let mut out: Vec<DirGroupSummary> = Vec::new();
        for (rank, row) in (1_u32..).zip(rows) {
            let (signature, dir_count, file_count, size_per_dir) = row?;
            out.push(DirGroupSummary {
                rank,
                signature,
                dir_count,
                file_count,
                size_per_dir,
            });
        }
        Ok(out)
    }

    /// The full twin-directory group by signature —
    /// for the right panel of the browser Dirs tab on entering a group. Uses
    /// the index `dir_dedup_by_scan_sig` (schema.rs:58). Returns `None`
    /// if the signature does not exist (safeguard).
    ///
    pub fn dir_group_paths(&self, scan_id: i64, signature: &str) -> Result<Option<DirGroup>> {
        use rusqlite::OptionalExtension;
        // LIMIT 1 (not MIN/COUNT): on an empty selection it returns NoRow → `.optional()`
        // gives `None`. MIN/COUNT return a SINGLE row with NULL even on an empty
        // selection, and `r.get::<_, i64>` then fails on NULL — not our case.
        // For all rows of a group `file_count` and `size_per_dir` are the same (that is how
        // they are written in `record_dir_groups`/`materialize_dir_groups`).
        let row = self
            .conn
            .query_row(
                "SELECT file_count, size_per_dir FROM dir_dedup
                 WHERE scan_id = ?1 AND signature = ?2 LIMIT 1",
                params![scan_id, signature],
                |r| Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)? as u64)),
            )
            .optional()?;
        let Some((file_count, size_per_dir)) = row else {
            return Ok(None);
        };
        let mut stmt = self.conn.prepare(
            "SELECT path FROM dir_dedup
             WHERE scan_id = ?1 AND signature = ?2 ORDER BY path",
        )?;
        let mut paths: Vec<PathBuf> = Vec::new();
        let rows = stmt.query_map(params![scan_id, signature], |r| {
            Ok(PathBuf::from(r.get::<_, String>(0)?))
        })?;
        for row in rows {
            paths.push(row?);
        }
        if paths.is_empty() {
            return Ok(None);
        }
        Ok(Some(DirGroup {
            id: 0,
            signature: signature.to_string(),
            paths,
            file_count,
            size_per_dir,
        }))
    }

    /// «twin folder» — finding twins of a specific directory in
    /// `dir_dedup`. `None` if the directory is not in a duplicate group. Otherwise `Some(group)`,
    /// where `group.paths` contains all members (including `dir_path` itself).
    /// Uses the index `dir_dedup_by_scan_sig` (schema.rs:58). Called from
    /// `resolve_watch_group` on the key `WatchKey::DirOf`.
    pub fn dir_twins(&self, scan_id: i64, dir_path: &Path) -> Result<Option<DirGroup>> {
        use rusqlite::OptionalExtension;
        let dir_str = dir_path.to_string_lossy();
        let row = self
            .conn
            .query_row(
                "SELECT signature, file_count, size_per_dir FROM dir_dedup
                 WHERE scan_id = ?1 AND path = ?2 LIMIT 1",
                params![scan_id, dir_str.as_ref()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)? as u32,
                        r.get::<_, i64>(2)? as u64,
                    ))
                },
            )
            .optional()?;
        let Some((signature, file_count, size_per_dir)) = row else {
            return Ok(None);
        };
        let mut stmt = self.conn.prepare(
            "SELECT path FROM dir_dedup
             WHERE scan_id = ?1 AND signature = ?2 ORDER BY path",
        )?;
        let mut paths: Vec<PathBuf> = Vec::new();
        let rows = stmt.query_map(params![scan_id, &signature], |r| {
            Ok(PathBuf::from(r.get::<_, String>(0)?))
        })?;
        for row in rows {
            paths.push(row?);
        }
        Ok(Some(DirGroup {
            id: 0,
            signature,
            paths,
            file_count,
            size_per_dir,
        }))
    }

    /// Files under `dir_path` whose hash occurs in
    /// a materialized `file_group` group (i.e. there is a duplicate SOMEWHERE in the scan,
    /// possibly outside `dir_path`). Used by the UX when a directory has no
    /// twin — to show duplicate files inside. Uses `file_group_hash`
    /// (schema.rs:76) for the IN subquery and `prefix_bounds` for the range. Called
    /// from `resolve_watch_group` on the key `WatchKey::DirOf` as a fallback.
    pub fn dup_files_inside(&self, scan_id: i64, dir_path: &Path) -> Result<Vec<PathBuf>> {
        let (lo, hi) = prefix_bounds(dir_path);
        let mut stmt = self.conn.prepare(
            "SELECT path FROM file
             WHERE scan_id = ?1 AND path >= ?2 AND path < ?3 AND hash IS NOT NULL
               AND lower(hex(hash)) IN (
                   SELECT hash FROM file_group WHERE scan_id = ?1
               )
             ORDER BY path",
        )?;
        let rows = stmt.query_map(params![scan_id, lo, hi], |r| {
            Ok(PathBuf::from(r.get::<_, String>(0)?))
        })?;
        let mut out: Vec<PathBuf> = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Whether `path` is covered by the active scan — that is, whether there is at least one
    /// row in `file` either EXACTLY at this path (it is a file from the scan manifest),
    /// or under this prefix (a directory in which at least one file is stored).
    /// Used by `resolve_watch_group` to distinguish «outside the scan» vs «in the scan,
    /// but without duplicates» — without this, render shows a misleading
    /// «no source» placeholder. Both queries are an index lookup of PK `(scan_id,path)`.
    pub fn is_path_in_scan(&self, scan_id: i64, path: &Path) -> Result<bool> {
        use rusqlite::OptionalExtension;
        let p = path.to_string_lossy();
        // 1) Exact match — the path is recorded as a file in the manifest.
        let hit: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM file WHERE scan_id = ?1 AND path = ?2 LIMIT 1",
                params![scan_id, p.as_ref()],
                |r| r.get(0),
            )
            .optional()?;
        if hit.is_some() {
            return Ok(true);
        }
        // 2) Prefix — the path is a directory, and there is at least one file under it.
        let (lo, hi) = prefix_bounds(path);
        let hit: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM file
                 WHERE scan_id = ?1 AND path >= ?2 AND path < ?3 LIMIT 1",
                params![scan_id, lo, hi],
                |r| r.get(0),
            )
            .optional()?;
        Ok(hit.is_some())
    }

    /// Lightweight summaries of all scan groups in «by benefit» order — Browser
    /// holds them instead of all `FileEntry`. A PK-covered query over `file_group`.
    pub fn group_summaries(&self, scan_id: i64) -> Result<Vec<GroupSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT rank, hash, file_count, size, reclaim FROM file_group
             WHERE scan_id = ?1 ORDER BY rank",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok(GroupSummary {
                rank: row.get(0)?,
                hash: row.get(1)?,
                file_count: row.get::<_, i64>(2)? as u64,
                size_bytes: row.get::<_, i64>(3)? as u64,
                reclaim_bytes: row.get::<_, i64>(4)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// A group summary by hex hash — for commander DuplicatesOfCursor:
    /// confirms that the file under the cursor belongs to a duplicate group. A point lookup over
    /// the index `file_group_hash`. `None` — the hash does not form a materialized group.
    pub fn group_summary_for_hash(
        &self,
        scan_id: i64,
        hash_hex: &str,
    ) -> Result<Option<GroupSummary>> {
        let row = self.conn.query_row(
            "SELECT rank, hash, file_count, size, reclaim FROM file_group
             WHERE scan_id = ?1 AND hash = ?2 LIMIT 1",
            params![scan_id, hash_hex],
            |row| {
                Ok(GroupSummary {
                    rank: row.get(0)?,
                    hash: row.get(1)?,
                    file_count: row.get::<_, i64>(2)? as u64,
                    size_bytes: row.get::<_, i64>(3)? as u64,
                    reclaim_bytes: row.get::<_, i64>(4)? as u64,
                })
            },
        );
        match row {
            Ok(summary) => Ok(Some(summary)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// The number of files marked for an action (non-keeper + has an action) — for the counter
    /// in the Browser header, without holding all groups in RAM.
    pub fn marked_count(&self, scan_id: i64) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_mark
             WHERE scan_id = ?1 AND is_keeper = 0 AND action IS NOT NULL",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Ensures the scan's `file_group` is materialized: if there are no summaries
    /// yet (the scan completed before materialization), computes `duplicate_groups` ONCE
    /// and writes them, then the result is immediately dropped (does not settle in RAM).
    /// Replaces `load_or_materialize` on the path of opening a finished scan.
    pub fn ensure_materialized(&mut self, scan_id: i64) -> Result<()> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_group WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        if count > 0 {
            return Ok(());
        }
        let mut groups = self.duplicate_groups(scan_id)?;
        crate::model::duplicate::sort_groups_by_benefit(&mut groups);
        if !groups.is_empty() {
            self.record_file_results(scan_id, &groups)?;
        }
        Ok(())
    }

    /// Action-plan rows from `file` + `file_mark` — without materializing
    /// all groups. The target: a NON-keeper file marked for an action with a known hash;
    /// the keeper — the DETERMINISTIC single one (first by path among the keepers of the
    /// same group). Targets without a resolved keeper are DISCARDED (fail-safe: we delete
    /// nothing without a keeper). Exactly reproduces the pair selection of `actions::plan_actions`.
    pub fn planned_action_rows(&self, scan_id: i64) -> Result<Vec<PlannedActionRow>> {
        // The former version (a single SELECT with TWO correlated subqueries per
        // target) froze the UI for seconds: the SQLite planner drove the outer query over the
        // `file` table (hundreds of thousands of rows). Now — two queries, DRIVEN by the small `file_mark`
        // (dozens of marked rows; `file` is taken by PK `(scan_id,path)`), and assembling pairs
        // in memory. O(marks), not O(all files). The keeper semantics (first by path) are
        // preserved → the central test `plan_from_db_equals_plan_from_ram` is green.

        // 1. Keeper for each hash: the first by path among marked keepers with a hash.
        let mut keeper_stmt = self.conn.prepare(
            "SELECT f.hash, f.path, f.device
               FROM file_mark m
               JOIN file f ON f.scan_id = m.scan_id AND f.path = m.path
              WHERE m.scan_id = ?1 AND m.is_keeper = 1 AND f.hash IS NOT NULL
              ORDER BY f.path",
        )?;
        let keeper_rows = keeper_stmt.query_map(params![scan_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                PathBuf::from(row.get::<_, String>(1)?),
                row.get::<_, i64>(2)? as u64,
            ))
        })?;
        let mut keepers: std::collections::HashMap<Vec<u8>, (PathBuf, u64)> =
            std::collections::HashMap::new();
        for row in keeper_rows {
            let (hash, path, device) = row?;
            // Queries by path → the first (minimal by path) wins.
            keepers.entry(hash).or_insert((path, device));
        }

        // 2. Targets: marked NON-keepers with an action and a known hash.
        let mut target_stmt = self.conn.prepare(
            "SELECT f.path, f.size, f.device, f.hash, m.action
               FROM file_mark m
               JOIN file f ON f.scan_id = m.scan_id AND f.path = m.path
              WHERE m.scan_id = ?1 AND m.is_keeper = 0 AND m.action IS NOT NULL
                AND f.hash IS NOT NULL
              ORDER BY f.hash, f.path",
        )?;
        let target_rows = target_stmt.query_map(params![scan_id], |row| {
            Ok((
                PathBuf::from(row.get::<_, String>(0)?),
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in target_rows {
            let (target, size, target_device, hash, action) = row?;
            // The group has no keeper → we do not touch the target (fail-safe, like plan_actions).
            let Some((keeper, keeper_device)) = keepers.get(&hash) else {
                continue;
            };
            out.push(PlannedActionRow {
                action,
                target,
                keeper: keeper.clone(),
                target_device,
                keeper_device: *keeper_device,
                size,
                expected_hash: hex_encode(&hash),
            });
        }
        Ok(out)
    }
}

fn now_string() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Decodes a hex hash string into bytes (the inverse of `hex_encode`). `None` — the string
/// is not valid hex. Needed for binding `file_group.hash` (hex TEXT) against
/// `file.hash` (BLOB[32]) in `group_files`.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// The half-open interval of descendant paths of directory `dir`: `[dir/"/" , dir/"0")`. `'0'` = `'/'
/// + 1`, so the range catches exactly `dir/...` and does not pick up siblings (`/x` ≠ `/x2`)
/// — unlike `LIKE 'dir/%'`, where `%`/`_` in a path are treated as wildcards.
///
/// The root `/` is a special case. The general formula would give `("//", "/0")`, but
/// real paths (`/tank/...`) sort ABOVE `"/0"` and fell out of the range —
/// a scan with root `/` returned empty (`dir_sizes_under`, `dir_signatures_under`,
/// `dup_files_inside`, `is_path_in_scan`). The descendants of `/` are all absolute paths:
/// each starts with `'/'` (0x2F), so any `/...` is ≥ `"/"` and `< "0"` (0x30).
fn prefix_bounds(dir: &Path) -> (String, String) {
    let s = dir.to_string_lossy();
    if s == "/" {
        return (String::from("/"), String::from("0"));
    }
    (format!("{s}/"), format!("{s}0"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::scan::ScanConfig;

    #[test]
    fn finds_duplicates_and_skips_unique_size() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(vec![PathBuf::from("/x")]);
        let scan_id = store.begin_scan(&config).unwrap();

        let files = vec![
            row("/a", 100, 1),
            row("/b", 100, 2),
            row("/c", 100, 3),
            row("/unique", 999, 4),
        ];
        store.record_files(scan_id, &files).unwrap();

        // /unique has a unique size -> not a candidate for hashing.
        let candidates = store.candidate_files(scan_id).unwrap();
        assert_eq!(candidates.len(), 3);

        // /a and /b — same hash; /c — different.
        let hash_ab = [1u8; 32];
        let hash_c = [2u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/a"), hash_ab),
                    (PathBuf::from("/b"), hash_ab),
                    (PathBuf::from("/c"), hash_c),
                ],
            )
            .unwrap();

        let groups = store.duplicate_groups(scan_id).unwrap();
        assert_eq!(groups.len(), 1, "expect one group of duplicates");
        assert_eq!(groups[0].files.len(), 2);
        assert_eq!(groups[0].reclaimable_bytes(), 100);
    }

    #[test]
    fn record_hashes_verified_is_conditional_on_identity() {
        // We commit the hash only when the full identity matches; otherwise 0
        // rows (race) — not a success. identity_version=1 is set only here.
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        let a = ManifestRow {
            path: PathBuf::from("/x/a"),
            size: 100,
            mtime: 5,
            mtime_nsec: 7,
            ctime_sec: 9,
            ctime_nsec: 11,
            device: 1,
            inode: 2,
        };
        let b = ManifestRow {
            path: PathBuf::from("/x/b"),
            ..a.clone()
        };
        store.record_files(id, &[a.clone(), b.clone()]).unwrap();
        let h = [3u8; 32];

        // Matching identity → committed: 1 row, its size (persisted delta).
        let p = store.record_hashes_verified(id, &[(a, h)]).unwrap();
        assert_eq!((p.files, p.bytes), (1, 100), "1 row committed, 100 bytes");
        // Non-matching identity (different mtime_nsec) → 0/0, hash not committed.
        let b_wrong = ManifestRow {
            mtime_nsec: 999,
            ..b
        };
        let p0 = store.record_hashes_verified(id, &[(b_wrong, h)]).unwrap();
        assert_eq!(
            (p0.files, p0.bytes),
            (0, 0),
            "identity did not match — nothing committed"
        );

        // identity_version: /x/a=1 (verified inheritance source), /x/b=0.
        let idv = |path: &str| -> i64 {
            store
                .conn
                .query_row(
                    "SELECT identity_version FROM file WHERE scan_id = ?1 AND path = ?2",
                    rusqlite::params![id, path],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(idv("/x/a"), 1);
        assert_eq!(idv("/x/b"), 0);
    }

    #[test]
    fn hash_failures_reconcile_to_unhashed_candidates() {
        // Hash_failures = candidate_stats.total_files − hashed_files — candidates WITHOUT
        // a committed hash RIGHT NOW, NOT accumulated attempts. Demonstrates "resume clears the
        // warning": as soon as a file gets a hash, it leaves the failure counter.
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        // Three candidates of the same size 100 (size occurs ≥2 → all are candidates).
        let mk = |p: &str, ino: u64| ManifestRow {
            path: PathBuf::from(p),
            size: 100,
            inode: ino,
            device: 1,
            ..Default::default()
        };
        let (a, b, c) = (mk("/x/a", 1), mk("/x/b", 2), mk("/x/c", 3));
        store
            .record_files(id, &[a.clone(), b.clone(), c.clone()])
            .unwrap();
        let h = [7u8; 32];

        // Nothing hashed yet → 3 candidates, 3 failures.
        let s0 = store.candidate_stats(id).unwrap();
        assert_eq!((s0.total_files, s0.hashed_files), (3, 0));
        assert_eq!(s0.total_files - s0.hashed_files, 3, "all 3 — failures");

        // Commit the hash of one → 2 failures (the counter reflects state, not history).
        assert_eq!(
            store.record_hashes_verified(id, &[(a, h)]).unwrap().files,
            1
        );
        let s1 = store.candidate_stats(id).unwrap();
        assert_eq!(
            s1.total_files - s1.hashed_files,
            2,
            "one committed — 2 failures"
        );
        assert_eq!(s1.hashed_bytes, 100);

        // Commit the rest → 0 failures (resume → success → no residual warning).
        store.record_hashes_verified(id, &[(b, h), (c, h)]).unwrap();
        let s2 = store.candidate_stats(id).unwrap();
        assert_eq!(
            s2.total_files - s2.hashed_files,
            0,
            "all committed — warning cleared"
        );
        assert_eq!(s2.hashed_files, 3);
    }

    #[test]
    fn hash_cache_disabled_never_reused() {
        // Hash_cache is disabled as a source of reuse — the key
        // (dev,inode,second-granularity mtime) is unsafe. Any record (including legacy)
        // is NEVER returned back.
        let mut store = ScanStore::open_in_memory().unwrap();
        assert_eq!(store.hash_by_identity(1, 2, 100, 5).unwrap(), None);
        store.upsert_hash(1, 2, 100, 5, &[7u8; 32]).unwrap();
        assert_eq!(
            store.hash_by_identity(1, 2, 100, 5).unwrap(),
            None,
            "cache disabled — record is not reused"
        );
    }

    #[test]
    fn move_event_roundtrip() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let event = MoveEvent {
            created_at: "2026-05-21T00:00:00+00:00".to_string(),
            scan_id: None,
            source_path: PathBuf::from("/src/a.txt"),
            target_path: PathBuf::from("/dst/a.txt.dup1"),
            hash: Some([3u8; 32]),
            duplicate: true,
        };
        store.record_move_event(&event).unwrap();
        let events = store.move_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_path, PathBuf::from("/src/a.txt"));
        assert_eq!(events[0].target_path, PathBuf::from("/dst/a.txt.dup1"));
        assert_eq!(events[0].hash, Some([3u8; 32]));
        assert!(events[0].duplicate);
    }

    #[test]
    fn inherit_hashes_by_path_survives_device_change() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(vec![PathBuf::from("/tank")]);

        // Scan A (before the "reboot"): device=10, the file is hashed.
        let a = store.begin_scan(&config).unwrap();
        store
            .record_files(
                a,
                &[ManifestRow {
                    path: PathBuf::from("/tank/foo"),
                    size: 100,
                    mtime: 42,
                    device: 10,
                    inode: 5,
                    ..Default::default()
                }],
            )
            .unwrap();
        let h = [7u8; 32];
        // The source must be fd-verified (identity_version=1), otherwise it
        // is unfit for inheritance. The same identity that was recorded in manifest #A.
        let a_row = ManifestRow {
            path: PathBuf::from("/tank/foo"),
            size: 100,
            mtime: 42,
            device: 10,
            inode: 5,
            ..Default::default()
        };
        assert_eq!(
            store
                .record_hashes_verified(a, &[(a_row, h)])
                .unwrap()
                .files,
            1
        );

        // Scan B (after the "reboot"): same path/size/mtime, but ZFS changed device+inode.
        let b = store.begin_scan(&config).unwrap();
        store
            .record_files(
                b,
                &[ManifestRow {
                    path: PathBuf::from("/tank/foo"),
                    size: 100,
                    mtime: 42,
                    device: 20,
                    inode: 99,
                    ..Default::default()
                }],
            )
            .unwrap();

        // The key (path,size,mtime) matches despite the device change → we inherit.
        assert_eq!(store.inherit_hashes(b).unwrap(), 1);
        let status = store.file_hash_status(b).unwrap();
        let foo = status
            .iter()
            .find(|(path, _, _)| path == &PathBuf::from("/tank/foo"))
            .unwrap();
        assert_eq!(foo.2, Some(h), "hash inherited by path");

        // A repeated call is idempotent (the file is already hashed).
        assert_eq!(store.inherit_hashes(b).unwrap(), 0);
    }

    #[test]
    fn inherit_requires_full_identity_and_verified_source() {
        // We inherit the hash only on a FULL match of the temporal identity
        // and a source with identity_version=1 (fd-verified).
        let mut store = ScanStore::open_in_memory().unwrap();
        let cfg = ScanConfig::new(vec![PathBuf::from("/t")]);

        // Source #A — fd-verified (version=1).
        let a = store.begin_scan(&cfg).unwrap();
        let src = ManifestRow {
            path: PathBuf::from("/t/f"),
            size: 100,
            mtime: 5,
            mtime_nsec: 100,
            ctime_sec: 9,
            ctime_nsec: 200,
            device: 1,
            inode: 1,
        };
        store.record_files(a, std::slice::from_ref(&src)).unwrap();
        store
            .record_hashes_verified(a, &[(src.clone(), [7u8; 32])])
            .unwrap();

        // #B: same second/size, but a different mtime_nsec → NOT inherited.
        let b = store.begin_scan(&cfg).unwrap();
        store
            .record_files(
                b,
                &[ManifestRow {
                    mtime_nsec: 999,
                    ..src.clone()
                }],
            )
            .unwrap();
        assert_eq!(store.inherit_hashes(b).unwrap(), 0, "different mtime_nsec");

        // #C: same mtime, but a different ctime → NOT inherited.
        let c = store.begin_scan(&cfg).unwrap();
        store
            .record_files(
                c,
                &[ManifestRow {
                    ctime_nsec: 999,
                    ..src.clone()
                }],
            )
            .unwrap();
        assert_eq!(store.inherit_hashes(c).unwrap(), 0, "different ctime");

        // #D: identity matches, but the source is legacy (version=0) → NOT inherited.
        let e = store.begin_scan(&cfg).unwrap();
        let legacy = ManifestRow {
            path: PathBuf::from("/t/legacy"),
            ..src.clone()
        };
        store
            .record_files(e, std::slice::from_ref(&legacy))
            .unwrap();
        store
            .record_hashes(e, &[(PathBuf::from("/t/legacy"), [8u8; 32])])
            .unwrap();
        let d = store.begin_scan(&cfg).unwrap();
        store.record_files(d, &[legacy]).unwrap();
        assert_eq!(store.inherit_hashes(d).unwrap(), 0, "source version=0");

        // Control: full match + source version=1 → inherited.
        let g = store.begin_scan(&cfg).unwrap();
        store.record_files(g, &[src]).unwrap();
        assert_eq!(store.inherit_hashes(g).unwrap(), 1, "full match");
    }

    #[test]
    fn resume_continues_unhashed_files() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(vec![PathBuf::from("/x")]);
        let scan_id = store.begin_scan(&config).unwrap();
        store
            .record_files(scan_id, &[row("/a", 100, 1), row("/b", 100, 2)])
            .unwrap();

        // Hashed only one file, then "crashed".
        store
            .record_hashes(scan_id, &[(PathBuf::from("/a"), [7u8; 32])])
            .unwrap();

        // On resume the only remaining candidate is the unhashed /b.
        let candidates = store.candidate_files(scan_id).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, PathBuf::from("/b"));
    }

    fn row(path: &str, size: u64, inode: u64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size,
            mtime: 0,
            device: 1,
            inode,
            ..Default::default()
        }
    }

    #[test]
    fn inherit_fills_resumable_session_no_disk_read() {
        // Resuming a session in the Hashing status inherits hashes from a past
        // completed scan (same path,size,mtime) → there is nothing to read from disk.
        let mut store = ScanStore::open_in_memory().unwrap();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        // Completed scan #A with hashes.
        let a = store.begin_scan(&cfg).unwrap();
        store
            .record_files(a, &[row("/x/a", 100, 1), row("/x/b", 100, 2)])
            .unwrap();
        // Source #A — fd-verified (version=1) via the same identity.
        assert_eq!(
            store
                .record_hashes_verified(
                    a,
                    &[
                        (row("/x/a", 100, 1), [1u8; 32]),
                        (row("/x/b", 100, 2), [2u8; 32]),
                    ],
                )
                .unwrap()
                .files,
            2
        );
        store.set_status(a, ScanStatus::Complete).unwrap();
        // Resumable session #B (status Hashing): same files, hash NULL.
        let b = store.begin_scan(&cfg).unwrap();
        store
            .record_files(b, &[row("/x/a", 100, 1), row("/x/b", 100, 2)])
            .unwrap();
        store.set_status(b, ScanStatus::Hashing).unwrap();
        // Before inheritance both are candidates (size 100 twice, hash NULL).
        assert_eq!(store.candidate_files(b).unwrap().len(), 2);
        // Inheritance (as `run_phases` does before `hash_phase` on resume).
        assert_eq!(
            store.inherit_hashes(b).unwrap(),
            2,
            "both inherited from #A"
        );
        // Now there is nothing to read from disk.
        assert!(
            store.candidate_files(b).unwrap().is_empty(),
            "after inherit candidate_files is empty → 0 disk reads"
        );
    }

    #[test]
    fn dir_groups_roundtrip() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        let groups = vec![DirGroup {
            id: 0,
            signature: "sig1".to_string(),
            paths: vec![PathBuf::from("/x/a"), PathBuf::from("/x/b")],
            file_count: 3,
            size_per_dir: 500,
        }];
        store.record_dir_groups(scan_id, &groups).unwrap();

        let loaded = store.dir_groups(scan_id).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].paths.len(), 2);
        assert_eq!(loaded[0].file_count, 3);
        assert_eq!(loaded[0].size_per_dir, 500);
        assert_eq!(loaded[0].reclaimable_bytes(), 500);
    }

    #[test]
    fn materialize_dir_groups_empty_producer_persists_nothing() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .materialize_dir_groups(scan_id, |_emit| Ok(()))
            .unwrap();
        assert!(store.dir_groups(scan_id).unwrap().is_empty());
    }

    #[test]
    fn materialize_dir_groups_filters_singletons_keeps_groups() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .materialize_dir_groups(scan_id, |emit| {
                // sig "S1" is shared by 2 directories → group; "S2" is a singleton → filtered out.
                emit(PathBuf::from("/x/a"), "S1".to_string(), 100, 5)?;
                emit(PathBuf::from("/x/b"), "S1".to_string(), 100, 5)?;
                emit(PathBuf::from("/x/c"), "S2".to_string(), 50, 2)?;
                Ok(())
            })
            .unwrap();
        let groups = store.dir_groups(scan_id).unwrap();
        assert_eq!(groups.len(), 1, "only the S1 group remains");
        assert_eq!(groups[0].signature, "S1");
        assert_eq!(groups[0].paths.len(), 2);
        assert_eq!(groups[0].file_count, 5);
        assert_eq!(groups[0].size_per_dir, 100);
    }

    #[test]
    fn dir_signatures_under_matches_persisted_for_old_algo() {
        // R6 C3: the live primitive MUST compute with the same algorithm as the persisted dir_dedup,
        // otherwise cross-panel highlight yields a ≠ hex. We check for Old.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &[
                    row("/x/a/f1", 100, 1),
                    row("/x/a/f2", 200, 2),
                    row("/x/b/f1", 100, 3),
                    row("/x/b/f2", 200, 4),
                ],
            )
            .unwrap();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/a/f1"), h1),
                    (PathBuf::from("/x/a/f2"), h2),
                    (PathBuf::from("/x/b/f1"), h1),
                    (PathBuf::from("/x/b/f2"), h2),
                ],
            )
            .unwrap();
        let all_files: Vec<(PathBuf, u64, Option<String>)> = store
            .file_hash_status(scan_id)
            .unwrap()
            .into_iter()
            .map(|(p, s, h)| (p, s, h.map(|h| hex_encode(&h))))
            .collect();
        let dir_groups = crate::model::duplicate::build_dir_groups(&all_files);
        store.record_dir_groups(scan_id, &dir_groups).unwrap();

        let live = store
            .dir_signatures_under(scan_id, &[PathBuf::from("/x/a")], DirSigAlgo::Old)
            .unwrap();
        let persisted = store.dir_groups(scan_id).unwrap();
        let group_with_a = persisted
            .iter()
            .find(|g| g.paths.contains(&PathBuf::from("/x/a")))
            .expect("/x/a must be in a group");
        assert_eq!(
            live.get(&PathBuf::from("/x/a")),
            Some(&group_with_a.signature),
            "Old: live == persisted"
        );
    }

    #[test]
    fn dir_signatures_under_matches_persisted_for_merkle_algo() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &[
                    row("/x/a/f1", 100, 1),
                    row("/x/a/f2", 200, 2),
                    row("/x/b/f1", 100, 3),
                    row("/x/b/f2", 200, 4),
                ],
            )
            .unwrap();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/a/f1"), h1),
                    (PathBuf::from("/x/a/f2"), h2),
                    (PathBuf::from("/x/b/f1"), h1),
                    (PathBuf::from("/x/b/f2"), h2),
                ],
            )
            .unwrap();
        // Persist via Merkle (as in the pipeline on the `--merkle-dirs` branch).
        let mut all_files: Vec<(PathBuf, u64, Option<String>)> = store
            .file_hash_status(scan_id)
            .unwrap()
            .into_iter()
            .map(|(p, s, h)| (p, s, h.map(|h| hex_encode(&h))))
            .collect();
        all_files.sort_by(|a, b| a.0.cmp(&b.0));
        store
            .materialize_dir_groups(scan_id, |emit| {
                crate::model::duplicate::build_dir_signatures_streaming(all_files, emit)
            })
            .unwrap();

        let live = store
            .dir_signatures_under(scan_id, &[PathBuf::from("/x/a")], DirSigAlgo::Merkle)
            .unwrap();
        let persisted = store.dir_groups(scan_id).unwrap();
        let group_with_a = persisted
            .iter()
            .find(|g| g.paths.contains(&PathBuf::from("/x/a")))
            .expect("/x/a must be in a group");
        assert_eq!(
            live.get(&PathBuf::from("/x/a")),
            Some(&group_with_a.signature),
            "Merkle: live == persisted"
        );
    }

    #[test]
    fn dir_signatures_under_suppresses_dir_with_unhashed_file() {
        // The live signature is NOT emitted for a directory with an unhashed
        // file (unique-size / failure) — no false cross-panel highlighting of "twins".
        // We check both algorithms.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &[
                    row("/x/a/f1", 100, 1),
                    row("/x/a/f2", 200, 2),
                    row("/x/a/uniq", 7, 3), // will stay without a hash
                ],
            )
            .unwrap();
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/a/f1"), [1u8; 32]),
                    (PathBuf::from("/x/a/f2"), [2u8; 32]),
                ],
            )
            .unwrap();

        for algo in [DirSigAlgo::Old, DirSigAlgo::Merkle] {
            let live = store
                .dir_signatures_under(scan_id, &[PathBuf::from("/x/a")], algo)
                .unwrap();
            assert!(
                !live.contains_key(&PathBuf::from("/x/a")),
                "{algo:?}: /x/a is incomplete (uniq without a hash) → no live signature"
            );
        }

        // Control: we finish hashing uniq → /x/a is complete → the signature appears.
        store
            .record_hashes(scan_id, &[(PathBuf::from("/x/a/uniq"), [3u8; 32])])
            .unwrap();
        let live = store
            .dir_signatures_under(scan_id, &[PathBuf::from("/x/a")], DirSigAlgo::Old)
            .unwrap();
        assert!(
            live.contains_key(&PathBuf::from("/x/a")),
            "after finishing hashing uniq /x/a is complete → the signature appears"
        );
    }

    #[test]
    fn dir_twins_returns_group_for_dir_in_dir_dedup() {
        // R6 C4: dir in a group → Some(group) with paths including the dir itself.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_dir_groups(
                scan_id,
                &[DirGroup {
                    id: 0,
                    signature: "SIG_TWINS".to_string(),
                    paths: vec![PathBuf::from("/x/a"), PathBuf::from("/x/b")],
                    file_count: 3,
                    size_per_dir: 500,
                }],
            )
            .unwrap();
        let twins = store
            .dir_twins(scan_id, &PathBuf::from("/x/a"))
            .unwrap()
            .expect("/x/a in a group");
        assert_eq!(twins.signature, "SIG_TWINS");
        let mut paths = twins.paths.clone();
        paths.sort();
        assert_eq!(paths, vec![PathBuf::from("/x/a"), PathBuf::from("/x/b")]);
        assert_eq!(twins.file_count, 3);
        assert_eq!(twins.size_per_dir, 500);
    }

    #[test]
    fn dir_twins_returns_none_for_dir_not_in_dir_dedup() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        // dir_dedup is empty.
        let twins = store
            .dir_twins(scan_id, &PathBuf::from("/x/orphan"))
            .unwrap();
        assert!(twins.is_none(), "a singleton outside groups — None");
    }

    // ---- Dir-group summaries for the browser tab ----

    #[test]
    fn dir_group_summaries_orders_by_reclaim_desc_with_1_based_rank() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/")]))
            .unwrap();
        // Group A: 2 directories × 1000 B → reclaim 1000.
        // Group B: 3 directories × 500 B  → reclaim 1000. tie → ORDER signature ASC.
        // Group C: 4 directories × 2000 B → reclaim 6000.  — the most beneficial of all.
        store
            .record_dir_groups(
                scan_id,
                &[
                    DirGroup {
                        id: 0,
                        signature: "SIG_A".to_string(),
                        paths: vec![PathBuf::from("/a1"), PathBuf::from("/a2")],
                        file_count: 1,
                        size_per_dir: 1000,
                    },
                    DirGroup {
                        id: 0,
                        signature: "SIG_B".to_string(),
                        paths: vec![
                            PathBuf::from("/b1"),
                            PathBuf::from("/b2"),
                            PathBuf::from("/b3"),
                        ],
                        file_count: 2,
                        size_per_dir: 500,
                    },
                    DirGroup {
                        id: 0,
                        signature: "SIG_C".to_string(),
                        paths: vec![
                            PathBuf::from("/c1"),
                            PathBuf::from("/c2"),
                            PathBuf::from("/c3"),
                            PathBuf::from("/c4"),
                        ],
                        file_count: 3,
                        size_per_dir: 2000,
                    },
                ],
            )
            .unwrap();
        let summaries = store.dir_group_summaries(scan_id).unwrap();
        assert_eq!(summaries.len(), 3);
        // First — C (reclaim 6000).
        assert_eq!(summaries[0].rank, 1);
        assert_eq!(summaries[0].signature, "SIG_C");
        assert_eq!(summaries[0].dir_count, 4);
        assert_eq!(summaries[0].file_count, 3);
        assert_eq!(summaries[0].size_per_dir, 2000);
        assert_eq!(summaries[0].reclaim_bytes(), 6000);
        // Second — A (reclaim 1000, SIG_A < SIG_B by the tie-break).
        assert_eq!(summaries[1].rank, 2);
        assert_eq!(summaries[1].signature, "SIG_A");
        // Third — B (reclaim 1000, SIG_B later).
        assert_eq!(summaries[2].rank, 3);
        assert_eq!(summaries[2].signature, "SIG_B");
    }

    #[test]
    fn dir_group_summaries_empty_when_dir_dedup_empty() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        let summaries = store.dir_group_summaries(scan_id).unwrap();
        assert!(summaries.is_empty());
    }

    #[test]
    fn dir_group_paths_returns_full_group_by_signature() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_dir_groups(
                scan_id,
                &[DirGroup {
                    id: 0,
                    signature: "SIG_X".to_string(),
                    paths: vec![PathBuf::from("/x/a"), PathBuf::from("/x/b")],
                    file_count: 2,
                    size_per_dir: 100,
                }],
            )
            .unwrap();
        let group = store
            .dir_group_paths(scan_id, "SIG_X")
            .unwrap()
            .expect("the signature exists");
        assert_eq!(group.signature, "SIG_X");
        let mut paths = group.paths.clone();
        paths.sort();
        assert_eq!(paths, vec![PathBuf::from("/x/a"), PathBuf::from("/x/b")]);
        assert_eq!(group.file_count, 2);
        assert_eq!(group.size_per_dir, 100);
        // Unknown signature — None.
        let none = store.dir_group_paths(scan_id, "NO_SUCH").unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn dup_files_inside_returns_only_files_with_duplicate_hashes() {
        // R6 C4: inside a dir we show only files whose hash occurs in file_group.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &[
                    row("/x/a/dup1", 100, 1), // h1
                    row("/x/a/uniq", 50, 2),  // h_unique
                    row("/x/b/dup2", 100, 3), // h1 — forms a pair → file_group
                ],
            )
            .unwrap();
        let h1 = [1u8; 32];
        let h_unique = [9u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/a/dup1"), h1),
                    (PathBuf::from("/x/a/uniq"), h_unique),
                    (PathBuf::from("/x/b/dup2"), h1),
                ],
            )
            .unwrap();
        store.materialize_file_groups(scan_id).unwrap();
        // /x/a contains dup1 (has a pair in /x/b) and uniq (no duplicate) → only dup1.
        let inside = store
            .dup_files_inside(scan_id, &PathBuf::from("/x/a"))
            .unwrap();
        assert_eq!(inside, vec![PathBuf::from("/x/a/dup1")]);
    }

    #[test]
    fn dup_files_inside_empty_for_dir_without_duplicates() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(scan_id, &[row("/x/lonely/only", 50, 1)])
            .unwrap();
        let h_unique = [9u8; 32];
        store
            .record_hashes(scan_id, &[(PathBuf::from("/x/lonely/only"), h_unique)])
            .unwrap();
        store.materialize_file_groups(scan_id).unwrap(); // no groups
        let inside = store
            .dup_files_inside(scan_id, &PathBuf::from("/x/lonely"))
            .unwrap();
        assert!(inside.is_empty());
    }

    #[test]
    fn is_path_in_scan_exact_file_hit_is_true() {
        // A file path that IS in the scan manifest → true (exact PK lookup).
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(scan_id, &[row("/x/a/file.txt", 10, 1)])
            .unwrap();
        assert!(store
            .is_path_in_scan(scan_id, &PathBuf::from("/x/a/file.txt"))
            .unwrap());
    }

    #[test]
    fn is_path_in_scan_dir_with_files_under_is_true() {
        // A directory path under which there are files → true (prefix lookup).
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(scan_id, &[row("/x/a/deep/file.txt", 10, 1)])
            .unwrap();
        // Both the root itself and an intermediate directory are covered by the scan.
        assert!(store
            .is_path_in_scan(scan_id, &PathBuf::from("/x"))
            .unwrap());
        assert!(store
            .is_path_in_scan(scan_id, &PathBuf::from("/x/a/deep"))
            .unwrap());
    }

    #[test]
    fn is_path_in_scan_unrelated_path_is_false() {
        // A path outside the scan (a different root / a missing directory) → false.
        // This is exactly the user case: /tank/documents/Документы outside scan, which
        // covers /tank/_UNSORTED — render now says "outside the scan", not "no source".
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(scan_id, &[row("/x/a/file.txt", 10, 1)])
            .unwrap();
        assert!(!store
            .is_path_in_scan(scan_id, &PathBuf::from("/y/unrelated"))
            .unwrap());
        assert!(!store
            .is_path_in_scan(scan_id, &PathBuf::from("/x/missing"))
            .unwrap());
    }

    #[test]
    fn prefix_bounds_root_covers_all_absolute_paths() {
        // The root `/` must cover all absolute paths.
        let (lo, hi) = prefix_bounds(Path::new("/"));
        assert_eq!((lo.as_str(), hi.as_str()), ("/", "0"));
        for p in ["/a", "/tank/file", "/usr/bin/x", "/zzz/deep"] {
            assert!(
                p >= lo.as_str() && p < hi.as_str(),
                "{p} outside the root range"
            );
        }
    }

    #[test]
    fn prefix_bounds_non_root_excludes_self_and_siblings() {
        let (lo, hi) = prefix_bounds(Path::new("/tank"));
        assert_eq!((lo.as_str(), hi.as_str()), ("/tank/", "/tank0"));
        assert!("/tank/a" >= lo.as_str() && "/tank/a" < hi.as_str());
        // The directory itself and a neighbour with a common prefix — outside the range.
        assert!(!("/tank" >= lo.as_str() && "/tank" < hi.as_str()));
        assert!(!("/tank2/a" >= lo.as_str() && "/tank2/a" < hi.as_str()));
    }

    #[test]
    fn dir_queries_under_root_cover_children() {
        // A scan with the root "/" — dir_sizes_under and
        // is_path_in_scan must see the descendants (previously prefix_bounds("/") lost them).
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/")]))
            .unwrap();
        store
            .record_files(
                id,
                &[
                    ManifestRow {
                        path: PathBuf::from("/tank/a"),
                        size: 100,
                        mtime: 1,
                        device: 1,
                        inode: 1,
                        ..Default::default()
                    },
                    ManifestRow {
                        path: PathBuf::from("/usr/b"),
                        size: 50,
                        mtime: 2,
                        device: 1,
                        inode: 2,
                        ..Default::default()
                    },
                ],
            )
            .unwrap();
        let sizes = store.dir_sizes_under(id, &[PathBuf::from("/")]).unwrap();
        assert_eq!(sizes.get(&PathBuf::from("/")).copied(), Some(150));
        assert!(store.is_path_in_scan(id, Path::new("/")).unwrap());
        assert!(store.is_path_in_scan(id, Path::new("/tank")).unwrap());
    }

    #[test]
    fn group_files_page_returns_offset_limit_window() {
        // The page [offset..offset+limit], ordered by path
        // via the file_hash_path index.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        let h = [1u8; 32];
        let hex = crate::model::duplicate::hex_encode(&h);
        // 5 files with the same hash; paths are intentionally not in alphabetical insertion order.
        store
            .record_files(
                scan_id,
                &[
                    row("/x/c", 10, 3),
                    row("/x/a", 10, 1),
                    row("/x/e", 10, 5),
                    row("/x/b", 10, 2),
                    row("/x/d", 10, 4),
                ],
            )
            .unwrap();
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/c"), h),
                    (PathBuf::from("/x/a"), h),
                    (PathBuf::from("/x/e"), h),
                    (PathBuf::from("/x/b"), h),
                    (PathBuf::from("/x/d"), h),
                ],
            )
            .unwrap();
        // First page (2 files) — a, b.
        let page1 = store.group_files_page(scan_id, &hex, 0, 2).unwrap();
        let paths1: Vec<_> = page1
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths1, vec!["/x/a", "/x/b"]);
        // Second page (offset 2, limit 2) — c, d.
        let page2 = store.group_files_page(scan_id, &hex, 2, 2).unwrap();
        let paths2: Vec<_> = page2
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths2, vec!["/x/c", "/x/d"]);
        // Third page (offset 4, limit 2) — e (tail).
        let page3 = store.group_files_page(scan_id, &hex, 4, 2).unwrap();
        let paths3: Vec<_> = page3
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths3, vec!["/x/e"]);
    }

    #[test]
    fn group_files_page_pages_do_not_overlap() {
        // The guarantee — neighbouring pages do not overlap (via
        // a stable ORDER BY path on the file_hash_path index). Before C1 `group_files_capped`
        // without ORDER BY could return overlapping pages.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        let h = [2u8; 32];
        let hex = crate::model::duplicate::hex_encode(&h);
        let entries: Vec<_> = (0..10)
            .map(|i| (PathBuf::from(format!("/x/{i:02}")), h))
            .collect();
        let rows: Vec<_> = entries
            .iter()
            .enumerate()
            .map(|(i, (p, _))| row(p.to_str().unwrap(), 10, (i + 1) as u64))
            .collect();
        store.record_files(scan_id, &rows).unwrap();
        store.record_hashes(scan_id, &entries).unwrap();
        let page1 = store.group_files_page(scan_id, &hex, 0, 4).unwrap();
        let page2 = store.group_files_page(scan_id, &hex, 4, 4).unwrap();
        let page3 = store.group_files_page(scan_id, &hex, 8, 4).unwrap();
        let all_paths: Vec<_> = page1
            .iter()
            .chain(page2.iter())
            .chain(page3.iter())
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        // 10 unique files; no duplicates between pages.
        let mut uniq = all_paths.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), 10);
        assert_eq!(all_paths.len(), 10);
    }

    #[test]
    fn group_files_count_matches_records() {
        // COUNT on the `file_hash` index (fast at any size).
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        let h = [3u8; 32];
        let hex = crate::model::duplicate::hex_encode(&h);
        store
            .record_files(
                scan_id,
                &[row("/x/a", 10, 1), row("/x/b", 10, 2), row("/x/c", 10, 3)],
            )
            .unwrap();
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/a"), h),
                    (PathBuf::from("/x/b"), h),
                    (PathBuf::from("/x/c"), h),
                ],
            )
            .unwrap();
        assert_eq!(store.group_files_count(scan_id, &hex).unwrap(), 3);
        // Unknown hash → 0.
        let other_hex = crate::model::duplicate::hex_encode(&[99u8; 32]);
        assert_eq!(store.group_files_count(scan_id, &other_hex).unwrap(), 0);
    }

    #[test]
    fn latest_scan_covering_returns_newest_complete_covering_cwd() {
        // Hybrid B — we pick the newest completed scan
        // whose roots cover cwd (or cwd covers one of the roots).
        let mut store = ScanStore::open_in_memory().unwrap();
        // An old completed scan /tank/a.
        let s1 = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        store.set_status(s1, ScanStatus::Complete).unwrap();
        // A fresh completed scan /tank/b — does NOT cover /tank/a.
        let s2 = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/b")]))
            .unwrap();
        store.set_status(s2, ScanStatus::Complete).unwrap();
        // cwd under s1 → we pick s1 (s2 does not cover it).
        let got = store
            .latest_scan_covering(&PathBuf::from("/tank/a/sub"))
            .unwrap();
        assert_eq!(got, Some(s1));
        // cwd under s2 → we pick s2.
        let got = store
            .latest_scan_covering(&PathBuf::from("/tank/b/x"))
            .unwrap();
        assert_eq!(got, Some(s2));
    }

    #[test]
    fn latest_scan_covering_prefers_newer_when_multiple_cover() {
        // When two scans both cover cwd — we take the fresher one (id DESC).
        let mut store = ScanStore::open_in_memory().unwrap();
        let s1 = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        store.set_status(s1, ScanStatus::Complete).unwrap();
        let s2 = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/doc")]))
            .unwrap();
        store.set_status(s2, ScanStatus::Complete).unwrap();
        // /tank/doc/x — both cover it (s1 as an ancestor, s2 as an exact ancestor); s2 is fresher.
        let got = store
            .latest_scan_covering(&PathBuf::from("/tank/doc/x"))
            .unwrap();
        assert_eq!(got, Some(s2));
    }

    #[test]
    fn latest_scan_covering_returns_none_when_uncovered() {
        // No root covers cwd → None. In this case
        // the commander will show "no scan for /cwd · F12 — choose".
        let mut store = ScanStore::open_in_memory().unwrap();
        let s1 = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        store.set_status(s1, ScanStatus::Complete).unwrap();
        assert_eq!(
            store
                .latest_scan_covering(&PathBuf::from("/other/pool"))
                .unwrap(),
            None
        );
    }

    #[test]
    fn latest_scan_covering_skips_non_complete() {
        // Unfinished (walking/hashing/aborted) scans we do NOT take
        // into the overlay — their data is incomplete/garbage.
        let mut store = ScanStore::open_in_memory().unwrap();
        // Fresh, but with status Walking (default after begin_scan).
        let _walking = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        // An old completed one — must be chosen.
        let s_complete = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        store.set_status(s_complete, ScanStatus::Complete).unwrap();
        // A fresh Aborted one.
        let aborted = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        store.set_status(aborted, ScanStatus::Aborted).unwrap();
        let got = store
            .latest_scan_covering(&PathBuf::from("/tank/a/x"))
            .unwrap();
        assert_eq!(got, Some(s_complete));
    }

    #[test]
    fn latest_scan_covering_works_when_cwd_above_root() {
        // Cwd above the scan root (user on /tank, scan only
        // /tank/abc). Inside cwd there is a scanned subdirectory → it counts as
        // coverage (the user will see the overlay on the subfolder).
        let mut store = ScanStore::open_in_memory().unwrap();
        let s1 = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/abc/deep")]))
            .unwrap();
        store.set_status(s1, ScanStatus::Complete).unwrap();
        let got = store.latest_scan_covering(&PathBuf::from("/tank")).unwrap();
        assert_eq!(got, Some(s1));
    }

    #[test]
    fn latest_scan_covering_includes_complete_with_warnings() {
        // A scan completed WITH WARNINGS is a full-fledged
        // completed one: the commander must consider it as covering cwd (SQL `IN`, not `= complete`).
        let mut store = ScanStore::open_in_memory().unwrap();
        let s = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        store
            .set_status(s, ScanStatus::CompleteWithWarnings)
            .unwrap();
        let got = store
            .latest_scan_covering(&PathBuf::from("/tank/a/sub"))
            .unwrap();
        assert_eq!(got, Some(s), "completed-with-warnings covers cwd");
    }

    #[test]
    fn is_path_in_scan_prefix_does_not_match_sibling() {
        // Directory /x/a is covered; /x/ab must not match (the classic
        // LIKE 'x/a%' trap — for us prefix_bounds closes it via `dir/` vs `dir0`).
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(scan_id, &[row("/x/a/file.txt", 10, 1)])
            .unwrap();
        assert!(!store
            .is_path_in_scan(scan_id, &PathBuf::from("/x/ab"))
            .unwrap());
    }

    #[test]
    fn materialize_dir_groups_replaces_existing_rows() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .materialize_dir_groups(scan_id, |emit| {
                emit(PathBuf::from("/x/o1"), "S_old".to_string(), 1, 1)?;
                emit(PathBuf::from("/x/o2"), "S_old".to_string(), 1, 1)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(store.dir_groups(scan_id).unwrap().len(), 1);
        store
            .materialize_dir_groups(scan_id, |emit| {
                emit(PathBuf::from("/x/n1"), "S_new".to_string(), 2, 2)?;
                emit(PathBuf::from("/x/n2"), "S_new".to_string(), 2, 2)?;
                Ok(())
            })
            .unwrap();
        let groups = store.dir_groups(scan_id).unwrap();
        assert_eq!(groups.len(), 1, "old group disappeared");
        assert_eq!(groups[0].signature, "S_new");
    }

    #[test]
    fn materialize_file_groups_equals_record_file_results() {
        // SQL aggregation of file_group is bit-for-bit == the old path
        // (duplicate_groups → sort_groups_by_benefit → record_file_results).
        fn seed(store: &mut ScanStore) -> i64 {
            let scan_id = store
                .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
                .unwrap();
            store
                .record_files(
                    scan_id,
                    &[
                        row("/x/a", 100, 1),
                        row("/x/b", 100, 2),
                        row("/x/c", 100, 3), // group h1: 3×100 → reclaim 200
                        row("/x/d", 50, 4),
                        row("/x/e", 50, 5),  // group h2: 2×50 → reclaim 50
                        row("/x/u", 200, 6), // unique → not a group
                    ],
                )
                .unwrap();
            let (h1, h2, hu) = ([1u8; 32], [2u8; 32], [9u8; 32]);
            store
                .record_hashes(
                    scan_id,
                    &[
                        (PathBuf::from("/x/a"), h1),
                        (PathBuf::from("/x/b"), h1),
                        (PathBuf::from("/x/c"), h1),
                        (PathBuf::from("/x/d"), h2),
                        (PathBuf::from("/x/e"), h2),
                        (PathBuf::from("/x/u"), hu),
                    ],
                )
                .unwrap();
            scan_id
        }

        // Old path.
        let mut old = ScanStore::open_in_memory().unwrap();
        let old_id = seed(&mut old);
        let mut groups = old.duplicate_groups(old_id).unwrap();
        crate::model::duplicate::sort_groups_by_benefit(&mut groups);
        old.record_file_results(old_id, &groups).unwrap();
        let old_sum = old.group_summaries(old_id).unwrap();

        // New path (SQL aggregation).
        let mut new = ScanStore::open_in_memory().unwrap();
        let new_id = seed(&mut new);
        new.materialize_file_groups(new_id).unwrap();
        let new_sum = new.group_summaries(new_id).unwrap();

        assert_eq!(old_sum.len(), new_sum.len(), "number of groups");
        for (o, n) in old_sum.iter().zip(&new_sum) {
            assert_eq!(o.rank, n.rank, "rank");
            assert_eq!(o.hash, n.hash, "hash (value and case)");
            assert_eq!(o.file_count, n.file_count, "file_count");
            assert_eq!(o.size_bytes, n.size_bytes, "size");
            assert_eq!(o.reclaim_bytes, n.reclaim_bytes, "reclaim");
        }
        // Exactly two groups; rank 0 — larger benefit (200), then 50; the unique one is discarded.
        assert_eq!(new_sum.len(), 2);
        assert_eq!(new_sum[0].reclaim_bytes, 200);
        assert_eq!(new_sum[1].reclaim_bytes, 50);
    }

    #[test]
    fn resume_probe_returns_newest_unfinished_and_complete() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let a = store.begin_scan(&cfg).unwrap();
        store.set_status(a, ScanStatus::Complete).unwrap();
        let b = store.begin_scan(&cfg).unwrap();
        store.set_status(b, ScanStatus::Hashing).unwrap(); // unfinished one is newer
        let c = store.begin_scan(&cfg).unwrap();
        store.set_status(c, ScanStatus::Complete).unwrap(); // newest Complete
        let (unfinished, complete) = store
            .resume_probe_for_roots(&[PathBuf::from("/x")])
            .unwrap();
        assert_eq!(unfinished.unwrap().scan_id, b, "newest unfinished");
        assert_eq!(complete.unwrap().scan_id, c, "newest completed");
        let (u2, c2) = store
            .resume_probe_for_roots(&[PathBuf::from("/y")])
            .unwrap();
        assert!(u2.is_none() && c2.is_none(), "no other roots");
    }

    #[test]
    fn resume_probe_buckets_complete_with_warnings_as_complete() {
        // CompleteWithWarnings lands in the probe's "complete" bucket, NOT in
        // "unfinished" — otherwise F2 would offer to resume an already finished scan.
        let mut store = ScanStore::open_in_memory().unwrap();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let a = store.begin_scan(&cfg).unwrap();
        store
            .set_status(a, ScanStatus::CompleteWithWarnings)
            .unwrap();
        let (unfinished, complete) = store
            .resume_probe_for_roots(&[PathBuf::from("/x")])
            .unwrap();
        assert!(
            unfinished.is_none(),
            "completed-with-warnings is not resumable"
        );
        assert_eq!(
            complete.unwrap().scan_id,
            a,
            "landed in the complete bucket"
        );
    }

    /// The materialized result is read with the same composition, while the marks
    /// (keeper/action) are pulled in FRESH from file_mark (LEFT JOIN), not from the snapshot.
    #[test]
    fn file_results_roundtrip_with_fresh_marks() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(id, &[row("/a", 100, 1), row("/b", 100, 2)])
            .unwrap();
        let h = [5u8; 32];
        store
            .record_hashes(id, &[(PathBuf::from("/a"), h), (PathBuf::from("/b"), h)])
            .unwrap();
        let groups = store.duplicate_groups(id).unwrap();
        assert_eq!(groups.len(), 1);
        store.record_file_results(id, &groups).unwrap();

        // The summary is materialized; group members are read from the `file` manifest by hash.
        let summaries = store.group_summaries(id).unwrap();
        assert_eq!(summaries.len(), 1, "one materialized group summary");
        assert_eq!(summaries[0].file_count, 2);
        let files = store.group_files(id, &summaries[0].hash).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| !f.is_keeper), "no marks yet");

        // Set a keeper mark and make sure group_files pulled it in fresh.
        let mut marked = files.clone();
        marked[0].is_keeper = true;
        store.save_marks(id, marked.iter()).unwrap();
        let reloaded = store.group_files(id, &summaries[0].hash).unwrap();
        assert!(
            reloaded.iter().any(|f| f.is_keeper),
            "keeper mark pulled in fresh from file_mark"
        );
    }

    /// A scan completed BEFORE materialization is counted once
    /// (`ensure_materialized`) and cached in `file_group` — afterwards opening reads
    /// the lightweight summaries instead of recomputing.
    #[test]
    fn ensure_materialized_falls_back_then_caches() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(id, &[row("/a", 100, 1), row("/b", 100, 2)])
            .unwrap();
        let h = [5u8; 32];
        store
            .record_hashes(id, &[(PathBuf::from("/a"), h), (PathBuf::from("/b"), h)])
            .unwrap();
        store.set_status(id, ScanStatus::Complete).unwrap();

        assert!(
            store.group_summaries(id).unwrap().is_empty(),
            "no materialization yet"
        );
        store.ensure_materialized(id).unwrap();
        assert_eq!(
            store.group_summaries(id).unwrap().len(),
            1,
            "computed and cached in file_group"
        );
    }

    /// Candidate progress surfaces in list_scans cheaply, without COUNT(*).
    #[test]
    fn candidate_progress_surfaces_in_list_scans() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .update_candidate_progress(id, 10, 1000, 4, 400)
            .unwrap();
        let scans = store.list_scans().unwrap();
        let info = scans.iter().find(|s| s.scan_id == id).unwrap();
        assert_eq!(info.files_total, 10);
        assert_eq!(info.files_hashed, 4);
        assert_eq!(info.cand_bytes_total, 1000);
        assert_eq!(info.cand_bytes_hashed, 400);
    }

    /// Trash hides from the active list and shows in the trash bin; restore reverses it.
    #[test]
    fn trash_then_restore_roundtrip() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store.trash_scan(id).unwrap();
        assert!(
            store.list_scans().unwrap().iter().all(|s| s.scan_id != id),
            "in the trash bin — absent from the active list"
        );
        assert!(
            store
                .list_trashed()
                .unwrap()
                .iter()
                .any(|s| s.scan_id == id),
            "visible in the trash bin"
        );
        store.restore_scan(id).unwrap();
        assert!(
            store.list_scans().unwrap().iter().any(|s| s.scan_id == id),
            "restored to the active list"
        );
        assert!(
            store
                .list_trashed()
                .unwrap()
                .iter()
                .all(|s| s.scan_id != id),
            "after restore, absent from the trash bin"
        );
    }

    /// Purge clears ALL scan_id tables (no orphans), but does not touch the shared
    /// hash_cache (keyed by device,inode).
    #[test]
    fn purge_removes_all_scan_tables_but_keeps_hash_cache() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(id, &[row("/a", 100, 1), row("/b", 100, 2)])
            .unwrap();
        let h = [5u8; 32];
        store
            .record_hashes(id, &[(PathBuf::from("/a"), h), (PathBuf::from("/b"), h)])
            .unwrap();
        let groups = store.duplicate_groups(id).unwrap();
        store.record_file_results(id, &groups).unwrap();
        store
            .record_dir_groups(
                id,
                &[DirGroup {
                    id: 0,
                    signature: "s".to_string(),
                    paths: vec![PathBuf::from("/x/a")],
                    file_count: 1,
                    size_per_dir: 10,
                }],
            )
            .unwrap();
        store.upsert_hash(1, 2, 100, 5, &h).unwrap();

        store.purge_scan(id).unwrap();

        assert!(
            store.group_summaries(id).unwrap().is_empty(),
            "file_group cleared"
        );
        assert!(
            store.dir_groups(id).unwrap().is_empty(),
            "dir_dedup cleared"
        );
        assert_eq!(store.manifest_count(id).unwrap(), 0, "file cleared");
        assert!(
            store.list_scans().unwrap().iter().all(|s| s.scan_id != id),
            "scan deleted"
        );
        // Hash_cache is disabled as a source — even a saved record is not
        // returned (purge clears scans; the cache is not reused anyway).
        assert_eq!(store.hash_by_identity(1, 2, 100, 5).unwrap(), None);
    }

    /// Retention keeps the newest `keep` completed scans of the same roots
    /// (including the one just completed) and sends the rest + the unfinished ones to the trash bin.
    #[test]
    fn retention_trashes_old_completes_and_unfinished() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let c1 = store.begin_scan(&cfg).unwrap();
        store.set_status(c1, ScanStatus::Complete).unwrap();
        let u = store.begin_scan(&cfg).unwrap();
        store.set_status(u, ScanStatus::Hashing).unwrap();
        let c2 = store.begin_scan(&cfg).unwrap();
        store.set_status(c2, ScanStatus::Complete).unwrap();
        let c3 = store.begin_scan(&cfg).unwrap();
        store.set_status(c3, ScanStatus::Complete).unwrap();

        // Fresh Complete = c3. keep=2 → c3+c2 are active; c1 (old Complete) and u → trash bin.
        assert_eq!(
            store
                .apply_retention(&[PathBuf::from("/x")], 2, c3)
                .unwrap(),
            2
        );
        let active: Vec<i64> = store
            .list_scans()
            .unwrap()
            .iter()
            .map(|s| s.scan_id)
            .collect();
        assert!(active.contains(&c3) && active.contains(&c2));
        assert!(!active.contains(&c1) && !active.contains(&u));
        let trashed: Vec<i64> = store
            .list_trashed()
            .unwrap()
            .iter()
            .map(|s| s.scan_id)
            .collect();
        assert!(trashed.contains(&c1) && trashed.contains(&u));
    }

    #[test]
    fn retention_counts_complete_with_warnings_as_complete() {
        // CompleteWithWarnings is counted by retention as a full-fledged Complete
        // (included in keep, trimmed beyond it) — not confused with an interrupted/unfinished one.
        let mut store = ScanStore::open_in_memory().unwrap();
        let cfg = ScanConfig::new(vec![PathBuf::from("/x")]);
        let c1 = store.begin_scan(&cfg).unwrap();
        store
            .set_status(c1, ScanStatus::CompleteWithWarnings)
            .unwrap();
        let c2 = store.begin_scan(&cfg).unwrap();
        store.set_status(c2, ScanStatus::Complete).unwrap();
        // Fresh = c2, keep=1 → c2 is active; c1 (old completed-with-warnings) → trash bin.
        assert_eq!(
            store
                .apply_retention(&[PathBuf::from("/x")], 1, c2)
                .unwrap(),
            1
        );
        let active: Vec<i64> = store
            .list_scans()
            .unwrap()
            .iter()
            .map(|s| s.scan_id)
            .collect();
        assert!(
            active.contains(&c2) && !active.contains(&c1),
            "c1 (complete_with_warnings) trimmed like an ordinary Complete"
        );
    }

    #[test]
    fn scan_result_roundtrip_carries_hash_failures() {
        // The scan_stats.hash_failures column passes write→read.
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        // Fresh scan_stats (from begin_scan) — hash_failures is 0 by default (column DEFAULT).
        assert_eq!(
            store.scan_summary(id).unwrap().hash_failures,
            0,
            "hash_failures=0 by default for a new scan"
        );

        // In production always writes 0; but the store layer MUST HONESTLY carry the value write→read
        // (otherwise the real count from would be silently lost) — we check with a NON-zero value to catch
        // a lost/shifted column. 0→0 would pass even with a hardcoded 0.
        let summary = ScanSummary {
            files_scanned: 10,
            groups_found: 2,
            total_reclaimable_bytes: 4096,
            bytes_hashed: 8192,
            elapsed_seconds: 1.5,
            hash_failures: 3,
        };
        store.record_scan_result(id, &summary).unwrap();

        // scan_summary (opening the result) sees the same value; the other columns
        // did not shift across the SELECT indexes.
        let got = store.scan_summary(id).unwrap();
        assert_eq!(
            got.hash_failures, 3,
            "hash_failures passes the roundtrip through scan_summary"
        );
        assert_eq!(
            got.files_scanned, 10,
            "columns did not shift across the SELECT indexes"
        );
        assert_eq!(got.total_reclaimable_bytes, 4096);

        // list_stats (--stats) also returns the column.
        let stats = store.list_stats().unwrap();
        let row = stats
            .iter()
            .find(|r| r.scan_id == id)
            .expect("scan in the statistics list");
        assert_eq!(
            row.hash_failures, 3,
            "hash_failures is read in list_stats too"
        );
    }

    // --- db-backed UI ---

    /// ManifestRow with arbitrary mtime/device/inode (for the semaphore branches).
    fn mrow_dev(path: &str, size: u64, mtime: i64, device: u64, inode: u64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size,
            mtime,
            device,
            inode,
            ..Default::default()
        }
    }

    /// A mark for save_marks (uses only path/is_keeper/action).
    fn mark_fe(path: &str, keeper: bool, action: Option<ActionKind>) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size: 0,
            mtime: 0,
            device: 0,
            inode: 0,
            is_keeper: keeper,
            action,
        }
    }

    fn temp_state_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("dedcom_store_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn open_sets_db_and_sidecars_0600() {
        // The DB file and WAL/SHM — 0600 (contents = paths of all files in the pool).
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_state_dir("mode");
        let db = dir.join("dedcom.db");
        let _store = ScanStore::open(&db).unwrap();
        let mode = std::fs::metadata(&db).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the DB file must be 0600");
        for suffix in ["-wal", "-shm"] {
            let mut p = db.clone().into_os_string();
            p.push(suffix);
            let p = PathBuf::from(p);
            if let Ok(meta) = std::fs::metadata(&p) {
                assert_eq!(
                    meta.permissions().mode() & 0o777,
                    0o600,
                    "{} must be 0600",
                    p.display()
                );
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_rejects_symlinked_db() {
        // Opening via a symlink would write the target outside the state-dir — refused (O_NOFOLLOW).
        let dir = temp_state_dir("symlink");
        let real = dir.join("real-target.db");
        std::fs::File::create(&real).unwrap();
        let db = dir.join("dedcom.db");
        std::os::unix::fs::symlink(&real, &db).unwrap();
        assert!(
            ScanStore::open(&db).is_err(),
            "a symlink at the DB file must be rejected"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Group summaries are read in "by benefit" order with correct fields.
    #[test]
    fn group_summaries_roundtrip() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        // A: 3×100 (reclaim 200); B: 2×50 (reclaim 50).
        store
            .record_files(
                id,
                &[
                    row("/a1", 100, 1),
                    row("/a2", 100, 2),
                    row("/a3", 100, 3),
                    row("/b1", 50, 4),
                    row("/b2", 50, 5),
                ],
            )
            .unwrap();
        let (ha, hb) = ([1u8; 32], [2u8; 32]);
        store
            .record_hashes(
                id,
                &[
                    (PathBuf::from("/a1"), ha),
                    (PathBuf::from("/a2"), ha),
                    (PathBuf::from("/a3"), ha),
                    (PathBuf::from("/b1"), hb),
                    (PathBuf::from("/b2"), hb),
                ],
            )
            .unwrap();
        let groups = store.duplicate_groups(id).unwrap();
        store.record_file_results(id, &groups).unwrap();

        let summaries = store.group_summaries(id).unwrap();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].rank, 0, "newest by benefit — rank 0");
        assert_eq!(summaries[0].file_count, 3);
        assert_eq!(summaries[0].size_bytes, 100);
        assert_eq!(summaries[0].reclaim_bytes, 200);
        assert_eq!(summaries[1].rank, 1);
        assert_eq!(summaries[1].reclaim_bytes, 50);
    }

    /// group_files reads members from the `file` manifest, and NOT from file_dedup (which
    /// is no longer written) — the table is empty, but the group members are returned.
    #[test]
    fn group_files_reads_from_manifest_not_file_dedup() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(id, &[row("/a", 100, 1), row("/b", 100, 2)])
            .unwrap();
        let h = [9u8; 32];
        store
            .record_hashes(id, &[(PathBuf::from("/a"), h), (PathBuf::from("/b"), h)])
            .unwrap();
        let groups = store.duplicate_groups(id).unwrap();
        store.record_file_results(id, &groups).unwrap();

        let dedup_rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM file_dedup WHERE scan_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dedup_rows, 0, "file_dedup is not written");

        let files = store.group_files(id, &hex_encode(&h)).unwrap();
        assert_eq!(files.len(), 2, "group members taken from the file manifest");
    }

    /// dir_dedup_status + classify yield each of the 6 semaphore branches; a path outside the scan
    /// does not land in the map (the caller treats it as NotInScan).
    #[test]
    fn dir_dedup_status_each_variant() {
        use crate::tui::commander::dedup::DedupStatus;
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                id,
                &[
                    mrow_dev("/uniq", 10, 0, 1, 1),
                    mrow_dev("/dupA", 20, 0, 1, 2),
                    mrow_dev("/dupB", 20, 0, 1, 3),
                    mrow_dev("/xdevA", 30, 0, 1, 4),
                    mrow_dev("/xdevB", 30, 0, 2, 5),
                    mrow_dev("/raw", 40, 0, 1, 6),
                    mrow_dev("/likeA", 50, 7, 1, 7),
                    mrow_dev("/likeB", 50, 7, 1, 8),
                ],
            )
            .unwrap();
        store
            .record_hashes(
                id,
                &[
                    (PathBuf::from("/uniq"), [1u8; 32]),
                    (PathBuf::from("/dupA"), [2u8; 32]),
                    (PathBuf::from("/dupB"), [2u8; 32]),
                    (PathBuf::from("/xdevA"), [3u8; 32]),
                    (PathBuf::from("/xdevB"), [3u8; 32]),
                ],
            )
            .unwrap();
        let paths: Vec<PathBuf> = ["/uniq", "/dupA", "/xdevA", "/raw", "/likeA"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let rows = store.dir_dedup_status(id, &paths).unwrap();
        let st = |p: &str| DedupStatus::classify(&rows[&PathBuf::from(p)]);
        assert_eq!(st("/uniq"), DedupStatus::HashedUnique);
        assert_eq!(st("/dupA"), DedupStatus::VerifiedDup);
        assert_eq!(st("/xdevA"), DedupStatus::DangerousDup);
        assert_eq!(st("/raw"), DedupStatus::Unhashed);
        assert_eq!(st("/likeA"), DedupStatus::LikelyDuplicate);
        let none = store
            .dir_dedup_status(id, &[PathBuf::from("/nope")])
            .unwrap();
        assert!(!none.contains_key(&PathBuf::from("/nope")), "NotInScan");
    }

    /// dir_sizes_under sums strictly descendants; a neighbour with the same prefix
    /// (`/x` vs `/x2`) does NOT land in (prefix range by PK, not LIKE%).
    #[test]
    fn dir_sizes_under_prefix_no_false_match() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/")]))
            .unwrap();
        store
            .record_files(
                id,
                &[
                    row("/x/a", 100, 1),
                    row("/x/b", 200, 2),
                    row("/x2/c", 999, 3),
                ],
            )
            .unwrap();
        let sizes = store.dir_sizes_under(id, &[PathBuf::from("/x")]).unwrap();
        assert_eq!(
            sizes.get(&PathBuf::from("/x")),
            Some(&300),
            "only /x/a+/x/b, without the neighbouring /x2/c"
        );
    }

    /// planned_action_rows skips groups without an action and without a keeper (fail-safe).
    #[test]
    fn planned_action_rows_skips_actionless_and_keeperless() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                id,
                &[
                    row("/a1", 10, 1),
                    row("/a2", 10, 2),
                    row("/b1", 20, 3),
                    row("/b2", 20, 4),
                    row("/c1", 30, 5),
                    row("/c2", 30, 6),
                ],
            )
            .unwrap();
        store
            .record_hashes(
                id,
                &[
                    (PathBuf::from("/a1"), [1u8; 32]),
                    (PathBuf::from("/a2"), [1u8; 32]),
                    (PathBuf::from("/b1"), [2u8; 32]),
                    (PathBuf::from("/b2"), [2u8; 32]),
                    (PathBuf::from("/c1"), [3u8; 32]),
                    (PathBuf::from("/c2"), [3u8; 32]),
                ],
            )
            .unwrap();
        store
            .save_marks(
                id,
                [
                    mark_fe("/a1", true, None),                      // A: keeper
                    mark_fe("/a2", false, Some(ActionKind::Delete)), // A: target
                    mark_fe("/b1", true, None),                      // B: keeper only
                    mark_fe("/c2", false, Some(ActionKind::Delete)), // C: delete without keeper
                ]
                .iter(),
            )
            .unwrap();

        let rows = store.planned_action_rows(id).unwrap();
        assert_eq!(rows.len(), 1, "only group A with keeper+action");
        assert_eq!(rows[0].target, PathBuf::from("/a2"));
        assert_eq!(rows[0].keeper, PathBuf::from("/a1"));
    }
}
