// SPDX-License-Identifier: Apache-2.0
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rusqlite::types::Value;
use rusqlite::{params, Connection, OpenFlags, Transaction};

use crate::error::{AppError, Result};
use crate::model::action::{ActionKind, MoveEvent};
use crate::model::duplicate::{
    build_dir_signatures_streaming, hex_encode, signature_of, DirGroup, DirSigAlgo, DuplicateGroup,
    FileEntry,
};
use crate::model::omission::{
    AuthorityUnavailable, DirCompleteness, EventCount, OmissionCounts, OmissionReason,
    OmissionSummary, PathKey, RootRegistration,
};
use crate::model::plan::{
    ActionPlan, MarkIntent, PlanGroupInput, PlanMemberEvidence, PlanObjectKey, PlanRefusal,
    PlanResult, RequestedMark,
};
use crate::model::reclaim::{
    DestructivePlanVerdict, GroupReclaim, LinkCount, ReclaimEstimate, ReclaimState,
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
    /// `st_nlink` observed by the walk; `0` = unknown (a legacy pre-v3 row, since a real link
    /// count is at least 1). How many of those links this scan actually saw is a separate
    /// question, answered by the manifest rows sharing `(device, inode)`.
    pub nlink: u64,
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
    /// Path rows that gained a digest: the committed representatives plus every alias the same
    /// checkpoint propagated to. Pathname completion advances by this.
    pub files: u64,
    /// Bytes actually read — the size of each committed representative, so one allocation counts
    /// once however many pathnames point at it. Aliases add nothing here.
    pub bytes: u64,
    /// Representatives whose conditional update committed. Always `<=` the batch size, which is
    /// what the hash-failure counter subtracts from; `files` can exceed the batch and must not.
    pub representatives: u64,
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
    /// Pathnames in the group — what the operator sees, never a link count.
    pub file_count: u64,
    /// Size of a single file in the group.
    pub size_bytes: u64,
    /// Distinct physical allocations behind `file_count` pathnames. `0` = a migrated pre-v3 row.
    pub object_count: u64,
    /// What the group is worth and how far that is trusted. Reclaim is a property of the
    /// allocations, so it never follows from `file_count`.
    pub reclaim: ReclaimEstimate,
}

/// What a materialized group says about itself, for the views that show one group at a time.
///
/// Read from the group's own row plus a lookup over its manifest rows — never recomputed from the
/// files currently on screen, because the browser pages a large group and a page is not the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupClaim {
    /// What the group is worth, and how far that is trusted.
    pub reclaim: ReclaimEstimate,
    /// Pathnames seen against links reported — the evidence behind the state.
    pub links: GroupLinks,
}

/// How many of an allocation's links a group actually observed.
///
/// The pair only makes sense together: `observed` counts pathnames this scan holds, `total` counts
/// the links the inodes report. Equal means the group is self-contained; `total` larger means
/// something outside the scan still holds those bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupLinks {
    /// Pathnames of the group.
    pub observed: u64,
    /// One validated link count per distinct allocation, summed.
    pub total: LinkCount,
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

/// Checkpoint store: a SQLite DB with the scan state and the file manifest.
pub struct ScanStore {
    conn: Connection,
    /// Test-only: how many set-based digest-propagation statements this store has issued. The
    /// hashing phase must spend one per batch, never one per alias, and a counter on the store
    /// itself proves that without a dependency, rusqlite tracing, or a timing measurement. Per
    /// instance rather than global, so parallel tests cannot pollute each other.
    #[cfg(test)]
    propagations: std::cell::Cell<u64>,
}

/// Process role. `false` — operator (may write), `true` — observer.
///
/// Held here, next to the only place that opens the DB, on purpose. The read-only guarantee has
/// to hold for every one of the ~25 places that open a store — including ones added later — so
/// it cannot be a checklist at the call sites; that is exactly the failure this replaces.
static OBSERVER_ROLE: AtomicBool = AtomicBool::new(false);

/// Declares the process an observer (or an operator again). Called once from the startup role
/// decision, and again if the user takes the operator role in the concurrency overlay.
pub fn set_observer_role(observer: bool) {
    OBSERVER_ROLE.store(observer, Ordering::SeqCst);
}

/// Whether this process is an observer and must not write to the DB.
pub fn is_observer_role() -> bool {
    OBSERVER_ROLE.load(Ordering::SeqCst)
}

/// Serialises everything that touches the process role or a file-backed store. The role is
/// process-wide by design, so a test that flips it would otherwise hand a read-only connection to
/// a test running in parallel. Lives here rather than in the test module because the callers that
/// open a store go well beyond this file.
#[cfg(test)]
pub(crate) fn role_guard() -> std::sync::MutexGuard<'static, ()> {
    static ROLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A panicking test poisons the lock; that must not cascade into unrelated failures.
    ROLE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The pathnames of `scan_id` still marked for an action, in path order.
///
/// The plan itself is built from real files on disk, so a test about what SURVIVES in the database
/// after a batch asks the database, not the planner.
#[cfg(test)]
pub(crate) fn marked_action_paths(db: &Path, scan_id: i64) -> Vec<PathBuf> {
    let store = ScanStore::open(db).unwrap();
    let mut stmt = store
        .conn
        .prepare(
            "SELECT path FROM file_mark
              WHERE scan_id = ?1 AND is_keeper = 0 AND action IS NOT NULL
              ORDER BY path",
        )
        .unwrap();
    let rows = stmt
        .query_map(params![scan_id], |row| row.get::<_, String>(0))
        .unwrap();
    rows.map(|row| PathBuf::from(row.unwrap())).collect()
}

/// Seeds `db` with one duplicate group — keeper `/x/a`, targets `/x/b` and `/x/c`, all marked —
/// and returns the scan id. Shared with the app-level tests: marks outlive the process, so
/// settling them after a batch has to be checked against a real file rather than a map in RAM.
#[cfg(test)]
pub(crate) fn seed_marked_group(db: &Path) -> i64 {
    use crate::model::action::ActionKind;
    use crate::model::duplicate::FileEntry;

    let mut store = ScanStore::open_writable(db).unwrap();
    let scan_id = store
        .begin_scan(&crate::model::scan::ScanConfig::new(vec![PathBuf::from(
            "/x",
        )]))
        .unwrap();
    let file = |path: &str, inode: u64| ManifestRow {
        path: PathBuf::from(path),
        size: 10,
        inode,
        device: 1,
        ..Default::default()
    };
    store
        .record_files(
            scan_id,
            &[file("/x/a", 1), file("/x/b", 2), file("/x/c", 3)],
        )
        .unwrap();
    store
        .record_hashes(
            scan_id,
            &[
                (PathBuf::from("/x/a"), [7u8; 32]),
                (PathBuf::from("/x/b"), [7u8; 32]),
                (PathBuf::from("/x/c"), [7u8; 32]),
            ],
        )
        .unwrap();
    let mark = |path: &str, keeper: bool, action: Option<ActionKind>| FileEntry {
        path: PathBuf::from(path),
        size: 10,
        device: 1,
        is_keeper: keeper,
        action,
        ..Default::default()
    };
    store
        .save_marks(
            scan_id,
            [
                mark("/x/a", true, None),
                mark("/x/b", false, Some(ActionKind::Delete)),
                mark("/x/c", false, Some(ActionKind::Delete)),
            ]
            .iter(),
        )
        .unwrap();
    scan_id
}

/// The scan-local temporal physical identity of a manifest row — the columns that decide whether
/// two pathnames are the same allocation *right now*. Bare `(device, inode)` is deliberately not
/// enough: an inode number is reused after a delete, and a same-second in-place edit would
/// otherwise look unchanged. Used as a `GROUP BY` list and as a join key; nothing here is ever
/// concatenated into a text key.
const OBJECT_KEY: &str = "device, inode, size, mtime, mtime_nsec, ctime_sec, ctime_nsec";

/// Sizes worth hashing: a size qualifies only when at least TWO DISTINCT physical objects share
/// it. Counting path rows instead is the P-1 defect — four aliases of one allocation are one copy,
/// not four, and reading them looks like four duplicates that would free three files.
///
/// The inner `GROUP BY` collapses the aliases of one object into a single row; the outer one
/// counts those objects per size.
fn eligible_sizes_sql() -> String {
    format!(
        "SELECT size FROM (
             SELECT size FROM file WHERE scan_id = ?1 GROUP BY {OBJECT_KEY}
         ) GROUP BY size HAVING COUNT(*) >= 2"
    )
}

/// Propagates a trusted digest to every hash-null pathname of the same current-scan object.
///
/// Set-based on purpose: one statement per checkpoint, not one per alias. The source must be
/// `identity_version = 1` — only an fd-verified or inherited-from-fd-verified digest — and the
/// target must match the source's complete temporal identity, so linking, unlinking or replacing
/// any alias changes the inode ctime and disqualifies the whole stale object. `hash IS NULL`
/// guarantees no existing digest is ever overwritten.
///
/// `LIMIT 1` is only safe because `conflicting_digest_objects` has already refused any object
/// carrying more than one distinct trusted digest, so there is nothing to choose between.
fn propagate_sql() -> String {
    let matches_source = "src.scan_id = file.scan_id
                  AND src.device = file.device AND src.inode = file.inode
                  AND src.size = file.size AND src.mtime = file.mtime
                  AND src.mtime_nsec = file.mtime_nsec
                  AND src.ctime_sec = file.ctime_sec AND src.ctime_nsec = file.ctime_nsec
                  AND src.identity_version = 1 AND src.hash IS NOT NULL";
    format!(
        "UPDATE file
            SET hash = (SELECT src.hash FROM file AS src WHERE {matches_source} LIMIT 1),
                identity_version = 1
          WHERE scan_id = ?1 AND hash IS NULL
            AND EXISTS (SELECT 1 FROM file AS src WHERE {matches_source})"
    )
}

/// The four candidate totals off ONE object relation and ONE eligibility relation.
///
/// `objects` collapses the manifest to one row per scan-local temporal physical object, carrying
/// how many pathnames it has and how many of them already hold a digest. `eligible` then counts
/// those objects per size. Everything the phase reports is a `SUM` over the join of the two, so the
/// expensive grouping happens once rather than once per reported number.
///
/// `MATERIALIZED` is explicit: `objects` is referenced twice, and without it SQLite is free to
/// inline the definition into both references, which is precisely the repetition being removed.
fn candidate_stats_sql() -> String {
    format!(
        "WITH objects AS MATERIALIZED (
             SELECT {OBJECT_KEY}, COUNT(*) AS paths, COUNT(hash) AS hashed_paths
               FROM file WHERE scan_id = ?1
              GROUP BY {OBJECT_KEY}
         ),
         eligible AS (
             SELECT size FROM objects GROUP BY size HAVING COUNT(*) >= 2
         )
         SELECT
             COALESCE(SUM(objects.paths), 0),
             COALESCE(SUM(objects.size), 0),
             COALESCE(SUM(objects.hashed_paths), 0),
             COALESCE(SUM(CASE WHEN objects.hashed_paths > 0 THEN objects.size ELSE 0 END), 0)
           FROM objects JOIN eligible ON eligible.size = objects.size"
    )
}

/// One row per (digest, physical object): how many of the object's pathnames carry that digest,
/// and the link-count evidence for the object as a whole.
///
/// This is the relation every result number comes off — group membership, pathname count, object
/// count, link totals and state all read the same grouping, so no two of them can disagree. The
/// object key is the complete temporal identity, spelled by `OBJECT_KEY` and never concatenated.
///
/// `observed` counts the object's pathnames *inside the group*, not inside the scan. That is the
/// conservative reading and the correct one: a pathname whose digest never landed is not a
/// pathname the result can act on, so counting it as observed would let a group promise to free an
/// allocation while one of its links stays behind.
fn group_objects_sql() -> String {
    format!(
        "SELECT hash AS digest, {OBJECT_KEY},
                COUNT(*)                AS observed,
                MIN(nlink)              AS nlink,
                COUNT(DISTINCT nlink)   AS nlink_distinct,
                MIN(typeof(nlink))      AS nlink_min_class,
                MAX(typeof(nlink))      AS nlink_max_class,
                MIN(path)               AS named
           FROM file
          WHERE scan_id = ?1 AND hash IS NOT NULL
          GROUP BY hash, {OBJECT_KEY}"
    )
}

/// The duplicate-content groups of a scan, off the object relation above.
///
/// `HAVING COUNT(*) >= 2` counts OBJECTS, not pathnames: a set of aliases is one allocation and
/// therefore not a duplicate of anything. Membership, the ceiling and the state are decided here,
/// once, and both the preflight and the materialization read this same definition so they cannot
/// drift apart.
///
/// The state expression is the checkpoint's rule in SQL: one unrecorded link count makes the group
/// unknown, one partially observed allocation makes it an upper bound, and only an all-observed
/// group is exact. It may read `nlink` as a number because `refuse_untrustworthy_group_objects`
/// has already refused, in this same transaction, every row whose storage class or value would
/// make that comparison meaningless.
fn group_rows_sql() -> String {
    format!(
        "WITH objects AS MATERIALIZED ({objects}),
              groups AS (
                  SELECT digest,
                         SUM(observed)              AS file_count,
                         MIN(size)                  AS size,
                         COUNT(*)                   AS object_count,
                         MIN(size) * (COUNT(*) - 1) AS ceiling,
                         CASE WHEN MIN(CASE WHEN nlink > 0 THEN 1 ELSE 0 END) = 0 THEN 0
                              WHEN MAX(CASE WHEN observed < nlink THEN 1 ELSE 0 END) = 1 THEN 2
                              ELSE 1
                         END                        AS state
                    FROM objects
                   GROUP BY digest
                  HAVING COUNT(*) >= 2
              )",
        objects = group_objects_sql()
    )
}

/// The cross-scan reuse key: the SAME pathname carrying the SAME full temporal identity in a
/// different scan, with an fd-verified digest. `device`/`inode` are deliberately absent — ZFS
/// changes both after an import or reboot, and a key that included them would re-read the pool
/// every time. `cur` is the current row, `prev` the candidate source.
const CROSS_SCAN_SOURCE: &str = "prev.path = cur.path AND prev.size = cur.size
                   AND prev.mtime = cur.mtime AND prev.mtime_nsec = cur.mtime_nsec
                   AND prev.ctime_sec = cur.ctime_sec AND prev.ctime_nsec = cur.ctime_nsec
                   AND prev.identity_version = 1 AND prev.hash IS NOT NULL
                   AND prev.scan_id <> cur.scan_id";

/// Inherits a past digest for every still-null pathname that has one. `MIN` rather than `LIMIT 1`:
/// a deterministic aggregate, and legitimate only after the caller's preflight has proved in the
/// same transaction that every eligible source carries one and the same digest.
fn inherit_sql() -> String {
    format!(
        "UPDATE file AS cur
            SET hash = (SELECT MIN(prev.hash) FROM file AS prev WHERE {CROSS_SCAN_SOURCE}),
                identity_version = 1
          WHERE cur.scan_id = ?1 AND cur.hash IS NULL
            AND EXISTS (SELECT 1 FROM file AS prev WHERE {CROSS_SCAN_SOURCE})"
    )
}

/// Current-scan physical objects for which the checkpoint offers more than one distinct digest.
///
/// The evidence is the union of two things, per object: the digests this scan already trusts, and
/// every trusted past digest offered to any of the object's still-null pathnames. `UNION` (not
/// `UNION ALL`) collapses repeats, so several past rows carrying the same digest are agreement.
/// This catches both shapes of the defect — two past scans disagreeing about one pathname, and two
/// aliases of one object each matching a different past digest.
fn conflicting_inheritance_objects(conn: &Connection, scan_id: i64) -> Result<u64> {
    let object_columns = "cur.device AS device, cur.inode AS inode, cur.size AS size,
                          cur.mtime AS mtime, cur.mtime_nsec AS mtime_nsec,
                          cur.ctime_sec AS ctime_sec, cur.ctime_nsec AS ctime_nsec";
    let count: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM (
                 SELECT 1 FROM (
                     SELECT {object_columns}, cur.hash AS hash
                       FROM file AS cur
                      WHERE cur.scan_id = ?1 AND cur.hash IS NOT NULL
                        AND cur.identity_version = 1
                     UNION
                     SELECT {object_columns}, prev.hash AS hash
                       FROM file AS cur JOIN file AS prev ON {CROSS_SCAN_SOURCE}
                      WHERE cur.scan_id = ?1 AND cur.hash IS NULL
                 )
                 GROUP BY {OBJECT_KEY}
                HAVING COUNT(DISTINCT hash) > 1)"
        ),
        params![scan_id],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

/// Objects whose aliases hold more than one distinct trusted digest. Only `identity_version = 1`
/// rows count: a legacy or move-path digest is never a propagation source, so disagreeing with one
/// is not a conflict.
fn conflicting_digest_objects(conn: &Connection, scan_id: i64) -> Result<u64> {
    let count: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM (
                 SELECT 1 FROM file
                  WHERE scan_id = ?1 AND hash IS NOT NULL AND identity_version = 1
                  GROUP BY {OBJECT_KEY}
                 HAVING COUNT(DISTINCT hash) > 1)"
        ),
        params![scan_id],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

/// What one physical object's aliases collectively say about their link count.
///
/// Grouping is a place a corrupt cell can hide. `MIN(nlink)` over `(integer 1, text 'oops')`
/// returns the integer, because SQLite sorts numbers below text — the aggregate would quietly
/// elect the one valid alias and the C2a/C2a1 gate would never see the broken one. So the group is
/// judged as a whole, before any value is trusted: which storage classes it contains, and whether
/// its rows agree.
struct GroupedLinkCount {
    /// `MIN(nlink)`. Meaningful only once the class and agreement checks have passed.
    value: Value,
    /// `COUNT(DISTINCT nlink)` — more than one means the aliases disagree.
    distinct: i64,
    /// `MIN(typeof(nlink))` and `MAX(typeof(nlink))`. Equal iff the group holds a single storage
    /// class; unlike `MIN(nlink)`, `typeof` of a NULL cell is the ordinary string `'null'`, so a
    /// NULL cannot slip past by being skipped the way aggregates skip it.
    min_class: String,
    max_class: String,
}

impl GroupedLinkCount {
    fn decode(&self, representative: &Path) -> Result<LinkCount> {
        let named = crate::textsan::terminal(&representative.display().to_string());
        if self.min_class != self.max_class {
            return Err(AppError::msg(format!(
                "dedcom.db holds link counts of two different types ({} and {}) for the one allocation behind {named}. Rescan, or move the old dedcom.db aside.",
                self.min_class, self.max_class
            )));
        }
        if self.distinct > 1 {
            return Err(AppError::msg(format!(
                "dedcom.db holds {} different link counts for the one allocation behind {named}; its pathnames are the same inode and cannot disagree. Rescan, or move the old dedcom.db aside.",
                self.distinct
            )));
        }
        // One storage class, one value: the shared checked decoder now sees exactly what every
        // alias of this object holds — including a non-integer class the whole group shares.
        link_count_from_sql(&self.value)
    }
}

/// Refuses to publish results whose allocations cannot be measured, before a single row is
/// written.
///
/// Everything the group SQL later treats as a number is checked here first, in one set-based
/// statement over the same relation the materialization uses: the storage class of every link
/// count, whether an allocation's pathnames agree about it, whether it is a possible count at all,
/// whether a group claims more pathnames of an allocation than its inode has links, and whether
/// the ceiling stays inside the persisted integer domain. SQLite answers an overflowing `*` with a
/// `REAL`, so `typeof(ceiling)` is the overflow test.
///
/// The `LIMIT 1` is safe in a way C3a's was not: the `WHERE` selects only rows that are already
/// wrong, so any of them is a truthful report, and the deterministic order makes the message the
/// same on every run. Called inside the publishing transaction, so a refusal rolls back the whole
/// result rather than leaving part of it trusted.
fn refuse_untrustworthy_group_objects(conn: &Connection, scan_id: i64) -> Result<()> {
    use rusqlite::OptionalExtension;

    type Offender = (String, i64, Value, i64, String, String, Value, i64);
    let offender: Option<Offender> = conn
        .query_row(
            &format!(
                "{groups}
                 SELECT objects.named, objects.observed, objects.nlink, objects.nlink_distinct,
                        objects.nlink_min_class, objects.nlink_max_class,
                        groups.size, groups.object_count
                   FROM objects JOIN groups ON groups.digest = objects.digest
                  WHERE objects.nlink_min_class <> objects.nlink_max_class
                     OR objects.nlink_distinct > 1
                     OR typeof(objects.nlink) <> 'integer'
                     OR objects.nlink < 0
                     OR (objects.nlink > 0 AND objects.observed > objects.nlink)
                     OR typeof(groups.size) <> 'integer'
                     OR typeof(groups.ceiling) <> 'integer'
                  ORDER BY objects.named
                  LIMIT 1",
                groups = group_rows_sql()
            ),
            params![scan_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((named, observed, nlink, distinct, min_class, max_class, size, object_count)) =
        offender
    else {
        return Ok(());
    };

    // The message comes from whichever gate the row actually fails, so the operator reads the same
    // wording here as anywhere else that decodes these columns.
    let path = PathBuf::from(&named);
    let sanitized = crate::textsan::terminal(&path.display().to_string());
    let links = GroupedLinkCount {
        value: nlink,
        distinct,
        min_class,
        max_class,
    }
    .decode(&path)?;
    let size = size_from_sql(&size, &sanitized)?;
    ReclaimEstimate::for_objects(
        size,
        &[crate::model::reclaim::ObjectLinks {
            observed: observed as u64,
            links,
        }],
        &sanitized,
    )?;
    ReclaimEstimate::object_ceiling(size, object_count as u64)?;
    Err(AppError::msg(format!(
        "the reclaim of the group behind {sanitized} cannot be established. Rescan, or move the old dedcom.db aside."
    )))
}

/// Recomputes the scan's totals from the group rows just written, and stores them beside their
/// state.
///
/// Reads the rows rather than the objects, and folds them with `ReclaimEstimate::for_fresh_scan` —
/// the one implementation of «what a set of groups is worth». The two publishing paths write
/// identical rows, so folding them through the same function is what makes their scan totals
/// identical too. The rows are read into a vector of three-field values first — on the largest
/// /tank result that is tens of megabytes for the length of one statement, against a second
/// implementation of the fold living in SQL where nothing could compare the two.
fn record_scan_reclaim(tx: &Connection, scan_id: i64) -> Result<()> {
    let mut stmt =
        tx.prepare("SELECT reclaim, reclaim_state FROM file_group WHERE scan_id = ?1")?;
    let mut rows = stmt.query(params![scan_id])?;
    let mut groups = Vec::new();
    while let Some(row) = rows.next()? {
        groups.push(ReclaimEstimate::from_persisted(row.get(0)?, row.get(1)?)?);
    }
    let total = ReclaimEstimate::for_fresh_scan(groups)?;
    tx.execute(
        "UPDATE scan_stats SET reclaimable_bytes = ?2, reclaim_state = ?3 WHERE scan_id = ?1",
        params![
            scan_id,
            total.persisted_bytes() as i64,
            total.state().as_i64()
        ],
    )?;
    Ok(())
}

/// Runs the one set-based propagation statement on an open transaction and returns the rows it
/// filled in. One statement per call — never a loop over aliases.
fn propagate_trusted_digests(tx: &Connection, scan_id: i64) -> Result<u64> {
    let updated = tx.execute(&propagate_sql(), params![scan_id])?;
    Ok(updated as u64)
}

impl ScanStore {
    fn new(conn: Connection) -> Self {
        Self {
            conn,
            #[cfg(test)]
            propagations: std::cell::Cell::new(0),
        }
    }

    /// Test-only: set-based propagation statements issued so far (see the field).
    #[cfg(test)]
    pub fn propagation_statements(&self) -> u64 {
        self.propagations.get()
    }

    /// Opens the DB for the process role: an observer gets a genuinely read-only connection,
    /// an operator the usual read-write one.
    pub fn open(db_path: &Path) -> Result<Self> {
        if is_observer_role() {
            return Self::open_read_only(db_path);
        }
        Self::open_writable(db_path)
    }

    /// Read-only connection for an observer: `SQLITE_OPEN_READ_ONLY` (which also refuses to
    /// CREATE the file — an observer on a clean state-dir must not conjure a dedcom.db) plus
    /// `PRAGMA query_only`, so SQLite itself rejects any write. Deliberately does none of the
    /// operator's setup: no WAL flip, no migration, no chmod — all of them write.
    pub fn open_read_only(db_path: &Path) -> Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(db_path, flags).map_err(|err| {
            AppError::msg(format!(
                "cannot open dedcom.db read-only ({}): {err}",
                crate::textsan::terminal(&db_path.display().to_string())
            ))
        })?;
        conn.execute_batch("PRAGMA busy_timeout=5000;\nPRAGMA query_only=1;")?;
        schema::ensure_version_supported(&conn)?;
        // Migrating needs a writer, so an out-of-date DB is reported here rather than as a
        // «no such column» from some query later on.
        schema::ensure_migrated(&conn)?;
        Ok(Self::new(conn))
    }

    /// Opens (creates) the DB, enables WAL, applies the schema.
    pub fn open_writable(db_path: &Path) -> Result<Self> {
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
        // Refuse a DB written by a newer build before touching it (no WAL flip, no migration).
        schema::ensure_version_supported(&conn)?;
        // busy_timeout — the background move worker holds its own connection
        // in parallel with the main one; WAL + waiting on a lock instead of a «locked» error.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;\nPRAGMA busy_timeout=5000;",
        )?;
        schema::migrate(&conn)?;
        // 0600 on the DB file and WAL/SHM (created by enabling WAL above): the contents — the paths of all
        // pool files — are for the owner only (errors are propagated, not best-effort).
        crate::paths::enforce_db_perms_0600(db_path)?;
        Ok(Self::new(conn))
    }

    /// Opens an in-memory DB — for unit tests.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        schema::migrate(&conn)?;
        Ok(Self::new(conn))
    }

    /// Path of the DB file — to derive the state_dir for reading config.json.
    pub fn db_path(&self) -> Option<PathBuf> {
        self.conn.path().map(PathBuf::from)
    }

    /// Looks for the most recent scan (to resume or view).
    pub fn find_resumable(&self) -> Result<Option<ResumeInfo>> {
        // Newest first; stream the rows and stop at the first whose status this build can parse,
        // skipping unknown-status rows (written by a future version) with a warning — without
        // materialising the whole scan list.
        let mut stmt = self
            .conn
            .prepare("SELECT id, created_at, status, config_json FROM scan ORDER BY id DESC")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let scan_id: i64 = row.get(0)?;
            let status_text: String = row.get(2)?;
            let Some(status) = ScanStatus::parse(&status_text) else {
                tracing::warn!(scan_id, status = %status_text, "skipping scan with unknown status");
                continue;
            };
            let created_at: String = row.get(1)?;
            let config_json: String = row.get(3)?;
            let config: ScanConfig = serde_json::from_str(&config_json)?;
            let stats = self.candidate_stats(scan_id)?;
            return Ok(Some(ResumeInfo {
                scan_id,
                created_at,
                status,
                roots: config.roots,
                files_total: stats.total_files,
                files_hashed: stats.hashed_files,
                cand_bytes_total: stats.total_bytes,
                cand_bytes_hashed: stats.hashed_bytes,
                files_scanned: 0,
                reclaim: ReclaimEstimate::unknown(),
                already_linked_sets: None,
            }));
        }
        Ok(None)
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
        type Raw = (
            i64,
            String,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        );
        let raw: Vec<Raw> = {
            // The guaranteed sum joins in as ONE aggregation over `file_group` for every listed
            // scan at once, not one query per row: `file_group` holds a row per group, and the
            // session list is exactly where a per-scan query used to be the freeze.
            let mut stmt = self.conn.prepare(
                "SELECT s.id, s.created_at, s.status, s.config_json,
                        COALESCE(st.cand_files_total, 0),
                        COALESCE(st.cand_files_hashed, 0),
                        COALESCE(st.cand_bytes_total, 0),
                        COALESCE(st.cand_bytes_hashed, 0),
                        COALESCE(st.files_scanned, 0),
                        COALESCE(st.reclaimable_bytes, 0),
                        COALESCE(st.reclaim_state, 0),
                        COALESCE(g.guaranteed, 0)
                 FROM scan s
                 LEFT JOIN scan_stats st ON st.scan_id = s.id
                 LEFT JOIN (SELECT scan_id, SUM(reclaim) AS guaranteed FROM file_group
                             WHERE reclaim_state = 1 GROUP BY scan_id) g ON g.scan_id = s.id
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
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
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
            reclaim_state,
            guaranteed,
        ) in raw
        {
            let Some(status) = ScanStatus::parse(&status_text) else {
                tracing::warn!(scan_id, status = %status_text, "skipping scan with unknown status");
                continue;
            };
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
                reclaim: ReclaimEstimate::from_persisted_scan(guaranteed, reclaim, reclaim_state)?,
                already_linked_sets: None,
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
        // Only the completed one states an already-linked count, and only here: this probe runs in
        // the background precisely so a manifest aggregation does not sit on the render path. The
        // session list above keeps its `None` and stays a `scan_stats` read.
        if let Some(info) = complete.as_mut() {
            info.already_linked_sets = self.already_linked_sets(info.scan_id).ok();
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
    /// scan/scan_stats/file/file_mark/dir_dedup/file_group/file_dedup/dir_omission/scan_root.
    /// We do NOT touch `hash_cache`
    /// — it is keyed by (device,inode) and shared across all scans. Metadata ≠ pool data
    /// (recreated by a re-scan). The heavy DELETE over `file` (millions of rows) should be called in the background.
    ///
    /// `dir_omission` comes before `scan_root`, and both before `scan`: the declared foreign keys
    /// enforce nothing while `PRAGMA foreign_keys` is off, so this order IS the enforcement. A
    /// ledger row that outlived its authority would be read against a root that no longer exists.
    pub fn purge_scan(&mut self, scan_id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        for table in [
            "scan_stats",
            "file_mark",
            "file",
            "dir_dedup",
            "file_group",
            "file_dedup",
            "dir_omission",
            "scan_root",
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

    /// Begins a new scan: creates a `scan` row, a `scan_stats` row and the scan's `scan_root`
    /// authority rows. Previous sessions are preserved — they can be selected on the sessions
    /// screen.
    ///
    /// One transaction, so a scan can never exist without the statistics row or with half its
    /// roots registered. Registration reads the config back out of the row just written rather
    /// than from the argument: the persisted value is the one every later reader sees, and a
    /// second path to the same fact is a second answer waiting to disagree.
    pub fn begin_scan(&mut self, config: &ScanConfig) -> Result<i64> {
        let config_json = serde_json::to_string(config)?;
        let now = now_string();

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO scan(created_at, updated_at, status, config_json)
             VALUES (?1, ?1, ?2, ?3)",
            params![now, ScanStatus::Walking.as_str(), config_json],
        )?;
        let scan_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO scan_stats(scan_id) VALUES (?1)",
            params![scan_id],
        )?;
        let registration = ensure_roots_tx(&tx, scan_id)?;
        tx.commit()?;
        log_registration(scan_id, &registration);
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
            "SELECT files_scanned, bytes_hashed, groups_found, elapsed_seconds, hash_failures
             FROM scan_stats WHERE scan_id = ?1",
            params![scan_id],
            |row| {
                Ok(ScanSummary {
                    files_scanned: row.get::<_, i64>(0)? as u64,
                    bytes_hashed: row.get::<_, i64>(1)? as u64,
                    groups_found: row.get::<_, i64>(2)? as usize,
                    elapsed_seconds: row.get::<_, f64>(3)?,
                    hash_failures: row.get::<_, i64>(4)? as u64,
                    // Filled below: both are decoded, and decoding can fail.
                    ..Default::default()
                })
            },
        )?;
        Ok(ScanSummary {
            reclaim: self.scan_reclaim(scan_id)?,
            already_linked_sets: self.already_linked_sets(scan_id)?,
            ..summary
        })
    }

    /// Changes the scan status.
    pub fn set_status(&self, scan_id: i64, status: ScanStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE scan SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![scan_id, status.as_str(), now_string()],
        )?;
        Ok(())
    }

    /// Deletes the scan's file manifest (before a re-walk), together with everything the previous
    /// walk claimed about completeness.
    ///
    /// One transaction, and that is the whole point: a ledger that outlived its manifest would let
    /// the next walk inherit the previous one's omissions, and an authority left standing over a
    /// deleted ledger would read as «nothing was omitted». Manifest, ledger and every root
    /// generation go together or not at all.
    ///
    /// Root registration runs here too, so a scan that predates the ledger — its `scan_root` rows
    /// were never written, because `begin_scan` is not called on resume — can earn an authority by
    /// re-walking. Idempotent: a scan whose roots are already registered keeps their rows, and
    /// their generations have just been zeroed anyway.
    pub fn clear_files(&mut self, scan_id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM file WHERE scan_id = ?1", params![scan_id])?;
        delete_ledger_tx(&tx, scan_id, &ClearScope::WholeScan)?;
        zero_generations_tx(&tx, scan_id, None)?;
        let registration = ensure_roots_tx(&tx, scan_id)?;
        tx.commit()?;
        log_registration(scan_id, &registration);
        Ok(())
    }

    /// Batch-adds files to the manifest (walk phase). hash = NULL.
    pub fn record_files(&mut self, scan_id: i64, files: &[ManifestRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO file
                     (scan_id, path, size, mtime, mtime_nsec, ctime_sec, ctime_nsec,
                      device, inode, nlink, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)",
            )?;
            for file in files {
                let path = file.path.to_string_lossy();
                // Checked: a count the signed column cannot hold is refused here, so the manifest
                // can never acquire the negative value the reader would have to call corrupt.
                let nlink = LinkCount::from_u64(file.nlink).to_i64()?;
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
                    nlink,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Materializes a LIGHTWEIGHT `file_group` summary from groups held in RAM — the `--verify`
    /// path, where byte-for-byte comparison may have split a group and only the caller knows the
    /// final membership. Opening a finished scan reads the summaries from here, and group members
    /// — from the `file` manifest by hash (`group_files`). Overwrites the scan's previous rows
    /// (idempotent).
    ///
    /// Ordering happens here rather than at the call site, so the one place that knows each
    /// group's guaranteed and potential bytes is also the place that ranks them. A caller cannot
    /// hand in an order derived from anything else.
    ///
    /// `file_dedup` (membership) IS NO LONGER WRITTEN — `file` already stores
    /// path/size/mtime/device/inode, there is no point duplicating them (scan.db does not bloat).
    /// The table is kept defined for compatibility; we clean up legacy rows.
    pub fn record_file_results(&mut self, scan_id: i64, groups: &[DuplicateGroup]) -> Result<()> {
        // Every figure first, before anything is written: an allocation nobody can measure has to
        // stop the whole result, not half of it. Groups of fewer than two allocations are not
        // duplicates of anything and never reach a row — the same rule the SQL path applies with
        // `HAVING COUNT(*) >= 2`.
        let mut rows: Vec<(&DuplicateGroup, GroupReclaim)> = Vec::with_capacity(groups.len());
        for group in groups {
            let reclaim = group.physical_reclaim()?;
            if reclaim.object_count >= 2 {
                rows.push((group, reclaim));
            }
        }
        rows.sort_by(|(left, left_reclaim), (right, right_reclaim)| {
            let (left_guaranteed, left_ceiling) = left_reclaim.estimate.order_key();
            let (right_guaranteed, right_ceiling) = right_reclaim.estimate.order_key();
            right_guaranteed
                .cmp(&left_guaranteed)
                .then(right_ceiling.cmp(&left_ceiling))
                .then(left.hash.cmp(&right.hash))
        });

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
                "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                        object_count, reclaim_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for (rank, (group, reclaim)) in rows.iter().enumerate() {
                ins_group.execute(params![
                    scan_id,
                    rank as i64,
                    group.hash,
                    reclaim.observed_paths as i64,
                    group.size_bytes as i64,
                    reclaim.estimate.persisted_bytes() as i64,
                    reclaim.object_count as i64,
                    reclaim.estimate.state().as_i64(),
                ])?;
            }
        }
        // In the SAME transaction as the rows: a crash must never leave results without their
        // totals or their marker, and an operator must never meet a scan whose headline was
        // written by one result and whose groups came from another. Written even for an empty
        // `groups` — with --verify that means every candidate group was rejected, and the empty
        // result is final, not re-derivable from raw hashes.
        record_scan_reclaim(&tx, scan_id)?;
        mark_prepared(&tx, scan_id)?;
        tx.commit()?;
        Ok(())
    }

    /// Materializes LIGHTWEIGHT `file_group` summaries via SQL aggregation — without loading
    /// `Vec<DuplicateGroup>` into RAM (on the 2.2M /tank it cuts the transient peak of the
    /// grouping phase). Result-identical to `record_file_results(&duplicate_groups)`: the same
    /// membership, pathname count, object count, state, guaranteed and potential bytes, and the
    /// same rank.
    ///
    /// The rank order is the checkpoint's total key — guaranteed bytes first, the trusted ceiling
    /// as the tiebreak, the hash last — expressed once as a window function here and once as a
    /// comparator in `record_file_results`. A hash is unique within a scan, so the key is total
    /// and the two paths cannot disagree about a tie. `hex_encode` = lower case →
    /// `lower(hex(hash))` (string order == BLOB order). `MIN(size)` — within a group the size is
    /// single (identical content). NOT the write path (apply/revalidate).
    pub fn materialize_file_groups(&mut self, scan_id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        // Before any row: nothing about this scan's allocations may be in doubt.
        refuse_untrustworthy_group_objects(&tx, scan_id)?;
        tx.execute(
            "DELETE FROM file_group WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM file_dedup WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            &format!(
                "{groups}
                 INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                        object_count, reclaim_state)
                 SELECT ?1,
                        ROW_NUMBER() OVER (ORDER BY guaranteed DESC, reclaim DESC, hash ASC) - 1,
                        hash, file_count, size, reclaim, object_count, state
                   FROM (
                       SELECT lower(hex(digest)) AS hash, file_count, size, object_count, state,
                              CASE WHEN state = 1 THEN ceiling ELSE 0 END AS guaranteed,
                              CASE WHEN state = 0 THEN 0 ELSE ceiling END AS reclaim
                         FROM groups
                   )",
                groups = group_rows_sql()
            ),
            params![scan_id],
        )?;
        // Same transaction as the rows (see record_file_results). Written even when the
        // aggregation produced nothing: «this scan has no duplicates» is a final answer, not a
        // reason to aggregate the manifest again on the next open.
        record_scan_reclaim(&tx, scan_id)?;
        mark_prepared(&tx, scan_id)?;
        tx.commit()?;
        Ok(())
    }

    /// Whether a writer has already prepared this scan's results.
    ///
    /// An explicit marker, NOT «file_group is non-empty»: an empty result is legitimate — a scan
    /// with no duplicates, or `--verify` rejecting every candidate group — and reading emptiness
    /// as «not prepared» would re-aggregate the whole manifest on every open and resurrect the
    /// groups verification threw away.
    pub fn results_materialized(&self, scan_id: i64) -> Result<bool> {
        let flag: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(results_materialized), 0) FROM scan_stats WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(flag != 0)
    }

    /// How far this scan's persisted reclaim total can be trusted. A legacy result and one this
    /// build has not computed yet both read as `Unknown`; an integer no build knows is an error,
    /// not a guess.
    pub fn scan_reclaim_state(&self, scan_id: i64) -> Result<ReclaimState> {
        let raw: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(reclaim_state), 0) FROM scan_stats WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        ReclaimState::from_i64(raw)
    }

    /// The scan's reclaim total: what its exact groups guarantee, the trusted ceiling beside it,
    /// and the state that says which of the two may be spoken aloud.
    ///
    /// The guaranteed sum is derived from the group rows rather than persisted, because v3 has one
    /// byte column per scan and the ceiling is the one that has to survive in it. Summing the
    /// exact groups is a read of the same table the browser already loads whole.
    pub fn scan_reclaim(&self, scan_id: i64) -> Result<ReclaimEstimate> {
        let guaranteed: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(reclaim), 0) FROM file_group
              WHERE scan_id = ?1 AND reclaim_state = ?2",
            params![scan_id, ReclaimState::Exact.as_i64()],
            |row| row.get(0),
        )?;
        let (ceiling, state): (i64, i64) = self.conn.query_row(
            "SELECT COALESCE(MAX(reclaimable_bytes), 0), COALESCE(MAX(reclaim_state), 0)
               FROM scan_stats WHERE scan_id = ?1",
            params![scan_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        ReclaimEstimate::from_persisted_scan(guaranteed, ceiling, state)
    }

    /// How many scan-local allocations already have two or more pathnames inside this scan.
    ///
    /// Informational, and deliberately independent of hashing: a set of aliases of a size nothing
    /// else shares is never hashed and never becomes a duplicate-content group, but it is exactly
    /// what an operator is looking for when a directory of «duplicates» produced no group at all.
    /// Counted from the manifest, never from synthetic rows — a link this scan never saw is not a
    /// pathname and is not counted here.
    pub fn already_linked_sets(&self, scan_id: i64) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM (
                     SELECT 1 FROM file WHERE scan_id = ?1
                      GROUP BY {OBJECT_KEY} HAVING COUNT(*) >= 2)"
            ),
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// The same count for every scan at once — one pass over the manifest instead of one pass per
    /// scan, for the `--stats` table and the session list.
    pub fn already_linked_sets_by_scan(&self) -> Result<HashMap<i64, u64>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT scan_id, COUNT(*) FROM (
                 SELECT scan_id FROM file GROUP BY scan_id, {OBJECT_KEY} HAVING COUNT(*) >= 2)
              GROUP BY scan_id"
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        let mut out = HashMap::new();
        for row in rows {
            let (scan_id, count) = row?;
            out.insert(scan_id, count);
        }
        Ok(out)
    }

    /// How many of a group's allocations' links the scan actually observed.
    ///
    /// A point lookup for the one group on screen, not a column: the pathname count is persisted,
    /// the link total is not, and re-deriving it for every row of a 645k-group list would put the
    /// manifest aggregation back into every open. One validated count per allocation — summing
    /// `nlink` once per pathname would multiply an alias set's links by its own size.
    pub fn group_links(&self, scan_id: i64, hash_hex: &str) -> Result<GroupLinks> {
        let Some(blob) = hex_decode(hash_hex) else {
            return Ok(GroupLinks {
                observed: 0,
                total: LinkCount::Unknown,
            });
        };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT COUNT(*), MIN(nlink), COUNT(DISTINCT nlink),
                    MIN(typeof(nlink)), MAX(typeof(nlink)), MIN(path)
               FROM file WHERE scan_id = ?1 AND hash = ?2
              GROUP BY {OBJECT_KEY}"
        ))?;
        let rows = stmt.query_map(params![scan_id, blob], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                GroupedLinkCount {
                    value: row.get::<_, Value>(1)?,
                    distinct: row.get::<_, i64>(2)?,
                    min_class: row.get::<_, String>(3)?,
                    max_class: row.get::<_, String>(4)?,
                },
                PathBuf::from(row.get::<_, String>(5)?),
            ))
        })?;
        let (mut observed, mut total) = (0u64, Some(0u64));
        for row in rows {
            let (paths, evidence, representative) = row?;
            observed += paths as u64;
            total = match (total, evidence.decode(&representative)?) {
                (Some(sum), LinkCount::Known(links)) => sum.checked_add(links),
                _ => None,
            };
        }
        Ok(GroupLinks {
            observed,
            total: total.map_or(LinkCount::Unknown, LinkCount::from_u64),
        })
    }

    /// Everything a single-group view needs to state its claim honestly: the persisted figure and
    /// the link evidence behind it. `None` — this digest has no materialized group.
    pub fn group_claim(&self, scan_id: i64, hash_hex: &str) -> Result<Option<GroupClaim>> {
        let Some(summary) = self.group_summary_for_hash(scan_id, hash_hex)? else {
            return Ok(None);
        };
        Ok(Some(GroupClaim {
            reclaim: summary.reclaim,
            links: self.group_links(scan_id, hash_hex)?,
        }))
    }

    /// Whether every manifest row of the scan carries a real link count. One unrecorded count is
    /// enough to make the scan unsafe to plan against — that row's allocation may have links
    /// nobody counted — and a manifest migrated from v2 is entirely in that state.
    ///
    /// One plan-time read returns the single worst cell, and `link_count_from_sql` decides what it
    /// means. The storage class is part of the test, not only the number: SQLite's `INTEGER` is an
    /// affinity rather than a constraint, so a `REAL`, `TEXT`, `BLOB` or `NULL` can sit in this
    /// column — and none of those compare `<= 0`, because numbers sort below text and blobs. A
    /// purely numeric filter would therefore skip them and call the manifest fully known.
    ///
    /// The ordering puts an invalid storage class ahead of every integer, so corruption is what
    /// gets reported even when a `0` or a negative row is present too; among integers the smallest
    /// comes first. No row selected at all means every count is a real one.
    pub fn scan_link_counts_known(&self, scan_id: i64) -> Result<bool> {
        use rusqlite::OptionalExtension;
        let worst: Option<Value> = self
            .conn
            .query_row(
                "SELECT nlink FROM file
                  WHERE scan_id = ?1 AND (typeof(nlink) <> 'integer' OR nlink <= 0)
                  ORDER BY typeof(nlink) = 'integer', nlink
                  LIMIT 1",
                params![scan_id],
                |row| row.get(0),
            )
            .optional()?;
        match worst {
            None => Ok(true),
            Some(value) => Ok(link_count_from_sql(&value)?.is_known()),
        }
    }

    /// Whether this scan's results may be turned into a destructive plan. Answers only — `R2D`
    /// owns wiring it into action construction and the confirmation screens, so nothing calls it
    /// outside tests yet and today's behaviour is unchanged.
    #[allow(dead_code)]
    pub fn destructive_plan_verdict(&self, scan_id: i64) -> Result<DestructivePlanVerdict> {
        Ok(DestructivePlanVerdict::of(
            self.scan_reclaim_state(scan_id)?,
            self.scan_link_counts_known(scan_id)?,
        ))
    }

    /// Marks the results prepared in its own transaction — for the paths that only need the
    /// marker (a legacy result that must be kept as-is rather than re-derived).
    fn mark_results_materialized(&mut self, scan_id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        mark_prepared(&tx, scan_id)?;
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

    /// One representative pathname per physical object still awaiting a digest.
    ///
    /// This is the hash-once contract: the content of an allocation is read once, not once per
    /// pathname pointing at it. Every path row stays in the manifest — nothing is collapsed there —
    /// but only the representative is handed to the hashing phase, and the digest reaches its
    /// aliases by propagation (`propagate_trusted_digests`) rather than by reading them again.
    ///
    /// The representative is `MIN(path)` within the object, so it is deterministic across runs and
    /// across a resume. Aliases share `nlink` by construction, so `MIN` over the group returns
    /// their common value; it is still decoded through the checked gate.
    pub fn candidate_objects(&self, scan_id: i64) -> Result<Vec<ManifestRow>> {
        // The link count comes back as evidence about the WHOLE group, not as one aggregated
        // value: `MIN` alone would let a valid alias vouch for a corrupt one (see
        // `grouped_link_count`). The two `typeof` extremes reveal every storage class present, and
        // the distinct count reveals aliases that disagree.
        let mut stmt = self.conn.prepare(&format!(
            "SELECT MIN(path), size, mtime, mtime_nsec, ctime_sec, ctime_nsec, device, inode,
                    MIN(nlink), COUNT(DISTINCT nlink),
                    MIN(typeof(nlink)), MAX(typeof(nlink))
             FROM file
             WHERE scan_id = ?1 AND hash IS NULL AND size IN ({})
             GROUP BY {OBJECT_KEY}",
            eligible_sizes_sql()
        ))?;
        // The link-count evidence travels beside the row rather than inside it: validating it is
        // checked and can fail, which a rusqlite row mapper cannot report. The field below is a
        // placeholder the loop replaces before anything reads it.
        let rows = stmt.query_map(params![scan_id], |row| {
            let file = ManifestRow {
                path: PathBuf::from(row.get::<_, String>(0)?),
                size: row.get::<_, i64>(1)? as u64,
                mtime: row.get::<_, i64>(2)?,
                mtime_nsec: row.get::<_, i64>(3)?,
                ctime_sec: row.get::<_, i64>(4)?,
                ctime_nsec: row.get::<_, i64>(5)?,
                device: row.get::<_, i64>(6)? as u64,
                inode: row.get::<_, i64>(7)? as u64,
                nlink: 0,
            };
            let evidence = GroupedLinkCount {
                value: row.get::<_, Value>(8)?,
                distinct: row.get::<_, i64>(9)?,
                min_class: row.get::<_, String>(10)?,
                max_class: row.get::<_, String>(11)?,
            };
            Ok((file, evidence))
        })?;

        let mut files = Vec::new();
        for row in rows {
            let (mut file, evidence) = row?;
            file.nlink = evidence.decode(&file.path)?.to_u64();
            files.push(file);
        }
        Ok(files)
    }

    /// Statistics on hashing candidates, in the two dimensions the phase actually has.
    ///
    /// Files count **path rows** — every pathname still has to end up with a digest, so pathname
    /// completion is what the file counter tracks. Bytes count **distinct physical objects once**,
    /// because that is what will be read from disk; charging an allocation once per alias would
    /// inflate the total, the rate and the ETA by exactly the duplication the scan is looking for.
    ///
    /// All four totals come off ONE object relation and ONE eligibility relation. Written as four
    /// separate subqueries — the shape this replaces — each carried its own copy of the complete
    /// eligible-size aggregation, so the scan-local object grouping ran four times per call, and
    /// the phase calls this at least at start and at final reconciliation. `MATERIALIZED` is
    /// explicit because `objects` is referenced twice and SQLite would otherwise be free to inline
    /// it, reintroducing exactly the duplication this removes.
    pub fn candidate_stats(&self, scan_id: i64) -> Result<CandidateStats> {
        let stats = self
            .conn
            .query_row(&candidate_stats_sql(), params![scan_id], |row| {
                Ok(CandidateStats {
                    total_files: row.get::<_, i64>(0)? as u64,
                    total_bytes: row.get::<_, i64>(1)? as u64,
                    hashed_files: row.get::<_, i64>(2)? as u64,
                    hashed_bytes: row.get::<_, i64>(3)? as u64,
                })
            })?;
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
        // Borrowed before the transaction takes `conn`: disjoint fields, so the counter stays
        // reachable while the transaction is open.
        #[cfg(test)]
        let counter = &self.propagations;
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
                    persisted.representatives += updated as u64;
                    persisted.files += updated as u64;
                    persisted.bytes += row.size;
                }
            }
        }
        // In the SAME transaction as the representatives: a crash must never leave an object
        // trusted while its unchanged aliases sit unpropagated, which a later run would then read
        // again. A representative that did not commit leaves no trusted source, so it propagates
        // nothing — the identity check above is the only gate needed.
        #[cfg(test)]
        counter.set(counter.get() + 1);
        persisted.files += propagate_trusted_digests(&tx, scan_id)?;
        tx.commit()?;
        Ok(persisted)
    }

    /// Spreads digests that cross-scan inheritance just produced across the aliases of each
    /// object, before any candidate is chosen. This is what makes a newly visible alias free: one
    /// surviving pathname inherits, every other pathname of the same allocation receives the
    /// digest, and the object needs zero content reads. A pathname that was actually renamed is a
    /// different case — the rename moved the inode's ctime, so nothing of that object inherits at
    /// all and it is read once.
    ///
    /// Refuses first if any object carries more than one distinct trusted digest — two aliases
    /// that inherited from different past scans cannot both be right, and picking by row order
    /// would be choosing a random answer to a data-safety question.
    pub fn propagate_inherited_hashes(&mut self, scan_id: i64) -> Result<u64> {
        #[cfg(test)]
        let counter = &self.propagations;
        let tx = self.conn.transaction()?;
        let conflicts = conflicting_digest_objects(&tx, scan_id)?;
        if conflicts > 0 {
            return Err(AppError::msg(format!(
                "{conflicts} physical object(s) in this scan carry more than one inherited hash. The checkpoint disagrees with itself; rescan without hash reuse, or move the old dedcom.db aside."
            )));
        }
        #[cfg(test)]
        counter.set(counter.get() + 1);
        let propagated = propagate_trusted_digests(&tx, scan_id)?;
        tx.commit()?;
        Ok(propagated)
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

    /// Assembles duplicate-content groups: files whose digest is shared by at least two DISTINCT
    /// physical allocations.
    ///
    /// Two pathnames of one inode are one copy, so an alias set — however many pathnames it holds
    /// — is not a group here, exactly as it is not one in `materialize_file_groups`. Every
    /// pathname of a qualifying group is returned; nothing is collapsed.
    ///
    /// Returned in `hash ASC` order with `id` following it. Rank by payoff belongs to the one
    /// place that computes payoff (`record_file_results`), so this reader has no benefit order to
    /// get wrong.
    pub fn duplicate_groups(&self, scan_id: i64) -> Result<Vec<DuplicateGroup>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT f.path, f.size, f.mtime, f.mtime_nsec, f.ctime_sec, f.ctime_nsec,
                    f.device, f.inode, f.nlink, f.hash, m.is_keeper, m.action
             FROM file f
             LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
             WHERE f.scan_id = ?1 AND f.hash IS NOT NULL
               AND f.hash IN (
                   SELECT digest FROM ({objects}) GROUP BY digest HAVING COUNT(*) >= 2
               )
             ORDER BY f.hash, f.path",
            objects = group_objects_sql()
        ))?;

        type Row = (
            PathBuf,
            u64,
            i64,
            i64,
            i64,
            i64,
            u64,
            u64,
            Value,
            Vec<u8>,
            Option<i64>,
            Option<String>,
        );
        let rows = stmt.query_map(params![scan_id], |row| {
            let assembled: Row = (
                PathBuf::from(row.get::<_, String>(0)?),
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)? as u64,
                row.get::<_, i64>(7)? as u64,
                row.get::<_, Value>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<String>>(11)?,
            );
            Ok(assembled)
        })?;

        let mut groups: Vec<DuplicateGroup> = Vec::new();
        for row in rows {
            let (
                path,
                size,
                mtime,
                mtime_nsec,
                ctime_sec,
                ctime_nsec,
                device,
                inode,
                nlink,
                hash_bytes,
                is_keeper,
                action,
            ) = row?;
            let hash = hex_encode(&hash_bytes);
            let entry = FileEntry {
                path,
                size,
                mtime,
                mtime_nsec,
                ctime_sec,
                ctime_nsec,
                device,
                inode,
                // Through the one checked gate: a link count of a class this column should never
                // hold is corruption, and turning it into a byte figure is how it would spread.
                nlink: link_count_from_sql(&nlink)?.to_u64(),
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

    /// Settles the persisted marks with what a batch of actions actually did — the durable half
    /// of what each UI does with its own copy. `attempted` are the targets the batch reached.
    /// A cancelled batch clears only those, so everything it never got to stays marked and a
    /// re-run applies exactly the remainder; a batch that ran to the end spends the whole plan,
    /// keepers included. One transaction: the plan is settled as a whole or not at all.
    pub fn reconcile_marks_after_batch(
        &mut self,
        scan_id: i64,
        attempted: &[PathBuf],
        cancelled: bool,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        if cancelled {
            let mut clear = tx.prepare("DELETE FROM file_mark WHERE scan_id = ?1 AND path = ?2")?;
            for target in attempted {
                clear.execute(params![scan_id, &*target.to_string_lossy()])?;
            }
            drop(clear);
        } else {
            tx.execute("DELETE FROM file_mark WHERE scan_id = ?1", params![scan_id])?;
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
    ///
    /// `reclaimable_bytes` and `reclaim_state` are deliberately NOT written here. They are
    /// published with the group rows that justify them, in one transaction (`record_scan_reclaim`);
    /// a second writer working from a summary carried through the pipeline is exactly how a
    /// headline drifts away from the rows underneath it.
    pub fn record_scan_result(&self, scan_id: i64, summary: &ScanSummary) -> Result<()> {
        self.conn.execute(
            "UPDATE scan_stats
                SET files_scanned = ?2, bytes_hashed = ?3,
                    groups_found = ?4, hash_failures = ?5
              WHERE scan_id = ?1",
            params![
                scan_id,
                summary.files_scanned as i64,
                summary.bytes_hashed as i64,
                summary.groups_found as i64,
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
            i64,
            i64,
        );
        // Both aggregations are joined in once for the whole table rather than run per row: the
        // report lists every scan there is, and a per-scan pass over the manifest would make
        // `--stats` cost a full sweep for each of them.
        let already_linked = self.already_linked_sets_by_scan()?;
        let raw: Vec<Raw> = {
            let mut stmt = self.conn.prepare(
                "SELECT s.id, s.created_at, s.status, s.config_json,
                        st.elapsed_seconds, st.storage_type, st.pool_layout, st.zfs_version,
                        st.files_scanned, st.bytes_hashed, st.groups_found, st.reclaimable_bytes,
                        st.hash_failures, COALESCE(st.reclaim_state, 0),
                        COALESCE(g.guaranteed, 0)
                   FROM scan s
                   JOIN scan_stats st ON st.scan_id = s.id
                   LEFT JOIN (SELECT scan_id, SUM(reclaim) AS guaranteed FROM file_group
                               WHERE reclaim_state = 1 GROUP BY scan_id) g ON g.scan_id = s.id
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
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
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
            reclaim_state,
            guaranteed,
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
                reclaim: ReclaimEstimate::from_persisted_scan(
                    guaranteed,
                    reclaimable,
                    reclaim_state,
                )?,
                already_linked_sets: already_linked.get(&id).copied().unwrap_or(0),
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
    /// Refuses first, then inherits — both in one transaction, so a refusal leaves every current
    /// hash and `identity_version` exactly as it was and the attempt is safely retryable.
    ///
    /// The old query answered a disagreement with `LIMIT 1`, i.e. by row order, and the
    /// current-scan check that runs afterwards could not notice: by then only the chosen digest
    /// existed. The preflight therefore weighs the complete evidence per current physical object —
    /// digests this scan already trusts, plus every trusted past digest offered to any of the
    /// object's still-null pathnames — and more than one distinct digest among them is an
    /// unanswerable question, not a value to pick.
    pub fn inherit_hashes(&mut self, scan_id: i64) -> Result<u64> {
        let tx = self.conn.transaction()?;
        let conflicts = conflicting_inheritance_objects(&tx, scan_id)?;
        if conflicts > 0 {
            return Err(AppError::msg(format!(
                "the checkpoint offers more than one hash for {conflicts} physical object(s) of this scan. Reusing either would be a guess; rescan without hash reuse, or move the old dedcom.db aside."
            )));
        }
        // Safe only because the same transaction just proved every eligible source agrees: with one
        // distinct digest, a deterministic aggregate and «any of them» are the same value.
        let updated = tx.execute(&inherit_sql(), params![scan_id])?;
        tx.commit()?;
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
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {GROUP_FILE_COLUMNS}
             FROM file f
             LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
             WHERE f.scan_id = ?1 AND f.hash = ?2
             ORDER BY f.path"
        ))?;
        let rows = stmt.query_map(params![scan_id, blob], group_file_row)?;
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
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {GROUP_FILE_COLUMNS}
             FROM file f
             LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
             WHERE f.scan_id = ?1 AND f.hash = ?2
             ORDER BY f.path
             LIMIT ?3 OFFSET ?4"
        ))?;
        let rows = stmt.query_map(
            params![scan_id, blob, limit as i64, offset as i64],
            group_file_row,
        )?;
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
            "SELECT rank, hash, file_count, size, reclaim, object_count, reclaim_state
             FROM file_group WHERE scan_id = ?1 ORDER BY rank",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok((
                GroupSummary {
                    rank: row.get(0)?,
                    hash: row.get(1)?,
                    file_count: row.get::<_, i64>(2)? as u64,
                    size_bytes: row.get::<_, i64>(3)? as u64,
                    object_count: row.get::<_, i64>(5)? as u64,
                    reclaim: ReclaimEstimate::unknown(),
                },
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            // Decoding is fallible — an unrecognised state is corruption, not an `Unknown` guess —
            // so it happens outside the rusqlite mapper, which has no way to report it.
            let (mut summary, reclaim, state) = row?;
            summary.reclaim = ReclaimEstimate::from_persisted(reclaim, state)?;
            out.push(summary);
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
            "SELECT rank, hash, file_count, size, reclaim, object_count, reclaim_state
             FROM file_group WHERE scan_id = ?1 AND hash = ?2 LIMIT 1",
            params![scan_id, hash_hex],
            |row| {
                Ok((
                    GroupSummary {
                        rank: row.get(0)?,
                        hash: row.get(1)?,
                        file_count: row.get::<_, i64>(2)? as u64,
                        size_bytes: row.get::<_, i64>(3)? as u64,
                        object_count: row.get::<_, i64>(5)? as u64,
                        reclaim: ReclaimEstimate::unknown(),
                    },
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        );
        match row {
            Ok((mut summary, reclaim, state)) => {
                summary.reclaim = ReclaimEstimate::from_persisted(reclaim, state)?;
                Ok(Some(summary))
            }
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

    /// Prepares a finished scan's results once, on the WRITER path — so that opening them is a
    /// pure read and an observer never has to write.
    ///
    /// Keyed off the explicit `results_materialized` marker, never off `file_group` being empty:
    /// empty is a legitimate answer. For a scan that predates the marker we must still not
    /// re-derive a result that already exists, because `--verify` may have filtered it and raw
    /// hashes would hand the rejected groups back. Two signals say «already finished»:
    /// rows in `file_group`, or an authoritative `scan_stats.groups_found = 0` — the completed
    /// scan recorded that it found nothing. Only a legacy scan with no result at all and no
    /// recorded count is aggregated.
    pub fn ensure_materialized(&mut self, scan_id: i64) -> Result<()> {
        use rusqlite::OptionalExtension;
        if self.results_materialized(scan_id)? {
            return Ok(());
        }
        let recorded: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_group WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        // `groups_found` only counts once the scan actually recorded its outcome: `begin_scan`
        // inserts the row with every metric at 0, so a bare zero is indistinguishable from
        // «nothing written yet». `record_scan_result` (the single writer, at completion) fills
        // files_scanned/bytes_hashed alongside it — non-zero there is what makes the count
        // authoritative.
        let stats: Option<(i64, i64, i64)> = self
            .conn
            .query_row(
                "SELECT groups_found, files_scanned, bytes_hashed FROM scan_stats
                  WHERE scan_id = ?1",
                params![scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let recorded_zero_groups = matches!(
            stats,
            Some((0, files, bytes)) if files > 0 || bytes > 0
        );
        if recorded > 0 || recorded_zero_groups {
            self.mark_results_materialized(scan_id)?;
        } else {
            // Result-identical to duplicate_groups + record_file_results, without the RAM peak
            // (see materialize_file_groups_equals_record_file_results); it sets the marker.
            self.materialize_file_groups(scan_id)?;
        }
        Ok(())
    }

    /// Ids of completed scans whose results are not prepared yet.
    pub fn unprepared_completed_scans(&self) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id
               FROM scan s
               LEFT JOIN scan_stats st ON st.scan_id = s.id
              WHERE s.status IN (?1, ?2)
                AND COALESCE(s.trashed, 0) = 0
                AND COALESCE(st.results_materialized, 0) = 0
              ORDER BY s.id",
        )?;
        let rows = stmt.query_map(
            params![
                ScanStatus::Complete.as_str(),
                ScanStatus::CompleteWithWarnings.as_str()
            ],
            |row| row.get::<_, i64>(0),
        )?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Prepares every completed scan that is still unprepared, so an observer finds ready
    /// results instead of having to write. Writer/operator path; returns how many were prepared.
    pub fn prepare_completed_scans(&mut self) -> Result<usize> {
        let pending = self.unprepared_completed_scans()?;
        let mut done = 0;
        for scan_id in pending {
            self.ensure_materialized(scan_id)?;
            done += 1;
        }
        Ok(done)
    }
}

// Test seam: fires once, after the requested marks have been reconciled with the durable ones and
// before any group is loaded.
//
// It exists so a test can commit a change from a SECOND connection at exactly the moment that used
// to matter, and prove deterministically — no sleeps, no racing threads — that the builder reads one
// database snapshot from end to end. Not compiled into a production build at all.
#[cfg(test)]
thread_local! {
    static AFTER_RECONCILE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arms the seam above for the current thread.
#[cfg(test)]
pub(crate) fn arm_after_reconcile(hook: impl FnOnce() + 'static) {
    AFTER_RECONCILE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn fire_after_reconcile() {
    if let Some(hook) = AFTER_RECONCILE.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

/// The destructive-plan authority.
///
/// Since R2D-C5-2 this is the only way into a plan: classic and the commander both call
/// `build_action_plan`, and the pathname-based builders it replaced are gone.
impl ScanStore {
    /// Builds the one destructive plan from durable evidence, or refuses.
    ///
    /// `requested` is what the caller believes is marked right now — a commander panel's marks, or
    /// the group open in the classic browser. It is reconciled against the database rather than
    /// trusted: the database is the authority for what is marked, and it is the only place that
    /// holds the members nobody marked. An unmarked alias is exactly the evidence that decides
    /// whether removing its sibling releases anything, so a plan assembled from marked pathnames
    /// alone cannot be right — that is the shape this builder exists to make impossible.
    ///
    /// Nothing is dropped to make a plan pass: every condition that cannot be justified refuses the
    /// whole plan and names the pathname.
    pub fn build_action_plan(
        &self,
        scan_id: i64,
        requested: &[RequestedMark],
    ) -> PlanResult<ActionPlan> {
        // One snapshot for the whole plan, opened before the first read and held until the plan
        // exists and has been validated against the disk.
        //
        // The checkpoint DB runs in WAL and more than one connection writes to it, so between two
        // autocommit reads a second copy of the program can commit. Reconciling the request against
        // the marks and then loading the groups as separate reads is exactly that window: the
        // request is checked against the old meaning and the plan is assembled from the new one.
        // A deferred transaction on this connection covers every statement made on it, including
        // the ones inside `destructive_plan_verdict`, so nothing here has to be threaded by hand.
        let snapshot = self
            .conn
            .unchecked_transaction()
            .map_err(Self::store_refusal)?;

        // The coarse gate first: a scan nobody could measure is not planned against at all.
        let verdict = self
            .destructive_plan_verdict(scan_id)
            .map_err(Self::store_refusal)?;
        if verdict != DestructivePlanVerdict::Allowed {
            return Err(PlanRefusal::RescanRequired);
        }

        let marks = self.durable_marks(scan_id)?;
        if marks.is_empty() {
            return Err(PlanRefusal::NoMarks);
        }
        // Every mark the caller holds has to exist durably AND mean the same thing. A mark whose
        // write failed leaves the older meaning behind, and planning that is how a window showing
        // DELETE ends up over a database that still says HARDLINK. Durable marks the caller does
        // NOT hold stay in: they are the operator's earlier work on another panel, not an error.
        let durable: HashMap<&Path, MarkIntent> = marks
            .iter()
            .map(|(path, intent, _)| (path.as_path(), *intent))
            .collect();
        // The request has to agree with itself before it is worth comparing with anything. One
        // pathname may be marked in two panels; one pathname marked two different ways in one
        // request is a window that does not know its own state, and which of the two we then
        // compared with the database would be an accident of order.
        let mut asked: HashMap<&Path, MarkIntent> = HashMap::with_capacity(requested.len());
        for mark in requested {
            if let Some(earlier) = asked.insert(mark.path.as_path(), mark.intent) {
                if earlier != mark.intent {
                    return Err(PlanRefusal::RequestContradictsItself {
                        path: mark.path.clone(),
                    });
                }
            }
        }
        // Then, in the caller's own order so the same request always names the same pathname first.
        for mark in requested {
            match durable.get(mark.path.as_path()) {
                None => {
                    return Err(PlanRefusal::MarkNotPersisted {
                        path: mark.path.clone(),
                    })
                }
                Some(found) if *found != mark.intent => {
                    return Err(PlanRefusal::MarkDisagrees {
                        path: mark.path.clone(),
                        requested: mark.intent,
                        durable: *found,
                    })
                }
                Some(_) => {}
            }
        }

        // The request has been checked against the marks as they stood. Everything the plan is
        // built from below must come from that same state.
        #[cfg(test)]
        fire_after_reconcile();

        let mut digests: Vec<Vec<u8>> = marks.iter().map(|(_, _, digest)| digest.clone()).collect();
        digests.sort();
        digests.dedup();
        let mut groups = Vec::with_capacity(digests.len());
        for digest in &digests {
            groups.push(self.plan_group(scan_id, digest)?);
        }

        // The model decides what becomes an action and what the plan may claim.
        let plan = ActionPlan::try_new(scan_id, groups)?;
        // And the files have to still be the files the manifest describes. The same structural
        // check `apply_batch` runs twice more, called here rather than left to the caller: a plan
        // that can be returned unvalidated is a plan someone forgets to validate. Still inside the
        // snapshot — the evidence it compares against must be the evidence the plan was folded
        // from.
        plan.preflight()?;
        // Nothing was written, so this only ends the read. It is not left to `Drop`: a failure here
        // means the snapshot did not last the whole way, and that refuses the plan like any other
        // unreadable evidence.
        snapshot.finish().map_err(Self::store_refusal)?;
        Ok(plan)
    }

    /// The scan's durable marks: what each one means, and the digest of its manifest row.
    ///
    /// Every row of `file_mark` is read and decoded, without an SQL filter on `is_keeper`/`action`:
    /// a filter would apply SQLite's comparison rules to values that may not be the shapes those
    /// columns are supposed to hold, and quietly leave a corrupt mark out of the plan. A mark whose
    /// manifest row is gone, or whose row carries no digest, refuses the plan the same way — both
    /// are pathnames the operator asked to act on and nothing can vouch for.
    fn durable_marks(&self, scan_id: i64) -> PlanResult<Vec<(PathBuf, MarkIntent, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT m.path, m.is_keeper, m.action, f.path, f.hash
                   FROM file_mark m
                   LEFT JOIN file f ON f.scan_id = m.scan_id AND f.path = m.path
                  WHERE m.scan_id = ?1
                  ORDER BY m.path",
            )
            .map_err(Self::store_refusal)?;
        let rows = stmt
            .query_map(params![scan_id], |row| {
                Ok((
                    PathBuf::from(row.get::<_, String>(0)?),
                    row.get::<_, Value>(1)?,
                    row.get::<_, Value>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })
            .map_err(Self::store_refusal)?;
        let mut out = Vec::new();
        for row in rows {
            let (path, is_keeper, action, manifest, digest) = row.map_err(Self::store_refusal)?;
            // Every row here came out of `file_mark` itself, so it is present by construction.
            // `save_marks` deletes a row that means neither, so one that says neither was not
            // written by this program.
            let intent =
                Self::mark_intent_from_sql(&path, true, &is_keeper, &action)?.ok_or_else(|| {
                    PlanRefusal::CorruptMark {
                        path: path.clone(),
                        field: "mark",
                        detail: "neither a keeper nor an action".to_string(),
                    }
                })?;
            if manifest.is_none() {
                return Err(PlanRefusal::NotInManifest { path });
            }
            match digest {
                Some(digest) => out.push((path, intent, digest)),
                None => return Err(PlanRefusal::MissingDigest { path }),
            }
        }
        Ok(out)
    }

    /// Decodes one mark, or refuses. `None` — this pathname carries no mark at all.
    ///
    /// `present` is the row-presence bit, and it is the difference between two things that look
    /// identical in a `LEFT JOIN` result: no `file_mark` row at all, whose columns are `NULL`
    /// because there is nothing to read, and a row that exists with a `NULL` in a column declared
    /// `INTEGER NOT NULL`. The first is an ordinary unmarked member. The second is damaged
    /// evidence, and reading it as «not the keeper» would turn it into whatever its `action` says.
    ///
    /// Strict where the rest of the program can afford not to be. `and_then(ActionKind::parse)`
    /// turns an identifier this build does not know into «no action», and the marked row then
    /// disappears from the plan while the rest of it is accepted — the operator confirms a screen
    /// that is missing something they marked. `is_keeper` is a flag, so on a present row only
    /// SQLite's integer `0` and `1` are that flag. A row that is both a keeper and an action states
    /// two incompatible fates for one pathname and is not something to normalise.
    fn mark_intent_from_sql(
        path: &Path,
        present: bool,
        is_keeper: &Value,
        action: &Value,
    ) -> PlanResult<Option<MarkIntent>> {
        let corrupt = |field: &'static str, value: &Value| PlanRefusal::CorruptMark {
            path: path.to_path_buf(),
            field,
            detail: Self::describe_value(value),
        };
        if !present {
            // Nothing was joined. Any value here would mean the query handed us columns of a row it
            // says does not exist.
            return match (is_keeper, action) {
                (Value::Null, Value::Null) => Ok(None),
                (Value::Null, other) => Err(corrupt("action", other)),
                (other, _) => Err(corrupt("is_keeper", other)),
            };
        }
        let keeper = match is_keeper {
            Value::Integer(0) => false,
            Value::Integer(1) => true,
            other => return Err(corrupt("is_keeper", other)),
        };
        let action = match action {
            Value::Null => None,
            Value::Text(text) => {
                Some(
                    ActionKind::parse(text).ok_or_else(|| PlanRefusal::CorruptMark {
                        path: path.to_path_buf(),
                        field: "action",
                        detail: format!("text {text:?}"),
                    })?,
                )
            }
            other => return Err(corrupt("action", other)),
        };
        match (keeper, action) {
            (true, Some(_)) => Err(PlanRefusal::ContradictoryMark {
                path: path.to_path_buf(),
            }),
            (true, None) => Ok(Some(MarkIntent::Keeper)),
            (false, Some(kind)) => Ok(Some(MarkIntent::Act(kind))),
            (false, None) => Ok(None),
        }
    }

    /// What a cell actually holds, for a refusal an operator can act on.
    fn describe_value(value: &Value) -> String {
        match value {
            Value::Null => "null".to_string(),
            Value::Integer(number) => format!("integer {number}"),
            Value::Real(number) => format!("real {number}"),
            Value::Text(text) => format!("text {text:?}"),
            Value::Blob(bytes) => format!("blob of {} bytes", bytes.len()),
        }
    }

    /// One referenced digest with EVERY persisted member, marked or not, strictly decoded.
    fn plan_group(&self, scan_id: i64, digest: &[u8]) -> PlanResult<PlanGroupInput> {
        let mut stmt = self
            .conn
            .prepare(
                // `m.rowid` is the row-presence bit: a joined row always has one, and no column of
                // it can be `NULL` by accident the way `m.is_keeper` can. Without it a damaged
                // `NULL` in a `NOT NULL` column is indistinguishable from no mark at all.
                "SELECT f.path, f.size, f.mtime, f.mtime_nsec, f.ctime_sec, f.ctime_nsec,
                        f.device, f.inode, f.nlink, f.identity_version,
                        m.is_keeper, m.action, m.rowid
                   FROM file f
                   LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
                  WHERE f.scan_id = ?1 AND f.hash = ?2
                  ORDER BY f.path",
            )
            .map_err(Self::store_refusal)?;
        let rows = stmt
            .query_map(params![scan_id, digest], |row| {
                Ok((
                    PathBuf::from(row.get::<_, String>(0)?),
                    PlanObjectKey {
                        size: row.get::<_, i64>(1)? as u64,
                        mtime: row.get::<_, i64>(2)?,
                        mtime_nsec: row.get::<_, i64>(3)?,
                        ctime_sec: row.get::<_, i64>(4)?,
                        ctime_nsec: row.get::<_, i64>(5)?,
                        device: row.get::<_, i64>(6)? as u64,
                        inode: row.get::<_, i64>(7)? as u64,
                        identity_version: row.get::<_, i64>(9)?,
                    },
                    row.get::<_, Value>(8)?,
                    row.get::<_, Value>(10)?,
                    row.get::<_, Value>(11)?,
                    row.get::<_, Option<i64>>(12)?.is_some(),
                ))
            })
            .map_err(Self::store_refusal)?;
        let mut members = Vec::new();
        for row in rows {
            let (path, key, nlink, is_keeper, action, marked) = row.map_err(Self::store_refusal)?;
            // Strict, unlike `group_file_row`: browsing may show a group whose counts cannot be
            // read, a destructive plan may not be built on one.
            let links =
                link_count_from_sql(&nlink).map_err(|err| PlanRefusal::CorruptLinkCount {
                    path: path.clone(),
                    detail: err.to_string(),
                })?;
            let mark = Self::mark_intent_from_sql(&path, marked, &is_keeper, &action)?;
            members.push(PlanMemberEvidence::new(path, key, links, mark)?);
        }
        Ok(PlanGroupInput {
            hash: hex_encode(digest),
            members,
        })
    }

    /// A read that failed is a refusal like any other — the plan is not built on a half-read
    /// database.
    fn store_refusal(err: impl std::fmt::Display) -> PlanRefusal {
        PlanRefusal::Store {
            detail: err.to_string(),
        }
    }
}

/// Sets the «results prepared» marker on an open transaction, so the marker and the rows it
/// describes commit together. `INSERT OR IGNORE` first — a scan from before `scan_stats` existed
/// has no row to update.
fn mark_prepared(conn: &Connection, scan_id: i64) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO scan_stats(scan_id) VALUES (?1)",
        params![scan_id],
    )?;
    conn.execute(
        "UPDATE scan_stats SET results_materialized = 1 WHERE scan_id = ?1",
        params![scan_id],
    )?;
    Ok(())
}

/// Decodes one `file.nlink` cell — the single gate between that column and the rest of the
/// program, for reading a manifest row and for the planning check alike.
///
/// SQLite's declared `INTEGER` is a type *affinity*, not a domain constraint: in a non-`STRICT`
/// table the cell can hold any storage class, and `1.5` really is stored as `real`, `'oops'` as
/// `text`. Only `integer` reaches the numeric domain check in `LinkCount`; every other class is a
/// damaged or externally modified DB and is refused here, at the store boundary, so the model
/// layer stays free of SQLite.
fn link_count_from_sql(value: &Value) -> Result<LinkCount> {
    if let Value::Integer(raw) = value {
        return LinkCount::from_i64(*raw);
    }
    let class = storage_class(value);
    Err(AppError::msg(format!(
        "dedcom.db holds a link count stored as {class}, not an integer. Rescan, or move the old dedcom.db aside."
    )))
}

/// The columns a group's file rows are read with: the complete temporal identity and the link
/// count beside the marks, so a `FileEntry` never carries a half-filled identity that a later
/// caller would take for the whole one.
const GROUP_FILE_COLUMNS: &str = "f.path, f.size, f.mtime, f.mtime_nsec, f.ctime_sec,
                                  f.ctime_nsec, f.device, f.inode, f.nlink,
                                  m.is_keeper, m.action";

/// Maps a `GROUP_FILE_COLUMNS` row. A link count of an impossible storage class decodes as
/// unknown here rather than failing the read: this is the browsing path, and a group whose counts
/// cannot be trusted is one the publishing gate already refused to give a figure to.
fn group_file_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileEntry> {
    Ok(FileEntry {
        path: PathBuf::from(row.get::<_, String>(0)?),
        size: row.get::<_, i64>(1)? as u64,
        mtime: row.get::<_, i64>(2)?,
        mtime_nsec: row.get::<_, i64>(3)?,
        ctime_sec: row.get::<_, i64>(4)?,
        ctime_nsec: row.get::<_, i64>(5)?,
        device: row.get::<_, i64>(6)? as u64,
        inode: row.get::<_, i64>(7)? as u64,
        nlink: link_count_from_sql(&row.get::<_, Value>(8)?)
            .unwrap_or(LinkCount::Unknown)
            .to_u64(),
        is_keeper: row.get::<_, Option<i64>>(9)?.unwrap_or(0) != 0,
        action: row
            .get::<_, Option<String>>(10)?
            .as_deref()
            .and_then(ActionKind::parse),
    })
}

/// SQLite's name for what a cell actually holds — the same word `typeof()` returns, so a message
/// and the SQL that found the cell say the same thing.
fn storage_class(value: &Value) -> &'static str {
    match value {
        Value::Integer(_) => "integer",
        Value::Null => "null",
        Value::Real(_) => "real",
        Value::Text(_) => "text",
        Value::Blob(_) => "blob",
    }
}

/// Decodes one `file.size` cell for the reclaim arithmetic. Same reasoning as
/// `link_count_from_sql`: a byte count that is not a whole number is not a byte count.
fn size_from_sql(value: &Value, named: &str) -> Result<u64> {
    match value {
        Value::Integer(raw) if *raw >= 0 => Ok(*raw as u64),
        Value::Integer(raw) => Err(AppError::msg(format!(
            "dedcom.db holds a negative file size ({raw}) for {named}. Rescan, or move the old dedcom.db aside."
        ))),
        other => Err(AppError::msg(format!(
            "dedcom.db holds the size of {named} as {}, not an integer. Rescan, or move the old dedcom.db aside.",
            storage_class(other)
        ))),
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

// ---------------------------------------------------------------------------------------------
// The omission ledger.
//
// Inert in R3A: the schema and this API exist, but nothing in a production build records an
// omission or asks for a verdict yet. R3B starts producing, R3D starts consuming, and the
// `allow(dead_code)` goes away with them — the same shape `model::plan` shipped in with R2D-C5-1.
// ---------------------------------------------------------------------------------------------

/// The scan's configured roots as normalized keys, or the typed reason there are none this build
/// can speak for.
enum PersistedRoots {
    /// Every configured root has a key and the keys are mutually disjoint, sorted.
    Keyable(Vec<PathKey>),
    /// Expected: the configuration itself cannot carry an authority.
    Unavailable(AuthorityUnavailable),
}

/// What a clear operation covers.
enum ClearScope {
    /// Every root of the scan.
    WholeScan,
    /// One root and everything under it.
    Root(PathKey),
    /// One directory of one root, and everything under that directory.
    Subtree { root: PathKey, directory: PathKey },
}

// Test-only: fail the Nth row insert of a ledger commit, from INSIDE the transaction.
//
// Thread-local and one-shot, the same design the walk's fault injection uses and for the same
// reason: a rollback assertion has to be about a failure that happens after real rows were
// written, not about validation refusing the call before it ever opened a transaction. Absent
// from every non-test build.
#[cfg(test)]
thread_local! {
    static LEDGER_INSERT_FAULT: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Arms the insert fault for this thread and disarms it on drop.
#[cfg(test)]
struct LedgerInsertFault;

#[cfg(test)]
impl LedgerInsertFault {
    /// Fails the insert that follows `survivors` successful ones.
    fn after(survivors: u32) -> Self {
        LEDGER_INSERT_FAULT.with(|slot| slot.set(Some(survivors)));
        LedgerInsertFault
    }

    /// Whether the armed fault is still waiting — a fault that never fired means the test proved
    /// nothing about rollback.
    fn pending(&self) -> bool {
        LEDGER_INSERT_FAULT.with(|slot| slot.get().is_some())
    }
}

#[cfg(test)]
impl Drop for LedgerInsertFault {
    fn drop(&mut self) {
        LEDGER_INSERT_FAULT.with(|slot| slot.set(None));
    }
}

/// Consumes one step of an armed insert fault, if any.
#[cfg(test)]
fn take_insert_fault() -> bool {
    LEDGER_INSERT_FAULT.with(|slot| match slot.get() {
        Some(0) => {
            slot.set(None);
            true
        }
        Some(remaining) => {
            slot.set(Some(remaining - 1));
            false
        }
        None => false,
    })
}

/// Reports a registration outcome once, where an operator can see it. An unavailable authority is
/// an expected state of the operator's own configuration, not a failure — the scan runs exactly as
/// it always did and simply cannot claim anything about completeness.
fn log_registration(scan_id: i64, registration: &RootRegistration) {
    match registration {
        RootRegistration::Registered { roots } => {
            tracing::debug!("scan {scan_id}: {roots} completeness root(s) registered")
        }
        RootRegistration::Unavailable(why) => tracing::info!(
            "scan {scan_id}: directory completeness will be reported as unknown — {}",
            why.explain()
        ),
    }
}

/// The scan's roots, as persisted in its own configuration.
fn persisted_roots_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<Vec<PathBuf>> {
    let json: String = tx.query_row(
        "SELECT config_json FROM scan WHERE id = ?1",
        params![scan_id],
        |row| row.get(0),
    )?;
    let config: ScanConfig = serde_json::from_str(&json)?;
    Ok(config.roots)
}

/// The scan's registered authorities: normalized root key and its generation.
fn registered_roots_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<Vec<(PathKey, i64)>> {
    let mut stmt = tx.prepare(
        "SELECT root_key, generation FROM scan_root WHERE scan_id = ?1 ORDER BY root_key",
    )?;
    let rows = stmt.query_map(params![scan_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (raw, generation) = row?;
        if generation < 0 {
            return Err(AppError::msg(format!(
                "dedcom.db holds a corrupt completeness generation ({generation}); rescan, or move the old dedcom.db aside."
            )));
        }
        out.push((PathKey::from_stored(&raw)?, generation));
    }
    Ok(out)
}

/// The scan's own configuration, reduced to normalized root keys — or the typed reason it cannot
/// be.
///
/// The ONE derivation of «which roots may this scan speak for». Registration, the commit and the
/// reader all go through it, so the persisted configuration and the registered authority cannot
/// drift apart in one path while another still trusts them. A configuration problem is an
/// outcome; a malformed `config_json` or a storage failure is an error, and the two never swap
/// places.
fn persisted_root_keys_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<PersistedRoots> {
    let roots = persisted_roots_tx(tx, scan_id)?;
    if roots.is_empty() {
        return Ok(PersistedRoots::Unavailable(AuthorityUnavailable::NoRoots));
    }

    let mut keys: Vec<PathKey> = Vec::with_capacity(roots.len());
    for root in &roots {
        match PathKey::new(root) {
            Some(key) => keys.push(key),
            None => {
                return Ok(PersistedRoots::Unavailable(
                    AuthorityUnavailable::UnkeyableRoot {
                        given: root.display().to_string(),
                    },
                ))
            }
        }
    }
    // Root validation compares canonicalized paths and skips the comparison entirely when either
    // path cannot be resolved, so a pair that does not exist yet reaches this point undetected.
    // Lexically overlapping keys would attribute one directory to two roots, so they get no
    // authority at all.
    for (index, outer) in keys.iter().enumerate() {
        for inner in keys.iter().skip(index + 1) {
            if inner.is_at_or_under(outer) || outer.is_at_or_under(inner) {
                let (outer, inner) = if inner.is_at_or_under(outer) {
                    (outer, inner)
                } else {
                    (inner, outer)
                };
                return Ok(PersistedRoots::Unavailable(
                    AuthorityUnavailable::AmbiguousRoots {
                        outer: outer.as_str().to_string(),
                        inner: inner.as_str().to_string(),
                    },
                ));
            }
        }
    }
    keys.sort();
    Ok(PersistedRoots::Keyable(keys))
}

/// Deletes every ledger row and every authority row of the scan. Used where a configuration stops
/// being one this build can speak for: the rows that survive such a moment are precisely the ones
/// that would keep a stale positive generation alive.
fn revoke_authority_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<()> {
    tx.execute(
        "DELETE FROM dir_omission WHERE scan_id = ?1",
        params![scan_id],
    )?;
    tx.execute("DELETE FROM scan_root WHERE scan_id = ?1", params![scan_id])?;
    Ok(())
}

/// Registers the scan's roots as completeness authorities, idempotently.
///
/// All-or-nothing: if any configured root has no lexical key, or two keys overlap once normalized,
/// the scan gets no authority — and any authority it already had is revoked in this same
/// transaction. Returning early instead would leave a positive generation standing for a
/// configuration this very call has just declared unspeakable, which is a trusted answer about a
/// root nobody can name. Refusing to start the scan is not the alternative: this is a verdict
/// about completeness, not a gate on scanning.
///
/// Existing rows keep their generation while the configuration still matches — re-registration
/// must not silently re-trust or re-doubt a root. A row for a root that is no longer configured is
/// removed together with its ledger rows.
fn ensure_roots_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<RootRegistration> {
    let keys = match persisted_root_keys_tx(tx, scan_id)? {
        PersistedRoots::Keyable(keys) => keys,
        PersistedRoots::Unavailable(why) => {
            revoke_authority_tx(tx, scan_id)?;
            return Ok(RootRegistration::Unavailable(why));
        }
    };

    for (stored, _) in registered_roots_tx(tx, scan_id)? {
        if !keys.contains(&stored) {
            tx.execute(
                "DELETE FROM dir_omission WHERE scan_id = ?1 AND root_key = ?2",
                params![scan_id, stored.as_str()],
            )?;
            tx.execute(
                "DELETE FROM scan_root WHERE scan_id = ?1 AND root_key = ?2",
                params![scan_id, stored.as_str()],
            )?;
        }
    }
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO scan_root(scan_id, root_key, generation) VALUES (?1, ?2, 0)",
        )?;
        for key in &keys {
            stmt.execute(params![scan_id, key.as_str()])?;
        }
    }
    Ok(RootRegistration::Registered { roots: keys.len() })
}

/// Zeroes the generation of one root, or of every root of the scan. Always issued in the same
/// transaction as the delete it accompanies: an authority left standing over deleted rows is
/// exactly the window that reads as «nothing was omitted here».
fn zero_generations_tx(tx: &Transaction<'_>, scan_id: i64, root: Option<&PathKey>) -> Result<()> {
    match root {
        Some(key) => tx.execute(
            "UPDATE scan_root SET generation = 0 WHERE scan_id = ?1 AND root_key = ?2",
            params![scan_id, key.as_str()],
        )?,
        None => tx.execute(
            "UPDATE scan_root SET generation = 0 WHERE scan_id = ?1",
            params![scan_id],
        )?,
    };
    Ok(())
}

/// Deletes ledger rows in one scope.
fn delete_ledger_tx(tx: &Transaction<'_>, scan_id: i64, scope: &ClearScope) -> Result<()> {
    match scope {
        ClearScope::WholeScan => {
            tx.execute(
                "DELETE FROM dir_omission WHERE scan_id = ?1",
                params![scan_id],
            )?;
        }
        ClearScope::Root(root) => {
            tx.execute(
                "DELETE FROM dir_omission WHERE scan_id = ?1 AND root_key = ?2",
                params![scan_id, root.as_str()],
            )?;
        }
        ClearScope::Subtree { root, directory } => {
            let (lo, hi) = directory.subtree_bounds();
            tx.execute(
                "DELETE FROM dir_omission
                  WHERE scan_id = ?1 AND root_key = ?2
                    AND (dir_key = ?3 OR (dir_key >= ?4 AND dir_key < ?5))",
                params![scan_id, root.as_str(), directory.as_str(), lo, hi],
            )?;
        }
    }
    Ok(())
}

/// The generation a new snapshot takes: one above anything the scan has ever used.
///
/// Reads both tables, because a row must never be able to claim a generation the authority has
/// already left behind. Checked — an authority sitting at `i64::MAX` refuses to advance rather
/// than wrapping into a generation some older row already carries.
fn next_generation_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<i64> {
    let highest: i64 = tx.query_row(
        "SELECT MAX(used) FROM (
             SELECT COALESCE(MAX(generation), 0) AS used FROM scan_root    WHERE scan_id = ?1
             UNION ALL
             SELECT COALESCE(MAX(generation), 0) AS used FROM dir_omission WHERE scan_id = ?1
         )",
        params![scan_id],
        |row| row.get(0),
    )?;
    highest.checked_add(1).ok_or_else(|| {
        AppError::msg(
            "this scan's completeness generation cannot advance any further; rescan into a fresh session",
        )
    })
}

/// Reads the verdicts for `dirs` from an open transaction.
///
/// The production query helper: the public method is this function plus the transaction that
/// makes it a snapshot, and the concurrency test drives exactly this, so a passing test cannot be
/// about a query that merely resembles the real one.
fn directory_completeness_tx(
    tx: &Transaction<'_>,
    scan_id: i64,
    dirs: &[&Path],
) -> Result<HashMap<PathBuf, DirCompleteness>> {
    // The registered authority is only worth reading while it still describes the scan's own
    // configuration. Checked HERE, inside the same snapshot as everything else, because an
    // explicit re-registration is what cleans stale rows and nothing guarantees one has run yet:
    // the interval between a configuration changing and the next `ensure_scan_roots` would
    // otherwise be a window of trusted answers about roots the scan no longer has.
    let registered = registered_roots_tx(tx, scan_id)?;
    let agrees = match persisted_root_keys_tx(tx, scan_id)? {
        PersistedRoots::Unavailable(_) => false,
        PersistedRoots::Keyable(persisted) => {
            let mut names: Vec<&PathKey> = registered.iter().map(|(key, _)| key).collect();
            names.sort();
            names.len() == persisted.len()
                && names.into_iter().zip(persisted.iter()).all(|(a, b)| a == b)
        }
    };
    // Not an error: a configuration this build cannot speak for is an expected state, and the
    // honest answer about every directory of such a scan is «unknown». A malformed `config_json`
    // or a storage failure already returned above, as an error.
    let roots: &[(PathKey, i64)] = if agrees { &registered } else { &[] };

    // The `dir_key = root_key` walk-error row is the root-wide sentinel: an iterator error that
    // carried no pathname at all could stand for any part of that tree, so it is included for
    // every directory the root owns — not only for the root and its ancestors. The ordinary range
    // propagates a row UPWARD, which is exactly why a row parked at the root would otherwise reach
    // no child at all.
    //
    // A path-known walk error that genuinely lands at the root is over-tainted by this, and that
    // is the deliberate trade: without a scope column the two rows are indistinguishable, and
    // over-tainting costs a twin claim while under-tainting costs the truth. Every other reason
    // stored at the root taints the root and its ancestors only, as usual.
    //
    // One statement with three disjuncts rather than two queries: a row satisfying more than one
    // of them is still one row in one `GROUP BY`, so nothing is counted twice.
    let mut stmt = tx.prepare(
        "SELECT reason, SUM(event_count) FROM dir_omission
          WHERE scan_id = ?1 AND root_key = ?2 AND generation = ?3
            AND (dir_key = ?4
                 OR (dir_key >= ?5 AND dir_key < ?6)
                 OR (reason = ?7 AND dir_key = ?2))
          GROUP BY reason
          ORDER BY reason",
    )?;

    let mut out = HashMap::with_capacity(dirs.len());
    for dir in dirs {
        let verdict = match PathKey::new(dir) {
            None => DirCompleteness::Unknown,
            Some(key) => {
                // Exactly one root may own a directory. Registration refuses an overlapping set,
                // so a second match cannot arise from a scan this build wrote; if one is there
                // anyway, refusing to choose is the only safe answer.
                let mut owning = roots.iter().filter(|(root, _)| key.is_at_or_under(root));
                match (owning.next(), owning.next()) {
                    (Some((root, generation)), None) if *generation > 0 => {
                        let (lo, hi) = key.subtree_bounds();
                        let rows = stmt.query_map(
                            params![
                                scan_id,
                                root.as_str(),
                                generation,
                                key.as_str(),
                                lo,
                                hi,
                                OmissionReason::WalkError.as_str(),
                            ],
                            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                        )?;
                        let mut summary = OmissionSummary::default();
                        for row in rows {
                            let (raw, total) = row?;
                            // An unrecognized reason is never folded into «complete»: the public
                            // result is an error, so a future value cannot make a directory look
                            // whole to a build that does not understand it.
                            let reason = OmissionReason::parse(&raw).ok_or_else(|| {
                                AppError::msg(format!(
                                    "dedcom.db records an omission reason this build does not know ({}); upgrade dedcom, or move the old dedcom.db aside.",
                                    crate::textsan::terminal(&raw)
                                ))
                            })?;
                            summary.add(reason, EventCount::from_i64(total)?)?;
                        }
                        if summary.is_empty() {
                            DirCompleteness::Complete
                        } else {
                            DirCompleteness::Incomplete(summary)
                        }
                    }
                    _ => DirCompleteness::Unknown,
                }
            }
        };
        out.insert(dir.to_path_buf(), verdict);
    }
    Ok(out)
}

#[allow(dead_code)]
impl ScanStore {
    /// Registers the scan's roots as completeness authorities and reports what happened.
    ///
    /// The outcome is typed rather than an error: `Unavailable` is an expected state of the
    /// operator's configuration, while a SQLite, I/O or constraint failure stays an `Err`. Folding
    /// the two together would let a broken checkpoint pass for a merely unkeyable one.
    pub fn ensure_scan_roots(&mut self, scan_id: i64) -> Result<RootRegistration> {
        let tx = self.conn.transaction()?;
        let registration = ensure_roots_tx(&tx, scan_id)?;
        tx.commit()?;
        log_registration(scan_id, &registration);
        Ok(registration)
    }

    /// Whether this root currently carries a trusted ledger, and at which generation. `None` when
    /// the root is not registered at all.
    pub fn root_generation(&self, scan_id: i64, root: &Path) -> Result<Option<i64>> {
        let Some(key) = PathKey::new(root) else {
            return Ok(None);
        };
        let tx = self.conn.unchecked_transaction()?;
        let found = registered_roots_tx(&tx, scan_id)?
            .into_iter()
            .find(|(stored, _)| *stored == key)
            .map(|(_, generation)| generation);
        Ok(found)
    }

    /// Writes the whole scan's omission ledger and advances every root's generation, in ONE
    /// transaction.
    ///
    /// `per_root` must carry EXACTLY the scan's registered root keys. A root that omitted nothing
    /// must still appear, with an empty count map: that explicit entry is the only thing proving
    /// the root was walked under the contract at all. A missing root, an extra root, or a scan
    /// with no registered roots refuses the whole call and writes nothing — a subset could
    /// otherwise buy trust for roots nobody looked at.
    ///
    /// Idempotent: the scan's previous rows are replaced wholesale, so committing the same walk
    /// twice leaves the same ledger (at a new generation).
    pub fn commit_omissions(
        &mut self,
        scan_id: i64,
        per_root: &BTreeMap<PathKey, OmissionCounts>,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;

        // Three sets must agree before a new generation is published: what the scan is configured
        // to cover, what it is registered to speak for, and what the producer is reporting.
        // Comparing the map against the registration alone would let a configuration that has
        // moved on still buy trust, because the registration is only refreshed by an explicit
        // call that may not have happened yet.
        let persisted = match persisted_root_keys_tx(&tx, scan_id)? {
            PersistedRoots::Keyable(keys) => keys,
            PersistedRoots::Unavailable(why) => {
                return Err(AppError::msg(format!(
                    "scan {scan_id} cannot publish an omission ledger: {}",
                    why.explain()
                )))
            }
        };
        let mut registered: Vec<PathKey> = registered_roots_tx(&tx, scan_id)?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        registered.sort();
        if registered.is_empty() {
            return Err(AppError::msg(format!(
                "scan {scan_id} has no registered completeness roots, so its omission ledger cannot be committed"
            )));
        }
        if registered != persisted {
            return Err(AppError::msg(format!(
                "scan {scan_id} has drifted from its registered completeness roots; re-register them before committing an omission ledger"
            )));
        }
        for key in &registered {
            if !per_root.contains_key(key) {
                return Err(AppError::msg(format!(
                    "the omission ledger is missing scan root {}; every selected root must be reported, with an empty count when nothing was omitted",
                    crate::textsan::terminal(key.as_str())
                )));
            }
        }
        for key in per_root.keys() {
            if !registered.contains(key) {
                return Err(AppError::msg(format!(
                    "the omission ledger names {}, which is not a selected root of scan {scan_id}",
                    crate::textsan::terminal(key.as_str())
                )));
            }
        }
        for (root, counts) in per_root {
            for (directory, _, _) in counts.iter() {
                if !directory.is_at_or_under(root) {
                    return Err(AppError::msg(format!(
                        "the omission ledger places {} outside its scan root {}",
                        crate::textsan::terminal(directory.as_str()),
                        crate::textsan::terminal(root.as_str())
                    )));
                }
            }
        }

        let generation = next_generation_tx(&tx, scan_id)?;
        delete_ledger_tx(&tx, scan_id, &ClearScope::WholeScan)?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO dir_omission
                     (scan_id, root_key, dir_key, reason, event_count, generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for (root, counts) in per_root {
                for (directory, reason, count) in counts.iter() {
                    #[cfg(test)]
                    if take_insert_fault() {
                        return Err(AppError::msg("injected ledger insert fault"));
                    }
                    stmt.execute(params![
                        scan_id,
                        root.as_str(),
                        directory.as_str(),
                        reason.as_str(),
                        count.to_i64()?,
                        generation,
                    ])?;
                }
            }
        }
        tx.execute(
            "UPDATE scan_root SET generation = ?2 WHERE scan_id = ?1",
            params![scan_id, generation],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Invalidates one subtree before it is re-walked: its rows go, and so does its root's
    /// authority. The subtree is part of that root's snapshot, so once a piece is missing the
    /// snapshot is no longer whole — leaving the generation alone would publish the remaining
    /// rows as a complete answer.
    pub fn clear_omissions_under(&mut self, scan_id: i64, directory: &Path) -> Result<()> {
        let tx = self.conn.transaction()?;
        let key = PathKey::new(directory).ok_or_else(|| {
            AppError::msg(format!(
                "{} cannot be used as a completeness key",
                crate::textsan::terminal(&directory.display().to_string())
            ))
        })?;
        let root = registered_roots_tx(&tx, scan_id)?
            .into_iter()
            .map(|(root, _)| root)
            .find(|root| key.is_at_or_under(root))
            .ok_or_else(|| {
                AppError::msg(format!(
                    "{} is not inside any selected root of scan {scan_id}",
                    crate::textsan::terminal(key.as_str())
                ))
            })?;
        delete_ledger_tx(
            &tx,
            scan_id,
            &ClearScope::Subtree {
                root: root.clone(),
                directory: key,
            },
        )?;
        zero_generations_tx(&tx, scan_id, Some(&root))?;
        tx.commit()?;
        Ok(())
    }

    /// Invalidates one root entirely — the replacement case. Other roots keep their authority,
    /// which is why the authority is per root at all.
    pub fn clear_root_omissions(&mut self, scan_id: i64, root: &Path) -> Result<()> {
        let tx = self.conn.transaction()?;
        let key = PathKey::new(root).ok_or_else(|| {
            AppError::msg(format!(
                "{} cannot be used as a completeness key",
                crate::textsan::terminal(&root.display().to_string())
            ))
        })?;
        if !registered_roots_tx(&tx, scan_id)?
            .iter()
            .any(|(stored, _)| *stored == key)
        {
            return Err(AppError::msg(format!(
                "{} is not a selected root of scan {scan_id}",
                crate::textsan::terminal(key.as_str())
            )));
        }
        delete_ledger_tx(&tx, scan_id, &ClearScope::Root(key.clone()))?;
        zero_generations_tx(&tx, scan_id, Some(&key))?;
        tx.commit()?;
        Ok(())
    }

    /// Invalidates the whole scan's ledger: every row goes and every root loses its authority.
    pub fn clear_scan_omissions(&mut self, scan_id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        delete_ledger_tx(&tx, scan_id, &ClearScope::WholeScan)?;
        zero_generations_tx(&tx, scan_id, None)?;
        tx.commit()?;
        Ok(())
    }

    /// What the checkpoint knows about each of `dirs`.
    ///
    /// Takes no root set: it reads the scan's own registered roots, so a consumer cannot supply
    /// the wrong ones. Everything — the roots, their generations and every requested directory —
    /// is read inside ONE deferred transaction, which in WAL is a real snapshot; preparing
    /// statements in a shared scope is not. Between two autocommit reads another copy of the
    /// program can commit a whole new generation, and an answer assembled half from each is an
    /// answer no state of the checkpoint ever had.
    pub fn directory_completeness(
        &self,
        scan_id: i64,
        dirs: &[&Path],
    ) -> Result<HashMap<PathBuf, DirCompleteness>> {
        let snapshot = self.conn.unchecked_transaction()?;
        directory_completeness_tx(&snapshot, scan_id, dirs)
    }
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
        let candidates = store.candidate_objects(scan_id).unwrap();
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
        let reclaim = groups[0].physical_reclaim().unwrap();
        assert_eq!(reclaim.object_count, 2);
        assert_eq!(reclaim.estimate.guaranteed_bytes(), 100);
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
            nlink: 1,
        };
        // Its own inode: two independent objects of one size, which is what this test is about.
        // (An actual alias of `/x/a` would now receive the digest by propagation — that contract
        // has its own tests.)
        let b = ManifestRow {
            path: PathBuf::from("/x/b"),
            inode: 3,
            ..a.clone()
        };
        store.record_files(id, &[a.clone(), b.clone()]).unwrap();
        let h = [3u8; 32];

        // Matching identity → committed: 1 row, its size (persisted delta).
        let p = store.record_hashes_verified(id, &[(a, h)]).unwrap();
        assert_eq!((p.files, p.bytes), (1, 100), "1 row committed, 100 bytes");
        assert_eq!(p.representatives, 1, "and it was the representative itself");
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
            nlink: 1,
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
        let candidates = store.candidate_objects(scan_id).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, PathBuf::from("/b"));
    }

    /// A manifest row for one ordinary file: its own inode, one link, and no unrecorded
    /// counts — the shape reclaim tests need unless they say otherwise.
    fn row(path: &str, size: u64, inode: u64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size,
            mtime: 0,
            device: 1,
            inode,
            nlink: 1,
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
        assert_eq!(store.candidate_objects(b).unwrap().len(), 2);
        // Inheritance (as `run_phases` does before `hash_phase` on resume).
        assert_eq!(
            store.inherit_hashes(b).unwrap(),
            2,
            "both inherited from #A"
        );
        // Now there is nothing to read from disk.
        assert!(
            store.candidate_objects(b).unwrap().is_empty(),
            "after inherit candidate_objects is empty → 0 disk reads"
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

    // === physical-object results ===
    //
    // Every regression below is published through BOTH paths by `published_both_ways`, so «the
    // SQL aggregation and the --verify path agree» is not one test that could rot while the rest
    // pass — it is the only way these tests can be written.

    /// The shared payload size in the regressions: `S` in the checkpoint's matrix.
    const S: u64 = 4096;

    /// A manifest row that names its own allocation explicitly.
    fn object_row(path: &str, size: u64, inode: u64, nlink: u64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size,
            mtime: 11,
            mtime_nsec: 22,
            ctime_sec: 33,
            ctime_nsec: 44,
            device: 1,
            inode,
            nlink,
        }
    }

    /// Seeds a scan with `rows` and gives every named pathname its digest.
    fn seed_objects(store: &mut ScanStore, rows: &[ManifestRow], hashed: &[(&str, u8)]) -> i64 {
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store.record_files(scan_id, rows).unwrap();
        let hashes: Vec<(PathBuf, [u8; 32])> = hashed
            .iter()
            .map(|(path, digest)| (PathBuf::from(*path), [*digest; 32]))
            .collect();
        store.record_hashes(scan_id, &hashes).unwrap();
        scan_id
    }

    /// One published group row, flattened for comparison:
    /// `(rank, hash, pathnames, size, allocations, state, guaranteed, potential)`.
    type PublishedGroup = (i64, String, u64, u64, u64, ReclaimState, u64, Option<u64>);

    /// What one publishing path produced: the group rows, the scan total and the informational
    /// already-linked count.
    #[derive(Debug, PartialEq)]
    struct Published {
        groups: Vec<PublishedGroup>,
        scan: (ReclaimState, u64, Option<u64>),
        already_linked_sets: u64,
    }

    fn published(store: &ScanStore, scan_id: i64) -> Published {
        let scan = store.scan_reclaim(scan_id).unwrap();
        Published {
            groups: store
                .group_summaries(scan_id)
                .unwrap()
                .into_iter()
                .map(|group| {
                    (
                        group.rank,
                        group.hash,
                        group.file_count,
                        group.size_bytes,
                        group.object_count,
                        group.reclaim.state(),
                        group.reclaim.guaranteed_bytes(),
                        group.reclaim.potential_bytes(),
                    )
                })
                .collect(),
            scan: (
                scan.state(),
                scan.guaranteed_bytes(),
                scan.potential_bytes(),
            ),
            already_linked_sets: store.already_linked_sets(scan_id).unwrap(),
        }
    }

    /// Publishes the same manifest through the SQL path and the RAM/`--verify` path, asserts the
    /// two are identical down to the row order, and returns what they agreed on.
    fn published_both_ways(seed: impl Fn(&mut ScanStore) -> i64) -> Published {
        let mut sql = ScanStore::open_in_memory().unwrap();
        let sql_id = seed(&mut sql);
        sql.materialize_file_groups(sql_id).unwrap();

        let mut ram = ScanStore::open_in_memory().unwrap();
        let ram_id = seed(&mut ram);
        let groups = ram.duplicate_groups(ram_id).unwrap();
        ram.record_file_results(ram_id, &groups).unwrap();

        let (from_sql, from_ram) = (published(&sql, sql_id), published(&ram, ram_id));
        assert_eq!(
            from_sql, from_ram,
            "the SQL aggregation and the --verify path must publish the same result"
        );
        assert!(sql.results_materialized(sql_id).unwrap());
        assert!(ram.results_materialized(ram_id).unwrap());
        from_sql
    }

    /// A set of aliases is one allocation: nothing to free, nothing to group, and every pathname
    /// still in the manifest. It is never hashed either, which is exactly why the informational
    /// count cannot depend on hashing.
    #[test]
    fn an_alias_only_set_is_not_a_group_and_is_counted_separately() {
        let result = published_both_ways(|store| {
            seed_objects(
                store,
                &[
                    object_row("/x/a1", S, 7, 3),
                    object_row("/x/a2", S, 7, 3),
                    object_row("/x/a3", S, 7, 3),
                ],
                &[("/x/a1", 1), ("/x/a2", 1), ("/x/a3", 1)],
            )
        });
        assert!(
            result.groups.is_empty(),
            "one allocation is not a duplicate"
        );
        assert_eq!(result.scan, (ReclaimState::Exact, 0, Some(0)));
        assert_eq!(
            result.already_linked_sets, 1,
            "the set is reported even though it never became a group"
        );

        // The pathnames themselves are untouched — nothing was collapsed away to make the group
        // disappear.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_objects(
            &mut store,
            &[
                object_row("/x/a1", S, 7, 3),
                object_row("/x/a2", S, 7, 3),
                object_row("/x/a3", S, 7, 3),
            ],
            &[("/x/a1", 1), ("/x/a2", 1), ("/x/a3", 1)],
        );
        store.materialize_file_groups(scan_id).unwrap();
        assert_eq!(store.manifest_count(scan_id).unwrap(), 3);
    }

    /// The control that must not move: two ordinary copies free exactly one of them.
    #[test]
    fn two_independent_copies_are_an_exact_group() {
        let result = published_both_ways(|store| {
            seed_objects(
                store,
                &[object_row("/x/a", S, 1, 1), object_row("/x/b", S, 2, 1)],
                &[("/x/a", 1), ("/x/b", 1)],
            )
        });
        assert_eq!(result.groups.len(), 1);
        let (_, _, paths, size, objects, state, guaranteed, potential) = &result.groups[0];
        assert_eq!((*paths, *size, *objects), (2, S, 2));
        assert_eq!(*state, ReclaimState::Exact);
        assert_eq!((*guaranteed, *potential), (S, Some(S)));
        assert_eq!(result.scan, (ReclaimState::Exact, S, Some(S)));
        assert_eq!(result.already_linked_sets, 0);
    }

    /// The mixed group: three pathnames, two allocations, and the answer is `S` — the pathname
    /// formula's `2S` is one allocation that does not exist.
    #[test]
    fn a_mixed_group_frees_one_allocation_not_one_per_pathname() {
        let result = published_both_ways(|store| {
            seed_objects(
                store,
                &[
                    object_row("/x/a1", S, 7, 2),
                    object_row("/x/a2", S, 7, 2),
                    object_row("/x/b", S, 9, 1),
                ],
                &[("/x/a1", 1), ("/x/a2", 1), ("/x/b", 1)],
            )
        });
        assert_eq!(result.groups.len(), 1);
        let (_, _, paths, _, objects, state, guaranteed, potential) = &result.groups[0];
        assert_eq!(
            (*paths, *objects),
            (3, 2),
            "every pathname is kept, and both counts are visible"
        );
        assert_eq!(*state, ReclaimState::Exact);
        assert_eq!((*guaranteed, *potential), (S, Some(S)), "S, never 2S");
        assert_eq!(
            result.already_linked_sets, 1,
            "the alias pair contributes to the informational count exactly once"
        );
    }

    /// A link the scan never saw is a link that still holds the bytes. The ceiling survives, the
    /// promise does not, and the numbers behind that verdict are visible.
    #[test]
    fn an_unobserved_external_link_makes_the_group_an_upper_bound() {
        let result = published_both_ways(|store| {
            seed_objects(
                store,
                &[
                    object_row("/x/seen", S, 7, 2), // its other link lives outside the scan
                    object_row("/x/twin", S, 9, 1),
                ],
                &[("/x/seen", 1), ("/x/twin", 1)],
            )
        });
        assert_eq!(result.groups.len(), 1);
        let (_, hash, paths, _, objects, state, guaranteed, potential) = &result.groups[0];
        assert_eq!((*paths, *objects), (2, 2));
        assert_eq!(*state, ReclaimState::UpperBound);
        assert_eq!((*guaranteed, *potential), (0, Some(S)));
        assert_eq!(result.scan, (ReclaimState::UpperBound, 0, Some(S)));

        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_objects(
            &mut store,
            &[
                object_row("/x/seen", S, 7, 2),
                object_row("/x/twin", S, 9, 1),
            ],
            &[("/x/seen", 1), ("/x/twin", 1)],
        );
        store.materialize_file_groups(scan_id).unwrap();
        let links = store.group_links(scan_id, hash).unwrap();
        assert_eq!(
            (links.observed, links.total),
            (2, LinkCount::Known(3)),
            "2 pathnames against 1 + 2 links: summed once per allocation, not once per pathname"
        );
    }

    /// More pathnames of an allocation than its inode has links cannot be true. Refuse, and leave
    /// nothing behind — no rows, no marker, no total.
    #[test]
    fn more_pathnames_than_links_refuses_and_leaves_no_partial_result() {
        for verify in [false, true] {
            let mut store = ScanStore::open_in_memory().unwrap();
            let scan_id = seed_objects(
                &mut store,
                &[
                    object_row("/x/a1", S, 7, 1), // two pathnames, one claimed link
                    object_row("/x/a2", S, 7, 1),
                    object_row("/x/b", S, 9, 1),
                ],
                &[("/x/a1", 1), ("/x/a2", 1), ("/x/b", 1)],
            );
            let err = if verify {
                let groups = store.duplicate_groups(scan_id).unwrap();
                store.record_file_results(scan_id, &groups).unwrap_err()
            } else {
                store.materialize_file_groups(scan_id).unwrap_err()
            };
            assert!(
                err.to_string().contains("cannot be right"),
                "the refusal must name the cause: {err}"
            );
            assert!(
                store.group_summaries(scan_id).unwrap().is_empty(),
                "a refused result leaves no rows"
            );
            assert!(
                !store.results_materialized(scan_id).unwrap(),
                "a refused result leaves no marker"
            );
            assert_eq!(
                store.scan_reclaim(scan_id).unwrap().potential_bytes(),
                None,
                "a refused result leaves no trusted total"
            );
        }
    }

    /// Aliases of one allocation reporting different link counts must be refused by BOTH
    /// publishing paths, and neither may leave anything behind.
    ///
    /// The rows and digests are seeded straight into the manifest, deliberately bypassing
    /// `candidate_objects` — that is where C3a already refuses this corruption during a real scan,
    /// and going through it would prove nothing about what the publishing paths do when a
    /// checkpoint is damaged after hashing, or written by something else.
    #[test]
    fn aliases_that_disagree_about_the_link_count_refuse_on_both_paths() {
        let seed = |store: &mut ScanStore| {
            seed_objects(
                store,
                &[
                    object_row("/x/a1", S, 7, 2),
                    object_row("/x/a2", S, 7, 1), // the same inode, a different count
                    object_row("/x/b", S, 9, 1),
                ],
                &[("/x/a1", 1), ("/x/a2", 1), ("/x/b", 1)],
            )
        };
        for verify in [false, true] {
            let mut store = ScanStore::open_in_memory().unwrap();
            let scan_id = seed(&mut store);
            let err = if verify {
                let groups = store.duplicate_groups(scan_id).unwrap();
                store.record_file_results(scan_id, &groups).unwrap_err()
            } else {
                store.materialize_file_groups(scan_id).unwrap_err()
            };
            assert!(
                err.to_string().contains("different link counts"),
                "both paths must name the same condition ({}): {err}",
                if verify { "RAM/--verify" } else { "SQL" }
            );
            assert!(
                store.group_summaries(scan_id).unwrap().is_empty(),
                "a refused result leaves no rows"
            );
            assert!(
                !store.results_materialized(scan_id).unwrap(),
                "a refused result leaves no marker"
            );
            assert_eq!(
                store.scan_reclaim(scan_id).unwrap().potential_bytes(),
                None,
                "a refused result leaves no trusted total"
            );
        }
    }

    /// A ceiling that leaves the persisted integer domain is refused on both paths. SQLite answers
    /// an overflowing `*` with a `REAL`, which is how a byte count would quietly become an
    /// approximation; the Rust path would have to wrap. Neither is allowed to happen.
    #[test]
    fn a_reclaim_ceiling_outside_the_integer_domain_refuses_on_both_paths() {
        let huge = (i64::MAX / 2) as u64 + 1;
        let seed = |store: &mut ScanStore| {
            seed_objects(
                store,
                &[
                    object_row("/x/a", huge, 1, 1),
                    object_row("/x/b", huge, 2, 1),
                    object_row("/x/c", huge, 3, 1),
                ],
                &[("/x/a", 1), ("/x/b", 1), ("/x/c", 1)],
            )
        };
        for verify in [false, true] {
            let mut store = ScanStore::open_in_memory().unwrap();
            let scan_id = seed(&mut store);
            let err = if verify {
                let groups = store.duplicate_groups(scan_id).unwrap();
                store.record_file_results(scan_id, &groups).unwrap_err()
            } else {
                store.materialize_file_groups(scan_id).unwrap_err()
            };
            assert!(
                err.to_string().contains("does not fit"),
                "the refusal must name the cause: {err}"
            );
            assert!(store.group_summaries(scan_id).unwrap().is_empty());
            assert!(!store.results_materialized(scan_id).unwrap());
        }
    }

    /// Bare `(device, inode)` would call these one allocation and hide a whole copy. The complete
    /// temporal key is what tells them apart.
    #[test]
    fn a_reused_inode_is_a_different_allocation() {
        let result = published_both_ways(|store| {
            let mut reused = object_row("/x/b", S, 7, 1);
            reused.ctime_sec = 999;
            seed_objects(
                store,
                &[object_row("/x/a", S, 7, 1), reused],
                &[("/x/a", 1), ("/x/b", 1)],
            )
        });
        assert_eq!(result.groups.len(), 1);
        let (_, _, paths, _, objects, state, guaranteed, _) = &result.groups[0];
        assert_eq!(
            (*paths, *objects),
            (2, 2),
            "the temporal key separates them"
        );
        assert_eq!((*state, *guaranteed), (ReclaimState::Exact, S));
        assert_eq!(
            result.already_linked_sets, 0,
            "two allocations sharing an inode number are not an already-linked set"
        );
    }

    /// A scan with nothing to say says exactly that: exact zero, and it stays that way on reopen.
    #[test]
    fn a_scan_without_duplicates_is_an_exact_zero() {
        let result = published_both_ways(|store| {
            seed_objects(
                store,
                &[object_row("/x/a", S, 1, 1), object_row("/x/u", S / 2, 2, 1)],
                &[("/x/a", 1), ("/x/u", 2)],
            )
        });
        assert!(result.groups.is_empty());
        assert_eq!(result.scan, (ReclaimState::Exact, 0, Some(0)));

        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_objects(
            &mut store,
            &[object_row("/x/a", S, 1, 1), object_row("/x/u", S / 2, 2, 1)],
            &[("/x/a", 1), ("/x/u", 2)],
        );
        store.materialize_file_groups(scan_id).unwrap();
        store.ensure_materialized(scan_id).unwrap();
        assert_eq!(
            store.scan_reclaim(scan_id).unwrap().potential_bytes(),
            Some(0),
            "reopening an exact zero does not turn it into an unknown"
        );
    }

    /// Mixed results are where the order matters: what is guaranteed leads, and the scan total keeps
    /// the guarantee and the ceiling apart.
    #[test]
    fn mixed_groups_order_by_guarantee_and_total_honestly() {
        let result = published_both_ways(|store| {
            seed_objects(
                store,
                &[
                    // An upper-bound group with the LARGEST ceiling — it must still rank below
                    // every exact group, because a ceiling is not a payoff.
                    object_row("/x/big_seen", 8 * S, 1, 2),
                    object_row("/x/big_twin", 8 * S, 2, 1),
                    // Two exact groups of different sizes.
                    object_row("/x/mid_a", 2 * S, 3, 1),
                    object_row("/x/mid_b", 2 * S, 4, 1),
                    object_row("/x/small_a", S, 5, 1),
                    object_row("/x/small_b", S, 6, 1),
                ],
                &[
                    ("/x/big_seen", 1),
                    ("/x/big_twin", 1),
                    ("/x/mid_a", 2),
                    ("/x/mid_b", 2),
                    ("/x/small_a", 3),
                    ("/x/small_b", 3),
                ],
            )
        });
        let ranked: Vec<(i64, ReclaimState, u64, Option<u64>)> = result
            .groups
            .iter()
            .map(|(rank, _, _, _, _, state, guaranteed, potential)| {
                (*rank, *state, *guaranteed, *potential)
            })
            .collect();
        assert_eq!(
            ranked,
            vec![
                (0, ReclaimState::Exact, 2 * S, Some(2 * S)),
                (1, ReclaimState::Exact, S, Some(S)),
                (2, ReclaimState::UpperBound, 0, Some(8 * S)),
            ],
            "guaranteed first, ceiling second — the biggest ceiling ranks last"
        );
        assert_eq!(
            result.scan,
            (ReclaimState::UpperBound, 3 * S, Some(11 * S)),
            "the headline is what the exact groups guarantee; the ceiling is stated apart"
        );
    }

    /// A group whose link counts were never recorded is browseable and worth nothing anyone may
    /// act on — the shape a v2 manifest migrated into v3 arrives in.
    #[test]
    fn an_unrecorded_link_count_publishes_an_unknown_result() {
        let result = published_both_ways(|store| {
            let mut legacy = object_row("/x/a", S, 1, 0);
            legacy.nlink = 0; // never recorded
            seed_objects(
                store,
                &[legacy, object_row("/x/b", S, 2, 1)],
                &[("/x/a", 1), ("/x/b", 1)],
            )
        });
        assert_eq!(result.groups.len(), 1, "the group stays browseable");
        let (_, _, _, _, _, state, guaranteed, potential) = &result.groups[0];
        assert_eq!(*state, ReclaimState::Unknown);
        assert_eq!((*guaranteed, *potential), (0, None));
        assert_eq!(
            result.scan,
            (ReclaimState::Unknown, 0, None),
            "one unmeasured group makes the scan total unmeasured, not smaller"
        );
    }

    /// Exactly what the v3 migration leaves behind: the old row, its old positive figure, and the
    /// defaults that say nothing about it is established.
    fn seed_migrated_v2(store: &mut ScanStore) -> i64 {
        let scan_id = seed_objects(
            store,
            &[object_row("/x/a", S, 1, 1), object_row("/x/b", S, 2, 1)],
            &[("/x/a", 1), ("/x/b", 1)],
        );
        store
            .conn
            .execute(
                "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                        object_count, reclaim_state)
                 VALUES (?1, 0, 'aabb', 3, ?2, ?3, 0, 0)",
                params![scan_id, S as i64, (2 * S) as i64],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_stats SET reclaimable_bytes = ?2, reclaim_state = 0,
                        files_scanned = 3, bytes_hashed = 100, groups_found = 1
                  WHERE scan_id = ?1",
                params![scan_id, (2 * S) as i64],
            )
            .unwrap();
        store.set_status(scan_id, ScanStatus::Complete).unwrap();
        scan_id
    }

    /// A migrated v2 summary keeps its old pathname number in the database as history, and hands
    /// none of it to anyone.
    #[test]
    fn a_migrated_v2_summary_stays_browseable_and_untrusted() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_migrated_v2(&mut store);

        store.ensure_materialized(scan_id).unwrap();
        let summaries = store.group_summaries(scan_id).unwrap();
        assert_eq!(summaries.len(), 1, "the row remains browseable");
        assert_eq!(summaries[0].file_count, 3, "its pathnames are still listed");
        assert_eq!(summaries[0].reclaim.state(), ReclaimState::Unknown);
        assert_eq!(summaries[0].reclaim.potential_bytes(), None);
        assert_eq!(
            crate::tui::reclaim_cell(summaries[0].reclaim),
            "rescan required"
        );
        assert_eq!(store.scan_reclaim(scan_id).unwrap().potential_bytes(), None);
        assert_eq!(
            store.scan_summary(scan_id).unwrap().reclaim.state(),
            ReclaimState::Unknown
        );
        assert_eq!(
            store.destructive_plan_verdict(scan_id).unwrap(),
            DestructivePlanVerdict::RescanRequired,
            "the existing plan guard still refuses it"
        );
        // The stored number is history: still in the table, never handed out.
        let stored: i64 = store
            .conn
            .query_row(
                "SELECT reclaim FROM file_group WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, (2 * S) as i64, "the migrated row is not rewritten");
    }

    /// The migrated row as the operator actually meets it: the summary comes out of the store and
    /// goes through the shared group renderer that classic and the commander both draw. A summary
    /// built by hand in the UI's own tests cannot show that the sentinel survives the database.
    #[test]
    fn a_migrated_v2_summary_reaches_the_browser_as_an_unknown_count() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_migrated_v2(&mut store);
        store.ensure_materialized(scan_id).unwrap();
        let summaries = store.group_summaries(scan_id).unwrap();
        assert_eq!(
            (summaries[0].object_count, summaries[0].reclaim.state()),
            (0, ReclaimState::Unknown),
            "the sentinel the renderer has to recognise"
        );
        for width in [52, 40] {
            let entries = crate::tui::screens::browser::tests::drawn_entries(width, &summaries);
            let text = &entries[0];
            assert!(
                text.contains("? objects"),
                "a count that was never recorded is not a count of zero ({width} columns): {text}"
            );
            assert!(
                !text.contains("0 objects"),
                "the contradiction this row used to draw ({width} columns): {text}"
            );
            assert!(
                text.contains("rescan required"),
                "the row still says how to get the count ({width} columns): {text}"
            );
            assert!(
                text.contains("3 files"),
                "its pathnames are still listed ({width} columns): {text}"
            );
        }
        // Reading the row does not rewrite it: the sentinel is still in the table afterwards.
        let stored: i64 = store
            .conn
            .query_row(
                "SELECT object_count FROM file_group WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, 0, "the migrated row keeps its sentinel");
    }

    // === R2D-C5-1: the inert plan authority ===
    //
    // Every test below drives `build_action_plan` over real files on a real filesystem: the builder
    // stats every pathname it plans and compares the full temporal identity, so synthetic manifest
    // rows would test something the production path never does. Nothing in production calls the
    // builder yet — C5-2 does the switching.

    use crate::model::plan::{MarkIntent, PlanWarning, RequestedMark};
    use crate::testfixtures::PlanScenario;

    /// The size of one member, read from the file rather than assumed.
    fn payload_size(path: &Path) -> u64 {
        std::fs::symlink_metadata(path).unwrap().len()
    }

    /// What a window says it marked, in the shape the builder demands: the pathname AND its meaning.
    fn del(path: &Path) -> RequestedMark {
        RequestedMark::acting(path.to_path_buf(), ActionKind::Delete)
    }

    fn keep(path: &Path) -> RequestedMark {
        RequestedMark::keeper(path.to_path_buf())
    }

    /// The commander's blind spot, from the store side: a panel marked one alias, the other alias
    /// exists only in the persisted group — and it is exactly what makes the plan worth nothing.
    #[test]
    fn a_plan_sees_the_unmarked_alias_a_panel_never_showed() {
        let _role = role_guard();
        let scenario = PlanScenario::new("blindspot");
        let keeper = scenario.file("keeper.bin");
        let alias_0 = scenario.file("alias_0.bin");
        let alias_1 = scenario.link(&alias_0, "alias_1.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_0.clone(), alias_1.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_0,
            false,
            Some(ActionKind::Delete),
        );

        let plan = store
            .build_action_plan(scan_id, &[del(&alias_0)])
            .expect("the plan is allowed — it is simply worth nothing");

        assert_eq!(plan.actions().len(), 1);
        assert_eq!(
            plan.summary().guaranteed_bytes(),
            0,
            "the unmarked alias keeps every block"
        );
        assert_eq!(plan.summary().potential_bytes(), Some(0));
        let object = plan.target_object_of(&plan.actions()[0]);
        assert_eq!((object.observed_links(), object.covered_links()), (2, 1));
        assert!(
            object.members().contains(&alias_1),
            "the alias nobody marked is in the evidence: {:?}",
            object.members()
        );
        assert_eq!(
            plan.summary().warnings(),
            &[PlanWarning::UncoveredAlias {
                representative: alias_0,
                remaining: 1,
            }]
        );
    }

    /// Both pathnames of the allocation marked: one allocation, one size.
    #[test]
    fn a_plan_over_both_aliases_claims_one_allocation() {
        let _role = role_guard();
        let scenario = PlanScenario::new("covered");
        let keeper = scenario.file("keeper.bin");
        let alias_0 = scenario.file("alias_0.bin");
        let alias_1 = scenario.link(&alias_0, "alias_1.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_0.clone(), alias_1.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_0,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &alias_1,
            false,
            Some(ActionKind::Delete),
        );

        let plan = store
            .build_action_plan(scan_id, &[del(&alias_0), del(&alias_1)])
            .expect("a fully covered allocation is plannable");

        assert_eq!(plan.actions().len(), 2, "two pathnames are removed");
        assert_eq!(plan.summary().covered_objects(), 1, "one allocation goes");
        assert_eq!(plan.summary().guaranteed_bytes(), payload_size(&alias_0));
        assert!(plan.summary().warnings().is_empty());
    }

    /// A link outside the scan keeps the allocation alive: nothing guaranteed, the ceiling stays.
    #[test]
    fn an_external_link_keeps_the_guarantee_at_zero() {
        let _role = role_guard();
        let scenario = PlanScenario::new("external");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin_b.bin");
        scenario.outside_link(&twin, "external.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));

        let plan = store
            .build_action_plan(scan_id, &[del(&twin)])
            .expect("an upper-bound plan is allowed");

        assert_eq!(plan.summary().guaranteed_bytes(), 0);
        assert_eq!(plan.summary().potential_bytes(), Some(payload_size(&twin)));
        assert_eq!(
            plan.summary().warnings(),
            &[PlanWarning::ExternalLinks {
                representative: twin,
                outside: 1,
            }]
        );
    }

    /// Durable marks are the plan; the caller's own view only has to agree with them.
    ///
    /// A mark made in another panel is the operator's earlier work and stays in. A path the caller
    /// believes is marked while the database holds no such mark refuses the whole plan, rather than
    /// planning the part that happened to be persisted.
    #[test]
    fn durable_marks_are_planned_and_a_phantom_mark_refuses() {
        let _role = role_guard();
        let scenario = PlanScenario::new("durable");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        // A second content, marked earlier in another panel.
        let other_keeper = scenario.root.join("other_keeper.bin");
        let other_twin = scenario.root.join("other_twin.bin");
        std::fs::write(&other_keeper, vec![9u8; 2048]).unwrap();
        std::fs::write(&other_twin, vec![9u8; 2048]).unwrap();
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[
                keeper.clone(),
                twin.clone(),
                other_keeper.clone(),
                other_twin.clone(),
            ],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        scenario.mark(&mut store, scan_id, &other_keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &other_twin,
            false,
            Some(ActionKind::Delete),
        );

        let plan = store
            .build_action_plan(scan_id, &[del(&twin)])
            .expect("both durable groups are planned");
        let targets: Vec<&Path> = plan
            .actions()
            .iter()
            .map(crate::model::plan::PlanAction::target)
            .collect();
        assert!(
            targets.contains(&other_twin.as_path()),
            "a mark from another panel is still the operator's work: {targets:?}"
        );

        let phantom = scenario.root.join("never_marked.bin");
        std::fs::write(&phantom, vec![7u8; 64]).unwrap();
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin), del(&phantom)])
                .expect_err("the caller believes in a mark the database never got"),
            PlanRefusal::MarkNotPersisted { path: phantom }
        );
    }

    /// The coarse gate comes first: a scan whose figures were never established is refused before
    /// a single mark is read, whatever the individual rows say.
    #[test]
    fn an_unestablished_scan_refuses_before_anything_else() {
        let _role = role_guard();
        let scenario = PlanScenario::new("unmeasured");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        store
            .build_action_plan(scan_id, &[del(&twin)])
            .expect("the control: this scan is plannable");

        // Exactly what a migrated pre-v3 result carries.
        store
            .conn
            .execute(
                "UPDATE scan_stats SET reclaim_state = 0 WHERE scan_id = ?1",
                params![scan_id],
            )
            .unwrap();
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin)])
                .expect_err("nothing measured, nothing planned"),
            PlanRefusal::RescanRequired
        );

        // A link count nobody recorded reaches the same verdict through the same gate.
        store
            .conn
            .execute(
                "UPDATE scan_stats SET reclaim_state = 1 WHERE scan_id = ?1",
                params![scan_id],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE file SET nlink = 0 WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, twin.to_string_lossy()],
            )
            .unwrap();
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin)])
                .expect_err("an unrecorded link count"),
            PlanRefusal::RescanRequired
        );
    }

    /// A digest this build never verified against the file cannot anchor a destructive plan, even
    /// though the scan-wide gate has nothing to say about it.
    #[test]
    fn a_digest_that_was_never_verified_refuses_the_plan() {
        let _role = role_guard();
        let scenario = PlanScenario::new("unverified");
        let keeper = scenario.file("keeper.bin");
        let alias_0 = scenario.file("alias_0.bin");
        let alias_1 = scenario.link(&alias_0, "alias_1.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_0.clone(), alias_1.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_0,
            false,
            Some(ActionKind::Delete),
        );

        // The unmarked alias is the one demoted: a referenced member is enough, it need not be a
        // target.
        store
            .conn
            .execute(
                "UPDATE file SET identity_version = 0 WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, alias_1.to_string_lossy()],
            )
            .unwrap();
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&alias_0)])
                .expect_err("an unverified row in a referenced group"),
            PlanRefusal::UnverifiedIdentity { path: alias_1 }
        );
    }

    /// A mark without a keeper, a mark without a digest, and a mark on the keeper's own allocation.
    #[test]
    fn keeperless_unhashed_and_already_linked_marks_refuse() {
        let _role = role_guard();
        let scenario = PlanScenario::new("refusals");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let linked = scenario.link(&keeper, "linked.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone(), linked.clone()]);

        // No keeper anywhere in the group.
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        assert!(
            matches!(
                store.build_action_plan(scan_id, &[del(&twin)]),
                Err(PlanRefusal::MissingKeeper { .. })
            ),
            "a group with a target and no keeper"
        );

        // The keeper's own allocation, marked: no action, and the mark is not swallowed.
        scenario.mark(&mut store, scan_id, &twin, false, None);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &linked,
            false,
            Some(ActionKind::Delete),
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&linked)])
                .expect_err("nothing is left to do"),
            PlanRefusal::NothingToDo
        );

        // A marked pathname whose row lost its digest.
        store
            .conn
            .execute(
                "UPDATE file SET hash = NULL WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, linked.to_string_lossy()],
            )
            .unwrap();
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&linked)])
                .expect_err("nothing vouches for that pathname"),
            PlanRefusal::MissingDigest { path: linked }
        );
    }

    /// The files have to still be the files: drift, a replacement, a symlink and a disappearance
    /// each refuse before the plan is returned.
    #[test]
    fn live_drift_refuses_before_the_plan_is_returned() {
        let _role = role_guard();
        let scenario = PlanScenario::new("drift");
        let keeper = scenario.file("keeper.bin");
        let alias_0 = scenario.file("alias_0.bin");
        let alias_1 = scenario.link(&alias_0, "alias_1.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_0.clone(), alias_1.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_0,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &alias_1,
            false,
            Some(ActionKind::Delete),
        );
        store
            .build_action_plan(scan_id, &[del(&alias_0)])
            .expect("the control: nothing has moved yet");

        // One alias re-counted and the other left alone: two pathnames of one inode cannot report
        // different link counts, and that is caught before anything is compared with the disk.
        store
            .conn
            .execute(
                "UPDATE file SET nlink = 3 WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, alias_0.to_string_lossy()],
            )
            .unwrap();
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&alias_0)])
                .expect_err("one allocation, two counts"),
            PlanRefusal::DisagreeingLinkCounts {
                path: alias_0.clone(),
                low: 2,
                high: 3,
            }
        );

        // Both aliases re-counted: the manifest now agrees with itself and not with the inode.
        store
            .conn
            .execute(
                "UPDATE file SET nlink = 3 WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, alias_1.to_string_lossy()],
            )
            .unwrap();
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&alias_0)])
                .expect_err("the manifest says three links, the inode says two"),
            PlanRefusal::Drifted {
                path: alias_0.clone(),
                field: "link count",
            }
        );
        store
            .conn
            .execute(
                "UPDATE file SET nlink = 2 WHERE scan_id = ?1 AND path IN (?2, ?3)",
                params![
                    scan_id,
                    alias_0.to_string_lossy(),
                    alias_1.to_string_lossy()
                ],
            )
            .unwrap();

        // The keeper is rewritten with the same bytes: a new temporal identity all the same.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&keeper, vec![7u8; payload_size(&keeper) as usize]).unwrap();
        assert!(
            matches!(
                store.build_action_plan(scan_id, &[del(&alias_0)]),
                Err(PlanRefusal::Drifted { ref path, .. }) if *path == keeper
            ),
            "a rewritten keeper is not the file the plan measured"
        );

        // A member replaced by a symbolic link, and a member that is simply gone.
        let scenario2 = PlanScenario::new("drift2");
        let keeper2 = scenario2.file("keeper.bin");
        let twin2 = scenario2.file("twin.bin");
        let mut store2 = scenario2.store();
        let scan2 = scenario2.seed(&mut store2, &[keeper2.clone(), twin2.clone()]);
        scenario2.mark(&mut store2, scan2, &keeper2, true, None);
        scenario2.mark(&mut store2, scan2, &twin2, false, Some(ActionKind::Delete));
        std::fs::remove_file(&twin2).unwrap();
        assert_eq!(
            store2
                .build_action_plan(scan2, &[del(&twin2)])
                .expect_err("the target is gone"),
            PlanRefusal::Vanished {
                path: twin2.clone()
            }
        );
        std::os::unix::fs::symlink(&keeper2, &twin2).unwrap();
        assert_eq!(
            store2
                .build_action_plan(scan2, &[del(&twin2)])
                .expect_err("the target is a symlink now"),
            PlanRefusal::Symlink { path: twin2 }
        );
    }

    /// One database, one plan: what the caller passes as its own view cannot change the answer.
    #[test]
    fn both_windows_build_the_same_plan_from_the_same_marks() {
        let _role = role_guard();
        let scenario = PlanScenario::new("parity");
        let keeper = scenario.file("keeper.bin");
        let alias_0 = scenario.file("alias_0.bin");
        let alias_1 = scenario.link(&alias_0, "alias_1.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_0.clone(), alias_1.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_0,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &alias_1,
            false,
            Some(ActionKind::Delete),
        );

        // The classic browser hands over the whole open group; a commander panel hands over the
        // marks it happens to hold.
        let classic = store
            .build_action_plan(scan_id, &[keep(&keeper), del(&alias_0), del(&alias_1)])
            .unwrap();
        let commander = store.build_action_plan(scan_id, &[del(&alias_0)]).unwrap();
        assert_eq!(classic, commander, "the database is the only authority");
        assert_eq!(classic.digest(), commander.digest());
    }

    /// The row-presence bit, straight at the decoder.
    ///
    /// `file_mark.is_keeper` is declared `INTEGER NOT NULL`, so SQLite itself will not hand out a
    /// present row with a `NULL` in that column — this guard is for a file that was not maintained
    /// by SQLite. That is also why the coverage is here rather than end to end: the case cannot be
    /// written through the schema it violates.
    #[test]
    fn a_present_mark_row_may_not_carry_a_null_flag() {
        let path = Path::new("/x/twin.bin");
        let delete = Value::Text("delete".to_string());

        assert_eq!(
            ScanStore::mark_intent_from_sql(path, false, &Value::Null, &Value::Null).unwrap(),
            None,
            "nothing was joined: an ordinary unmarked member"
        );
        assert_eq!(
            ScanStore::mark_intent_from_sql(path, true, &Value::Null, &delete)
                .expect_err("a present row whose flag is null"),
            PlanRefusal::CorruptMark {
                path: path.to_path_buf(),
                field: "is_keeper",
                detail: "null".to_string(),
            },
            "a damaged flag must not be read as «not the keeper» and become its action"
        );
        assert_eq!(
            ScanStore::mark_intent_from_sql(path, true, &Value::Integer(0), &delete).unwrap(),
            Some(MarkIntent::Act(ActionKind::Delete))
        );
        assert_eq!(
            ScanStore::mark_intent_from_sql(path, true, &Value::Integer(1), &Value::Null).unwrap(),
            Some(MarkIntent::Keeper)
        );
        assert_eq!(
            ScanStore::mark_intent_from_sql(path, true, &Value::Integer(0), &Value::Null).unwrap(),
            None,
            "the decoder reports «neither»; `durable_marks` is where a present row may not mean it"
        );
        assert!(
            matches!(
                ScanStore::mark_intent_from_sql(path, false, &Value::Null, &delete),
                Err(PlanRefusal::CorruptMark {
                    field: "action",
                    ..
                })
            ),
            "a row the join says is absent cannot bring values along"
        );
    }

    /// Every read that builds one plan sees one database.
    ///
    /// This project runs in WAL with more than one connection, so a second copy of the program can
    /// commit between two autocommit reads. Without one snapshot the typed request check is
    /// bypassed: the marks are reconciled, the meaning changes underneath, and the plan comes back
    /// carrying an action the operator's window never showed.
    #[test]
    fn the_whole_plan_is_read_from_one_snapshot() {
        let _role = role_guard();
        let scenario = PlanScenario::new("snapshot");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));

        // A second connection commits the newer meaning at exactly the moment between the
        // reconciliation and the group load — deterministically, not by racing.
        let db_path = scenario.db_path.clone();
        let target = twin.clone();
        arm_after_reconcile(move || {
            let other = ScanStore::open_writable(&db_path).expect("a second connection");
            other
                .conn
                .execute(
                    "UPDATE file_mark SET action = 'hardlink' WHERE path = ?1",
                    params![target.to_string_lossy()],
                )
                .expect("the other copy of the program commits");
        });

        let plan = store
            .build_action_plan(scan_id, &[del(&twin)])
            .expect("the snapshot the request was checked against");
        assert_eq!(
            plan.actions()[0].kind(),
            ActionKind::Delete,
            "the plan may not carry a meaning that arrived after the request was reconciled"
        );

        // The change is committed, so the next build sees it — and refuses, because the window is
        // still asking for the older meaning.
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin)])
                .expect_err("the newer meaning is durable now"),
            PlanRefusal::MarkDisagrees {
                path: twin,
                requested: MarkIntent::Act(ActionKind::Delete),
                durable: MarkIntent::Act(ActionKind::Hardlink),
            }
        );
    }

    /// A mark whose write never landed leaves the older meaning in the database. Proving the
    /// pathname is marked is not enough — the window says DELETE, the database still says HARDLINK,
    /// and planning the older meaning is exactly the accident this comparison exists to stop.
    #[test]
    fn a_request_that_disagrees_with_the_database_refuses() {
        let _role = role_guard();
        let scenario = PlanScenario::new("disagree");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &twin,
            false,
            Some(ActionKind::Hardlink),
        );

        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin)])
                .expect_err("the window says delete, the database says hardlink"),
            PlanRefusal::MarkDisagrees {
                path: twin.clone(),
                requested: MarkIntent::Act(ActionKind::Delete),
                durable: MarkIntent::Act(ActionKind::Hardlink),
            }
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[keep(&twin)])
                .expect_err("the window says keeper, the database says hardlink"),
            PlanRefusal::MarkDisagrees {
                path: twin.clone(),
                requested: MarkIntent::Keeper,
                durable: MarkIntent::Act(ActionKind::Hardlink),
            }
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin), keep(&twin)])
                .expect_err("the window does not know its own state"),
            PlanRefusal::RequestContradictsItself { path: twin.clone() }
        );

        let plan = store
            .build_action_plan(
                scan_id,
                &[
                    keep(&keeper),
                    RequestedMark::acting(twin.clone(), ActionKind::Hardlink),
                ],
            )
            .expect("exact semantics on both sides");
        assert_eq!(plan.actions().len(), 1);
        assert_eq!(plan.actions()[0].kind(), ActionKind::Hardlink);
    }

    /// A mark the database cannot express refuses the WHOLE plan. It is never quietly left out,
    /// even when everything else in the group is valid — the operator would confirm a screen that
    /// no longer contains something they marked.
    #[test]
    fn a_mark_that_cannot_be_read_refuses_the_whole_plan() {
        let _role = role_guard();
        let scenario = PlanScenario::new("corruptmark");
        let keeper = scenario.file("keeper.bin");
        let twin_a = scenario.file("twin_a.bin");
        let twin_b = scenario.file("twin_b.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), twin_a.clone(), twin_b.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &twin_a,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &twin_b,
            false,
            Some(ActionKind::Delete),
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin_a)])
                .expect("the control: two valid targets")
                .actions()
                .len(),
            2
        );

        let poke = |store: &ScanStore, sql: &str| {
            store
                .conn
                .execute(sql, params![scan_id, twin_b.to_string_lossy()])
                .unwrap();
        };

        poke(
            &store,
            "UPDATE file_mark SET action = 'obliterate' WHERE scan_id = ?1 AND path = ?2",
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin_a)])
                .expect_err("an action identifier this build does not know"),
            PlanRefusal::CorruptMark {
                path: twin_b.clone(),
                field: "action",
                detail: "text \"obliterate\"".to_string(),
            }
        );

        poke(
            &store,
            "UPDATE file_mark SET action = 'delete', is_keeper = 2 WHERE scan_id = ?1 AND path = ?2",
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin_a)])
                .expect_err("a flag that is not a flag"),
            PlanRefusal::CorruptMark {
                path: twin_b.clone(),
                field: "is_keeper",
                detail: "integer 2".to_string(),
            }
        );

        poke(
            &store,
            "UPDATE file_mark SET is_keeper = 1 WHERE scan_id = ?1 AND path = ?2",
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin_a)])
                .expect_err("kept and acted on at once"),
            PlanRefusal::ContradictoryMark {
                path: twin_b.clone()
            }
        );

        poke(
            &store,
            "UPDATE file_mark SET is_keeper = 0, action = NULL WHERE scan_id = ?1 AND path = ?2",
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin_a)])
                .expect_err("a mark that means nothing"),
            PlanRefusal::CorruptMark {
                path: twin_b,
                field: "mark",
                detail: "neither a keeper nor an action".to_string(),
            }
        );
    }

    /// Two durable keeper marks are two different plans, and the commander writes one pathname at a
    /// time, so this needs no hand-edited database.
    #[test]
    fn two_durable_keepers_refuse() {
        let _role = role_guard();
        let scenario = PlanScenario::new("twokeepers");
        let first = scenario.file("a_keeper.bin");
        let second = scenario.file("b_keeper.bin");
        let twin = scenario.file("c_twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[first.clone(), second.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &first, true, None);
        scenario.mark(&mut store, scan_id, &second, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));

        assert_eq!(
            store
                .build_action_plan(scan_id, &[del(&twin)])
                .expect_err("nothing says which file is kept"),
            PlanRefusal::MultipleKeepers {
                hash: {
                    let digest: Vec<u8> = store
                        .conn
                        .query_row(
                            "SELECT hash FROM file WHERE scan_id = ?1 AND path = ?2",
                            params![scan_id, twin.to_string_lossy()],
                            |row| row.get(0),
                        )
                        .unwrap();
                    hex_encode(&digest)
                },
                first,
                second,
            }
        );
    }

    /// One inode cannot hold two contents. A damaged database that says otherwise would have the
    /// plan count — and act on — a single allocation as two groups.
    #[test]
    fn one_allocation_under_two_digests_refuses() {
        let _role = role_guard();
        let scenario = PlanScenario::new("twodigests");
        let a_keeper = scenario.file("a_keeper.bin");
        let alias_0 = scenario.file("alias_0.bin");
        let alias_1 = scenario.link(&alias_0, "alias_1.bin");
        // Another content of the same length, so only the digests differ.
        let b_keeper = scenario.root.join("b_keeper.bin");
        std::fs::write(&b_keeper, vec![9u8; payload_size(&alias_0) as usize]).unwrap();
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[
                a_keeper.clone(),
                alias_0.clone(),
                alias_1.clone(),
                b_keeper.clone(),
            ],
        );
        let other: Vec<u8> = store
            .conn
            .query_row(
                "SELECT hash FROM file WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, b_keeper.to_string_lossy()],
                |row| row.get(0),
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE file SET hash = ?3 WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, alias_1.to_string_lossy(), other],
            )
            .unwrap();
        scenario.mark(&mut store, scan_id, &a_keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_0,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(&mut store, scan_id, &b_keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_1,
            false,
            Some(ActionKind::Delete),
        );

        assert!(
            matches!(
                store.build_action_plan(scan_id, &[del(&alias_0)]),
                Err(PlanRefusal::ObjectInTwoGroups { .. })
            ),
            "one allocation may not be counted as two groups"
        );
    }

    #[test]
    fn materialized_scan_without_duplicates_stays_empty() {
        // Zero groups is a legitimate final answer, not «not prepared yet».
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_no_duplicates(&mut store);
        store.materialize_file_groups(scan_id).unwrap();
        assert!(store.results_materialized(scan_id).unwrap());
        store.ensure_materialized(scan_id).unwrap();
        assert!(
            store.group_summaries(scan_id).unwrap().is_empty(),
            "a scan with no duplicates must stay empty"
        );
    }

    #[test]
    fn verified_scan_with_zero_groups_is_not_resurrected() {
        // --verify rejected every candidate group (record_file_results with an empty slice)
        // while the raw hashes still match. Re-deriving from those hashes would hand the user
        // back exactly the groups verification refused.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_two_groups(&mut store);
        store.record_file_results(scan_id, &[]).unwrap();
        store.ensure_materialized(scan_id).unwrap();
        assert!(
            store.group_summaries(scan_id).unwrap().is_empty(),
            "a read fallback must not resurrect a group rejected by verification"
        );
    }

    #[test]
    fn reopening_an_empty_result_does_not_recompute() {
        // A duplicate pair added to the manifest AFTER the result was prepared must not appear
        // — proof that opening does not re-aggregate the manifest.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_no_duplicates(&mut store);
        store.materialize_file_groups(scan_id).unwrap();
        store
            .record_files(scan_id, &[row("/x/p", 70, 7), row("/x/q", 70, 8)])
            .unwrap();
        let h = [7u8; 32];
        store
            .record_hashes(
                scan_id,
                &[(PathBuf::from("/x/p"), h), (PathBuf::from("/x/q"), h)],
            )
            .unwrap();
        store.ensure_materialized(scan_id).unwrap();
        assert!(
            store.group_summaries(scan_id).unwrap().is_empty(),
            "an already prepared result must not be recomputed"
        );
    }

    #[test]
    fn writer_prepares_legacy_result_once_observer_only_reads() {
        // A scan finished before the marker existed: nothing recorded, flag unset.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_two_groups(&mut store);
        assert!(!store.results_materialized(scan_id).unwrap());
        // The observer reads and sees the not-yet-prepared (empty) result — it writes nothing.
        assert!(store.group_summaries(scan_id).unwrap().is_empty());
        assert!(!store.results_materialized(scan_id).unwrap());
        // The writer prepares it once.
        store.ensure_materialized(scan_id).unwrap();
        assert!(store.results_materialized(scan_id).unwrap());
        let prepared = store.group_summaries(scan_id).unwrap();
        assert_eq!(prepared.len(), 2);
        assert_eq!(prepared[0].reclaim.guaranteed_bytes(), 200);
        // A second call changes nothing.
        store.ensure_materialized(scan_id).unwrap();
        assert_eq!(store.group_summaries(scan_id).unwrap().len(), 2);
    }

    #[test]
    fn legacy_verified_empty_result_is_not_reaggregated() {
        // The dangerous shape: a scan finished under --verify which rejected every candidate
        // group, from before the marker existed. Raw hashes still match, file_group is empty and
        // the marker defaults to 0 — only scan_stats.groups_found = 0 says the empty result is
        // final. Aggregating here would hand back exactly what verification refused.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_two_groups(&mut store);
        store.set_status(scan_id, ScanStatus::Complete).unwrap();
        // As the completed scan recorded it: files were scanned and hashed, and verification
        // left zero groups behind.
        store
            .record_scan_result(
                scan_id,
                &ScanSummary {
                    files_scanned: 6,
                    bytes_hashed: 500,
                    groups_found: 0,
                    ..Default::default()
                },
            )
            .unwrap();
        // Migration default, as an upgraded legacy DB would have it.
        store
            .conn
            .execute(
                "UPDATE scan_stats SET results_materialized = 0 WHERE scan_id = ?1",
                params![scan_id],
            )
            .unwrap();
        store.ensure_materialized(scan_id).unwrap();
        assert!(
            store.group_summaries(scan_id).unwrap().is_empty(),
            "writer preparation must not resurrect groups rejected by verification"
        );
        assert!(
            store.results_materialized(scan_id).unwrap(),
            "the empty result is now explicitly marked prepared"
        );
    }

    #[test]
    fn writer_prepares_every_unprepared_completed_scan() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let with_dupes = seed_two_groups(&mut store);
        store.set_status(with_dupes, ScanStatus::Complete).unwrap();
        let unfinished = seed_two_groups(&mut store);
        store.set_status(unfinished, ScanStatus::Hashing).unwrap();
        assert_eq!(
            store.unprepared_completed_scans().unwrap(),
            vec![with_dupes],
            "only completed scans are prepared"
        );
        assert_eq!(store.prepare_completed_scans().unwrap(), 1);
        assert!(store.results_materialized(with_dupes).unwrap());
        assert_eq!(store.group_summaries(with_dupes).unwrap().len(), 2);
        // Idempotent: nothing left to do on a second pass.
        assert_eq!(store.prepare_completed_scans().unwrap(), 0);
    }

    #[test]
    fn results_and_marker_commit_together() {
        // The marker must never be observable without the rows it describes.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_two_groups(&mut store);
        store.materialize_file_groups(scan_id).unwrap();
        assert!(store.results_materialized(scan_id).unwrap());
        assert_eq!(store.group_summaries(scan_id).unwrap().len(), 2);
    }

    #[test]
    fn legacy_recorded_result_is_kept_not_reaggregated() {
        // Legacy scan WITH rows already recorded (possibly filtered by --verify): the writer
        // marks it prepared instead of re-deriving it from raw hashes.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_two_groups(&mut store);
        let mut groups = store.duplicate_groups(scan_id).unwrap();
        groups.truncate(1); // verification dropped one of them
        store.record_file_results(scan_id, &groups).unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_stats SET results_materialized = 0 WHERE scan_id = ?1",
                params![scan_id],
            )
            .unwrap();
        store.ensure_materialized(scan_id).unwrap();
        assert_eq!(
            store.group_summaries(scan_id).unwrap().len(),
            1,
            "the dropped group must not come back"
        );
    }

    /// One scan, three files with distinct hashes — no duplicate groups.
    fn seed_no_duplicates(store: &mut ScanStore) -> i64 {
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &[row("/x/a", 10, 1), row("/x/b", 20, 2), row("/x/c", 30, 3)],
            )
            .unwrap();
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/a"), [1u8; 32]),
                    (PathBuf::from("/x/b"), [2u8; 32]),
                    (PathBuf::from("/x/c"), [3u8; 32]),
                ],
            )
            .unwrap();
        scan_id
    }

    /// Two duplicate groups (reclaim 200 and 50) plus one unique file.
    fn seed_two_groups(store: &mut ScanStore) -> i64 {
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                scan_id,
                &[
                    row("/x/a", 100, 1),
                    row("/x/b", 100, 2),
                    row("/x/c", 100, 3),
                    row("/x/d", 50, 4),
                    row("/x/e", 50, 5),
                    row("/x/u", 200, 6),
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
            bytes_hashed: 8192,
            elapsed_seconds: 1.5,
            hash_failures: 3,
            ..Default::default()
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
        assert_eq!(
            got.reclaim.potential_bytes(),
            None,
            "the summary of a scan whose results were never materialized promises nothing"
        );

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

    /// Restores the operator role no matter how the test ends.
    struct RoleReset;
    impl Drop for RoleReset {
        fn drop(&mut self) {
            set_observer_role(false);
        }
    }

    #[test]
    fn read_only_open_refuses_to_create_a_missing_db() {
        // An observer on a clean state-dir must not conjure a dedcom.db.
        let dir = temp_state_dir("ro_missing");
        let db = dir.join("dedcom.db");
        assert!(ScanStore::open_read_only(&db).is_err());
        assert!(!db.exists(), "read-only open must not create the DB file");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_only_store_reads_but_rejects_writes() {
        let _role = role_guard();
        let dir = temp_state_dir("ro_writes");
        let db = dir.join("dedcom.db");
        let scan_id = {
            let mut store = ScanStore::open_writable(&db).unwrap();
            let id = store
                .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
                .unwrap();
            store.set_status(id, ScanStatus::Complete).unwrap();
            id
        };
        let mut observer = ScanStore::open_read_only(&db).unwrap();
        // Reading works.
        let scans = observer.list_scans().unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].scan_id, scan_id);
        // Every write is refused by SQLite itself, not by a check we remembered to write.
        assert!(observer
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/b")]))
            .is_err());
        assert!(observer.set_status(scan_id, ScanStatus::Aborted).is_err());
        assert!(observer.trash_scan(scan_id).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn observer_role_routes_open_to_a_read_only_store() {
        let _role = role_guard();
        let _reset = RoleReset;
        let dir = temp_state_dir("ro_role");
        let db = dir.join("dedcom.db");
        {
            let mut store = ScanStore::open_writable(&db).unwrap();
            store
                .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
                .unwrap();
        }
        // As an observer, the ordinary open() must hand back a store that cannot write.
        set_observer_role(true);
        assert!(is_observer_role());
        let mut store = ScanStore::open(&db).unwrap();
        assert_eq!(store.list_scans().unwrap().len(), 1);
        assert!(store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/b")]))
            .is_err());
        drop(store);
        // Back as the operator, the same call writes again.
        set_observer_role(false);
        let mut store = ScanStore::open(&db).unwrap();
        assert!(store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/b")]))
            .is_ok());
        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn observer_cannot_mark_while_the_operator_holds_the_db_open() {
        // The shape the finding is about: an observer next to a LIVE operator must not get a
        // mark into the table the operator's deletion plan is built from.
        let dir = temp_state_dir("ro_concurrent");
        let db = dir.join("dedcom.db");
        let mut operator = ScanStore::open_writable(&db).unwrap();
        let scan_id = operator
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        operator
            .record_files(scan_id, &[row("/tank/a/one", 100, 1)])
            .unwrap();
        operator.set_status(scan_id, ScanStatus::Complete).unwrap();

        // The operator's store stays open for the whole test.
        let mut observer = ScanStore::open_read_only(&db).unwrap();
        assert_eq!(
            observer.list_scans().unwrap().len(),
            1,
            "the observer still reads"
        );

        let marked = FileEntry {
            path: PathBuf::from("/tank/a/one"),
            size: 100,
            mtime: 1,
            device: 1,
            inode: 1,
            action: Some(ActionKind::Delete),
            ..Default::default()
        };
        assert!(
            observer.save_marks(scan_id, [&marked].into_iter()).is_err(),
            "an observer must not be able to save marks"
        );
        let marks: i64 = operator
            .conn
            .query_row(
                "SELECT COUNT(*) FROM file_mark WHERE scan_id = ?1",
                params![scan_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(marks, 0, "file_mark must be unchanged after the attempt");
        // The operator itself still writes.
        assert!(operator.save_marks(scan_id, [&marked].into_iter()).is_ok());

        drop(observer);
        drop(operator);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_only_refuses_a_db_that_needs_migrating() {
        let _role = role_guard();
        let dir = temp_state_dir("ro_oldschema");
        let db = dir.join("dedcom.db");
        drop(ScanStore::open_writable(&db).unwrap());
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.pragma_update(None, "user_version", schema::SCHEMA_VERSION - 1)
                .unwrap();
        }
        // Migrating needs a writer, so this is reported plainly instead of surfacing later as
        // «no such column» from some query.
        assert!(ScanStore::open_read_only(&db).is_err());
        std::fs::remove_dir_all(&dir).ok();
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
        let _role = role_guard();
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
    fn scans_filtered_skips_unknown_status_instead_of_failing() {
        // One row written by a future build with an unknown status must NOT hide every session.
        let mut store = ScanStore::open_in_memory().unwrap();
        let good = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        store.set_status(good, ScanStatus::Complete).unwrap();
        let future = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/b")]))
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan SET status = 'from_the_future' WHERE id = ?1",
                params![future],
            )
            .unwrap();
        let scans = store.list_scans().unwrap();
        assert_eq!(
            scans.len(),
            1,
            "the unknown-status row is skipped, not fatal"
        );
        assert_eq!(scans[0].scan_id, good);
    }

    #[test]
    fn find_resumable_skips_unknown_status_and_returns_next() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let older = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
            .unwrap();
        store.set_status(older, ScanStatus::Hashing).unwrap();
        let newest = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/b")]))
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan SET status = 'from_the_future' WHERE id = ?1",
                params![newest],
            )
            .unwrap();
        let got = store.find_resumable().unwrap().expect("a resumable scan");
        assert_eq!(got.scan_id, older, "the unparseable newest row is skipped");
    }

    #[test]
    fn open_refuses_db_from_a_newer_schema() {
        let _role = role_guard();
        let dir = temp_state_dir("future_ver");
        let db = dir.join("dedcom.db");
        drop(ScanStore::open(&db).unwrap());
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.pragma_update(None, "user_version", schema::SCHEMA_VERSION + 1)
                .unwrap();
        }
        assert!(
            ScanStore::open(&db).is_err(),
            "a DB from a newer schema version must be refused"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_stamps_a_legacy_versionless_db_and_keeps_data() {
        let _role = role_guard();
        let dir = temp_state_dir("legacy_ver");
        let db = dir.join("dedcom.db");
        let scan_id = {
            let mut store = ScanStore::open(&db).unwrap();
            let id = store
                .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/a")]))
                .unwrap();
            store.set_status(id, ScanStatus::Complete).unwrap();
            id
        };
        // Simulate a pre-versioning (v0.9) DB: clear the stamp.
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.pragma_update(None, "user_version", 0i64).unwrap();
        }
        // Reopen with the new build: it must re-stamp and keep the scan.
        let store = ScanStore::open(&db).unwrap();
        let scans = store.list_scans().unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].scan_id, scan_id);
        drop(store);
        let conn = rusqlite::Connection::open(&db).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, schema::SCHEMA_VERSION);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_rejects_symlinked_db() {
        // Opening via a symlink would write the target outside the state-dir — refused (O_NOFOLLOW).
        let _role = role_guard();
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
        assert_eq!(summaries[0].reclaim.guaranteed_bytes(), 200);
        assert_eq!(summaries[1].rank, 1);
        assert_eq!(summaries[1].reclaim.guaranteed_bytes(), 50);
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

    /// A real DB on disk with one group: keeper `/x/a`, targets `/x/b` and `/x/c`. Marks outlive
    /// the process, so the post-batch reconciliation has to be checked against the file, not
    /// against a map in RAM.
    fn store_on_disk_with_marked_group(tag: &str) -> (PathBuf, ScanStore, i64) {
        let dir = temp_state_dir(tag);
        let db = dir.join("dedcom.db");
        let id = seed_marked_group(&db);
        (dir, ScanStore::open_writable(&db).unwrap(), id)
    }

    fn marked_paths(store: &ScanStore, scan_id: i64) -> Vec<String> {
        let mut stmt = store
            .conn
            .prepare("SELECT path FROM file_mark WHERE scan_id = ?1 ORDER BY path")
            .unwrap();
        let rows = stmt
            .query_map(params![scan_id], |row| row.get::<_, String>(0))
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    }

    #[test]
    fn reconciling_a_cancelled_batch_leaves_the_rest_of_the_plan_marked() {
        let (dir, mut store, id) = store_on_disk_with_marked_group("marks_cancelled");
        // The batch reached /x/b and was stopped before /x/c.
        store
            .reconcile_marks_after_batch(id, &[PathBuf::from("/x/b")], true)
            .unwrap();

        assert_eq!(
            marked_paths(&store, id),
            vec!["/x/a".to_string(), "/x/c".to_string()],
            "the attempted target is gone; the keeper the rest of the plan needs stays"
        );

        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reconciling_a_finished_batch_leaves_no_plan_to_rebuild() {
        let (dir, mut store, id) = store_on_disk_with_marked_group("marks_finished");
        store
            .reconcile_marks_after_batch(id, &[PathBuf::from("/x/b"), PathBuf::from("/x/c")], false)
            .unwrap();

        assert!(
            marked_paths(&store, id).is_empty(),
            "a spent plan leaves nothing marked, keepers included"
        );

        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A fresh v3 scan of the hardlink forest persists the real `st_nlink` of every pathname it
    /// walks — the four aliases of the shared inode, the twin whose second link lies outside the
    /// scan, and the plain control — while the manifest still holds exactly one row per pathname.
    /// The expectation is read back from the filesystem, so it cannot drift from the fixture.
    #[test]
    fn a_fresh_scan_persists_real_link_counts() {
        let forest = crate::testfixtures::HardlinkForest::build("nlink_v3");
        let mut store = ScanStore::open_in_memory().unwrap();
        let cancel = AtomicBool::new(false);
        match crate::pipeline::run_scan(
            &mut store,
            &forest.scan_config(),
            None,
            false,
            &cancel,
            |_| {},
        ) {
            Ok(crate::pipeline::ScanOutcome::Completed(_)) => {}
            Ok(crate::pipeline::ScanOutcome::Cancelled) => {
                panic!("the scan must not cancel itself")
            }
            Err(err) => panic!("scan the forest: {err}"),
        }

        let mut stmt = store
            .conn
            .prepare("SELECT path, nlink FROM file ORDER BY path")
            .unwrap();
        let persisted: Vec<(String, i64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();

        let mut walked: Vec<PathBuf> = std::fs::read_dir(&forest.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        walked.sort();
        let expected: Vec<(String, i64)> = walked
            .iter()
            .map(|path| {
                (
                    path.to_string_lossy().into_owned(),
                    forest.nlink_of(path) as i64,
                )
            })
            .collect();

        assert_eq!(
            persisted, expected,
            "one row per pathname, each with its real link count"
        );
        // Named explicitly so the numbers the fixture exists for are visible in the test itself.
        assert_eq!(
            forest.nlink_of(&forest.aliases[0]),
            4,
            "the shared inode has four links, all inside the root"
        );
        assert_eq!(
            forest.nlink_of(&forest.twin_b),
            2,
            "twin_b has two links, one of them outside the scan"
        );
        assert_eq!(forest.nlink_of(&forest.twin_a), 1, "twin_a is a lone link");
    }

    /// Rewinds an open DB to the v2 shape: drops what v3 added and restamps. Migration needs a
    /// writer, so this is how a test produces the DB an observer must refuse.
    fn rewind_to_v2(conn: &Connection) {
        conn.execute_batch(
            "DROP INDEX file_scan_identity;
             DROP INDEX file_hash_identity;
             ALTER TABLE file       DROP COLUMN nlink;
             ALTER TABLE file_group DROP COLUMN object_count;
             ALTER TABLE file_group DROP COLUMN reclaim_state;
             ALTER TABLE scan_stats DROP COLUMN reclaim_state;",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 2i64).unwrap();
    }

    /// An observer holds a genuinely read-only connection and cannot migrate. Opening a v2 DB has
    /// to fail immediately, naming the reason — not later, deep inside a query, as «no such
    /// column» — and the DB must be left exactly as it was for the operator to upgrade.
    #[test]
    fn an_observer_refuses_a_v2_db_without_migrating_it() {
        let dir = temp_state_dir("readonly_v2");
        let db = dir.join("dedcom.db");
        {
            let store = ScanStore::open_writable(&db).unwrap();
            rewind_to_v2(&store.conn);
        }

        // Not `expect_err`: that needs `Debug` on the success type, and `ScanStore` has none.
        let text = match ScanStore::open_read_only(&db) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("a v2 DB must be refused on a read-only connection"),
        };
        assert!(
            text.contains("older schema") && text.contains("read-only"),
            "the message must explain the refusal: {text}"
        );

        // Untouched: still v2, and still without the v3 column.
        let conn = Connection::open(&db).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2, "the observer must not have migrated anything");
        assert!(
            conn.prepare("SELECT nlink FROM file").is_err(),
            "nothing wrote the v3 column either"
        );

        drop(conn);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A migrated pre-v3 scan stays browseable but must never reach a destructive plan: its link
    /// counts were never recorded, so no build can tell an alias from an independent copy in it.
    #[test]
    fn a_migrated_scan_without_link_counts_refuses_destructive_planning() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        // Exactly what the v2→v3 migration leaves behind: rows with no link count.
        store
            .conn
            .execute_batch(&format!(
                "INSERT INTO file(scan_id, path, size, mtime, device, inode, hash)
                     VALUES ({id}, '/tank/a', 100, 42, 10, 5, X'AABB'),
                            ({id}, '/tank/b', 100, 42, 10, 5, X'AABB');"
            ))
            .unwrap();

        assert_eq!(store.scan_reclaim_state(id).unwrap(), ReclaimState::Unknown);
        assert!(
            !store.scan_link_counts_known(id).unwrap(),
            "a migrated manifest has no link counts"
        );
        assert_eq!(
            store.destructive_plan_verdict(id).unwrap(),
            DestructivePlanVerdict::RescanRequired
        );
    }

    /// The other side of the gate, end to end on a real filesystem: a fresh scan of the hardlink
    /// forest records every link count, publishes what the forest is physically worth, and opens
    /// the gate on its own.
    ///
    /// The forest is six duplicate pathnames over three allocations: four aliases of one inode
    /// (all four seen), an independent twin, and a twin whose second link lives outside the scan
    /// root. Keeping one allocation could free two — but one of those two is held by a link
    /// nobody scanned, so nothing is guaranteed.
    #[test]
    fn a_fresh_scan_knows_its_link_counts_and_the_gate_opens_on_a_trusted_state() {
        let forest = crate::testfixtures::HardlinkForest::build("verdict_v3");
        let mut store = ScanStore::open_in_memory().unwrap();
        let cancel = AtomicBool::new(false);
        match crate::pipeline::run_scan(
            &mut store,
            &forest.scan_config(),
            None,
            false,
            &cancel,
            |_| {},
        ) {
            Ok(crate::pipeline::ScanOutcome::Completed(_)) => {}
            Ok(crate::pipeline::ScanOutcome::Cancelled) => {
                panic!("the scan must not cancel itself")
            }
            Err(err) => panic!("scan the forest: {err}"),
        }
        let id = store.latest_scan_id().unwrap().expect("the scan exists");

        assert!(
            store.scan_link_counts_known(id).unwrap(),
            "every walked row carries a real link count"
        );
        let summaries = store.group_summaries(id).unwrap();
        assert_eq!(summaries.len(), 1, "one duplicate-content group");
        let size = summaries[0].size_bytes;
        assert_eq!(
            (summaries[0].file_count, summaries[0].object_count),
            (6, 3),
            "six pathnames over three allocations — every pathname kept"
        );
        assert_eq!(summaries[0].reclaim.state(), ReclaimState::UpperBound);
        assert_eq!(
            (
                summaries[0].reclaim.guaranteed_bytes(),
                summaries[0].reclaim.potential_bytes()
            ),
            (0, Some(2 * size)),
            "the outside link guarantees nothing, and the ceiling is two allocations"
        );
        let links = store.group_links(id, &summaries[0].hash).unwrap();
        assert_eq!(
            (links.observed, links.total),
            (6, LinkCount::Known(7)),
            "4 + 1 + 2 links, counted once per allocation; the seventh is the one outside"
        );
        assert_eq!(
            store.already_linked_sets(id).unwrap(),
            1,
            "the alias set is reported once"
        );
        assert_eq!(
            store.scan_reclaim(id).unwrap().state(),
            ReclaimState::UpperBound
        );
        // The state is established, so the gate opens on its own — it is a gate, not a permanent
        // refusal. What may be claimed once it is open is R2D's question.
        assert_eq!(
            store.destructive_plan_verdict(id).unwrap(),
            DestructivePlanVerdict::Allowed
        );
    }

    /// A reclaim state this build does not recognise is an error, not a silent «unknown» — a
    /// number written by something else must not be interpreted at all.
    #[test]
    fn an_unrecognised_persisted_reclaim_state_is_refused() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_stats SET reclaim_state = 7 WHERE scan_id = ?1",
                params![id],
            )
            .unwrap();

        let err = store
            .scan_reclaim_state(id)
            .expect_err("7 is not a reclaim state");
        assert!(
            err.to_string().contains("unknown reclaim state"),
            "the message must name the cause: {err}"
        );
        assert!(store.destructive_plan_verdict(id).is_err());
    }

    /// Seeds a completed-looking scan and returns its id. `file.nlink` is a signed SQLite
    /// `INTEGER` with no domain constraint, so a damaged or externally modified DB can hold a
    /// value `st_nlink` could never produce; these tests write one deliberately.
    fn store_with_seeded_manifest(rows: &[(&str, i64, i64)]) -> (ScanStore, i64) {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        for (index, (path, size, nlink)) in rows.iter().enumerate() {
            store
                .conn
                .execute(
                    "INSERT INTO file(scan_id, path, size, mtime, device, inode, nlink)
                     VALUES (?1, ?2, ?3, 42, 10, ?4, ?5)",
                    params![id, path, size, index as i64 + 1, nlink],
                )
                .unwrap();
        }
        (store, id)
    }

    /// A negative persisted link count is corruption, not a large real count. Planning must refuse
    /// with an explicit error — and here the trust state is deliberately set to `Exact`, so the
    /// link-count check is the only thing standing between this scan and `Allowed`.
    #[test]
    fn a_corrupt_negative_link_count_refuses_destructive_planning() {
        let (store, id) = store_with_seeded_manifest(&[("/tank/a", 100, -1)]);
        store
            .conn
            .execute(
                "UPDATE scan_stats SET reclaim_state = ?2 WHERE scan_id = ?1",
                params![id, ReclaimState::Exact.as_i64()],
            )
            .unwrap();

        let err = store
            .scan_link_counts_known(id)
            .expect_err("a negative link count must not read as known");
        assert!(
            err.to_string().contains("corrupt link count"),
            "the message must name the cause: {err}"
        );

        match store.destructive_plan_verdict(id) {
            Err(err) => assert!(
                err.to_string().contains("corrupt link count"),
                "the verdict must refuse for the same reason: {err}"
            ),
            Ok(verdict) => panic!("corruption must never produce a verdict, got {verdict:?}"),
        }
    }

    /// The same value read back through the manifest: an unchecked `as u64` would turn `-1` into
    /// `u64::MAX` and hand a hashing candidate a link count larger than the filesystem could ever
    /// report. Reading must fail instead.
    #[test]
    fn a_corrupt_negative_link_count_refuses_candidate_reading() {
        // Two rows of one size, so both are hashing candidates.
        let (store, id) = store_with_seeded_manifest(&[("/tank/a", 100, -1), ("/tank/b", 100, 1)]);

        match store.candidate_objects(id) {
            Err(err) => assert!(
                err.to_string().contains("corrupt link count"),
                "the message must name the cause: {err}"
            ),
            Ok(rows) => panic!(
                "a corrupt row must not be readable, got {:?}",
                rows.iter().map(|row| row.nlink).collect::<Vec<_>>()
            ),
        }
    }

    /// The accepted domain, at its edges: `0` stays the ordinary legacy unknown, `1` and a larger
    /// real count round-trip untouched, and the scan only counts as known once no row is left at
    /// `0`.
    #[test]
    fn link_count_boundaries_round_trip_through_the_manifest() {
        let (store, id) = store_with_seeded_manifest(&[
            ("/tank/a", 100, 0),
            ("/tank/b", 100, 1),
            ("/tank/c", 100, 4),
        ]);

        let mut read: Vec<(String, u64)> = store
            .candidate_objects(id)
            .unwrap()
            .into_iter()
            .map(|row| (row.path.to_string_lossy().into_owned(), row.nlink))
            .collect();
        read.sort();
        assert_eq!(
            read,
            vec![
                ("/tank/a".to_string(), 0),
                ("/tank/b".to_string(), 1),
                ("/tank/c".to_string(), 4),
            ],
            "0 stays unknown, real counts survive unchanged"
        );

        assert!(
            !store.scan_link_counts_known(id).unwrap(),
            "one legacy row is enough to make the scan unknown"
        );
        assert_eq!(
            store.destructive_plan_verdict(id).unwrap(),
            DestructivePlanVerdict::RescanRequired,
            "a 0 is the ordinary legacy refusal, not an error"
        );

        store
            .conn
            .execute("DELETE FROM file WHERE path = '/tank/a'", [])
            .unwrap();
        assert!(
            store.scan_link_counts_known(id).unwrap(),
            "with every row at 1 or more the counts are known"
        );
    }

    /// The write side of the same invariant: a count SQLite's signed column cannot hold must be
    /// refused before the insert, not wrapped into a negative the reader would then call corrupt.
    #[test]
    fn a_link_count_too_large_for_the_column_is_refused_before_it_is_written() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        let row = ManifestRow {
            path: PathBuf::from("/tank/a"),
            size: 100,
            device: 1,
            inode: 2,
            nlink: u64::MAX,
            ..Default::default()
        };

        assert!(
            store.record_files(id, &[row]).is_err(),
            "a count that does not fit the column must not be written"
        );
        let negative: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM file WHERE scan_id = ?1 AND nlink < 0",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(negative, 0, "nothing negative reached the manifest");
    }

    /// Seeds a scan whose `file.nlink` cells are written as the given raw SQL literals, and marks
    /// the reclaim state `Exact` — so the link-count check is the only thing between the scan and
    /// `Allowed`. All rows share one size, so every one of them is a hashing candidate.
    ///
    /// SQLite's `INTEGER` is a type *affinity*, not a constraint: `1.5` really is stored as `real`
    /// and `'oops'` as `text` in a non-`STRICT` table. Each test asserts the storage class it got
    /// before relying on it.
    fn store_with_raw_nlinks(literals: &[&str]) -> (ScanStore, i64) {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        for (index, literal) in literals.iter().enumerate() {
            let inode = index + 1;
            store
                .conn
                .execute_batch(&format!(
                    "INSERT INTO file(scan_id, path, size, mtime, device, inode, nlink)
                     VALUES ({id}, '/tank/f{index}', 100, 42, 10, {inode}, {literal});"
                ))
                .unwrap();
        }
        store
            .conn
            .execute(
                "UPDATE scan_stats SET reclaim_state = ?2 WHERE scan_id = ?1",
                params![id, ReclaimState::Exact.as_i64()],
            )
            .unwrap();
        (store, id)
    }

    fn stored_class(store: &ScanStore, path: &str) -> String {
        store
            .conn
            .query_row(
                "SELECT typeof(nlink) FROM file WHERE path = ?1",
                params![path],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// A link count that is not an integer at all. None of these compare `<= 0` — numbers sort
    /// below text and blobs — so a purely numeric test skips them and calls the manifest fully
    /// known. They must be refused instead, both by the planning gate and by manifest reading.
    #[test]
    fn a_non_integer_link_count_refuses_planning_and_reading() {
        for (literal, class) in [("1.5", "real"), ("'oops'", "text"), ("X'00'", "blob")] {
            // A valid row beside it, so nothing here depends on the scan being otherwise empty.
            let (store, id) = store_with_raw_nlinks(&[literal, "1"]);
            assert_eq!(
                stored_class(&store, "/tank/f0"),
                class,
                "{literal} must really land as {class}"
            );

            let err = store
                .scan_link_counts_known(id)
                .expect_err("a non-integer link count must not read as known")
                .to_string();
            assert!(
                err.contains(&format!("stored as {class}")),
                "the message must name the storage class: {err}"
            );

            match store.destructive_plan_verdict(id) {
                Err(err) => assert!(
                    err.to_string().contains("not an integer"),
                    "the verdict must refuse for the same reason: {err}"
                ),
                Ok(verdict) => panic!("{literal} must never produce a verdict, got {verdict:?}"),
            }

            match store.candidate_objects(id) {
                Err(err) => assert!(
                    err.to_string().contains(&format!("stored as {class}")),
                    "reading must refuse for the same named reason: {err}"
                ),
                Ok(rows) => panic!("{literal} must not become a manifest row, got {rows:?}"),
            }
        }
    }

    /// Corruption must win over the ordinary legacy case: a row with an invalid storage class
    /// cannot be hidden by a `0` or a negative row that the numeric ordering would otherwise
    /// surface first.
    #[test]
    fn an_invalid_storage_class_is_not_hidden_by_a_zero_or_negative_row() {
        let (store, id) = store_with_raw_nlinks(&["0", "'oops'", "-1"]);
        assert_eq!(stored_class(&store, "/tank/f1"), "text");

        let err = store
            .scan_link_counts_known(id)
            .expect_err("an invalid storage class must not be hidden")
            .to_string();
        assert!(
            err.contains("stored as text"),
            "the invalid type must be reported, not the 0 or the -1: {err}"
        );
        assert!(
            store.destructive_plan_verdict(id).is_err(),
            "and planning must never proceed"
        );
    }

    // ---- C3c: candidate statistics -------------------------------------------------------------

    fn sized_row(path: &str, inode: u64, size: u64) -> ManifestRow {
        ManifestRow {
            size,
            ..alias_row(path, inode, 11)
        }
    }

    fn stats_of(rows: &[ManifestRow]) -> (ScanStore, i64, CandidateStats) {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store.record_files(id, rows).unwrap();
        let stats = store.candidate_stats(id).unwrap();
        (store, id, stats)
    }

    #[test]
    fn an_empty_manifest_has_no_candidate_statistics() {
        let (_store, _id, stats) = stats_of(&[]);
        assert_eq!(
            (
                stats.total_files,
                stats.total_bytes,
                stats.hashed_files,
                stats.hashed_bytes
            ),
            (0, 0, 0, 0)
        );
    }

    /// Neither a size only one object has, nor a size several *names of one object* share, is
    /// something to hash. Both must be absent from every total.
    #[test]
    fn unique_sizes_and_alias_only_sizes_are_excluded_from_every_total() {
        let (_store, _id, stats) = stats_of(&[
            // One object under three names: one allocation, nothing to compare it with.
            sized_row("/x/a1", 2, 100),
            sized_row("/x/a2", 2, 100),
            sized_row("/x/a3", 2, 100),
            // A size nobody else has.
            sized_row("/x/lonely", 3, 999),
        ]);
        assert_eq!(
            (
                stats.total_files,
                stats.total_bytes,
                stats.hashed_files,
                stats.hashed_bytes
            ),
            (0, 0, 0, 0),
            "aliases alone do not make a size eligible"
        );
    }

    #[test]
    fn two_independent_objects_of_one_size_are_two_paths_and_two_object_sizes() {
        let (_store, _id, stats) =
            stats_of(&[sized_row("/x/a", 2, 100), sized_row("/x/b", 3, 100)]);
        assert_eq!((stats.total_files, stats.total_bytes), (2, 200));
        assert_eq!((stats.hashed_files, stats.hashed_bytes), (0, 0));
    }

    /// The two dimensions, side by side: every pathname is counted, every allocation once.
    #[test]
    fn aliases_count_as_paths_while_bytes_count_allocations() {
        let (_store, _id, stats) = stats_of(&[
            sized_row("/x/a1", 2, 100),
            sized_row("/x/a2", 2, 100),
            sized_row("/x/a3", 2, 100),
            sized_row("/x/b", 3, 100),
        ]);
        assert_eq!(stats.total_files, 4, "four pathnames must end up hashed");
        assert_eq!(stats.total_bytes, 200, "over two allocations");
    }

    /// A partially hashed object: only the pathnames that actually carry a digest advance the file
    /// counter, while its allocation enters the byte counter once — it was read once.
    #[test]
    fn a_partially_hashed_object_charges_its_bytes_once() {
        let (store, id, before) = stats_of(&[
            sized_row("/x/a1", 2, 100),
            sized_row("/x/a2", 2, 100),
            sized_row("/x/b", 3, 100),
        ]);
        assert_eq!((before.total_files, before.total_bytes), (3, 200));

        // Only one of the two aliases is given a digest, directly, without propagation.
        store
            .conn
            .execute(
                "UPDATE file SET hash = X'AA' WHERE scan_id = ?1 AND path = '/x/a1'",
                params![id],
            )
            .unwrap();

        let stats = store.candidate_stats(id).unwrap();
        assert_eq!(stats.hashed_files, 1, "one pathname carries a digest");
        assert_eq!(
            stats.hashed_bytes, 100,
            "and its allocation is charged once, not once per alias"
        );
    }

    /// On a clean completion both dimensions reach their totals — pathnames because propagation
    /// fills the aliases, bytes because every allocation was read.
    #[test]
    fn a_clean_completion_reaches_both_totals() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                id,
                &[
                    sized_row("/x/a1", 2, 100),
                    sized_row("/x/a2", 2, 100),
                    sized_row("/x/b", 3, 100),
                ],
            )
            .unwrap();
        let total = store.candidate_stats(id).unwrap();

        for representative in store.candidate_objects(id).unwrap() {
            store
                .record_hashes_verified(id, &[(representative, [3u8; 32])])
                .unwrap();
        }

        let done = store.candidate_stats(id).unwrap();
        assert_eq!(done.hashed_files, total.total_files, "every pathname");
        assert_eq!(done.hashed_bytes, total.total_bytes, "every allocation");
    }

    // ---- C3a: the grouped link-count boundary --------------------------------------------------

    /// Object A under two names on inode 2, each with the given raw `nlink` literal, plus an
    /// independent object B of the same size — so the size is genuinely eligible and A is genuinely
    /// a candidate, rather than the test proving something about an empty set.
    fn store_with_alias_pair(literals: [&str; 2]) -> (ScanStore, i64) {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        let [first, second] = literals;
        store
            .conn
            .execute_batch(&format!(
                "INSERT INTO file(scan_id, path, size, mtime, mtime_nsec, ctime_sec, ctime_nsec,
                                  device, inode, nlink)
                 VALUES ({id}, '/tank/a1', 100, 5, 7, 9, 11, 1, 2, {first}),
                        ({id}, '/tank/a2', 100, 5, 7, 9, 11, 1, 2, {second}),
                        ({id}, '/tank/b',  100, 5, 7, 9, 11, 1, 3, 1);"
            ))
            .unwrap();
        (store, id)
    }

    /// Grouping is where a corrupt cell can hide: `MIN` over `(integer 1, text 'oops')` returns the
    /// integer, because SQLite sorts numbers below text. The valid alias must not vouch for its
    /// broken twin — they are two names for one inode.
    #[test]
    fn a_corrupt_alias_cannot_hide_behind_a_valid_one() {
        for (literal, class) in [("'oops'", "text"), ("1.5", "real"), ("X'78'", "blob")] {
            let (store, id) = store_with_alias_pair(["1", literal]);
            assert_eq!(
                stored_class(&store, "/tank/a2"),
                class,
                "{literal} must really land as {class}"
            );

            match store.candidate_objects(id) {
                Err(err) => assert!(
                    err.to_string().contains(class),
                    "the message must name the offending storage class: {err}"
                ),
                Ok(rows) => panic!(
                    "{literal} was hidden by its valid alias, got link counts {:?}",
                    rows.iter().map(|row| row.nlink).collect::<Vec<_>>()
                ),
            }
        }
    }

    /// Two names for one inode cannot have two different link counts. That is an inconsistent
    /// checkpoint, not a value to pick between.
    #[test]
    fn aliases_of_one_object_may_not_disagree_on_the_link_count() {
        let (store, id) = store_with_alias_pair(["1", "2"]);
        let err = store
            .candidate_objects(id)
            .expect_err("disagreeing link counts must refuse")
            .to_string();
        assert!(
            err.contains("different link counts"),
            "the message must name the cause: {err}"
        );
    }

    /// The `NULL` half of the same boundary, asserted on the evidence type directly: the column's
    /// `NOT NULL` keeps a NULL out of any manifest this build writes, so there is no DB fixture to
    /// build — and the gate deliberately does not rely on that constraint holding. Aggregates skip
    /// NULLs, which is exactly why the class extremes, not `MIN(nlink)`, are what detect it.
    #[test]
    fn a_null_alias_cannot_hide_behind_a_valid_one() {
        let mixed = GroupedLinkCount {
            value: Value::Integer(1),
            distinct: 1,
            min_class: "integer".to_string(),
            max_class: "null".to_string(),
        };
        let err = mixed
            .decode(Path::new("/tank/a1"))
            .expect_err("a NULL beside an integer must refuse")
            .to_string();
        assert!(
            err.contains("null") && err.contains("integer"),
            "the message must name both classes: {err}"
        );

        // And a group that is wholly NULL reaches the shared decoder, which names it.
        let all_null = GroupedLinkCount {
            value: Value::Null,
            distinct: 0,
            min_class: "null".to_string(),
            max_class: "null".to_string(),
        };
        assert!(all_null
            .decode(Path::new("/tank/a1"))
            .expect_err("a NULL link count must refuse")
            .to_string()
            .contains("stored as null"));
    }

    /// Control: aliases that agree on a real count produce exactly one representative for their
    /// object, deterministically the first pathname, and the count survives unchanged.
    #[test]
    fn aliases_agreeing_on_a_positive_count_yield_one_representative() {
        let (store, id) = store_with_alias_pair(["2", "2"]);
        let rows = store.candidate_objects(id).unwrap();
        assert_eq!(rows.len(), 2, "object A once, plus the control object B");

        let a = rows.iter().find(|row| row.inode == 2).expect("object A");
        assert_eq!(
            a.path,
            PathBuf::from("/tank/a1"),
            "the representative is the first pathname of the object"
        );
        assert_eq!(a.nlink, 2, "and it carries the count its aliases agree on");
    }

    /// Control: a wholly legacy object stays the accepted unknown rather than becoming an error.
    #[test]
    fn all_legacy_zero_aliases_stay_the_accepted_unknown() {
        let (store, id) = store_with_alias_pair(["0", "0"]);
        let rows = store.candidate_objects(id).unwrap();
        let a = rows.iter().find(|row| row.inode == 2).expect("object A");
        assert_eq!(a.nlink, 0, "0 is legacy-unknown, not corruption");
    }

    // ---- R2B: hash once, preserve every pathname ----------------------------------------------

    /// Runs a real scan of `root` and returns the store, the scan id and the reads it performed.
    fn scan_counting_reads(root: &Path) -> (ScanStore, i64, usize) {
        let mut store = ScanStore::open_in_memory().unwrap();
        let mut config = ScanConfig::new(vec![root.to_path_buf()]);
        config.min_size = 0;
        config.exclude_globs = Vec::new();
        let cancel = AtomicBool::new(false);

        let log = crate::testfixtures::ReadLog::start();
        match crate::pipeline::run_scan(&mut store, &config, None, false, &cancel, |_| {}) {
            Ok(crate::pipeline::ScanOutcome::Completed(_)) => {}
            Ok(crate::pipeline::ScanOutcome::Cancelled) => {
                panic!("the scan must not cancel itself")
            }
            Err(err) => panic!("scan {}: {err}", root.display()),
        }
        let reads = log.count_under(root);
        drop(log);

        let id = store.latest_scan_id().unwrap().expect("the scan exists");
        (store, id, reads)
    }

    /// Every manifest pathname with its digest, as hex; `None` where no digest was recorded.
    fn digests(store: &ScanStore, scan_id: i64) -> Vec<(String, Option<String>)> {
        let mut stmt = store
            .conn
            .prepare("SELECT path, hash FROM file WHERE scan_id = ?1 ORDER BY path")
            .unwrap();
        let rows = stmt
            .query_map(params![scan_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?.map(|h| hex_encode(&h)),
                ))
            })
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = temp_state_dir(tag).join("root");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The forest end to end: three reads for three allocations, every one of the seven pathnames
    /// still in the manifest, and all six duplicate-content pathnames carrying the same digest —
    /// the four aliases got theirs by propagation, having never been opened.
    #[test]
    fn every_alias_receives_the_digest_its_object_was_read_for() {
        let forest = crate::testfixtures::HardlinkForest::build("r2b_forest");
        let (store, id, reads) = scan_counting_reads(&forest.root);

        assert_eq!(reads, 3, "one read per allocation");
        let recorded = digests(&store, id);
        assert_eq!(recorded.len(), 7, "seven pathnames, seven manifest rows");

        let by_path: std::collections::HashMap<&str, &Option<String>> = recorded
            .iter()
            .map(|(path, hash)| (path.as_str(), hash))
            .collect();
        let duplicate = forest.duplicate_pathnames();
        let first = by_path[duplicate[0].to_string_lossy().as_ref()]
            .clone()
            .expect("the first duplicate pathname has a digest");
        for path in &duplicate {
            assert_eq!(
                by_path[path.to_string_lossy().as_ref()].as_ref(),
                Some(&first),
                "{} must carry the group's digest",
                path.display()
            );
        }
        assert!(
            by_path[forest.unique.to_string_lossy().as_ref()].is_none(),
            "the unique-size file is not a candidate and stays unhashed"
        );

        // The link outside the scan root is not, and must not become, a manifest row.
        assert!(
            !recorded
                .iter()
                .any(|(path, _)| path == &forest.external.to_string_lossy()),
            "the unobserved link must not appear in the manifest"
        );

        // One propagation statement for the inheritance pass plus one per hashing batch — never
        // one per alias.
        assert_eq!(
            store.propagation_statements(),
            2,
            "set-based propagation: one inheritance pass + one batch"
        );
    }

    /// An alias-only set is one allocation under several names. There is nothing to compare it
    /// with, so nothing is read — and every pathname still keeps its row.
    #[test]
    fn an_alias_only_set_is_read_zero_times() {
        let root = scratch("r2b_alias_only");
        let first = root.join("a.bin");
        std::fs::write(&first, vec![7u8; 4096]).unwrap();
        for name in ["b.bin", "c.bin"] {
            std::fs::hard_link(&first, root.join(name)).unwrap();
        }

        let (store, id, reads) = scan_counting_reads(&root);
        assert_eq!(reads, 0, "one allocation is not a duplicate of itself");
        assert!(
            store.candidate_objects(id).unwrap().is_empty(),
            "and it is not a candidate"
        );
        let recorded = digests(&store, id);
        assert_eq!(recorded.len(), 3, "all three pathnames keep their rows");
        assert!(
            recorded.iter().all(|(_, hash)| hash.is_none()),
            "nothing was hashed, so nothing carries a digest"
        );
        assert!(
            store.duplicate_groups(id).unwrap().is_empty(),
            "and no duplicate-content group is formed"
        );

        std::fs::remove_dir_all(root.parent().unwrap()).ok();
    }

    /// The control that must not move: two byte-identical files on two inodes are read twice and
    /// still form an ordinary group.
    #[test]
    fn two_independent_identical_files_are_still_read_twice() {
        let root = scratch("r2b_control");
        for name in ["a.bin", "b.bin"] {
            std::fs::write(root.join(name), vec![7u8; 4096]).unwrap();
        }

        let (store, id, reads) = scan_counting_reads(&root);
        assert_eq!(reads, 2, "two allocations, two reads");
        let groups = store.duplicate_groups(id).unwrap();
        assert_eq!(groups.len(), 1, "the ordinary group is still found");
        assert_eq!(groups[0].files.len(), 2);

        std::fs::remove_dir_all(root.parent().unwrap()).ok();
    }

    /// A manifest row on object `(device 1, inode)` with an explicit temporal identity, so a test
    /// can state exactly which pathnames are the same allocation and which are not.
    fn alias_row(path: &str, inode: u64, ctime_nsec: i64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size: 100,
            mtime: 5,
            mtime_nsec: 7,
            ctime_sec: 9,
            ctime_nsec,
            device: 1,
            inode,
            nlink: 2,
        }
    }

    /// A finished past scan holding a trusted (fd-verified) digest for every given row.
    fn past_scan(store: &mut ScanStore, rows: &[ManifestRow], hash: [u8; 32]) -> i64 {
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store.record_files(id, rows).unwrap();
        let pairs: Vec<(ManifestRow, [u8; 32])> =
            rows.iter().map(|row| (row.clone(), hash)).collect();
        store.record_hashes_verified(id, &pairs).unwrap();
        id
    }

    fn hash_of(store: &ScanStore, scan_id: i64, path: &str) -> Option<String> {
        store
            .conn
            .query_row(
                "SELECT hash FROM file WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, path],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .unwrap()
            .map(|h| hex_encode(&h))
    }

    /// R7a — the zero-read case, in the shape a filesystem can actually produce: a hardlink
    /// pathname that already existed but lay outside the previous scan's roots, so it has no past
    /// manifest row of its own. Nothing on disk changed between the two scans, so the inode's
    /// ctime is untouched and the pathname that *was* in scope still matches its past row exactly.
    ///
    /// It inherits by path, the newly visible pathname is filled by current-object propagation,
    /// and the allocation is left with nothing to read.
    ///
    /// A rename cannot stand in for this: `rename(2)` updates the inode's ctime, which is
    /// `an_object_whose_ctime_moved_is_read_exactly_once` below.
    #[test]
    fn a_newly_visible_alias_is_filled_from_its_surviving_twin_without_a_read() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let hash = [9u8; 32];
        // The past scan saw only /x/a. /x/b was already a link to the same inode, but outside that
        // scan's roots, so the checkpoint has no row for it.
        past_scan(&mut store, &[alias_row("/x/a", 2, 11)], hash);

        // The current scan's roots now cover both pathnames of that same, untouched allocation —
        // same device, inode and full temporal identity as the past row.
        let now = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(now, &[alias_row("/x/a", 2, 11), alias_row("/x/b", 2, 11)])
            .unwrap();

        assert_eq!(
            store.inherit_hashes(now).unwrap(),
            1,
            "only /x/a has a past row to inherit from"
        );
        assert_eq!(
            store.propagate_inherited_hashes(now).unwrap(),
            1,
            "and /x/b is filled from it, unread"
        );

        let expected = Some(hex_encode(&hash));
        assert_eq!(hash_of(&store, now, "/x/a"), expected);
        assert_eq!(hash_of(&store, now, "/x/b"), expected);
        assert!(
            store.candidate_objects(now).unwrap().is_empty(),
            "nothing is left to read"
        );
    }

    /// R7a-prime — an actual name mutation. `rename(2)`, `link(2)` and `unlink(2)` all update the
    /// inode's ctime, so once a twin is renamed the whole allocation carries a temporal identity
    /// the past manifest does not have — including the pathname that kept its own name and was
    /// never touched. Nothing inherits, and the allocation is read exactly once, through one
    /// deterministic representative, however many names point at it.
    ///
    /// This is the case a rename really produces; the zero-read one is
    /// `a_newly_visible_alias_is_filled_from_its_surviving_twin_without_a_read` above.
    #[test]
    fn an_object_whose_ctime_moved_is_read_exactly_once() {
        let mut store = ScanStore::open_in_memory().unwrap();
        past_scan(
            &mut store,
            &[alias_row("/x/a", 2, 11), alias_row("/x/b", 2, 11)],
            [9u8; 32],
        );

        // `/x/b` was renamed to `/x/b2`. That moved the inode's ctime from 11 to 77, so BOTH
        // pathnames of the object now fail the cross-scan match — `/x/a` included. A second
        // allocation of the same size keeps the size eligible at all.
        let now = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                now,
                &[
                    alias_row("/x/a", 2, 77),
                    alias_row("/x/b2", 2, 77),
                    alias_row("/x/other", 3, 11),
                ],
            )
            .unwrap();

        assert_eq!(
            store.inherit_hashes(now).unwrap(),
            0,
            "the ctime moved, so not even the surviving pathname matches"
        );
        assert_eq!(
            store.propagate_inherited_hashes(now).unwrap(),
            0,
            "and there is no trusted digest to spread"
        );
        let candidates = store.candidate_objects(now).unwrap();
        assert_eq!(candidates.len(), 2, "two allocations, two representatives");
        let mut representatives: Vec<String> = candidates
            .iter()
            .map(|row| row.path.to_string_lossy().into_owned())
            .collect();
        representatives.sort();
        assert_eq!(
            representatives,
            vec!["/x/a".to_string(), "/x/other".to_string()],
            "one representative for the mutated object, one for the control, both deterministic"
        );
    }

    /// A pathname whose content was replaced by something else of the same size must not receive a
    /// digest — not by inheritance, whose key includes the full temporal identity, and not by
    /// propagation, which is a different allocation.
    #[test]
    fn a_same_size_replacement_receives_no_digest() {
        let mut store = ScanStore::open_in_memory().unwrap();
        past_scan(&mut store, &[alias_row("/x/a", 2, 11)], [9u8; 32]);

        let now = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                now,
                &[
                    // Same path and size, new content: a different ctime, and a different inode.
                    alias_row("/x/a", 4, 77),
                    alias_row("/x/other", 3, 11),
                ],
            )
            .unwrap();

        assert_eq!(
            store.inherit_hashes(now).unwrap(),
            0,
            "the identity differs"
        );
        assert_eq!(store.propagate_inherited_hashes(now).unwrap(), 0);
        assert_eq!(hash_of(&store, now, "/x/a"), None, "and it stays unhashed");
    }

    fn identity_version_of(store: &ScanStore, scan_id: i64, path: &str) -> i64 {
        store
            .conn
            .query_row(
                "SELECT identity_version FROM file WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, path],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// Two aliases of one allocation whose past digests disagree cannot both be right. The refusal
    /// has to come *before* anything is written: choosing by row order would be answering a
    /// data-safety question at random, and inheriting one of them first would leave the scan
    /// half-poisoned even though the answer is unknowable.
    #[test]
    fn conflicting_inherited_digests_refuse_instead_of_picking_one() {
        let mut store = ScanStore::open_in_memory().unwrap();
        past_scan(&mut store, &[alias_row("/x/a", 2, 11)], [1u8; 32]);
        past_scan(&mut store, &[alias_row("/x/b", 2, 11)], [2u8; 32]);

        let now = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                now,
                &[
                    alias_row("/x/a", 2, 11),
                    alias_row("/x/b", 2, 11),
                    alias_row("/x/c", 2, 11),
                ],
            )
            .unwrap();

        let err = store
            .inherit_hashes(now)
            .expect_err("disagreeing digests for one allocation must refuse");
        assert!(
            err.to_string().contains("more than one"),
            "the message must name the cause: {err}"
        );

        // No winner, and no partial state: nothing was written at all.
        for path in ["/x/a", "/x/b", "/x/c"] {
            assert_eq!(
                hash_of(&store, now, path),
                None,
                "{path} must stay unhashed"
            );
            assert_eq!(
                identity_version_of(&store, now, path),
                0,
                "{path} untouched"
            );
        }
        // The independent current-scan defence still refuses too, on a scan left exactly as it was.
        assert_eq!(store.propagate_inherited_hashes(now).unwrap(), 0);
    }

    /// Two past scans offering different digests for the *same* current pathname. The old
    /// correlated `LIMIT 1` answered this by row order, and the later current-object check could
    /// not notice, because by then only the chosen digest existed.
    #[test]
    fn two_past_scans_disagreeing_about_one_pathname_refuse_inheritance() {
        let mut store = ScanStore::open_in_memory().unwrap();
        past_scan(&mut store, &[alias_row("/x/a", 2, 11)], [1u8; 32]);
        past_scan(&mut store, &[alias_row("/x/a", 2, 11)], [2u8; 32]);

        let now = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                now,
                &[alias_row("/x/a", 2, 11), alias_row("/x/other", 3, 11)],
            )
            .unwrap();

        let err = store
            .inherit_hashes(now)
            .expect_err("two past digests for one pathname must refuse");
        assert!(
            err.to_string().contains("more than one"),
            "the message must name the cause: {err}"
        );
        assert_eq!(
            hash_of(&store, now, "/x/a"),
            None,
            "no arbitrary winner was written"
        );
        assert_eq!(identity_version_of(&store, now, "/x/a"), 0);
    }

    /// A digest already trusted on the current object is evidence too. A twin whose past source
    /// disagrees with it must refuse, leaving the trusted digest exactly where it was.
    #[test]
    fn a_past_digest_disagreeing_with_the_current_object_refuses() {
        let mut store = ScanStore::open_in_memory().unwrap();
        past_scan(&mut store, &[alias_row("/x/b", 2, 11)], [1u8; 32]);

        let now = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(now, &[alias_row("/x/a", 2, 11), alias_row("/x/b", 2, 11)])
            .unwrap();
        // /x/a is already fd-verified in this scan, with a different digest.
        store
            .record_hashes_verified(now, &[(alias_row("/x/a", 2, 11), [7u8; 32])])
            .unwrap();
        // Propagation gave the alias the trusted digest; put it back to null so the past source is
        // the only thing offering /x/b a value.
        store
            .conn
            .execute(
                "UPDATE file SET hash = NULL, identity_version = 0
                  WHERE scan_id = ?1 AND path = '/x/b'",
                params![now],
            )
            .unwrap();

        let err = store
            .inherit_hashes(now)
            .expect_err("a past digest contradicting the current object must refuse");
        assert!(err.to_string().contains("more than one"), "{err}");
        assert_eq!(
            hash_of(&store, now, "/x/a"),
            Some(hex_encode(&[7u8; 32])),
            "the digest this scan verified is preserved"
        );
        assert_eq!(
            hash_of(&store, now, "/x/b"),
            None,
            "and the twin stays null"
        );
    }

    /// Several past scans carrying the SAME digest are agreement, not a conflict.
    #[test]
    fn repeated_past_rows_with_one_digest_are_agreement() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let hash = [1u8; 32];
        past_scan(&mut store, &[alias_row("/x/a", 2, 11)], hash);
        past_scan(&mut store, &[alias_row("/x/a", 2, 11)], hash);
        past_scan(&mut store, &[alias_row("/x/a", 2, 11)], hash);

        let now = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                now,
                &[alias_row("/x/a", 2, 11), alias_row("/x/other", 3, 11)],
            )
            .unwrap();

        assert_eq!(
            store.inherit_hashes(now).unwrap(),
            1,
            "exactly one current row inherits"
        );
        assert_eq!(hash_of(&store, now, "/x/a"), Some(hex_encode(&hash)));
        assert_eq!(identity_version_of(&store, now, "/x/a"), 1);
    }

    /// A representative whose manifest identity no longer matches what was opened commits nothing
    /// — and therefore propagates nothing to its aliases either.
    #[test]
    fn a_representative_that_lost_its_identity_propagates_to_no_alias() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                id,
                &[
                    alias_row("/x/a", 2, 11),
                    alias_row("/x/b", 2, 11),
                    alias_row("/x/other", 3, 11),
                ],
            )
            .unwrap();

        // What the hashing phase saw no longer matches the manifest row.
        let stale = ManifestRow {
            ctime_nsec: 999,
            ..alias_row("/x/a", 2, 11)
        };
        let persisted = store
            .record_hashes_verified(id, &[(stale, [5u8; 32])])
            .unwrap();
        assert_eq!(
            persisted,
            PersistedHashes::default(),
            "nothing committed, nothing propagated, no bytes claimed"
        );
        assert_eq!(hash_of(&store, id, "/x/a"), None);
        assert_eq!(hash_of(&store, id, "/x/b"), None);
    }

    /// After a cancellation the committed objects stay committed, and a resume re-selects only
    /// what is genuinely left — each remaining allocation exactly once.
    #[test]
    fn a_resume_reads_every_remaining_object_at_most_once() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                id,
                &[
                    alias_row("/x/a", 2, 11),
                    alias_row("/x/b", 2, 11),
                    alias_row("/x/c", 3, 11),
                    alias_row("/x/d", 4, 11),
                ],
            )
            .unwrap();

        // One batch got through before the cancellation.
        let first = store.candidate_objects(id).unwrap();
        assert_eq!(first.len(), 3, "three allocations, three representatives");
        let done = first[0].clone();
        let persisted = store
            .record_hashes_verified(id, &[(done.clone(), [8u8; 32])])
            .unwrap();
        assert_eq!(persisted.representatives, 1);
        assert_eq!(persisted.bytes, 100, "one allocation, charged once");

        // Resume: the finished allocation is gone from the candidates, the rest appear once each.
        let resumed = store.candidate_objects(id).unwrap();
        let objects: Vec<u64> = resumed.iter().map(|row| row.inode).collect();
        assert_eq!(objects.len(), 2, "only the unfinished allocations");
        assert!(
            !objects.contains(&done.inode),
            "a committed object is not read again"
        );
        let mut unique = objects.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), objects.len(), "and each appears exactly once");
    }

    /// Progress counts pathnames in one dimension and allocations in the other: an alias completes
    /// a pathname without claiming a byte that was never read.
    #[test]
    fn propagated_aliases_advance_pathnames_without_inflating_bytes() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        store
            .record_files(
                id,
                &[
                    alias_row("/x/a", 2, 11),
                    alias_row("/x/b", 2, 11),
                    alias_row("/x/c", 2, 11),
                    alias_row("/x/other", 3, 11),
                ],
            )
            .unwrap();

        let stats = store.candidate_stats(id).unwrap();
        assert_eq!(stats.total_files, 4, "four pathnames must end up hashed");
        assert_eq!(
            stats.total_bytes, 200,
            "but only two allocations will be read"
        );

        let before = store.propagation_statements();
        let persisted = store
            .record_hashes_verified(id, &[(alias_row("/x/a", 2, 11), [8u8; 32])])
            .unwrap();
        assert_eq!(persisted.representatives, 1, "one representative committed");
        assert_eq!(persisted.files, 3, "and it completed three pathnames");
        assert_eq!(persisted.bytes, 100, "having read one allocation once");
        assert_eq!(
            store.propagation_statements() - before,
            1,
            "one statement for the batch, not one per alias"
        );

        let after = store.candidate_stats(id).unwrap();
        assert_eq!(after.hashed_files, 3);
        assert_eq!(
            after.hashed_bytes, 100,
            "bytes follow allocations, not names"
        );
    }

    /// The decoder itself, over every storage class SQLite can put in the column. `null` is here
    /// even though `NOT NULL` should keep it out of a DB this build wrote — the point of the gate
    /// is that it does not depend on the column definition holding.
    #[test]
    fn only_the_integer_storage_class_reaches_the_numeric_domain() {
        for (value, class) in [
            (Value::Null, "null"),
            (Value::Real(1.5), "real"),
            (Value::Text("oops".to_string()), "text"),
            (Value::Blob(vec![0]), "blob"),
        ] {
            let err = link_count_from_sql(&value)
                .expect_err("a non-integer storage class must not decode")
                .to_string();
            assert!(
                err.contains(&format!("stored as {class}")),
                "the message must name the storage class: {err}"
            );
        }

        // Integers still go through the numeric domain unchanged.
        assert_eq!(
            link_count_from_sql(&Value::Integer(0)).unwrap(),
            LinkCount::Unknown
        );
        assert_eq!(
            link_count_from_sql(&Value::Integer(4)).unwrap(),
            LinkCount::Known(4)
        );
        assert!(link_count_from_sql(&Value::Integer(-1)).is_err());
    }

    // -----------------------------------------------------------------------------------------
    // The omission ledger.
    // -----------------------------------------------------------------------------------------

    fn key(path: &str) -> PathKey {
        PathKey::new(Path::new(path)).expect("a keyable path")
    }

    /// A store with one scan rooted at the given paths.
    fn ledger_store(roots: &[&str]) -> (ScanStore, i64) {
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(roots.iter().map(PathBuf::from).collect());
        let scan_id = store.begin_scan(&config).unwrap();
        (store, scan_id)
    }

    /// One root's counts, from a list of `(directory, reason)` events.
    fn counts(events: &[(&str, OmissionReason)]) -> OmissionCounts {
        let mut out = OmissionCounts::new();
        for (dir, reason) in events {
            out.bump(key(dir), *reason).unwrap();
        }
        out
    }

    /// A whole-scan ledger for one root.
    fn one_root(
        root: &str,
        events: &[(&str, OmissionReason)],
    ) -> BTreeMap<PathKey, OmissionCounts> {
        BTreeMap::from([(key(root), counts(events))])
    }

    fn verdict(store: &ScanStore, scan_id: i64, dir: &str) -> DirCompleteness {
        store
            .directory_completeness(scan_id, &[Path::new(dir)])
            .unwrap()
            .remove(Path::new(dir))
            .expect("every requested directory gets a verdict")
    }

    /// A root that omitted nothing is `Complete` — but only because it was reported explicitly.
    #[test]
    fn an_explicitly_empty_root_is_complete() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Complete);
        assert_eq!(
            verdict(&store, scan_id, "/tank/a"),
            DirCompleteness::Complete
        );
    }

    /// The same empty ledger, before any commit, is NOT complete. Emptiness is never the signal:
    /// the authority is.
    #[test]
    fn an_uncommitted_scan_is_unknown_not_complete() {
        let (store, scan_id) = ledger_store(&["/tank"]);
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(0)
        );
    }

    /// An empty map proves nothing about any root, so it cannot buy an authority.
    #[test]
    fn an_empty_ledger_map_is_refused() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        let err = store
            .commit_omissions(scan_id, &BTreeMap::new())
            .expect_err("an empty map must not set the authority");
        assert!(err.to_string().contains("missing scan root"), "{err}");
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
    }

    /// A subset of a multi-root scan is refused: reporting one root says nothing about the other.
    #[test]
    fn a_subset_of_the_root_set_is_refused() {
        let (mut store, scan_id) = ledger_store(&["/tank/one", "/tank/two"]);
        let err = store
            .commit_omissions(scan_id, &one_root("/tank/one", &[]))
            .expect_err("a subset must be refused");
        assert!(err.to_string().contains("/tank/two"), "{err}");
        for dir in ["/tank/one", "/tank/two"] {
            assert_eq!(verdict(&store, scan_id, dir), DirCompleteness::Unknown);
        }
    }

    /// A root nobody selected cannot join the ledger either.
    #[test]
    fn an_extra_root_is_refused() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        let mut per_root = one_root("/tank", &[]);
        per_root.insert(key("/other"), OmissionCounts::new());
        let err = store
            .commit_omissions(scan_id, &per_root)
            .expect_err("an unselected root must be refused");
        assert!(err.to_string().contains("/other"), "{err}");
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
    }

    /// A directory outside its declared root is refused before anything is written.
    #[test]
    fn a_directory_outside_its_root_is_refused() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        let err = store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/elsewhere/x", OmissionReason::MinSize)]),
            )
            .expect_err("a directory outside the root must be refused");
        assert!(err.to_string().contains("outside its scan root"), "{err}");
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
    }

    /// A root whose spelling has no lexical key leaves the scan without an authority — and the
    /// scan itself is created exactly as before.
    #[test]
    fn an_unkeyable_root_yields_no_authority_and_still_scans() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(vec![PathBuf::from("/tank/../tank")]);
        let scan_id = store.begin_scan(&config).unwrap();
        assert_eq!(
            store.load_config(scan_id).unwrap().roots,
            vec![PathBuf::from("/tank/../tank")],
            "the scan exists and keeps its configuration verbatim"
        );
        assert!(matches!(
            store.ensure_scan_roots(scan_id).unwrap(),
            RootRegistration::Unavailable(AuthorityUnavailable::UnkeyableRoot { .. })
        ));
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
        assert!(store.commit_omissions(scan_id, &BTreeMap::new()).is_err());
    }

    /// Root validation skips its canonical comparison when a path cannot be resolved, so two
    /// overlapping roots that do not exist yet reach the ledger. Attributing a directory to two
    /// roots is impossible, so the scan gets no authority at all.
    #[test]
    fn lexically_overlapping_roots_yield_no_authority() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(vec![
            PathBuf::from("/nowhere/deep"),
            PathBuf::from("/nowhere"),
        ]);
        let scan_id = store.begin_scan(&config).unwrap();
        match store.ensure_scan_roots(scan_id).unwrap() {
            RootRegistration::Unavailable(AuthorityUnavailable::AmbiguousRoots {
                outer,
                inner,
            }) => assert_eq!(
                (outer.as_str(), inner.as_str()),
                ("/nowhere", "/nowhere/deep")
            ),
            other => panic!("overlapping roots must not register: {other:?}"),
        }
        assert_eq!(
            verdict(&store, scan_id, "/nowhere/deep"),
            DirCompleteness::Unknown
        );
    }

    /// Two spellings that normalize to one key are the same root; the pair is ambiguous.
    #[test]
    fn two_spellings_of_one_root_yield_no_authority() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(vec![PathBuf::from("/nowhere"), PathBuf::from("/nowhere/")]);
        let scan_id = store.begin_scan(&config).unwrap();
        assert!(matches!(
            store.ensure_scan_roots(scan_id).unwrap(),
            RootRegistration::Unavailable(AuthorityUnavailable::AmbiguousRoots { .. })
        ));
    }

    /// A trailing slash on an ordinary root is a spelling, not a different root: it keys to the
    /// same string the walk's directories key to, so containment works.
    #[test]
    fn a_trailing_slash_root_still_owns_its_directories() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(vec![PathBuf::from("/tank/root/")]);
        let scan_id = store.begin_scan(&config).unwrap();
        assert!(store.ensure_scan_roots(scan_id).unwrap().is_registered());
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank/root", &[("/tank/root/sub", OmissionReason::MinSize)]),
            )
            .unwrap();
        assert!(matches!(
            verdict(&store, scan_id, "/tank/root/sub"),
            DirCompleteness::Incomplete(_)
        ));
        assert_eq!(
            store
                .root_generation(scan_id, Path::new("/tank/root/"))
                .unwrap(),
            Some(1),
            "both spellings resolve to the one authority"
        );
    }

    /// Every reason round-trips through storage and comes back typed.
    #[test]
    fn each_reason_round_trips_through_the_ledger() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        let events: Vec<(String, OmissionReason)> = OmissionReason::ALL
            .into_iter()
            .map(|reason| (format!("/tank/{}", reason.as_str()), reason))
            .collect();
        let mut per_dir = OmissionCounts::new();
        for (dir, reason) in &events {
            per_dir.bump(key(dir), *reason).unwrap();
        }
        store
            .commit_omissions(scan_id, &BTreeMap::from([(key("/tank"), per_dir)]))
            .unwrap();

        for (dir, reason) in &events {
            match verdict(&store, scan_id, dir) {
                DirCompleteness::Incomplete(summary) => {
                    let recorded: Vec<_> = summary.per_reason().collect();
                    assert_eq!(
                        recorded,
                        vec![(*reason, EventCount::ONE)],
                        "{dir} must record exactly its own reason"
                    );
                }
                other => panic!("{dir} must be incomplete, got {other:?}"),
            }
        }
    }

    /// Repeated events of one reason aggregate into one row with a count; two reasons in one
    /// directory stay two rows.
    #[test]
    fn repeated_events_aggregate_per_directory_and_reason() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root(
                    "/tank",
                    &[
                        ("/tank/a", OmissionReason::MinSize),
                        ("/tank/a", OmissionReason::MinSize),
                        ("/tank/a", OmissionReason::MinSize),
                        ("/tank/a", OmissionReason::NonUtf8),
                    ],
                ),
            )
            .unwrap();

        let rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM dir_omission WHERE scan_id = ?1",
                params![scan_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2, "one row per (directory, reason)");

        match verdict(&store, scan_id, "/tank/a") {
            DirCompleteness::Incomplete(summary) => {
                assert_eq!(
                    summary.per_reason().collect::<Vec<_>>(),
                    vec![
                        (OmissionReason::MinSize, EventCount::new(3).unwrap()),
                        (OmissionReason::NonUtf8, EventCount::ONE),
                    ]
                );
                assert_eq!(summary.known_omitted_files().unwrap(), 4);
                assert!(!summary.has_unknown_cardinality());
            }
            other => panic!("expected incomplete, got {other:?}"),
        }
    }

    /// Two disjoint roots are judged independently: one root's omission never reaches the other.
    #[test]
    fn two_independent_roots_do_not_see_each_other() {
        let (mut store, scan_id) = ledger_store(&["/tank/one", "/tank/two"]);
        let mut per_root = one_root("/tank/one", &[("/tank/one/a", OmissionReason::MinSize)]);
        per_root.insert(key("/tank/two"), OmissionCounts::new());
        store.commit_omissions(scan_id, &per_root).unwrap();

        assert!(matches!(
            verdict(&store, scan_id, "/tank/one"),
            DirCompleteness::Incomplete(_)
        ));
        assert_eq!(
            verdict(&store, scan_id, "/tank/two"),
            DirCompleteness::Complete
        );
        assert_eq!(
            verdict(&store, scan_id, "/tank/two/a"),
            DirCompleteness::Complete
        );
    }

    /// Propagation reaches every ancestor up to and including the root, and stops there: the
    /// directory above the root belongs to no root and has no verdict.
    #[test]
    fn an_omission_propagates_up_to_the_root_and_no_further() {
        let (mut store, scan_id) = ledger_store(&["/tank/root"]);
        store
            .commit_omissions(
                scan_id,
                &one_root(
                    "/tank/root",
                    &[("/tank/root/a/b/c/d", OmissionReason::MinSize)],
                ),
            )
            .unwrap();

        for dir in [
            "/tank/root/a/b/c/d",
            "/tank/root/a/b/c",
            "/tank/root/a/b",
            "/tank/root/a",
            "/tank/root",
        ] {
            assert!(
                matches!(
                    verdict(&store, scan_id, dir),
                    DirCompleteness::Incomplete(_)
                ),
                "{dir} must see the omission"
            );
        }
        // Above the root, and a sibling that merely shares a prefix.
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
        assert_eq!(verdict(&store, scan_id, "/"), DirCompleteness::Unknown);
        assert_eq!(
            verdict(&store, scan_id, "/tank/rootless"),
            DirCompleteness::Unknown
        );
        // And a sibling INSIDE the root is complete, not tainted by its neighbour.
        assert_eq!(
            verdict(&store, scan_id, "/tank/root/a/b/c/d-other"),
            DirCompleteness::Complete
        );
    }

    /// A walk error attributed to the root itself — the case where the iterator error carried no
    /// pathname at all — taints the WHOLE root, not just the root directory.
    ///
    /// The ordinary range propagates a row upward to ancestors, so a row parked at the root would
    /// reach no child. An error that could not name a path could have swallowed any part of that
    /// tree, so the row at `dir_key = root_key` is a root-wide sentinel instead. The count stays
    /// an event count, never a number of files.
    #[test]
    fn a_pathless_walk_error_at_the_root_taints_every_directory_under_it() {
        let (mut store, scan_id) = ledger_store(&["/tank/root", "/tank/other"]);
        let mut per_root = one_root("/tank/root", &[("/tank/root", OmissionReason::WalkError)]);
        per_root.insert(key("/tank/other"), OmissionCounts::new());
        store.commit_omissions(scan_id, &per_root).unwrap();

        // The root itself, a direct child, a deep descendant and a sibling of that child: every
        // directory the root owns is incomplete, with a cardinality nobody can state.
        for dir in [
            "/tank/root",
            "/tank/root/sub",
            "/tank/root/sub/deeper/still",
            "/tank/root/another",
        ] {
            match verdict(&store, scan_id, dir) {
                DirCompleteness::Incomplete(summary) => {
                    assert!(
                        summary.has_unknown_cardinality(),
                        "{dir}: the hidden file count is unknowable"
                    );
                    assert_eq!(summary.known_omitted_files().unwrap(), 0, "{dir}");
                    assert_eq!(summary.unknown_cardinality_events(), 1, "{dir}");
                }
                other => panic!("{dir} must be incomplete, got {other:?}"),
            }
        }

        // The other selected root is untouched: a sentinel is root-wide, not scan-wide.
        assert_eq!(
            verdict(&store, scan_id, "/tank/other"),
            DirCompleteness::Complete
        );
        assert_eq!(
            verdict(&store, scan_id, "/tank/other/sub"),
            DirCompleteness::Complete
        );
    }

    /// The sentinel is `walk_error` alone. Any other reason stored at the root keeps the ordinary
    /// upward rule, or a `min_size` filter at the top of a tree would condemn every directory in
    /// it.
    #[test]
    fn another_reason_at_the_root_does_not_taint_descendants() {
        let (mut store, scan_id) = ledger_store(&["/tank/root"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank/root", &[("/tank/root", OmissionReason::MinSize)]),
            )
            .unwrap();

        assert!(matches!(
            verdict(&store, scan_id, "/tank/root"),
            DirCompleteness::Incomplete(_)
        ));
        assert_eq!(
            verdict(&store, scan_id, "/tank/root/sub"),
            DirCompleteness::Complete,
            "a root-level size filter says nothing about a child"
        );
    }

    /// A walk error BELOW the root is an ordinary row: it taints its own directory and its
    /// ancestors, and leaves unrelated siblings alone.
    #[test]
    fn a_walk_error_below_the_root_keeps_the_ordinary_rule() {
        let (mut store, scan_id) = ledger_store(&["/tank/root"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank/root", &[("/tank/root/a", OmissionReason::WalkError)]),
            )
            .unwrap();

        for dir in ["/tank/root/a", "/tank/root"] {
            assert!(
                matches!(
                    verdict(&store, scan_id, dir),
                    DirCompleteness::Incomplete(_)
                ),
                "{dir} must see the error"
            );
        }
        assert_eq!(
            verdict(&store, scan_id, "/tank/root/b"),
            DirCompleteness::Complete,
            "an unrelated sibling is not tainted by a located error"
        );
        // A descendant of the tainted directory is not tainted either: the error was located, so
        // it propagates upward like any other row. Where a whole subtree really is unreadable, the
        // producer records the error against that subtree's own directory — which is R3B's
        // attribution decision, not something this rule can make for it.
        assert_eq!(
            verdict(&store, scan_id, "/tank/root/a/deeper"),
            DirCompleteness::Complete
        );
    }

    /// Clearing a subtree invalidates that root — and only that root.
    #[test]
    fn a_subtree_clear_invalidates_its_root_and_leaves_the_other_alone() {
        let (mut store, scan_id) = ledger_store(&["/tank/one", "/tank/two"]);
        let mut per_root = one_root("/tank/one", &[("/tank/one/a", OmissionReason::MinSize)]);
        per_root.insert(
            key("/tank/two"),
            counts(&[("/tank/two/b", OmissionReason::NonUtf8)]),
        );
        store.commit_omissions(scan_id, &per_root).unwrap();

        store
            .clear_omissions_under(scan_id, Path::new("/tank/one/a"))
            .unwrap();

        // The cleared root is unknown, NOT complete: the rows went and the authority went with
        // them, in one transaction.
        assert_eq!(
            verdict(&store, scan_id, "/tank/one"),
            DirCompleteness::Unknown
        );
        assert_eq!(
            verdict(&store, scan_id, "/tank/one/a"),
            DirCompleteness::Unknown
        );
        assert_eq!(
            store
                .root_generation(scan_id, Path::new("/tank/one"))
                .unwrap(),
            Some(0)
        );
        // The untouched root keeps both its rows and its trust.
        assert!(matches!(
            verdict(&store, scan_id, "/tank/two/b"),
            DirCompleteness::Incomplete(_)
        ));
        assert_eq!(
            store
                .root_generation(scan_id, Path::new("/tank/two"))
                .unwrap(),
            Some(1)
        );
    }

    /// The same guarantee across a reopen: a crash right after a partial clear cannot leave a
    /// trusted-empty window, because the zeroed generation was committed with the delete.
    #[test]
    fn a_crash_after_a_partial_clear_leaves_no_trusted_empty_window() {
        let _role = role_guard();
        let dir = temp_state_dir("ledger_clear_crash");
        let db = dir.join("dedcom.db");
        let scan_id = {
            let mut store = ScanStore::open_writable(&db).unwrap();
            let (scan_id, _) = (
                store
                    .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
                    .unwrap(),
                (),
            );
            store
                .commit_omissions(
                    scan_id,
                    &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
                )
                .unwrap();
            store
                .clear_omissions_under(scan_id, Path::new("/tank/a"))
                .unwrap();
            scan_id // the process ends here, as abruptly as a crash
        };

        let reopened = ScanStore::open_writable(&db).unwrap();
        assert_eq!(
            verdict(&reopened, scan_id, "/tank"),
            DirCompleteness::Unknown,
            "an empty ledger after a clear must never read as complete"
        );
        let rows: i64 = reopened
            .conn
            .query_row(
                "SELECT COUNT(*) FROM dir_omission WHERE scan_id = ?1",
                params![scan_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "the rows really are gone");
        drop(reopened);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Replacing one root of a multi-root scan leaves the others trusted.
    #[test]
    fn a_root_clear_is_independent() {
        let (mut store, scan_id) = ledger_store(&["/tank/one", "/tank/two"]);
        let mut per_root = one_root("/tank/one", &[("/tank/one/a", OmissionReason::MinSize)]);
        per_root.insert(key("/tank/two"), OmissionCounts::new());
        store.commit_omissions(scan_id, &per_root).unwrap();

        store
            .clear_root_omissions(scan_id, Path::new("/tank/one"))
            .unwrap();
        assert_eq!(
            verdict(&store, scan_id, "/tank/one"),
            DirCompleteness::Unknown
        );
        assert_eq!(
            verdict(&store, scan_id, "/tank/two"),
            DirCompleteness::Complete
        );
    }

    /// A whole-scan clear takes every row and every authority.
    #[test]
    fn a_scan_clear_invalidates_every_root() {
        let (mut store, scan_id) = ledger_store(&["/tank/one", "/tank/two"]);
        let mut per_root = one_root("/tank/one", &[("/tank/one/a", OmissionReason::MinSize)]);
        per_root.insert(key("/tank/two"), OmissionCounts::new());
        store.commit_omissions(scan_id, &per_root).unwrap();

        store.clear_scan_omissions(scan_id).unwrap();
        for dir in ["/tank/one", "/tank/two", "/tank/one/a"] {
            assert_eq!(verdict(&store, scan_id, dir), DirCompleteness::Unknown);
        }
    }

    /// `clear_files` is the re-walk hook: manifest and ledger go together, so the next walk cannot
    /// inherit the previous one's omissions.
    #[test]
    fn clear_files_clears_the_ledger_with_the_manifest() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .record_files(scan_id, &[row("/tank/a.bin", 100, 1)])
            .unwrap();
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();

        store.clear_files(scan_id).unwrap();

        assert_eq!(store.manifest_count(scan_id).unwrap(), 0);
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
        // The root stays registered, so the next walk can earn trust again.
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(0)
        );
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Complete);
    }

    /// A scan that predates the ledger has no `scan_root` row at all — `begin_scan` is not called
    /// on resume. Re-walking it registers the roots, so a full re-walk can earn an authority.
    #[test]
    fn clear_files_registers_the_roots_of_a_scan_that_predates_the_ledger() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        // Rewind to a pre-ledger scan: the row exists, the authority never did.
        store
            .conn
            .execute("DELETE FROM scan_root WHERE scan_id = ?1", params![scan_id])
            .unwrap();
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            None
        );
        assert!(
            store
                .commit_omissions(scan_id, &one_root("/tank", &[]))
                .is_err(),
            "with no authority there is nothing to commit against"
        );

        store.clear_files(scan_id).unwrap();

        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(0)
        );
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Complete);
    }

    /// A second commit replaces the first wholesale and advances the generation; no row of the
    /// superseded generation survives to be read as evidence.
    #[test]
    fn a_second_commit_replaces_the_ledger_and_advances_the_generation() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(1)
        );

        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/b", OmissionReason::NonUtf8)]),
            )
            .unwrap();
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(2)
        );

        assert_eq!(
            verdict(&store, scan_id, "/tank/a"),
            DirCompleteness::Complete,
            "the first generation's row is gone, not merely outvoted"
        );
        assert!(matches!(
            verdict(&store, scan_id, "/tank/b"),
            DirCompleteness::Incomplete(_)
        ));
        let generations: Vec<i64> = store
            .conn
            .prepare("SELECT DISTINCT generation FROM dir_omission WHERE scan_id = ?1")
            .unwrap()
            .query_map(params![scan_id], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(generations, vec![2]);
    }

    /// Committing the same walk twice leaves the same ledger.
    #[test]
    fn committing_the_same_walk_twice_is_idempotent() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        let ledger = one_root(
            "/tank",
            &[
                ("/tank/a", OmissionReason::MinSize),
                ("/tank/a", OmissionReason::MinSize),
                ("/tank/b", OmissionReason::WalkError),
            ],
        );
        store.commit_omissions(scan_id, &ledger).unwrap();
        let first = verdict(&store, scan_id, "/tank");
        store.commit_omissions(scan_id, &ledger).unwrap();
        assert_eq!(verdict(&store, scan_id, "/tank"), first);
    }

    /// An authority that cannot advance refuses, and rolls back without touching the snapshot it
    /// already holds. Wrapping would hand a new snapshot a generation an old row already carries.
    #[test]
    fn a_generation_at_the_ceiling_refuses_to_advance() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_root SET generation = ?2 WHERE scan_id = ?1",
                params![scan_id, i64::MAX],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE dir_omission SET generation = ?2 WHERE scan_id = ?1",
                params![scan_id, i64::MAX],
            )
            .unwrap();

        let err = store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/b", OmissionReason::NonUtf8)]),
            )
            .expect_err("the generation must not wrap");
        assert!(err.to_string().contains("cannot advance"), "{err}");

        // The previous snapshot survives untouched: rows, generation and verdict.
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(i64::MAX)
        );
        let rows: Vec<(String, String)> = store
            .conn
            .prepare("SELECT dir_key, reason FROM dir_omission WHERE scan_id = ?1")
            .unwrap()
            .query_map(params![scan_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![("/tank/a".to_string(), "min_size".to_string())],
            "the refused commit deleted nothing"
        );
    }

    /// The rollback is real: the fault fires INSIDE the transaction, after a row was already
    /// inserted, so what the test proves is that the transaction unwound — not that validation
    /// refused the call before it started.
    #[test]
    fn a_failure_after_the_first_insert_rolls_the_whole_commit_back() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/kept", OmissionReason::MinSize)]),
            )
            .unwrap();
        let before: Vec<(String, String, i64)> = store
            .conn
            .prepare("SELECT dir_key, reason, generation FROM dir_omission WHERE scan_id = ?1")
            .unwrap()
            .query_map(params![scan_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(before.len(), 1);

        let fault = LedgerInsertFault::after(1);
        let err = store
            .commit_omissions(
                scan_id,
                &one_root(
                    "/tank",
                    &[
                        ("/tank/a", OmissionReason::MinSize),
                        ("/tank/b", OmissionReason::NonUtf8),
                        ("/tank/c", OmissionReason::WalkError),
                    ],
                ),
            )
            .expect_err("the injected fault must fail the commit");
        assert!(err.to_string().contains("injected"), "{err}");
        assert!(
            !fault.pending(),
            "the fault must have fired — an unfired fault proves nothing about rollback"
        );

        let after: Vec<(String, String, i64)> = store
            .conn
            .prepare("SELECT dir_key, reason, generation FROM dir_omission WHERE scan_id = ?1")
            .unwrap()
            .query_map(params![scan_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            after, before,
            "the previous generation survives the rolled-back commit whole"
        );
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(1),
            "and the authority never advanced"
        );
    }

    /// `purge_scan` removes the ledger and the authority with everything else, and leaves another
    /// scan alone.
    #[test]
    fn purge_scan_removes_the_ledger_and_the_authority() {
        let (mut store, doomed) = ledger_store(&["/tank/one"]);
        let survivor = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank/two")]))
            .unwrap();
        store
            .commit_omissions(
                doomed,
                &one_root("/tank/one", &[("/tank/one/a", OmissionReason::MinSize)]),
            )
            .unwrap();
        store
            .commit_omissions(
                survivor,
                &one_root("/tank/two", &[("/tank/two/b", OmissionReason::NonUtf8)]),
            )
            .unwrap();

        store.purge_scan(doomed).unwrap();

        for (table, count) in [("dir_omission", 0i64), ("scan_root", 0)] {
            let found: i64 = store
                .conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE scan_id = ?1"),
                    params![doomed],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(found, count, "{table} must be empty for the purged scan");
        }
        assert!(matches!(
            verdict(&store, survivor, "/tank/two/b"),
            DirCompleteness::Incomplete(_)
        ));
    }

    /// A count no real row can hold is refused twice over: by SQLite on every write path, and by
    /// the typed decoder if one is in the file anyway.
    ///
    /// The second half needs `PRAGMA ignore_check_constraints`, because the constraint really does
    /// hold on `UPDATE` as well as `INSERT`. That pragma is exactly how a value like this arrives
    /// in practice — an external editor or a damaged file, the same threat model `LinkCount`
    /// guards `file.nlink` against.
    #[test]
    fn a_corrupt_event_count_is_refused_at_both_ends() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();

        for bad in [0i64, -1] {
            let inserted = store.conn.execute(
                "INSERT INTO dir_omission
                     (scan_id, root_key, dir_key, reason, event_count, generation)
                 VALUES (?1, '/tank', '/tank/z', 'min_size', ?2, 1)",
                params![scan_id, bad],
            );
            assert!(
                inserted.is_err(),
                "the CHECK must refuse an inserted event_count of {bad}"
            );
            let updated = store.conn.execute(
                "UPDATE dir_omission SET event_count = ?2 WHERE scan_id = ?1",
                params![scan_id, bad],
            );
            assert!(
                updated.is_err(),
                "and an updated event_count of {bad} just the same"
            );
        }

        // Past the constraint, as a damaged file would be: the read refuses rather than reporting
        // a nonsense summary.
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = ON")
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE dir_omission SET event_count = -5 WHERE scan_id = ?1",
                params![scan_id],
            )
            .unwrap();
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = OFF")
            .unwrap();

        let err = store
            .directory_completeness(scan_id, &[Path::new("/tank/a")])
            .expect_err("a corrupt count must not be summarised");
        assert!(err.to_string().contains("corrupt omission count"), "{err}");
    }

    /// A reason this build does not know keeps the directory incomplete — never complete — and the
    /// public result is an error rather than a summary that quietly drops it.
    #[test]
    fn an_unknown_reason_is_an_error_not_a_complete_directory() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE dir_omission SET reason = 'quota_error' WHERE scan_id = ?1",
                params![scan_id],
            )
            .unwrap();

        let err = store
            .directory_completeness(scan_id, &[Path::new("/tank/a")])
            .expect_err("an unknown reason must not be summarised");
        assert!(
            err.to_string().contains("does not know"),
            "the message must name the problem: {err}"
        );
        // The row is still there — the refusal is a read-side refusal, not a silent deletion.
        let rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM dir_omission WHERE scan_id = ?1",
                params![scan_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
    }

    /// A row above its root, or under a root it does not belong to, cannot be written; and a
    /// root-keyed read would not return it in any case.
    #[test]
    fn a_row_outside_its_root_cannot_be_stored() {
        let (mut store, scan_id) = ledger_store(&["/tank/one", "/tank/two"]);
        // Above the root.
        assert!(
            store
                .conn
                .execute(
                    "INSERT INTO dir_omission
                         (scan_id, root_key, dir_key, reason, event_count, generation)
                     VALUES (?1, '/tank/one', '/tank', 'min_size', 1, 1)",
                    params![scan_id],
                )
                .is_err(),
            "the CHECK must refuse a directory above its root"
        );
        // A prefix sibling of the root is not under it either.
        assert!(
            store
                .conn
                .execute(
                    "INSERT INTO dir_omission
                         (scan_id, root_key, dir_key, reason, event_count, generation)
                     VALUES (?1, '/tank/one', '/tank/oneself/x', 'min_size', 1, 1)",
                    params![scan_id],
                )
                .is_err(),
            "the CHECK must refuse a prefix sibling"
        );

        // A row correctly under the OTHER root is invisible to a read keyed on the first.
        let mut per_root = one_root("/tank/one", &[]);
        per_root.insert(
            key("/tank/two"),
            counts(&[("/tank/two/x", OmissionReason::MinSize)]),
        );
        store.commit_omissions(scan_id, &per_root).unwrap();
        assert_eq!(
            verdict(&store, scan_id, "/tank/one"),
            DirCompleteness::Complete
        );
    }

    /// SQLite's integer `sum()` raises `integer overflow` rather than returning a smaller number
    /// or a float, so an aggregate that cannot be represented surfaces as an error.
    #[test]
    fn an_aggregate_that_overflows_is_an_error_not_a_wrong_number() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root(
                    "/tank",
                    &[
                        ("/tank/a", OmissionReason::MinSize),
                        ("/tank/b", OmissionReason::MinSize),
                    ],
                ),
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE dir_omission SET event_count = ?2 WHERE scan_id = ?1",
                params![scan_id, i64::MAX],
            )
            .unwrap();

        let err = store
            .directory_completeness(scan_id, &[Path::new("/tank")])
            .expect_err("the aggregate must not silently wrap");
        assert!(
            err.to_string().to_lowercase().contains("overflow"),
            "the error must name the overflow: {err}"
        );
    }

    /// The reader really is one snapshot. Connection A opens it, reads one directory, and only
    /// then does connection B replace the whole ledger and commit. A's second read must still be
    /// the generation it started with — an answer half from each is an answer the checkpoint never
    /// held.
    ///
    /// Drives `directory_completeness_tx`, the exact helper the public method uses: a hand-written
    /// parallel query would prove something about the test, not about production.
    #[test]
    fn one_reader_snapshot_cannot_mix_two_generations() {
        let _role = role_guard();
        let dir = temp_state_dir("ledger_snapshot");
        let db = dir.join("dedcom.db");

        let mut writer = ScanStore::open_writable(&db).unwrap();
        let journal: String = writer
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            journal.to_lowercase(),
            "wal",
            "without WAL the second connection would block instead of committing, and this test \
             would hang rather than prove anything"
        );
        let scan_id = writer
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        writer
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();

        let reader = ScanStore::open_writable(&db).unwrap();
        let snapshot = reader.conn.unchecked_transaction().unwrap();
        let first =
            directory_completeness_tx(&snapshot, scan_id, &[Path::new("/tank/one")]).unwrap();
        assert_eq!(
            first.get(Path::new("/tank/one")),
            Some(&DirCompleteness::Complete),
            "generation 1 says nothing was omitted"
        );

        // A whole new generation lands between the reader's two queries.
        writer
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/two", OmissionReason::MinSize)]),
            )
            .unwrap();
        assert_eq!(
            writer.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(2)
        );

        let second =
            directory_completeness_tx(&snapshot, scan_id, &[Path::new("/tank/two")]).unwrap();
        assert_eq!(
            second.get(Path::new("/tank/two")),
            Some(&DirCompleteness::Complete),
            "inside one snapshot both answers come from generation 1"
        );

        // Closing the snapshot moves the reader forward, so the test would notice a snapshot that
        // was simply stale forever.
        drop(snapshot);
        assert!(
            matches!(
                verdict(&reader, scan_id, "/tank/two"),
                DirCompleteness::Incomplete(_)
            ),
            "a fresh read must see generation 2"
        );

        drop(reader);
        drop(writer);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A directory that has no lexical key gets no verdict — and certainly not a complete one.
    #[test]
    fn an_unkeyable_directory_is_unknown() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        for dir in ["/tank/../tank/a", "relative/dir"] {
            assert_eq!(
                verdict(&store, scan_id, dir),
                DirCompleteness::Unknown,
                "{dir} must not receive a verdict"
            );
        }
    }

    /// Rewrites the scan's persisted roots behind the store's back — the external-editor seam the
    /// corrupt-count and unknown-reason tests already use, and the only way a configuration and a
    /// registration can diverge inside one process.
    fn repoint_config(store: &ScanStore, scan_id: i64, roots: &[&str]) {
        let mut config = store.load_config(scan_id).unwrap();
        config.roots = roots.iter().map(PathBuf::from).collect();
        store
            .conn
            .execute(
                "UPDATE scan SET config_json = ?2 WHERE id = ?1",
                params![scan_id, serde_json::to_string(&config).unwrap()],
            )
            .unwrap();
    }

    /// A configuration that stops being keyable revokes the authority it used to carry — rows,
    /// generation and all — rather than leaving a trusted answer standing for roots nobody can
    /// name.
    #[test]
    fn a_configuration_that_becomes_unkeyable_revokes_its_authority() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(1)
        );

        repoint_config(&store, scan_id, &["/tank/../tank"]);

        // The reader refuses the stale authority immediately, before any re-registration runs.
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
        assert_eq!(
            verdict(&store, scan_id, "/tank/a"),
            DirCompleteness::Unknown
        );

        match store.ensure_scan_roots(scan_id).unwrap() {
            RootRegistration::Unavailable(AuthorityUnavailable::UnkeyableRoot { .. }) => {}
            other => panic!("an unkeyable configuration must be reported: {other:?}"),
        }
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            None,
            "the stale authority row is gone, not merely ignored"
        );
        let rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM dir_omission WHERE scan_id = ?1",
                params![scan_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "and so is the ledger it vouched for");
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
    }

    /// A configuration repointed at a different root is untrusted by the reader at once, and a
    /// commit naming the old root cannot publish another trusted generation.
    #[test]
    fn a_repointed_configuration_is_untrusted_before_re_registration() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();

        repoint_config(&store, scan_id, &["/other"]);

        // The registration still says `/tank`, and its generation is still 1 — but the reader
        // compares the two and refuses to use it.
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(1)
        );
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
        assert_eq!(
            verdict(&store, scan_id, "/tank/a"),
            DirCompleteness::Unknown
        );
        assert_eq!(verdict(&store, scan_id, "/other"), DirCompleteness::Unknown);

        // And the producer cannot commit against the stale registration either.
        let err = store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .expect_err("a drifted configuration must not publish a generation");
        assert!(err.to_string().contains("drifted"), "{err}");
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            Some(1),
            "the refused commit published nothing"
        );

        // Re-registering adopts the new root at generation 0 — untrusted until a snapshot of the
        // new configuration earns it.
        assert!(store.ensure_scan_roots(scan_id).unwrap().is_registered());
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            None
        );
        assert_eq!(
            store.root_generation(scan_id, Path::new("/other")).unwrap(),
            Some(0)
        );
        assert_eq!(verdict(&store, scan_id, "/other"), DirCompleteness::Unknown);

        // An exact snapshot of the new configuration then earns trust normally.
        store
            .commit_omissions(scan_id, &one_root("/other", &[]))
            .unwrap();
        assert_eq!(
            verdict(&store, scan_id, "/other"),
            DirCompleteness::Complete
        );
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
    }

    /// The ordinary path is unaffected: an unchanged configuration commits and reads exactly as
    /// before, so the agreement check costs nothing a working scan notices.
    #[test]
    fn an_unchanged_configuration_commits_and_reads_normally() {
        let (mut store, scan_id) = ledger_store(&["/tank/one", "/tank/two"]);
        let mut per_root = one_root("/tank/one", &[("/tank/one/a", OmissionReason::MinSize)]);
        per_root.insert(key("/tank/two"), OmissionCounts::new());
        store.commit_omissions(scan_id, &per_root).unwrap();

        assert!(matches!(
            verdict(&store, scan_id, "/tank/one/a"),
            DirCompleteness::Incomplete(_)
        ));
        assert_eq!(
            verdict(&store, scan_id, "/tank/two"),
            DirCompleteness::Complete
        );
        // Re-registration on an unchanged configuration keeps both generations.
        assert!(store.ensure_scan_roots(scan_id).unwrap().is_registered());
        for root in ["/tank/one", "/tank/two"] {
            assert_eq!(
                store.root_generation(scan_id, Path::new(root)).unwrap(),
                Some(1),
                "{root} must keep its trust"
            );
        }
    }

    /// A configuration reduced to no roots at all is the same class of problem, and revokes just
    /// as thoroughly.
    #[test]
    fn a_configuration_with_no_roots_revokes_its_authority() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Complete);

        repoint_config(&store, scan_id, &[]);
        assert_eq!(verdict(&store, scan_id, "/tank"), DirCompleteness::Unknown);
        assert!(matches!(
            store.ensure_scan_roots(scan_id).unwrap(),
            RootRegistration::Unavailable(AuthorityUnavailable::NoRoots)
        ));
        assert_eq!(
            store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            None
        );
    }

    /// A `config_json` that is not a configuration at all is a storage error, never a quiet
    /// `Unknown`: the two must not be able to swap places.
    #[test]
    fn malformed_config_json_is_an_error_not_an_unknown() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan SET config_json = 'not json' WHERE id = ?1",
                params![scan_id],
            )
            .unwrap();

        assert!(
            store
                .directory_completeness(scan_id, &[Path::new("/tank")])
                .is_err(),
            "a malformed configuration must surface, not read as unknown"
        );
        assert!(store.ensure_scan_roots(scan_id).is_err());
        assert!(store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .is_err());
    }

    /// Every requested directory appears in the result, so a caller cannot mistake an absent key
    /// for anything at all.
    #[test]
    fn every_requested_directory_gets_an_answer() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();
        let dirs = [
            Path::new("/tank"),
            Path::new("/tank/a"),
            Path::new("/tank/b"),
            Path::new("/elsewhere"),
        ];
        let answers = store.directory_completeness(scan_id, &dirs).unwrap();
        assert_eq!(answers.len(), dirs.len());
        for dir in dirs {
            assert!(answers.contains_key(dir), "{} is missing", dir.display());
        }
    }
}
