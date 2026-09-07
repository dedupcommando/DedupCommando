// SPDX-License-Identifier: Apache-2.0
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rusqlite::types::Value;
use rusqlite::{params, Connection, OpenFlags, Transaction};

use crate::error::{AppError, Result};
#[cfg(test)]
use crate::model::action::MoveEventRow;
use crate::model::action::{ActionKind, MoveEvent, PathFidelity};
#[cfg(test)]
use crate::model::duplicate::sort_attributed_by_benefit;
use crate::model::duplicate::{
    build_dir_signatures_streaming_in_context, hex_encode, signature_of, AttributedDirGroup,
    DirGroup, DirSigAlgo, DirTrust, DuplicateGroup, FileEntry,
};
use crate::model::omission::{
    AuthorityUnavailable, CompletenessSnapshot, DirCompleteness, DirDisposition, DirScope,
    LegacyContext, OmissionCounts, PathKey, RootRegistration, ScanAccounting, SignatureContext,
    SnapshotOutcome, StoredOmission,
};
#[cfg(test)]
use crate::model::omission::{EventCount, OmissionReason};
use crate::model::plan::{
    ActionPlan, GroupId, GroupWitness, MarkIntent, PlanGroupInput, PlanMemberEvidence,
    PlanObjectKey, PlanRefusal, PlanResult, PlanWitness, RequestedMark,
};
use crate::model::reclaim::{
    DestructivePlanVerdict, GroupReclaim, LinkCount, ReclaimEstimate, ReclaimState,
};
use crate::model::scan::{
    OmissionAccounting, ResumeInfo, ScanConfig, ScanEnvironment, ScanStatsRow, ScanStatus,
    ScanSummary,
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

/// A lightweight duplicate-group summary — one `file_group` row, without
/// members. Browser holds a Vec of these summaries (645k×~48 B ≈ 31 MiB), and reads a group's
/// members on entry through the membership snapshot, rather than the whole scan into RAM.
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

/// A lightweight twin-directory group summary with the trust the current ledger vouches — for
/// the `[2] Directories` tab in the browser. Analogous to `GroupSummary` for file groups: one
/// attributed read → summaries without `paths`; the surviving paths of one group are read on
/// entry (`attributed_dir_group`). Counts are of SURVIVING members: a member the current ledger
/// suppresses is removed exactly as the builder would have removed it, and a group left with
/// fewer than two members is not a group at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributedDirGroupSummary {
    /// Sequential «by benefit» rank (1-based, for UI `#N`), assigned after suppression.
    pub rank: u32,
    /// blake3 signature of the directory's contents (hex). The key for `attributed_dir_group`.
    pub signature: String,
    /// Surviving twin directories in the group (>= 2, re-evaluated after suppression).
    pub dir_count: u32,
    /// Files in a SINGLE directory of the group (the same for all — same signature).
    pub file_count: u32,
    /// Total size of one directory's files (the same for all in the group).
    pub size_per_dir: u64,
    /// `Trusted` only when EVERY surviving member is trusted; an `Unknown` member keeps the group
    /// browseable and makes it an unverified candidate.
    pub trust: DirTrust,
}

impl AttributedDirGroupSummary {
    /// How much space will be freed if one directory of the group is kept. A display figure for
    /// TRUSTED groups; an unverified candidate never shows one.
    pub fn reclaim_bytes(&self) -> u64 {
        let extra = (self.dir_count.saturating_sub(1)) as u64;
        self.size_per_dir.saturating_mul(extra)
    }
}

/// Every attributed summary of one scan plus the only aggregate a mixed list may display: the
/// exact total over trusted groups and a separate COUNT of unverified candidates. There is
/// deliberately no combined figure — an unverified candidate has no meaningful reclaim ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttributedDirGroupSummaries {
    pub groups: Vec<AttributedDirGroupSummary>,
    /// Checked sum of `reclaim_bytes` over `Trusted` groups only.
    pub trusted_reclaim_total: u64,
    /// How many groups are unverified candidates (`Untrusted`).
    pub unverified_groups: u32,
}

/// One live directory signature plus the trust the ledger vouched at the moment it was read.
///
/// `Suppressed` is represented by absence — exactly the absence the builders produce — so an
/// untyped consumer cannot exist: whoever holds a signature holds its trust beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDirSignature {
    pub signature: String,
    pub trust: DirTrust,
}

/// Checkpoint store: a SQLite DB with the scan state and the file manifest.
pub struct ScanStore {
    conn: Connection,
    /// The configured database path and the identity that path carried, observed immediately
    /// around the open. Not a claim about SQLite's own descriptor — see `settled_identity`.
    /// `None` for an in-memory store, which has no path to be replaced. Re-checked before every
    /// trusted membership answer, so a checkpoint swapped underneath a live connection is
    /// refused rather than answered.
    db_identity: Option<(PathBuf, crate::paths::PathIdentity)>,
    /// The one cached whole-authority validation of the active scan. A single slot, not a map:
    /// the UI activates one checkpoint at a time, so a slot cannot grow and cannot serve a
    /// scan it was not computed for.
    ///
    /// Interior mutability for the same reason the counters use it: the snapshot borrows
    /// `conn` for its transaction, so recording the verdict cannot also take `&mut self`. It
    /// keeps `membership_snapshot`'s public signature unchanged as well.
    membership_cache: std::cell::RefCell<Option<MembershipCacheEntry>>,
    /// Test-only: how many set-based digest-propagation statements this store has issued. The
    /// hashing phase must spend one per batch, never one per alias, and a counter on the store
    /// itself proves that without a dependency, rusqlite tracing, or a timing measurement. Per
    /// instance rather than global, so parallel tests cannot pollute each other.
    #[cfg(test)]
    propagations: std::cell::Cell<u64>,
    /// Test-only: SQL statements spent on the staged apply-lease path (open → acquire →
    /// release). The lease must not grow with the plan — the 40 000-group case pins this
    /// number. Same per-instance shape as `propagations`, for the same reason.
    #[cfg(test)]
    membership_statements: std::cell::Cell<u64>,
    /// Test-only: how many times this store ran the FULL whole-authority validation. Per
    /// instance, deliberately not a process-wide counter: parallel tests and unrelated opens
    /// would pollute a global one, and «this store validated once» is the only claim a store
    /// unit test can honestly make. Proving «only one browsing store exists» belongs to the
    /// future actor commit and needs its own scoped seam.
    #[cfg(test)]
    full_validations: std::cell::Cell<u64>,
    /// Test-only: identity probes spent on this store. The claim it exists for is «one probe per
    /// store operation» — a membership request must not pay one for the snapshot and another for
    /// the answer, and a reader must not quietly pay none.
    #[cfg(test)]
    identity_probes: std::cell::Cell<u64>,
    /// Test-only: member rows the export currently holds in RAM, and the high-water mark of that
    /// number. The claim they exist for is «the export buffers ONE group, never the scan»: a
    /// process-memory measurement answers to the allocator and the page cache, while a counter of
    /// the rows the reader itself is holding answers to nothing else.
    #[cfg(test)]
    export_rows_now: std::cell::Cell<u64>,
    #[cfg(test)]
    export_rows_max: std::cell::Cell<u64>,
}

/// One cached whole-authority validation, valid only while the connection still sees the same
/// database state that produced it.
///
/// The key is the whole tuple. `data_version` alone is not enough (it does not move for this
/// connection's own writes, which is why the concrete writers revoke explicitly), and
/// mode/generation alone are not enough (the accepted corruption tests mutate rows without
/// bumping the generation).
struct MembershipCacheEntry {
    scan_id: i64,
    mode: MembershipMode,
    generation: i64,
    data_version: i64,
    /// Either the completed integrity result, or a deterministic refusal — a verdict that is a
    /// pure function of the database state this key pins. Transient failures never land here.
    outcome: std::result::Result<AuthorityIntegrity, MembershipMiss>,
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

/// Test seam: every open of ONE checkpoint, in order, with the schema version its opener found.
///
/// It exists to state an ordering claim that a sleep could only make probabilistically — that
/// nothing opened the checkpoint before the boot thread's migration had committed. Keyed by
/// pathname, so a test never records another test's opens. Not compiled into a production build.
#[cfg(test)]
pub(crate) mod open_ledger {
    use super::{Connection, Path, PathBuf};

    static LEDGER: std::sync::Mutex<Option<(PathBuf, Vec<i64>)>> = std::sync::Mutex::new(None);

    fn slot() -> std::sync::MutexGuard<'static, Option<(PathBuf, Vec<i64>)>> {
        LEDGER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Arms the ledger for one database and disarms it on drop.
    pub(crate) struct Recording;

    impl Recording {
        pub(crate) fn of(db_path: &Path) -> Self {
            *slot() = Some((db_path.to_path_buf(), Vec::new()));
            Recording
        }

        /// The schema version each opener found, in the order they opened.
        pub(crate) fn versions(&self) -> Vec<i64> {
            slot()
                .as_ref()
                .map(|(_, seen)| seen.clone())
                .unwrap_or_default()
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            *slot() = None;
        }
    }

    pub(super) fn record(db_path: &Path, conn: &Connection) {
        let mut armed = slot();
        let Some((path, seen)) = armed.as_mut() else {
            return;
        };
        if path != db_path {
            return;
        }
        if let Ok(version) = conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0)) {
            seen.push(version);
        }
    }
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
        nlink: 1,
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
    // A batch is applied from a finished, published scan, so the fixture is one: the browsing
    // actor opens it exactly as it opens a real result, and the settlement it acknowledges is
    // the settlement of a real authority.
    store
        .set_status(scan_id, crate::model::scan::ScanStatus::Complete)
        .unwrap();
    store
        .publish_results(scan_id, PublishMode::Derived)
        .unwrap();
    scan_id
}

/// The scan-local temporal physical identity of a manifest row — the columns that decide whether
/// two pathnames are the same allocation *right now*. Bare `(device, inode)` is deliberately not
/// enough: an inode number is reused after a delete, and a same-second in-place edit would
/// otherwise look unchanged. Used as a `GROUP BY` list and as a join key; nothing here is ever
/// concatenated into a text key.
const OBJECT_KEY: &str = "device, inode, size, mtime, mtime_nsec, ctime_sec, ctime_nsec";

/// The same key, qualified for a statement that joins `file` as `f` beside another relation.
const OBJECT_KEY_F: &str =
    "f.device, f.inode, f.size, f.mtime, f.mtime_nsec, f.ctime_sec, f.ctime_nsec";

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

/// Closes the identity bracket around `Connection::open*` and returns what the store retains.
///
/// `before` is the probe taken immediately before the open; both openers now require it, so a
/// failure there is a refusal rather than an «unknown» that weakens the comparison. If the two
/// probes disagree, the path was replaced across the open itself and the store refuses instead
/// of proceeding — which is why every caller runs this as its FIRST action after the open, ahead
/// of any pragma, migration or permission work that would otherwise act on the replacement.
///
/// What this does NOT prove, stated here rather than discovered later: it is the identity of the
/// PATH observed immediately around the open, not of the file SQLite itself opened.
/// `rusqlite::Connection` exposes no portable OS descriptor at this version, and reading
/// SQLite's private `unixFile` layout to find one would be VFS-dependent unsafe code. An
/// adversarial replace-and-restore between the two probes is not detected. Ordinary
/// replacement — the case an operator actually hits — is.
fn settled_identity(
    db_path: &Path,
    before: crate::paths::PathIdentity,
) -> Result<Option<(PathBuf, crate::paths::PathIdentity)>> {
    let after = crate::paths::probe_existing_db_file(db_path)?;
    if before != after {
        // Typed, not a message: the same fact reaches a later reader as
        // `MembershipMiss::ReopenRequired`, and both are recognised by matching rather than by
        // reading the sentence. The sentence itself is unchanged.
        let shown = crate::textsan::terminal(&db_path.display().to_string());
        return Err(AppError::PathChanged {
            detail: format!(
                "dedcom.db was replaced while it was being opened: {shown}. Try again."
            ),
            path: shown,
        });
    }
    Ok(Some((db_path.to_path_buf(), after)))
}

// Test-only one-shot seam at the exact instant between a successful SQLite open and the
// closing identity probe. It exists so a test can swap the pathname there and prove that the
// refusal happens before WAL setup, migration or `enforce_db_perms_0600` can act on the
// replacement — a race that no sleep or second thread could pin down deterministically.
#[cfg(test)]
thread_local! {
    static OPEN_RACE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arms the one-shot open-race hook for this thread and disarms it on drop.
#[cfg(test)]
pub(crate) struct OpenRace;

#[cfg(test)]
impl OpenRace {
    pub(crate) fn armed(action: impl FnOnce() + 'static) -> Self {
        OPEN_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
        OpenRace
    }

    /// Whether the armed shot was consumed. A test whose seam was never reached proved nothing.
    pub(crate) fn fired(&self) -> bool {
        OPEN_RACE_HOOK.with(|slot| slot.borrow().is_none())
    }
}

#[cfg(test)]
impl Drop for OpenRace {
    fn drop(&mut self) {
        OPEN_RACE_HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

// Test-only one-shot fault in the full-validator path, so a transient store failure can be
// produced deterministically — the real thing is a disk or SQLite hiccup, which no test can
// schedule. Proves the retry contract: such a failure is never cached.
#[cfg(test)]
thread_local! {
    static VALIDATOR_FAULT: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Arms the one-shot validator fault for this thread and disarms it on drop.
#[cfg(test)]
pub(crate) struct ValidatorFault;

#[cfg(test)]
impl ValidatorFault {
    pub(crate) fn armed(detail: &str) -> Self {
        VALIDATOR_FAULT.with(|slot| *slot.borrow_mut() = Some(detail.to_string()));
        ValidatorFault
    }

    pub(crate) fn fired(&self) -> bool {
        VALIDATOR_FAULT.with(|slot| slot.borrow().is_none())
    }
}

#[cfg(test)]
impl Drop for ValidatorFault {
    fn drop(&mut self) {
        VALIDATOR_FAULT.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
fn take_validator_fault() -> Option<String> {
    VALIDATOR_FAULT.with(|slot| slot.borrow_mut().take())
}

#[cfg(test)]
fn take_open_race_hook() {
    let action = OPEN_RACE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
}

// Test-only one-shot seam at the exact instant between the export's selection read and the
// snapshot it then opens. That gap is the only place an export can observe two database states,
// so a trash, a newer scan, a republication or a mark written there is what the seam schedules —
// deterministically, which no sleep or second thread could do.
#[cfg(test)]
thread_local! {
    static EXPORT_RACE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arms the one-shot export-race hook for this thread and disarms it on drop.
#[cfg(test)]
pub(crate) struct ExportRace;

#[cfg(test)]
impl ExportRace {
    pub(crate) fn armed(action: impl FnOnce() + 'static) -> Self {
        EXPORT_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
        ExportRace
    }

    /// Whether the armed shot was consumed. A test whose seam was never reached proved nothing.
    pub(crate) fn fired(&self) -> bool {
        EXPORT_RACE_HOOK.with(|slot| slot.borrow().is_none())
    }
}

#[cfg(test)]
impl Drop for ExportRace {
    fn drop(&mut self) {
        EXPORT_RACE_HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
fn take_export_race_hook() {
    let action = EXPORT_RACE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
}

/// Runs the one set-based propagation statement on an open transaction and returns the rows it
/// filled in. One statement per call — never a loop over aliases.
fn propagate_trusted_digests(tx: &Connection, scan_id: i64) -> Result<u64> {
    let updated = tx.execute(&propagate_sql(), params![scan_id])?;
    Ok(updated as u64)
}

impl ScanStore {
    fn new(conn: Connection) -> Self {
        Self::with_identity(conn, None)
    }

    fn with_identity(
        conn: Connection,
        db_identity: Option<(PathBuf, crate::paths::PathIdentity)>,
    ) -> Self {
        Self {
            conn,
            db_identity,
            membership_cache: std::cell::RefCell::new(None),
            #[cfg(test)]
            propagations: std::cell::Cell::new(0),
            #[cfg(test)]
            membership_statements: std::cell::Cell::new(0),
            #[cfg(test)]
            full_validations: std::cell::Cell::new(0),
            #[cfg(test)]
            identity_probes: std::cell::Cell::new(0),
            #[cfg(test)]
            export_rows_now: std::cell::Cell::new(0),
            #[cfg(test)]
            export_rows_max: std::cell::Cell::new(0),
        }
    }

    /// Test-only: the most member rows the export ever held at once (see the fields).
    #[cfg(test)]
    pub fn export_buffered_rows_max(&self) -> u64 {
        self.export_rows_max.get()
    }

    /// Test-only: how many member rows the export is holding RIGHT NOW.
    ///
    /// The high-water mark alone cannot prove the buffer is released: a later, larger group
    /// reaches the same peak whether or not a failed export left its own rows counted. This is
    /// the value that must be zero the moment an export returns, however it returned.
    #[cfg(test)]
    pub fn export_buffered_rows_now(&self) -> u64 {
        self.export_rows_now.get()
    }

    /// Test-only: identity probes this store has spent (see the field).
    #[cfg(test)]
    pub(crate) fn identity_probes(&self) -> u64 {
        self.identity_probes.get()
    }

    /// Test-only: set-based propagation statements issued so far (see the field).
    #[cfg(test)]
    pub fn propagation_statements(&self) -> u64 {
        self.propagations.get()
    }

    /// Test-only: full whole-authority validations this store has run (see the field).
    #[cfg(test)]
    pub fn full_validation_count(&self) -> u64 {
        self.full_validations.get()
    }

    /// Test-only: seed a stored-corruption state by editing the tables directly, then drop the
    /// cached verdict so the validator is the thing under test.
    ///
    /// This is NOT a simulation of an outside process, and it does not exercise any
    /// invalidation mechanism: the statement runs on THIS connection, which is exactly why
    /// `PRAGMA data_version` would not move for it and why the revocation has to be explicit
    /// here. Its only job is to put already-corrupt rows in front of the validator. Invalidation
    /// by a second connection is proved separately, by the `data_version` test. Production has
    /// no equivalent path — every membership write in the binary goes through one of the
    /// revoking methods.
    #[cfg(test)]
    pub(crate) fn corrupt_directly<P: rusqlite::Params>(&self, sql: &str, params: P) -> usize {
        let changed = self.conn.execute(sql, params).expect("corruption fixture");
        self.revoke_membership_cache();
        changed
    }

    /// Drops the cached whole-authority result.
    ///
    /// Called by the concrete writers that mutate membership state, immediately BEFORE their
    /// own transaction begins — never after the commit. A connection's own commit does not move
    /// its `data_version`, so the token cannot see these writes at all; and revoking first means
    /// a failed or rolled-back write leaves the cache empty rather than stale. The cost of
    /// revoking too early is one extra validation; the cost of revoking too late is a trusted
    /// answer that is false.
    ///
    /// Deliberately NOT called from `ensure_materialized`, `prepare_completed_scans` or
    /// `prepare_legacy_for_viewing`: those usually only read or return at once, and revoking on
    /// their entry would turn ordinary browsing into false misses. Their real write paths reach
    /// one of the concrete hooks instead.
    fn revoke_membership_cache(&self) {
        *self.membership_cache.borrow_mut() = None;
    }

    /// Test-only: apply-lease statements issued so far (see the field).
    #[cfg(test)]
    pub fn membership_statement_count(&self) -> u64 {
        self.membership_statements.get()
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
        // The opening half of the bracket around `Connection::open*`. An observer opens an
        // existing database, so this probe must succeed — its error is propagated with its own
        // context rather than downgraded to «unknown».
        let before = crate::paths::probe_existing_db_file(db_path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(db_path, flags).map_err(|err| {
            AppError::msg(format!(
                "cannot open dedcom.db read-only ({}): {err}",
                crate::textsan::terminal(&db_path.display().to_string())
            ))
        })?;
        // The closing half of the bracket, FIRST — before any pragma, schema read or anything
        // else that could act on a file that is no longer the one we probed.
        let identity = settled_identity(db_path, before)?;
        // Before `query_only` and before either version check: connection-local state only, so a
        // future DB is still left untouched by the refusal below.
        schema::enforce_foreign_keys(&conn)?;
        conn.execute_batch("PRAGMA busy_timeout=5000;\nPRAGMA query_only=1;")?;
        schema::ensure_version_supported(&conn)?;
        // Migrating needs a writer, so an out-of-date DB is reported here rather than as a
        // «no such column» from some query later on.
        schema::ensure_migrated(&conn)?;
        Ok(Self::with_identity(conn, identity))
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
        // The opening half of the bracket. `prepare_db_file` has just created or verified the
        // file, so this probe must succeed — the absence-before-create case is already handled
        // there, and a failure here is a real refusal rather than «unknown».
        let before = crate::paths::probe_existing_db_file(db_path)?;
        let conn = Connection::open(db_path)?;
        // The closing half, FIRST. Everything below writes to or about the file — WAL setup,
        // migration, `enforce_db_perms_0600` — so a path swapped between `prepare_db_file` and
        // here must be refused before any of it can touch the replacement.
        #[cfg(test)]
        take_open_race_hook();
        #[cfg(test)]
        open_ledger::record(db_path, &conn);
        let identity = settled_identity(db_path, before)?;
        // First, and before the refusal below: the declared relationships are only worth what this
        // connection enforces, and the pragma is connection state — nothing is written, so a DB
        // from a newer build is still left exactly as it was.
        schema::enforce_foreign_keys(&conn)?;
        // busy_timeout comes first now, and on its own: it is connection-local state that writes
        // nothing, so it is safe ahead of the refusals below, and the shape guard holds a read
        // transaction for the whole of its judgement — a concurrent writer has to be able to WAIT
        // for that rather than be handed «database is locked» on the first attempt.
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        // Refuse a DB written by a newer build before touching it (no WAL flip, no migration).
        schema::ensure_version_supported(&conn)?;
        // And refuse one that is not our checkpoint at all — also before the WAL flip below, so a
        // database we do not own keeps its bytes, its mtime and its sidecar census. Reading
        // `sqlite_master` and `PRAGMA table_info` writes nothing; the WAL flip below does.
        schema::ensure_recognisable_shape(&conn)?;
        // WAL and synchronous for the run itself — the background move worker holds its own
        // connection in parallel with the main one.
        conn.execute_batch("PRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;")?;
        schema::migrate(&conn)?;
        // 0600 on the DB file and WAL/SHM (created by enabling WAL above): the contents — the paths of all
        // pool files — are for the owner only (errors are propagated, not best-effort).
        crate::paths::enforce_db_perms_0600(db_path)?;
        Ok(Self::with_identity(conn, identity))
    }

    /// Opens an in-memory DB — for unit tests.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        schema::enforce_foreign_keys(&conn)?;
        schema::migrate(&conn)?;
        Ok(Self::new(conn))
    }

    /// Path of the DB file — to derive the state_dir for reading config.json.
    pub fn db_path(&self) -> Option<PathBuf> {
        self.conn.path().map(PathBuf::from)
    }

    /// Looks for the most recent scan (to resume or view).
    ///
    /// Test-only since CSV-C1: its last production caller was `--export-csv`, and the export now
    /// selects through `newest_active_scan_tx`, which the trash predicate this one lacks is the
    /// whole point of. Headless resume left it earlier for the same reason
    /// (`run_headless_scan` uses `resume_probe_for_roots`). Kept because the resume-ordering
    /// fixtures still ask this exact question.
    #[cfg(test)]
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
    /// `dir_omission` comes before `scan_root`, and both before `scan`. Foreign keys ARE enforced —
    /// every `ScanStore` connection turns them on and proves it (`schema::enforce_foreign_keys`) —
    /// so the cascades would carry these deletes anyway; the explicit order stays as deliberate
    /// defense in depth. A ledger row that outlived its authority would be read against a root that
    /// no longer exists, and a delete whose meaning lives only in a cascade is a delete no reader
    /// of this function can check.
    pub fn purge_scan(&mut self, scan_id: i64) -> Result<()> {
        self.revoke_membership_cache();
        let tx = self.conn.transaction()?;
        for table in [
            "scan_stats",
            "file_mark",
            "file",
            "dir_dedup",
            // Members before the summaries they name, and the authority before the scan it
            // belongs to. Their cascades are live (see the doc comment), so this order is defense
            // in depth — the same deliberate belt-and-braces the ledger below already gets.
            "file_group_member",
            "scan_membership",
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
            // Test seam: fails part-way down the list, so a rollback assertion here is about a
            // real partial delete rather than a transaction that never began.
            #[cfg(test)]
            if table == "dir_dedup" && take_clear_fault() {
                return Err(AppError::msg("injected purge fault"));
            }
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
        let tx = self.conn.unchecked_transaction()?;
        scan_config_tx(&tx, scan_id)
    }

    /// The current scan status.
    pub fn scan_status(&self, scan_id: i64) -> Result<ScanStatus> {
        let tx = self.conn.unchecked_transaction()?;
        scan_status_tx(&tx, scan_id)
    }

    /// Summary of a completed scan from `scan_stats` — for opening the result
    /// without recomputation.
    ///
    /// One read transaction for all four of its parts: the counters, the reclaim total, the
    /// alias sets and the omission account described three different database states before
    /// R4B-2c1, which is how a summary could report a total that no longer matched its groups.
    pub fn scan_summary(&self, scan_id: i64) -> Result<ScanSummary> {
        let tx = self.conn.unchecked_transaction()?;
        scan_summary_tx(&tx, scan_id)
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
    /// walk claimed about completeness AND everything the previous run published about its results.
    ///
    /// One transaction, and that is the whole point: a ledger that outlived its manifest would let
    /// the next walk inherit the previous one's omissions, and an authority left standing over a
    /// deleted ledger would read as «nothing was omitted». Manifest, ledger and every root
    /// generation go together or not at all.
    ///
    /// The results go with them, for the same reason. A summary describes members of a manifest
    /// that no longer exists, so `file_group` outliving the manifest is a group whose files cannot
    /// be found; `results_materialized` outliving it is worse still, because opening the scan then
    /// returns through that marker and hands the operator the old groups as if they were current.
    /// Revoked here: the v5 membership authority (`scan_membership`) and its members
    /// (`file_group_member`), `file_group`, the legacy `file_dedup` rows, `dir_dedup`, the prepared
    /// marker, the published reclaim total and its state, and the counters that describe the
    /// deleted manifest (`groups_found`, `files_scanned`, `bytes_hashed`, `hash_failures` and the
    /// four candidate-progress columns).
    ///
    /// Deliberately NOT revoked: `file_mark` — the operator's own work, which a re-walk of the same
    /// roots re-attaches to a fresh manifest, and which already refuses a plan while its manifest
    /// row is missing; `elapsed_seconds` and the environment columns, which describe the session
    /// rather than its result; `move_event`, a journal that is not scan-scoped in meaning; and
    /// `hash_cache`, which is keyed by allocation and shared across scans.
    ///
    /// Root registration runs here too, so a scan that predates the ledger — its `scan_root` rows
    /// were never written, because `begin_scan` is not called on resume — can earn an authority by
    /// re-walking. Idempotent: a scan whose roots are already registered keeps their rows, and
    /// their generations have just been zeroed anyway.
    pub fn clear_files(&mut self, scan_id: i64) -> Result<()> {
        // Membership is about to change; this connection's own write is invisible to the token,
        // so the verdict is dropped BEFORE the attempt and never restored by it.
        self.revoke_membership_cache();
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM file WHERE scan_id = ?1", params![scan_id])?;
        delete_ledger_tx(&tx, scan_id, &ClearScope::WholeScan)?;
        // Members first, then the authority that names their publication, then the summaries they
        // belong to: membership that outlives its manifest is a trusted orphan, and an authority
        // left standing over deleted members would read as «this scan's membership is known».
        tx.execute(
            "DELETE FROM file_group_member WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM scan_membership WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM file_group WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM file_dedup WHERE scan_id = ?1",
            params![scan_id],
        )?;
        // Test seam: fails HERE, with the manifest, the ledger and both membership tables already
        // gone and the rest of the transaction still ahead — the only position from which a
        // rollback assertion is about a real partial write.
        #[cfg(test)]
        if take_clear_fault() {
            return Err(AppError::msg("injected clear fault"));
        }
        tx.execute("DELETE FROM dir_dedup WHERE scan_id = ?1", params![scan_id])?;
        revoke_published_results_tx(&tx, scan_id)?;
        zero_generations_tx(&tx, scan_id, None)?;
        let registration = ensure_roots_tx(&tx, scan_id)?;
        tx.commit()?;
        log_registration(scan_id, &registration);
        Ok(())
    }

    /// Batch-adds files to the manifest (walk phase). hash = NULL.
    pub fn record_files(&mut self, scan_id: i64, files: &[ManifestRow]) -> Result<()> {
        self.revoke_membership_cache();
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
    /// Materializes LIGHTWEIGHT `file_group` summaries via SQL aggregation — without loading
    /// `Vec<DuplicateGroup>` into RAM. Browse-only: it writes NO `scan_membership` row and NO
    /// member row, so the scan's authority stays exactly what it was.
    ///
    /// Private since R4B-2c: publication goes through `publish_results` alone, and the one
    /// caller left is `prepare_legacy_for_viewing`'s Unknown branch — a legacy/migrated
    /// checkpoint gets viewable summaries without ever minting membership authority.
    ///
    /// The rank order is the checkpoint's total key — guaranteed bytes first, the trusted ceiling
    /// as the tiebreak, the hash last — the same window function `publish_results(Derived)`
    /// uses, so a later republication assigns the same ranks to the same rows.
    fn materialize_browse_summaries(&mut self, scan_id: i64) -> Result<()> {
        self.revoke_membership_cache();
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
        let tx = self.conn.unchecked_transaction()?;
        scan_reclaim_tx(&tx, scan_id)
    }

    /// How many scan-local allocations already have two or more pathnames inside this scan.
    ///
    /// Informational, and deliberately independent of hashing: a set of aliases of a size nothing
    /// else shares is never hashed and never becomes a duplicate-content group, but it is exactly
    /// what an operator is looking for when a directory of «duplicates» produced no group at all.
    /// Counted from the manifest, never from synthetic rows — a link this scan never saw is not a
    /// pathname and is not counted here.
    pub fn already_linked_sets(&self, scan_id: i64) -> Result<u64> {
        let tx = self.conn.unchecked_transaction()?;
        already_linked_sets_tx(&tx, scan_id)
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
    /// One validated count per allocation — summing `nlink` once per pathname would multiply an
    /// alias set's links by its own size. Test-only since R4B-2c: the identity-keyed
    /// `MembershipSnapshot::group_claim` carries the same evidence for the trusted surface.
    #[cfg(test)]
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
        self.revoke_membership_cache();
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
        // Before the counter is borrowed: revocation needs `&mut self`, and the borrow below
        // holds a shared reference for the rest of the call.
        self.revoke_membership_cache();
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
        self.revoke_membership_cache();
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
    ///
    /// What this writes is byte-exact and marked `Exact`: both pathnames go in as the raw bytes
    /// the move handled, so two names that differ only outside UTF-8 stay two distinguishable
    /// rows. Whether every move reaches this table is the caller's affair — `move_batch::record`
    /// is best-effort and does not report a refused insert.
    pub fn record_move_event(&mut self, event: &MoveEvent) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let source: &[u8] = event.source_path.as_os_str().as_bytes();
        let target: &[u8] = event.target_path.as_os_str().as_bytes();
        let hash: Option<&[u8]> = event.hash.as_ref().map(|h| &h[..]);
        self.conn.execute(
            "INSERT INTO move_event
                (created_at, scan_id, source_path, target_path, hash, duplicate, path_fidelity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.created_at,
                event.scan_id,
                source,
                target,
                hash,
                event.duplicate as i64,
                PathFidelity::Exact.stored()
            ],
        )?;
        Ok(())
    }

    /// All move events, oldest first, each with the fidelity of its pathnames. For now read only
    /// by tests; remove `#[cfg(test)]` when a dedup pass appears that finishes off the marked
    /// `.dupN` (round v2).
    ///
    /// The pathnames come back as the bytes SQLite holds — BLOB for a v6 writer's rows, TEXT for a
    /// row written by a build from before schema versioning — and never through a `String`, which
    /// would refuse every byte sequence that is not UTF-8. A `path_fidelity` outside its domain is
    /// an error, not a guess: the CHECK makes one impossible for the product's own writers, so
    /// seeing one means the file is not what it says.
    #[cfg(test)]
    pub fn move_events(&self) -> Result<Vec<MoveEventRow>> {
        use std::os::unix::ffi::OsStringExt;
        let mut stmt = self.conn.prepare(
            "SELECT id, created_at, scan_id, source_path, target_path, hash, duplicate,
                    path_fidelity
             FROM move_event ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get_ref(3)?.as_bytes()?.to_vec(),
                row.get_ref(4)?.as_bytes()?.to_vec(),
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, created_at, scan_id, source, target, hash, duplicate, fidelity) = row?;
            let path_fidelity = PathFidelity::from_stored(fidelity).ok_or_else(|| {
                AppError::msg(format!(
                    "move_event row {id} carries path_fidelity {fidelity}, outside its domain"
                ))
            })?;
            out.push(MoveEventRow {
                event: MoveEvent {
                    created_at,
                    scan_id,
                    source_path: PathBuf::from(std::ffi::OsString::from_vec(source)),
                    target_path: PathBuf::from(std::ffi::OsString::from_vec(target)),
                    hash: hash.and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok()),
                    duplicate: duplicate != 0,
                },
                path_fidelity,
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

    /// The scan's duplicate-directory groups, revalidated against the CURRENT ledger and sorted
    /// by benefit. One deferred transaction: the rows and the authority they are judged by
    /// cannot come from different WAL states.
    ///
    /// Test-only since R4B-2c: production reads the summaries through the browsing actor's
    /// `OpenedBrowse` and opens one group at a time by signature.
    #[cfg(test)]
    pub fn attributed_dir_groups(&self, scan_id: i64) -> Result<Vec<AttributedDirGroup>> {
        let tx = self.conn.unchecked_transaction()?;
        attributed_dir_groups_tx(&tx, scan_id)
    }

    /// Saves action marks without reading back a settled after-image.
    ///
    /// Test-only since R4B-2c: every production mark travels through the browsing actor and
    /// `save_marks_settled`, which refuses a replaced database and returns the durable image.
    /// The fixtures keep this raw writer because seeding marks predates any actor.
    #[cfg(test)]
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

    /// Writes marks and hands back what the database now holds for exactly those pathnames.
    ///
    /// The after-image is read INSIDE the same transaction as the write. Reading it after the
    /// commit would describe a second database state, and the caller would settle its screen from
    /// a state it never wrote — the defect class this work has already rejected three times.
    ///
    /// Three refusals happen before anything is written: a replaced database file, one pathname
    /// requested twice with two different meanings, and a pathname with no manifest row. The
    /// fourth is the strict decoder on the way back out, which is why a row that ends up both
    /// keeper and action fails here rather than in a plan the operator has already confirmed.
    ///
    /// Staged by R4B-2a with no production caller; R4B-2b's mark acknowledgement carries the
    /// returned image, and R4B-2c settles the UI from it instead of from its own before-image.
    pub fn save_marks_settled(
        &mut self,
        scan_id: i64,
        files: &[FileEntry],
    ) -> std::result::Result<Vec<(PathBuf, Option<MarkIntent>)>, MarkWriteError> {
        use rusqlite::OptionalExtension;
        let store = |err: rusqlite::Error| MarkWriteError::Store {
            detail: err.to_string(),
        };
        // Before the transaction, and before any write: this connection must still be looking at
        // the database the operator is looking at.
        self.ensure_current_path()
            .map_err(|err| MarkWriteError::PathChanged {
                detail: err.to_string(),
            })?;
        // The request has to agree with itself before it is worth writing. One pathname named
        // twice with two different fates is a window that does not know its own state, and which
        // of the two won would be an accident of iteration order.
        let mut wanted: Vec<(&Path, bool, Option<ActionKind>)> = Vec::with_capacity(files.len());
        for file in files {
            let path = file.path.as_path();
            match wanted.iter().find(|(seen, _, _)| *seen == path) {
                Some((_, keeper, action))
                    if *keeper != file.is_keeper || *action != file.action =>
                {
                    return Err(MarkWriteError::RequestContradictsItself {
                        path: file.path.clone(),
                    })
                }
                Some(_) => {}
                None => wanted.push((path, file.is_keeper, file.action)),
            }
        }

        let tx = self.conn.transaction().map_err(store)?;
        {
            let mut manifest = tx
                .prepare("SELECT 1 FROM file WHERE scan_id = ?1 AND path = ?2")
                .map_err(store)?;
            let mut upsert = tx
                .prepare(
                    "INSERT OR REPLACE INTO file_mark(scan_id, path, is_keeper, action)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .map_err(store)?;
            let mut clear = tx
                .prepare("DELETE FROM file_mark WHERE scan_id = ?1 AND path = ?2")
                .map_err(store)?;
            for (path, keeper, action) in &wanted {
                let text = path.to_string_lossy();
                // A mark for a pathname this scan never saw has nothing to vouch for it. The
                // commander checks this separately today; here it is part of the write.
                let known: Option<i64> = manifest
                    .query_row(params![scan_id, &*text], |row| row.get(0))
                    .optional()
                    .map_err(store)?;
                if known.is_none() {
                    return Err(MarkWriteError::NotInManifest {
                        path: path.to_path_buf(),
                    });
                }
                if !*keeper && action.is_none() {
                    clear.execute(params![scan_id, &*text]).map_err(store)?;
                } else {
                    upsert
                        .execute(params![
                            scan_id,
                            &*text,
                            *keeper as i64,
                            action.map(|kind| kind.as_str()),
                        ])
                        .map_err(store)?;
                }
            }
        }

        // The read-back, still inside the transaction. `m.rowid` is the row-presence bit the
        // strict decoder needs: a joined row always has one, and no column of it can be NULL by
        // accident the way `is_keeper` can.
        let mut after: Vec<(PathBuf, Option<MarkIntent>)> = Vec::with_capacity(wanted.len());
        {
            let mut read = tx
                .prepare(
                    "SELECT m.is_keeper, m.action, m.rowid FROM file_mark m
                      WHERE m.scan_id = ?1 AND m.path = ?2",
                )
                .map_err(store)?;
            for (path, _, _) in &wanted {
                let text = path.to_string_lossy();
                let row: Option<(Value, Value)> = read
                    .query_row(params![scan_id, &*text], |row| {
                        Ok((row.get::<_, Value>(0)?, row.get::<_, Value>(1)?))
                    })
                    .optional()
                    .map_err(store)?;
                let (present, is_keeper, action) = match row {
                    Some((keeper, action)) => (true, keeper, action),
                    None => (false, Value::Null, Value::Null),
                };
                let intent = decode_mark(path, present, &is_keeper, &action)?;
                after.push((path.to_path_buf(), intent));
            }
        }
        tx.commit().map_err(store)?;
        Ok(after)
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
        self.revoke_membership_cache();
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

    // `scan_created_at` used to live here as an autocommit reader for the browsing door.
    // R4B-2c1 moved it onto `MembershipSnapshot`, where it reads inside the transaction the rest
    // of the open payload comes from, and nothing else asked for it.

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

    /// The content signature of each directory in `dirs`, with the trust the current ledger
    /// vouches for it — one read snapshot: three authority statements plus one existing subtree
    /// query per requested directory.
    ///
    /// A signature is produced ONLY for directories both classifiers call whole enough to show:
    /// every scanned file under it has a hash (the unhashed-file rule, unchanged), AND the ledger
    /// does not suppress it. A `Suppressed` directory is absent — exactly the absence the
    /// builders produce — and under a bounded scan a directory outside every selected root is
    /// absent too, mirroring the materialized output's root bounding. `Unknown` stays inspectable
    /// as `Untrusted`; the consumer decides that only `Trusted` may look like an exact match.
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
    ) -> Result<HashMap<PathBuf, LiveDirSignature>> {
        let tx = self.conn.unchecked_transaction()?;
        let outcome = completeness_snapshot_tx(&tx, scan_id)?;
        let legacy = LegacyContext;
        let ctx: &dyn SignatureContext = match &outcome {
            SnapshotOutcome::Bounded(snapshot) => snapshot,
            SnapshotOutcome::Unavailable(_) => &legacy,
        };

        let mut out = HashMap::new();
        // We take ALL files under the directory (not only `hash IS NOT NULL`).
        // An unhashed file (unique-size / failure) makes the directory INCOMPLETE — a live
        // signature for it is NOT produced (no false cross-panel «twin» highlighting).
        let mut stmt = tx.prepare(
            "SELECT path, hash FROM file
             WHERE scan_id = ?1 AND path >= ?2 AND path < ?3
             ORDER BY path",
        )?;
        for dir in dirs {
            // The ledger gate, before any row is read: a suppressed directory emits nothing, and
            // a bounded scan emits nothing above or outside its selected roots — the same
            // above-root loss the materialized path accepted.
            let trust = match ctx.disposition(dir) {
                DirDisposition::Suppressed => continue,
                DirDisposition::Trusted => DirTrust::Trusted,
                DirDisposition::Untrusted => DirTrust::Untrusted,
            };
            if matches!(ctx.scope(dir), DirScope::Outside) {
                continue;
            }
            let (lo, hi) = prefix_bounds(dir);
            let rows = stmt.query_map(params![scan_id, lo, hi], |row| {
                Ok((
                    PathBuf::from(row.get::<_, String>(0)?),
                    row.get::<_, Option<Vec<u8>>>(1)?,
                ))
            })?;
            let signature = match algo {
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
                        Some(signature_of(&entries))
                    } else {
                        None
                    }
                }
                DirSigAlgo::Merkle => {
                    // Gather files under `dir` (size is not needed for sig — 0 placeholder),
                    // run the accepted marker-aware streaming build with the same context; an
                    // incomplete or suppressed `dir` is NOT emitted → no sig.
                    let mut files: Vec<(PathBuf, u64, Option<String>)> = Vec::new();
                    for row in rows {
                        let (path, hash) = row?;
                        files.push((path, 0, hash.map(|h| hex_encode(&h))));
                    }
                    if files.is_empty() {
                        continue;
                    }
                    let mut dir_sig: Option<String> = None;
                    build_dir_signatures_streaming_in_context(files, ctx, |emitted| {
                        if emitted.path.as_path() == dir.as_path() {
                            dir_sig = Some(emitted.signature);
                        }
                        Ok(())
                    })?;
                    dir_sig
                }
            };
            if let Some(signature) = signature {
                out.insert(dir.clone(), LiveDirSignature { signature, trust });
            }
        }
        Ok(out)
    }

    /// Attributed summaries of all twin-directory groups for the browser tab `[2] Directories`
    /// and its header totals. One deferred transaction, exactly 4 statements: 3 authority reads
    /// plus one ordered `dir_dedup` scan, folded with O(1) state per signature run and no path
    /// retained. Members the current ledger suppresses are removed, cardinality is re-evaluated
    /// (`< 2` survivors → no group), `rank` is 1-based over the surviving groups.
    /// Attributed summaries of all twin-directory groups, in one deferred transaction.
    ///
    /// Test-only since R4B-2c1: production reads them through `MembershipSnapshot`, inside the
    /// transaction the rest of the `Open` payload comes from. The store-level tests that check
    /// the folding rules themselves keep asking here, where the answer is not entangled with a
    /// membership authority they are not about.
    #[cfg(test)]
    pub fn attributed_dir_group_summaries(
        &self,
        scan_id: i64,
    ) -> Result<AttributedDirGroupSummaries> {
        let tx = self.conn.unchecked_transaction()?;
        attributed_dir_group_summaries_tx(&tx, scan_id)
    }

    /// The full twin-directory group by signature, revalidated against the CURRENT ledger — for
    /// the right panel of the browser Dirs tab on entering a group. Uses the index
    /// `dir_dedup_by_scan_sig` (schema.rs:58). One deferred transaction, exactly 4 statements.
    /// Returns `None` if the signature does not exist, or if the current ledger has whittled the
    /// group below two surviving members — a claim with no twin is not answered.
    pub fn attributed_dir_group(
        &self,
        scan_id: i64,
        signature: &str,
    ) -> Result<Option<AttributedDirGroup>> {
        let tx = self.conn.unchecked_transaction()?;
        attributed_dir_group_tx(&tx, scan_id, signature)
    }

    /// The twin-directory group the cursor's own directory belongs to, revalidated against the
    /// CURRENT ledger — for the watch panel of `WatchKey::DirOf`. Keyed by the path, not by a
    /// signature the caller supplies, so the answer is about the directory the user is standing on.
    /// One deferred transaction, exactly 4 statements: the three authority reads plus one indexed
    /// `dir_dedup` read whose subquery resolves the cursor's signature (both halves are covered by
    /// the PK and by `dir_dedup_by_scan_sig`, schema.rs:85).
    ///
    /// `None` when the directory is in no group, when the current ledger has whittled the group
    /// below two surviving members, or when it suppresses the cursor itself — a directory whose
    /// own contents are no longer established may not be presented as one of a pair, and the
    /// surviving remainder is not «duplicates of this cursor» either.
    #[cfg(test)]
    pub fn attributed_dir_group_at(
        &self,
        scan_id: i64,
        dir_path: &Path,
    ) -> Result<Option<AttributedDirGroup>> {
        let tx = self.conn.unchecked_transaction()?;
        attributed_dir_group_at_tx(&tx, scan_id, dir_path)
    }

    /// Whether `path` is covered by the active scan — an exact manifest row, or at least one
    /// row under the prefix.
    ///
    /// Test-only since R4B-2c: the watch surface gets the same split from `dir_group_at`, which
    /// decides it inside the snapshot that answered the rest of the question.
    #[cfg(test)]
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

    /// The browse-only summary rows of a scan, in rank order.
    ///
    /// Test-only since R4B-2c: production reads summaries through the membership snapshot, which
    /// carries each row's IDENTITY and names the inconsistent ones. This is the raw row list —
    /// the question a legacy, browse-only checkpoint can still answer.
    #[cfg(test)]
    pub fn browse_summaries(&self, scan_id: i64) -> Result<Vec<GroupSummary>> {
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
            let (mut summary, reclaim, state) = row?;
            summary.reclaim = ReclaimEstimate::from_persisted(reclaim, state)?;
            out.push(summary);
        }
        Ok(out)
    }

    /// The number of files marked for an action (non-keeper + has an action) — for the counter
    /// in the Browser header, without holding all groups in RAM.
    pub fn marked_count(&self, scan_id: i64) -> Result<u64> {
        let tx = self.conn.unchecked_transaction()?;
        marked_count_tx(&tx, scan_id)
    }

    /// Prepares a legacy scan's browse-only summaries once, on the WRITER path — so that
    /// opening them is a pure read and an observer never has to write. Private since R4B-2c:
    /// the only door in is `prepare_legacy_for_viewing`, and nothing here ever writes a
    /// `scan_membership` or member row — viewing cannot mint authority.
    ///
    /// Keyed off the explicit `results_materialized` marker, never off `file_group` being empty:
    /// empty is a legitimate answer. For a scan that predates the marker we must still not
    /// re-derive a result that already exists, because `--verify` may have filtered it and raw
    /// hashes would hand the rejected groups back. Two signals say «already finished»:
    /// rows in `file_group`, or an authoritative `scan_stats.groups_found = 0` — the completed
    /// scan recorded that it found nothing. Only a legacy scan with no result at all and no
    /// recorded count is aggregated.
    fn prepare_browse_summaries(&mut self, scan_id: i64) -> Result<()> {
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
            // The browse-only SQL aggregation, without the RAM peak; it sets the marker and
            // deliberately leaves the scan's membership authority exactly as it was.
            self.materialize_browse_summaries(scan_id)?;
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
    /// Goes through `prepare_legacy_for_viewing`, so an authoritative scan is validated by the
    /// same whole-authority rules every reader obeys and a legacy one stays browse-only.
    pub fn prepare_completed_scans(&mut self) -> Result<usize> {
        let pending = self.unprepared_completed_scans()?;
        let mut done = 0;
        for scan_id in pending {
            self.prepare_legacy_for_viewing(scan_id)?;
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
        // One validated membership snapshot for the whole plan, opened before the first read and
        // held until the plan exists and has been validated against the disk. The snapshot IS the
        // transaction, so the mark reconciliation, the membership resolution, the evidence, the
        // witness and the preflight all describe one database state — and the same whole-authority
        // validation every trusted reader obeys has already passed for it.
        let snapshot = match self.membership_snapshot(scan_id) {
            Ok(snapshot) => snapshot,
            // A scan with no published membership authority has nothing a destructive plan may
            // be keyed by. Everything else is a store-class refusal with its own sentence.
            Err(MembershipMiss::Unknown) => return Err(PlanRefusal::RescanRequired),
            Err(miss) => return Err(Self::store_refusal(describe_miss(&miss))),
        };

        // The coarse gate second: a scan nobody could measure is not planned against at all.
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

        // Membership, not digest, decides what the plan is about: every marked pathname must
        // belong to a group of the CURRENT publication. A mark whose pathname is a member of
        // nothing — a verify-rejected file, or a mark that outlived a republication — refuses
        // the whole plan; folding it back in by digest is the defect this round removes.
        let mut ids: Vec<GroupId> = Vec::new();
        for (path, _, _) in &marks {
            let id = match snapshot.group_of_path(path) {
                Ok(Some(id)) => id,
                Ok(None) => return Err(PlanRefusal::NotAMember { path: path.clone() }),
                Err(miss) => return Err(Self::store_refusal(describe_miss(&miss))),
            };
            ids.push(id);
        }
        ids.sort_by_key(|id| id.rank);
        ids.dedup();
        // The witness reads each group's CURRENT digest and exact member pathnames inside this
        // same snapshot; the strict evidence rows come from the same place. `PlanGroupInput`
        // is keyed by identity, so two Explicit ranks sharing one digest stay two groups.
        let witness = snapshot
            .witness_of(&ids)
            .map_err(|miss| Self::store_refusal(describe_miss(&miss)))?;
        let mut groups = Vec::with_capacity(ids.len());
        for (id, witnessed) in ids.iter().zip(&witness.groups) {
            let members = snapshot.plan_members(id).map_err(|miss| match miss {
                PlanEvidenceMiss::Membership(miss) => Self::store_refusal(describe_miss(&miss)),
                // Already the exact refusal the operator has to read, and the exact variant the
                // windows match on — passed through rather than flattened into a sentence.
                PlanEvidenceMiss::Member(refusal) => refusal,
            })?;
            groups.push(PlanGroupInput {
                id: *id,
                hash: witnessed.digest.clone(),
                members,
            });
        }

        // The model decides what becomes an action and what the plan may claim — and derives
        // the owned witness from these same inputs, so the lease revalidates what was planned.
        let plan = ActionPlan::try_new(scan_id, groups)?;
        // And the files have to still be the files the manifest describes. The same structural
        // check the guarded batch runs twice more, called here rather than left to the caller: a
        // plan that can be returned unvalidated is a plan someone forgets to validate. Still
        // inside the snapshot — the evidence it compares against must be the evidence the plan
        // was folded from. The snapshot ends when it drops, and nothing was written.
        plan.preflight()?;
        drop(snapshot);
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

    /// The planner's view of [`decode_mark`]. One decoder, two callers: the plan builder refuses
    /// with `PlanRefusal`, the settled writer with `MarkWriteError`, and neither has its own idea
    /// of what a valid mark is.
    fn mark_intent_from_sql(
        path: &Path,
        present: bool,
        is_keeper: &Value,
        action: &Value,
    ) -> PlanResult<Option<MarkIntent>> {
        decode_mark(path, present, is_keeper, action).map_err(PlanRefusal::from)
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
/// is not valid hex.
///
/// Test-only since R4B-2c: nothing in production binds a digest against `file.hash` any more —
/// membership is what answers, and it is keyed by identity.
#[cfg(test)]
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

/// What a clear operation covers. `Root` and `Subtree` are the accepted partial-invalidation
/// scopes that R3D deliberately leaves unwired (P0 decision D7: the only production re-walk is
/// whole-scan) — they stay for the future partial-rescan consumer and their tests.
#[allow(dead_code)]
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

/// Arms the insert fault for this thread and disarms it on drop. `pub(crate)`: the pipeline's
/// re-walk crash test drives the same fault through `run_scan`, not only through the store.
#[cfg(test)]
pub(crate) struct LedgerInsertFault;

#[cfg(test)]
impl LedgerInsertFault {
    /// Fails the insert that follows `survivors` successful ones.
    pub(crate) fn after(survivors: u32) -> Self {
        LEDGER_INSERT_FAULT.with(|slot| slot.set(Some(survivors)));
        LedgerInsertFault
    }

    /// Whether the armed fault is still waiting — a fault that never fired means the test proved
    /// nothing about rollback.
    pub(crate) fn pending(&self) -> bool {
        LEDGER_INSERT_FAULT.with(|slot| slot.get().is_some())
    }
}

#[cfg(test)]
impl Drop for LedgerInsertFault {
    fn drop(&mut self) {
        LEDGER_INSERT_FAULT.with(|slot| slot.set(None));
    }
}

// Test-only: fail `clear_files` or `purge_scan` from INSIDE its open transaction.
//
// A separate seam from `LEDGER_INSERT_FAULT` above, because that one is consulted only on the
// ledger insert path and neither of these ever reaches it — arming it would prove nothing about
// these transactions. Holding the write lock from a second connection is no substitute either: it
// stops the transaction from ever starting, which is no-start atomicity, a different property from
// rolling back after rows have already gone. Absent from every non-test build.
#[cfg(test)]
thread_local! {
    static CLEAR_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms the one-shot clear fault for this thread and disarms it on drop.
#[cfg(test)]
pub(crate) struct ClearFault;

#[cfg(test)]
impl ClearFault {
    /// Arms the shot. In `clear_files` it fires once the manifest, the ledger, the membership and
    /// `file_group`/`file_dedup` rows are gone and before anything else in that transaction; in
    /// `purge_scan`, once the first tables of its explicit list have been deleted.
    pub(crate) fn armed() -> Self {
        CLEAR_FAULT.with(|slot| slot.set(true));
        ClearFault
    }

    /// Whether the armed shot has been consumed. A test whose seam was never reached proved
    /// nothing about rollback, so it has to assert this rather than the error alone.
    pub(crate) fn fired(&self) -> bool {
        CLEAR_FAULT.with(|slot| !slot.get())
    }
}

#[cfg(test)]
impl Drop for ClearFault {
    fn drop(&mut self) {
        CLEAR_FAULT.with(|slot| slot.set(false));
    }
}

/// Consumes an armed clear fault, if any.
#[cfg(test)]
fn take_clear_fault() -> bool {
    CLEAR_FAULT.with(|slot| slot.replace(false))
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

// ---------------------------------------------------------------------------------------------
// The membership authority (staged by R4B-1, production since R4B-2c).
//
// Everything from here to the next section is the ownership of group membership: the typed
// snapshot/resolver every trusted reader goes through, the exact-schema apply opener, the
// fail-fast whole-batch lease and the two publication paths. Since the R4B-2c cutover this IS
// the production route — the digest-keyed readers and the pre-authority writers are gone.
// ---------------------------------------------------------------------------------------------

/// Who last published a scan's results, as `scan_membership` records it. `Unknown` is the
/// ABSENCE of that row — a migrated checkpoint, or a publication that never committed — and is
/// only ever inferred from absence, never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipMode {
    /// No authority row: browse-only; only the candidate view may answer, without identities.
    Unknown,
    /// Membership is the manifest by the CURRENT summary's digest; zero member rows exist.
    Derived,
    /// Membership is the `file_group_member` rows of the current generation; a raw digest is
    /// never a fallback.
    Explicit,
}

/// Why a trusted membership answer does not exist. Typed — no caller decides anything by
/// parsing an English sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipMiss {
    NoSuchScan,
    NoSuchGroup,
    /// The scan has no membership authority.
    Unknown,
    /// The asked-for generation is not the current publication.
    Stale {
        expected: i64,
        found: i64,
    },
    /// The stored authority/membership contradicts itself; nothing is repaired silently.
    Inconsistent {
        detail: String,
    },
    /// The store's configured path no longer names the file it named when the store opened it,
    /// so no trusted answer may be given from this connection. Only a fresh verified open
    /// recovers. Deliberately not an `Inconsistent`: nothing about the membership rows is
    /// wrong — they simply belong to a database that is no longer at that path.
    ReopenRequired {
        detail: String,
    },
    /// The database read itself failed.
    Store {
        detail: String,
    },
}

impl From<rusqlite::Error> for MembershipMiss {
    fn from(err: rusqlite::Error) -> Self {
        MembershipMiss::Store {
            detail: err.to_string(),
        }
    }
}

/// One group resolved through the membership authority: the identity, the mode that vouched
/// for it, the current summary row and the exact ordered members.
#[derive(Debug, Clone)]
pub struct ResolvedGroup {
    pub id: GroupId,
    /// Which authority vouched for this answer. Carried so a caller can say so; the UI keys on
    /// the identity and deliberately does not branch on the mode.
    #[allow(dead_code)]
    pub mode: MembershipMode,
    pub summary: GroupSummary,
    pub members: Vec<FileEntry>,
}

/// The current summaries under one authority. Every summary/membership disagreement is NAMED by
/// its exact identity rather than repaired — the caller decides, this reader never normalizes.
#[derive(Debug, Clone)]
pub struct MembershipSummaries {
    /// The authority and the publication these summaries came from. Every identity below
    /// already carries the generation, so the UI reads them from there; these two are the
    /// answer's own provenance.
    #[allow(dead_code)]
    pub mode: MembershipMode,
    #[allow(dead_code)]
    pub generation: i64,
    pub groups: Vec<(GroupId, GroupSummary)>,
    pub inconsistent: Vec<GroupId>,
}

/// Untrusted digest candidates of an Unknown scan — for browsing only. Deliberately carries no
/// `GroupId`, no membership test and no conversion to `ResolvedGroup`: nothing a destructive
/// gate could accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateView {
    pub candidates: Vec<DigestCandidate>,
}

/// One raw-digest candidate: the digest and how many pathnames currently share it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestCandidate {
    pub digest: String,
    pub paths: u64,
}

/// Why the apply lease was not granted. Pre-batch only: every variant means nothing on the
/// filesystem has happened. `Open`/`Schema` carry the raw diagnostic; the actions layer
/// sanitizes exactly once at `ApplyRefusal` construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseRefusal {
    /// The database file could not be verified or opened.
    Open {
        detail: String,
    },
    /// The file is not exactly the current schema (older and newer each keep their wording).
    Schema {
        detail: String,
    },
    /// Another writer holds the write lock right now; `busy_timeout=0` never queues.
    DatabaseBusy,
    /// This process is an observer and must not take a write lease at all.
    ReadOnlyRole,
    NoSuchScan,
    /// The scan has no membership authority.
    Unknown,
    /// The authority generation moved since the plan was built.
    Stale {
        expected: i64,
        found: i64,
    },
    /// A witnessed rank has no current summary row.
    RankMissing {
        rank: i64,
    },
    /// The current summary's digest is not the witnessed one.
    DigestChanged {
        rank: i64,
        expected: String,
        found: String,
    },
    /// The live member count differs from the witnessed member set.
    MemberCountChanged {
        rank: i64,
        expected: u64,
        found: u64,
    },
    /// The member set differs; names one differing pathname.
    MembershipChanged {
        path: PathBuf,
    },
    /// Summary and membership storage contradict each other, or the witness is malformed.
    Inconsistent {
        detail: String,
    },
    /// The database read itself failed mid-validation.
    Store {
        detail: String,
    },
}

/// What the staged publisher writes: the Derived SQL materialization, or the Explicit verified
/// groups a `--verify` run produced.
#[derive(Debug, Clone, Copy)]
pub enum PublishMode<'a> {
    Derived,
    Explicit(&'a [DuplicateGroup]),
}

// ---------------------------------------------------------------------------------------------
// R4B-2a — the typed store surface the future browsing actor reads through.
//
// Everything from here to the end of this block is data and errors only: no actor, no messages,
// no production caller. The readers themselves live on `MembershipSnapshot`, so each answer comes
// from the one validated transaction that snapshot already owns.
// ---------------------------------------------------------------------------------------------

/// Peers the file-info overlay lists at once.
///
/// The overlay is a read-only text list with no paging keys of its own, so it is smaller than the
/// browser's own group page. Without a cap a single answer would carry every pathname of a
/// multi-million-member group through a serialized reader and hold every other request behind it.
pub const FILE_INFO_PEER_CAP: usize = 200;

/// Inner-duplicate rows one directory answer returns. Same reason, a longer list: this one fills a
/// panel body rather than an overlay.
pub const DIR_INNER_CAP: usize = 1_000;

/// One panel row's dedup evidence: what to draw, and the digest to SHOW.
///
/// `hash_text` is display data and nothing else. It is safe to carry precisely because no
/// comparison accepts it: group equality is `GroupId`, so a digest cannot become an identity by
/// being convenient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelFile {
    pub status: PanelFileStatus,
    pub hash_text: Option<String>,
}

/// What one panel row is, as membership sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelFileStatus {
    /// No manifest row in this scan.
    NotInScan,
    /// In the manifest, not hashed yet, and nothing shares its size and mtime.
    NotHashed,
    /// Not hashed, but another manifest row carries the same size and mtime.
    LikelyBySizeMtime { peers: u64 },
    /// A member of this exact current group.
    InGroup {
        id: GroupId,
        members: u64,
        distinct_devices: u64,
    },
    /// Hashed and in the manifest, but a member of no current group — an alias-only set among
    /// them, which is one allocation and therefore not a duplicate of anything.
    NotGrouped,
    /// No trusted answer for this row. It renders as unavailable and takes no part in exact
    /// cross-panel matching.
    Unavailable(PanelMiss),
}

/// Why one row has no membership answer while the batch as a whole succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelMiss {
    /// The scan has no membership authority: browse-only.
    Unknown,
    /// The central validation named this row's rank inconsistent, so it has no exact identity.
    Inconsistent { detail: String },
}

/// What the directory watch surface can answer, as ONE value.
///
/// A sum rather than a pair of results on purpose: the shape it replaces could represent a read
/// failure and a successful fallback at the same time, and the fallback is what the operator then
/// acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirGroupAnswer {
    /// The directory's surviving twins, as the current ledger attributes them.
    Group(Box<AttributedDirGroup>),
    /// Trusted fallback: files under the directory that are members of a current group.
    InnerDupes {
        members: Vec<InnerDupe>,
        total: u64,
        truncated: bool,
    },
    /// No authority: raw-digest candidates. They carry NO `GroupId` and are never duplicates —
    /// nothing here may be shown as a confirmed twin.
    InnerCandidates {
        paths: Vec<PathBuf>,
        total: u64,
        truncated: bool,
    },
    /// The directory is covered by the scan and holds nothing duplicated.
    NoDuplicates,
    /// The scan does not cover this directory at all.
    NotInScan,
}

/// One inner duplicate: the pathname and the identity of the group that vouches for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerDupe {
    pub path: PathBuf,
    pub id: GroupId,
}

/// What the file-info surface knows about one pathname.
///
/// Manifest presence is the OUTER decision, and it is established positively. «No duplicates
/// found» is representable only for a present row whose membership is `NotGrouped`; a pathname
/// outside the scan and a membership refusal each keep their own rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileInfoAnswer {
    /// No manifest row for this pathname in this scan.
    NotInScan,
    InScan {
        /// `None` means only that this manifest row carries no digest yet.
        hash_text: Option<String>,
        /// Independent of presence, so a refusal can never be read as «no duplicates».
        membership: std::result::Result<FileMembership, MembershipMiss>,
    },
}

/// The membership half of a file-info answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileMembership {
    /// In the manifest, member of no current group. The ONLY state that may render
    /// «No duplicates found».
    NotGrouped,
    InGroup(Box<FileGroupInfo>),
}

/// The group behind a file-info answer: an identity, a bounded page of peers, and the honest
/// total. Two Explicit ranks sharing a digest stay separate, because this is keyed by identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileGroupInfo {
    pub id: GroupId,
    /// At most `FILE_INFO_PEER_CAP`, in member order, excluding the subject itself.
    pub peers: Vec<PathBuf>,
    /// The group's real member count, whatever `peers` holds.
    pub total: u64,
    pub truncated: bool,
}

/// Why one durable mark did not decode. The single strict decoder's error; `PlanRefusal` and
/// `MarkWriteError` both convert FROM it, so there is exactly one place that judges a mark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkDecodeError {
    Corrupt {
        path: PathBuf,
        field: &'static str,
        detail: String,
    },
    Contradictory {
        path: PathBuf,
    },
}

/// Why a settled mark write did not happen, or did not settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkWriteError {
    /// The same pathname was requested twice with two different meanings.
    RequestContradictsItself { path: PathBuf },
    /// A requested pathname has no manifest row in this scan.
    NotInManifest { path: PathBuf },
    /// The after-image did not decode.
    Decode(MarkDecodeError),
    /// The database file at the configured path was replaced. Nothing was written.
    PathChanged { detail: String },
    /// The write or the read-back failed.
    Store { detail: String },
}

impl std::fmt::Display for MarkDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarkDecodeError::Corrupt {
                path,
                field,
                detail,
            } => write!(
                f,
                "dedcom.db holds an unreadable mark for {} ({field}: {detail})",
                path.display()
            ),
            MarkDecodeError::Contradictory { path } => write!(
                f,
                "{} is marked both as the keeper and for an action",
                path.display()
            ),
        }
    }
}

impl From<MarkDecodeError> for PlanRefusal {
    fn from(err: MarkDecodeError) -> Self {
        match err {
            MarkDecodeError::Corrupt {
                path,
                field,
                detail,
            } => PlanRefusal::CorruptMark {
                path,
                field,
                detail,
            },
            MarkDecodeError::Contradictory { path } => PlanRefusal::ContradictoryMark { path },
        }
    }
}

impl From<MarkDecodeError> for MarkWriteError {
    fn from(err: MarkDecodeError) -> Self {
        MarkWriteError::Decode(err)
    }
}

/// One durable mark, decoded strictly, or a refusal.
///
/// `present` is the row-presence bit, and it is the difference between two things a `LEFT JOIN`
/// renders identically: no `file_mark` row at all, whose columns are `NULL` because there is
/// nothing to read, and a row that exists carrying a `NULL` in a column declared `INTEGER NOT
/// NULL`. The first is an ordinary unmarked member; the second is damaged evidence, and reading
/// it as «not the keeper» would turn it into whatever its `action` says.
///
/// Strict where the rest of the program can afford not to be. `and_then(ActionKind::parse)` would
/// turn an identifier this build does not know into «no action», and the marked row would then
/// vanish from a plan the operator confirms. `is_keeper` is a flag, so on a present row only
/// SQLite's integer `0` and `1` are that flag. A row that is both a keeper and an action states
/// two incompatible fates for one pathname and is not something to normalise.
fn decode_mark(
    path: &Path,
    present: bool,
    is_keeper: &Value,
    action: &Value,
) -> std::result::Result<Option<MarkIntent>, MarkDecodeError> {
    let corrupt = |field: &'static str, value: &Value| MarkDecodeError::Corrupt {
        path: path.to_path_buf(),
        field,
        detail: ScanStore::describe_value(value),
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
                ActionKind::parse(text).ok_or_else(|| MarkDecodeError::Corrupt {
                    path: path.to_path_buf(),
                    field: "action",
                    detail: format!("text {text:?}"),
                })?,
            )
        }
        other => return Err(corrupt("action", other)),
    };
    match (keeper, action) {
        (true, Some(_)) => Err(MarkDecodeError::Contradictory {
            path: path.to_path_buf(),
        }),
        (true, None) => Ok(Some(MarkIntent::Keeper)),
        (false, Some(kind)) => Ok(Some(MarkIntent::Act(kind))),
        (false, None) => Ok(None),
    }
}

// ---------------------------------------------------------------------------------------------
// Transaction-scoped scan readers.
//
// One body per question, so the autocommit method on `ScanStore` and the snapshot-scoped answer
// cannot drift apart. Everything an `Open` payload needs lives here: since R4B-2c1 the browsing
// actor builds the whole payload from ONE snapshot, and a second copy of any of this SQL is
// exactly how «one database state» would quietly become several.
// ---------------------------------------------------------------------------------------------

/// EXACTLY the newest session the operator has not moved to the trash, with the status it
/// carries — one row, `LIMIT 1`, no looking further down the list.
///
/// The trash predicate is the session list's (`scans_filtered`): a trashed session is hidden
/// everywhere the operator looks, so an export handing its contents back would answer about a
/// session the product says is gone.
///
/// The unknown-status rule is deliberately the OPPOSITE of `find_resumable`'s and the session
/// lists'. They skip a row written by a newer build and move on, which is right for them: a
/// resume looks for something it can continue, and a list shows what it can render. An export
/// promises one specific session — the newest active one — so skipping it would hand the operator
/// an artifact about an OLDER session under the name of the newest. That is a silent session
/// switch, and it refuses here instead. Neither `find_resumable` nor the lists are changed.
///
/// Reads nothing else: an export needs an id and a status, not a session card, so none of the
/// progress or reclaim aggregation is paid here.
fn newest_active_scan_tx(tx: &Transaction<'_>) -> Result<Option<(i64, ScanStatus)>> {
    use rusqlite::OptionalExtension;
    let newest: Option<(i64, String)> = tx
        .query_row(
            "SELECT id, status FROM scan WHERE COALESCE(trashed, 0) = 0 ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((scan_id, status_text)) = newest else {
        return Ok(None);
    };
    let Some(status) = ScanStatus::parse(&status_text) else {
        return Err(AppError::msg(format!(
            "the newest session (scan {scan_id}) carries status {status_text:?}, which this build \
             does not know — most likely it was written by a newer dedcom. Exporting an older \
             session under the newest session's name is not something this mode will do. Nothing \
             was written."
        )));
    };
    Ok(Some((scan_id, status)))
}

fn scan_config_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<ScanConfig> {
    let json: String = tx.query_row(
        "SELECT config_json FROM scan WHERE id = ?1",
        params![scan_id],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_str(&json)?)
}

fn scan_status_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<ScanStatus> {
    let text: String = tx.query_row(
        "SELECT status FROM scan WHERE id = ?1",
        params![scan_id],
        |row| row.get(0),
    )?;
    ScanStatus::parse(&text).ok_or_else(|| AppError::msg(format!("unknown scan status: {text}")))
}

fn scan_created_at_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    let row = tx
        .query_row(
            "SELECT created_at FROM scan WHERE id = ?1",
            params![scan_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(row)
}

fn marked_count_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<u64> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM file_mark
         WHERE scan_id = ?1 AND is_keeper = 0 AND action IS NOT NULL",
        params![scan_id],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

fn scan_reclaim_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<ReclaimEstimate> {
    let guaranteed: i64 = tx.query_row(
        "SELECT COALESCE(SUM(reclaim), 0) FROM file_group
          WHERE scan_id = ?1 AND reclaim_state = ?2",
        params![scan_id, ReclaimState::Exact.as_i64()],
        |row| row.get(0),
    )?;
    let (ceiling, state): (i64, i64) = tx.query_row(
        "SELECT COALESCE(MAX(reclaimable_bytes), 0), COALESCE(MAX(reclaim_state), 0)
           FROM scan_stats WHERE scan_id = ?1",
        params![scan_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ReclaimEstimate::from_persisted_scan(guaranteed, ceiling, state)
}

fn already_linked_sets_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<u64> {
    let count: i64 = tx.query_row(
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

fn scan_omission_accounting_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<OmissionAccounting> {
    Ok(match completeness_snapshot_tx(tx, scan_id)? {
        SnapshotOutcome::Bounded(snapshot) => match snapshot.scan_accounting()? {
            ScanAccounting::Exact(totals) => OmissionAccounting::Ledger(totals),
            ScanAccounting::Unavailable => OmissionAccounting::Unavailable,
        },
        SnapshotOutcome::Unavailable(_) => OmissionAccounting::Unavailable,
    })
}

fn scan_summary_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<ScanSummary> {
    let summary = tx.query_row(
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
        reclaim: scan_reclaim_tx(tx, scan_id)?,
        already_linked_sets: already_linked_sets_tx(tx, scan_id)?,
        // The reopen side of counter parity: an authoritative ledger folds to the same totals
        // the completion published; anything less is typed `Unavailable`, never an exact zero.
        omissions: scan_omission_accounting_tx(tx, scan_id)?,
        ..summary
    })
}

/// One consistent read of a scan's membership. See [`ScanStore::membership_snapshot`].
pub struct MembershipSnapshot<'a> {
    tx: Transaction<'a>,
    scan_id: i64,
    mode: MembershipMode,
    generation: i64,
    /// The whole-authority integrity result, computed once when the snapshot was taken and
    /// shared by every trusted method.
    integrity: AuthorityIntegrity,
    /// Test-only meter of the rows the export buffers; nothing in production.
    export_meter: ExportMeter<'a>,
}

/// Test-only meter of the member rows an export holds at once; compiles to nothing in production.
///
/// Same shape as [`LeaseMeter`], for the same reason: the claim being metered is about one
/// operation, and a counter living on the store keeps it readable after that operation ended.
struct ExportMeter<'a> {
    #[cfg(test)]
    now: &'a std::cell::Cell<u64>,
    #[cfg(test)]
    max: &'a std::cell::Cell<u64>,
    #[cfg(not(test))]
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl ExportMeter<'_> {
    /// One more member row is now buffered.
    fn push(&self) {
        #[cfg(test)]
        {
            let now = self.now.get() + 1;
            self.now.set(now);
            if now > self.max.get() {
                self.max.set(now);
            }
        }
    }

    /// The buffered group was handed over and dropped.
    fn release(&self) {
        #[cfg(test)]
        self.now.set(0);
    }
}

/// Releases the live-buffer count on EVERY exit from an export — success, a corrupt row, a sink
/// error, an unwind. Without it a failed export would leave the meter claiming a group that was
/// already dropped, and the next export's high-water mark would be measured on top of a fiction.
struct MeterScope<'m, 'a>(&'m ExportMeter<'a>);

impl Drop for MeterScope<'_, '_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// One member row of an export, read strictly.
///
/// `links` is `0` for a row whose link count was never recorded (a pre-v3 manifest), exactly as
/// `FileEntry::nlink` reports it — an export is a report and says «unknown», where a destructive
/// plan refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportMember {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub device: u64,
    pub inode: u64,
    pub links: u64,
    /// The durable mark, decoded by the strict decoder — never the browsing one, which would read
    /// a damaged flag as «not the keeper» and an unknown action as «no action».
    pub mark: Option<MarkIntent>,
}

/// One published group of an export: its authoritative identity, its digest and its members in
/// member order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportGroup {
    pub id: GroupId,
    pub hash: String,
    pub members: Vec<ExportMember>,
}

/// A cell an export prints as a physical fact, decoded instead of cast.
///
/// `row.get::<_, i64>(n)? as u64` turns a stored `-1` into 18446744073709551615, and a CSV that
/// prints that has quietly converted a damaged row into a plausible size, device or inode. The
/// storage class is checked with it, so a `NULL` or a text cell refuses here too.
fn nonnegative_cell(value: &Value, field: &str, path: &Path) -> Result<u64> {
    match value {
        Value::Integer(raw) if *raw >= 0 => Ok(*raw as u64),
        other => Err(AppError::msg(format!(
            "{field} holds {} for {} — not a value a filesystem can report. The export refuses \
             rather than printing it as fact. Nothing was written.",
            authority_cell(other),
            crate::textsan::terminal(&path.display().to_string())
        ))),
    }
}

/// The sub-second half of an mtime, in the domain a filesystem can produce.
///
/// It is not cosmetic here: the fallback keeper is the maximum by `(mtime, mtime_nsec, path)`, so
/// a cell outside `0..1_000_000_000` would decide which file an operator's tooling keeps.
fn nanoseconds_cell(value: &Value, path: &Path) -> Result<i64> {
    match value {
        Value::Integer(raw) if (0..1_000_000_000).contains(raw) => Ok(*raw),
        other => Err(AppError::msg(format!(
            "file.mtime_nsec holds {} for {} — outside the 0..999999999 a filesystem can report, \
             and the exported keeper is chosen by it. Nothing was written.",
            authority_cell(other),
            crate::textsan::terminal(&path.display().to_string())
        ))),
    }
}

/// The one statement an export streams, per authority mode.
///
/// Composed from the same member relation the trusted readers use (`member_source`), with the
/// scan-wide filter this reader adds — a second spelling of «what a member is» is exactly how the
/// export and the browser would come to disagree.
///
/// The order is `(rank, path)` and it is meant to come from the indexes rather than from a
/// sorter: Explicit drives `file_group_member` by its primary key `(scan_id, group_rank, path)`,
/// Derived drives `file_group` by `(scan_id, rank)` and probes `file_hash_path
/// (scan_id, hash, path)`. That is a claim about a query plan, so it is not left as a comment —
/// `export_plan_tests` runs `EXPLAIN QUERY PLAN` over these exact statements and fails on
/// `USE TEMP B-TREE FOR ORDER BY`.
fn export_rows_sql(mode: MembershipMode) -> &'static str {
    match mode {
        MembershipMode::Explicit => {
            "SELECT mm.group_rank, g.hash, g.size, f.path, f.size, f.mtime, f.mtime_nsec,
                    f.device, f.inode, f.nlink, m.is_keeper, m.action, m.rowid
               FROM file_group_member mm
               JOIN file_group g     ON g.scan_id = mm.scan_id AND g.rank = mm.group_rank
               JOIN file f           ON f.scan_id = mm.scan_id AND f.path = mm.path
               LEFT JOIN file_mark m ON m.scan_id = mm.scan_id AND m.path = mm.path
              WHERE mm.scan_id = ?1
              ORDER BY mm.group_rank, mm.path"
        }
        _ => {
            "SELECT g.rank, g.hash, g.size, f.path, f.size, f.mtime, f.mtime_nsec,
                    f.device, f.inode, f.nlink, m.is_keeper, m.action, m.rowid
               FROM file_group g
               JOIN file f           ON f.scan_id = g.scan_id AND f.hash = unhex(g.hash)
               LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
              WHERE g.scan_id = ?1
              ORDER BY g.rank, f.path"
        }
    }
}

/// What one export covered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportTotals {
    pub groups: u64,
    pub rows: u64,
}

/// The one snapshot an export runs from, with the two facts its own header line needs.
///
/// Constructed only by [`ScanStore::open_trusted_export`], which is where both eligibility rules
/// live: a trusted authority AND a finished scan.
pub struct TrustedExport<'a> {
    pub snapshot: MembershipSnapshot<'a>,
    pub scan_id: i64,
    pub status: ScanStatus,
}

/// What the one central validation found. Structural corruption never reaches this value — it
/// fails the snapshot outright — so what remains is the per-group disagreement the contract
/// deliberately keeps reportable: a summary whose `file_count` differs from its real member
/// count. `summaries()` names those identities; every exact answer for them refuses.
#[derive(Debug, Clone, Default)]
struct AuthorityIntegrity {
    inconsistent_ranks: std::collections::BTreeSet<i64>,
}

/// The held apply lease: one `BEGIN IMMEDIATE` transaction that validated the witness and now
/// spans the whole destructive batch. Readers continue (WAL); no other writer can commit until
/// this drops. Dropping rolls the transaction back — the lease only ever reads, so release and
/// rollback are the same thing.
pub struct MembershipLease<'a> {
    /// Kept for its Drop: the rollback IS the release.
    _tx: Transaction<'a>,
    #[cfg(test)]
    statements: &'a std::cell::Cell<u64>,
}

impl MembershipLease<'_> {
    /// Test-only: statements spent on this store's lease path so far. Readable while the lease
    /// is held, which a borrow of the store itself would not be.
    #[cfg(test)]
    pub(crate) fn statements_so_far(&self) -> u64 {
        self.statements.get()
    }
}

impl Drop for MembershipLease<'_> {
    fn drop(&mut self) {
        // The inner transaction's own Drop issues the ROLLBACK; this only meters it in tests.
        #[cfg(test)]
        self.statements.set(self.statements.get() + 1);
    }
}

/// Test-only statement meter for the lease path; compiles to nothing in production.
struct LeaseMeter<'a> {
    #[cfg(test)]
    cell: &'a std::cell::Cell<u64>,
    #[cfg(not(test))]
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl LeaseMeter<'_> {
    fn bump(&self) {
        #[cfg(test)]
        self.cell.set(self.cell.get() + 1);
    }
}

/// The BEGIN IMMEDIATE outcome, typed: a held write lock is `DatabaseBusy` (the fail-fast
/// answer), anything else is a store failure. Decided on the SQLite error code, never on text.
fn lease_begin_refusal(err: rusqlite::Error) -> LeaseRefusal {
    if let rusqlite::Error::SqliteFailure(code, _) = &err {
        if code.code == rusqlite::ErrorCode::DatabaseBusy {
            return LeaseRefusal::DatabaseBusy;
        }
    }
    LeaseRefusal::Store {
        detail: err.to_string(),
    }
}

fn lease_store_refusal(err: rusqlite::Error) -> LeaseRefusal {
    LeaseRefusal::Store {
        detail: err.to_string(),
    }
}

/// The authority cell for a message: the integer itself, or the storage class that sits where
/// an integer had to be.
fn authority_cell(value: &Value) -> String {
    match value {
        Value::Integer(raw) => raw.to_string(),
        other => storage_class(other).to_string(),
    }
}

/// How a damaged group-summary cell is named in a refusal.
///
/// Numbers print as themselves — including a `reclaim_state` that is an integer but not one of
/// the states, where the number IS the diagnosis. A damaged `hash` is the one cell whose stored
/// text must not be echoed: it is attacker-shaped free text from a corrupt row. Its length is
/// reported instead — that is what separates a truncated digest from a mistyped one — together
/// with what is actually wrong with it, because a length alone leaves an operator staring at a
/// 64-character value with no idea why the build rejected it.
fn summary_cell(cell: &str, value: &Value) -> String {
    match (cell, value) {
        ("hash", Value::Text(text)) => format!(
            "text of length {} that is not canonical lower-case hex",
            text.chars().count()
        ),
        _ => authority_cell(value),
    }
}

/// Where the operator will find the row. A rank is a group's address — but only while it is a
/// rank; when the rank is itself the damaged cell there is nothing to look up by, so the row is
/// named by the rowid instead.
fn group_locator(rank: &Value, rowid: i64) -> String {
    match rank {
        Value::Integer(value) if *value >= 0 => format!("group rank {value}"),
        _ => format!("group rowid {rowid}"),
    }
}

/// Decodes one `scan_membership` row that is REQUIRED to be well-formed: mode 1/2 and a
/// positive integer generation. Anything else is corruption, typed by the caller.
fn decode_authority(
    mode_value: &Value,
    generation_value: &Value,
) -> std::result::Result<(MembershipMode, i64), String> {
    let mode = match mode_value {
        Value::Integer(1) => MembershipMode::Derived,
        Value::Integer(2) => MembershipMode::Explicit,
        other => {
            return Err(format!(
                "scan_membership.mode holds {} — not a known membership mode",
                authority_cell(other)
            ))
        }
    };
    match generation_value {
        Value::Integer(generation) if *generation > 0 => Ok((mode, *generation)),
        other => Err(format!(
            "scan_membership.generation holds {} — not a positive publication generation",
            authority_cell(other)
        )),
    }
}

/// Every value `file_group.reclaim_state` may legitimately hold, as an SQL list.
///
/// Taken from the enum rather than written as `IN (0, 1, 2)`: the exhaustive `match` below is
/// what makes a new variant a compile error here instead of a silently narrowed domain check
/// that would start rejecting freshly published data.
fn persisted_reclaim_states() -> String {
    let all = [
        ReclaimState::Unknown,
        ReclaimState::Exact,
        ReclaimState::UpperBound,
    ];
    for state in all {
        match state {
            ReclaimState::Unknown | ReclaimState::Exact | ReclaimState::UpperBound => {}
        }
    }
    all.iter()
        .map(|state| state.as_i64().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The one whole-authority validation every trusted membership answer rests on.
///
/// Set-wise and fixed in statement count — never per group, never per page. It accounts for the
/// COMPLETE scan, because the alternative is what R4B-1 shipped: each method validating the
/// subset it happened to read, so corruption one row past a `LIMIT` was trusted.
///
/// Statements: 1 (summary domains, both modes) + 1 (mode-specific structure) + 1 (per-rank
/// count agreement). Structural corruption that cannot be represented safely returns
/// `Inconsistent` here, before any trusted answer exists; ordinary per-group count
/// disagreement is carried out as the exact ranks, so `summaries()` can name them while every
/// exact answer for them refuses.
fn validate_authority(
    tx: &Connection,
    scan_id: i64,
    mode: MembershipMode,
    generation: i64,
) -> std::result::Result<AuthorityIntegrity, MembershipMiss> {
    use rusqlite::OptionalExtension;

    if mode == MembershipMode::Unknown {
        // Nothing is trusted, so there is nothing to validate: the candidate view derives raw
        // digests and hands back no identity at all.
        return Ok(AuthorityIntegrity::default());
    }

    // 1. Storage classes AND the real persisted domains of every summary cell this layer
    //    converts to Rust. A declared INTEGER is an affinity, not a domain: `-3` and a BLOB
    //    both live happily in `file_count`, and `as u64` would turn the first into
    //    18446744073709551613. Two of these are domains rather than ranges: `reclaim_state`
    //    is an enum, so `99` is not «large», it is not a state at all; and `hash` is
    //    canonical lower-case BLAKE3 hex, which is what `GroupWitness.digest` is specified to
    //    carry — an identity whose digest no consumer can decode is not a trusted identity.
    //    Counting the damage was not enough: the operator was told that something in the scan is
    //    out of domain, never which cell to look at. The same predicates now also name the
    //    offending column, carry its stored value and locate its row.
    //
    //    The row is chosen deterministically. `ORDER BY rank` alone is undefined precisely when
    //    `rank` is the damaged cell, so valid ranks sort first (the leading boolean), ties break
    //    on `rowid`, and `file_group` is a rowid table — the schema declares no WITHOUT ROWID.
    let offender: Option<(String, Value, Value, i64)> = tx
        .query_row(
            &format!(
                "SELECT CASE
                          WHEN typeof(rank) <> 'integer' OR rank < 0 THEN 'rank'
                          WHEN typeof(hash) <> 'text'
                            OR length(hash) <> 64 OR hash GLOB '*[^0-9a-f]*' THEN 'hash'
                          WHEN typeof(file_count) <> 'integer' OR file_count < 0
                            THEN 'file_count'
                          WHEN typeof(size) <> 'integer' OR size < 0 THEN 'size'
                          WHEN typeof(reclaim) <> 'integer' OR reclaim < 0 THEN 'reclaim'
                          WHEN typeof(object_count) <> 'integer' OR object_count < 0
                            THEN 'object_count'
                          ELSE 'reclaim_state'
                        END,
                        CASE
                          WHEN typeof(rank) <> 'integer' OR rank < 0 THEN rank
                          WHEN typeof(hash) <> 'text'
                            OR length(hash) <> 64 OR hash GLOB '*[^0-9a-f]*' THEN hash
                          WHEN typeof(file_count) <> 'integer' OR file_count < 0
                            THEN file_count
                          WHEN typeof(size) <> 'integer' OR size < 0 THEN size
                          WHEN typeof(reclaim) <> 'integer' OR reclaim < 0 THEN reclaim
                          WHEN typeof(object_count) <> 'integer' OR object_count < 0
                            THEN object_count
                          ELSE reclaim_state
                        END,
                        rank,
                        rowid
                   FROM file_group
                  WHERE scan_id = ?1
                    AND (typeof(rank) <> 'integer' OR rank < 0
                      OR typeof(hash) <> 'text'
                      OR length(hash) <> 64 OR hash GLOB '*[^0-9a-f]*'
                      OR typeof(file_count) <> 'integer' OR file_count < 0
                      OR typeof(size) <> 'integer' OR size < 0
                      OR typeof(reclaim) <> 'integer' OR reclaim < 0
                      OR typeof(object_count) <> 'integer' OR object_count < 0
                      OR typeof(reclaim_state) <> 'integer'
                      OR reclaim_state NOT IN ({states}))
                  ORDER BY (typeof(rank) <> 'integer' OR rank < 0), rank, rowid
                  LIMIT 1",
                states = persisted_reclaim_states()
            ),
            params![scan_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if let Some((cell, value, rank, rowid)) = offender {
        return Err(MembershipMiss::Inconsistent {
            detail: format!(
                "file_group.{cell} holds {} for {} — not in the domain this build can read. \
                 Nothing was written.",
                summary_cell(&cell, &value),
                group_locator(&rank, rowid)
            ),
        });
    }

    match mode {
        MembershipMode::Explicit => {
            // 2. Every structural Explicit invariant, in ONE statement, over the whole scan.
            let (
                bad_cells,
                wrong_generation,
                no_manifest,
                no_summary,
                duplicated,
                empty_groups,
                foreign_digest,
            ): (i64, i64, i64, i64, i64, i64, i64) = tx.query_row(
                "SELECT
                   (SELECT COUNT(*) FROM file_group_member m
                     WHERE m.scan_id = ?1
                       AND (typeof(m.path) <> 'text' OR m.path = ''
                         OR typeof(m.group_rank) <> 'integer' OR m.group_rank < 0
                         OR typeof(m.generation) <> 'integer')),
                   (SELECT COUNT(*) FROM file_group_member m
                     WHERE m.scan_id = ?1 AND m.generation <> ?2),
                   (SELECT COUNT(*) FROM file_group_member m
                     LEFT JOIN file f ON f.scan_id = m.scan_id AND f.path = m.path
                     WHERE m.scan_id = ?1 AND f.path IS NULL),
                   (SELECT COUNT(*) FROM file_group_member m
                     LEFT JOIN file_group g ON g.scan_id = m.scan_id AND g.rank = m.group_rank
                     WHERE m.scan_id = ?1 AND g.rank IS NULL),
                   (SELECT COUNT(*) FROM (SELECT path FROM file_group_member
                                           WHERE scan_id = ?1
                                           GROUP BY path HAVING COUNT(*) > 1)),
                   (SELECT COUNT(*) FROM file_group g
                     LEFT JOIN file_group_member m
                            ON m.scan_id = g.scan_id AND m.group_rank = g.rank
                     WHERE g.scan_id = ?1 AND m.path IS NULL),
                   (SELECT COUNT(*) FROM file_group_member m
                     JOIN file_group g ON g.scan_id = m.scan_id AND g.rank = m.group_rank
                     JOIN file       f ON f.scan_id = m.scan_id AND f.path = m.path
                     WHERE m.scan_id = ?1
                       AND (f.hash IS NULL
                         OR typeof(f.hash) <> 'blob'
                         OR length(f.hash) <> 32
                         OR unhex(g.hash) IS NULL
                         OR f.hash <> unhex(g.hash)))",
                params![scan_id, generation],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )?;
            for (count, what) in [
                (
                    bad_cells,
                    "member row(s) whose stored values are out of domain",
                ),
                (
                    wrong_generation,
                    "member row(s) of a generation other than the current publication",
                ),
                (no_manifest, "member row(s) with no manifest row"),
                (no_summary, "member row(s) with no group summary"),
                (duplicated, "pathname(s) belonging to two ranks"),
                (empty_groups, "explicit group(s) with no members"),
                (
                    foreign_digest,
                    "member row(s) whose manifest digest is not their group's own",
                ),
            ] {
                if count != 0 {
                    return Err(MembershipMiss::Inconsistent {
                        detail: format!("scan {scan_id} holds {count} {what}"),
                    });
                }
            }
        }
        MembershipMode::Derived => {
            // 2'. Derived membership is reconstructed from the summary's digest alone, so it
            //     has two invariants of its own. No member row may exist — a surplus row is
            //     corruption, never surplus. And no digest may name two summaries: two
            //     Explicit ranks may legitimately share a digest, because byte verification
            //     supplied their disjoint member rows, but Derived has no such discriminator
            //     and would put the very same manifest pathnames in both groups. That is a
            //     mode-aware READ invariant, deliberately not a UNIQUE index on
            //     `file_group.hash` — the index would forbid the legitimate Explicit case too.
            let (members, duplicate_digests): (i64, i64) = tx.query_row(
                "SELECT
                   (SELECT COUNT(*) FROM file_group_member WHERE scan_id = ?1),
                   (SELECT COUNT(*) FROM (SELECT hash FROM file_group
                                           WHERE scan_id = ?1
                                           GROUP BY hash HAVING COUNT(*) > 1))",
                params![scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if members != 0 {
                return Err(MembershipMiss::Inconsistent {
                    detail: format!(
                        "scan {scan_id} declares derived membership but holds {members} explicit \
                         member row(s)"
                    ),
                });
            }
            if duplicate_digests != 0 {
                return Err(MembershipMiss::Inconsistent {
                    detail: format!(
                        "scan {scan_id} derives membership from digests but holds \
                         {duplicate_digests} digest(s) naming two group summaries"
                    ),
                });
            }
        }
        MembershipMode::Unknown => unreachable!("returned above"),
    }

    // 3. Per-rank count agreement, for the whole scan at once. This is the ONE disagreement
    //    the contract keeps reportable rather than fatal: the caller learns which identities
    //    are inconsistent, and every exact answer for them refuses.
    let members_expr = match mode {
        MembershipMode::Explicit => {
            "(SELECT COUNT(*) FROM file_group_member m
               WHERE m.scan_id = g.scan_id AND m.group_rank = g.rank)"
        }
        _ => {
            "(SELECT COUNT(*) FROM file f
               WHERE f.scan_id = g.scan_id AND f.hash = unhex(g.hash))"
        }
    };
    let mut stmt = tx.prepare(&format!(
        "SELECT g.rank FROM file_group g
          WHERE g.scan_id = ?1 AND {members_expr} <> g.file_count
          ORDER BY g.rank"
    ))?;
    let rows = stmt.query_map(params![scan_id], |row| row.get::<_, i64>(0))?;
    let mut inconsistent_ranks = std::collections::BTreeSet::new();
    for row in rows {
        inconsistent_ranks.insert(row?);
    }
    Ok(AuthorityIntegrity { inconsistent_ranks })
}

/// Serializes the witnessed `{rank, digest}` pairs into the ONE JSON array parameter the
/// validation statements bind — the bound-variable count never grows with the plan.
fn witness_wants_json(witness: &PlanWitness) -> String {
    let wants: Vec<serde_json::Value> = witness
        .groups
        .iter()
        .map(|group| serde_json::json!({ "r": group.id.rank, "d": group.digest }))
        .collect();
    serde_json::Value::Array(wants).to_string()
}

impl ScanStore {
    /// One consistent read of a scan's membership: a deferred read transaction is taken and
    /// every answer of the returned snapshot comes from it, so authority and members can never
    /// be read from two different database states. Reads only; fails closed on malformed
    /// authority instead of downgrading it to Unknown.
    ///
    /// Since R4B-2c every trusted membership reader — the browsing actor, the plan builder,
    /// the pipeline's completion listing and the headless output — goes through this snapshot.
    pub fn membership_snapshot(
        &self,
        scan_id: i64,
    ) -> std::result::Result<MembershipSnapshot<'_>, MembershipMiss> {
        use rusqlite::OptionalExtension;
        // Before the token, before the cache, before any membership row: does the path still
        // name the file it named when this store opened it? A replaced checkpoint leaves the
        // previous inode alive behind an already-open descriptor, so answering would be a
        // confident report about a database that is no longer at that path. A mismatch drops the
        // cache AND refuses; only a fresh verified open recovers.
        self.ensure_db_identity()?;
        let tx = self.conn.unchecked_transaction()?;
        // Read inside the transaction, so the token and every row below describe ONE database
        // state rather than a check-then-read pair.
        let data_version: i64 = tx.query_row("PRAGMA data_version", [], |row| row.get(0))?;
        let exists: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM scan WHERE id = ?1)",
            params![scan_id],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Err(MembershipMiss::NoSuchScan);
        }
        let authority: Option<(Value, Value)> = tx
            .query_row(
                "SELECT mode, generation FROM scan_membership WHERE scan_id = ?1",
                params![scan_id],
                |row| Ok((row.get::<_, Value>(0)?, row.get::<_, Value>(1)?)),
            )
            .optional()?;
        let (mode, generation) = match &authority {
            None => (MembershipMode::Unknown, 0),
            Some((mode_value, generation_value)) => decode_authority(mode_value, generation_value)
                .map_err(|detail| MembershipMiss::Inconsistent { detail })?,
        };
        // ONE whole-authority integrity result, shared by every trusted method. Nothing below
        // re-derives a subset of it: a page, a reverse lookup or a membership test that
        // validated only what it happened to read is exactly how corruption outside the read
        // escapes. Recomputed only when this connection's key changed — the transaction itself
        // is always fresh and short, and only the VERDICT is reused.
        let integrity = match self.cached_integrity(scan_id, mode, generation, data_version) {
            Some(cached) => cached?,
            None => {
                // Counted only when there is something to validate: `validate_authority`
                // returns at once for an Unknown authority, so counting that would report work
                // nobody did.
                #[cfg(test)]
                if mode != MembershipMode::Unknown {
                    self.full_validations.set(self.full_validations.get() + 1);
                }
                #[cfg(test)]
                let outcome = match take_validator_fault() {
                    Some(detail) => Err(MembershipMiss::Store { detail }),
                    None => validate_authority(&tx, scan_id, mode, generation),
                };
                #[cfg(not(test))]
                let outcome = validate_authority(&tx, scan_id, mode, generation);
                self.remember_integrity(scan_id, mode, generation, data_version, &outcome);
                outcome?
            }
        };
        Ok(MembershipSnapshot {
            tx,
            scan_id,
            mode,
            generation,
            integrity,
            export_meter: ExportMeter {
                #[cfg(test)]
                now: &self.export_rows_now,
                #[cfg(test)]
                max: &self.export_rows_max,
                #[cfg(not(test))]
                _phantom: std::marker::PhantomData,
            },
        })
    }

    /// The one snapshot `--export-csv` runs from, or a refusal that leaves the operator's
    /// destination alone.
    ///
    /// Two facts are checked, and they are genuinely different things. The authority answers «is
    /// this membership trusted»; the status answers «has the scan finished». Production publishes
    /// the authority first and sets the final status afterwards (`pipeline::run_phases`), so a
    /// reader that took only the authority would export a scan still hashing — and this mode takes
    /// no instance lock, which is exactly why it can be in that window.
    ///
    /// The selection is made in autocommit and RE-MADE inside the snapshot: between the two, the
    /// session can be trashed or a newer one can finish, and answering from the first read would
    /// describe a session nobody asked for.
    pub fn open_trusted_export(&self) -> Result<TrustedExport<'_>> {
        let selected = {
            let tx = self.conn.unchecked_transaction()?;
            newest_active_scan_tx(&tx)?
        };
        let Some((scan_id, _)) = selected else {
            return Err(AppError::msg("no saved scan"));
        };
        // The seam: everything a second writer could do lands exactly here.
        #[cfg(test)]
        take_export_race_hook();
        let snapshot = self.membership_snapshot(scan_id).map_err(|miss| {
            AppError::msg(format!(
                "scan {scan_id} cannot be exported: {}",
                describe_miss(&miss)
            ))
        })?;
        // Re-made under the snapshot's own transaction, so the answer is about ONE state.
        let confirmed = newest_active_scan_tx(&snapshot.tx)?;
        let Some((confirmed_id, status)) = confirmed else {
            return Err(AppError::msg(
                "the selected session was moved to the trash while the export was starting; \
                 nothing was written. Run the export again.",
            ));
        };
        if confirmed_id != scan_id {
            return Err(AppError::msg(format!(
                "the newest active session changed from {scan_id} to {confirmed_id} while the \
                 export was starting; nothing was written. Run the export again."
            )));
        }
        if snapshot.mode() == MembershipMode::Unknown {
            return Err(AppError::msg(format!(
                "scan {scan_id} has no verified membership — it comes from an older version of \
                 dedcom, or it never finished publishing. Re-run the scan to export it; opening \
                 the checkpoint does not republish it. Nothing was written."
            )));
        }
        if !status.is_completed() {
            return Err(AppError::msg(format!(
                "scan {scan_id} has not finished (status: {}); a CSV of a running scan would \
                 describe a result that does not exist yet. Nothing was written.",
                status.as_str()
            )));
        }
        Ok(TrustedExport {
            snapshot,
            scan_id,
            status,
        })
    }

    /// The configured path still names the file this store opened.
    ///
    /// One `stat`-class probe and no SQL. An in-memory store has no path to be replaced and is
    /// exempt. On a mismatch the cached authority verdict is dropped too, but the refusal — not
    /// the drop — is the safety property: this connection must not answer about a database nobody
    /// is looking at any more.
    ///
    /// What it does NOT prove is the same limit `settled_identity` states: this is the identity of
    /// the PATH at the moment of one probe, never of the file SQLite itself holds open.
    ///
    /// Staged by R4B-2a. `membership_snapshot` reaches it through `ensure_db_identity`, and the
    /// new `save_marks_settled` calls it directly; the existing readers keep today's behaviour
    /// until the UI that has to render the refusal switches with them.
    pub fn ensure_current_path(&self) -> Result<()> {
        let Some((path, opened_as)) = self.db_identity.as_ref() else {
            return Ok(());
        };
        #[cfg(test)]
        self.identity_probes.set(self.identity_probes.get() + 1);
        let shown = crate::textsan::terminal(&path.display().to_string());
        let refusal = |detail: String| AppError::PathChanged {
            path: shown.clone(),
            detail,
        };
        match crate::paths::probe_existing_db_file(path) {
            Ok(now) if now == *opened_as => Ok(()),
            Ok(_) => {
                self.revoke_membership_cache();
                Err(refusal(format!(
                    "dedcom.db at {shown} no longer names the file it named when it was opened; reopen required"
                )))
            }
            Err(err) => {
                self.revoke_membership_cache();
                Err(refusal(format!(
                    "dedcom.db at {shown} can no longer be identified: {err}"
                )))
            }
        }
    }

    /// The membership half of the same check: one probe, and the typed refusal every trusted
    /// reader already understands. The sentence is `ensure_current_path`'s, unchanged — nothing
    /// here re-words it, and nothing anywhere decides control flow by reading it.
    fn ensure_db_identity(&self) -> std::result::Result<(), MembershipMiss> {
        self.ensure_current_path()
            .map_err(|err| MembershipMiss::ReopenRequired {
                detail: err.to_string(),
            })
    }

    /// The cached verdict, if it was computed for exactly this key on this connection.
    fn cached_integrity(
        &self,
        scan_id: i64,
        mode: MembershipMode,
        generation: i64,
        data_version: i64,
    ) -> Option<std::result::Result<AuthorityIntegrity, MembershipMiss>> {
        let slot = self.membership_cache.borrow();
        let entry = slot.as_ref()?;
        (entry.scan_id == scan_id
            && entry.mode == mode
            && entry.generation == generation
            && entry.data_version == data_version)
            .then(|| entry.outcome.clone())
    }

    /// Stores a completed verdict. Only two kinds are cacheable: a finished integrity result,
    /// and a deterministic `Inconsistent` — a pure function of the state this key pins. A
    /// transient `Store` failure is a reason to retry, never a verdict, and `Unknown` is the
    /// absence of authority rather than a validation at all (it costs nothing to recompute).
    fn remember_integrity(
        &self,
        scan_id: i64,
        mode: MembershipMode,
        generation: i64,
        data_version: i64,
        outcome: &std::result::Result<AuthorityIntegrity, MembershipMiss>,
    ) {
        let cacheable = match outcome {
            Ok(_) => mode != MembershipMode::Unknown,
            Err(MembershipMiss::Inconsistent { .. }) => true,
            Err(_) => false,
        };
        if !cacheable {
            return;
        }
        *self.membership_cache.borrow_mut() = Some(MembershipCacheEntry {
            scan_id,
            mode,
            generation,
            data_version,
            outcome: outcome.clone(),
        });
    }

    /// Opens the checkpoint for the destructive apply lease — and does nothing else. The path
    /// is verified first (no create, no follow, no chmod); SQLite opens `READ_WRITE` explicitly
    /// WITHOUT `CREATE`; the R4A-C1 foreign-key helper runs with its read-back; this connection
    /// alone gets `busy_timeout=0` (the lease never queues); and the schema must be exactly
    /// current — no migration, no WAL flip, no vacuum, nothing altered merely by opening.
    ///
    /// Since R4B-2c the apply worker's guarded boundary opens through here alone.
    pub fn open_for_apply_lease(db_path: &Path) -> std::result::Result<Self, LeaseRefusal> {
        if is_observer_role() {
            return Err(LeaseRefusal::ReadOnlyRole);
        }
        if let Err(err) = crate::paths::verify_existing_db_file(db_path) {
            return Err(LeaseRefusal::Open {
                detail: err.to_string(),
            });
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = match Connection::open_with_flags(db_path, flags) {
            Ok(conn) => conn,
            Err(err) => {
                return Err(LeaseRefusal::Open {
                    detail: err.to_string(),
                })
            }
        };
        // The R4A-C1 invariant, per connection, proved by read-back (2 statements).
        if let Err(err) = schema::enforce_foreign_keys(&conn) {
            return Err(LeaseRefusal::Open {
                detail: err.to_string(),
            });
        }
        // Fail-fast: the apply lease never queues behind another writer (1 statement).
        if let Err(err) = conn.execute_batch("PRAGMA busy_timeout=0;") {
            return Err(LeaseRefusal::Open {
                detail: err.to_string(),
            });
        }
        // Exactly v5, one PRAGMA read, distinct older/newer refusals (1 statement).
        if let Err(err) = schema::ensure_version_exact(&conn) {
            return Err(LeaseRefusal::Schema {
                detail: err.to_string(),
            });
        }
        let store = Self::new(conn);
        #[cfg(test)]
        store.membership_statements.set(4);
        Ok(store)
    }

    /// Takes the fail-fast whole-batch membership lease: `BEGIN IMMEDIATE` under
    /// `busy_timeout=0`, then the witness is revalidated against the LIVE authority, summaries
    /// and members — in order: scan, authority/generation, per-rank summary digest and count,
    /// exact member sets, mode-specific member source — before anything destructive may start.
    /// There is no wait parameter and no retry: a refused acquisition is the answer, not a
    /// queue. The lease writes nothing and releases by RAII rollback.
    ///
    /// Statement shape (pinned by test): BEGIN + scan existence + authority + one validation
    /// statement (explicit) or two (derived, adding the no-member-rows assertion) + the
    /// ROLLBACK on drop. Each validation statement binds the scan id and ONE JSON array of
    /// `{rank, digest}`; member sets come back one ROW per member and are compared in Rust —
    /// neither statements nor bind variables grow with the plan.
    ///
    /// Since R4B-2c every real batch holds this lease across its whole run.
    pub fn acquire_membership_lease(
        &mut self,
        witness: &PlanWitness,
    ) -> std::result::Result<MembershipLease<'_>, LeaseRefusal> {
        // Witness self-consistency costs no statement and fails closed before the lock.
        if witness.groups.is_empty() {
            return Err(LeaseRefusal::Inconsistent {
                detail: "the witness carries no groups".into(),
            });
        }
        let mut ranks = std::collections::HashSet::new();
        for group in &witness.groups {
            if group.id.scan_id != witness.scan_id {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!(
                        "witnessed rank {} belongs to scan {}, not scan {}",
                        group.id.rank, group.id.scan_id, witness.scan_id
                    ),
                });
            }
            if group.id.generation != witness.generation {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!(
                        "witnessed rank {} carries generation {}, the witness {}",
                        group.id.rank, group.id.generation, witness.generation
                    ),
                });
            }
            if group.id.rank < 0 {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!("witnessed rank {} is negative", group.id.rank),
                });
            }
            if !ranks.insert(group.id.rank) {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!("rank {} is witnessed twice", group.id.rank),
                });
            }
            if group.members.is_empty() {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!("witnessed rank {} carries no members", group.id.rank),
                });
            }
        }

        // Disjoint-field borrows: the meter cell first, the connection second (the same shape
        // `record_hashes_verified` uses).
        #[cfg(test)]
        let statements = &self.membership_statements;
        let meter = LeaseMeter {
            #[cfg(test)]
            cell: statements,
            #[cfg(not(test))]
            _phantom: std::marker::PhantomData,
        };
        let tx = match self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        {
            Ok(tx) => tx,
            Err(err) => return Err(lease_begin_refusal(err)),
        };
        meter.bump(); // BEGIN IMMEDIATE

        validate_lease_witness(&tx, witness, &meter)?;

        Ok(MembershipLease {
            _tx: tx,
            #[cfg(test)]
            statements,
        })
    }

    /// The future single publication path: replaces summaries, membership, authority, the scan
    /// totals and the prepared marker in ONE immediate transaction and returns the generation
    /// it published. The generation starts at 1 and increments checked — an overflow refuses
    /// and the whole transaction rolls back. Derived publishes no member rows; Explicit writes
    /// every surviving group's members against the rank the authoritative reclaim sort
    /// assigned. FK enforcement is ON on every store connection, and the child-before-parent
    /// DELETE order is kept anyway: the active `ON DELETE CASCADE` from `file_group` to
    /// `file_group_member` would empty the member table on its own — that fact is stated here
    /// and pinned by a test rather than silently relied on.
    ///
    /// Since R4B-2c this is the ONLY publication path: the pipeline publishes `Derived` for an
    /// ordinary hash-only completion and `Explicit` from the exact populations `--verify`
    /// returned.
    pub fn publish_results(&mut self, scan_id: i64, mode: PublishMode<'_>) -> Result<i64> {
        use rusqlite::OptionalExtension;
        self.revoke_membership_cache();
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let previous: Option<Value> = tx
            .query_row(
                "SELECT generation FROM scan_membership WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get::<_, Value>(0),
            )
            .optional()?;
        let generation = match previous {
            None => 1,
            Some(Value::Integer(previous)) if previous > 0 => {
                previous.checked_add(1).ok_or_else(|| {
                    AppError::msg(format!(
                        "scan {scan_id} has exhausted its publication generations ({previous}); \
                         republication would overflow"
                    ))
                })?
            }
            Some(other) => {
                return Err(AppError::msg(format!(
                    "scan_membership.generation for scan {scan_id} holds {} — refusing to \
                     publish over corrupt authority",
                    authority_cell(&other)
                )))
            }
        };
        // Children before parents; the summaries after both. The CASCADE would remove the
        // member rows on its own — kept explicit so the delete's meaning stays in the code.
        tx.execute(
            "DELETE FROM file_group_member WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM file_group WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM file_dedup WHERE scan_id = ?1",
            params![scan_id],
        )?;
        let mode_value: i64 = match mode {
            PublishMode::Derived => {
                // The same aggregation, order and refusal the production SQL writer uses.
                refuse_untrustworthy_group_objects(&tx, scan_id)?;
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
                1
            }
            PublishMode::Explicit(groups) => {
                // Figures first, before anything is written, and the same total order the
                // Derived SQL window uses — an allocation nobody can measure stops the whole
                // result, and a group of fewer than two allocations is not a duplicate.
                let mut rows: Vec<(&DuplicateGroup, GroupReclaim)> =
                    Vec::with_capacity(groups.len());
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
                {
                    let mut ins_group = tx.prepare(
                        "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                                object_count, reclaim_state)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    )?;
                    let mut ins_member = tx.prepare(
                        "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                         VALUES (?1, ?2, ?3, ?4)",
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
                        for file in &group.files {
                            let path = file.path.to_string_lossy();
                            ins_member.execute(params![
                                scan_id,
                                rank as i64,
                                &*path,
                                generation
                            ])?;
                            // Test seam: fails right after the FIRST member insert, with parent
                            // and child rows already in the open transaction — the only
                            // position from which a rollback assertion is about a real partial
                            // write.
                            #[cfg(test)]
                            if take_publish_fault() {
                                return Err(AppError::msg("injected publish fault"));
                            }
                        }
                    }
                }
                2
            }
        };
        record_scan_reclaim(&tx, scan_id)?;
        mark_prepared(&tx, scan_id)?;
        tx.execute(
            "INSERT INTO scan_membership(scan_id, mode, generation) VALUES (?1, ?2, ?3)
             ON CONFLICT(scan_id) DO UPDATE SET mode = excluded.mode,
                                                generation = excluded.generation",
            params![scan_id, mode_value, generation],
        )?;
        tx.commit()?;
        Ok(generation)
    }

    /// The future single preparation path: distinguishes a scan the v5 authority already
    /// speaks for from a legacy/migrated one it does not. A scan with NO authority gets
    /// today's browse-only summary preparation (`ensure_materialized`) and deliberately NO
    /// `scan_membership`/`file_group_member` row: a completed v4→v5 checkpoint stays Unknown
    /// and browse-only until a real republish or rescan.
    ///
    /// An authoritative scan is validated by the SAME whole-authority rules every reader
    /// obeys, under one consistent snapshot — not by reading the two authority cells and
    /// calling that validation. A valid scan is left byte-identical; every corruption those
    /// rules name is refused here too, including the per-rank count disagreement, because
    /// «prepared» must not mean «prepared and unusable».
    ///
    /// Since R4B-2c this is the ONLY preparation path: the startup sweep, the pipeline's
    /// walk-less branches and the browsing actor's `Open` all pass through here.
    pub fn prepare_legacy_for_viewing(&mut self, scan_id: i64) -> Result<()> {
        let legacy = {
            let snapshot = self.membership_snapshot(scan_id).map_err(|miss| {
                AppError::msg(format!(
                    "scan {scan_id} cannot be prepared: {}",
                    describe_miss(&miss)
                ))
            })?;
            if snapshot.mode() == MembershipMode::Unknown {
                true
            } else {
                // The one reportable disagreement is fatal for preparation: a browsing surface
                // opened on it would show a group whose every exact answer refuses.
                let summaries = snapshot.summaries().map_err(|miss| {
                    AppError::msg(format!(
                        "scan {scan_id} cannot be prepared: {}",
                        describe_miss(&miss)
                    ))
                })?;
                if let Some(id) = summaries.inconsistent.first() {
                    return Err(AppError::msg(format!(
                        "scan {scan_id} holds a group (rank {}) whose summary and membership \
                         disagree — refusing to prepare corrupt authority",
                        id.rank
                    )));
                }
                false
            }
        };
        if legacy {
            // Browsing summaries only. No authority row, no member row, nothing invented.
            return self.prepare_browse_summaries(scan_id);
        }
        Ok(())
    }
}

/// Why a group's strict plan evidence could not be read.
///
/// Two different things, deliberately not merged: `Membership` is the store's own answer about
/// the authority (unknown, stale, corrupt, unreadable), while `Member` is the evidence
/// constructor refusing one readable row — an unverified digest, an unrecorded link count. The
/// second is already a typed `PlanRefusal` and stays one all the way to the caller: rendering it
/// into a sentence would leave the plan builder with nothing to match on but text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanEvidenceMiss {
    Membership(MembershipMiss),
    Member(PlanRefusal),
}

impl From<MembershipMiss> for PlanEvidenceMiss {
    fn from(miss: MembershipMiss) -> Self {
        PlanEvidenceMiss::Membership(miss)
    }
}

impl From<rusqlite::Error> for PlanEvidenceMiss {
    fn from(err: rusqlite::Error) -> Self {
        PlanEvidenceMiss::Membership(MembershipMiss::from(err))
    }
}

/// One sentence for a typed miss, so a caller that must return `AppError` does not have to
/// invent wording per call site — and so no control flow is ever decided from the text.
fn describe_miss(miss: &MembershipMiss) -> String {
    match miss {
        MembershipMiss::NoSuchScan => "no such scan".into(),
        MembershipMiss::NoSuchGroup => "no such group".into(),
        MembershipMiss::Unknown => "the scan has no membership authority".into(),
        MembershipMiss::Stale { expected, found } => {
            format!("the plan carries generation {expected}, the database {found}")
        }
        MembershipMiss::Inconsistent { detail } => detail.clone(),
        MembershipMiss::ReopenRequired { detail } => detail.clone(),
        MembershipMiss::Store { detail } => detail.clone(),
    }
}

impl MembershipSnapshot<'_> {
    pub fn mode(&self) -> MembershipMode {
        self.mode
    }

    /// The current publication generation — only a scan WITH authority has one.
    ///
    /// Every identity this snapshot hands out already carries the generation, so production
    /// reads it from there; this is the standalone question, kept for the tests that ask it.
    #[cfg(test)]
    pub fn generation(&self) -> Option<i64> {
        (self.mode != MembershipMode::Unknown).then_some(self.generation)
    }

    fn require_authority(&self) -> std::result::Result<(), MembershipMiss> {
        if self.mode == MembershipMode::Unknown {
            return Err(MembershipMiss::Unknown);
        }
        Ok(())
    }

    /// An identity is answerable only when it names this scan's CURRENT publication AND the
    /// central validation found its rank consistent. The rank check is here, in the one gate
    /// every exact answer passes through, rather than in each method.
    fn require_current(&self, id: &GroupId) -> std::result::Result<(), MembershipMiss> {
        self.require_authority()?;
        if id.scan_id != self.scan_id || id.rank < 0 {
            return Err(MembershipMiss::NoSuchGroup);
        }
        if id.generation != self.generation {
            return Err(MembershipMiss::Stale {
                expected: id.generation,
                found: self.generation,
            });
        }
        self.require_consistent(id.rank)
    }

    /// A rank the central validation found inconsistent answers nothing exactly — only
    /// `summaries()` reports it, by identity.
    fn require_consistent(&self, rank: i64) -> std::result::Result<(), MembershipMiss> {
        if self.integrity.inconsistent_ranks.contains(&rank) {
            return Err(MembershipMiss::Inconsistent {
                detail: format!(
                    "group rank {rank} of scan {} declares a member count its membership does \
                     not hold",
                    self.scan_id
                ),
            });
        }
        Ok(())
    }

    /// Every current summary with its identity, plus the identities the central validation
    /// found inconsistent — named, never repaired. The inconsistency verdict is not recomputed
    /// here: it is the same whole-authority result every other method obeys.
    pub fn summaries(&self) -> std::result::Result<MembershipSummaries, MembershipMiss> {
        self.require_authority()?;
        let mut stmt = self.tx.prepare(
            "SELECT rank, hash, file_count, size, reclaim, object_count, reclaim_state
               FROM file_group WHERE scan_id = ?1 ORDER BY rank",
        )?;
        let rows = stmt.query_map(params![self.scan_id], |row| {
            Ok((
                GroupSummary {
                    rank: row.get(0)?,
                    hash: row.get(1)?,
                    // The domains were validated centrally, so these conversions cannot turn a
                    // negative cell into a plausible huge count.
                    file_count: row.get::<_, i64>(2)? as u64,
                    size_bytes: row.get::<_, i64>(3)? as u64,
                    object_count: row.get::<_, i64>(5)? as u64,
                    reclaim: ReclaimEstimate::unknown(),
                },
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut groups = Vec::new();
        let mut inconsistent = Vec::new();
        for row in rows {
            let (mut summary, reclaim, state) = row?;
            summary.reclaim = ReclaimEstimate::from_persisted(reclaim, state).map_err(|err| {
                MembershipMiss::Inconsistent {
                    detail: err.to_string(),
                }
            })?;
            let id = GroupId {
                scan_id: self.scan_id,
                rank: summary.rank,
                generation: self.generation,
            };
            if self.integrity.inconsistent_ranks.contains(&summary.rank) {
                inconsistent.push(id);
            }
            groups.push((id, summary));
        }
        Ok(MembershipSummaries {
            mode: self.mode,
            generation: self.generation,
            groups,
            inconsistent,
        })
    }

    /// Streams the whole publication in `(rank, path)` order, handing the sink ONE group at a
    /// time and dropping it before the next begins.
    ///
    /// This is what makes `--export-csv` bounded: the peak is the largest group's members, not
    /// the scan's. `summaries()` is deliberately not used — it would materialise every identity
    /// of the publication for an answer this reader already carries per row.
    ///
    /// Strict on both things a report can get quietly wrong: a link count of an impossible
    /// storage class and a mark that does not decode both refuse the whole export. Skipping the
    /// row instead would publish a file that silently omits it, and skipping the group would
    /// publish one that silently under-reports.
    pub fn for_each_export_group(
        &self,
        mut sink: impl FnMut(&ExportGroup) -> Result<()>,
    ) -> Result<ExportTotals> {
        self.require_authority()
            .map_err(|miss| AppError::msg(describe_miss(&miss)))?;
        if let Some(rank) = self.integrity.inconsistent_ranks.iter().next() {
            return Err(AppError::msg(format!(
                "group rank {rank} of scan {} declares a member count its membership does not \
                 hold; the export refuses rather than writing a file that omits it. Nothing was \
                 written.",
                self.scan_id
            )));
        }
        // Whatever happens below — a corrupt cell, a sink error, an unwind — the live-buffer
        // meter must not be left holding a group that no longer exists.
        let _meter = MeterScope(&self.export_meter);
        let mut stmt = self.tx.prepare(export_rows_sql(self.mode))?;
        let mut rows = stmt.query(params![self.scan_id])?;
        let mut totals = ExportTotals::default();
        let mut current: Option<ExportGroup> = None;
        while let Some(row) = rows.next()? {
            let rank: i64 = row.get(0)?;
            if current.as_ref().is_some_and(|group| group.id.rank != rank) {
                let group = current.take().expect("checked above");
                totals.groups += 1;
                totals.rows += group.members.len() as u64;
                sink(&group)?;
                drop(group);
                self.export_meter.release();
            }
            let path = PathBuf::from(row.get::<_, String>(3)?);
            if path.as_os_str().is_empty() {
                return Err(AppError::msg(format!(
                    "scan {} holds a manifest row with an empty pathname in group rank {rank}; \
                     the export refuses rather than naming nothing. Nothing was written.",
                    self.scan_id
                )));
            }
            let nlink = row.get::<_, Value>(9)?;
            let is_keeper = row.get::<_, Value>(10)?;
            let action = row.get::<_, Value>(11)?;
            let present = row.get::<_, Option<i64>>(12)?.is_some();
            let mark = decode_mark(&path, present, &is_keeper, &action).map_err(|err| {
                AppError::msg(format!(
                    "{err}; the export refuses rather than guessing what the operator meant. \
                     Nothing was written."
                ))
            })?;
            // The size the artifact prints is the published summary's, checked against the
            // member's own cell: one of them being damaged is a disagreement worth refusing, not
            // a number to pick between.
            let summary_size =
                nonnegative_cell(&row.get::<_, Value>(2)?, "file_group.size", &path)?;
            let member_size = nonnegative_cell(&row.get::<_, Value>(4)?, "file.size", &path)?;
            if summary_size != member_size {
                return Err(AppError::msg(format!(
                    "{} is {member_size} bytes while its group declares {summary_size}; the \
                     export refuses a physical report its own authority contradicts. Nothing was \
                     written.",
                    crate::textsan::terminal(&path.display().to_string())
                )));
            }
            let member = ExportMember {
                size: summary_size,
                mtime: row.get::<_, i64>(5)?,
                mtime_nsec: nanoseconds_cell(&row.get::<_, Value>(6)?, &path)?,
                device: nonnegative_cell(&row.get::<_, Value>(7)?, "file.device", &path)?,
                inode: nonnegative_cell(&row.get::<_, Value>(8)?, "file.inode", &path)?,
                links: link_count_from_sql(&nlink)?.to_u64(),
                path,
                mark,
            };
            let hash: String = row.get(1)?;
            let group = current.get_or_insert_with(|| ExportGroup {
                id: GroupId {
                    scan_id: self.scan_id,
                    rank,
                    generation: self.generation,
                },
                hash,
                members: Vec::new(),
            });
            group.members.push(member);
            self.export_meter.push();
        }
        if let Some(group) = current.take() {
            totals.groups += 1;
            totals.rows += group.members.len() as u64;
            sink(&group)?;
            drop(group);
            self.export_meter.release();
        }
        Ok(totals)
    }

    /// The exact group — trusted membership only, never a raw-digest fallback.
    pub fn group(&self, id: &GroupId) -> std::result::Result<ResolvedGroup, MembershipMiss> {
        self.resolve(id, None)
    }

    /// A stable page of the exact group's members: same order, same trust, same refusals.
    pub fn group_page(
        &self,
        id: &GroupId,
        offset: usize,
        limit: usize,
    ) -> std::result::Result<ResolvedGroup, MembershipMiss> {
        self.resolve(id, Some((offset, limit)))
    }

    /// The exact group's live member count.
    pub fn group_member_count(&self, id: &GroupId) -> std::result::Result<u64, MembershipMiss> {
        self.require_current(id)?;
        let count: i64 = match self.mode {
            MembershipMode::Explicit => self.tx.query_row(
                "SELECT COUNT(*) FROM file_group_member
                  WHERE scan_id = ?1 AND group_rank = ?2",
                params![id.scan_id, id.rank],
                |row| row.get(0),
            )?,
            _ => self.tx.query_row(
                "SELECT COUNT(*) FROM file f
                   JOIN file_group g ON g.scan_id = f.scan_id AND g.rank = ?2
                  WHERE f.scan_id = ?1 AND f.hash = unhex(g.hash)",
                params![id.scan_id, id.rank],
                |row| row.get(0),
            )?,
        };
        Ok(count as u64)
    }

    /// Every current group identity carrying this digest, in rank order. Two explicit ranks
    /// may legitimately share one digest — that is exactly R4-V1's split populations.
    ///
    /// No production route asks a digest for identities any more: the UI holds identities and
    /// the plan resolves pathnames. It stays as the proof that a digest CANNOT silently pick
    /// one of two ranks, which its tests assert.
    #[cfg(test)]
    ///
    /// Every returned rank passes the same consistency gate the exact answers pass. An
    /// inconsistent rank refuses the whole lookup rather than being filtered out of it:
    /// filtering would turn corruption into a smaller answer that looks entirely valid.
    pub fn groups_of_digest(
        &self,
        digest: &str,
    ) -> std::result::Result<Vec<GroupId>, MembershipMiss> {
        self.require_authority()?;
        let mut stmt = self.tx.prepare(
            "SELECT rank FROM file_group WHERE scan_id = ?1 AND hash = ?2 ORDER BY rank",
        )?;
        let rows = stmt.query_map(params![self.scan_id, digest], |row| row.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let rank = row?;
            self.require_consistent(rank)?;
            out.push(GroupId {
                scan_id: self.scan_id,
                rank,
                generation: self.generation,
            });
        }
        Ok(out)
    }

    /// Which group holds this exact pathname, if any.
    pub fn group_of_path(
        &self,
        path: &Path,
    ) -> std::result::Result<Option<GroupId>, MembershipMiss> {
        use rusqlite::OptionalExtension;
        self.require_authority()?;
        let text = path.to_string_lossy();
        match self.mode {
            MembershipMode::Explicit => {
                // Generation, manifest presence and summary existence were settled centrally
                // for every member of the scan; what remains is this rank's own consistency,
                // which no identity may escape.
                let rank: Option<i64> = self
                    .tx
                    .query_row(
                        "SELECT group_rank FROM file_group_member
                          WHERE scan_id = ?1 AND path = ?2",
                        params![self.scan_id, &*text],
                        |row| row.get(0),
                    )
                    .optional()?;
                match rank {
                    None => Ok(None),
                    Some(rank) => {
                        self.require_consistent(rank)?;
                        Ok(Some(GroupId {
                            scan_id: self.scan_id,
                            rank,
                            generation: self.generation,
                        }))
                    }
                }
            }
            _ => {
                let mut stmt = self.tx.prepare(
                    "SELECT g.rank
                       FROM file f
                       JOIN file_group g ON g.scan_id = f.scan_id
                                        AND g.hash = lower(hex(f.hash))
                      WHERE f.scan_id = ?1 AND f.path = ?2
                      ORDER BY g.rank LIMIT 2",
                )?;
                let rows =
                    stmt.query_map(params![self.scan_id, &*text], |row| row.get::<_, i64>(0))?;
                let ranks: Vec<i64> = rows.collect::<rusqlite::Result<_>>()?;
                match ranks.as_slice() {
                    [] => Ok(None),
                    [rank] => {
                        self.require_consistent(*rank)?;
                        Ok(Some(GroupId {
                            scan_id: self.scan_id,
                            rank: *rank,
                            generation: self.generation,
                        }))
                    }
                    _ => Err(MembershipMiss::Inconsistent {
                        detail: format!(
                            "one digest resolves {} to two ranks under derived authority",
                            crate::textsan::terminal(&text)
                        ),
                    }),
                }
            }
        }
    }

    /// The membership test for one exact identity and pathname.
    ///
    /// Production asks the question the other way round — «which group holds this pathname» —
    /// through `group_of_path` and `file_info`; this is the direct test, kept for the tests.
    #[cfg(test)]
    pub fn is_member(
        &self,
        id: &GroupId,
        path: &Path,
    ) -> std::result::Result<bool, MembershipMiss> {
        self.require_current(id)?;
        let text = path.to_string_lossy();
        let exists: i64 = match self.mode {
            MembershipMode::Explicit => self.tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM file_group_member
                                WHERE scan_id = ?1 AND group_rank = ?2 AND path = ?3)",
                params![id.scan_id, id.rank, &*text],
                |row| row.get(0),
            )?,
            _ => self.tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM file_group g
                                 JOIN file f ON f.scan_id = g.scan_id
                                            AND f.hash = unhex(g.hash)
                                            AND f.path = ?3
                                WHERE g.scan_id = ?1 AND g.rank = ?2)",
                params![id.scan_id, id.rank, &*text],
                |row| row.get(0),
            )?,
        };
        Ok(exists != 0)
    }

    // ----- the rest of one browsing payload, from this same transaction -----
    //
    // R4B-2c1: an `Open` used to read its membership under a snapshot and then take its config,
    // status, summary, creation time, marked count and directory summaries through separate
    // autocommit calls. A second writer — including a `--force` operator — could republish or
    // change marks between them, and the payload then carried old `GroupId`s beside new totals:
    // its first group request refused the very identity the UI had just installed. These read
    // inside the snapshot's own transaction, so the whole payload describes one database state.

    /// The scan's configuration, as this snapshot sees it.
    pub fn scan_config(&self) -> Result<ScanConfig> {
        scan_config_tx(&self.tx, self.scan_id)
    }

    /// The scan's status, as this snapshot sees it.
    pub fn scan_status(&self) -> Result<ScanStatus> {
        scan_status_tx(&self.tx, self.scan_id)
    }

    /// The scan's summary — counters, reclaim total, alias sets and omission account — all from
    /// this snapshot.
    pub fn scan_summary(&self) -> Result<ScanSummary> {
        scan_summary_tx(&self.tx, self.scan_id)
    }

    /// The scan's creation time, as this snapshot sees it.
    pub fn scan_created_at(&self) -> Result<Option<String>> {
        scan_created_at_tx(&self.tx, self.scan_id)
    }

    /// How many pathnames of this scan are marked for an action, as this snapshot sees it.
    pub fn marked_count(&self) -> Result<u64> {
        marked_count_tx(&self.tx, self.scan_id)
    }

    /// The attributed twin-directory summaries, revalidated against the ledger THIS snapshot
    /// holds rather than against whatever the ledger says by the time the payload is assembled.
    pub fn attributed_dir_group_summaries(&self) -> Result<AttributedDirGroupSummaries> {
        attributed_dir_group_summaries_tx(&self.tx, self.scan_id)
    }

    /// The Unknown scan's browse-only raw-digest candidates. `Ok(None)` when the scan HAS
    /// authority — a trusted scan is answered by the trusted API, and this view deliberately
    /// offers nothing a destructive gate could accept.
    pub fn unknown_candidates(&self) -> std::result::Result<Option<CandidateView>, MembershipMiss> {
        if self.mode != MembershipMode::Unknown {
            return Ok(None);
        }
        // The same object rule every candidate reader applies: a digest counts only when at
        // least two DISTINCT allocations carry it.
        let mut stmt = self.tx.prepare(&format!(
            "SELECT lower(hex(digest)) AS digest_hex, SUM(observed)
               FROM ({objects})
              GROUP BY digest HAVING COUNT(*) >= 2
              ORDER BY digest_hex",
            objects = group_objects_sql()
        ))?;
        let rows = stmt.query_map(params![self.scan_id], |row| {
            Ok(DigestCandidate {
                digest: row.get(0)?,
                paths: row.get::<_, i64>(1)? as u64,
            })
        })?;
        let mut candidates = Vec::new();
        for row in rows {
            candidates.push(row?);
        }
        Ok(Some(CandidateView { candidates }))
    }

    // -----------------------------------------------------------------------------------------
    // R4B-2a — the readers the future browsing actor uses.
    //
    // Every one of them answers from the transaction this snapshot already owns. None opens a
    // second transaction, and none takes a second identity probe: the one probe was spent when
    // the snapshot was created, which is what makes «one probe per operation» true rather than
    // aspirational.
    // -----------------------------------------------------------------------------------------

    /// What a group is worth and what evidence stands behind it — keyed by IDENTITY.
    ///
    /// The digest-keyed reader it replaces cannot tell two Explicit ranks sharing one digest
    /// apart, so it would answer for whichever the index happened to reach first.
    /// No production route reads it yet: both windows assemble the open group's claim from
    /// the `ResolvedGroup` summary (P0 §4 G3), so the identity-keyed claim reader stays
    /// test-covered until a view needs the link evidence beside the reclaim figure.
    #[allow(dead_code)]
    pub fn group_claim(&self, id: &GroupId) -> std::result::Result<GroupClaim, MembershipMiss> {
        use rusqlite::OptionalExtension;
        self.require_current(id)?;
        let persisted: Option<(i64, i64)> = self
            .tx
            .query_row(
                "SELECT reclaim, reclaim_state FROM file_group WHERE scan_id = ?1 AND rank = ?2",
                params![id.scan_id, id.rank],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (reclaim, state) = persisted.ok_or(MembershipMiss::NoSuchGroup)?;
        let reclaim = ReclaimEstimate::from_persisted(reclaim, state).map_err(|err| {
            MembershipMiss::Inconsistent {
                detail: err.to_string(),
            }
        })?;
        Ok(GroupClaim {
            reclaim,
            links: self.group_links_of(id)?,
        })
    }

    /// One validated link count per distinct allocation of THIS group's members, summed.
    fn group_links_of(&self, id: &GroupId) -> std::result::Result<GroupLinks, MembershipMiss> {
        let mut stmt = self.tx.prepare(&format!(
            "SELECT COUNT(*), MIN(f.nlink), COUNT(DISTINCT f.nlink),
                    MIN(typeof(f.nlink)), MAX(typeof(f.nlink)), MIN(f.path)
               FROM {source}
              WHERE {filter}
              GROUP BY {OBJECT_KEY_F}",
            source = self.member_source(),
            filter = self.member_filter(),
        ))?;
        let rows = stmt.query_map(params![id.scan_id, id.rank], |row| {
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
            let decoded =
                evidence
                    .decode(&representative)
                    .map_err(|err| MembershipMiss::Inconsistent {
                        detail: err.to_string(),
                    })?;
            total = match (total, decoded) {
                (Some(sum), LinkCount::Known(links)) => sum.checked_add(links),
                _ => None,
            };
        }
        Ok(GroupLinks {
            observed,
            total: total.map_or(LinkCount::Unknown, LinkCount::from_u64),
        })
    }

    /// The member relation for this authority: Explicit reads its own rows, Derived reads the
    /// manifest by the CURRENT summary's digest. There is no third form, and no raw-digest
    /// fallback under Explicit.
    fn member_source(&self) -> &'static str {
        match self.mode {
            MembershipMode::Explicit => {
                "file_group_member mm JOIN file f ON f.scan_id = mm.scan_id AND f.path = mm.path"
            }
            _ => "file_group g JOIN file f ON f.scan_id = g.scan_id AND f.hash = unhex(g.hash)",
        }
    }

    fn member_filter(&self) -> &'static str {
        match self.mode {
            MembershipMode::Explicit => "mm.scan_id = ?1 AND mm.group_rank = ?2",
            _ => "g.scan_id = ?1 AND g.rank = ?2",
        }
    }

    /// The member pathnames of one group, in member order, optionally capped.
    fn member_paths(
        &self,
        id: &GroupId,
        limit: Option<usize>,
    ) -> std::result::Result<Vec<PathBuf>, MembershipMiss> {
        let mut stmt = self.tx.prepare(&format!(
            "SELECT f.path FROM {source} WHERE {filter} ORDER BY f.path LIMIT ?3",
            source = self.member_source(),
            filter = self.member_filter(),
        ))?;
        // SQLite reads a negative limit as «no limit».
        let cap = limit.map_or(-1i64, |n| n as i64);
        let rows = stmt.query_map(params![id.scan_id, id.rank, cap], |row| {
            Ok(PathBuf::from(row.get::<_, String>(0)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Every persisted member of one group, as the destructive plan is allowed to read it.
    ///
    /// Strict where browsing is not: `group_page` tolerates a link count of an impossible storage
    /// class because a group whose counts cannot be trusted is still worth showing, while a plan
    /// built on one is not. The evidence constructor is the trust boundary and it refuses here.
    pub fn plan_members(
        &self,
        id: &GroupId,
    ) -> std::result::Result<Vec<PlanMemberEvidence>, PlanEvidenceMiss> {
        self.require_current(id)?;
        let inconsistent = |err: String| {
            PlanEvidenceMiss::Membership(MembershipMiss::Inconsistent { detail: err })
        };
        let mut stmt = self.tx.prepare(&format!(
            "SELECT f.path, f.size, f.mtime, f.mtime_nsec, f.ctime_sec, f.ctime_nsec,
                    f.device, f.inode, f.nlink, f.identity_version,
                    m.is_keeper, m.action, m.rowid
               FROM {source}
               LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
              WHERE {filter}
              ORDER BY f.path",
            source = self.member_source(),
            filter = self.member_filter(),
        ))?;
        let rows = stmt.query_map(params![id.scan_id, id.rank], |row| {
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
        })?;
        let mut members = Vec::new();
        for row in rows {
            let (path, key, nlink, is_keeper, action, marked) = row?;
            let links = link_count_from_sql(&nlink).map_err(|err| inconsistent(err.to_string()))?;
            let mark = decode_mark(&path, marked, &is_keeper, &action)
                .map_err(|err| inconsistent(err.to_string()))?;
            // The constructor's own refusal travels as itself: «this pathname carries a digest
            // this build never verified» is a plan refusal about a readable row, not a corrupt
            // store, and the plan builder returns it unchanged.
            members.push(
                PlanMemberEvidence::new(path, key, links, mark)
                    .map_err(PlanEvidenceMiss::Member)?,
            );
        }
        Ok(members)
    }

    /// The witness a future plan hands to the apply lease: for each identity, the digest its
    /// CURRENT summary carries and the exact member pathnames.
    ///
    /// The digest is read here rather than remembered by the caller, so the lease compares what
    /// the plan was folded from against what the database says now.
    pub fn witness_of(&self, ids: &[GroupId]) -> std::result::Result<PlanWitness, MembershipMiss> {
        use rusqlite::OptionalExtension;
        // An empty list must not produce a witness for a scan with no authority.
        self.require_authority()?;
        let mut groups = Vec::with_capacity(ids.len());
        for id in ids {
            self.require_current(id)?;
            let digest: Option<String> = self
                .tx
                .query_row(
                    "SELECT hash FROM file_group WHERE scan_id = ?1 AND rank = ?2",
                    params![id.scan_id, id.rank],
                    |row| row.get(0),
                )
                .optional()?;
            groups.push(GroupWitness {
                id: *id,
                digest: digest.ok_or(MembershipMiss::NoSuchGroup)?,
                members: self.member_paths(id, None)?,
            });
        }
        Ok(PlanWitness {
            scan_id: self.scan_id,
            generation: self.generation,
            groups,
        })
    }

    /// Dedup evidence for a whole panel of pathnames, in a bounded number of statements.
    ///
    /// Three statements regardless of how many pathnames are asked for — the batch travels as one
    /// JSON array, the same way the lease binds its witness — against the point lookup per
    /// pathname the current reader spends. The membership half needs authority; the size/mtime
    /// half is a candidate signal about rows that were never hashed and needs none, which is why
    /// an Unknown scan still renders something instead of nothing.
    pub fn panel_files(
        &self,
        paths: &[&Path],
    ) -> std::result::Result<HashMap<PathBuf, PanelFile>, MembershipMiss> {
        let want = serde_json::Value::Array(
            paths
                .iter()
                .map(|path| serde_json::Value::String(path.to_string_lossy().into_owned()))
                .collect(),
        )
        .to_string();
        let mut out: HashMap<PathBuf, PanelFile> = HashMap::with_capacity(paths.len());

        // 1. The manifest half: is the pathname in the scan at all, and does its row carry a
        //    digest yet. `f.rowid` is the row-presence bit — a LEFT JOIN renders «no row» and
        //    «row with NULL columns» identically without it.
        {
            // `hex(NULL)` is the empty string in SQLite, not NULL — so «no digest» has to be
            // asked for explicitly, or an unhashed row would carry a digest of «».
            let mut stmt = self.tx.prepare(
                "WITH want(path) AS (SELECT value FROM json_each(?2))
                 SELECT want.path, f.rowid IS NOT NULL,
                        CASE WHEN f.hash IS NULL THEN NULL ELSE lower(hex(f.hash)) END
                   FROM want
                   LEFT JOIN file f ON f.scan_id = ?1 AND f.path = want.path",
            )?;
            let rows = stmt.query_map(params![self.scan_id, &want], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?;
            for row in rows {
                let (path, present, hash_text) = row?;
                let status = match (present, hash_text.is_some(), self.mode) {
                    (false, _, _) => PanelFileStatus::NotInScan,
                    (true, false, _) => PanelFileStatus::NotHashed,
                    // Hashed, but nothing may vouch for a group: browse-only.
                    (true, true, MembershipMode::Unknown) => {
                        PanelFileStatus::Unavailable(PanelMiss::Unknown)
                    }
                    // Hashed and under authority: a member until statement 2 says otherwise.
                    (true, true, _) => PanelFileStatus::NotGrouped,
                };
                out.insert(PathBuf::from(path), PanelFile { status, hash_text });
            }
        }

        // 2. The membership half. `COUNT(DISTINCT …)` cannot be a window function in SQLite, so
        //    the per-rank aggregate is a grouped subquery joined back — one statement either way,
        //    and the bind count does not grow with the batch.
        if self.mode != MembershipMode::Unknown {
            let sql = match self.mode {
                MembershipMode::Explicit => {
                    "WITH want(path) AS (SELECT value FROM json_each(?2)),
                          hit(path, rank) AS (
                              SELECT want.path, mm.group_rank
                                FROM want
                                JOIN file_group_member mm
                                  ON mm.scan_id = ?1 AND mm.path = want.path),
                          agg(rank, members, devices) AS (
                              SELECT mm.group_rank, COUNT(*), COUNT(DISTINCT f.device)
                                FROM file_group_member mm
                                JOIN file f ON f.scan_id = mm.scan_id AND f.path = mm.path
                               WHERE mm.scan_id = ?1
                                 AND mm.group_rank IN (SELECT rank FROM hit)
                               GROUP BY mm.group_rank)
                     SELECT hit.path, hit.rank, agg.members, agg.devices
                       FROM hit JOIN agg ON agg.rank = hit.rank"
                }
                _ => {
                    "WITH want(path) AS (SELECT value FROM json_each(?2)),
                          hit(path, rank) AS (
                              SELECT want.path, g.rank
                                FROM want
                                JOIN file f
                                  ON f.scan_id = ?1 AND f.path = want.path
                                 AND f.hash IS NOT NULL
                                JOIN file_group g
                                  ON g.scan_id = ?1 AND g.hash = lower(hex(f.hash))),
                          agg(rank, members, devices) AS (
                              SELECT g.rank, COUNT(*), COUNT(DISTINCT f.device)
                                FROM file_group g
                                JOIN file f ON f.scan_id = g.scan_id AND f.hash = unhex(g.hash)
                               WHERE g.scan_id = ?1 AND g.rank IN (SELECT rank FROM hit)
                               GROUP BY g.rank)
                     SELECT hit.path, hit.rank, agg.members, agg.devices
                       FROM hit JOIN agg ON agg.rank = hit.rank"
                }
            };
            let mut stmt = self.tx.prepare(sql)?;
            let rows = stmt.query_map(params![self.scan_id, &want], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                ))
            })?;
            for row in rows {
                let (path, rank, members, distinct_devices) = row?;
                // A rank the central validation named inconsistent has no exact identity to
                // hand out. The row says so and takes no part in cross-panel matching.
                let status = if self.integrity.inconsistent_ranks.contains(&rank) {
                    PanelFileStatus::Unavailable(PanelMiss::Inconsistent {
                        detail: format!(
                            "group rank {rank} of scan {} declares a member count its membership \
                             does not hold",
                            self.scan_id
                        ),
                    })
                } else {
                    PanelFileStatus::InGroup {
                        id: GroupId {
                            scan_id: self.scan_id,
                            rank,
                            generation: self.generation,
                        },
                        members,
                        distinct_devices,
                    }
                };
                if let Some(entry) = out.get_mut(Path::new(&path)) {
                    entry.status = status;
                }
            }
        }

        // 3. The candidate half: an unhashed row whose size and mtime another row shares is a
        //    likely duplicate the scan has not proved yet. Nothing here claims membership.
        {
            let mut stmt = self.tx.prepare(
                "WITH want(path) AS (SELECT value FROM json_each(?2)),
                      un(path, size, mtime) AS (
                          SELECT want.path, f.size, f.mtime
                            FROM want
                            JOIN file f ON f.scan_id = ?1 AND f.path = want.path
                           WHERE f.hash IS NULL)
                 SELECT un.path,
                        (SELECT COUNT(*) FROM file p
                          WHERE p.scan_id = ?1 AND p.size = un.size AND p.mtime = un.mtime)
                   FROM un",
            )?;
            let rows = stmt.query_map(params![self.scan_id, &want], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                let (path, peers) = row?;
                if peers < 2 {
                    continue;
                }
                if let Some(entry) = out.get_mut(Path::new(&path)) {
                    entry.status = PanelFileStatus::LikelyBySizeMtime { peers };
                }
            }
        }
        Ok(out)
    }

    /// What the directory watch surface can say about `dir`, as one value.
    ///
    /// The inner-duplicates fallback is derived through THIS authority. The reader it replaces
    /// selected manifest rows whose digest appears anywhere in `file_group` and never consulted
    /// `file_group_member`, so under Explicit authority it returned pathnames byte verification
    /// had rejected — the exact defect this work exists to remove.
    pub fn dir_group_at(&self, dir: &Path) -> std::result::Result<DirGroupAnswer, MembershipMiss> {
        let store = |err: AppError| MembershipMiss::Store {
            detail: err.to_string(),
        };
        // The attributed ledger answer first, on this same transaction — so the directory
        // decision and the membership decision cannot come from two database states.
        if let Some(group) =
            attributed_dir_group_at_tx(&self.tx, self.scan_id, dir).map_err(store)?
        {
            return Ok(DirGroupAnswer::Group(Box::new(group)));
        }
        let (lo, hi) = prefix_bounds(dir);
        let cap = (DIR_INNER_CAP + 1) as i64;

        if self.mode == MembershipMode::Unknown {
            // No authority: raw-digest candidates, and they are never called duplicates. The
            // object rule is the same one every candidate reader applies — a digest counts only
            // when at least two DISTINCT allocations carry it.
            let listing = format!(
                "SELECT path FROM file
                  WHERE scan_id = ?1 AND path >= ?2 AND path < ?3 AND hash IS NOT NULL
                    AND hash IN (SELECT digest FROM ({objects})
                                  GROUP BY digest HAVING COUNT(*) >= 2)
                  ORDER BY path LIMIT ?4",
                objects = group_objects_sql()
            );
            let mut stmt = self.tx.prepare(&listing)?;
            let rows = stmt.query_map(params![self.scan_id, &lo, &hi, cap], |row| {
                Ok(PathBuf::from(row.get::<_, String>(0)?))
            })?;
            let mut paths = Vec::new();
            for row in rows {
                paths.push(row?);
            }
            if paths.is_empty() {
                return self.dir_absence(dir, &lo, &hi);
            }
            let total: i64 = self.tx.query_row(
                &format!(
                    "SELECT COUNT(*) FROM file
                      WHERE scan_id = ?1 AND path >= ?2 AND path < ?3 AND hash IS NOT NULL
                        AND hash IN (SELECT digest FROM ({objects})
                                      GROUP BY digest HAVING COUNT(*) >= 2)",
                    objects = group_objects_sql()
                ),
                params![self.scan_id, &lo, &hi],
                |row| row.get(0),
            )?;
            paths.truncate(DIR_INNER_CAP);
            let total = total as u64;
            return Ok(DirGroupAnswer::InnerCandidates {
                truncated: total > paths.len() as u64,
                total,
                paths,
            });
        }

        let (ranks_sql, listing, counting) = match self.mode {
            MembershipMode::Explicit => (
                "SELECT DISTINCT mm.group_rank FROM file_group_member mm
                  WHERE mm.scan_id = ?1 AND mm.path >= ?2 AND mm.path < ?3",
                "SELECT mm.path, mm.group_rank FROM file_group_member mm
                  WHERE mm.scan_id = ?1 AND mm.path >= ?2 AND mm.path < ?3
                  ORDER BY mm.path LIMIT ?4",
                "SELECT COUNT(*) FROM file_group_member mm
                  WHERE mm.scan_id = ?1 AND mm.path >= ?2 AND mm.path < ?3",
            ),
            _ => (
                "SELECT DISTINCT g.rank FROM file f
                   JOIN file_group g ON g.scan_id = f.scan_id AND g.hash = lower(hex(f.hash))
                  WHERE f.scan_id = ?1 AND f.hash IS NOT NULL
                    AND f.path >= ?2 AND f.path < ?3",
                "SELECT f.path, g.rank FROM file f
                   JOIN file_group g ON g.scan_id = f.scan_id AND g.hash = lower(hex(f.hash))
                  WHERE f.scan_id = ?1 AND f.hash IS NOT NULL
                    AND f.path >= ?2 AND f.path < ?3
                  ORDER BY f.path LIMIT ?4",
                "SELECT COUNT(*) FROM file f
                   JOIN file_group g ON g.scan_id = f.scan_id AND g.hash = lower(hex(f.hash))
                  WHERE f.scan_id = ?1 AND f.hash IS NOT NULL
                    AND f.path >= ?2 AND f.path < ?3",
            ),
        };

        // The integrity gate runs over every DISTINCT rank represented anywhere under the
        // prefix, BEFORE a single member is built — never over the capped page. Judging only the
        // rows the display happens to show would let a corrupt group that sorts past the cap be
        // counted in the exact total and never checked, and the answer would come back trusted
        // and merely shorter. It is a separate statement rather than a wider listing because the
        // fix must not materialise every pathname of the directory to find its groups.
        {
            let mut stmt = self.tx.prepare(ranks_sql)?;
            let rows =
                stmt.query_map(params![self.scan_id, &lo, &hi], |row| row.get::<_, i64>(0))?;
            let mut any = false;
            for row in rows {
                any = true;
                // One inconsistent rank refuses the WHOLE lookup. Filtering it out, or
                // decrementing the total, would turn corruption into a list that looks valid.
                self.require_consistent(row?)?;
            }
            if !any {
                return self.dir_absence(dir, &lo, &hi);
            }
        }

        let mut stmt = self.tx.prepare(listing)?;
        let rows = stmt.query_map(params![self.scan_id, &lo, &hi, cap], |row| {
            Ok((
                PathBuf::from(row.get::<_, String>(0)?),
                row.get::<_, i64>(1)?,
            ))
        })?;
        let mut members = Vec::new();
        for row in rows {
            let (path, rank) = row?;
            members.push(InnerDupe {
                path,
                id: GroupId {
                    scan_id: self.scan_id,
                    rank,
                    generation: self.generation,
                },
            });
        }
        let total: i64 = self
            .tx
            .query_row(counting, params![self.scan_id, &lo, &hi], |row| row.get(0))?;
        members.truncate(DIR_INNER_CAP);
        let total = total as u64;
        Ok(DirGroupAnswer::InnerDupes {
            truncated: total > members.len() as u64,
            total,
            members,
        })
    }

    /// Nothing duplicated under `dir` — but is the directory covered by the scan at all? The two
    /// answers are different advice to the operator and must not share one rendering.
    fn dir_absence(
        &self,
        dir: &Path,
        lo: &str,
        hi: &str,
    ) -> std::result::Result<DirGroupAnswer, MembershipMiss> {
        use rusqlite::OptionalExtension;
        let text = dir.to_string_lossy();
        let exact: Option<i64> = self
            .tx
            .query_row(
                "SELECT 1 FROM file WHERE scan_id = ?1 AND path = ?2 LIMIT 1",
                params![self.scan_id, &*text],
                |row| row.get(0),
            )
            .optional()?;
        if exact.is_some() {
            return Ok(DirGroupAnswer::NoDuplicates);
        }
        let under: Option<i64> = self
            .tx
            .query_row(
                "SELECT 1 FROM file WHERE scan_id = ?1 AND path >= ?2 AND path < ?3 LIMIT 1",
                params![self.scan_id, lo, hi],
                |row| row.get(0),
            )
            .optional()?;
        Ok(if under.is_some() {
            DirGroupAnswer::NoDuplicates
        } else {
            DirGroupAnswer::NotInScan
        })
    }

    /// Everything the file-info surface needs about one pathname, from this one snapshot.
    ///
    /// Manifest presence is established positively and is the OUTER decision, so «no duplicates
    /// found» cannot be printed for a pathname the scan never saw, nor for one whose membership
    /// could not be read.
    pub fn file_info(&self, path: &Path) -> std::result::Result<FileInfoAnswer, MembershipMiss> {
        use rusqlite::OptionalExtension;
        let text = path.to_string_lossy();
        // `hex(NULL)` is «» in SQLite, so the absence of a digest is asked for by name.
        let row: Option<Option<String>> = self
            .tx
            .query_row(
                "SELECT CASE WHEN hash IS NULL THEN NULL ELSE lower(hex(hash)) END
                   FROM file WHERE scan_id = ?1 AND path = ?2",
                params![self.scan_id, &*text],
                |row| row.get(0),
            )
            .optional()?;
        let Some(hash_text) = row else {
            return Ok(FileInfoAnswer::NotInScan);
        };
        Ok(FileInfoAnswer::InScan {
            hash_text,
            membership: self.file_membership(path),
        })
    }

    /// The membership half of a file-info answer, computed separately so a refusal keeps its own
    /// rendering instead of being flattened into «no duplicates».
    fn file_membership(&self, path: &Path) -> std::result::Result<FileMembership, MembershipMiss> {
        self.require_authority()?;
        // `group_of_path` already passes the rank through the consistency gate.
        let Some(id) = self.group_of_path(path)? else {
            return Ok(FileMembership::NotGrouped);
        };
        let total = self.group_member_count(&id)?;
        let mut peers = self.member_paths(&id, Some(FILE_INFO_PEER_CAP + 1))?;
        peers.retain(|member| member != path);
        peers.truncate(FILE_INFO_PEER_CAP);
        Ok(FileMembership::InGroup(Box::new(FileGroupInfo {
            id,
            // The subject is not its own peer, so the honest comparison is against total - 1.
            truncated: total.saturating_sub(1) > peers.len() as u64,
            total,
            peers,
        })))
    }

    /// Shared body of `group`/`group_page`.
    fn resolve(
        &self,
        id: &GroupId,
        page: Option<(usize, usize)>,
    ) -> std::result::Result<ResolvedGroup, MembershipMiss> {
        use rusqlite::OptionalExtension;
        self.require_current(id)?;
        let summary: Option<(GroupSummary, i64, i64)> = self
            .tx
            .query_row(
                "SELECT rank, hash, file_count, size, reclaim, object_count, reclaim_state
                   FROM file_group WHERE scan_id = ?1 AND rank = ?2",
                params![id.scan_id, id.rank],
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
            )
            .optional()?;
        let Some((mut summary, reclaim, state)) = summary else {
            return Err(MembershipMiss::NoSuchGroup);
        };
        summary.reclaim = ReclaimEstimate::from_persisted(reclaim, state).map_err(|err| {
            MembershipMiss::Inconsistent {
                detail: err.to_string(),
            }
        })?;
        // `require_current` already refused a rank the central validation found inconsistent,
        // and that validation covered the WHOLE scan — every member's generation, manifest row
        // and summary, over every rank, not just the rows a page happens to return. What is
        // left to check here is only the shape of what was actually read.
        let members = match self.mode {
            MembershipMode::Explicit => self.explicit_members(id, page)?,
            _ => self.derived_members(id, page)?,
        };
        if page.is_none() && members.len() as u64 != summary.file_count {
            return Err(MembershipMiss::Inconsistent {
                detail: format!(
                    "group rank {} returned {} members against a declared {}",
                    id.rank,
                    members.len(),
                    summary.file_count
                ),
            });
        }
        Ok(ResolvedGroup {
            id: *id,
            mode: self.mode,
            summary,
            members,
        })
    }

    /// Explicit members: the member rows joined to the manifest. An INNER join is correct here
    /// precisely BECAUSE the central validation ran under this same transaction — a member
    /// without a manifest row already refused the whole snapshot, so a join that could silently
    /// shorten a page cannot be reached with one.
    fn explicit_members(
        &self,
        id: &GroupId,
        page: Option<(usize, usize)>,
    ) -> std::result::Result<Vec<FileEntry>, MembershipMiss> {
        let (limit, offset) = page_bounds(page);
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {GROUP_FILE_COLUMNS}
               FROM file_group_member mm
               JOIN file f           ON f.scan_id = mm.scan_id AND f.path = mm.path
               LEFT JOIN file_mark m ON m.scan_id = mm.scan_id AND m.path = mm.path
              WHERE mm.scan_id = ?1 AND mm.group_rank = ?2
              ORDER BY mm.path
              LIMIT ?3 OFFSET ?4"
        ))?;
        let rows = stmt.query_map(params![id.scan_id, id.rank, limit, offset], group_file_row)?;
        let mut members = Vec::new();
        for row in rows {
            members.push(row?);
        }
        Ok(members)
    }

    /// Derived members: the manifest by the CURRENT summary's digest — exactly the production
    /// composition, read under this snapshot.
    fn derived_members(
        &self,
        id: &GroupId,
        page: Option<(usize, usize)>,
    ) -> std::result::Result<Vec<FileEntry>, MembershipMiss> {
        let (limit, offset) = page_bounds(page);
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {GROUP_FILE_COLUMNS}
               FROM file_group g
               JOIN file f       ON f.scan_id = g.scan_id AND f.hash = unhex(g.hash)
               LEFT JOIN file_mark m ON m.scan_id = f.scan_id AND m.path = f.path
              WHERE g.scan_id = ?1 AND g.rank = ?2
              ORDER BY f.path
              LIMIT ?3 OFFSET ?4"
        ))?;
        let rows = stmt.query_map(params![id.scan_id, id.rank, limit, offset], group_file_row)?;
        let mut members = Vec::new();
        for row in rows {
            members.push(row?);
        }
        Ok(members)
    }
}

/// `LIMIT`/`OFFSET` for an optional page: the full set is `LIMIT -1 OFFSET 0` (SQLite reads a
/// negative limit as «no limit»).
fn page_bounds(page: Option<(usize, usize)>) -> (i64, i64) {
    match page {
        Some((offset, limit)) => (limit as i64, offset as i64),
        None => (-1, 0),
    }
}

/// The lease-side witness validation, in the frozen order: scan, authority, then one
/// mode-specific statement whose rows carry one member per ROW.
fn validate_lease_witness(
    tx: &Connection,
    witness: &PlanWitness,
    meter: &LeaseMeter<'_>,
) -> std::result::Result<(), LeaseRefusal> {
    use rusqlite::OptionalExtension;
    // 1. The scan exists.
    meter.bump();
    let exists: i64 = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM scan WHERE id = ?1)",
            params![witness.scan_id],
            |row| row.get(0),
        )
        .map_err(lease_store_refusal)?;
    if exists == 0 {
        return Err(LeaseRefusal::NoSuchScan);
    }
    // 2. Authority exists, is well-typed, and is exactly the witnessed generation.
    meter.bump();
    let authority: Option<(Value, Value)> = tx
        .query_row(
            "SELECT mode, generation FROM scan_membership WHERE scan_id = ?1",
            params![witness.scan_id],
            |row| Ok((row.get::<_, Value>(0)?, row.get::<_, Value>(1)?)),
        )
        .optional()
        .map_err(lease_store_refusal)?;
    let Some((mode_value, generation_value)) = authority else {
        return Err(LeaseRefusal::Unknown);
    };
    let (mode, generation) = decode_authority(&mode_value, &generation_value)
        .map_err(|detail| LeaseRefusal::Inconsistent { detail })?;
    if generation != witness.generation {
        return Err(LeaseRefusal::Stale {
            expected: witness.generation,
            found: generation,
        });
    }
    // 3.–5. Summaries, exact member sets and the mode's own member source.
    let wants = witness_wants_json(witness);
    match mode {
        MembershipMode::Explicit => {
            validate_explicit_witness(tx, witness, &wants, generation, meter)
        }
        _ => validate_derived_witness(tx, witness, &wants, meter),
    }
}

/// The `digest_state` a healthy Explicit member row reports: its manifest digest is a 32-byte
/// BLOB equal to the decoded digest of its own group's summary. Every other value names one
/// failing shape, each its own ordered CASE branch in the statement — so NULL and a failed
/// decode are settled before any equality, `x <> NULL` being NULL rather than true.
const MEMBER_DIGEST_OK: i64 = 6;

/// One row of the lease validation statements, already grouped per rank in arrival order.
struct WitnessedRank {
    rank: i64,
    witness_digest: String,
    current_digest: Option<String>,
    /// pathname, its own generation, and the state of its live manifest digest.
    members: Vec<(String, Option<i64>, i64)>,
    declared_count: Option<i64>,
    observed: i64,
}

/// Rank → witnessed group, built once. The acquisition preflight has already refused a
/// repeated rank, so the map is total and lossless — and it is what keeps validation O(K)
/// instead of the O(K²) a linear `find` per returned rank would cost while the SQL and bind
/// counts stayed fixed.
type WitnessIndex<'a> = HashMap<i64, &'a GroupWitness>;

fn witness_index(witness: &PlanWitness) -> WitnessIndex<'_> {
    witness
        .groups
        .iter()
        .map(|group| (group.id.rank, group))
        .collect()
}

/// Checks one accumulated rank against the witness, in the frozen refusal order.
fn check_witnessed_rank(
    checked: &WitnessedRank,
    index: &WitnessIndex<'_>,
    generation: Option<i64>,
) -> std::result::Result<(), LeaseRefusal> {
    let group = index
        .get(&checked.rank)
        .copied()
        .ok_or_else(|| LeaseRefusal::Inconsistent {
            detail: format!("validation returned unwitnessed rank {}", checked.rank),
        })?;
    let Some(current_digest) = &checked.current_digest else {
        if checked.members.is_empty() {
            return Err(LeaseRefusal::RankMissing { rank: checked.rank });
        }
        return Err(LeaseRefusal::Inconsistent {
            detail: format!("rank {} has member rows but no summary row", checked.rank),
        });
    };
    if *current_digest != checked.witness_digest {
        return Err(LeaseRefusal::DigestChanged {
            rank: checked.rank,
            expected: checked.witness_digest.clone(),
            found: current_digest.clone(),
        });
    }
    let declared = checked.declared_count.unwrap_or(-1);
    if declared != checked.observed {
        return Err(LeaseRefusal::Inconsistent {
            detail: format!(
                "rank {} declares {declared} members while its membership holds {}",
                checked.rank, checked.observed
            ),
        });
    }
    if checked.observed as u64 != group.members.len() as u64 {
        return Err(LeaseRefusal::MemberCountChanged {
            rank: checked.rank,
            expected: group.members.len() as u64,
            found: checked.observed.max(0) as u64,
        });
    }
    let witnessed: std::collections::HashSet<&Path> =
        group.members.iter().map(PathBuf::as_path).collect();
    for (path, member_generation, digest_state) in &checked.members {
        let live = Path::new(path);
        if !witnessed.contains(live) {
            return Err(LeaseRefusal::MembershipChanged {
                path: live.to_path_buf(),
            });
        }
        if let (Some(expected), Some(found)) = (generation, member_generation.as_ref()) {
            if *found != expected {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!(
                        "rank {} carries a member of generation {found} under authority \
                         generation {expected}",
                        checked.rank
                    ),
                });
            }
        }
        // Only once this really is the planned member: the digest it carries RIGHT NOW must
        // still be its group's own. Mutating `file.hash` alone leaves pathname, member row,
        // summary, authority and witness identical, so the set comparison above cannot see
        // it — and inheriting the resolver's earlier word is precisely what the last gate
        // before a destructive batch may not do.
        let wrong = match digest_state {
            1 => Some("no digest"),
            2 => Some("a digest that is not a blob"),
            3 => Some("a digest of the wrong length"),
            4 => Some("a group digest that does not decode"),
            5 => Some("a digest that is not this group's"),
            _ => None,
        };
        if let Some(what) = wrong {
            return Err(LeaseRefusal::Inconsistent {
                detail: format!(
                    "rank {} carries member {} with {what}",
                    checked.rank,
                    crate::textsan::terminal(path)
                ),
            });
        }
    }
    let live: std::collections::HashSet<&Path> = checked
        .members
        .iter()
        .map(|(path, _, _)| Path::new(path.as_str()))
        .collect();
    for path in &group.members {
        if !live.contains(path.as_path()) {
            return Err(LeaseRefusal::MembershipChanged { path: path.clone() });
        }
    }
    Ok(())
}

/// Streams the per-rank rows of one validation statement into `check_witnessed_rank`, plus the
/// final count of ranks seen (every witnessed rank must come back — `want` drives the join).
fn stream_witnessed_ranks(
    rows: &mut rusqlite::Rows<'_>,
    index: &WitnessIndex<'_>,
    generation: Option<i64>,
    read_member_generation: bool,
) -> std::result::Result<usize, LeaseRefusal> {
    let mut seen = 0usize;
    let mut current: Option<WitnessedRank> = None;
    loop {
        let row = match rows.next() {
            Ok(row) => row,
            Err(err) => return Err(lease_store_refusal(err)),
        };
        let Some(row) = row else { break };
        let rank: i64 = row.get(0).map_err(lease_store_refusal)?;
        let witness_digest: String = row.get(1).map_err(lease_store_refusal)?;
        let current_digest: Option<String> = row.get(2).map_err(lease_store_refusal)?;
        let declared_count: Option<i64> = row.get(3).map_err(lease_store_refusal)?;
        let member_path: Option<String> = row.get(4).map_err(lease_store_refusal)?;
        let member_generation: Option<i64> = if read_member_generation {
            row.get(5).map_err(lease_store_refusal)?
        } else {
            None
        };
        let observed: i64 = row
            .get(if read_member_generation { 6 } else { 5 })
            .map_err(lease_store_refusal)?;
        // Explicit only; carried to `check_witnessed_rank` rather than judged here, so a
        // member that is not the planned one is reported as a changed membership — the
        // sharper fact — instead of as whatever digest the substitute happened to hold.
        let mut digest_state = MEMBER_DIGEST_OK;
        if !read_member_generation {
            // Derived mode carries one more column: the scan's count of digests naming two
            // summaries. Derived membership IS the digest, so a duplicate inserted after
            // planning silently puts the same manifest pathnames in two groups — it must stop
            // the batch before it starts, and it costs no extra statement because the scalar
            // is uncorrelated.
            let duplicate_digests: i64 = row.get(6).map_err(lease_store_refusal)?;
            if duplicate_digests != 0 {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!(
                        "derived authority holds {duplicate_digests} digest(s) naming two group \
                         summaries"
                    ),
                });
            }
        }
        if read_member_generation {
            // Explicit mode carries three more columns: this member's manifest presence, the
            // state of its live manifest digest, and the scan's count of pathnames living in
            // two ranks. All three are structural corruption that must stop the batch before
            // it starts.
            let has_manifest: i64 = row.get(7).map_err(lease_store_refusal)?;
            if member_path.is_some() && has_manifest == 0 {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!(
                        "rank {rank} carries member {} with no manifest row",
                        crate::textsan::terminal(member_path.as_deref().unwrap_or_default())
                    ),
                });
            }
            digest_state = row.get(9).map_err(lease_store_refusal)?;
            let duplicated: i64 = row.get(8).map_err(lease_store_refusal)?;
            if duplicated != 0 {
                return Err(LeaseRefusal::Inconsistent {
                    detail: format!(
                        "the scan holds {duplicated} pathname(s) belonging to two ranks"
                    ),
                });
            }
        }
        if current.as_ref().map(|c| c.rank) != Some(rank) {
            if let Some(done) = current.take() {
                check_witnessed_rank(&done, index, generation)?;
                seen += 1;
            }
            current = Some(WitnessedRank {
                rank,
                witness_digest,
                current_digest,
                declared_count,
                members: Vec::new(),
                observed,
            });
        }
        if let (Some(rankrows), Some(path)) = (current.as_mut(), member_path) {
            rankrows
                .members
                .push((path, member_generation, digest_state));
        }
    }
    if let Some(done) = current.take() {
        check_witnessed_rank(&done, index, generation)?;
        seen += 1;
    }
    Ok(seen)
}

/// Explicit-mode validation: one statement, one member per ROW (P0d §1.2). Pathname boundaries
/// are row boundaries — nothing is concatenated, nothing is parsed, and a member named `a\nb`
/// can never equal two members `a` and `b`.
///
/// Every returned member also carries its manifest presence, the state of its live manifest
/// digest and its own generation, and the statement counts the scan's duplicated pathnames
/// once, as an uncorrelated scalar. So the final gate re-establishes the structural Explicit
/// invariants itself — a member whose manifest row was deleted after planning, one whose
/// manifest digest is no longer the group's, a member of another generation, a member with no
/// summary, one pathname in two ranks — instead of trusting an earlier resolver read or the
/// unique index still existing in an externally damaged database. The digest re-check is not
/// covered by the member-set comparison: mutating `file.hash` alone leaves path, member row,
/// summary and witness identical. Statement and bind counts are unchanged: one statement,
/// three binds, whatever K is — the facts ride as columns of the row stream already there.
fn validate_explicit_witness(
    tx: &Connection,
    witness: &PlanWitness,
    wants: &str,
    generation: i64,
    meter: &LeaseMeter<'_>,
) -> std::result::Result<(), LeaseRefusal> {
    meter.bump();
    let mut stmt = tx
        .prepare(
            "WITH want(rank, digest) AS (
                 SELECT json_extract(value, '$.r'), json_extract(value, '$.d')
                   FROM json_each(?2)
             )
             SELECT want.rank, want.digest, g.hash, g.file_count, m.path, m.generation,
                    COUNT(m.path) OVER (PARTITION BY want.rank) AS observed,
                    f.path IS NOT NULL                          AS has_manifest,
                    (SELECT COUNT(*) FROM (SELECT path FROM file_group_member
                                            WHERE scan_id = ?1
                                            GROUP BY path HAVING COUNT(*) > 1)) AS dup_paths,
                    CASE WHEN f.path      IS NULL          THEN 0
                         WHEN f.hash      IS NULL          THEN 1
                         WHEN typeof(f.hash) <> 'blob'     THEN 2
                         WHEN length(f.hash) <> 32         THEN 3
                         WHEN unhex(g.hash) IS NULL        THEN 4
                         WHEN f.hash <> unhex(g.hash)      THEN 5
                         ELSE 6 END                             AS digest_state
               FROM want
               LEFT JOIN file_group        g ON g.scan_id = ?1 AND g.rank       = want.rank
               LEFT JOIN file_group_member m ON m.scan_id = ?1 AND m.group_rank = want.rank
               LEFT JOIN file              f ON f.scan_id = ?1 AND f.path        = m.path
              ORDER BY want.rank, m.path",
        )
        .map_err(lease_store_refusal)?;
    let mut rows = stmt
        .query(params![witness.scan_id, wants])
        .map_err(lease_store_refusal)?;
    let index = witness_index(witness);
    let seen = stream_witnessed_ranks(&mut rows, &index, Some(generation), true)?;
    if seen != witness.groups.len() {
        return Err(LeaseRefusal::Inconsistent {
            detail: format!(
                "validation covered {seen} of {} witnessed ranks",
                witness.groups.len()
            ),
        });
    }
    Ok(())
}

/// Derived-mode validation: membership is derived from the CURRENT summary's digest — never
/// the witness's — and the witnessed digest is compared against the summary in Rust, so a
/// substituted digest is caught rather than followed. Plus the mode's own invariant: a derived
/// scan carries no member rows at all.
fn validate_derived_witness(
    tx: &Connection,
    witness: &PlanWitness,
    wants: &str,
    meter: &LeaseMeter<'_>,
) -> std::result::Result<(), LeaseRefusal> {
    meter.bump();
    let mut stmt = tx
        .prepare(
            "WITH want(rank, digest) AS (
                 SELECT json_extract(value, '$.r'), json_extract(value, '$.d')
                   FROM json_each(?2)
             )
             SELECT want.rank, want.digest, g.hash, g.file_count, f.path,
                    COUNT(f.path) OVER (PARTITION BY want.rank) AS observed,
                    (SELECT COUNT(*) FROM (SELECT hash FROM file_group
                                            WHERE scan_id = ?1
                                            GROUP BY hash HAVING COUNT(*) > 1)) AS dup_digests
               FROM want
               LEFT JOIN file_group g ON g.scan_id = ?1 AND g.rank = want.rank
               LEFT JOIN file       f ON f.scan_id = ?1 AND f.hash = unhex(g.hash)
              ORDER BY want.rank, f.path",
        )
        .map_err(lease_store_refusal)?;
    let mut rows = stmt
        .query(params![witness.scan_id, wants])
        .map_err(lease_store_refusal)?;
    let index = witness_index(witness);
    let seen = stream_witnessed_ranks(&mut rows, &index, None, false)?;
    if seen != witness.groups.len() {
        return Err(LeaseRefusal::Inconsistent {
            detail: format!(
                "validation covered {seen} of {} witnessed ranks",
                witness.groups.len()
            ),
        });
    }
    meter.bump();
    let members: i64 = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM file_group_member WHERE scan_id = ?1)",
            params![witness.scan_id],
            |row| row.get(0),
        )
        .map_err(lease_store_refusal)?;
    if members != 0 {
        return Err(LeaseRefusal::Inconsistent {
            detail: "derived authority with explicit member rows".into(),
        });
    }
    Ok(())
}

// A one-shot fault for `publish_results`, mirroring `ClearFault`: it fires right after the
// FIRST explicit member insert — parent summary and one child row already written inside the
// open transaction — so a green rollback assertion is about a real partial write, not a
// preflight refusal. Absent from every non-test build.
#[cfg(test)]
thread_local! {
    static PUBLISH_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms the one-shot publish fault for this thread and disarms it on drop.
#[cfg(test)]
pub(crate) struct PublishFault;

#[cfg(test)]
impl PublishFault {
    pub(crate) fn armed() -> Self {
        PUBLISH_FAULT.with(|slot| slot.set(true));
        PublishFault
    }

    /// Whether the armed shot has been consumed. A test whose seam was never reached proved
    /// nothing about rollback, so it has to assert this rather than the error alone.
    pub(crate) fn fired(&self) -> bool {
        PUBLISH_FAULT.with(|slot| !slot.get())
    }
}

#[cfg(test)]
impl Drop for PublishFault {
    fn drop(&mut self) {
        PUBLISH_FAULT.with(|slot| slot.set(false));
    }
}

/// Consumes an armed publish fault, if any.
#[cfg(test)]
fn take_publish_fault() -> bool {
    PUBLISH_FAULT.with(|slot| slot.replace(false))
}

// ---------------------------------------------------------------------------------------------
// End of the R4B-1 staged membership authority.
// ---------------------------------------------------------------------------------------------

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

/// Revokes, in the caller's open transaction, everything the previous run published about this
/// scan's results. A plain `UPDATE`: a scan with no `scan_stats` row has nothing to revoke, and
/// inventing one here would be a second writer of a row `begin_scan` owns.
///
/// `elapsed_seconds` and the environment columns are absent from the list on purpose — they
/// describe the session, which is continuing, not the result, which is gone.
fn revoke_published_results_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<()> {
    tx.execute(
        "UPDATE scan_stats
            SET results_materialized = 0,
                reclaimable_bytes = 0,
                reclaim_state = 0,
                groups_found = 0,
                files_scanned = 0,
                bytes_hashed = 0,
                hash_failures = 0,
                cand_files_total = 0,
                cand_bytes_total = 0,
                cand_files_hashed = 0,
                cand_bytes_hashed = 0
          WHERE scan_id = ?1",
        params![scan_id],
    )?;
    Ok(())
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

// Test-only statement seam for the bounded snapshot load and its consumers. Thread-local like the
// walk's fault seams and for the same reason: parallel tests must not pollute each other, and the
// helpers below are free functions with no `self` to hang a per-instance counter on. The claim it
// pins is the design's: the classification portion of every ledger read is exactly three flat
// statements, regardless of how many directories or groups are then answered offline.
#[cfg(test)]
thread_local! {
    static LEDGER_STATEMENTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Resets the seam for the current thread and returns the previous count.
#[cfg(test)]
pub(crate) fn reset_ledger_statements() -> u64 {
    LEDGER_STATEMENTS.with(|cell| cell.replace(0))
}

/// Statements the ledger read path has executed on this thread since the last reset.
#[cfg(test)]
pub(crate) fn ledger_statements() -> u64 {
    LEDGER_STATEMENTS.with(|cell| cell.get())
}

#[cfg(test)]
fn note_ledger_statement() {
    LEDGER_STATEMENTS.with(|cell| cell.set(cell.get() + 1));
}

#[cfg(not(test))]
fn note_ledger_statement() {}

/// One bounded snapshot load: exactly three flat reads — the persisted `config_json`, the
/// registered root generations, and the scan's whole omission ledger — inside the caller's
/// transaction, handed to the accepted pure constructor.
///
/// Deliberately RAW reads: `CompletenessSnapshot::build` is the single validator and the single
/// stale-generation filter, and validating or filtering here as well would be a second copy of
/// those rules waiting to disagree. Reading the whole ledger without a generation predicate is
/// bounded by what `commit_omissions` leaves behind — one generation per root — plus whatever a
/// zeroed root still holds, which the constructor drops.
fn completeness_snapshot_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<SnapshotOutcome> {
    note_ledger_statement();
    let roots = persisted_roots_tx(tx, scan_id)?;

    note_ledger_statement();
    let mut stmt = tx.prepare("SELECT root_key, generation FROM scan_root WHERE scan_id = ?1")?;
    let rows = stmt.query_map(params![scan_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut registered = Vec::new();
    for row in rows {
        registered.push(row?);
    }

    note_ledger_statement();
    let mut stmt = tx.prepare(
        "SELECT root_key, dir_key, reason, event_count, generation
           FROM dir_omission WHERE scan_id = ?1",
    )?;
    let rows = stmt.query_map(params![scan_id], |row| {
        Ok(StoredOmission {
            root_key: row.get(0)?,
            dir_key: row.get(1)?,
            reason: row.get(2)?,
            event_count: row.get(3)?,
            generation: row.get(4)?,
        })
    })?;
    let mut omissions = Vec::new();
    for row in rows {
        omissions.push(row?);
    }

    CompletenessSnapshot::build(&roots, registered, omissions)
}

/// Reads the verdicts for `dirs` from an open transaction.
///
/// The production query helper: the public method is this function plus the transaction that
/// makes it a snapshot, and the concurrency test drives exactly this, so a passing test cannot be
/// about a query that merely resembles the real one. Since R3D the classification itself is the
/// accepted `CompletenessSnapshot::verdict` — the same authority the builders and the live path
/// consult — so the per-directory SQL formulation this helper used to carry is gone, and with it
/// the possibility of the two classifiers drifting.
#[allow(dead_code)] // consumed through `directory_completeness`, whose production wiring is deferred
fn directory_completeness_tx(
    tx: &Transaction<'_>,
    scan_id: i64,
    dirs: &[&Path],
) -> Result<HashMap<PathBuf, DirCompleteness>> {
    let outcome = completeness_snapshot_tx(tx, scan_id)?;
    let mut out = HashMap::with_capacity(dirs.len());
    match outcome {
        SnapshotOutcome::Bounded(snapshot) => {
            for dir in dirs {
                out.insert(dir.to_path_buf(), snapshot.verdict(dir)?);
            }
        }
        // Not an error: a configuration this build cannot speak for is an expected state, and
        // the honest answer about every directory of such a scan is «unknown». Malformed stored
        // data already returned above, as an error.
        SnapshotOutcome::Unavailable(_) => {
            for dir in dirs {
                out.insert(dir.to_path_buf(), DirCompleteness::Unknown);
            }
        }
    }
    Ok(out)
}

/// One member's revalidated standing: `None` for a member the current ledger suppresses —
/// removed exactly as the builder would have removed it — otherwise its trust.
fn member_trust_of(ctx: &dyn SignatureContext, path: &Path) -> Option<DirTrust> {
    match ctx.disposition(path) {
        DirDisposition::Suppressed => None,
        DirDisposition::Trusted => Some(DirTrust::Trusted),
        DirDisposition::Untrusted => Some(DirTrust::Untrusted),
    }
}

/// The signature context an attributed read classifies against: the bounded snapshot, or the
/// legacy everything-untrusted context when the configuration carries no authority — so legacy
/// and unkeyable scans stay browseable with every member surviving as `Untrusted`.
fn attribution_context<'a>(
    outcome: &'a SnapshotOutcome,
    legacy: &'a LegacyContext,
) -> &'a dyn SignatureContext {
    match outcome {
        SnapshotOutcome::Bounded(snapshot) => snapshot,
        SnapshotOutcome::Unavailable(_) => legacy,
    }
}

/// Attributed summaries: the three authority reads plus exactly ONE ordered `dir_dedup` scan,
/// folded with O(1) state per signature run and no path retained.
fn attributed_dir_group_summaries_tx(
    tx: &Transaction<'_>,
    scan_id: i64,
) -> Result<AttributedDirGroupSummaries> {
    let outcome = completeness_snapshot_tx(tx, scan_id)?;
    let legacy = LegacyContext;
    let ctx = attribution_context(&outcome, &legacy);

    struct Run {
        signature: String,
        file_count: u32,
        size_per_dir: u64,
        survivors: u32,
        any_untrusted: bool,
    }
    fn flush(run: Option<Run>, groups: &mut Vec<AttributedDirGroupSummary>) {
        if let Some(run) = run {
            // Cardinality is re-evaluated over the SURVIVING members: fewer than two means the
            // stored rows no longer form a group at all.
            if run.survivors >= 2 {
                groups.push(AttributedDirGroupSummary {
                    rank: 0,
                    signature: run.signature,
                    dir_count: run.survivors,
                    file_count: run.file_count,
                    size_per_dir: run.size_per_dir,
                    trust: if run.any_untrusted {
                        DirTrust::Untrusted
                    } else {
                        DirTrust::Trusted
                    },
                });
            }
        }
    }

    note_ledger_statement();
    let mut stmt = tx.prepare(
        "SELECT signature, path, file_count, size_per_dir FROM dir_dedup
          WHERE scan_id = ?1 ORDER BY signature, path",
    )?;
    let rows = stmt.query_map(params![scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? as u32,
            row.get::<_, i64>(3)? as u64,
        ))
    })?;

    let mut groups: Vec<AttributedDirGroupSummary> = Vec::new();
    let mut run: Option<Run> = None;
    for row in rows {
        let (signature, path, file_count, size_per_dir) = row?;
        if run
            .as_ref()
            .map(|r| r.signature != signature)
            .unwrap_or(true)
        {
            flush(run.take(), &mut groups);
            run = Some(Run {
                signature,
                file_count,
                size_per_dir,
                survivors: 0,
                any_untrusted: false,
            });
        }
        let current = run.as_mut().expect("a run was just opened");
        match member_trust_of(ctx, Path::new(&path)) {
            None => {}
            Some(DirTrust::Trusted) => current.survivors += 1,
            Some(DirTrust::Untrusted) => {
                current.survivors += 1;
                current.any_untrusted = true;
            }
        }
    }
    flush(run.take(), &mut groups);

    // The same benefit order the SQL aggregation used: (dirs − 1) × size DESC, signature ASC —
    // over the surviving counts, so a fully trusted scan is value/order-identical to the parent.
    groups.sort_by(|a, b| {
        b.reclaim_bytes()
            .cmp(&a.reclaim_bytes())
            .then_with(|| a.signature.cmp(&b.signature))
    });
    let mut trusted_reclaim_total: u64 = 0;
    let mut unverified_groups: u32 = 0;
    for (index, group) in groups.iter_mut().enumerate() {
        group.rank = (index + 1) as u32;
        match group.trust {
            DirTrust::Trusted => {
                trusted_reclaim_total = trusted_reclaim_total
                    .checked_add(group.reclaim_bytes())
                    .ok_or_else(|| {
                        AppError::msg("the trusted reclaim total overflowed while aggregating")
                    })?;
            }
            DirTrust::Untrusted => unverified_groups += 1,
        }
    }
    Ok(AttributedDirGroupSummaries {
        groups,
        trusted_reclaim_total,
        unverified_groups,
    })
}

/// Attributed full groups (paths retained): the three authority reads plus exactly ONE ordered
/// `dir_dedup` scan, then the shared benefit sort.
///
/// Test-only since R4B-2c: production lists the SUMMARIES the `Open` payload carries and opens
/// one group at a time by signature, so a panel never holds every group's paths at once.
#[cfg(test)]
fn attributed_dir_groups_tx(tx: &Transaction<'_>, scan_id: i64) -> Result<Vec<AttributedDirGroup>> {
    let outcome = completeness_snapshot_tx(tx, scan_id)?;
    let legacy = LegacyContext;
    let ctx = attribution_context(&outcome, &legacy);

    note_ledger_statement();
    let mut stmt = tx.prepare(
        "SELECT signature, path, file_count, size_per_dir FROM dir_dedup
          WHERE scan_id = ?1 ORDER BY signature, path",
    )?;
    let rows = stmt.query_map(params![scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? as u32,
            row.get::<_, i64>(3)? as u64,
        ))
    })?;

    struct Run {
        signature: String,
        file_count: u32,
        size_per_dir: u64,
        members: Vec<(PathBuf, DirTrust)>,
    }
    fn flush(run: Option<Run>, groups: &mut Vec<AttributedDirGroup>) {
        if let Some(run) = run {
            if run.members.len() >= 2 {
                let trust = if run
                    .members
                    .iter()
                    .all(|(_, trust)| *trust == DirTrust::Trusted)
                {
                    DirTrust::Trusted
                } else {
                    DirTrust::Untrusted
                };
                let (paths, member_trust): (Vec<PathBuf>, Vec<DirTrust>) =
                    run.members.into_iter().unzip();
                groups.push(AttributedDirGroup {
                    group: DirGroup {
                        id: 0,
                        signature: run.signature,
                        paths,
                        file_count: run.file_count,
                        size_per_dir: run.size_per_dir,
                    },
                    member_trust,
                    trust,
                });
            }
        }
    }

    let mut groups: Vec<AttributedDirGroup> = Vec::new();
    let mut run: Option<Run> = None;
    for row in rows {
        let (signature, path, file_count, size_per_dir) = row?;
        if run
            .as_ref()
            .map(|r| r.signature != signature)
            .unwrap_or(true)
        {
            flush(run.take(), &mut groups);
            run = Some(Run {
                signature,
                file_count,
                size_per_dir,
                members: Vec::new(),
            });
        }
        let current = run.as_mut().expect("a run was just opened");
        let path = PathBuf::from(path);
        if let Some(trust) = member_trust_of(ctx, &path) {
            current.members.push((path, trust));
        }
    }
    flush(run.take(), &mut groups);
    sort_attributed_by_benefit(&mut groups);
    Ok(groups)
}

/// One attributed group by signature (the classic on-entry read): the three authority reads plus
/// exactly ONE indexed read of the group's own rows.
fn attributed_dir_group_tx(
    tx: &Transaction<'_>,
    scan_id: i64,
    signature: &str,
) -> Result<Option<AttributedDirGroup>> {
    let outcome = completeness_snapshot_tx(tx, scan_id)?;
    let legacy = LegacyContext;
    let ctx = attribution_context(&outcome, &legacy);

    note_ledger_statement();
    // One statement, not a header probe plus a member read: `file_count` and `size_per_dir` are
    // the same on every row of a group, so the first row carries them.
    let mut stmt = tx.prepare(
        "SELECT path, file_count, size_per_dir FROM dir_dedup
          WHERE scan_id = ?1 AND signature = ?2 ORDER BY path",
    )?;
    let rows = stmt.query_map(params![scan_id, signature], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as u32,
            row.get::<_, i64>(2)? as u64,
        ))
    })?;

    let mut header: Option<(u32, u64)> = None;
    let mut members: Vec<(PathBuf, DirTrust)> = Vec::new();
    for row in rows {
        let (path, file_count, size_per_dir) = row?;
        header.get_or_insert((file_count, size_per_dir));
        let path = PathBuf::from(path);
        if let Some(trust) = member_trust_of(ctx, &path) {
            members.push((path, trust));
        }
    }
    let Some((file_count, size_per_dir)) = header else {
        return Ok(None);
    };
    // The revalidated cardinality rule, at open time too: a group the current ledger has whittled
    // below two members no longer exists, and answering it would present a claim with no twin.
    if members.len() < 2 {
        return Ok(None);
    }
    let trust = if members.iter().all(|(_, trust)| *trust == DirTrust::Trusted) {
        DirTrust::Trusted
    } else {
        DirTrust::Untrusted
    };
    let (paths, member_trust): (Vec<PathBuf>, Vec<DirTrust>) = members.into_iter().unzip();
    Ok(Some(AttributedDirGroup {
        group: DirGroup {
            id: 0,
            signature: signature.to_string(),
            paths,
            file_count,
            size_per_dir,
        },
        member_trust,
        trust,
    }))
}

/// The same attributed read, keyed by the cursor's directory instead of a signature: the three
/// authority reads plus ONE group statement whose subquery names the cursor's signature.
fn attributed_dir_group_at_tx(
    tx: &Transaction<'_>,
    scan_id: i64,
    dir_path: &Path,
) -> Result<Option<AttributedDirGroup>> {
    let outcome = completeness_snapshot_tx(tx, scan_id)?;
    let legacy = LegacyContext;
    let ctx = attribution_context(&outcome, &legacy);

    note_ledger_statement();
    // The subquery names the cursor's signature (a PK-range probe over this scan's rows, the shape
    // the watch reader always had); the outer read then walks that signature through
    // `dir_dedup_by_scan_sig`. `file_count` and `size_per_dir` are equal on every row of a group,
    // so the first row carries them, and the cursor is always among the rows — it is what named
    // the signature.
    let mut stmt = tx.prepare(
        "SELECT path, signature, file_count, size_per_dir FROM dir_dedup
          WHERE scan_id = ?1 AND signature = (
                SELECT signature FROM dir_dedup WHERE scan_id = ?1 AND path = ?2
          )
          ORDER BY path",
    )?;
    let cursor = dir_path.to_string_lossy();
    let rows = stmt.query_map(params![scan_id, cursor.as_ref()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? as u32,
            row.get::<_, i64>(3)? as u64,
        ))
    })?;

    let mut header: Option<(String, u32, u64)> = None;
    let mut members: Vec<(PathBuf, DirTrust)> = Vec::new();
    let mut cursor_survives = false;
    for row in rows {
        let (path, signature, file_count, size_per_dir) = row?;
        header.get_or_insert((signature, file_count, size_per_dir));
        let path = PathBuf::from(path);
        if let Some(trust) = member_trust_of(ctx, &path) {
            cursor_survives |= path == dir_path;
            members.push((path, trust));
        }
    }
    let Some((signature, file_count, size_per_dir)) = header else {
        return Ok(None);
    };
    // The cursor's own standing is decided first: a directory the current ledger suppresses is a
    // member of nothing, and answering with whoever survived would offer a DIFFERENT pair as
    // «duplicates of this cursor». Then the same cardinality rule as every attributed reader.
    if !cursor_survives || members.len() < 2 {
        return Ok(None);
    }
    let trust = if members.iter().all(|(_, trust)| *trust == DirTrust::Trusted) {
        DirTrust::Trusted
    } else {
        DirTrust::Untrusted
    };
    let (paths, member_trust): (Vec<PathBuf>, Vec<DirTrust>) = members.into_iter().unzip();
    Ok(Some(AttributedDirGroup {
        group: DirGroup {
            id: 0,
            signature,
            paths,
            file_count,
            size_per_dir,
        },
        member_trust,
        trust,
    }))
}

impl ScanStore {
    /// Registers the scan's roots as completeness authorities and reports what happened.
    ///
    /// The outcome is typed rather than an error: `Unavailable` is an expected state of the
    /// operator's configuration, while a SQLite, I/O or constraint failure stays an `Err`. Folding
    /// the two together would let a broken checkpoint pass for a merely unkeyable one.
    ///
    /// Production registers through `begin_scan`/`clear_files` (the same `ensure_roots_tx`), so
    /// this standalone entry stays test-consumed — accepted API, deliberately unwired (D7).
    #[allow(dead_code)]
    pub fn ensure_scan_roots(&mut self, scan_id: i64) -> Result<RootRegistration> {
        let tx = self.conn.transaction()?;
        let registration = ensure_roots_tx(&tx, scan_id)?;
        tx.commit()?;
        log_registration(scan_id, &registration);
        Ok(registration)
    }

    /// Whether this root currently carries a trusted ledger, and at which generation. `None` when
    /// the root is not registered at all.
    #[allow(dead_code)] // accepted R3A reader, test-consumed until a per-root UI needs it
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
    /// rows as a complete answer. Unwired in R3D (D7): the only production re-walk is whole-scan.
    #[allow(dead_code)]
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
    /// which is why the authority is per root at all. Unwired in R3D (D7), as above.
    #[allow(dead_code)]
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
    /// Production reaches the same effect through `clear_files`; this narrower entry stays
    /// test-consumed (it is how the bounded-generation-zero resume cases are seeded).
    #[allow(dead_code)]
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
    #[allow(dead_code)] // the accepted verdict reader; its production consumer arrives with the UI round
    pub fn directory_completeness(
        &self,
        scan_id: i64,
        dirs: &[&Path],
    ) -> Result<HashMap<PathBuf, DirCompleteness>> {
        let snapshot = self.conn.unchecked_transaction()?;
        directory_completeness_tx(&snapshot, scan_id, dirs)
    }

    /// The scan's completeness authority, loaded in ONE read snapshot — exactly three flat
    /// statements, then the accepted pure constructor. Every later verdict is offline.
    pub fn completeness_snapshot(&self, scan_id: i64) -> Result<SnapshotOutcome> {
        let tx = self.conn.unchecked_transaction()?;
        completeness_snapshot_tx(&tx, scan_id)
    }

    /// Whether this scan's persisted ledger is fully authoritative: the configured and registered
    /// root sets agree and every root carries a positive generation. This is the resume
    /// predicate's other half — hard snapshot corruption stays `Err` and is never «solved» by a
    /// re-walk.
    pub fn ledger_authoritative(&self, scan_id: i64) -> Result<bool> {
        Ok(match self.completeness_snapshot(scan_id)? {
            SnapshotOutcome::Bounded(snapshot) => snapshot.fully_authoritative(),
            SnapshotOutcome::Unavailable(_) => false,
        })
    }

    /// The reopen-side omission account. `Unavailable` is an ordinary, expected answer here —
    /// pre-ledger scans, drifted or cleared authority, and roots-unavailable configurations whose
    /// observed detail was deliberately session-only.
    pub fn scan_omission_accounting(&self, scan_id: i64) -> Result<OmissionAccounting> {
        let tx = self.conn.unchecked_transaction()?;
        scan_omission_accounting_tx(&tx, scan_id)
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

    /// Storage classes of the two pathname columns, one pair per row in id order.
    fn pathname_storage_classes(store: &ScanStore) -> Vec<(String, String)> {
        store
            .conn
            .prepare("SELECT typeof(source_path), typeof(target_path) FROM move_event ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(|row| row.unwrap())
            .collect()
    }

    /// A UTF-8 pathname — LF and non-ASCII included — comes back exactly, stored as BLOB and
    /// marked exact. LF is legal inside a pathname, so one row with a newline is one row.
    #[test]
    fn move_event_roundtrip() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let event = MoveEvent {
            created_at: "2026-05-21T00:00:00+00:00".to_string(),
            scan_id: None,
            source_path: PathBuf::from("/src/we\nird/ünïcødé.txt"),
            target_path: PathBuf::from("/dst/ünïcødé.txt.dup1"),
            hash: Some([3u8; 32]),
            duplicate: true,
        };
        store.record_move_event(&event).unwrap();
        let rows = store.move_events().unwrap();
        assert_eq!(rows.len(), 1, "the LF name is one row, not two");
        assert_eq!(
            rows[0].event.source_path,
            PathBuf::from("/src/we\nird/ünïcødé.txt")
        );
        assert_eq!(
            rows[0].event.target_path,
            PathBuf::from("/dst/ünïcødé.txt.dup1")
        );
        assert_eq!(rows[0].event.hash, Some([3u8; 32]));
        assert!(rows[0].event.duplicate);
        assert_eq!(rows[0].path_fidelity, PathFidelity::Exact);
        assert_eq!(
            pathname_storage_classes(&store),
            vec![("blob".to_string(), "blob".to_string())],
            "stored as BLOB, not TEXT"
        );
    }

    /// The stored value and the fidelity are inverse to each other, and nothing outside the
    /// column's domain maps back.
    #[test]
    fn path_fidelity_round_trips_through_its_stored_value() {
        for fidelity in [PathFidelity::CarriedFromText, PathFidelity::Exact] {
            assert_eq!(PathFidelity::from_stored(fidelity.stored()), Some(fidelity));
        }
        assert_eq!(PathFidelity::from_stored(2), None);
        assert_eq!(PathFidelity::from_stored(-1), None);
    }

    /// Two pathnames that differ only outside UTF-8 stay two rows, each with its own bytes.
    ///
    /// The premise first, so the test proves what it claims: the two names differ as bytes, yet
    /// `to_string_lossy` maps them onto ONE string — a writer that binds a String is blind to the
    /// difference between them, and a journal fed by it would hold two rows reading the same.
    #[test]
    fn distinct_non_utf8_pathnames_stay_distinct_in_the_journal() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let a = OsStr::from_bytes(b"/a/\x80.bin");
        let b = OsStr::from_bytes(b"/a/\xff.bin");
        assert_ne!(a, b, "the two names are distinct on disk");
        assert_eq!(
            a.to_string_lossy(),
            b.to_string_lossy(),
            "but lossy conversion collapses them onto one string"
        );

        let mut store = ScanStore::open_in_memory().unwrap();
        for (source, target) in [
            (a, OsStr::from_bytes(b"/t/\x80.bin")),
            (b, OsStr::from_bytes(b"/t/\xff.bin")),
        ] {
            store
                .record_move_event(&MoveEvent {
                    created_at: "2026-09-07T00:00:00+00:00".to_string(),
                    scan_id: None,
                    source_path: PathBuf::from(source),
                    target_path: PathBuf::from(target),
                    hash: None,
                    duplicate: false,
                })
                .unwrap();
        }

        let rows = store.move_events().unwrap();
        assert_eq!(rows.len(), 2, "one row per move");
        assert_eq!(
            rows[0].event.source_path.as_os_str(),
            a,
            "the first row holds the first name's own bytes"
        );
        assert_eq!(
            rows[1].event.source_path.as_os_str(),
            b,
            "and the second row the second name's"
        );
        assert_eq!(
            rows[0].event.target_path.as_os_str().as_bytes(),
            b"/t/\x80.bin"
        );
        assert_eq!(
            rows[1].event.target_path.as_os_str().as_bytes(),
            b"/t/\xff.bin"
        );
        assert_ne!(
            rows[0].event.source_path, rows[1].event.source_path,
            "two names, two rows, no collapse"
        );
        for row in &rows {
            assert_eq!(row.path_fidelity, PathFidelity::Exact);
        }
        assert_eq!(
            pathname_storage_classes(&store),
            vec![("blob".to_string(), "blob".to_string()); 2],
            "stored as BLOB, not TEXT"
        );
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

    /// The persisted directory groups as plain `DirGroup`s — the attributed reader's view with
    /// the trust stripped, for tests that assert what storage round-trips. Every scan here has a
    /// generation-zero (or absent) ledger, so no member is suppressed and the membership equals
    /// the stored rows.
    fn plain_dir_groups(store: &ScanStore, scan_id: i64) -> Vec<DirGroup> {
        store
            .attributed_dir_groups(scan_id)
            .unwrap()
            .into_iter()
            .map(|attributed| attributed.group)
            .collect()
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

        let loaded = plain_dir_groups(&store, scan_id);
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
        assert!(plain_dir_groups(&store, scan_id).is_empty());
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
        let groups = plain_dir_groups(&store, scan_id);
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
        let persisted = plain_dir_groups(&store, scan_id);
        let group_with_a = persisted
            .iter()
            .find(|g| g.paths.contains(&PathBuf::from("/x/a")))
            .expect("/x/a must be in a group");
        assert_eq!(
            live.get(&PathBuf::from("/x/a"))
                .map(|l| l.signature.as_str()),
            Some(group_with_a.signature.as_str()),
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
        let persisted = plain_dir_groups(&store, scan_id);
        let group_with_a = persisted
            .iter()
            .find(|g| g.paths.contains(&PathBuf::from("/x/a")))
            .expect("/x/a must be in a group");
        assert_eq!(
            live.get(&PathBuf::from("/x/a"))
                .map(|l| l.signature.as_str()),
            Some(group_with_a.signature.as_str()),
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
    fn dir_group_at_returns_the_cursors_group_with_its_trust() {
        // R6 C4, now attributed: a dir in a group → Some(group) with paths including the dir
        // itself — and, on a ledger that vouches for nothing, every member `Untrusted`.
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
        let group = store
            .attributed_dir_group_at(scan_id, &PathBuf::from("/x/a"))
            .unwrap()
            .expect("/x/a in a group");
        assert_eq!(group.group.signature, "SIG_TWINS");
        assert_eq!(
            group.group.paths,
            vec![PathBuf::from("/x/a"), PathBuf::from("/x/b")]
        );
        assert_eq!(group.group.file_count, 3);
        assert_eq!(group.group.size_per_dir, 500);
        assert_eq!(group.trust, DirTrust::Untrusted);
        assert_eq!(
            group.member_trust,
            vec![DirTrust::Untrusted, DirTrust::Untrusted],
            "a generation-zero ledger vouches for nothing"
        );
    }

    #[test]
    fn dir_group_at_returns_none_for_dir_not_in_dir_dedup() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/x")]))
            .unwrap();
        // dir_dedup is empty.
        let group = store
            .attributed_dir_group_at(scan_id, &PathBuf::from("/x/orphan"))
            .unwrap();
        assert!(group.is_none(), "a singleton outside groups — None");
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
        let attributed = store.attributed_dir_group_summaries(scan_id).unwrap();
        // The scan's ledger sits at generation zero, so every member is Untrusted: the bytes stay
        // out of the trusted total and every group counts as an unverified candidate.
        assert_eq!(attributed.trusted_reclaim_total, 0);
        assert_eq!(attributed.unverified_groups, 3);
        let summaries = attributed.groups;
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
        let attributed = store.attributed_dir_group_summaries(scan_id).unwrap();
        assert!(attributed.groups.is_empty());
        assert_eq!(attributed.trusted_reclaim_total, 0);
        assert_eq!(attributed.unverified_groups, 0);
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
        let attributed = store
            .attributed_dir_group(scan_id, "SIG_X")
            .unwrap()
            .expect("the signature exists");
        let group = &attributed.group;
        assert_eq!(group.signature, "SIG_X");
        let mut paths = group.paths.clone();
        paths.sort();
        assert_eq!(paths, vec![PathBuf::from("/x/a"), PathBuf::from("/x/b")]);
        assert_eq!(group.file_count, 2);
        assert_eq!(group.size_per_dir, 100);
        assert_eq!(
            attributed.member_trust,
            vec![DirTrust::Untrusted, DirTrust::Untrusted],
            "a generation-zero ledger vouches for nothing"
        );
        // Unknown signature — None.
        let none = store.attributed_dir_group(scan_id, "NO_SUCH").unwrap();
        assert!(none.is_none());
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

    /// Members of the group carrying `hash_hex`, read through the membership authority.
    ///
    /// The digest is only how these tests NAME the group they seeded; the answer itself comes
    /// from membership, so a pathname verification rejected can never appear in it.
    fn members_of_digest(store: &ScanStore, scan_id: i64, hash_hex: &str) -> Vec<FileEntry> {
        let snapshot = store
            .membership_snapshot(scan_id)
            .expect("a published scan");
        let ids = snapshot
            .groups_of_digest(hash_hex)
            .expect("a digest lookup");
        match ids.first() {
            Some(id) => snapshot.group(id).expect("the group resolves").members,
            None => Vec::new(),
        }
    }

    /// A page of the scan's only published group, by IDENTITY — the question the old
    /// digest-keyed pager asked, now asked of the authority that owns membership.
    fn snapshot_page(
        store: &ScanStore,
        scan_id: i64,
        offset: usize,
        limit: usize,
    ) -> Vec<FileEntry> {
        let snapshot = store
            .membership_snapshot(scan_id)
            .expect("a published scan");
        let summaries = snapshot.summaries().expect("published summaries");
        let (id, _) = summaries.groups.first().expect("one group");
        snapshot
            .group_page(id, offset, limit)
            .expect("the page resolves")
            .members
    }

    /// The live member count of the group carrying `hash_hex`; `0` when no group carries it.
    fn snapshot_count(store: &ScanStore, scan_id: i64, hash_hex: &str) -> u64 {
        let snapshot = store
            .membership_snapshot(scan_id)
            .expect("a published scan");
        let ids = snapshot
            .groups_of_digest(hash_hex)
            .expect("a digest lookup");
        match ids.first() {
            Some(id) => snapshot.group_member_count(id).expect("the count resolves"),
            None => 0,
        }
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
        // The pages come out of the published authority, so the fixture publishes through the one
        // production writer. A digest that was never published is not a group.
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        // First page (2 files) — a, b.
        let page1 = snapshot_page(&store, scan_id, 0, 2);
        let paths1: Vec<_> = page1
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths1, vec!["/x/a", "/x/b"]);
        // Second page (offset 2, limit 2) — c, d.
        let page2 = snapshot_page(&store, scan_id, 2, 2);
        let paths2: Vec<_> = page2
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths2, vec!["/x/c", "/x/d"]);
        // Third page (offset 4, limit 2) — e (tail).
        let page3 = snapshot_page(&store, scan_id, 4, 2);
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
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        let page1 = snapshot_page(&store, scan_id, 0, 4);
        let page2 = snapshot_page(&store, scan_id, 4, 4);
        let page3 = snapshot_page(&store, scan_id, 8, 4);
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
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        assert_eq!(snapshot_count(&store, scan_id, &hex), 3);
        // Unknown hash → 0.
        let other_hex = crate::model::duplicate::hex_encode(&[99u8; 32]);
        assert_eq!(snapshot_count(&store, scan_id, &other_hex), 0);
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
        assert_eq!(plain_dir_groups(&store, scan_id).len(), 1);
        store
            .materialize_dir_groups(scan_id, |emit| {
                emit(PathBuf::from("/x/n1"), "S_new".to_string(), 2, 2)?;
                emit(PathBuf::from("/x/n2"), "S_new".to_string(), 2, 2)?;
                Ok(())
            })
            .unwrap();
        let groups = plain_dir_groups(&store, scan_id);
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
                .browse_summaries(scan_id)
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
        sql.publish_results(sql_id, PublishMode::Derived).unwrap();

        let mut ram = ScanStore::open_in_memory().unwrap();
        let ram_id = seed(&mut ram);
        let groups = ram.duplicate_groups(ram_id).unwrap();
        ram.publish_results(ram_id, PublishMode::Explicit(&groups))
            .unwrap();

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
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
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
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
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
                store
                    .publish_results(scan_id, PublishMode::Explicit(&groups))
                    .unwrap_err()
            } else {
                store
                    .publish_results(scan_id, PublishMode::Derived)
                    .unwrap_err()
            };
            assert!(
                err.to_string().contains("cannot be right"),
                "the refusal must name the cause: {err}"
            );
            assert!(
                store.browse_summaries(scan_id).unwrap().is_empty(),
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
                store
                    .publish_results(scan_id, PublishMode::Explicit(&groups))
                    .unwrap_err()
            } else {
                store
                    .publish_results(scan_id, PublishMode::Derived)
                    .unwrap_err()
            };
            assert!(
                err.to_string().contains("different link counts"),
                "both paths must name the same condition ({}): {err}",
                if verify { "RAM/--verify" } else { "SQL" }
            );
            assert!(
                store.browse_summaries(scan_id).unwrap().is_empty(),
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
                store
                    .publish_results(scan_id, PublishMode::Explicit(&groups))
                    .unwrap_err()
            } else {
                store
                    .publish_results(scan_id, PublishMode::Derived)
                    .unwrap_err()
            };
            assert!(
                err.to_string().contains("does not fit"),
                "the refusal must name the cause: {err}"
            );
            assert!(store.browse_summaries(scan_id).unwrap().is_empty());
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
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        store.prepare_legacy_for_viewing(scan_id).unwrap();
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

        store.prepare_legacy_for_viewing(scan_id).unwrap();
        let summaries = store.browse_summaries(scan_id).unwrap();
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

    /// The migrated row as the operator meets it since R4B-2c: a scan that never published an
    /// authority hands the browser its untrusted candidates, and no group row at all.
    ///
    /// This replaces the assertion that the migrated summary reaches the group renderer carrying
    /// `? objects` — that route required the pre-cutover design, in which an unpublished scan's
    /// browse-only summaries were drawn as if they were groups. The guarantee is strictly
    /// stronger now: a count that was never recorded cannot be mis-drawn as `0 objects`, because
    /// the row it lives in reaches no renderer, no identity and no destructive gate. Its old
    /// positive figure stays in the table as history, exactly as before.
    #[test]
    fn a_migrated_v2_scan_reaches_the_browser_as_candidates_and_never_as_groups() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_migrated_v2(&mut store);
        store.prepare_legacy_for_viewing(scan_id).unwrap();

        let candidates = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            assert_eq!(
                snapshot.mode(),
                MembershipMode::Unknown,
                "preparing a legacy result may not invent an authority"
            );
            assert_eq!(
                snapshot
                    .summaries()
                    .expect_err("no authority, no summaries"),
                MembershipMiss::Unknown,
                "the renderer is never handed a group of an unpublished scan"
            );
            snapshot
                .unknown_candidates()
                .expect("an Unknown scan answers with candidates")
                .expect("and it is Unknown, so the view exists")
        };
        // What the browser draws instead: raw digests over at least two allocations, with the
        // pathname count they actually have — not the migrated row's remembered `3`.
        assert_eq!(candidates.candidates.len(), 1);
        assert_eq!(candidates.candidates[0].paths, 2);
        // The candidate view carries no identity, so nothing can plan against it.
        assert_eq!(
            store.destructive_plan_verdict(scan_id).unwrap(),
            DestructivePlanVerdict::RescanRequired
        );
        assert_eq!(
            store
                .build_action_plan(scan_id, &[])
                .expect_err("no authority"),
            PlanRefusal::RescanRequired
        );
        // Reading it does not rewrite it: the sentinel and the old figure are still in the table.
        let (stored_objects, stored_files): (i64, i64) = store
            .conn
            .query_row(
                "SELECT object_count, file_count FROM file_group WHERE scan_id = ?1",
                params![scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (stored_objects, stored_files),
            (0, 3),
            "the migrated row keeps its sentinel and its history"
        );
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
    ///
    /// Since R4B-2c the plan is keyed by the published authority, so the damage is published
    /// damage: two explicit ranks, each naming one pathname of the SAME allocation under a
    /// different digest. That is the shape R4-V1's split populations make representable, and it
    /// is stronger than the manifest-only corruption this replaces — the rows the plan trusts
    /// most are the ones telling the lie.
    #[test]
    fn one_allocation_under_two_digests_refuses() {
        use std::os::unix::fs::MetadataExt;
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
        // And the authority repeats the lie: two explicit ranks, one pathname of the shared
        // allocation in each, published by the one production writer.
        let entry = |path: &Path| {
            let meta = std::fs::symlink_metadata(path).expect("scenario stat");
            FileEntry {
                path: path.to_path_buf(),
                size: meta.size(),
                mtime: meta.mtime(),
                mtime_nsec: meta.mtime_nsec(),
                ctime_sec: meta.ctime(),
                ctime_nsec: meta.ctime_nsec(),
                device: meta.dev(),
                inode: meta.ino(),
                nlink: meta.nlink(),
                is_keeper: false,
                action: None,
            }
        };
        let payload_digest: Vec<u8> = store
            .conn
            .query_row(
                "SELECT hash FROM file WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, alias_0.to_string_lossy()],
                |row| row.get(0),
            )
            .unwrap();
        let size = payload_size(&alias_0);
        let split = vec![
            DuplicateGroup {
                id: 0,
                size_bytes: size,
                hash: hex_encode(&payload_digest),
                files: vec![entry(&a_keeper), entry(&alias_0)],
            },
            DuplicateGroup {
                id: 1,
                size_bytes: size,
                hash: hex_encode(&other),
                files: vec![entry(&b_keeper), entry(&alias_1)],
            },
        ];
        store
            .publish_results(scan_id, PublishMode::Explicit(&split))
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
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        assert!(store.results_materialized(scan_id).unwrap());
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        assert!(
            store.browse_summaries(scan_id).unwrap().is_empty(),
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
        store
            .publish_results(scan_id, PublishMode::Explicit(&[]))
            .unwrap();
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        assert!(
            store.browse_summaries(scan_id).unwrap().is_empty(),
            "a read fallback must not resurrect a group rejected by verification"
        );
    }

    #[test]
    fn reopening_an_empty_result_does_not_recompute() {
        // A duplicate pair added to the manifest AFTER the result was prepared must not appear
        // — proof that opening does not re-aggregate the manifest.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_no_duplicates(&mut store);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
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
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        assert!(
            store.browse_summaries(scan_id).unwrap().is_empty(),
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
        assert!(store.browse_summaries(scan_id).unwrap().is_empty());
        assert!(!store.results_materialized(scan_id).unwrap());
        // The writer prepares it once.
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        assert!(store.results_materialized(scan_id).unwrap());
        let prepared = store.browse_summaries(scan_id).unwrap();
        assert_eq!(prepared.len(), 2);
        assert_eq!(prepared[0].reclaim.guaranteed_bytes(), 200);
        // A second call changes nothing.
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        assert_eq!(store.browse_summaries(scan_id).unwrap().len(), 2);
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
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        assert!(
            store.browse_summaries(scan_id).unwrap().is_empty(),
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
        assert_eq!(store.browse_summaries(with_dupes).unwrap().len(), 2);
        // Idempotent: nothing left to do on a second pass.
        assert_eq!(store.prepare_completed_scans().unwrap(), 0);
    }

    #[test]
    fn results_and_marker_commit_together() {
        // The marker must never be observable without the rows it describes.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_two_groups(&mut store);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        assert!(store.results_materialized(scan_id).unwrap());
        assert_eq!(store.browse_summaries(scan_id).unwrap().len(), 2);
    }

    #[test]
    fn legacy_recorded_result_is_kept_not_reaggregated() {
        // Legacy scan WITH rows already recorded (possibly filtered by --verify): the writer
        // marks it prepared instead of re-deriving it from raw hashes.
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_two_groups(&mut store);
        let mut groups = store.duplicate_groups(scan_id).unwrap();
        groups.truncate(1); // verification dropped one of them
        store
            .publish_results(scan_id, PublishMode::Explicit(&groups))
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_stats SET results_materialized = 0 WHERE scan_id = ?1",
                params![scan_id],
            )
            .unwrap();
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        assert_eq!(
            store.browse_summaries(scan_id).unwrap().len(),
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
        store
            .publish_results(id, PublishMode::Explicit(&groups))
            .unwrap();

        // The summary is materialized; group members are read from the `file` manifest by hash.
        let summaries = store.browse_summaries(id).unwrap();
        assert_eq!(summaries.len(), 1, "one materialized group summary");
        assert_eq!(summaries[0].file_count, 2);
        let files = members_of_digest(&store, id, &summaries[0].hash);
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| !f.is_keeper), "no marks yet");

        // Set a keeper mark and make sure group_files pulled it in fresh.
        let mut marked = files.clone();
        marked[0].is_keeper = true;
        store.save_marks(id, marked.iter()).unwrap();
        let reloaded = members_of_digest(&store, id, &summaries[0].hash);
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
            store.browse_summaries(id).unwrap().is_empty(),
            "no materialization yet"
        );
        store.prepare_legacy_for_viewing(id).unwrap();
        assert_eq!(
            store.browse_summaries(id).unwrap().len(),
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
        store
            .publish_results(id, PublishMode::Explicit(&groups))
            .unwrap();
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
            store.browse_summaries(id).unwrap().is_empty(),
            "file_group cleared"
        );
        // Raw count: the attributed reader needs the scan's own config row, which purge has
        // just deleted — the table state is what this assertion is about.
        let dir_rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM dir_dedup WHERE scan_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dir_rows, 0, "dir_dedup cleared");
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
        // The connection setup that now runs before the refusal touches connection-local state
        // only, so the file itself must come through untouched: same bytes, same stamp.
        let before = std::fs::read(&db).unwrap();
        assert!(
            ScanStore::open(&db).is_err(),
            "a DB from a newer schema version must be refused"
        );
        assert_eq!(
            std::fs::read(&db).unwrap(),
            before,
            "a refused open must leave the file byte-identical"
        );
        let stamped: i64 = rusqlite::Connection::open(&db)
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stamped, schema::SCHEMA_VERSION + 1, "and its stamp alone");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every production route hands back a connection that enforces the schema's declared
    /// relationships. Enforcement is per connection, so «the database has foreign keys» is not a
    /// property a caller can rely on — «this constructor turned them on and checked» is.
    #[test]
    fn every_store_constructor_enforces_foreign_keys() {
        let _role = role_guard();
        let dir = temp_state_dir("fk_routes");
        let db = dir.join("dedcom.db");

        let enforced = |store: &ScanStore| -> i64 {
            store
                .conn
                .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
                .unwrap()
        };

        let writable = ScanStore::open_writable(&db).unwrap();
        assert_eq!(enforced(&writable), 1, "open_writable");
        drop(writable);

        let observer = ScanStore::open_read_only(&db).unwrap();
        assert_eq!(enforced(&observer), 1, "open_read_only");
        drop(observer);

        let memory = ScanStore::open_in_memory().unwrap();
        assert_eq!(enforced(&memory), 1, "open_in_memory");

        // And the enforcement is real on the route an operator actually gets, not only reported:
        // a ledger row with no registered root is refused by the key.
        let store = ScanStore::open_writable(&db).unwrap();
        let orphan = store.conn.execute(
            "INSERT INTO dir_omission(scan_id, root_key, dir_key, reason, event_count, generation)
             VALUES (1, '/tank', '/tank/a', 'min_size', 1, 1)",
            [],
        );
        match orphan {
            Err(rusqlite::Error::SqliteFailure(err, _)) => {
                assert_eq!(err.extended_code, 787, "expected a foreign-key refusal")
            }
            other => panic!("an orphan ledger row must be refused: {other:?}"),
        }
        drop(store);
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
        // A real pre-versioning (v0.9) checkpoint — the shape that build actually wrote, not
        // today's shape with its stamp cleared. The v6 move journal is rewound to the v5 table,
        // the v4 and v5 tables go, the v3 columns and indexes go, the v2 marker goes, and only
        // then the stamp. Clearing the stamp alone would leave a database declaring v0 while
        // carrying names that arrived at v4 and v5; that is incoherent rather than legacy, and
        // the opener refuses it — see `a_current_shape_with_a_zeroed_stamp_is_refused` in main.rs.
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            crate::testfixtures::strip_v6(&conn);
            conn.execute_batch(
                "DROP TABLE file_group_member;
                 DROP TABLE scan_membership;
                 DROP TABLE dir_omission;
                 DROP TABLE scan_root;
                 DROP INDEX file_scan_identity;
                 DROP INDEX file_hash_identity;
                 ALTER TABLE file       DROP COLUMN nlink;
                 ALTER TABLE file_group DROP COLUMN object_count;
                 ALTER TABLE file_group DROP COLUMN reclaim_state;
                 ALTER TABLE scan_stats DROP COLUMN reclaim_state;
                 ALTER TABLE scan_stats DROP COLUMN results_materialized;",
            )
            .unwrap();
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
        let restored: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE name IN ('scan_membership', 'file_group_member', 'scan_root',
                                 'dir_omission', 'file_scan_identity', 'file_hash_identity')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            restored, 6,
            "the migration rebuilt every object the rewind removed"
        );
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
        store
            .publish_results(id, PublishMode::Explicit(&groups))
            .unwrap();

        let summaries = store.browse_summaries(id).unwrap();
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
        store
            .publish_results(id, PublishMode::Explicit(&groups))
            .unwrap();

        let dedup_rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM file_dedup WHERE scan_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dedup_rows, 0, "file_dedup is not written");

        let files = members_of_digest(&store, id, &hex_encode(&h));
        assert_eq!(files.len(), 2, "group members taken from the file manifest");
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
        let summaries = store.browse_summaries(id).unwrap();
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

    /// Everything one finished run publishes about a scan: manifest, hashes, group summaries and
    /// their reclaim total, directory groups, a legacy membership row of the kind a migrated
    /// database still carries, the completed-run counters, candidate progress, the omission ledger,
    /// an operator mark, the session's own elapsed/environment fields, and the two stores that are
    /// not scan result state at all — the move journal and the shared hash cache.
    fn seed_published_scan(store: &mut ScanStore) -> i64 {
        let config = ScanConfig::new(vec![PathBuf::from("/tank")]);
        let scan_id = store.begin_scan(&config).unwrap();
        store
            .record_files(
                scan_id,
                &[
                    row("/tank/a.bin", 100, 1),
                    row("/tank/b.bin", 100, 2),
                    row("/tank/u.bin", 70, 3),
                ],
            )
            .unwrap();
        let dup = [1u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/tank/a.bin"), dup),
                    (PathBuf::from("/tank/b.bin"), dup),
                    (PathBuf::from("/tank/u.bin"), [9u8; 32]),
                ],
            )
            .unwrap();
        // Group summaries, the v5 authority, the published reclaim total and the prepared marker,
        // in one write. The exact populations a `--verify` run publishes, through the one
        // production writer: what a clear or a purge has to remove is what production wrote, not
        // rows a test hand-crafted beside it.
        let verified = store.duplicate_groups(scan_id).unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        // Directory groups: two directories sharing one signature, so the >= 2 filter keeps them.
        store
            .materialize_dir_groups(scan_id, |emit| {
                emit(PathBuf::from("/tank/one"), "sig".to_string(), 100, 1)?;
                emit(PathBuf::from("/tank/two"), "sig".to_string(), 100, 1)
            })
            .unwrap();
        // A legacy membership row. Production stopped writing `file_dedup` in v2, but a migrated
        // checkpoint still holds them and they describe the same vanishing manifest.
        store
            .conn
            .execute(
                "INSERT INTO file_dedup(scan_id, hash, path, size, mtime, device, inode)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    scan_id,
                    hex_encode(&dup),
                    "/tank/a.bin",
                    100i64,
                    0i64,
                    1i64,
                    1i64
                ],
            )
            .unwrap();
        // The publication above wrote the v5 authority itself: Explicit mode, generation 1, both
        // members of rank 0 — asserted here so a fixture that stops publishing membership fails
        // where it is built rather than inside the test that depends on it.
        assert_eq!(
            store
                .conn
                .query_row(
                    "SELECT mode, generation FROM scan_membership WHERE scan_id = ?1",
                    params![scan_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            (2, 1),
            "the fixture publishes an explicit first generation"
        );
        store
            .record_scan_environment(
                scan_id,
                &crate::model::scan::ScanEnvironment {
                    storage_type: "nvme".to_string(),
                    pool_layout: "mirror".to_string(),
                    zfs_version: "2.4.3".to_string(),
                },
            )
            .unwrap();
        store.add_elapsed(scan_id, 12.5).unwrap();
        store
            .record_scan_result(
                scan_id,
                &ScanSummary {
                    files_scanned: 3,
                    bytes_hashed: 270,
                    groups_found: 1,
                    hash_failures: 2,
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .update_candidate_progress(scan_id, 3, 270, 3, 270)
            .unwrap();
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/x", OmissionReason::MinSize)]),
            )
            .unwrap();
        // The operator's own work: one keeper mark on a real group member.
        let summaries = store.browse_summaries(scan_id).unwrap();
        let mut files = members_of_digest(store, scan_id, &summaries[0].hash);
        files[0].is_keeper = true;
        store.save_marks(scan_id, files.iter()).unwrap();
        // Neither of these is this scan's result: a move journal entry and a shared cache row.
        store
            .record_move_event(&MoveEvent {
                created_at: "2026-08-03T00:00:00+00:00".to_string(),
                scan_id: Some(scan_id),
                source_path: PathBuf::from("/tank/moved"),
                target_path: PathBuf::from("/tank/elsewhere"),
                hash: Some([7u8; 32]),
                duplicate: false,
            })
            .unwrap();
        store.upsert_hash(1, 1, 100, 0, &dup).unwrap();
        scan_id
    }

    /// Everything a clear must be able to compare, before and after. Rows are rendered to text so
    /// a mismatch names the row that changed instead of printing an opaque tuple.
    #[derive(Debug, PartialEq)]
    struct ScanState {
        manifest: Vec<String>,
        groups: Vec<String>,
        authority: Vec<String>,
        members: Vec<String>,
        legacy_members: Vec<String>,
        dir_groups: Vec<String>,
        materialized: bool,
        /// `groups_found, files_scanned, bytes_hashed, hash_failures, reclaimable_bytes,
        /// reclaim_state, cand_files_total, cand_bytes_total, cand_files_hashed, cand_bytes_hashed`
        counters: Vec<i64>,
        elapsed: f64,
        environment: Vec<Option<String>>,
        marks: Vec<String>,
        omissions: i64,
        root_generation: Option<i64>,
        move_events: usize,
        cached_hashes: i64,
    }

    /// One query rendered as sorted text lines.
    fn rendered(store: &ScanStore, sql: &str, scan_id: i64, columns: usize) -> Vec<String> {
        let mut stmt = store.conn.prepare(sql).unwrap();
        stmt.query_map(params![scan_id], |row| {
            let mut line = String::new();
            for index in 0..columns {
                if index > 0 {
                    line.push('|');
                }
                line.push_str(&format!("{:?}", row.get_ref(index)?));
            }
            Ok(line)
        })
        .unwrap()
        .map(|row| row.unwrap())
        .collect()
    }

    fn scan_state(store: &ScanStore, scan_id: i64) -> ScanState {
        let counters = store
            .conn
            .query_row(
                "SELECT groups_found, files_scanned, bytes_hashed, hash_failures,
                        reclaimable_bytes, reclaim_state, cand_files_total, cand_bytes_total,
                        cand_files_hashed, cand_bytes_hashed
                   FROM scan_stats WHERE scan_id = ?1",
                params![scan_id],
                |row| {
                    let mut out = Vec::with_capacity(10);
                    for index in 0..10 {
                        out.push(row.get::<_, i64>(index)?);
                    }
                    Ok(out)
                },
            )
            .unwrap();
        let environment = store
            .conn
            .query_row(
                "SELECT storage_type, pool_layout, zfs_version FROM scan_stats WHERE scan_id = ?1",
                params![scan_id],
                |row| Ok(vec![row.get(0)?, row.get(1)?, row.get(2)?]),
            )
            .unwrap();
        let omissions = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM dir_omission WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        let cached_hashes = store
            .conn
            .query_row("SELECT COUNT(*) FROM hash_cache", [], |row| row.get(0))
            .unwrap();
        ScanState {
            manifest: rendered(
                store,
                "SELECT path, hash, size FROM file WHERE scan_id = ?1 ORDER BY path",
                scan_id,
                3,
            ),
            groups: rendered(
                store,
                "SELECT rank, hash, file_count, size, reclaim, object_count, reclaim_state
                   FROM file_group WHERE scan_id = ?1 ORDER BY rank",
                scan_id,
                7,
            ),
            authority: rendered(
                store,
                "SELECT mode, generation FROM scan_membership WHERE scan_id = ?1",
                scan_id,
                2,
            ),
            members: rendered(
                store,
                "SELECT group_rank, path, generation FROM file_group_member
                  WHERE scan_id = ?1 ORDER BY group_rank, path",
                scan_id,
                3,
            ),
            legacy_members: rendered(
                store,
                "SELECT hash, path FROM file_dedup WHERE scan_id = ?1 ORDER BY path",
                scan_id,
                2,
            ),
            dir_groups: rendered(
                store,
                "SELECT signature, path, file_count, size_per_dir
                   FROM dir_dedup WHERE scan_id = ?1 ORDER BY path",
                scan_id,
                4,
            ),
            materialized: store.results_materialized(scan_id).unwrap(),
            counters,
            elapsed: store.elapsed_seconds(scan_id).unwrap(),
            environment,
            marks: rendered(
                store,
                "SELECT path, is_keeper, action FROM file_mark WHERE scan_id = ?1 ORDER BY path",
                scan_id,
                3,
            ),
            omissions,
            root_generation: store.root_generation(scan_id, Path::new("/tank")).unwrap(),
            move_events: store.move_events().unwrap().len(),
            cached_hashes,
        }
    }

    /// A result describes members of a manifest. Clearing the manifest without clearing the result
    /// leaves summaries whose files cannot be found — and, through the prepared marker, an opening
    /// scan that returns those summaries as if they were current.
    #[test]
    fn clear_files_revokes_every_published_result() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_published_scan(&mut store);
        let before = scan_state(&store, scan_id);
        assert!(!before.groups.is_empty(), "the fixture published groups");
        assert!(before.materialized, "the fixture set the prepared marker");
        assert!(
            !before.authority.is_empty(),
            "the fixture published an authority"
        );
        assert_eq!(before.members.len(), 2, "the fixture published members");

        store.clear_files(scan_id).unwrap();

        let after = scan_state(&store, scan_id);
        assert_eq!(store.manifest_count(scan_id).unwrap(), 0);
        assert!(
            after.groups.is_empty(),
            "file_group must go with the manifest"
        );
        assert!(
            after.authority.is_empty(),
            "an authority over a deleted manifest reads as «this membership is known»"
        );
        assert!(
            after.members.is_empty(),
            "members that outlive their manifest are trusted orphans"
        );
        assert!(
            after.legacy_members.is_empty(),
            "legacy file_dedup rows describe the same vanished manifest"
        );
        assert!(
            after.dir_groups.is_empty(),
            "directory groups are derived from the manifest too"
        );
        assert!(
            !after.materialized,
            "the prepared marker must not survive the result it marks"
        );
        assert_eq!(
            after.counters,
            vec![0i64; 10],
            "every counter describing the deleted manifest is revoked"
        );
        // Read back through the ordinary APIs, not only the columns.
        for summary in store.browse_summaries(scan_id).unwrap() {
            let members = members_of_digest(&store, scan_id, &summary.hash);
            assert!(
                !members.is_empty(),
                "a surviving summary of {} files whose members cannot be found",
                summary.file_count
            );
        }
        assert!(store.browse_summaries(scan_id).unwrap().is_empty());
        let reclaim = store.scan_reclaim(scan_id).unwrap();
        assert_eq!(reclaim.guaranteed_bytes(), 0);
        assert_eq!(reclaim.state(), ReclaimState::Unknown);
        // The marker no longer short-circuits an open: preparing a cleared scan finds nothing to
        // hand back, rather than returning through a marker left over from the previous result.
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        assert!(
            store.browse_summaries(scan_id).unwrap().is_empty(),
            "preparing a cleared scan must not return the previous run's groups"
        );
    }

    /// The operator's marks, the session's own time and environment, the move journal and the
    /// cross-scan hash cache are not this scan's result and must survive untouched.
    #[test]
    fn clear_files_keeps_marks_session_fields_and_shared_stores() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_published_scan(&mut store);
        let before = scan_state(&store, scan_id);

        store.clear_files(scan_id).unwrap();

        let after = scan_state(&store, scan_id);
        assert_eq!(
            after.marks, before.marks,
            "operator intent survives a re-walk"
        );
        assert_eq!(after.elapsed, before.elapsed, "the session time continues");
        assert_eq!(after.environment, before.environment);
        assert_eq!(
            after.move_events, before.move_events,
            "not scan result state"
        );
        assert_eq!(
            after.cached_hashes, before.cached_hashes,
            "hash_cache is keyed by allocation and shared across scans"
        );
        // And the existing contract is untouched: ledger gone, root still registered at zero.
        assert_eq!(after.omissions, 0);
        assert_eq!(after.root_generation, Some(0));
    }

    /// Clearing one scan is not allowed to reach into another.
    #[test]
    fn clear_files_touches_only_its_own_scan() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let first = seed_published_scan(&mut store);
        let second = seed_published_scan(&mut store);
        let before = scan_state(&store, second);

        store.clear_files(first).unwrap();

        assert_eq!(
            scan_state(&store, second),
            before,
            "the other scan is untouched"
        );
    }

    /// The reset must not poison the next run: a re-walk publishes fresh summaries and a fresh
    /// total over the same columns it just zeroed.
    #[test]
    fn a_cleared_scan_can_publish_again() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_published_scan(&mut store);
        store.clear_files(scan_id).unwrap();

        store
            .record_files(
                scan_id,
                &[row("/tank/a.bin", 100, 1), row("/tank/b.bin", 100, 2)],
            )
            .unwrap();
        let dup = [4u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/tank/a.bin"), dup),
                    (PathBuf::from("/tank/b.bin"), dup),
                ],
            )
            .unwrap();
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();

        let summaries = store.browse_summaries(scan_id).unwrap();
        assert_eq!(summaries.len(), 1, "the next run publishes normally");
        assert_eq!(summaries[0].file_count, 2);
        assert!(store.results_materialized(scan_id).unwrap());
        assert_eq!(
            store.scan_reclaim(scan_id).unwrap().guaranteed_bytes(),
            100,
            "a fresh total, not the zero the clear left behind"
        );
    }

    /// Rollback, proved from inside the transaction. The fault fires with the manifest, the ledger
    /// and both membership tables already deleted and the rest of the clear still ahead, so what
    /// this asserts is a real undo — not a transaction that never started.
    #[test]
    fn a_clear_that_fails_mid_transaction_restores_everything() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_published_scan(&mut store);
        let before = scan_state(&store, scan_id);

        let fault = ClearFault::armed();
        let err = store
            .clear_files(scan_id)
            .expect_err("the armed fault must fail the clear");
        assert!(err.to_string().contains("injected clear fault"), "{err}");
        assert!(
            fault.fired(),
            "a seam that was never reached proves nothing"
        );

        assert_eq!(
            scan_state(&store, scan_id),
            before,
            "a failed clear leaves the complete prior state"
        );
    }

    /// The control, named for what it actually proves: with another writer holding the database,
    /// the clear never starts. That is no-start atomicity, not rollback — the test above is the
    /// rollback proof.
    #[test]
    fn a_clear_that_cannot_take_the_write_lock_changes_nothing() {
        // `role_guard` is this file's own pre-existing lock for every file-backed store (the
        // observer role is process-wide); it is not serialisation introduced to steady a race.
        let _role = role_guard();
        let dir = temp_state_dir("clear_no_start");
        let db = dir.join("dedcom.db");
        let mut store = ScanStore::open_writable(&db).unwrap();
        let scan_id = seed_published_scan(&mut store);
        let before = scan_state(&store, scan_id);

        // A second connection owns the write lock; ours refuses at once rather than queueing.
        let blocker = Connection::open(&db).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        store.conn.execute_batch("PRAGMA busy_timeout=0").unwrap();

        let err = store
            .clear_files(scan_id)
            .expect_err("no destructive statement can run against a held write lock");
        match &err {
            AppError::Db(rusqlite::Error::SqliteFailure(code, _)) => assert_eq!(
                code.code,
                rusqlite::ErrorCode::DatabaseBusy,
                "expected a busy refusal, got {err}"
            ),
            other => panic!("expected a busy refusal, got {other}"),
        }

        blocker.execute_batch("ROLLBACK").unwrap();
        assert_eq!(scan_state(&store, scan_id), before);
        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Rows of the two v5 tables anywhere in the database, whatever scan they belong to.
    fn membership_rows(store: &ScanStore) -> (i64, i64) {
        store
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM scan_membership),
                        (SELECT COUNT(*) FROM file_group_member)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    /// A purge is the hard, irreversible delete: it must leave no row of the scan anywhere,
    /// membership included, and it must not reach into a second scan.
    #[test]
    fn purge_scan_removes_the_membership_tables_and_spares_other_scans() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let first = seed_published_scan(&mut store);
        let second = seed_published_scan(&mut store);
        let other_before = scan_state(&store, second);
        assert_eq!(
            membership_rows(&store),
            (2, 4),
            "both scans have membership"
        );

        store.purge_scan(first).unwrap();

        // The purged scan keeps no row anywhere — `scan_stats` is gone too, so this asks the
        // tables directly rather than through the snapshot helper.
        for table in [
            "scan_membership",
            "file_group_member",
            "file_group",
            "file",
            "file_dedup",
            "dir_dedup",
            "scan_stats",
            "file_mark",
        ] {
            let rows: i64 = store
                .conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE scan_id = ?1"),
                    params![first],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(rows, 0, "{table} still holds rows of the purged scan");
        }
        assert_eq!(
            membership_rows(&store),
            (1, 2),
            "only the purged scan's membership is gone"
        );
        assert_eq!(
            scan_state(&store, second),
            other_before,
            "the other scan is untouched"
        );
        let scans: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM scan WHERE id = ?1",
                params![first],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(scans, 0, "the scan row itself is gone");
    }

    /// A purge that fails part-way down its table list leaves every row, membership included.
    /// The fault fires after real deletes, so this is rollback rather than no-start atomicity.
    #[test]
    fn a_failed_purge_preserves_every_row() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed_published_scan(&mut store);
        let before = scan_state(&store, scan_id);

        let fault = ClearFault::armed();
        let err = store
            .purge_scan(scan_id)
            .expect_err("the armed fault must fail the purge");
        assert!(err.to_string().contains("injected purge fault"), "{err}");
        assert!(
            fault.fired(),
            "a seam that was never reached proves nothing"
        );

        assert_eq!(
            scan_state(&store, scan_id),
            before,
            "a failed purge leaves the complete prior state"
        );
        assert_eq!(membership_rows(&store), (1, 2));
    }

    /// Since R4B-2c publication is production, and this is the positive proof of which flow
    /// publishes what. An ordinary hash-only completion publishes a DERIVED authority — one
    /// `scan_membership` row and no member rows, because derived membership IS the manifest's own
    /// digest join and is answerable without them. `--verify` publishes an EXPLICIT authority
    /// whose member rows are exactly the populations it verified. Walking and hashing publish
    /// nothing at all, and preparing a legacy result still invents nothing: an authority nobody
    /// published may not be inferred from the rows lying around.
    #[test]
    fn an_ordinary_completion_publishes_derived_authority() {
        let mut store = ScanStore::open_in_memory().unwrap();

        // Fresh scan: manifest and hashes only.
        let fresh = seed_two_groups(&mut store);
        assert_eq!(
            membership_rows(&store),
            (0, 0),
            "walking/hashing publishes none"
        );

        // The default publication path — what every ordinary completion runs.
        store.publish_results(fresh, PublishMode::Derived).unwrap();
        assert_eq!(
            membership_rows(&store),
            (1, 0),
            "one derived authority, and no member rows to go stale beside the manifest"
        );
        {
            let snapshot = store.membership_snapshot(fresh).unwrap();
            assert_eq!(snapshot.mode(), MembershipMode::Derived);
            assert_eq!(snapshot.generation(), Some(1), "the first publication");
            let summaries = snapshot.summaries().expect("derived authority answers");
            assert_eq!(
                summaries.groups.len(),
                2,
                "both seeded groups are published"
            );
            // Answerable without member rows: every summary's count comes back through the
            // authority, so «no rows» is not «no membership».
            for (id, summary) in &summaries.groups {
                assert_eq!(
                    snapshot.group_member_count(id).unwrap(),
                    summary.file_count,
                    "the derived group answers its own population"
                );
            }
        }

        // The --verify publication path: the same question, answered by explicit member rows.
        let verified = seed_two_groups(&mut store);
        let groups = store.duplicate_groups(verified).unwrap();
        let explicit_members: i64 = groups.iter().map(|group| group.files.len() as i64).sum();
        store
            .publish_results(verified, PublishMode::Explicit(&groups))
            .unwrap();
        assert_eq!(
            membership_rows(&store),
            (2, explicit_members),
            "an explicit publication writes exactly the populations it verified"
        );
        {
            let snapshot = store.membership_snapshot(verified).unwrap();
            assert_eq!(snapshot.mode(), MembershipMode::Explicit);
            assert_eq!(snapshot.generation(), Some(1));
        }

        // The legacy preparation path.
        let legacy = seed_two_groups(&mut store);
        store.set_status(legacy, ScanStatus::Complete).unwrap();
        store.prepare_legacy_for_viewing(legacy).unwrap();
        assert!(store.results_materialized(legacy).unwrap());
        assert_eq!(
            membership_rows(&store),
            (2, explicit_members),
            "preparing a legacy result may not invent an authority"
        );
        assert_eq!(
            store.membership_snapshot(legacy).unwrap().mode(),
            MembershipMode::Unknown,
            "browsing an old checkpoint leaves it Unknown"
        );
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

    /// An aggregate that cannot be represented is an error, never a smaller number — with the
    /// accepted model boundary, now that the store classifies through the snapshot: the count
    /// domain is `u64`, so two `i64::MAX` cells still fit (barely) and it takes a third to leave
    /// the domain. This replaces the old SQL-side rule, whose `sum()` overflowed at the SIGNED
    /// boundary the model deliberately does not have.
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
        match verdict(&store, scan_id, "/tank") {
            DirCompleteness::Incomplete(summary) => assert_eq!(
                summary.known_omitted_files().unwrap(),
                (i64::MAX as u64) * 2,
                "two maxima still fit the unsigned domain — the accepted model boundary"
            ),
            other => panic!("expected incomplete, got {other:?}"),
        }

        // The third maximum leaves the domain: checked aggregation refuses.
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root(
                    "/tank",
                    &[
                        ("/tank/a", OmissionReason::MinSize),
                        ("/tank/b", OmissionReason::MinSize),
                        ("/tank/c", OmissionReason::MinSize),
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
            .expect_err("three maxima cannot be summed into one figure");
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

    // -----------------------------------------------------------------------------------------
    // R3D: the bounded snapshot load, its statement seam, authority, attribution and live trust.
    // -----------------------------------------------------------------------------------------

    /// The statement counts, pinned by the seam rather than promised in prose: classification is
    /// always the 3 flat authority reads, each attributed reader adds exactly its one group scan,
    /// and answering one directory costs the same statements as answering forty.
    #[test]
    fn ledger_statement_counts_are_pinned() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/a", OmissionReason::MinSize)]),
            )
            .unwrap();
        store
            .record_dir_groups(
                scan_id,
                &[DirGroup {
                    id: 0,
                    signature: "SIG".to_string(),
                    paths: vec![PathBuf::from("/tank/x"), PathBuf::from("/tank/y")],
                    file_count: 1,
                    size_per_dir: 10,
                }],
            )
            .unwrap();

        reset_ledger_statements();
        store
            .directory_completeness(scan_id, &[Path::new("/tank/a")])
            .unwrap();
        assert_eq!(ledger_statements(), 3, "one directory: 3 reads");

        let many: Vec<PathBuf> = (0..40)
            .map(|i| PathBuf::from(format!("/tank/d{i}")))
            .collect();
        let many_refs: Vec<&Path> = many.iter().map(PathBuf::as_path).collect();
        reset_ledger_statements();
        store.directory_completeness(scan_id, &many_refs).unwrap();
        assert_eq!(ledger_statements(), 3, "forty directories: still 3 reads");

        reset_ledger_statements();
        store.completeness_snapshot(scan_id).unwrap();
        assert_eq!(
            ledger_statements(),
            3,
            "the snapshot load itself is 3 reads"
        );

        reset_ledger_statements();
        store.attributed_dir_group_summaries(scan_id).unwrap();
        assert_eq!(ledger_statements(), 4, "summaries: 3 + one ordered scan");

        reset_ledger_statements();
        store.attributed_dir_groups(scan_id).unwrap();
        assert_eq!(ledger_statements(), 4, "full groups: 3 + one ordered scan");

        reset_ledger_statements();
        store.attributed_dir_group(scan_id, "SIG").unwrap();
        assert_eq!(ledger_statements(), 4, "one group: 3 + one indexed read");

        reset_ledger_statements();
        store
            .attributed_dir_group_at(scan_id, &PathBuf::from("/tank/x"))
            .unwrap();
        assert_eq!(
            ledger_statements(),
            4,
            "the cursor's group: 3 + one indexed read, the signature named by its subquery"
        );

        reset_ledger_statements();
        store
            .dir_signatures_under(scan_id, &many, DirSigAlgo::Old)
            .unwrap();
        assert_eq!(
            ledger_statements(),
            3,
            "live signatures: the classification stays 3 reads however many directories ask"
        );
    }

    /// The resume predicate's store half, over every authority shape the accounting matrix names.
    #[test]
    fn ledger_authoritative_matches_the_accounting_matrix() {
        // A5-shaped: committed ledger, all generations positive.
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        assert!(store.ledger_authoritative(scan_id).unwrap());
        assert_eq!(
            store.scan_omission_accounting(scan_id).unwrap(),
            OmissionAccounting::Ledger(crate::model::omission::OmissionSummary::default()),
            "a committed empty ledger reopens as the exact zero"
        );

        // A7-shaped: generations zeroed.
        store.clear_scan_omissions(scan_id).unwrap();
        assert!(!store.ledger_authoritative(scan_id).unwrap());
        assert_eq!(
            store.scan_omission_accounting(scan_id).unwrap(),
            OmissionAccounting::Unavailable,
            "a zeroed ledger must never read as an exact zero"
        );

        // A2-shaped: pre-ledger — no scan_root rows at all.
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        store
            .conn
            .execute("DELETE FROM scan_root WHERE scan_id = ?1", params![scan_id])
            .unwrap();
        assert!(!store.ledger_authoritative(scan_id).unwrap());
        assert_eq!(
            store.scan_omission_accounting(scan_id).unwrap(),
            OmissionAccounting::Unavailable
        );

        // A3-shaped: registration drift — the registered root is not the configured one.
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_root SET root_key = '/other' WHERE scan_id = ?1",
                params![scan_id],
            )
            .unwrap();
        assert!(!store.ledger_authoritative(scan_id).unwrap());

        // A4-shaped: mixed authority — one positive root, one zeroed.
        let (mut store, scan_id) = ledger_store(&["/tank/one", "/tank/two"]);
        let both = BTreeMap::from([
            (key("/tank/one"), counts(&[])),
            (key("/tank/two"), counts(&[])),
        ]);
        store.commit_omissions(scan_id, &both).unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_root SET generation = 0 WHERE scan_id = ?1 AND root_key = '/tank/two'",
                params![scan_id],
            )
            .unwrap();
        assert!(
            !store.ledger_authoritative(scan_id).unwrap(),
            "one positive root cannot vouch for the scan"
        );
        assert_eq!(
            store.scan_omission_accounting(scan_id).unwrap(),
            OmissionAccounting::Unavailable
        );

        // Hard corruption stays an error, never a re-walk-shaped `false`. The schema CHECKs bar a
        // negative generation and a malformed key from ever being written, so the seedable
        // corruption is a reason string this build does not know.
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
        assert!(store.ledger_authoritative(scan_id).is_err());
    }

    /// Reopen counter parity for a real ledger: what the walk committed is what a fresh
    /// accounting read folds — same totals, `Ledger` provenance.
    #[test]
    fn reopened_accounting_equals_the_committed_ledger() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(
                scan_id,
                &one_root(
                    "/tank",
                    &[
                        ("/tank/a", OmissionReason::MinSize),
                        ("/tank/a", OmissionReason::MinSize),
                        ("/tank/b", OmissionReason::UnsupportedEntry),
                        ("/tank", OmissionReason::WalkError),
                    ],
                ),
            )
            .unwrap();
        match store.scan_omission_accounting(scan_id).unwrap() {
            OmissionAccounting::Ledger(totals) => {
                assert_eq!(totals.known_omitted_files().unwrap(), 2);
                assert_eq!(totals.unsupported_entries().unwrap(), 1);
                assert_eq!(totals.unknown_cardinality_events(), 1);
            }
            other => panic!("expected the exact ledger account, got {other:?}"),
        }
    }

    /// Stored-member suppression at read time: a ledger change AFTER materialization removes the
    /// affected member exactly as the builder would have, re-evaluates cardinality, and a group
    /// left below two members is gone — from the list, from the batch and from the open-by-
    /// signature read alike. The unaffected `Unknown-free` members keep the group browseable.
    #[test]
    fn a_later_ledger_change_suppresses_stored_members_on_every_reader() {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        store
            .record_dir_groups(
                scan_id,
                &[
                    DirGroup {
                        id: 0,
                        signature: "PAIR".to_string(),
                        paths: vec![PathBuf::from("/tank/p1"), PathBuf::from("/tank/p2")],
                        file_count: 1,
                        size_per_dir: 100,
                    },
                    DirGroup {
                        id: 1,
                        signature: "TRIO".to_string(),
                        paths: vec![
                            PathBuf::from("/tank/t1"),
                            PathBuf::from("/tank/t2"),
                            PathBuf::from("/tank/t3"),
                        ],
                        file_count: 1,
                        size_per_dir: 40,
                    },
                ],
            )
            .unwrap();

        // Everything trusted at first: both groups, full membership, trusted totals.
        let before = store.attributed_dir_group_summaries(scan_id).unwrap();
        assert_eq!(before.groups.len(), 2);
        assert_eq!(before.unverified_groups, 0);
        assert_eq!(before.trusted_reclaim_total, 100 + 80);

        // The next walk finds an omission under p1 and inside t3: p1 and t3 are now suppressed.
        store
            .commit_omissions(
                scan_id,
                &one_root(
                    "/tank",
                    &[
                        ("/tank/p1", OmissionReason::MetadataError),
                        ("/tank/t3/inner", OmissionReason::NonUtf8),
                    ],
                ),
            )
            .unwrap();

        let after = store.attributed_dir_group_summaries(scan_id).unwrap();
        assert_eq!(
            after.groups.len(),
            1,
            "PAIR fell below two members and is no group at all"
        );
        assert_eq!(after.groups[0].signature, "TRIO");
        assert_eq!(after.groups[0].dir_count, 2, "t3 is gone, t1+t2 survive");
        assert_eq!(after.groups[0].trust, DirTrust::Trusted);
        assert_eq!(
            after.trusted_reclaim_total, 40,
            "one survivor's worth of extra copies"
        );

        let batch = store.attributed_dir_groups(scan_id).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(
            batch[0].group.paths,
            vec![PathBuf::from("/tank/t1"), PathBuf::from("/tank/t2")]
        );
        assert_eq!(
            batch[0].member_trust,
            vec![DirTrust::Trusted, DirTrust::Trusted]
        );

        assert!(
            store
                .attributed_dir_group(scan_id, "PAIR")
                .unwrap()
                .is_none(),
            "opening the whittled group answers None, not a one-member claim"
        );
        let trio = store
            .attributed_dir_group(scan_id, "TRIO")
            .unwrap()
            .expect("TRIO still exists");
        assert_eq!(trio.group.paths.len(), 2);
    }

    /// A hard snapshot error surfaces from every attributed reader — never an empty list that
    /// would render as «no directory groups».
    #[test]
    fn attributed_readers_propagate_hard_snapshot_errors() {
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
            .attributed_dir_group_summaries(scan_id)
            .expect_err("an unknown reason is a hard error")
            .to_string();
        assert!(err.contains("does not know"), "{err}");
        assert!(store.attributed_dir_groups(scan_id).is_err());
        assert!(store.attributed_dir_group(scan_id, "ANY").is_err());
        assert!(store
            .attributed_dir_group_at(scan_id, &PathBuf::from("/tank/a"))
            .is_err());
        assert!(store
            .dir_signatures_under(scan_id, &[PathBuf::from("/tank/a")], DirSigAlgo::Old)
            .is_err());
    }

    /// A store with one trusted TRIO, so a single suppression can be aimed either at the cursor
    /// or at one of its twins.
    fn trio_store() -> (ScanStore, i64) {
        let (mut store, scan_id) = ledger_store(&["/tank"]);
        store
            .commit_omissions(scan_id, &one_root("/tank", &[]))
            .unwrap();
        store
            .record_dir_groups(
                scan_id,
                &[DirGroup {
                    id: 0,
                    signature: "TRIO".to_string(),
                    paths: vec![
                        PathBuf::from("/tank/t1"),
                        PathBuf::from("/tank/t2"),
                        PathBuf::from("/tank/t3"),
                    ],
                    file_count: 2,
                    size_per_dir: 60,
                }],
            )
            .unwrap();
        (store, scan_id)
    }

    /// The watch lookup obeys the same current ledger as every other attributed reader: while it
    /// is clean the cursor's group is answered whole and fully trusted, and a suppressed TWIN just
    /// disappears from the membership.
    #[test]
    fn the_watch_lookup_removes_a_suppressed_twin() {
        let (mut store, scan_id) = trio_store();
        let cursor = PathBuf::from("/tank/t1");

        let before = store
            .attributed_dir_group_at(scan_id, &cursor)
            .unwrap()
            .expect("a clean ledger answers the whole group");
        assert_eq!(before.trust, DirTrust::Trusted);
        assert_eq!(
            before.group.paths,
            vec![
                PathBuf::from("/tank/t1"),
                PathBuf::from("/tank/t2"),
                PathBuf::from("/tank/t3")
            ],
            "a fully trusted answer keeps the parent's order and values"
        );
        assert_eq!(before.member_trust, vec![DirTrust::Trusted; 3]);
        assert_eq!(before.group.file_count, 2);
        assert_eq!(before.group.size_per_dir, 60);

        // A later walk finds an omission inside t3: that twin is suppressed, the cursor is not.
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/t3/inner", OmissionReason::NonUtf8)]),
            )
            .unwrap();
        let after = store
            .attributed_dir_group_at(scan_id, &cursor)
            .unwrap()
            .expect("cursor and one twin survive");
        assert_eq!(
            after.group.paths,
            vec![PathBuf::from("/tank/t1"), PathBuf::from("/tank/t2")],
            "the suppressed twin is gone, the cursor stays"
        );
        assert_eq!(after.trust, DirTrust::Trusted);
    }

    /// A suppressed cursor is a member of nothing — and the survivors are NOT offered in its place.
    /// This is the resurrection the residual reader allowed: stored paths presented as duplicates
    /// of a directory whose own contents the ledger no longer establishes.
    #[test]
    fn a_suppressed_cursor_has_no_directory_group() {
        let (mut store, scan_id) = trio_store();
        store
            .commit_omissions(
                scan_id,
                &one_root("/tank", &[("/tank/t1", OmissionReason::MetadataError)]),
            )
            .unwrap();
        assert!(
            store
                .attributed_dir_group_at(scan_id, &PathBuf::from("/tank/t1"))
                .unwrap()
                .is_none(),
            "the surviving pair is not «duplicates of this cursor»"
        );
        // The pair itself is untouched when asked from one of its own members.
        let survivors = store
            .attributed_dir_group_at(scan_id, &PathBuf::from("/tank/t2"))
            .unwrap()
            .expect("t2 and t3 still are twins of each other");
        assert_eq!(
            survivors.group.paths,
            vec![PathBuf::from("/tank/t2"), PathBuf::from("/tank/t3")]
        );
    }

    /// Cardinality is re-evaluated after suppression: a group whittled below two members is no
    /// group at all, even for the member that survived.
    #[test]
    fn the_watch_lookup_answers_none_below_two_survivors() {
        let (mut store, scan_id) = trio_store();
        store
            .commit_omissions(
                scan_id,
                &one_root(
                    "/tank",
                    &[
                        ("/tank/t2", OmissionReason::MetadataError),
                        ("/tank/t3", OmissionReason::MetadataError),
                    ],
                ),
            )
            .unwrap();
        assert!(
            store
                .attributed_dir_group_at(scan_id, &PathBuf::from("/tank/t1"))
                .unwrap()
                .is_none(),
            "one survivor is a claim with no twin"
        );
    }

    /// An `Unknown` member survives — inspectable — but never looks exact: it carries `Untrusted`
    /// and drags the aggregate down with it.
    #[test]
    fn an_unknown_member_survives_the_watch_lookup_as_untrusted() {
        let (mut store, scan_id) = trio_store();
        // The authority is gone: nothing is suppressed, and nothing is vouched for either.
        store.clear_scan_omissions(scan_id).unwrap();
        let group = store
            .attributed_dir_group_at(scan_id, &PathBuf::from("/tank/t1"))
            .unwrap()
            .expect("an unverified group stays inspectable");
        assert_eq!(group.trust, DirTrust::Untrusted);
        assert_eq!(group.member_trust, vec![DirTrust::Untrusted; 3]);
    }

    /// Typed live trust, all three states in one scan: a suppressed directory is absent, a
    /// trusted one carries `Trusted`, and after the authority is zeroed the same signature comes
    /// back `Untrusted` — inspectable, never exact-looking.
    #[test]
    fn live_signatures_carry_the_ledger_trust() {
        let (mut store, scan_id) = ledger_store(&["/x"]);
        store
            .record_files(
                scan_id,
                &[
                    row("/x/a/f1", 100, 1),
                    row("/x/b/f1", 100, 2),
                    row("/x/c/f1", 100, 3),
                ],
            )
            .unwrap();
        let h = [7u8; 32];
        store
            .record_hashes(
                scan_id,
                &[
                    (PathBuf::from("/x/a/f1"), h),
                    (PathBuf::from("/x/b/f1"), h),
                    (PathBuf::from("/x/c/f1"), h),
                ],
            )
            .unwrap();
        // The walk saw an omission under /x/c: it is suppressed; /x/a and /x/b stay whole.
        store
            .commit_omissions(
                scan_id,
                &one_root("/x", &[("/x/c", OmissionReason::MetadataError)]),
            )
            .unwrap();

        let dirs = [
            PathBuf::from("/x/a"),
            PathBuf::from("/x/b"),
            PathBuf::from("/x/c"),
        ];
        let live = store
            .dir_signatures_under(scan_id, &dirs, DirSigAlgo::Old)
            .unwrap();
        let a = live.get(Path::new("/x/a")).expect("/x/a is whole");
        assert_eq!(a.trust, DirTrust::Trusted);
        assert_eq!(
            live.get(Path::new("/x/b")).map(|l| &l.signature),
            Some(&a.signature),
            "the twins share a signature"
        );
        assert!(
            !live.contains_key(Path::new("/x/c")),
            "a suppressed directory emits nothing"
        );

        // The same store, its authority zeroed: the signature survives, its trust does not.
        store.clear_scan_omissions(scan_id).unwrap();
        let untrusted = store
            .dir_signatures_under(scan_id, &dirs, DirSigAlgo::Old)
            .unwrap();
        let a = untrusted.get(Path::new("/x/a")).expect("still inspectable");
        assert_eq!(
            a.trust,
            DirTrust::Untrusted,
            "an Unknown signature must never look exact"
        );
        assert!(
            untrusted.contains_key(Path::new("/x/c")),
            "nothing suppresses /x/c once the ledger is gone — it is merely untrusted"
        );
    }

    /// Root bounding on the live path: a bounded scan emits nothing above its selected root —
    /// the same above-root loss the materialized output accepted — while an unkeyable
    /// configuration keeps today's unbounded output, everything untrusted.
    #[test]
    fn live_signatures_are_root_bounded_exactly_like_the_builders() {
        let (mut store, scan_id) = ledger_store(&["/x/root"]);
        store
            .record_files(scan_id, &[row("/x/root/a/f1", 100, 1)])
            .unwrap();
        store
            .record_hashes(scan_id, &[(PathBuf::from("/x/root/a/f1"), [7u8; 32])])
            .unwrap();
        store
            .commit_omissions(scan_id, &one_root("/x/root", &[]))
            .unwrap();
        let live = store
            .dir_signatures_under(
                scan_id,
                &[PathBuf::from("/x"), PathBuf::from("/x/root/a")],
                DirSigAlgo::Old,
            )
            .unwrap();
        assert!(
            !live.contains_key(Path::new("/x")),
            "above the selected root there is no live signature"
        );
        assert!(live.contains_key(Path::new("/x/root/a")));

        // The unkeyable configuration: `..` in the root. The scan keeps its legacy output.
        let mut store = ScanStore::open_in_memory().unwrap();
        let config = ScanConfig::new(vec![PathBuf::from("/x/other/../root")]);
        let scan_id = store.begin_scan(&config).unwrap();
        store
            .record_files(scan_id, &[row("/x/root/a/f1", 100, 1)])
            .unwrap();
        store
            .record_hashes(scan_id, &[(PathBuf::from("/x/root/a/f1"), [7u8; 32])])
            .unwrap();
        let live = store
            .dir_signatures_under(
                scan_id,
                &[PathBuf::from("/x"), PathBuf::from("/x/root/a")],
                DirSigAlgo::Old,
            )
            .unwrap();
        let above = live
            .get(Path::new("/x"))
            .expect("the legacy context keeps the above-root signature");
        assert_eq!(above.trust, DirTrust::Untrusted);
        assert_eq!(
            live.get(Path::new("/x/root/a")).map(|l| l.trust),
            Some(DirTrust::Untrusted),
            "nothing is trusted without an authority"
        );
    }
}

/// R4B-1: the staged membership authority. Everything here exercises APIs no production route
/// calls yet — the switch is R4B-2 — so these tests ARE the only callers today.
#[cfg(test)]
mod membership_staging_tests {
    use super::*;
    use crate::model::plan::{GroupWitness, PlanWitness};
    use crate::model::scan::ScanConfig;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "dedcom_membership_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A manifest row carrying the real identity of an existing file — the plan and reclaim
    /// authorities compare against `stat`, so synthetic rows would not do.
    fn manifest_row(path: &Path) -> ManifestRow {
        let meta = std::fs::symlink_metadata(path).unwrap();
        ManifestRow {
            path: path.to_path_buf(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            device: meta.dev(),
            inode: meta.ino(),
            nlink: meta.nlink(),
        }
    }

    /// A scan whose manifest is `files`, each carrying the supplied digest.
    fn seed(store: &mut ScanStore, root: &Path, files: &[(PathBuf, [u8; 32])]) -> i64 {
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![root.to_path_buf()]))
            .unwrap();
        let rows: Vec<ManifestRow> = files.iter().map(|(path, _)| manifest_row(path)).collect();
        store.record_files(scan_id, &rows).unwrap();
        let hashes: Vec<(PathBuf, [u8; 32])> = files.to_vec();
        store.record_hashes(scan_id, &hashes).unwrap();
        scan_id
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn member_paths(group: &ResolvedGroup) -> Vec<PathBuf> {
        group.members.iter().map(|f| f.path.clone()).collect()
    }

    /// The witness a plan over `ids` would carry, taken from the resolver itself.
    fn witness_of(snapshot: &MembershipSnapshot<'_>, ids: &[GroupId]) -> PlanWitness {
        let groups: Vec<GroupWitness> = ids
            .iter()
            .map(|id| {
                let resolved = snapshot.group(id).expect("the witnessed group resolves");
                GroupWitness {
                    id: *id,
                    digest: resolved.summary.hash.clone(),
                    members: member_paths(&resolved),
                }
            })
            .collect();
        PlanWitness {
            scan_id: ids[0].scan_id,
            generation: ids[0].generation,
            groups,
        }
    }

    const OUT_OF_DOMAIN: &str = "— not in the domain this build can read. Nothing was written.";

    /// A real published scan of one group, damaged in exactly one summary cell, and the refusal
    /// that damage produces. Real because the refusal has to be the one an export would hit.
    fn refusal_for(tag: &str, damage: &str) -> String {
        let dir = temp_dir(tag);
        let digest = [7u8; 32];
        let a = write(&dir, "a.bin", b"same");
        let b = write(&dir, "b.bin", b"same");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        store.conn.execute_batch(damage).unwrap();

        let miss = match store.membership_snapshot(scan_id) {
            Ok(_) => panic!("a summary cell outside its domain must refuse"),
            Err(miss) => miss,
        };
        std::fs::remove_dir_all(&dir).ok();
        match miss {
            MembershipMiss::Inconsistent { detail } => detail,
            other => panic!("the damage must be reported as inconsistent, not {other:?}"),
        }
    }

    fn assert_names(detail: &str, head: &str) {
        assert!(
            detail.starts_with(head),
            "the refusal must open with `{head}`, not `{detail}`"
        );
        assert!(
            detail.ends_with(OUT_OF_DOMAIN),
            "and close with the domain sentence: {detail}"
        );
    }

    /// §8.3 C4a–C4g require the refusal to name the CELL. Seven columns are validated here, so
    /// there are seven branches, and each one has to name itself — a single shared sentence that
    /// merely counts damaged rows tells the operator nothing about what to repair.
    #[test]
    fn a_negative_rank_names_itself_and_locates_the_row_by_rowid() {
        let detail = refusal_for("cell-rank-negative", "UPDATE file_group SET rank = -1");
        assert_names(&detail, "file_group.rank holds -1 for group rowid ");
    }

    #[test]
    fn a_hash_of_the_wrong_storage_class_names_the_hash() {
        let detail = refusal_for("cell-hash-blob", "UPDATE file_group SET hash = X'0011'");
        assert_names(&detail, "file_group.hash holds blob for group rank 0 ");
    }

    #[test]
    fn a_short_hash_names_the_hash_by_length_and_never_echoes_it() {
        let detail = refusal_for("cell-hash-short", "UPDATE file_group SET hash = 'abc'");
        assert_names(
            &detail,
            "file_group.hash holds text of length 3 that is not canonical lower-case hex \
             for group rank 0 ",
        );
        assert!(
            !detail.contains("abc"),
            "the stored text is not echoed: {detail}"
        );
    }

    /// The length alone would say nothing here — the value is 64 characters, exactly as a digest
    /// should be — so the refusal has to say what is wrong with it.
    #[test]
    fn a_hash_with_a_non_hex_character_names_the_hash() {
        let detail = refusal_for(
            "cell-hash-nonhex",
            "UPDATE file_group SET hash = 'z' || substr(hash, 2)",
        );
        assert_names(
            &detail,
            "file_group.hash holds text of length 64 that is not canonical lower-case hex \
             for group rank 0 ",
        );
    }

    #[test]
    fn a_negative_file_count_names_the_file_count() {
        let detail = refusal_for("cell-file-count", "UPDATE file_group SET file_count = -1");
        assert_names(&detail, "file_group.file_count holds -1 for group rank 0 ");
    }

    /// Each numeric branch fails two ways — a negative integer, and a cell that is not an integer
    /// at all — and the `CASE` covers both. Only the negative half had a witness; a half-branch
    /// with no test is the same gap that sent this commit back for correction.
    #[test]
    fn numeric_summary_cells_of_the_wrong_storage_class_name_themselves() {
        for (tag, cell) in [
            ("cell-file-count-text", "file_count"),
            ("cell-size-text", "size"),
            ("cell-reclaim-text", "reclaim"),
            ("cell-object-count-text", "object_count"),
        ] {
            let detail = refusal_for(tag, &format!("UPDATE file_group SET {cell} = 'x'"));
            assert_names(
                &detail,
                &format!("file_group.{cell} holds text for group rank 0 "),
            );
        }
    }

    /// C4a itself, at the layer that raises it.
    #[test]
    fn a_negative_size_names_the_size() {
        let detail = refusal_for("cell-size", "UPDATE file_group SET size = -1");
        assert_names(&detail, "file_group.size holds -1 for group rank 0 ");
    }

    #[test]
    fn a_negative_reclaim_names_the_reclaim() {
        let detail = refusal_for("cell-reclaim", "UPDATE file_group SET reclaim = -1");
        assert_names(&detail, "file_group.reclaim holds -1 for group rank 0 ");
    }

    #[test]
    fn a_negative_object_count_names_the_object_count() {
        let detail = refusal_for(
            "cell-object-count",
            "UPDATE file_group SET object_count = -1",
        );
        assert_names(
            &detail,
            "file_group.object_count holds -1 for group rank 0 ",
        );
    }

    /// `reclaim_state` is an enum, so it fails in two different ways and both must name it: an
    /// integer that is not a state prints the number, because the number IS the diagnosis.
    #[test]
    fn a_reclaim_state_outside_the_enum_names_the_value() {
        let detail = refusal_for(
            "cell-state-value",
            "UPDATE file_group SET reclaim_state = 99",
        );
        assert_names(
            &detail,
            "file_group.reclaim_state holds 99 for group rank 0 ",
        );
    }

    #[test]
    fn a_reclaim_state_of_the_wrong_storage_class_names_the_class() {
        let detail = refusal_for(
            "cell-state-text",
            "UPDATE file_group SET reclaim_state = 'x'",
        );
        assert_names(
            &detail,
            "file_group.reclaim_state holds text for group rank 0 ",
        );
    }

    /// A rank that is not an integer is the case `ORDER BY rank` cannot answer and `row.get::<i64>`
    /// would turn into a raw conversion error. Both storage classes are read as values, and the
    /// row is located by rowid because there is no rank to look it up by.
    #[test]
    fn a_rank_of_a_foreign_storage_class_is_read_as_a_value() {
        for (tag, damage, rendered) in [
            (
                "cell-rank-text",
                "UPDATE file_group SET rank = 'abc'",
                "text",
            ),
            (
                "cell-rank-blob",
                "UPDATE file_group SET rank = X'0102'",
                "blob",
            ),
        ] {
            let detail = refusal_for(tag, damage);
            assert_names(
                &detail,
                &format!("file_group.rank holds {rendered} for group rowid "),
            );
        }
    }

    /// Two damaged rows must not produce a message that depends on the order SQLite happened to
    /// return them in: the same row is named every time, and it is the one an operator can
    /// address.
    #[test]
    fn two_damaged_summaries_always_name_the_same_row() {
        let dir = temp_dir("cell-order");
        let files = [
            (write(&dir, "a.bin", b"one"), [1u8; 32]),
            (write(&dir, "b.bin", b"one"), [1u8; 32]),
            (write(&dir, "c.bin", b"two"), [2u8; 32]),
            (write(&dir, "d.bin", b"two"), [2u8; 32]),
        ];
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &files);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        store
            .conn
            .execute_batch("UPDATE file_group SET size = -1")
            .unwrap();

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..5 {
            match store.membership_snapshot(scan_id) {
                Ok(_) => panic!("two damaged summaries must refuse"),
                Err(MembershipMiss::Inconsistent { detail }) => {
                    seen.insert(detail);
                }
                Err(other) => panic!("expected an inconsistency, got {other:?}"),
            }
        }
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            seen.len(),
            1,
            "the same row must be named on every run: {seen:?}"
        );
        let detail = seen.into_iter().next().unwrap();
        assert_names(&detail, "file_group.size holds -1 for group rank 0 ");
    }

    /// Matrix: an Unknown scan can yield only a candidate view. No `ResolvedGroup`, no
    /// identity, nothing a destructive gate could accept — and the candidates are still the
    /// object rule's, not a pathname count.
    #[test]
    fn unknown_authority_yields_only_candidates() {
        let dir = temp_dir("unknown");
        let digest = [3u8; 32];
        let a = write(&dir, "a.bin", b"same");
        let b = write(&dir, "b.bin", b"same");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        assert_eq!(snapshot.mode(), MembershipMode::Unknown);
        assert_eq!(snapshot.generation(), None, "no publication, no generation");
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        assert!(matches!(snapshot.group(&id), Err(MembershipMiss::Unknown)));
        assert_eq!(snapshot.summaries().unwrap_err(), MembershipMiss::Unknown);
        assert_eq!(
            snapshot.groups_of_digest(&hex_encode(&digest)).unwrap_err(),
            MembershipMiss::Unknown
        );
        let view = snapshot
            .unknown_candidates()
            .unwrap()
            .expect("an unknown scan offers candidates");
        assert_eq!(view.candidates.len(), 1);
        assert_eq!(view.candidates[0].digest, hex_encode(&digest));
        assert_eq!(view.candidates[0].paths, 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix: an ordinary scan published derived and published explicit resolves to exactly
    /// the same members, in the same order — the switch cannot move what the operator sees.
    #[test]
    fn derived_and_explicit_resolve_identical_members() {
        let dir = temp_dir("parity");
        let digest = [9u8; 32];
        let a = write(&dir, "a.bin", b"twins");
        let b = write(&dir, "b.bin", b"twins");
        let files = [(a.clone(), digest), (b.clone(), digest)];

        let mut derived_store = ScanStore::open_in_memory().unwrap();
        let derived_scan = seed(&mut derived_store, &dir, &files);
        assert_eq!(
            derived_store
                .publish_results(derived_scan, PublishMode::Derived)
                .unwrap(),
            1,
            "the first publication is generation 1"
        );

        let mut explicit_store = ScanStore::open_in_memory().unwrap();
        let explicit_scan = seed(&mut explicit_store, &dir, &files);
        let verified = crate::pipeline::verify::verify_groups(
            explicit_store.duplicate_groups(explicit_scan).unwrap(),
        )
        .unwrap();
        assert_eq!(verified.len(), 1);
        explicit_store
            .publish_results(explicit_scan, PublishMode::Explicit(&verified))
            .unwrap();

        let derived = derived_store.membership_snapshot(derived_scan).unwrap();
        let explicit = explicit_store.membership_snapshot(explicit_scan).unwrap();
        assert_eq!(derived.mode(), MembershipMode::Derived);
        assert_eq!(explicit.mode(), MembershipMode::Explicit);

        let derived_group = derived
            .group(&GroupId {
                scan_id: derived_scan,
                rank: 0,
                generation: 1,
            })
            .unwrap();
        let explicit_group = explicit
            .group(&GroupId {
                scan_id: explicit_scan,
                rank: 0,
                generation: 1,
            })
            .unwrap();
        assert_eq!(member_paths(&derived_group), vec![a.clone(), b.clone()]);
        assert_eq!(member_paths(&explicit_group), member_paths(&derived_group));
        assert_eq!(
            derived_group.summary.file_count,
            explicit_group.summary.file_count
        );
        assert_eq!(derived_group.summary.hash, explicit_group.summary.hash);
        // Membership tests and reverse lookups agree across the modes too.
        assert!(derived.is_member(&derived_group.id, &a).unwrap());
        assert!(explicit.is_member(&explicit_group.id, &a).unwrap());
        assert_eq!(
            derived.group_of_path(&b).unwrap().map(|id| id.rank),
            Some(0)
        );
        assert_eq!(
            explicit.group_of_path(&b).unwrap().map(|id| id.rank),
            Some(0)
        );
        // A page is a stable slice of the same order.
        let page = explicit.group_page(&explicit_group.id, 1, 1).unwrap();
        assert_eq!(member_paths(&page), vec![b]);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// THE release-blocking integration: R4-V1 splits one digest into two byte populations,
    /// explicit publication gives each its own identity, and the resolver keeps them apart. A
    /// digest lookup returns both ranks; each exact group returns only its own population. A
    /// raw-digest union here would be the defect R4B exists to close.
    #[test]
    fn two_same_digest_populations_never_merge() {
        let dir = temp_dir("split");
        let digest = [11u8; 32];
        let x1 = write(&dir, "x1.bin", b"XXXX");
        let x2 = write(&dir, "x2.bin", b"XXXX");
        let y1 = write(&dir, "y1.bin", b"YYYYYY");
        let y2 = write(&dir, "y2.bin", b"YYYYYY");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(
            &mut store,
            &dir,
            &[
                (x1.clone(), digest),
                (x2.clone(), digest),
                (y1.clone(), digest),
                (y2.clone(), digest),
            ],
        );

        // The real comparator, on the real files: one candidate group in, two populations out.
        let candidates = store.duplicate_groups(scan_id).unwrap();
        assert_eq!(candidates.len(), 1, "one digest, one candidate group");
        assert_eq!(candidates[0].files.len(), 4);
        let verified = crate::pipeline::verify::verify_groups(candidates).unwrap();
        assert_eq!(verified.len(), 2, "verification split the digest");

        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        let snapshot = store.membership_snapshot(scan_id).unwrap();
        let hex = hex_encode(&digest);
        let ids = snapshot.groups_of_digest(&hex).unwrap();
        assert_eq!(ids.len(), 2, "the digest names two identities");
        assert_ne!(ids[0].rank, ids[1].rank);

        let first = snapshot.group(&ids[0]).unwrap();
        let second = snapshot.group(&ids[1]).unwrap();
        assert_eq!(first.summary.hash, hex);
        assert_eq!(second.summary.hash, hex, "both keep the shared digest");
        let first_members = member_paths(&first);
        let second_members = member_paths(&second);
        let (x_id, xs, y_id, ys) = if first_members.contains(&x1) {
            (ids[0], first_members, ids[1], second_members)
        } else {
            (ids[1], second_members, ids[0], first_members)
        };
        assert_eq!(
            xs,
            vec![x1.clone(), x2.clone()],
            "the X population, in order"
        );
        assert_eq!(
            ys,
            vec![y1.clone(), y2.clone()],
            "the Y population, in order"
        );
        assert_eq!(first.summary.file_count, 2);
        assert_eq!(second.summary.file_count, 2);
        assert_ne!(
            first.summary.size_bytes, second.summary.size_bytes,
            "each population keeps its own size"
        );
        // Neither identity answers for the other's pathnames — a digest union would.
        assert!(snapshot.is_member(&x_id, &x1).unwrap());
        assert!(!snapshot.is_member(&x_id, &y1).unwrap());
        assert!(snapshot.is_member(&y_id, &y2).unwrap());
        assert!(!snapshot.is_member(&y_id, &x2).unwrap());
        assert_eq!(snapshot.group_of_path(&x1).unwrap(), Some(x_id));
        assert_eq!(snapshot.group_of_path(&y2).unwrap(), Some(y_id));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix: a stale identity never resolves the current rank, even when the rank still
    /// exists and still holds the same files.
    #[test]
    fn a_stale_generation_never_resolves() {
        let dir = temp_dir("stale");
        let digest = [21u8; 32];
        let a = write(&dir, "a.bin", b"stale");
        let b = write(&dir, "b.bin", b"stale");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        assert_eq!(
            store
                .publish_results(scan_id, PublishMode::Derived)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .publish_results(scan_id, PublishMode::Derived)
                .unwrap(),
            2,
            "republication increments the generation"
        );

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        assert_eq!(snapshot.generation(), Some(2));
        let stale = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        assert!(matches!(
            snapshot.group(&stale),
            Err(MembershipMiss::Stale {
                expected: 1,
                found: 2
            })
        ));
        assert!(snapshot
            .group(&GroupId {
                generation: 2,
                ..stale
            })
            .is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix: summary and membership disagreeing is NAMED in the summaries, refused by the
    /// exact-group path and refused by the lease — never repaired, never averaged.
    #[test]
    fn a_summary_member_disagreement_is_named_and_refused() {
        let dir = temp_dir("disagree");
        let digest = [31u8; 32];
        let a = write(&dir, "a.bin", b"disagree");
        let b = write(&dir, "b.bin", b"disagree");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(
            &mut store,
            &dir,
            &[(a.clone(), digest), (b.clone(), digest)],
        );
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();

        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(&snapshot, &[id])
        };

        // The summary now claims three members while the membership still holds two.
        store.corrupt_directly(
            "UPDATE file_group SET file_count = 3 WHERE scan_id = ?1 AND rank = 0",
            params![scan_id],
        );

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        let summaries = snapshot.summaries().unwrap();
        assert_eq!(
            summaries.inconsistent,
            vec![id],
            "the exact identity is named, not repaired"
        );
        assert!(matches!(
            snapshot.group(&id),
            Err(MembershipMiss::Inconsistent { .. })
        ));
        drop(snapshot);
        assert!(matches!(
            store.acquire_membership_lease(&witness),
            Err(LeaseRefusal::Inconsistent { .. })
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix: a member containing LF is ONE member through publication, resolver, witness and
    /// lease — and a group of two members `a`/`b` is not the same as one member `a\nb`. This is
    /// the case a delimiter-encoded member list cannot distinguish.
    #[test]
    fn an_lf_member_stays_one_member_everywhere() {
        let dir = temp_dir("newline");
        let digest = [41u8; 32];
        let weird = write(&dir, "we\nird.bin", b"lf-payload");
        let plain = write(&dir, "plain.bin", b"lf-payload");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(
            &mut store,
            &dir,
            &[(weird.clone(), digest), (plain.clone(), digest)],
        );
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();

        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            let resolved = snapshot.group(&id).unwrap();
            assert_eq!(
                resolved.members.len(),
                2,
                "the LF name is one member, not two"
            );
            assert!(member_paths(&resolved).contains(&weird));
            let rows: i64 = store
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM file_group_member WHERE scan_id = ?1",
                    params![scan_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rows, 2, "one row per member, LF and all");
            witness_of(&snapshot, &[id])
        };
        assert!(store.acquire_membership_lease(&witness).is_ok());

        // The counter-fixture: the same concatenation spelled as two ordinary members must
        // NOT validate against the one-LF-member witness.
        let split: Vec<PathBuf> = {
            let mut base = dir.clone();
            base.push("we");
            let mut second = dir.clone();
            second.push("ird.bin");
            vec![base, second]
        };
        let mut forged = witness.clone();
        forged.groups[0].members = split;
        assert!(
            matches!(
                store.acquire_membership_lease(&forged),
                Err(LeaseRefusal::MembershipChanged { .. })
            ),
            "two members must not pass for one LF-containing member"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix: a publication that would overflow the generation refuses, and leaves the
    /// previous authority, summaries, members, totals and marker byte-identical.
    #[test]
    fn a_generation_overflow_refuses_and_changes_nothing() {
        let dir = temp_dir("overflow");
        let digest = [51u8; 32];
        let a = write(&dir, "a.bin", b"overflow");
        let b = write(&dir, "b.bin", b"overflow");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_membership SET generation = ?2 WHERE scan_id = ?1",
                params![scan_id, i64::MAX],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE file_group_member SET generation = ?2 WHERE scan_id = ?1",
                params![scan_id, i64::MAX],
            )
            .unwrap();
        let before = authority_fingerprint(&store, scan_id);

        let err = store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap_err()
            .to_string();
        assert!(err.contains("overflow"), "{err}");
        assert_eq!(
            authority_fingerprint(&store, scan_id),
            before,
            "the refused publication rolled everything back"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Everything a publication owns, as one comparable value: authority, summaries, members,
    /// the scan totals and the prepared marker.
    fn authority_fingerprint(store: &ScanStore, scan_id: i64) -> String {
        let authority: String = store
            .conn
            .query_row(
                "SELECT COALESCE((SELECT mode || '/' || generation FROM scan_membership
                                   WHERE scan_id = ?1), 'none')",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        let mut groups = store
            .conn
            .prepare(
                "SELECT rank, hash, file_count, size, reclaim, object_count, reclaim_state
                   FROM file_group WHERE scan_id = ?1 ORDER BY rank",
            )
            .unwrap();
        let summaries: Vec<String> = groups
            .query_map(params![scan_id], |row| {
                Ok(format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let mut members_stmt = store
            .conn
            .prepare(
                "SELECT group_rank, path, generation FROM file_group_member
                  WHERE scan_id = ?1 ORDER BY group_rank, path",
            )
            .unwrap();
        let members: Vec<String> = members_stmt
            .query_map(params![scan_id], |row| {
                Ok(format!(
                    "{}|{}|{}",
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let totals: String = store
            .conn
            .query_row(
                "SELECT COALESCE(reclaimable_bytes, -1) || '/' || COALESCE(reclaim_state, -1)
                        || '/' || COALESCE(results_materialized, -1)
                   FROM scan_stats WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        format!(
            "{authority}\n{}\n{}\n{totals}",
            summaries.join(","),
            members.join(",")
        )
    }

    /// Matrix: a fault AFTER the first explicit member insert rolls the whole publication
    /// back. The seam fires with a summary row and a member row already written inside the
    /// open transaction, so this proves transactional rollback rather than a preflight refusal.
    #[test]
    fn a_fault_after_the_first_member_insert_rolls_the_publication_back() {
        let dir = temp_dir("rollback");
        let digest = [61u8; 32];
        let a = write(&dir, "a.bin", b"rollback");
        let b = write(&dir, "b.bin", b"rollback");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();

        // First publication crash: nothing partial may survive, and the scan stays Unknown.
        let fault = PublishFault::armed();
        let err = store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap_err()
            .to_string();
        assert!(err.contains("injected publish fault"), "{err}");
        assert!(fault.fired(), "the seam must actually have been reached");
        drop(fault);
        assert_eq!(
            store.membership_snapshot(scan_id).unwrap().mode(),
            MembershipMode::Unknown,
            "a crashed first publication leaves no authority"
        );
        let rows: (i64, i64) = store
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM file_group WHERE scan_id = ?1),
                        (SELECT COUNT(*) FROM file_group_member WHERE scan_id = ?1)",
                params![scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rows, (0, 0), "no partial summaries, no partial members");

        // Republication crash: the PRIOR generation survives complete.
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        let before = authority_fingerprint(&store, scan_id);
        let fault = PublishFault::armed();
        assert!(store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .is_err());
        assert!(fault.fired());
        drop(fault);
        assert_eq!(
            authority_fingerprint(&store, scan_id),
            before,
            "the prior generation is preserved completely"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix: preparation validates an already-authoritative scan and does nothing to it,
    /// while a migrated legacy scan is prepared for browsing WITHOUT ever manufacturing
    /// authority — it stays Unknown until a real republish or rescan. Malformed authority is
    /// an error, not a shrug.
    #[test]
    fn preparation_never_manufactures_authority() {
        let dir = temp_dir("prepare");
        let digest = [71u8; 32];
        let a = write(&dir, "a.bin", b"prepare");
        let b = write(&dir, "b.bin", b"prepare");
        let mut store = ScanStore::open_in_memory().unwrap();

        // Legacy/migrated: completed, no authority row.
        let legacy = seed(
            &mut store,
            &dir,
            &[(a.clone(), digest), (b.clone(), digest)],
        );
        store
            .set_status(legacy, crate::model::scan::ScanStatus::Complete)
            .unwrap();
        store.prepare_legacy_for_viewing(legacy).unwrap();
        assert!(
            store.results_materialized(legacy).unwrap(),
            "browsing summaries are prepared"
        );
        let authority: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM scan_membership WHERE scan_id = ?1",
                params![legacy],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(authority, 0, "preparation invents no authority");
        assert_eq!(
            store.membership_snapshot(legacy).unwrap().mode(),
            MembershipMode::Unknown,
            "a migrated checkpoint stays browse-only"
        );

        // Already authoritative: validated and left exactly as it was.
        let published = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        store
            .publish_results(published, PublishMode::Derived)
            .unwrap();
        let before = authority_fingerprint(&store, published);
        store.prepare_legacy_for_viewing(published).unwrap();
        assert_eq!(
            authority_fingerprint(&store, published),
            before,
            "preparing an authoritative scan is a no-op"
        );

        // Malformed authority is an error on both the preparation and the snapshot paths. The
        // CHECK is suspended to seed it, because that is exactly the case the decoder must not
        // delegate to SQLite: a row written by a build without the constraint, or edited by
        // hand, arrives with the constraint no longer standing between it and the reader.
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints=1;")
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE scan_membership SET mode = 7 WHERE scan_id = ?1",
                params![published],
            )
            .unwrap();
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints=0;")
            .unwrap();
        assert!(store.prepare_legacy_for_viewing(published).is_err());
        assert!(matches!(
            store.membership_snapshot(published),
            Err(MembershipMiss::Inconsistent { .. })
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A derived scan carrying explicit member rows is corruption — the snapshot refuses it
    /// rather than ignoring the surplus, and so does preparation.
    #[test]
    fn a_derived_scan_with_member_rows_is_corruption() {
        let dir = temp_dir("derived_rows");
        let digest = [81u8; 32];
        let a = write(&dir, "a.bin", b"derived");
        let b = write(&dir, "b.bin", b"derived");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a.clone(), digest), (b, digest)]);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        let path = a.to_string_lossy().to_string();
        store
            .conn
            .execute(
                "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                 VALUES (?1, 0, ?2, 1)",
                params![scan_id, path],
            )
            .unwrap();

        assert!(matches!(
            store.membership_snapshot(scan_id),
            Err(MembershipMiss::Inconsistent { .. })
        ));
        assert!(store.prepare_legacy_for_viewing(scan_id).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    // --- the staged apply-lease opener ---

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode()
    }

    /// A published v5 checkpoint on disk, plus its scan id.
    fn on_disk_checkpoint(dir: &Path) -> (PathBuf, i64) {
        let digest = [91u8; 32];
        let a = write(dir, "a.bin", b"on-disk");
        let b = write(dir, "b.bin", b"on-disk");
        let db = dir.join("dedcom.db");
        let mut store = ScanStore::open_writable(&db).unwrap();
        let scan_id = seed(&mut store, dir, &[(a, digest), (b, digest)]);
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        (db, scan_id)
    }

    /// The opener accepts the current schema and alters NOTHING by opening: no migration, no
    /// WAL flip, no chmod, no vacuum. Foreign keys are on, `busy_timeout` is the fail-fast 0,
    /// and the file plus its WAL/SHM companions keep their modes.
    #[test]
    fn the_apply_opener_accepts_v5_and_changes_nothing() {
        let _guard = role_guard();
        let dir = temp_dir("opener_ok");
        let (db, _scan_id) = on_disk_checkpoint(&dir);
        let db_mode_before = mode_of(&db);

        let store = ScanStore::open_for_apply_lease(&db).expect("a current checkpoint opens");
        let version: i64 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, schema::SCHEMA_VERSION, "no migration happened");
        let journal: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal, "wal", "the journal mode is left as it was");
        let fk: i64 = store
            .conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign keys are enforced on this connection");
        let busy: i64 = store
            .conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy, 0, "the apply lease never queues");
        assert_eq!(
            store.membership_statement_count(),
            4,
            "opening costs exactly: FK set + FK read-back + busy_timeout + version"
        );
        // Nothing is widened. The main file keeps the exact mode it had; the WAL/SHM
        // companions — which this connection may itself materialise, since the operator's
        // store was closed and its WAL checkpointed away — inherit the main file's
        // permissions from SQLite's unix VFS, so they are asserted rather than assumed.
        assert_eq!(
            mode_of(&db),
            db_mode_before,
            "the DB file's mode is untouched"
        );
        assert_eq!(mode_of(&db) & 0o777, 0o600);
        for suffix in ["-wal", "-shm"] {
            let mut companion = db.as_os_str().to_owned();
            companion.push(suffix);
            if let Ok(meta) = std::fs::metadata(Path::new(&companion)) {
                assert_eq!(
                    meta.permissions().mode() & 0o777,
                    0o600,
                    "{suffix} must not be wider than the database itself"
                );
            }
        }

        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Path safety: an absent database is not created, a symlink is refused with its target
    /// untouched, and a directory, a FIFO with no writer and a socket are all refused —
    /// promptly, with no helper thread and no timeout.
    #[test]
    fn the_apply_opener_refuses_every_unsafe_path() {
        let _guard = role_guard();
        let dir = temp_dir("opener_paths");

        let absent = dir.join("absent.db");
        assert!(matches!(
            ScanStore::open_for_apply_lease(&absent),
            Err(LeaseRefusal::Open { .. })
        ));
        assert!(!absent.exists(), "the opener creates nothing");

        let (db, _scan_id) = on_disk_checkpoint(&dir);
        let link = dir.join("link.db");
        std::os::unix::fs::symlink(&db, &link).unwrap();
        let target_before = std::fs::metadata(&db).unwrap().len();
        assert!(matches!(
            ScanStore::open_for_apply_lease(&link),
            Err(LeaseRefusal::Open { .. })
        ));
        assert_eq!(
            std::fs::metadata(&db).unwrap().len(),
            target_before,
            "the symlink's target is untouched"
        );

        assert!(matches!(
            ScanStore::open_for_apply_lease(&dir),
            Err(LeaseRefusal::Open { .. })
        ));

        let fifo = dir.join("fifo.db");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid C string for a child of an existing directory; mode 0600.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            ScanStore::open_for_apply_lease(&fifo),
            Err(LeaseRefusal::Open { .. })
        ));

        let sock = dir.join("sock.db");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(matches!(
            ScanStore::open_for_apply_lease(&sock),
            Err(LeaseRefusal::Open { .. })
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Schema safety: v0, v4 and a future v6 are each refused BEFORE any membership SQL, with
    /// the direction's own wording, and `user_version` is left exactly as it was.
    #[test]
    fn the_apply_opener_refuses_every_other_schema() {
        let _guard = role_guard();
        let dir = temp_dir("opener_schema");
        let (db, _scan_id) = on_disk_checkpoint(&dir);

        for (seeded, expected) in [
            (0, "older schema"),
            (schema::SCHEMA_VERSION - 1, "older schema"),
            (schema::SCHEMA_VERSION + 1, "newer version"),
        ] {
            {
                let conn = Connection::open(&db).unwrap();
                conn.pragma_update(None, "user_version", seeded).unwrap();
            }
            match ScanStore::open_for_apply_lease(&db) {
                Err(LeaseRefusal::Schema { detail }) => {
                    assert!(detail.contains(expected), "v{seeded}: {detail}")
                }
                Err(other) => panic!("v{seeded} must be a schema refusal, got {other:?}"),
                Ok(_) => panic!("v{seeded} must not open at all"),
            }
            let conn = Connection::open(&db).unwrap();
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, seeded, "the refusal wrote nothing");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// An observer never takes a write lease at all — refused before the file is even opened.
    #[test]
    fn the_apply_opener_refuses_an_observer() {
        let _guard = role_guard();
        let dir = temp_dir("opener_role");
        let (db, _scan_id) = on_disk_checkpoint(&dir);
        set_observer_role(true);
        let refusal = ScanStore::open_for_apply_lease(&db);
        set_observer_role(false);
        assert_eq!(refusal.err(), Some(LeaseRefusal::ReadOnlyRole));

        std::fs::remove_dir_all(&dir).ok();
    }

    // --- the staged fail-fast membership lease ---

    /// The ordinary acquisition validates the witness and pins the statement shape: BEGIN,
    /// scan existence, authority, one validation statement (explicit) and the ROLLBACK that
    /// releases it. A derived scan spends one more — its no-member-rows assertion.
    #[test]
    fn the_lease_validates_and_releases_with_a_fixed_statement_shape() {
        let dir = temp_dir("lease_shape");
        let digest = [101u8; 32];
        let a = write(&dir, "a.bin", b"lease");
        let b = write(&dir, "b.bin", b"lease");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(&snapshot, &[id])
        };

        let before = store.membership_statement_count();
        {
            let lease = store
                .acquire_membership_lease(&witness)
                .expect("the current witness validates");
            assert_eq!(
                lease.statements_so_far() - before,
                4,
                "BEGIN + scan + authority + one explicit validation statement"
            );
        }
        assert_eq!(
            store.membership_statement_count() - before,
            5,
            "the release costs exactly the ROLLBACK"
        );

        // The same shape in derived mode, plus its own invariant statement.
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        let derived_witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(
                &snapshot,
                &[GroupId {
                    generation: 2,
                    ..id
                }],
            )
        };
        let before = store.membership_statement_count();
        {
            let lease = store.acquire_membership_lease(&derived_witness).unwrap();
            assert_eq!(
                lease.statements_so_far() - before,
                5,
                "derived adds the no-member-rows assertion"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A witness from the previous publication never takes the lease, even though the rank and
    /// its files are unchanged.
    #[test]
    fn the_lease_refuses_a_stale_generation() {
        let dir = temp_dir("lease_stale");
        let digest = [111u8; 32];
        let a = write(&dir, "a.bin", b"stale-lease");
        let b = write(&dir, "b.bin", b"stale-lease");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(
                &snapshot,
                &[GroupId {
                    scan_id,
                    rank: 0,
                    generation: 1,
                }],
            )
        };
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();

        assert_eq!(
            store.acquire_membership_lease(&witness).err(),
            Some(LeaseRefusal::Stale {
                expected: 1,
                found: 2
            })
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Corruption without a generation bump is caught by the lease, one typed refusal per
    /// distinguishable case: a substituted digest, two ranks whose summaries were swapped, a
    /// changed member set, and an absent rank.
    #[test]
    fn the_lease_refuses_corruption_without_a_generation_bump() {
        let dir = temp_dir("lease_corrupt");
        let digest = [121u8; 32];
        let a = write(&dir, "a.bin", b"corrupt");
        let b = write(&dir, "b.bin", b"corrupt");
        // A third manifest row outside the group: substituting a member for THIS pathname is a
        // membership change, while substituting one for a pathname the manifest never had is a
        // missing manifest row — two different refusals, and the fixture must not conflate them.
        let spare = write(&dir, "spare.bin", b"unrelated");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(
            &mut store,
            &dir,
            &[
                (a.clone(), digest),
                (b, digest),
                (spare.clone(), [122u8; 32]),
            ],
        );
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(&snapshot, &[id])
        };
        assert!(store.acquire_membership_lease(&witness).is_ok());

        // A member set that changed under a live authority, to a pathname the manifest does
        // hold — so the refusal is about membership, not about a missing manifest row.
        store
            .conn
            .execute(
                "UPDATE file_group_member SET path = ?2
                  WHERE scan_id = ?1 AND group_rank = 0 AND path = ?3",
                params![scan_id, spare.to_string_lossy(), a.to_string_lossy()],
            )
            .unwrap();
        assert_eq!(
            store.acquire_membership_lease(&witness).err(),
            Some(LeaseRefusal::MembershipChanged {
                path: spare.clone()
            })
        );
        store
            .conn
            .execute(
                "UPDATE file_group_member SET path = ?2
                  WHERE scan_id = ?1 AND group_rank = 0 AND path = ?3",
                params![scan_id, a.to_string_lossy(), spare.to_string_lossy()],
            )
            .unwrap();

        // A substituted digest at the planned rank.
        store
            .conn
            .execute(
                "UPDATE file_group SET hash = 'deadbeef' WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        match store.acquire_membership_lease(&witness) {
            Err(LeaseRefusal::DigestChanged { rank, found, .. }) => {
                assert_eq!(rank, 0);
                assert_eq!(found, "deadbeef");
            }
            Err(other) => panic!("a substituted digest must be DigestChanged, got {other:?}"),
            Ok(_) => panic!("a substituted digest must not take the lease"),
        }

        // The rank itself gone: the member rows follow it through the CASCADE, so what the
        // witness meets is an absent identity rather than orphaned membership.
        store
            .conn
            .execute(
                "DELETE FROM file_group WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        let orphans: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM file_group_member WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0, "the active CASCADE took the member rows too");
        assert_eq!(
            store.acquire_membership_lease(&witness).err(),
            Some(LeaseRefusal::RankMissing { rank: 0 })
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Fail-fast, proved on a real file: while another connection holds `BEGIN IMMEDIATE`, the
    /// lease returns `DatabaseBusy` at once — `busy_timeout=0`, no queue, no retry — and once
    /// that holder rolls back, the very same acquisition succeeds.
    #[test]
    fn the_lease_refuses_a_busy_database_immediately() {
        let _guard = role_guard();
        let dir = temp_dir("lease_busy");
        let (db, scan_id) = on_disk_checkpoint(&dir);
        let mut store = ScanStore::open_for_apply_lease(&db).unwrap();
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(
                &snapshot,
                &[GroupId {
                    scan_id,
                    rank: 0,
                    generation: 1,
                }],
            )
        };

        let holder = Connection::open(&db).unwrap();
        holder.execute_batch("PRAGMA busy_timeout=0;").unwrap();
        holder.execute_batch("BEGIN IMMEDIATE;").unwrap();
        assert_eq!(
            store.acquire_membership_lease(&witness).err(),
            Some(LeaseRefusal::DatabaseBusy)
        );
        holder.execute_batch("ROLLBACK;").unwrap();
        assert!(
            store.acquire_membership_lease(&witness).is_ok(),
            "the same acquisition succeeds once the writer is gone"
        );

        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The other side of the same lock: a forced publisher cannot commit while the lease is
    /// held, and can the moment it drops. This is what makes the lease a whole-batch guard
    /// rather than a check.
    #[test]
    fn a_publisher_cannot_commit_while_the_lease_is_held() {
        let _guard = role_guard();
        let dir = temp_dir("lease_publisher");
        let (db, scan_id) = on_disk_checkpoint(&dir);
        let mut store = ScanStore::open_for_apply_lease(&db).unwrap();
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(
                &snapshot,
                &[GroupId {
                    scan_id,
                    rank: 0,
                    generation: 1,
                }],
            )
        };

        let publisher = Connection::open(&db).unwrap();
        publisher.execute_batch("PRAGMA busy_timeout=0;").unwrap();
        {
            let _lease = store.acquire_membership_lease(&witness).unwrap();
            let blocked = publisher.execute_batch(
                "BEGIN IMMEDIATE; UPDATE scan_membership SET generation = 99; COMMIT;",
            );
            assert!(blocked.is_err(), "no writer may commit under the lease");
            let _ = publisher.execute_batch("ROLLBACK;");
        }
        publisher
            .execute_batch("BEGIN IMMEDIATE; UPDATE scan_membership SET generation = 99; COMMIT;")
            .expect("the same write succeeds once the lease is released");

        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A plan far past SQLite's 32766-variable ceiling validates in the SAME number of
    /// statements as a two-group plan: the witness travels as one JSON array, members come
    /// back one per row, and nothing is chunked, truncated or queried per group.
    #[test]
    fn a_forty_thousand_group_witness_validates_with_the_same_statements() {
        const GROUPS: i64 = 40_000;
        let dir = temp_dir("lease_bulk");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![dir.clone()]))
            .unwrap();
        // Seeded straight into the authority tables: this pins the lease's cost, and building
        // 40 000 real published groups would measure the publisher instead.
        {
            let tx = store.conn.transaction().unwrap();
            {
                let mut summary = tx
                    .prepare(
                        "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                                object_count, reclaim_state)
                         VALUES (?1, ?2, ?3, 2, 4096, 4096, 2, 1)",
                    )
                    .unwrap();
                let mut member = tx
                    .prepare(
                        "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                         VALUES (?1, ?2, ?3, 1)",
                    )
                    .unwrap();
                // Every member gets its manifest row, carrying its group's own digest: since
                // R4B-1a the lease re-checks manifest presence and since R4B-1c the digest
                // behind it, so a fixture missing either would be proving a refusal instead of
                // the statement count it exists to pin.
                let mut manifest = tx
                    .prepare(
                        "INSERT INTO file(scan_id, path, size, mtime, device, inode, nlink, hash)
                         VALUES (?1, ?2, 4096, 0, 1, ?3, 1, unhex(?4))",
                    )
                    .unwrap();
                for rank in 0..GROUPS {
                    let digest = format!("{rank:064x}");
                    summary.execute(params![scan_id, rank, digest]).unwrap();
                    for (index, side) in ['a', 'b'].into_iter().enumerate() {
                        let path = format!("/pool/{rank}/{side}.bin");
                        member.execute(params![scan_id, rank, path]).unwrap();
                        manifest
                            .execute(params![scan_id, path, rank * 2 + index as i64 + 1, digest])
                            .unwrap();
                    }
                }
            }
            tx.execute(
                "INSERT INTO scan_membership(scan_id, mode, generation) VALUES (?1, 2, 1)",
                params![scan_id],
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let witness = PlanWitness {
            scan_id,
            generation: 1,
            groups: (0..GROUPS)
                .map(|rank| GroupWitness {
                    id: GroupId {
                        scan_id,
                        rank,
                        generation: 1,
                    },
                    digest: format!("{rank:064x}"),
                    members: vec![
                        PathBuf::from(format!("/pool/{rank}/a.bin")),
                        PathBuf::from(format!("/pool/{rank}/b.bin")),
                    ],
                })
                .collect(),
        };

        let before = store.membership_statement_count();
        {
            let lease = store
                .acquire_membership_lease(&witness)
                .expect("40 000 groups validate");
            assert_eq!(
                lease.statements_so_far() - before,
                4,
                "the same four statements a two-group plan spends"
            );
        }

        // And it still refuses a single corrupted member among the forty thousand — the
        // substitute is a real manifest row of a different group, so what the lease meets is a
        // membership change rather than a missing manifest row.
        let mut forged = witness;
        forged.groups[39_999].members[1] = PathBuf::from("/pool/0/a.bin");
        assert!(matches!(
            store.acquire_membership_lease(&forged),
            Err(LeaseRefusal::MembershipChanged { .. })
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A witness that is malformed in itself never reaches the database: a foreign scan, a
    /// mixed generation, a negative rank, a repeated rank and an empty member list are all
    /// refused before the write lock is taken.
    #[test]
    fn a_malformed_witness_is_refused_before_the_lock() {
        let dir = temp_dir("lease_witness");
        let digest = [131u8; 32];
        let a = write(&dir, "a.bin", b"witness");
        let b = write(&dir, "b.bin", b"witness");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        let good = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(&snapshot, &[id])
        };

        let mut foreign = good.clone();
        foreign.groups[0].id.scan_id = scan_id + 1;
        let mut mixed = good.clone();
        mixed.groups[0].id.generation = 2;
        let mut negative = good.clone();
        negative.groups[0].id.rank = -1;
        let mut twice = good.clone();
        twice.groups.push(good.groups[0].clone());
        let mut empty_members = good.clone();
        empty_members.groups[0].members.clear();
        let mut no_groups = good.clone();
        no_groups.groups.clear();

        let before = store.membership_statement_count();
        for (label, witness) in [
            ("foreign scan", foreign),
            ("mixed generation", mixed),
            ("negative rank", negative),
            ("repeated rank", twice),
            ("no members", empty_members),
            ("no groups", no_groups),
        ] {
            assert!(
                matches!(
                    store.acquire_membership_lease(&witness),
                    Err(LeaseRefusal::Inconsistent { .. })
                ),
                "{label} must be refused"
            );
        }
        assert_eq!(
            store.membership_statement_count(),
            before,
            "a malformed witness costs no statement and takes no lock"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // --- R4B-1a: the fail-open paths R4B-1 left open, each red on parent `6c2e739` ---

    /// A published Explicit scan over `count` byte-identical files sharing one digest.
    fn published_explicit(tag: &str, count: usize) -> (PathBuf, ScanStore, i64, Vec<PathBuf>) {
        let dir = temp_dir(tag);
        let digest = [5u8; 32];
        let paths: Vec<PathBuf> = (0..count)
            .map(|i| write(&dir, &format!("f{i}.bin"), b"identical"))
            .collect();
        let mut store = ScanStore::open_in_memory().unwrap();
        let files: Vec<(PathBuf, [u8; 32])> = paths.iter().map(|p| (p.clone(), digest)).collect();
        let scan_id = seed(&mut store, &dir, &files);
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        assert_eq!(verified.len(), 1, "the fixture publishes one group");
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        (dir, store, scan_id, paths)
    }

    /// Moves one member row to another generation without touching the authority — the shape
    /// a partially-applied republication or a hand edit leaves behind.
    fn corrupt_member_generation(store: &ScanStore, scan_id: i64, path: &Path) {
        let changed = store.corrupt_directly(
            "UPDATE file_group_member SET generation = generation + 98
              WHERE scan_id = ?1 AND path = ?2",
            params![scan_id, path.to_string_lossy()],
        );
        assert_eq!(changed, 1, "the fixture must really corrupt one member row");
    }

    /// Red on `6c2e739`: preparation read the two authority cells and called that validation.
    /// A member of another generation must refuse it.
    #[test]
    fn preparation_refuses_a_member_of_another_generation() {
        let (dir, mut store, scan_id, paths) = published_explicit("prep_gen", 2);
        corrupt_member_generation(&store, scan_id, &paths[1]);

        let err = store
            .prepare_legacy_for_viewing(scan_id)
            .expect_err("preparation must refuse a wrong-generation member")
            .to_string();
        assert!(err.contains("generation"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Red on `6c2e739`: `group_page` validated only the rows its `LIMIT` returned, so
    /// corruption one row past the page was trusted. The whole-scan validation now refuses the
    /// page — and a valid group still pages exactly as before.
    #[test]
    fn a_page_cannot_hide_corruption_outside_its_own_rows() {
        let (dir, store, scan_id, paths) = published_explicit("page_gen", 3);
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };

        // Control first: the valid group pages stably.
        {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            let first = snapshot.group_page(&id, 0, 1).unwrap();
            let second = snapshot.group_page(&id, 1, 1).unwrap();
            assert_eq!(member_paths(&first), vec![paths[0].clone()]);
            assert_eq!(member_paths(&second), vec![paths[1].clone()]);
        }

        corrupt_member_generation(&store, scan_id, &paths[2]);
        let snapshot = store.membership_snapshot(scan_id);
        match snapshot {
            Err(MembershipMiss::Inconsistent { .. }) => {}
            Err(other) => panic!("expected Inconsistent, got {other:?}"),
            Ok(snapshot) => panic!(
                "the snapshot must refuse; instead page 0 returned {:?}",
                snapshot.group_page(&id, 0, 1).map(|g| member_paths(&g))
            ),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Red on `6c2e739`: `group_of_path` read a rank and `is_member` an existence bit, both
    /// ignoring the member's generation. Neither may vouch for it now.
    #[test]
    fn the_reverse_lookups_refuse_a_member_of_another_generation() {
        let (dir, store, scan_id, paths) = published_explicit("reverse_gen", 2);
        corrupt_member_generation(&store, scan_id, &paths[1]);

        match store.membership_snapshot(scan_id) {
            Err(MembershipMiss::Inconsistent { .. }) => {}
            Err(other) => panic!("expected Inconsistent, got {other:?}"),
            Ok(snapshot) => {
                let id = GroupId {
                    scan_id,
                    rank: 0,
                    generation: 1,
                };
                panic!(
                    "the snapshot must refuse; instead group_of_path gave {:?} and is_member {:?}",
                    snapshot
                        .group_of_path(&paths[1])
                        .map(|id| id.map(|i| i.rank)),
                    snapshot.is_member(&id, &paths[1])
                );
            }
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A member row whose manifest row is gone, a member row whose summary is gone, one
    /// pathname in two ranks (with the unique index dropped, as an externally damaged DB would
    /// have it), and an out-of-domain summary cell: each fails closed at the snapshot, so no
    /// trusted answer for the scan can exist at all.
    #[test]
    fn structural_corruption_fails_the_whole_snapshot_closed() {
        // (a) member without its manifest row.
        let (dir, mut store, scan_id, paths) = published_explicit("struct_manifest", 2);
        let deleted = store
            .conn
            .execute(
                "DELETE FROM file WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, paths[1].to_string_lossy()],
            )
            .unwrap();
        assert_eq!(deleted, 1, "the manifest row is really gone");
        assert!(matches!(
            store.membership_snapshot(scan_id),
            Err(MembershipMiss::Inconsistent { .. })
        ));
        assert!(store.prepare_legacy_for_viewing(scan_id).is_err());
        std::fs::remove_dir_all(&dir).ok();

        // (b) member without its summary — seeded with the foreign keys suspended, which is
        //     the only way this shape exists at all under a live CASCADE.
        let (dir, mut store, scan_id, _paths) = published_explicit("struct_orphan", 2);
        store
            .conn
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        store
            .conn
            .execute(
                "DELETE FROM file_group WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        store.conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let orphans: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM file_group_member WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 2, "the fixture kept orphaned member rows");
        assert!(matches!(
            store.membership_snapshot(scan_id),
            Err(MembershipMiss::Inconsistent { .. })
        ));
        assert!(store.prepare_legacy_for_viewing(scan_id).is_err());
        std::fs::remove_dir_all(&dir).ok();

        // (c) one pathname in two ranks, with the unique index dropped.
        let (dir, mut store, scan_id, paths) = published_explicit("struct_dup", 2);
        store
            .conn
            .execute_batch("DROP INDEX IF EXISTS file_group_member_by_path;")
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                        object_count, reclaim_state)
                 SELECT ?1, 1, hash, 1, size, reclaim, object_count, reclaim_state
                   FROM file_group WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                 VALUES (?1, 1, ?2, 1)",
                params![scan_id, paths[0].to_string_lossy()],
            )
            .unwrap();
        assert!(matches!(
            store.membership_snapshot(scan_id),
            Err(MembershipMiss::Inconsistent { .. })
        ));
        assert!(store.prepare_legacy_for_viewing(scan_id).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every numeric family this layer converts is checked for storage class AND domain: a
    /// negative or non-integer cell refuses instead of becoming a plausible huge unsigned
    /// value. `18446744073709551613` is what `-3 as u64` would have produced.
    #[test]
    fn out_of_domain_summary_cells_are_refused_not_cast() {
        for column in [
            "rank",
            "file_count",
            "size",
            "reclaim",
            "object_count",
            "reclaim_state",
        ] {
            let (dir, store, scan_id, _paths) = published_explicit(&format!("domain_{column}"), 2);
            // Both guards are suspended to seed the row: the CHECK because the value is out of
            // domain by construction, and the foreign key because `rank` is a parent column of
            // `file_group_member`. That is exactly the state the decoder must not delegate to
            // SQLite — a build without the constraint, or a hand edit, leaves it behind.
            store
                .conn
                .execute_batch("PRAGMA ignore_check_constraints=1; PRAGMA foreign_keys=OFF;")
                .unwrap();
            store
                .conn
                .execute(
                    &format!("UPDATE file_group SET {column} = -3 WHERE scan_id = ?1 AND rank = 0"),
                    params![scan_id],
                )
                .unwrap();
            assert!(
                matches!(
                    store.membership_snapshot(scan_id),
                    Err(MembershipMiss::Inconsistent { .. })
                ),
                "a negative {column} must be refused"
            );
            std::fs::remove_dir_all(&dir).ok();

            let (dir, store, scan_id, _paths) = published_explicit(&format!("class_{column}"), 2);
            // Both guards are suspended to seed the row: the CHECK because the value is out of
            // domain by construction, and the foreign key because `rank` is a parent column of
            // `file_group_member`. That is exactly the state the decoder must not delegate to
            // SQLite — a build without the constraint, or a hand edit, leaves it behind.
            store
                .conn
                .execute_batch("PRAGMA ignore_check_constraints=1; PRAGMA foreign_keys=OFF;")
                .unwrap();
            store
                .conn
                .execute(
                    &format!(
                        "UPDATE file_group SET {column} = x'00ff' WHERE scan_id = ?1 AND rank = 0"
                    ),
                    params![scan_id],
                )
                .unwrap();
            assert!(
                matches!(
                    store.membership_snapshot(scan_id),
                    Err(MembershipMiss::Inconsistent { .. })
                ),
                "a BLOB in {column} must be refused"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// The kept distinction: an ordinary per-group count disagreement is NOT fatal to the
    /// snapshot — `summaries()` names the exact identity — while every exact answer for that
    /// identity refuses, and preparation refuses too.
    #[test]
    fn a_count_disagreement_is_named_by_summaries_and_refused_everywhere_else() {
        let (dir, mut store, scan_id, paths) = published_explicit("count_split", 2);
        store
            .conn
            .execute(
                "UPDATE file_group SET file_count = 3 WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };

        {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            let summaries = snapshot.summaries().unwrap();
            assert_eq!(summaries.inconsistent, vec![id], "the identity is named");
            assert_eq!(summaries.groups.len(), 1, "the summary itself still reads");
            let digest = summaries.groups[0].1.hash.clone();
            // Every trusted lookup, including the digest one — a method omitted from this
            // matrix is exactly how `groups_of_digest` kept handing back a known-bad rank.
            for refused in [
                snapshot.group(&id).err(),
                snapshot.group_page(&id, 0, 1).err(),
                snapshot.group_member_count(&id).err(),
                snapshot.is_member(&id, &paths[0]).err(),
                snapshot.group_of_path(&paths[0]).err(),
                snapshot.groups_of_digest(&digest).err(),
            ] {
                assert!(
                    matches!(refused, Some(MembershipMiss::Inconsistent { .. })),
                    "every exact answer must refuse: {refused:?}"
                );
            }
        }
        assert!(store.prepare_legacy_for_viewing(scan_id).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Red on `6c2e739`: the lease joined the witnessed ranks to their member rows but never
    /// back to the manifest, so a member whose `file` row was deleted after planning still
    /// took the lease. It must refuse, before `after_lease`.
    #[test]
    fn the_lease_refuses_a_member_whose_manifest_row_was_deleted() {
        let (dir, mut store, scan_id, paths) = published_explicit("lease_manifest", 2);
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(&snapshot, &[id])
        };
        assert!(
            store.acquire_membership_lease(&witness).is_ok(),
            "the fixture's witness is valid before the corruption"
        );

        let deleted = store
            .conn
            .execute(
                "DELETE FROM file WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, paths[1].to_string_lossy()],
            )
            .unwrap();
        assert_eq!(deleted, 1);
        let (members, manifest): (i64, i64) = store
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM file_group_member WHERE scan_id = ?1),
                        (SELECT COUNT(*) FROM file WHERE scan_id = ?1)",
                params![scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (members, manifest),
            (2, 1),
            "the exact corrupt shape: two member rows, one manifest row"
        );

        match store.acquire_membership_lease(&witness) {
            Err(LeaseRefusal::Inconsistent { detail }) => {
                assert!(detail.contains("manifest"), "{detail}")
            }
            Err(other) => panic!("expected Inconsistent, got {other:?}"),
            Ok(_) => panic!("the lease must refuse a member with no manifest row"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The lease also refuses the other structural Explicit corruptions that can appear after
    /// planning without a generation bump — a member whose summary is gone, and one pathname
    /// in two ranks with the unique index dropped — without relying on an earlier resolver
    /// read or on the index still existing.
    #[test]
    fn the_lease_refuses_structural_corruption_after_planning() {
        // (a) the summary of a witnessed rank is gone while its member rows remain.
        let (dir, mut store, scan_id, _paths) = published_explicit("lease_orphan", 2);
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(&snapshot, &[id])
        };
        store
            .conn
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        store
            .conn
            .execute(
                "DELETE FROM file_group WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        store.conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        assert!(
            matches!(
                store.acquire_membership_lease(&witness),
                Err(LeaseRefusal::Inconsistent { .. })
            ),
            "member rows with no summary must refuse the lease"
        );
        std::fs::remove_dir_all(&dir).ok();

        // (b) one pathname in two ranks, unique index dropped.
        let (dir, mut store, scan_id, paths) = published_explicit("lease_dup", 2);
        let id = GroupId {
            scan_id,
            rank: 0,
            generation: 1,
        };
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(&snapshot, &[id])
        };
        store
            .conn
            .execute_batch("DROP INDEX IF EXISTS file_group_member_by_path;")
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                        object_count, reclaim_state)
                 SELECT ?1, 1, hash, 1, size, reclaim, object_count, reclaim_state
                   FROM file_group WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                 VALUES (?1, 1, ?2, 1)",
                params![scan_id, paths[0].to_string_lossy()],
            )
            .unwrap();
        match store.acquire_membership_lease(&witness) {
            Err(LeaseRefusal::Inconsistent { detail }) => {
                assert!(detail.contains("two ranks"), "{detail}")
            }
            Err(other) => panic!("expected Inconsistent, got {other:?}"),
            Ok(_) => panic!("one pathname in two ranks must refuse the lease"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- R4B-1b: the invariants the whole-authority validator was still missing ---

    /// A `reclaim_state` outside the persisted enum is not «large», it is not a state: the
    /// snapshot refuses centrally, before a reverse lookup or a membership test can answer.
    /// The positive control runs every valid state, so the stricter predicate cannot start
    /// rejecting published data.
    #[test]
    fn a_reclaim_state_outside_the_enum_is_refused_centrally() {
        for state in [
            ReclaimState::Unknown,
            ReclaimState::Exact,
            ReclaimState::UpperBound,
        ] {
            let (dir, store, scan_id, _paths) =
                published_explicit(&format!("state_ok_{}", state.as_i64()), 2);
            store
                .conn
                .execute(
                    "UPDATE file_group SET reclaim_state = ?2 WHERE scan_id = ?1 AND rank = 0",
                    params![scan_id, state.as_i64()],
                )
                .unwrap();
            assert!(
                store.membership_snapshot(scan_id).is_ok(),
                "a published reclaim state must stay readable: {state:?}"
            );
            std::fs::remove_dir_all(&dir).ok();
        }

        let (dir, store, scan_id, paths) = published_explicit("state_bad", 2);
        store
            .conn
            .execute(
                "UPDATE file_group SET reclaim_state = 99 WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        match store.membership_snapshot(scan_id) {
            Err(MembershipMiss::Inconsistent { .. }) => {}
            Err(other) => panic!("expected Inconsistent, got {other:?}"),
            Ok(snapshot) => panic!(
                "the snapshot must refuse centrally; is_member answered {:?}",
                snapshot.is_member(
                    &GroupId {
                        scan_id,
                        rank: 0,
                        generation: 1
                    },
                    &paths[0]
                )
            ),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A member path that is TEXT but empty is not a pathname. With the CHECKs suspended it
    /// otherwise satisfies manifest presence, summary, generation and count, and becomes
    /// trusted membership.
    #[test]
    fn an_empty_member_path_is_out_of_domain() {
        let (dir, store, scan_id, paths) = published_explicit("empty_path", 2);
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints=1;")
            .unwrap();
        for table in ["file", "file_group_member"] {
            store
                .conn
                .execute(
                    &format!("UPDATE {table} SET path = '' WHERE scan_id = ?1 AND path = ?2"),
                    params![scan_id, paths[1].to_string_lossy()],
                )
                .unwrap();
        }
        assert!(matches!(
            store.membership_snapshot(scan_id),
            Err(MembershipMiss::Inconsistent { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The summary digest is the domain `GroupWitness.digest` is specified to carry: canonical
    /// lower-case hex of the right length. An identity whose digest no consumer can decode is
    /// not a trusted identity — while a real published digest, of course, still reads.
    #[test]
    fn a_non_canonical_summary_digest_is_refused() {
        for (label, forged) in [
            ("empty", String::new()),
            ("short", "abcd".to_string()),
            ("upper case", "A".repeat(64)),
            ("non-hex", "z".repeat(64)),
            ("too long", "a".repeat(65)),
        ] {
            let (dir, store, scan_id, _paths) =
                published_explicit(&format!("digest_{}", label.replace(' ', "_")), 2);
            store
                .conn
                .execute(
                    "UPDATE file_group SET hash = ?2 WHERE scan_id = ?1 AND rank = 0",
                    params![scan_id, forged],
                )
                .unwrap();
            assert!(
                matches!(
                    store.membership_snapshot(scan_id),
                    Err(MembershipMiss::Inconsistent { .. })
                ),
                "a {label} digest must refuse"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// Derived membership IS the digest, so two derived summaries sharing one would put the
    /// very same manifest pathnames in two groups. Two EXPLICIT ranks sharing a digest stay
    /// legitimate — that is R4-V1's split populations, asserted right here so the new rule
    /// cannot quietly outlaw them.
    #[test]
    fn derived_authority_refuses_two_ranks_with_one_digest() {
        let dir = temp_dir("derived_dup");
        let digest = [9u8; 32];
        let a = write(&dir, "a.bin", b"twins");
        let b = write(&dir, "b.bin", b"twins");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        assert!(store.membership_snapshot(scan_id).is_ok(), "the control");

        store
            .conn
            .execute(
                "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                        object_count, reclaim_state)
                 SELECT ?1, 1, hash, file_count, size, reclaim, object_count, reclaim_state
                   FROM file_group WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        store.revoke_membership_cache(); // the INSERT above bypassed every legitimate writer
        match store.membership_snapshot(scan_id) {
            Err(MembershipMiss::Inconsistent { detail }) => {
                assert!(detail.contains("two group summaries"), "{detail}")
            }
            Err(other) => panic!("expected Inconsistent, got {other:?}"),
            Ok(_) => panic!("two derived ranks with one digest must refuse"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The same shape appearing AFTER planning must refuse the final lease — the plan's own
    /// rank still validates perfectly, which is exactly why the check has to be there.
    #[test]
    fn the_derived_lease_refuses_a_duplicate_digest_added_after_planning() {
        let dir = temp_dir("derived_lease_dup");
        let digest = [10u8; 32];
        let a = write(&dir, "a.bin", b"twins");
        let b = write(&dir, "b.bin", b"twins");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(
                &snapshot,
                &[GroupId {
                    scan_id,
                    rank: 0,
                    generation: 1,
                }],
            )
        };
        assert!(
            store.acquire_membership_lease(&witness).is_ok(),
            "the witness is valid before the duplicate exists"
        );

        store
            .conn
            .execute(
                "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim,
                                        object_count, reclaim_state)
                 SELECT ?1, 1, hash, file_count, size, reclaim, object_count, reclaim_state
                   FROM file_group WHERE scan_id = ?1 AND rank = 0",
                params![scan_id],
            )
            .unwrap();
        match store.acquire_membership_lease(&witness) {
            Err(LeaseRefusal::Inconsistent { detail }) => {
                assert!(detail.contains("two group summaries"), "{detail}")
            }
            Err(other) => panic!("expected Inconsistent, got {other:?}"),
            Ok(_) => panic!("a duplicate derived digest must refuse the lease"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The final lease re-establishes the selected member's manifest digest itself. Mutating
    /// only `file.hash` leaves the member path, the member row, the summary, the authority,
    /// the generation and the witness identical, so the member-set comparison cannot see it —
    /// and the resolver's earlier word is exactly what a pre-destructive gate may not inherit.
    /// Each shape asserts what was actually stored, so a failed UPDATE cannot fake a pass.
    #[test]
    fn the_lease_rechecks_the_selected_manifest_digest_after_planning() {
        for (label, forged) in [
            ("another valid-length blob", Value::Blob(vec![6u8; 32])),
            ("null", Value::Null),
            ("non-blob", Value::Text("not a digest".into())),
            ("wrong length", Value::Blob(vec![5u8; 16])),
        ] {
            let (dir, mut store, scan_id, paths) = published_explicit(&label.replace(' ', "_"), 2);
            let witness = {
                let snapshot = store.membership_snapshot(scan_id).unwrap();
                witness_of(
                    &snapshot,
                    &[GroupId {
                        scan_id,
                        rank: 0,
                        generation: 1,
                    }],
                )
            };
            assert!(
                store.acquire_membership_lease(&witness).is_ok(),
                "the control lease succeeds before the mutation ({label})"
            );

            store.corrupt_directly(
                "UPDATE file SET hash = ?3 WHERE scan_id = ?1 AND path = ?2",
                params![scan_id, paths[1].to_string_lossy(), forged],
            );
            let (class, length): (String, Option<i64>) = store
                .conn
                .query_row(
                    "SELECT typeof(hash), length(hash) FROM file
                      WHERE scan_id = ?1 AND path = ?2",
                    params![scan_id, paths[1].to_string_lossy()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let stored = (class.as_str(), length);
            match label {
                "another valid-length blob" => assert_eq!(stored, ("blob", Some(32))),
                "null" => assert_eq!(stored, ("null", None)),
                "non-blob" => assert_eq!(class.as_str(), "text"),
                "wrong length" => assert_eq!(stored, ("blob", Some(16))),
                other => panic!("unlisted case {other}"),
            }

            assert!(
                matches!(
                    store.membership_snapshot(scan_id),
                    Err(MembershipMiss::Inconsistent { .. })
                ),
                "the resolver calls it inconsistent ({label})"
            );
            match store.acquire_membership_lease(&witness) {
                Err(LeaseRefusal::Inconsistent { detail }) => assert!(
                    detail.contains("digest"),
                    "the refusal names the digest, not the missing row: {detail}"
                ),
                Err(other) => panic!("expected Inconsistent, got {other:?} ({label})"),
                Ok(_) => panic!("the lease must reject the foreign manifest digest ({label})"),
            }
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    // --- R4B-CACHE-1: the connection-local validation cache and path-identity refusal ---

    /// A file-backed published Explicit scan: the cache and the path-identity check both need a
    /// real file, which `open_in_memory` has no way to provide.
    fn published_on_disk(tag: &str) -> (PathBuf, PathBuf, ScanStore, i64, Vec<PathBuf>) {
        let dir = temp_dir(tag);
        let db_path = dir.join("dedcom.db");
        let digest = [5u8; 32];
        let paths: Vec<PathBuf> = (0..2)
            .map(|i| write(&dir, &format!("f{i}.bin"), b"identical"))
            .collect();
        let mut store = ScanStore::open_writable(&db_path).unwrap();
        let files: Vec<(PathBuf, [u8; 32])> = paths.iter().map(|p| (p.clone(), digest)).collect();
        let scan_id = seed(&mut store, &dir, &files);
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        (dir, db_path, store, scan_id, paths)
    }

    /// Takes and drops one snapshot, returning whether it was trusted.
    /// Members of the group carrying a digest, through the authority — this module's own copy
    /// of the reader, so it stays independent of the other test module's fixtures.
    fn members_by_digest(store: &ScanStore, scan_id: i64, hash_hex: &str) -> Vec<FileEntry> {
        let snapshot = store
            .membership_snapshot(scan_id)
            .expect("a published scan");
        let ids = snapshot
            .groups_of_digest(hash_hex)
            .expect("a digest lookup");
        match ids.first() {
            Some(id) => snapshot.group(id).expect("the group resolves").members,
            None => Vec::new(),
        }
    }

    fn snap_ok(store: &ScanStore, scan_id: i64) -> bool {
        store.membership_snapshot(scan_id).is_ok()
    }

    /// Evidence 1 and 5: an unchanged store validates once however many snapshots are taken,
    /// and an ordinary `file_mark` write on that same store — which cannot change membership —
    /// does not cost a revalidation.
    #[test]
    fn an_unchanged_store_validates_once_and_marks_do_not_revalidate() {
        let _guard = role_guard();
        let (dir, _db, mut store, scan_id, paths) = published_on_disk("cache_once");
        for _ in 0..8 {
            assert!(snap_ok(&store, scan_id));
        }
        assert_eq!(
            store.full_validation_count(),
            1,
            "one epoch, one full validation"
        );

        let mut marked = members_by_digest(
            &store,
            scan_id,
            &[5u8; 32].iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            }),
        );
        assert_eq!(marked.len(), 2, "the fixture's group is readable");
        marked[0].is_keeper = true;
        store.save_marks(scan_id, marked.iter()).unwrap();
        assert!(snap_ok(&store, scan_id));
        assert_eq!(
            store.full_validation_count(),
            1,
            "a mark is intent, not membership — no revalidation"
        );
        assert!(paths.len() == 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Evidence 2: a second connection changing the manifest digest, a member row, a summary or
    /// the authority is seen by the token, so the next request cannot reuse the old trust.
    #[test]
    fn a_second_connection_write_forces_revalidation() {
        for (label, sql) in [
            (
                "manifest digest",
                "UPDATE file SET hash = X'0102' WHERE scan_id = ?1",
            ),
            (
                "member row",
                "UPDATE file_group_member SET generation = 9 WHERE scan_id = ?1",
            ),
            (
                "summary",
                "UPDATE file_group SET file_count = 9 WHERE scan_id = ?1",
            ),
            (
                "authority",
                "UPDATE scan_membership SET generation = 9 WHERE scan_id = ?1",
            ),
        ] {
            let _guard = role_guard();
            let (dir, db, store, scan_id, _paths) =
                published_on_disk(&format!("cache_ext_{}", label.replace(' ', "_")));
            assert!(snap_ok(&store, scan_id));
            assert_eq!(store.full_validation_count(), 1);
            {
                let other = ScanStore::open_writable(&db).unwrap();
                other
                    .conn
                    .execute_batch("PRAGMA ignore_check_constraints=1;")
                    .unwrap();
                other.conn.execute(sql, params![scan_id]).unwrap();
            }
            let _ = store.membership_snapshot(scan_id);
            assert_eq!(
                store.full_validation_count(),
                2,
                "an external {label} change must not reuse the old verdict"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// Evidence 3: the concrete same-store membership writers revoke before their own write —
    /// the token cannot see them, so nothing else would.
    #[test]
    fn same_store_membership_writers_revoke_before_writing() {
        let _guard = role_guard();
        let (dir, _db, mut store, scan_id, _paths) = published_on_disk("cache_writers");
        assert!(snap_ok(&store, scan_id));
        assert_eq!(store.full_validation_count(), 1);

        // Each writer is checked twice: the slot is empty the instant it returns (the
        // revocation happened before its write, not after its commit), and the next snapshot
        // really re-runs the validator.
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        assert!(
            store.membership_cache.borrow().is_none(),
            "publication revoked"
        );
        assert!(snap_ok(&store, scan_id));
        assert_eq!(store.full_validation_count(), 2);

        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();
        assert!(
            store.membership_cache.borrow().is_none(),
            "materialization revoked"
        );
        assert!(snap_ok(&store, scan_id));
        assert_eq!(store.full_validation_count(), 3);

        // `clear_files` takes the authority with the manifest, so the scan reads Unknown
        // afterwards — the point here is that the slot is empty before that write lands.
        store.clear_files(scan_id).unwrap();
        assert!(
            store.membership_cache.borrow().is_none(),
            "clear_files revoked"
        );
        assert!(matches!(
            store.membership_snapshot(scan_id).map(|s| s.mode()),
            Ok(MembershipMode::Unknown)
        ));
        assert_eq!(
            store.full_validation_count(),
            3,
            "an authority that no longer exists validates nothing"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Evidence 4: revocation happens before the attempt, so a write that fails mid-transaction
    /// and rolls back cannot leave the previous verdict standing.
    #[test]
    fn a_rolled_back_write_does_not_resurrect_the_cache() {
        let _guard = role_guard();
        let (dir, _db, mut store, scan_id, _paths) = published_on_disk("cache_rollback");
        assert!(snap_ok(&store, scan_id));
        assert_eq!(store.full_validation_count(), 1);

        let fault = ClearFault::armed();
        assert!(
            store.clear_files(scan_id).is_err(),
            "the injected fault fails the write"
        );
        assert!(fault.fired(), "the seam was actually reached");
        drop(fault);
        // The rows are back (rollback), and the verdict is not.
        assert!(snap_ok(&store, scan_id), "the rollback restored the rows");
        assert_eq!(
            store.full_validation_count(),
            2,
            "the cache was revoked before the attempt and never restored by it"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Evidence 6 and 7: replacing, removing, symlinking or retyping the database path makes the
    /// old connection refuse with the typed reopen-required miss even though its cache was hot —
    /// it must never answer from the orphaned inode — and a verified reopen recovers with
    /// exactly one validation.
    #[test]
    fn a_replaced_database_path_refuses_until_a_verified_reopen() {
        for label in ["replaced", "removed", "symlinked", "directory"] {
            let _guard = role_guard();
            let (dir, db, store, scan_id, _paths) = published_on_disk(&format!("cache_id_{label}"));
            assert!(snap_ok(&store, scan_id), "hot cache first");
            assert_eq!(store.full_validation_count(), 1);

            let spare = dir.join("spare.db");
            std::fs::copy(&db, &spare).unwrap();
            std::fs::remove_file(&db).unwrap();
            match label {
                "replaced" => std::fs::rename(&spare, &db).unwrap(),
                "removed" => {}
                "symlinked" => std::os::unix::fs::symlink(&spare, &db).unwrap(),
                "directory" => std::fs::create_dir(&db).unwrap(),
                other => panic!("unlisted case {other}"),
            }

            match store.membership_snapshot(scan_id) {
                Err(MembershipMiss::ReopenRequired { .. }) => {}
                Err(other) => panic!("expected ReopenRequired, got {other:?} ({label})"),
                Ok(_) => panic!("the orphaned connection must not answer ({label})"),
            }
            assert_eq!(
                store.full_validation_count(),
                1,
                "the refusal happens before any membership read ({label})"
            );
            drop(store);

            if label == "replaced" {
                let reopened = ScanStore::open_writable(&db).unwrap();
                assert!(snap_ok(&reopened, scan_id), "a verified reopen recovers");
                assert_eq!(
                    reopened.full_validation_count(),
                    1,
                    "and pays exactly one validation"
                );
            }
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// Evidence 8, 9 and 10: `Unknown` is never cached as authority, a deterministic
    /// inconsistency is, a transient store failure is not, and a cache entry is bound to its own
    /// scan id.
    #[test]
    fn only_deterministic_verdicts_are_cached() {
        let _guard = role_guard();
        let (dir, _db, mut store, scan_id, _paths) = published_on_disk("cache_policy");

        // Unknown: a scan with no authority row. Every request re-asks; nothing is promoted.
        let other_scan = seed(&mut store, &dir, &[]);
        for _ in 0..3 {
            assert!(matches!(
                store.membership_snapshot(other_scan).map(|s| s.mode()),
                Ok(MembershipMode::Unknown)
            ));
        }
        assert_eq!(
            store.full_validation_count(),
            0,
            "Unknown validates nothing and caches nothing"
        );

        // A deterministic inconsistency IS cached: the second request reuses the refusal. A
        // domain violation is used rather than a count disagreement, because the latter is
        // reported by identity instead of refusing the snapshot.
        store.corrupt_directly(
            "UPDATE file_group SET reclaim_state = 99 WHERE scan_id = ?1",
            params![scan_id],
        );
        assert!(matches!(
            store.membership_snapshot(scan_id),
            Err(MembershipMiss::Inconsistent { .. })
        ));
        let after_first = store.full_validation_count();
        assert!(matches!(
            store.membership_snapshot(scan_id),
            Err(MembershipMiss::Inconsistent { .. })
        ));
        assert_eq!(
            store.full_validation_count(),
            after_first,
            "a deterministic refusal is a verdict, not a retry"
        );

        // The policy itself, stated where a caller can see it: a transient store failure and an
        // Unknown result never become entries, whatever the key.
        let integrity = AuthorityIntegrity::default();
        store.revoke_membership_cache();
        store.remember_integrity(
            scan_id,
            MembershipMode::Explicit,
            1,
            7,
            &Err(MembershipMiss::Store {
                detail: "disk hiccup".into(),
            }),
        );
        assert!(
            store.membership_cache.borrow().is_none(),
            "a transient failure is retried, never cached"
        );
        store.remember_integrity(scan_id, MembershipMode::Unknown, 0, 7, &Ok(integrity));
        assert!(
            store.membership_cache.borrow().is_none(),
            "Unknown is the absence of authority, not a cached authority"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The single slot belongs to one scan at a time: snapshotting A, then B, then A again
    /// validates three times, and each answer is that scan's own — an entry never answers for
    /// another scan id, and the replacement is what makes the third validation necessary.
    #[test]
    fn one_slot_cannot_answer_for_two_scans() {
        let _guard = role_guard();
        let dir = temp_dir("cache_two_scans");
        let db_path = dir.join("dedcom.db");
        let mut store = ScanStore::open_writable(&db_path).unwrap();

        // Two authoritative scans on one store, with different member counts so a swapped
        // answer could not pass unnoticed.
        let mut publish = |tag: &str, count: usize| -> (i64, Vec<PathBuf>) {
            let paths: Vec<PathBuf> = (0..count)
                .map(|i| write(&dir, &format!("{tag}{i}.bin"), tag.as_bytes()))
                .collect();
            let digest = [tag.as_bytes()[0]; 32];
            let files: Vec<(PathBuf, [u8; 32])> =
                paths.iter().map(|p| (p.clone(), digest)).collect();
            let scan_id = seed(&mut store, &dir, &files);
            let verified =
                crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                    .unwrap();
            store
                .publish_results(scan_id, PublishMode::Explicit(&verified))
                .unwrap();
            (scan_id, paths)
        };
        let (scan_a, paths_a) = publish("a", 2);
        let (scan_b, paths_b) = publish("b", 3);

        let members = |store: &ScanStore, scan_id: i64| -> Vec<PathBuf> {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            let summaries = snapshot.summaries().unwrap();
            assert_eq!(summaries.groups.len(), 1, "each scan publishes one group");
            let id = summaries.groups[0].0;
            member_paths(&snapshot.group(&id).expect("the group resolves"))
        };

        let baseline = store.full_validation_count();
        assert_eq!(members(&store, scan_a), paths_a, "A answers for A");
        assert_eq!(
            store.full_validation_count() - baseline,
            1,
            "A validated once"
        );
        assert_eq!(members(&store, scan_b), paths_b, "B answers for B");
        assert_eq!(
            store.full_validation_count() - baseline,
            2,
            "B could not reuse A's entry"
        );
        assert_eq!(members(&store, scan_a), paths_a, "A still answers for A");
        assert_eq!(
            store.full_validation_count() - baseline,
            3,
            "and A could not reuse B's entry either"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A transient store failure is retried, not remembered: the first request fails, leaves
    /// the slot empty, and the second runs the full validator again and succeeds.
    #[test]
    fn a_transient_validator_failure_is_retried_not_cached() {
        let _guard = role_guard();
        let (dir, _db, store, scan_id, _paths) = published_on_disk("cache_retry");
        let baseline = store.full_validation_count();

        let fault = ValidatorFault::armed("injected disk hiccup");
        match store.membership_snapshot(scan_id) {
            Err(MembershipMiss::Store { detail }) => {
                assert!(detail.contains("injected disk hiccup"), "{detail}")
            }
            Err(other) => panic!("expected Store, got {other:?}"),
            Ok(_) => panic!("the injected fault must fail the request"),
        }
        assert!(fault.fired(), "the seam was really reached");
        drop(fault);
        assert!(
            store.membership_cache.borrow().is_none(),
            "a transient failure leaves nothing behind"
        );
        assert_eq!(
            store.full_validation_count() - baseline,
            1,
            "one attempted validation"
        );

        assert!(
            snap_ok(&store, scan_id),
            "the retry succeeds on unchanged data"
        );
        assert_eq!(
            store.full_validation_count() - baseline,
            2,
            "the retry ran the validator again rather than reusing a refusal"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The bracket closes before anything else: a pathname swapped at the exact instant after
    /// SQLite opened must be refused before WAL setup, migration or the 0600 chmod can act on
    /// the replacement.
    #[test]
    fn a_path_swapped_during_open_is_refused_before_any_side_effect() {
        let _guard = role_guard();
        let dir = temp_dir("open_race");
        let db_path = dir.join("dedcom.db");
        drop(ScanStore::open_writable(&db_path).unwrap());

        // A different, deliberately untouched regular database file, with a mode no opener
        // would leave behind.
        let replacement = dir.join("other.db");
        drop(ScanStore::open_writable(&replacement).unwrap());
        for suffix in ["-wal", "-shm"] {
            std::fs::remove_file(format!("{}{suffix}", replacement.display())).ok();
        }
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before_bytes = std::fs::read(&replacement).unwrap();

        // SQLite names its journal companions after the pathname it was ASKED to open, not
        // after the inode behind it. The swap replaces `dedcom.db`, so a WAL flip against the
        // replacement would create `dedcom.db-wal`/`-shm` — checking `other.db-*` would be
        // checking names SQLite would never write.
        let sidecars: Vec<PathBuf> = ["-wal", "-shm"]
            .iter()
            .map(|suffix| PathBuf::from(format!("{}{suffix}", db_path.display())))
            .collect();
        for sidecar in &sidecars {
            std::fs::remove_file(sidecar).ok();
            assert!(
                !sidecar.exists(),
                "the fixture starts with no {} — otherwise the assertion below proves nothing",
                sidecar.display()
            );
        }

        let swap_to = replacement.clone();
        let target = db_path.clone();
        let race = OpenRace::armed(move || {
            std::fs::remove_file(&target).unwrap();
            std::fs::hard_link(&swap_to, &target).unwrap();
        });
        let refused = ScanStore::open_writable(&db_path);
        assert!(race.fired(), "the seam was really reached");
        drop(race);
        assert!(
            refused.is_err(),
            "a path replaced during the open must be refused"
        );

        // Nothing ran against the replacement: same mode, same bytes, no sidecars created.
        assert_eq!(
            std::fs::metadata(&replacement)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640,
            "enforce_db_perms_0600 must not have reached the replacement"
        );
        assert_eq!(
            std::fs::read(&replacement).unwrap(),
            before_bytes,
            "no migration or WAL flip wrote to the replacement"
        );
        // The names SQLite would actually have created had the WAL flip run against the swapped
        // path.
        for sidecar in &sidecars {
            assert!(
                !sidecar.exists(),
                "no journal companion may be created for the swapped path: {}",
                sidecar.display()
            );
        }
        // Kept as a secondary check only: these names would never appear anyway, so they do not
        // stand in for the ones above.
        for suffix in ["-wal", "-shm"] {
            let named_after_the_inode = PathBuf::from(format!("{}{suffix}", replacement.display()));
            assert!(!named_after_the_inode.exists());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Evidence 11: a writer landing while a snapshot is open cannot produce a mixed answer —
    /// the snapshot's own transaction pins one database state, and the NEXT snapshot sees the
    /// change because the token moved.
    #[test]
    fn a_writer_mid_snapshot_cannot_mix_states() {
        let _guard = role_guard();
        let (dir, db, store, scan_id, _paths) = published_on_disk("cache_seam");
        let snapshot = store.membership_snapshot(scan_id).unwrap();
        assert!(
            snapshot.summaries().unwrap().inconsistent.is_empty(),
            "the control: this state is consistent"
        );
        // A second connection makes the summary disagree with its membership WHILE the snapshot
        // is open.
        {
            let other = ScanStore::open_writable(&db).unwrap();
            other
                .conn
                .execute(
                    "UPDATE file_group SET file_count = 9 WHERE scan_id = ?1 AND rank = 0",
                    params![scan_id],
                )
                .unwrap();
        }
        assert!(
            snapshot.summaries().unwrap().inconsistent.is_empty(),
            "the open snapshot answers from its own database state, never a mixture"
        );
        drop(snapshot);
        // And the next request sees it, because the external commit moved the token. A count
        // disagreement is the one contradiction the contract reports by identity instead of
        // refusing outright, so it surfaces in `inconsistent` rather than as an error.
        let after = store.membership_snapshot(scan_id).unwrap();
        assert_eq!(
            after.summaries().unwrap().inconsistent.len(),
            1,
            "the next snapshot names the rank the external write broke"
        );
        drop(after);
        assert_eq!(
            store.full_validation_count(),
            2,
            "the second request revalidated rather than reusing the first verdict"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Evidence 13: the wrapper paths that usually only read must not throw the cache away —
    /// that was the whole point of hooking the concrete writers instead of their callers.
    #[test]
    fn read_only_wrappers_do_not_revoke_a_hot_cache() {
        let _guard = role_guard();
        let (dir, _db, mut store, scan_id, _paths) = published_on_disk("cache_wrappers");
        assert!(snap_ok(&store, scan_id));
        assert_eq!(store.full_validation_count(), 1);

        // Already prepared: `ensure_materialized` returns at the marker.
        store.prepare_legacy_for_viewing(scan_id).unwrap();
        // Nothing pending: the loop body never runs.
        store.prepare_completed_scans().unwrap();
        // Already authoritative: preparation validates and no-ops.
        store.prepare_legacy_for_viewing(scan_id).unwrap();

        assert!(snap_ok(&store, scan_id));
        assert_eq!(
            store.full_validation_count(),
            1,
            "read-only wrapper paths keep the epoch"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Evidence 12: the apply lease is untouched by any of this — it opens its own connection,
    /// spends its own statements and consults no cache.
    #[test]
    fn the_apply_lease_is_unaffected_by_the_cache() {
        let _guard = role_guard();
        let (dir, db, store, scan_id, _paths) = published_on_disk("cache_lease");
        let witness = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            witness_of(
                &snapshot,
                &[GroupId {
                    scan_id,
                    rank: 0,
                    generation: 1,
                }],
            )
        };
        assert_eq!(store.full_validation_count(), 1);
        drop(store);

        let mut leased = ScanStore::open_for_apply_lease(&db).unwrap();
        let before = leased.membership_statement_count();
        {
            let lease = leased.acquire_membership_lease(&witness).unwrap();
            assert_eq!(
                lease.statements_so_far() - before,
                4,
                "the lease still spends its own four statements"
            );
        }
        assert_eq!(
            leased.full_validation_count(),
            0,
            "the lease never runs the resolver's validation"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An explicit member whose manifest row carries a DIFFERENT digest is a foreign import.
    /// Every other structural rule still agrees — count, generation, manifest presence,
    /// non-empty path, unique rank — which is what made this shape trusted before.
    #[test]
    fn an_explicit_member_must_carry_its_summary_digest() {
        let dir = temp_dir("foreign_member");
        let digest_a = [11u8; 32];
        let digest_b = [12u8; 32];
        let a1 = write(&dir, "a1.bin", b"aaaa");
        let a2 = write(&dir, "a2.bin", b"aaaa");
        let outsider = write(&dir, "b1.bin", b"bbbbbb");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(
            &mut store,
            &dir,
            &[
                (a1, digest_a),
                (a2.clone(), digest_a),
                (outsider.clone(), digest_b),
            ],
        );
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        assert!(store.membership_snapshot(scan_id).is_ok(), "the control");

        let moved = store.corrupt_directly(
            "UPDATE file_group_member SET path = ?2 WHERE scan_id = ?1 AND path = ?3",
            params![scan_id, outsider.to_string_lossy(), a2.to_string_lossy()],
        );
        assert_eq!(moved, 1, "one member row was redirected");
        let backed: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM file_group_member m
                   JOIN file f ON f.scan_id = m.scan_id AND f.path = m.path
                  WHERE m.scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(backed, 2, "every member still has a manifest row");

        match store.membership_snapshot(scan_id) {
            Err(MembershipMiss::Inconsistent { detail }) => {
                assert!(detail.contains("manifest digest"), "{detail}")
            }
            Err(other) => panic!("expected Inconsistent, got {other:?}"),
            Ok(_) => panic!("a member carrying another digest must refuse"),
        }
        assert!(store.prepare_legacy_for_viewing(scan_id).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    // =========================================================================================
    // R4B-2a — the typed store surface.
    // =========================================================================================

    /// A file-backed store, which is the only kind that HAS a path identity to check.
    fn file_store(dir: &Path) -> (PathBuf, ScanStore) {
        let db = dir.join("dedcom.db");
        let store = ScanStore::open_writable(&db).unwrap();
        (db, store)
    }

    /// Replaces the database file with a different regular file at the same pathname — an
    /// ordinary operator replacement, not an adversarial one.
    fn replace_db(db: &Path) {
        let spare = db.with_extension("spare");
        std::fs::write(&spare, b"not the checkpoint").unwrap();
        std::fs::remove_file(db).unwrap();
        std::fs::rename(&spare, db).unwrap();
    }

    /// Like `seed`, but with digests this build verified against the files themselves. The plan
    /// evidence constructor refuses an `identity_version = 0` row on purpose, so a fixture for
    /// anything plan-shaped has to be the verified kind.
    fn seed_verified(store: &mut ScanStore, root: &Path, files: &[(PathBuf, [u8; 32])]) -> i64 {
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![root.to_path_buf()]))
            .unwrap();
        let rows: Vec<ManifestRow> = files.iter().map(|(path, _)| manifest_row(path)).collect();
        store.record_files(scan_id, &rows).unwrap();
        let verified: Vec<(ManifestRow, [u8; 32])> = files
            .iter()
            .map(|(path, digest)| (manifest_row(path), *digest))
            .collect();
        store.record_hashes_verified(scan_id, &verified).unwrap();
        scan_id
    }

    fn published_split(dir: &Path, store: &mut ScanStore) -> (i64, PathBuf, PathBuf, PathBuf) {
        let digest = [0x5au8; 32];
        let x1 = write(dir, "x1.bin", b"XXXX");
        let x2 = write(dir, "x2.bin", b"XXXX");
        let y1 = write(dir, "y1.bin", b"YYYYYY");
        let y2 = write(dir, "y2.bin", b"YYYYYY");
        let scan_id = seed_verified(
            store,
            dir,
            &[
                (x1.clone(), digest),
                (x2.clone(), digest),
                (y1.clone(), digest),
                (y2, digest),
            ],
        );
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        assert_eq!(verified.len(), 2, "the fixture must really split");
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
        (scan_id, x1, x2, y1)
    }

    /// The cross-open replacement refusal is a TYPE, not a sentence.
    ///
    /// Red on the parent: the same swap produced `AppError::Msg`, so no caller could recognise it
    /// without reading the text — and reading it is what this whole contract forbids.
    #[test]
    fn the_cross_open_replacement_refusal_is_typed() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_typed_open");
        let db = dir.join("dedcom.db");
        drop(ScanStore::open_writable(&db).unwrap());
        let swapped = db.clone();
        let race = OpenRace::armed(move || replace_db(&swapped));
        let err = match ScanStore::open_writable(&db) {
            Err(err) => err,
            Ok(_) => panic!("a swapped path must refuse the open"),
        };
        assert!(race.fired(), "the seam must have fired");
        match err {
            AppError::PathChanged {
                ref path,
                ref detail,
            } => {
                assert!(
                    detail.contains("replaced while it was being opened"),
                    "{detail}"
                );
                assert!(path.contains("dedcom.db"), "{path}");
            }
            other => panic!("expected a typed PathChanged, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `ensure_current_path` answers by identity, and an in-memory store has no path to lose.
    #[test]
    fn ensure_current_path_answers_by_identity() {
        let _role = role_guard();
        let memory = ScanStore::open_in_memory().unwrap();
        assert!(memory.ensure_current_path().is_ok());
        assert_eq!(memory.identity_probes(), 0, "no path, nothing to probe");

        let dir = temp_dir("r4b2a_identity");
        let (db, store) = file_store(&dir);
        assert!(store.ensure_current_path().is_ok());
        assert_eq!(store.identity_probes(), 1);

        replace_db(&db);
        match store.ensure_current_path() {
            Err(AppError::PathChanged { .. }) => {}
            other => panic!("a replaced database must refuse: {other:?}"),
        }

        std::fs::remove_file(&db).unwrap();
        match store.ensure_current_path() {
            Err(AppError::PathChanged { .. }) => {}
            other => panic!("a removed database must refuse: {other:?}"),
        }
        assert_eq!(store.identity_probes(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// One membership request spends exactly ONE probe, and every new reader spends none: the
    /// snapshot already paid for the whole operation.
    #[test]
    fn a_membership_request_spends_exactly_one_probe() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_probes");
        let (_db, mut store) = file_store(&dir);
        let (scan_id, x1, _x2, _y1) = published_split(&dir, &mut store);

        let before = store.identity_probes();
        let snapshot = store.membership_snapshot(scan_id).unwrap();
        assert_eq!(
            store.identity_probes(),
            before + 1,
            "the snapshot itself is the one probe"
        );
        let ids: Vec<GroupId> = snapshot
            .summaries()
            .unwrap()
            .groups
            .iter()
            .map(|(id, _)| *id)
            .collect();
        let paths: Vec<&Path> = vec![x1.as_path()];
        snapshot.panel_files(&paths).unwrap();
        snapshot.plan_members(&ids[0]).unwrap();
        snapshot.witness_of(&ids).unwrap();
        snapshot.group_claim(&ids[0]).unwrap();
        snapshot.dir_group_at(&dir).unwrap();
        snapshot.file_info(&x1).unwrap();
        assert_eq!(
            store.identity_probes(),
            before + 1,
            "no new reader may pay a second probe"
        );
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A replaced database is refused BEFORE the write, and `file_mark` is left byte-identical.
    #[test]
    fn save_marks_settled_refuses_a_replaced_database_before_writing() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_marks_swap");
        let (db, mut store) = file_store(&dir);
        let (scan_id, x1, _x2, _y1) = published_split(&dir, &mut store);
        let marks_before = mark_rows(&store, scan_id);

        replace_db(&db);
        let entry = FileEntry {
            path: x1,
            is_keeper: true,
            ..Default::default()
        };
        match store.save_marks_settled(scan_id, &[entry]) {
            Err(MarkWriteError::PathChanged { .. }) => {}
            other => panic!("a replaced database must refuse before writing: {other:?}"),
        }
        assert_eq!(
            mark_rows(&store, scan_id),
            marks_before,
            "nothing may have been written"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every `file_mark` row of a scan, for a byte-identical before/after comparison.
    fn mark_rows(store: &ScanStore, scan_id: i64) -> Vec<(String, Value, Value)> {
        let mut stmt = store
            .conn
            .prepare(
                "SELECT path, is_keeper, action FROM file_mark WHERE scan_id = ?1 ORDER BY path",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![scan_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Value>(1)?,
                    row.get::<_, Value>(2)?,
                ))
            })
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    }

    /// The after-image is what the DATABASE holds, read inside the same transaction as the write.
    #[test]
    fn save_marks_settled_returns_the_same_transaction_after_image() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_marks_after");
        let (_db, mut store) = file_store(&dir);
        let (scan_id, x1, x2, _y1) = published_split(&dir, &mut store);

        let keeper = FileEntry {
            path: x1.clone(),
            is_keeper: true,
            ..Default::default()
        };
        let target = FileEntry {
            path: x2.clone(),
            action: Some(ActionKind::Delete),
            ..Default::default()
        };
        let after = store
            .save_marks_settled(scan_id, &[keeper, target])
            .unwrap();
        assert_eq!(
            after,
            vec![
                (x1.clone(), Some(MarkIntent::Keeper)),
                (x2.clone(), Some(MarkIntent::Act(ActionKind::Delete))),
            ]
        );
        // And it really is the database's own state, not the request echoed back.
        assert_eq!(mark_rows(&store, scan_id).len(), 2, "both rows are durable");

        // Clearing a mark removes the row, and the image says so.
        let cleared = FileEntry {
            path: x2.clone(),
            ..Default::default()
        };
        let after = store.save_marks_settled(scan_id, &[cleared]).unwrap();
        assert_eq!(after, vec![(x2, None)]);
        assert_eq!(mark_rows(&store, scan_id).len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The three refusals that happen before or instead of a durable write.
    #[test]
    fn save_marks_settled_refuses_contradictions_and_strangers() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_marks_refuse");
        let (_db, mut store) = file_store(&dir);
        let (scan_id, x1, _x2, _y1) = published_split(&dir, &mut store);
        let before = mark_rows(&store, scan_id);

        // One pathname, two fates, in one request.
        let one = FileEntry {
            path: x1.clone(),
            is_keeper: true,
            ..Default::default()
        };
        let other = FileEntry {
            path: x1.clone(),
            action: Some(ActionKind::Delete),
            ..Default::default()
        };
        match store.save_marks_settled(scan_id, &[one, other]) {
            Err(MarkWriteError::RequestContradictsItself { path }) => assert_eq!(path, x1),
            other => panic!("expected RequestContradictsItself, got {other:?}"),
        }
        assert_eq!(mark_rows(&store, scan_id), before);

        // A pathname this scan never saw has nothing to vouch for it.
        let stranger = FileEntry {
            path: dir.join("never-scanned.bin"),
            is_keeper: true,
            ..Default::default()
        };
        match store.save_marks_settled(scan_id, &[stranger]) {
            Err(MarkWriteError::NotInManifest { path }) => {
                assert_eq!(path, dir.join("never-scanned.bin"))
            }
            other => panic!("expected NotInManifest, got {other:?}"),
        }
        assert_eq!(mark_rows(&store, scan_id), before);

        // Keeper AND action for one pathname is two incompatible fates; the strict decoder
        // catches it on the way back out, so the transaction rolls back.
        let both = FileEntry {
            path: x1.clone(),
            is_keeper: true,
            action: Some(ActionKind::Delete),
            ..Default::default()
        };
        match store.save_marks_settled(scan_id, &[both]) {
            Err(MarkWriteError::Decode(MarkDecodeError::Contradictory { path })) => {
                assert_eq!(path, x1)
            }
            other => panic!("expected a contradictory decode, got {other:?}"),
        }
        assert_eq!(
            mark_rows(&store, scan_id),
            before,
            "a refused read-back rolls the write back"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The strict decoder itself, case by case.
    ///
    /// `save_marks_settled` can only reach `Contradictory` through its own writes — it never
    /// writes an unknown action or a non-integer flag — so those cases are proved here, on the
    /// one decoder both the planner and the writer use.
    #[test]
    fn the_strict_mark_decoder_keeps_its_cases_distinct() {
        let path = Path::new("/x/a");
        let text = |s: &str| Value::Text(s.to_string());
        // No row at all.
        assert_eq!(
            decode_mark(path, false, &Value::Null, &Value::Null).unwrap(),
            None
        );
        // A row that does not exist cannot have values.
        assert!(matches!(
            decode_mark(path, false, &Value::Integer(1), &Value::Null),
            Err(MarkDecodeError::Corrupt {
                field: "is_keeper",
                ..
            })
        ));
        // A flag is 0 or 1, and nothing else.
        assert!(matches!(
            decode_mark(path, true, &Value::Integer(2), &Value::Null),
            Err(MarkDecodeError::Corrupt {
                field: "is_keeper",
                ..
            })
        ));
        assert!(matches!(
            decode_mark(path, true, &text("yes"), &Value::Null),
            Err(MarkDecodeError::Corrupt {
                field: "is_keeper",
                ..
            })
        ));
        // An identifier this build does not know is not «no action».
        assert!(matches!(
            decode_mark(path, true, &Value::Integer(0), &text("teleport")),
            Err(MarkDecodeError::Corrupt {
                field: "action",
                ..
            })
        ));
        // Two fates for one pathname.
        assert!(matches!(
            decode_mark(path, true, &Value::Integer(1), &text("delete")),
            Err(MarkDecodeError::Contradictory { .. })
        ));
        // The healthy shapes.
        assert_eq!(
            decode_mark(path, true, &Value::Integer(1), &Value::Null).unwrap(),
            Some(MarkIntent::Keeper)
        );
        assert_eq!(
            decode_mark(path, true, &Value::Integer(0), &text("delete")).unwrap(),
            Some(MarkIntent::Act(ActionKind::Delete))
        );
        assert_eq!(
            decode_mark(path, true, &Value::Integer(0), &Value::Null).unwrap(),
            None
        );
    }

    /// D3 — the inner-duplicates fallback never returns a pathname byte verification rejected.
    ///
    /// Red on the parent: `dup_files_inside` selects manifest rows whose digest appears anywhere
    /// in `file_group`, so the lone file — which `verify_groups` dropped as a population of one —
    /// comes back as a «duplicate» under Explicit authority.
    #[test]
    fn the_directory_fallback_never_returns_a_verified_rejected_member() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_rejected");
        let digest = [0x77u8; 32];
        let a = write(&dir, "a.bin", b"AAAA");
        let b = write(&dir, "b.bin", b"AAAA");
        let lonely = write(&dir, "lonely.bin", b"ZZZZZZZZ");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(
            &mut store,
            &dir,
            &[
                (a.clone(), digest),
                (b.clone(), digest),
                (lonely.clone(), digest),
            ],
        );
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        assert_eq!(verified.len(), 1, "the lone population is dropped");
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();

        // The reader that returned `lonely` here is gone: on the parent, `dup_files_inside`
        // answered from `hash IN file_group` and handed back exactly this verification-rejected
        // pathname (R4B-2c red transcript, D3). What follows is the answer that replaces it.
        let snapshot = store.membership_snapshot(scan_id).unwrap();
        match snapshot.dir_group_at(&dir).unwrap() {
            DirGroupAnswer::InnerDupes {
                members,
                total,
                truncated,
            } => {
                let paths: Vec<&PathBuf> = members.iter().map(|m| &m.path).collect();
                assert!(paths.contains(&&a) && paths.contains(&&b));
                assert!(
                    !paths.contains(&&lonely),
                    "a rejected member is not a member"
                );
                assert_eq!(total, 2);
                assert!(!truncated);
            }
            other => panic!("expected InnerDupes, got {other:?}"),
        }
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// D1/D2 — one inconsistent rank refuses the WHOLE directory answer, in both modes. It is
    /// never filtered out into a shorter list that looks entirely valid.
    #[test]
    fn an_inconsistent_rank_refuses_the_whole_directory_answer() {
        let _role = role_guard();
        for explicit in [true, false] {
            let dir = temp_dir(if explicit {
                "r4b2a_dir_x"
            } else {
                "r4b2a_dir_d"
            });
            let digest = [0x31u8; 32];
            let a = write(&dir, "a.bin", b"SAME");
            let b = write(&dir, "b.bin", b"SAME");
            let mut store = ScanStore::open_in_memory().unwrap();
            let scan_id = seed(&mut store, &dir, &[(a, digest), (b, digest)]);
            if explicit {
                let verified = crate::pipeline::verify::verify_groups(
                    store.duplicate_groups(scan_id).unwrap(),
                )
                .unwrap();
                store
                    .publish_results(scan_id, PublishMode::Explicit(&verified))
                    .unwrap();
            } else {
                store
                    .publish_results(scan_id, PublishMode::Derived)
                    .unwrap();
            }
            // A healthy control first, so the refusal below is the corruption and not the shape.
            {
                let snapshot = store.membership_snapshot(scan_id).unwrap();
                assert!(matches!(
                    snapshot.dir_group_at(&dir).unwrap(),
                    DirGroupAnswer::InnerDupes { total: 2, .. }
                ));
            }
            // The one reportable disagreement: the summary claims a count its membership does
            // not hold.
            store.corrupt_directly(
                "UPDATE file_group SET file_count = file_count + 1 WHERE scan_id = ?1",
                params![scan_id],
            );
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            match snapshot.dir_group_at(&dir) {
                Err(MembershipMiss::Inconsistent { .. }) => {}
                other => panic!("explicit={explicit}: expected a whole refusal, got {other:?}"),
            }
            drop(snapshot);
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// D4 — an Unknown scan yields typed candidates. They carry no identity and are never
    /// presented as duplicates.
    #[test]
    fn an_unknown_scan_yields_typed_candidates() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_dir_unknown");
        let digest = [0x41u8; 32];
        let a = write(&dir, "a.bin", b"SAME");
        let b = write(&dir, "b.bin", b"SAME");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(
            &mut store,
            &dir,
            &[(a.clone(), digest), (b.clone(), digest)],
        );

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        assert_eq!(snapshot.mode(), MembershipMode::Unknown);
        match snapshot.dir_group_at(&dir).unwrap() {
            DirGroupAnswer::InnerCandidates {
                paths,
                total,
                truncated,
            } => {
                assert_eq!(paths, vec![a, b]);
                assert_eq!(total, 2);
                assert!(!truncated);
            }
            other => panic!("expected InnerCandidates, got {other:?}"),
        }
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// D5 — the directory answer is capped, and says so with an exact total.
    #[test]
    fn the_directory_answer_is_capped_with_an_exact_total() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_dir_cap");
        let digest = [0x51u8; 32];
        let members = DIR_INNER_CAP + 5;
        let mut files = Vec::with_capacity(members);
        for index in 0..members {
            files.push((write(&dir, &format!("m{index:05}.bin"), b"SAME"), digest));
        }
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &files);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        match snapshot.dir_group_at(&dir).unwrap() {
            DirGroupAnswer::InnerDupes {
                members: rows,
                total,
                truncated,
            } => {
                assert_eq!(rows.len(), DIR_INNER_CAP, "the cap is exact");
                assert_eq!(total, members as u64, "the total is the real one");
                assert!(truncated);
            }
            other => panic!("expected InnerDupes, got {other:?}"),
        }
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Corruption that sorts PAST the display cap still refuses the whole answer.
    ///
    /// The defect this pins: the integrity gate used to run over the capped page, so a group
    /// whose pathnames sort after the limit was counted in the exact total and never checked.
    /// The caller then received a trusted answer that was merely shorter — which is precisely
    /// the «filtering turns corruption into a plausible list» failure the rule exists to stop.
    #[test]
    fn an_inconsistent_rank_beyond_the_cap_still_refuses() {
        let _role = role_guard();
        for explicit in [true, false] {
            let dir = temp_dir(if explicit { "r4b2a1_x" } else { "r4b2a1_d" });
            // Healthy, early-sorting, and exactly enough to fill the display limit.
            let mut files = Vec::with_capacity(DIR_INNER_CAP + 3);
            for index in 0..=DIR_INNER_CAP {
                files.push((
                    write(&dir, &format!("a{index:05}.bin"), b"EARLY"),
                    [0xa1u8; 32],
                ));
            }
            // A real second group — two members and its own digest, so it is a group under both
            // authorities — whose pathnames sort past the cap.
            let z0 = write(&dir, "z0.bin", b"LATE");
            let z1 = write(&dir, "z1.bin", b"LATE");
            files.push((z0.clone(), [0xb2u8; 32]));
            files.push((z1, [0xb2u8; 32]));

            let mut store = ScanStore::open_in_memory().unwrap();
            let scan_id = seed(&mut store, &dir, &files);
            if explicit {
                let verified = crate::pipeline::verify::verify_groups(
                    store.duplicate_groups(scan_id).unwrap(),
                )
                .unwrap();
                assert_eq!(verified.len(), 2, "two real groups under the directory");
                store
                    .publish_results(scan_id, PublishMode::Explicit(&verified))
                    .unwrap();
            } else {
                store
                    .publish_results(scan_id, PublishMode::Derived)
                    .unwrap();
            }

            // The healthy control, which also proves the late group really is past the cap —
            // without that, the corrupt case below would not reach the defect.
            let late = {
                let snapshot = store.membership_snapshot(scan_id).unwrap();
                let late = snapshot.group_of_path(&z0).unwrap().unwrap();
                match snapshot.dir_group_at(&dir).unwrap() {
                    DirGroupAnswer::InnerDupes {
                        members,
                        total,
                        truncated,
                    } => {
                        assert_eq!(members.len(), DIR_INNER_CAP, "the cap is exact");
                        assert_eq!(total, files.len() as u64, "the total counts the late rows");
                        assert!(truncated);
                        assert!(
                            !members.iter().any(|member| member.id == late),
                            "explicit={explicit}: the late group must be past the display cap"
                        );
                    }
                    other => panic!("explicit={explicit}: expected InnerDupes, got {other:?}"),
                }
                late
            };

            // Corrupt ONLY the late rank: its summary now claims a member it does not hold.
            store.corrupt_directly(
                "UPDATE file_group SET file_count = file_count + 1
                  WHERE scan_id = ?1 AND rank = ?2",
                params![scan_id, late.rank],
            );
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            // On the parent this returned `InnerDupes` with the same 1000 healthy rows and a
            // total that included the corrupt group's members.
            match snapshot.dir_group_at(&dir) {
                Err(MembershipMiss::Inconsistent { .. }) => {}
                other => panic!(
                    "explicit={explicit}: corruption past the display cap must refuse the whole \
                     lookup, got {other:?}"
                ),
            }
            drop(snapshot);
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// A directory the scan covers but that holds nothing duplicated, and one it does not cover
    /// at all, are two different pieces of advice and keep two different answers.
    #[test]
    fn the_directory_answer_separates_absence_from_emptiness() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_dir_absence");
        let inside = dir.join("inside");
        std::fs::create_dir_all(&inside).unwrap();
        let lone = write(&inside, "only.bin", b"UNIQUE");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(lone, [0x61u8; 32])]);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        assert!(matches!(
            snapshot.dir_group_at(&inside).unwrap(),
            DirGroupAnswer::NoDuplicates
        ));
        assert!(matches!(
            snapshot.dir_group_at(Path::new("/nowhere-at-all")).unwrap(),
            DirGroupAnswer::NotInScan
        ));
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// F3 — the four states one pathname can be in, each with its own answer.
    #[test]
    fn file_info_separates_absence_unhashed_ungrouped_and_membership() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_file_info");
        let mut store = ScanStore::open_in_memory().unwrap();
        let (scan_id, x1, x2, y1) = published_split(&dir, &mut store);
        // A manifest row with no digest yet, added after publication so it groups with nothing.
        let pending = write(&dir, "pending.bin", b"NOT HASHED YET");
        store
            .record_files(scan_id, &[manifest_row(&pending)])
            .unwrap();

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        // Outside the scan entirely.
        assert!(matches!(
            snapshot.file_info(Path::new("/nowhere/at/all")).unwrap(),
            FileInfoAnswer::NotInScan
        ));
        // In the scan, no digest yet: absence of a hash is not absence of the file.
        match snapshot.file_info(&pending).unwrap() {
            FileInfoAnswer::InScan {
                hash_text,
                membership,
            } => {
                assert!(hash_text.is_none());
                assert!(matches!(membership, Ok(FileMembership::NotGrouped)));
            }
            other => panic!("expected InScan, got {other:?}"),
        }
        // A member of an exact group: the peers are its own population, never the digest union.
        match snapshot.file_info(&x1).unwrap() {
            FileInfoAnswer::InScan {
                hash_text,
                membership,
            } => {
                assert!(hash_text.is_some());
                let FileMembership::InGroup(info) = membership.unwrap() else {
                    panic!("x1 is a member")
                };
                assert_eq!(info.total, 2);
                assert_eq!(info.peers, vec![x2.clone()]);
                assert!(!info.truncated);
                // The other same-digest population is a different identity and is not a peer.
                let other = snapshot.group_of_path(&y1).unwrap().unwrap();
                assert_ne!(other, info.id, "two Explicit ranks stay separate");
                assert!(!info.peers.contains(&y1));
            }
            other => panic!("expected InScan, got {other:?}"),
        }
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// F3 on a group larger than the cap: bounded peers, exact total, honest truncation.
    #[test]
    fn file_info_bounds_a_large_group() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_file_info_cap");
        let digest = [0x71u8; 32];
        let members = FILE_INFO_PEER_CAP + 40;
        let mut files = Vec::with_capacity(members);
        for index in 0..members {
            files.push((write(&dir, &format!("p{index:05}.bin"), b"SAME"), digest));
        }
        let subject = files[0].0.clone();
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &files);
        store
            .publish_results(scan_id, PublishMode::Derived)
            .unwrap();

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        match snapshot.file_info(&subject).unwrap() {
            FileInfoAnswer::InScan { membership, .. } => {
                let FileMembership::InGroup(info) = membership.unwrap() else {
                    panic!("the subject is a member")
                };
                assert_eq!(info.peers.len(), FILE_INFO_PEER_CAP, "the cap is exact");
                assert_eq!(info.total, members as u64);
                assert!(info.truncated);
                assert!(!info.peers.contains(&subject), "not its own peer");
            }
            other => panic!("expected InScan, got {other:?}"),
        }
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An Unknown scan answers F3 with a typed membership refusal, never «no duplicates».
    #[test]
    fn file_info_refuses_membership_without_authority() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_file_info_unknown");
        let digest = [0x81u8; 32];
        let a = write(&dir, "a.bin", b"SAME");
        let b = write(&dir, "b.bin", b"SAME");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a.clone(), digest), (b, digest)]);

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        match snapshot.file_info(&a).unwrap() {
            FileInfoAnswer::InScan {
                hash_text,
                membership,
            } => {
                assert!(hash_text.is_some(), "the digest may still be shown");
                assert!(matches!(membership, Err(MembershipMiss::Unknown)));
            }
            other => panic!("expected InScan, got {other:?}"),
        }
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The panel batch: membership under authority, candidacy without it, and a fixed statement
    /// shape either way.
    #[test]
    fn panel_files_answers_membership_candidacy_and_absence() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_panel");
        let mut store = ScanStore::open_in_memory().unwrap();
        let (scan_id, x1, x2, y1) = published_split(&dir, &mut store);
        let twin_a = write(&dir, "twin_a.bin", b"1234567");
        let twin_b = write(&dir, "twin_b.bin", b"1234567");
        store
            .record_files(scan_id, &[manifest_row(&twin_a), manifest_row(&twin_b)])
            .unwrap();
        let outside = dir.join("never.bin");

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        let paths: Vec<&Path> = vec![
            x1.as_path(),
            y1.as_path(),
            twin_a.as_path(),
            outside.as_path(),
        ];
        let rows = snapshot.panel_files(&paths).unwrap();
        assert_eq!(rows.len(), 4);

        let x_row = &rows[&x1];
        let PanelFileStatus::InGroup {
            id: x_id,
            members,
            distinct_devices,
        } = x_row.status.clone()
        else {
            panic!("x1 is a member: {:?}", x_row.status)
        };
        assert_eq!(members, 2);
        assert!(distinct_devices >= 1);
        assert!(x_row.hash_text.is_some(), "the digest is display data");

        let PanelFileStatus::InGroup { id: y_id, .. } = rows[&y1].status.clone() else {
            panic!("y1 is a member")
        };
        assert_ne!(x_id, y_id, "same digest, two identities");
        assert_eq!(
            rows[&x1].hash_text, rows[&y1].hash_text,
            "the digest really is shared — identity is what separates them"
        );

        // Unhashed, and something shares its size and mtime.
        assert!(matches!(
            rows[&twin_a].status,
            PanelFileStatus::LikelyBySizeMtime { peers } if peers >= 2
        ));
        assert!(rows[&twin_a].hash_text.is_none());
        assert_eq!(rows[&outside].status, PanelFileStatus::NotInScan);
        drop(snapshot);

        // An inconsistent rank hands out no identity, and the row is barred from matching. The
        // rank comes from the identity the reader just returned — ranks are assigned by payoff,
        // so naming a literal here would test whichever group happened to sort first.
        store.corrupt_directly(
            "UPDATE file_group SET file_count = file_count + 1 WHERE scan_id = ?1 AND rank = ?2",
            params![scan_id, x_id.rank],
        );
        let snapshot = store.membership_snapshot(scan_id).unwrap();
        let rows = snapshot.panel_files(&[x1.as_path(), x2.as_path()]).unwrap();
        assert!(matches!(
            rows[&x1].status,
            PanelFileStatus::Unavailable(PanelMiss::Inconsistent { .. })
        ));
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Without authority a hashed row is unavailable, not «not grouped»: nothing may vouch for it.
    #[test]
    fn panel_files_marks_an_unknown_scan_unavailable() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_panel_unknown");
        let digest = [0x91u8; 32];
        let a = write(&dir, "a.bin", b"SAME");
        let b = write(&dir, "b.bin", b"SAME");
        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = seed(&mut store, &dir, &[(a.clone(), digest), (b, digest)]);

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        let rows = snapshot.panel_files(&[a.as_path()]).unwrap();
        assert_eq!(
            rows[&a].status,
            PanelFileStatus::Unavailable(PanelMiss::Unknown)
        );
        assert!(rows[&a].hash_text.is_some());
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `plan_members` is strict where `group_page` is deliberately lenient: a corrupt link count
    /// may still be browsed, and may not be planned against.
    #[test]
    fn plan_members_refuses_what_browsing_tolerates() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_plan_members");
        let mut store = ScanStore::open_in_memory().unwrap();
        let (scan_id, x1, _x2, _y1) = published_split(&dir, &mut store);
        let id = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            let id = snapshot.group_of_path(&x1).unwrap().unwrap();
            let members = snapshot.plan_members(&id).unwrap();
            assert_eq!(members.len(), 2, "every persisted member, marked or not");
            id
        };

        store.corrupt_directly(
            "UPDATE file SET nlink = 'plenty' WHERE scan_id = ?1 AND path = ?2",
            params![scan_id, x1.to_string_lossy()],
        );
        let snapshot = store.membership_snapshot(scan_id).unwrap();
        assert!(
            snapshot.group_page(&id, 0, 10).is_ok(),
            "browsing still shows the group"
        );
        assert!(
            matches!(
                snapshot.plan_members(&id),
                Err(PlanEvidenceMiss::Membership(
                    MembershipMiss::Inconsistent { .. }
                ))
            ),
            "a plan may not be built on it"
        );
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The other half of the same boundary: a row the store reads perfectly well, which the
    /// evidence constructor refuses. That refusal is already typed, and it stays typed — the
    /// builder must be able to match the variant, not parse a sentence out of a store-class
    /// error. Its end-to-end counterpart is `a_digest_that_was_never_verified_refuses_the_plan`.
    #[test]
    fn plan_members_hands_back_the_constructors_own_refusal() {
        let _role = role_guard();
        let dir = temp_dir("r4b2c_plan_member_refusal");
        let mut store = ScanStore::open_in_memory().unwrap();
        let (scan_id, x1, _x2, _y1) = published_split(&dir, &mut store);
        let id = {
            let snapshot = store.membership_snapshot(scan_id).unwrap();
            snapshot.group_of_path(&x1).unwrap().unwrap()
        };

        // A well-formed row whose digest this build never verified against the file itself.
        store.corrupt_directly(
            "UPDATE file SET identity_version = 0 WHERE scan_id = ?1 AND path = ?2",
            params![scan_id, x1.to_string_lossy()],
        );

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        assert!(
            snapshot.group_page(&id, 0, 10).is_ok(),
            "browsing still shows the group"
        );
        assert_eq!(
            snapshot.plan_members(&id),
            Err(PlanEvidenceMiss::Member(PlanRefusal::UnverifiedIdentity {
                path: x1
            })),
            "the constructor's typed refusal is what comes back"
        );
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The witness carries the CURRENT summary's digest and the exact members, and refuses a
    /// stale identity outright.
    #[test]
    fn witness_of_reads_the_current_digest_and_members() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_witness");
        let mut store = ScanStore::open_in_memory().unwrap();
        let (scan_id, x1, x2, y1) = published_split(&dir, &mut store);

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        let x_id = snapshot.group_of_path(&x1).unwrap().unwrap();
        let y_id = snapshot.group_of_path(&y1).unwrap().unwrap();
        let witness = snapshot.witness_of(&[x_id, y_id]).unwrap();
        assert_eq!(witness.scan_id, scan_id);
        assert_eq!(witness.groups.len(), 2);
        assert_eq!(witness.groups[0].members, vec![x1.clone(), x2]);
        assert_eq!(
            witness.groups[0].digest, witness.groups[1].digest,
            "the split populations really do share a digest"
        );
        assert_ne!(witness.groups[0].id, witness.groups[1].id);
        drop(snapshot);

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        let stale = GroupId {
            generation: x_id.generation - 1,
            ..x_id
        };
        assert!(matches!(
            snapshot.witness_of(&[stale]),
            Err(MembershipMiss::Stale { .. })
        ));
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A claim belongs to an identity, not to a digest: the two same-digest populations each
    /// state their own.
    #[test]
    fn group_claim_is_keyed_by_identity() {
        let _role = role_guard();
        let dir = temp_dir("r4b2a_claim");
        let mut store = ScanStore::open_in_memory().unwrap();
        let (scan_id, x1, _x2, y1) = published_split(&dir, &mut store);

        let snapshot = store.membership_snapshot(scan_id).unwrap();
        let x_id = snapshot.group_of_path(&x1).unwrap().unwrap();
        let y_id = snapshot.group_of_path(&y1).unwrap().unwrap();
        let x_claim = snapshot.group_claim(&x_id).unwrap();
        let y_claim = snapshot.group_claim(&y_id).unwrap();
        assert_eq!(x_claim.links.observed, 2);
        assert_eq!(y_claim.links.observed, 2);
        // Different bytes behind each population, so the two claims are not the same figure.
        assert_ne!(
            x_claim.reclaim, y_claim.reclaim,
            "each identity states its own claim"
        );
        drop(snapshot);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Structural: this commit adds the guard to the NEW surface only.
    ///
    /// The whole point of the commit boundary is that a refusal must not appear underneath a UI
    /// that still swallows it. This walks the source and names every method that calls the guard,
    /// so adding one to an existing reader fails here rather than in review.
    #[test]
    fn only_the_new_surface_calls_the_identity_guard() {
        // Production code only: everything from the first `#[cfg(test)] mod` onward is tests,
        // and this test's own assertion text names the call it is looking for.
        let whole = include_str!("store.rs");
        let source = whole
            .split_once("\n#[cfg(test)]\nmod ")
            .map(|(production, _)| production)
            .unwrap_or(whole);
        let mut current = String::new();
        let mut callers: Vec<String> = Vec::new();
        for line in source.lines() {
            let trimmed = line.trim_start();
            if line.starts_with("    fn ") || line.starts_with("    pub fn ") {
                let rest = trimmed.trim_start_matches("pub ").trim_start_matches("fn ");
                current = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
            }
            if trimmed.contains("self.ensure_current_path()") {
                callers.push(current.clone());
            }
        }
        callers.sort();
        callers.dedup();
        assert_eq!(
            callers,
            vec![
                "ensure_db_identity".to_string(),
                "save_marks_settled".to_string()
            ],
            "R4B-2a guards the new surface only; the existing readers switch with the UI that has \
             to render the refusal"
        );
    }
}

/// What the export reader buffers, and what SQLite does with the order it asks for.
#[cfg(test)]
mod export_reader_tests {
    use super::*;

    fn manifest(path: &str, inode: u64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size: 8192,
            mtime: 1000,
            mtime_nsec: 0,
            ctime_sec: 1000,
            ctime_nsec: 0,
            device: 7,
            inode,
            nlink: 1,
        }
    }

    /// `sizes` = how many pathnames each digest gets; each pathname is its own allocation.
    fn seed(store: &mut ScanStore, sizes: &[usize]) -> i64 {
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        let mut rows = Vec::new();
        let mut hashes = Vec::new();
        let mut inode = 1u64;
        for (group, count) in sizes.iter().enumerate() {
            for member in 0..*count {
                let path = format!("/tank/g{group}/f{member}");
                rows.push(manifest(&path, inode));
                hashes.push((PathBuf::from(path), [group as u8 + 1; 32]));
                inode += 1;
            }
        }
        store.record_files(id, &rows).unwrap();
        store.record_hashes(id, &hashes).unwrap();
        id
    }

    /// The bound the export promises: it holds ONE group, never the scan. Metered by the rows the
    /// reader itself buffers — process memory would answer to the allocator instead.
    #[test]
    fn the_export_buffers_one_group_at_a_time() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[2, 5, 3]);
        store.publish_results(id, PublishMode::Derived).unwrap();

        let snapshot = store.membership_snapshot(id).unwrap();
        let mut seen = Vec::new();
        let totals = snapshot
            .for_each_export_group(|group| {
                seen.push(group.members.len());
                Ok(())
            })
            .unwrap();
        drop(snapshot);

        assert_eq!(totals.groups, 3);
        assert_eq!(totals.rows, 10);
        seen.sort_unstable();
        assert_eq!(seen, vec![2, 3, 5]);
        assert_eq!(
            store.export_buffered_rows_max(),
            5,
            "the peak is the largest group, exactly"
        );
        assert!(
            store.export_buffered_rows_max() < totals.rows,
            "and it is strictly below the whole scan"
        );
    }

    /// The same bound at scale: 51 000 member rows across five groups, and the export still holds
    /// only the largest one. Deterministic — a row count, not a memory or timing measurement.
    #[test]
    fn the_export_buffers_one_group_at_a_time_at_scale() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[10_000, 20_000, 15_000, 5_000, 1_000]);
        store.publish_results(id, PublishMode::Derived).unwrap();

        let snapshot = store.membership_snapshot(id).unwrap();
        let totals = snapshot.for_each_export_group(|_| Ok(())).unwrap();
        drop(snapshot);

        assert_eq!(totals.groups, 5);
        assert_eq!(totals.rows, 51_000);
        assert_eq!(
            store.export_buffered_rows_max(),
            20_000,
            "the peak is the largest group, at any scale"
        );
        assert!(store.export_buffered_rows_max() < totals.rows);
        assert_eq!(
            store.export_buffered_rows_now(),
            0,
            "and nothing is still held when it returns"
        );
    }

    /// A failed export must not leave the meter holding a group that was already dropped.
    ///
    /// Asserted on the LIVE count rather than only on the high-water mark. With `[2, 5, 3]` the
    /// first group is the two-row one, so a stale `2` is invisible the moment the five-row group
    /// sets the same expected peak — which is exactly how this test used to pass with the release
    /// guard deleted. The live count is zero or it is not.
    #[test]
    fn a_failing_sink_releases_the_live_buffer() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[2, 5, 3]);
        store.publish_results(id, PublishMode::Derived).unwrap();

        {
            let snapshot = store.membership_snapshot(id).unwrap();
            assert_eq!(snapshot.for_each_export_group(|_| Ok(())).unwrap().rows, 10);
        }
        assert_eq!(
            store.export_buffered_rows_now(),
            0,
            "a finished export holds nothing"
        );

        {
            let snapshot = store.membership_snapshot(id).unwrap();
            let err = snapshot
                .for_each_export_group(|_| Err(AppError::msg("the sink refuses")))
                .unwrap_err()
                .to_string();
            assert!(err.contains("the sink refuses"), "{err}");
        }
        assert_eq!(
            store.export_buffered_rows_now(),
            0,
            "and a refused one holds nothing either"
        );

        {
            let snapshot = store.membership_snapshot(id).unwrap();
            assert_eq!(snapshot.for_each_export_group(|_| Ok(())).unwrap().rows, 10);
        }
        assert_eq!(
            store.export_buffered_rows_max(),
            5,
            "the peak is the largest group, never a sum across exports"
        );
        assert!(store.export_buffered_rows_max() < 10);
    }

    /// The same, when the sink unwinds instead of returning an error.
    #[test]
    fn a_panicking_sink_releases_the_live_buffer() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[2, 5, 3]);
        store.publish_results(id, PublishMode::Derived).unwrap();

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let snapshot = store.membership_snapshot(id).unwrap();
            let _ = snapshot.for_each_export_group(|_| panic!("the sink panics"));
        }));
        std::panic::set_hook(previous);
        assert!(outcome.is_err(), "the sink must have unwound");
        assert_eq!(
            store.export_buffered_rows_now(),
            0,
            "the unwind released the buffer on its way out"
        );

        {
            let snapshot = store.membership_snapshot(id).unwrap();
            assert_eq!(snapshot.for_each_export_group(|_| Ok(())).unwrap().rows, 10);
        }
        assert_eq!(store.export_buffered_rows_max(), 5);
        assert_eq!(store.export_buffered_rows_now(), 0);
    }

    /// Members arrive in `(rank, path)` order, so one group's rows are contiguous and the file is
    /// deterministic for a fixed snapshot.
    #[test]
    fn the_export_streams_in_rank_then_path_order() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[3, 3]);
        store.publish_results(id, PublishMode::Derived).unwrap();

        let snapshot = store.membership_snapshot(id).unwrap();
        let mut ranks = Vec::new();
        snapshot
            .for_each_export_group(|group| {
                ranks.push(group.id.rank);
                let paths: Vec<_> = group.members.iter().map(|m| m.path.clone()).collect();
                let mut sorted = paths.clone();
                sorted.sort();
                assert_eq!(paths, sorted, "members arrive in path order");
                Ok(())
            })
            .unwrap();
        assert_eq!(ranks, vec![0, 1], "and groups in rank order");
    }

    /// The identity every row carries is the published one.
    #[test]
    fn every_exported_group_carries_the_published_identity() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[2]);
        let generation = store.publish_results(id, PublishMode::Derived).unwrap();
        let republished = store.publish_results(id, PublishMode::Derived).unwrap();
        assert_eq!(republished, generation + 1);

        let snapshot = store.membership_snapshot(id).unwrap();
        snapshot
            .for_each_export_group(|group| {
                assert_eq!(group.id.scan_id, id);
                assert_eq!(group.id.generation, republished);
                Ok(())
            })
            .unwrap();
    }

    /// A scan with no membership authority answers nothing here either — the export's own
    /// eligibility gate is not the only thing standing between Unknown and an artifact.
    #[test]
    fn an_unknown_authority_answers_no_export_rows() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[2]);
        let snapshot = store.membership_snapshot(id).unwrap();
        let err = snapshot
            .for_each_export_group(|_| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no membership authority"), "{err}");
    }

    /// The ordering claim is about a query PLAN, so it is checked against the planner rather than
    /// argued from index columns. `EXPLAIN QUERY PLAN` over the exact bound statement must not
    /// contain a temporary sort — if it ever does, the export sorts the whole scan and the
    /// bounded-memory story above is only half of the truth.
    fn plan_of(store: &ScanStore, scan_id: i64, mode: MembershipMode) -> Vec<String> {
        let sql = format!("EXPLAIN QUERY PLAN {}", export_rows_sql(mode));
        let mut stmt = store.conn.prepare(&sql).unwrap();
        let rows = stmt
            .query_map(params![scan_id], |row| row.get::<_, String>(3))
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    }

    #[test]
    fn the_derived_export_plan_uses_no_temporary_sort() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[2, 2]);
        store.publish_results(id, PublishMode::Derived).unwrap();

        let plan = plan_of(&store, id, MembershipMode::Derived);
        assert!(
            !plan.iter().any(|step| step.contains("TEMP B-TREE")),
            "the Derived export must not sort the scan: {plan:#?}"
        );
    }

    #[test]
    fn the_explicit_export_plan_uses_no_temporary_sort() {
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = seed(&mut store, &[2, 2]);
        let groups = store.duplicate_groups(id).unwrap();
        store
            .publish_results(id, PublishMode::Explicit(&groups))
            .unwrap();

        let plan = plan_of(&store, id, MembershipMode::Explicit);
        assert!(
            !plan.iter().any(|step| step.contains("TEMP B-TREE")),
            "the Explicit export must not sort the scan: {plan:#?}"
        );
    }
}
