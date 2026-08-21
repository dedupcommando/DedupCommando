// SPDX-License-Identifier: Apache-2.0
use rusqlite::{params, Connection, OptionalExtension};

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
    -- `st_nlink` of the inode at walk time, from the metadata the walk already read (no second
    -- stat). 0 means unknown — a legacy pre-v3 row — because a real link count is always >= 1.
    -- Reclaim is a property of the physical object, so «how many links does it have» and «how
    -- many of them did this scan see» are what separate a guaranteed figure from a guess.
    nlink   INTEGER NOT NULL DEFAULT 0,
    hash    BLOB,
    PRIMARY KEY (scan_id, path)
);
CREATE INDEX IF NOT EXISTS file_size ON file(scan_id, size);
CREATE INDEX IF NOT EXISTS file_hash ON file(scan_id, hash);
CREATE INDEX IF NOT EXISTS file_content ON file(device, inode, size, mtime);
-- Physical identity within ONE scan: which pathnames of this scan share an allocation.
-- `file_content` above cannot serve this — it is not scan-scoped.
CREATE INDEX IF NOT EXISTS file_scan_identity ON file(scan_id, device, inode);
-- Counting distinct allocations per content group without touching the table.
CREATE INDEX IF NOT EXISTS file_hash_identity ON file(scan_id, hash, device, inode);
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
    reclaimable_bytes INTEGER NOT NULL DEFAULT 0,
    -- How far `reclaimable_bytes` above can be trusted: `model::reclaim::ReclaimState`
    -- (0 unknown, 1 exact, 2 upper bound). 0 for every pre-v3 total.
    reclaim_state     INTEGER NOT NULL DEFAULT 0
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
    -- Distinct physical allocations behind `file_count` pathnames. 0 = unknown (pre-v3 summary).
    object_count  INTEGER NOT NULL DEFAULT 0,
    -- Trust in this group's `reclaim`, same enum as `scan_stats.reclaim_state`.
    reclaim_state INTEGER NOT NULL DEFAULT 0,
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
-- v5, the membership authority: which writer last published this scan's results, and which
-- publication the member rows below belong to. ONE row per scan.
--
-- Absence of a row is the answer for a scan no v5 writer has spoken for — a migrated v4
-- checkpoint, or one whose publication never committed — and it reads as «unknown», never as
-- «derived». There is deliberately no persisted unknown mode: a mode column that could spell it
-- would let a writer, or a migration, manufacture the one state that must only ever be inferred
-- from absence.
--
-- `mode` 1 = derived (membership is the manifest by digest), 2 = explicit (membership is the
-- `file_group_member` rows). `generation` is bumped by every publication, so a group identity
-- carried by an older plan can be recognised as stale rather than silently re-resolved: rank is
-- reassigned by payoff on each publication, and `{scan_id, rank}` alone would name a different
-- group after republication.
--
-- Storage only in R4A: no production reader or writer touches this table yet.
CREATE TABLE IF NOT EXISTS scan_membership (
    scan_id    INTEGER NOT NULL PRIMARY KEY,
    mode       INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    CHECK (mode IN (1, 2)),
    CHECK (generation > 0),
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);
-- v5, the accepted members of one verified group. Written ONLY in explicit mode.
--
-- `path` carries the exact `file.path` TEXT spelling, in whatever form the walk yielded: a scan
-- rooted at a relative path stores relative pathnames, and a name containing LF is one member, not
-- two. No absolute-path check, no normalization, no canonicalization — the membership domain is
-- the manifest's domain or it is a second answer waiting to disagree.
--
-- `generation` is redundant with `scan_membership.generation` by construction (publication is
-- delete-then-insert in one transaction) and is kept as a cross-check against a hand-edited row.
CREATE TABLE IF NOT EXISTS file_group_member (
    scan_id    INTEGER NOT NULL,
    group_rank INTEGER NOT NULL,
    path       TEXT NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY (scan_id, group_rank, path),
    CHECK (group_rank >= 0),
    CHECK (generation > 0),
    CHECK (path <> ''),
    FOREIGN KEY (scan_id, group_rank)
        REFERENCES file_group(scan_id, rank) ON DELETE CASCADE
);
-- The reverse question every cursor asks — «which group is this pathname in?» — and the structural
-- form of the rule that one path belongs to at most one group of a scan. Not a duplicate of the
-- primary key: that one is prefixed by `group_rank`, this one is not. `file_group.hash` stays
-- non-unique, so two explicit ranks may legitimately share one digest.
CREATE UNIQUE INDEX IF NOT EXISTS file_group_member_by_path
    ON file_group_member(scan_id, path);
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
-- The scan's selected roots, in the one normalized representation the omission ledger uses
-- (`model::omission::PathKey`), each carrying its own completeness authority.
--
-- `generation` = 0 means this root's ledger is NOT trusted — never committed, or invalidated by a
-- clear. A positive value is the generation of the snapshot that produced the rows currently
-- stored for it. There is deliberately no scan-wide trust marker: a scan-wide flag would stay
-- «trusted» while a per-root clear removed that root's rows, and a reader in that window would
-- see an empty ledger and call the root complete.
--
-- Absent entirely for every scan migrated from an older schema, and for any scan whose roots
-- could not all be keyed. No row means no authority, which reads as «unknown» — never «complete».
CREATE TABLE IF NOT EXISTS scan_root (
    scan_id    INTEGER NOT NULL,
    root_key   TEXT    NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, root_key),
    CHECK (generation >= 0),
    -- Shape only. Normalization itself is a Rust invariant (`PathKey` is the sole constructor);
    -- SQL cannot verify it.
    CHECK (root_key = '/'
           OR (substr(root_key, 1, 1) = '/' AND substr(root_key, -1, 1) <> '/')),
    -- Enforced: every `ScanStore` connection turns foreign keys on and proves it
    -- (`enforce_foreign_keys`). The explicit child-before-parent order in purge_scan and
    -- clear_files stays anyway — defense in depth, and the one thing that keeps a delete's meaning
    -- visible in the code rather than in a cascade.
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);
-- Directories that lost at least one file, or suffered at least one walk error, with the typed
-- reason and how many EVENTS. Events, not files: the iterator-error branch is reached before the
-- entry's type is known, so one such event may stand for a file, a directory, or an entire
-- unreadable subtree.
--
-- A dedicated table rather than synthetic `file` rows: a fake manifest row would become a hash
-- candidate and corrupt the physical-object model, and it could not carry a count at all.
--
-- `dir_key` is the nearest keyable ancestor of the omitted child — its parent in every ordinary
-- case. No child pathname is stored anywhere, so a name that cannot be represented as UTF-8 costs
-- the ledger nothing and no lossy pathname is ever written.
CREATE TABLE IF NOT EXISTS dir_omission (
    scan_id     INTEGER NOT NULL,
    root_key    TEXT    NOT NULL,
    dir_key     TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    event_count INTEGER NOT NULL,
    generation  INTEGER NOT NULL,
    -- `root_key` is deliberately NOT in the key: including it would let one directory hold rows
    -- under two roots and double every aggregate.
    PRIMARY KEY (scan_id, dir_key, reason),
    CHECK (event_count > 0),
    CHECK (generation > 0),
    CHECK (reason <> ''),
    -- Never above the root. Equivalent to component containment ONLY because both operands are
    -- PathKeys; SQL cannot check that, so this is a backstop against a hand-written row, not the
    -- enforcement. The writer validates containment in Rust.
    CHECK (dir_key = root_key
           OR root_key = '/'
           OR substr(dir_key, 1, length(root_key) + 1) = root_key || '/'),
    FOREIGN KEY (scan_id, root_key) REFERENCES scan_root(scan_id, root_key) ON DELETE CASCADE
);
-- Root-keyed lookup: a whole-root clear is `scan_id`+`root_key`, and the subtree queries add a
-- `dir_key` range. The PK's own index already covers (scan_id, dir_key).
CREATE INDEX IF NOT EXISTS dir_omission_by_root
    ON dir_omission(scan_id, root_key, dir_key);
";

/// Current on-disk schema version, stamped into `PRAGMA user_version`. Bump this (and add a
/// migration step) whenever the schema changes in a way an older build cannot read. A DB from
/// before versioning reports 0; its schema equals v1, so it is stamped on first open.
///
/// v2 adds `scan_stats.results_materialized`. An older build would not see the marker and would
/// fall back to «is file_group empty?», which re-derives results `--verify` had rejected — so v2
/// is deliberately not readable by a v1 build.
///
/// v3 adds the physical-object fields: `file.nlink`, `file_group.object_count`, and the
/// `reclaim_state` trust marker on both `file_group` and `scan_stats`. A v2 build must not open a
/// v3 DB: it cannot see `nlink`, and re-materializing `file_group` with its pathname formula
/// (`store::materialize_file_groups`) would silently re-inflate reclaim. There is no down
/// migration; the escape is the one the refusal message already names — move `dedcom.db` aside.
///
/// v4 adds the omission ledger: `scan_root` (the per-root completeness authority) and
/// `dir_omission` (what each directory lost, and why). Purely additive — two new tables and no
/// column on any existing one, so the migration reads no data and rewrites no row. A v3 build must
/// not open a v4 DB: it cannot see `scan_root`, so it would judge a v4 scan's directories by the
/// hash-only completeness rule alone and hand back exactly the false twins the ledger exists to
/// suppress.
///
/// v5 adds the membership authority: `scan_membership` (which writer published this scan's
/// results, and which publication) and `file_group_member` (the accepted members of a verified
/// group). Purely additive — two new tables and one index, no column on any existing table, so the
/// migration reads no data and rewrites no row. A v4 build must not open a v5 DB: it cannot see the
/// authority, so it would answer every membership question from raw digests and hand back the very
/// pathnames verification rejected.
pub const SCHEMA_VERSION: i64 = 5;

/// Turns foreign-key enforcement on for one freshly opened connection, and proves it took.
///
/// The declared keys in `SCHEMA` are only worth what the connection enforces, and enforcement is
/// per connection, not per database. The pinned bundled SQLite happens to default it on
/// (`libsqlite3-sys` compiles the amalgamation with `SQLITE_DEFAULT_FOREIGN_KEYS=1`), which is
/// exactly why this exists: an invariant that holds by accident of a dependency's build flags is
/// one a version bump can withdraw in silence. Every `ScanStore` constructor states it instead.
///
/// The read-back is the point. `PRAGMA foreign_keys` is a no-op inside a transaction, so a caller
/// that only issued the write would go on believing a setting that never applied; this fails
/// closed on the observed integer rather than on any error text.
///
/// Connection-local state only: nothing is written to the database, so this is safe to run before
/// the future-schema refusal that must leave a newer file untouched.
pub fn enforce_foreign_keys(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    let enabled: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if enabled != 1 {
        return Err(AppError::msg(format!(
            "dedcom.db opened without foreign-key enforcement (PRAGMA foreign_keys = {enabled}); \
             refusing to work on a checkpoint whose declared relationships are not enforced"
        )));
    }
    Ok(())
}

/// The version refusal itself, parameterized by the maximum schema a *reading build* supports.
///
/// Being a parameter rather than a constant is what makes the downgrade guarantee testable: a build
/// that only knows an older schema differs from this one, for this purpose, in exactly that number.
/// Passing it is therefore a real execution of the same comparison an older build would make —
/// unlike comparing two constants, which proves nothing about the code.
///
/// Reads only. A refusal must leave the DB exactly as it was, which is what lets a DB from a future
/// build survive being opened by this one.
fn ensure_version_at_most(conn: &Connection, supported: i64) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > supported {
        return Err(AppError::msg(format!(
            "dedcom.db was created by a newer version (schema v{version}; this build supports v{supported}). Upgrade dedcom, or move the old dedcom.db aside."
        )));
    }
    Ok(())
}

/// Refuses a DB written by a newer build. Reads `PRAGMA user_version` and errors if it is above
/// what this build knows; otherwise does nothing. Must run before any write so a future DB is
/// left untouched.
pub fn ensure_version_supported(conn: &Connection) -> Result<()> {
    ensure_version_at_most(conn, SCHEMA_VERSION)
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

/// Accepts exactly the current schema and nothing else — for a connection that must neither
/// migrate nor tolerate a half-known file (the staged apply-lease opener). One `PRAGMA
/// user_version` read serves both comparisons: calling the two existing helpers would read the
/// pragma twice, and the two reads could in principle disagree. Performs no migration and no
/// write.
///
/// The two directions keep distinct wording, and the older one is deliberately NOT the
/// read-only helper's sentence: this caller holds a READ_WRITE connection and its reader IS the
/// operator, so «read-only mode cannot upgrade it — start dedcom as the operator» would send
/// someone to do what they are already doing. What is actually true is that a destructive apply
/// refuses to migrate at all: migration belongs to the ordinary open path, which must run
/// first.
///
/// Staged by R4B-1; `ScanStore::open_for_apply_lease` is its only caller until R4B-2 wires the
/// worker route.
pub fn ensure_version_exact(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(AppError::msg(format!(
            "dedcom.db was created by a newer version (schema v{version}; this build supports v{SCHEMA_VERSION}). Upgrade dedcom, or move the old dedcom.db aside."
        )));
    }
    if version < SCHEMA_VERSION {
        return Err(AppError::msg(format!(
            "dedcom.db uses an older schema (v{version}; this build needs v{SCHEMA_VERSION}), and applying actions never migrates the checkpoint. Open dedcom normally once so it upgrades the database, then run the actions again."
        )));
    }
    Ok(())
}

/// One table of a floor: its name and the columns a checkpoint of that version must carry.
type TableFloor = (&'static str, &'static [&'static str]);

const NOT_A_CHECKPOINT: &str = "dedcom.db is not a checkpoint this build can upgrade";
const NOTHING_CHANGED: &str =
    "Nothing was changed. Move it aside, or point --state-dir at the right directory.";

/// The floor of v0 and v1 — what the first public build actually wrote.
///
/// A version's real shape is the `CREATE` payload of the commit that introduced it PLUS the
/// `add_column_if_missing` ladder that build already carried: at the first public commit the
/// ladder alone contributes `scan.trashed`, `scan_stats.hash_failures` and the four `cand_*`
/// columns, none of which are in that commit's payload. Reading the payload alone would accept
/// shapes no release ever wrote.
///
/// `scan` comes first so a database that is not ours at all is refused by the table an operator
/// recognises rather than by an alphabetically earlier one.
const FLOOR_V0: &[TableFloor] = &[
    (
        "scan",
        &[
            "id",
            "created_at",
            "updated_at",
            "status",
            "config_json",
            "trashed",
        ],
    ),
    (
        "file",
        &[
            "scan_id",
            "path",
            "size",
            "mtime",
            "mtime_nsec",
            "ctime_sec",
            "ctime_nsec",
            "identity_version",
            "device",
            "inode",
            "hash",
        ],
    ),
    (
        "file_group",
        &["scan_id", "rank", "hash", "file_count", "size", "reclaim"],
    ),
    (
        "scan_stats",
        &[
            "scan_id",
            "elapsed_seconds",
            "storage_type",
            "pool_layout",
            "zfs_version",
            "files_scanned",
            "bytes_hashed",
            "groups_found",
            "reclaimable_bytes",
            "hash_failures",
            "cand_files_total",
            "cand_bytes_total",
            "cand_files_hashed",
            "cand_bytes_hashed",
        ],
    ),
    ("file_mark", &["scan_id", "path", "is_keeper", "action"]),
    (
        "dir_dedup",
        &["scan_id", "signature", "path", "file_count", "size_per_dir"],
    ),
    (
        "file_dedup",
        &[
            "scan_id", "hash", "path", "size", "mtime", "device", "inode",
        ],
    ),
    (
        "hash_cache",
        &["device", "inode", "size", "mtime", "hash", "updated_at"],
    ),
    (
        "move_event",
        &[
            "id",
            "created_at",
            "scan_id",
            "source_path",
            "target_path",
            "hash",
            "duplicate",
        ],
    ),
];

/// Per-version additions. A floor is frozen by the version bump that introduced it: a new
/// `add_column_if_missing` belongs in a NEW row here behind a NEW `SCHEMA_VERSION`, never
/// appended to a floor already published — that would retroactively reject databases the old
/// build wrote correctly.
const FLOOR_V2_COLUMNS: &[(&str, &str)] = &[("scan_stats", "results_materialized")];
const FLOOR_V3_COLUMNS: &[(&str, &str)] = &[
    ("file", "nlink"),
    ("file_group", "object_count"),
    ("file_group", "reclaim_state"),
    ("scan_stats", "reclaim_state"),
];
const FLOOR_V4_TABLES: &[TableFloor] = &[
    (
        "dir_omission",
        &[
            "scan_id",
            "root_key",
            "dir_key",
            "reason",
            "event_count",
            "generation",
        ],
    ),
    ("scan_root", &["scan_id", "root_key", "generation"]),
];
const FLOOR_V5_TABLES: &[TableFloor] = &[
    (
        "file_group_member",
        &["scan_id", "group_rank", "path", "generation"],
    ),
    ("scan_membership", &["scan_id", "mode", "generation"]),
];

fn floor_for(version: i64) -> Vec<(&'static str, Vec<&'static str>)> {
    let mut floor: Vec<(&'static str, Vec<&'static str>)> = FLOOR_V0
        .iter()
        .map(|(table, columns)| (*table, columns.to_vec()))
        .collect();
    let mut add_columns = |adds: &[(&'static str, &'static str)]| {
        for (table, column) in adds {
            if let Some(entry) = floor.iter_mut().find(|(name, _)| name == table) {
                entry.1.push(column);
            }
        }
    };
    if version >= 2 {
        add_columns(FLOOR_V2_COLUMNS);
    }
    if version >= 3 {
        add_columns(FLOOR_V3_COLUMNS);
    }
    if version >= 4 {
        floor.extend(
            FLOOR_V4_TABLES
                .iter()
                .map(|(table, columns)| (*table, columns.to_vec())),
        );
    }
    if version >= 5 {
        floor.extend(
            FLOOR_V5_TABLES
                .iter()
                .map(|(table, columns)| (*table, columns.to_vec())),
        );
    }
    floor
}

/// Every name this build's migration creates with `IF NOT EXISTS`, and the schema version at
/// which the name first existed. Both halves matter: the migration always runs the WHOLE current
/// `SCHEMA`, so it will create all of these whatever version the database claims, and a name that
/// did not exist at the claimed version cannot legitimately be in a checkpoint of that version.
///
/// Provenance was read out of this repository's own history, one bump commit at a time, not
/// transcribed from memory: v0 `0fbbb5e`, v1 `27f698f`, v2 `6c1ecd6`, v3 `75f8370`, v4 `eee4a94`,
/// v5 `0a0df8d`.
const PRODUCT_TABLES: &[(&str, i64)] = &[
    ("scan", 0),
    ("file", 0),
    ("file_group", 0),
    ("scan_stats", 0),
    ("file_mark", 0),
    ("dir_dedup", 0),
    ("file_dedup", 0),
    ("hash_cache", 0),
    ("move_event", 0),
    ("scan_root", 4),
    ("dir_omission", 4),
    ("scan_membership", 5),
    ("file_group_member", 5),
];

/// Name, the version it arrived at, its table, whether it is UNIQUE, and its key columns in
/// order. Every one of them is non-partial, BINARY and ascending, over plain columns — that is
/// asserted rather than stored, because a squatter is free to differ in exactly those ways.
type IndexSpec = (
    &'static str,
    i64,
    &'static str,
    bool,
    &'static [&'static str],
);

const PRODUCT_INDEXES: &[IndexSpec] = &[
    ("file_size", 0, "file", false, &["scan_id", "size"]),
    ("file_hash", 0, "file", false, &["scan_id", "hash"]),
    (
        "file_content",
        0,
        "file",
        false,
        &["device", "inode", "size", "mtime"],
    ),
    (
        "file_path_content",
        0,
        "file",
        false,
        &["path", "size", "mtime"],
    ),
    (
        "file_hash_path",
        0,
        "file",
        false,
        &["scan_id", "hash", "path"],
    ),
    (
        "file_reuse_identity",
        0,
        "file",
        false,
        &[
            "path",
            "size",
            "mtime",
            "mtime_nsec",
            "ctime_sec",
            "ctime_nsec",
            "identity_version",
        ],
    ),
    (
        "dir_dedup_by_scan_sig",
        0,
        "dir_dedup",
        false,
        &["scan_id", "signature"],
    ),
    (
        "file_group_hash",
        0,
        "file_group",
        false,
        &["scan_id", "hash"],
    ),
    (
        "file_dedup_by_scan_hash",
        0,
        "file_dedup",
        false,
        &["scan_id", "hash"],
    ),
    (
        "file_scan_identity",
        3,
        "file",
        false,
        &["scan_id", "device", "inode"],
    ),
    (
        "file_hash_identity",
        3,
        "file",
        false,
        &["scan_id", "hash", "device", "inode"],
    ),
    (
        "dir_omission_by_root",
        4,
        "dir_omission",
        false,
        &["scan_id", "root_key", "dir_key"],
    ),
    (
        "file_group_member_by_path",
        5,
        "file_group_member",
        true,
        &["scan_id", "path"],
    ),
];

fn object_kind(conn: &Connection, name: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT type FROM sqlite_master WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?)
}

fn not_ours(detail: String) -> AppError {
    AppError::msg(format!("{NOT_A_CHECKPOINT}: {detail}. {NOTHING_CHANGED}"))
}

/// Refuses a database in which one of our names is taken by something that is not ours.
///
/// Every name here is created with `IF NOT EXISTS`, which is silent when the name is already
/// occupied. That silence is the danger: the object we meant to create never appears, the
/// migration reports success, and the stamp at the end says v5. For
/// `file_group_member_by_path` — the one UNIQUE index in the schema — that means a checkpoint
/// declared v5 with no uniqueness behind membership at all.
///
/// A name introduced later than the claimed version is refused WITHOUT looking at its shape. A
/// genuine v0 checkpoint cannot carry a name that only came into existence at v5; the fact that
/// it does is the answer, and a well-formed impostor is no better than a malformed one.
fn ensure_no_squatted_name(conn: &Connection, version: i64) -> Result<()> {
    for (table, since) in PRODUCT_TABLES {
        let Some(kind) = object_kind(conn, table)? else {
            continue;
        };
        if *since > version {
            return Err(not_ours(format!(
                "`{table}` belongs to schema v{since}, but this checkpoint declares v{version}"
            )));
        }
        if kind != "table" {
            return Err(not_ours(format!("`{table}` is a {kind}, not a table")));
        }
    }

    for (name, since, owner, unique, columns) in PRODUCT_INDEXES {
        let Some(kind) = object_kind(conn, name)? else {
            continue;
        };
        if *since > version {
            return Err(not_ours(format!(
                "`{name}` belongs to schema v{since}, but this checkpoint declares v{version}"
            )));
        }
        if kind != "index" {
            return Err(not_ours(format!("`{name}` is a {kind}, not an index")));
        }
        let indexed: String = conn.query_row(
            "SELECT tbl_name FROM sqlite_master WHERE name = ?1",
            [name],
            |row| row.get(0),
        )?;
        if indexed != *owner {
            return Err(not_ours(format!(
                "`{name}` indexes `{indexed}`, not `{owner}`"
            )));
        }
        // `unique` and `partial` live only on the owner's index list; the key columns, their
        // collation and their direction only on index_xinfo. Neither is visible to index_info,
        // which is why checking the column names alone would pass a partial NOCASE index.
        let (is_unique, is_partial): (i64, i64) = conn.query_row(
            "SELECT \"unique\", partial FROM pragma_index_list(?1) WHERE name = ?2",
            params![owner, name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if (is_unique != 0) != *unique {
            let expected = if *unique {
                "is not unique"
            } else {
                "is unique"
            };
            return Err(not_ours(format!("index `{name}` {expected}")));
        }
        if is_partial != 0 {
            return Err(not_ours(format!("index `{name}` is partial")));
        }
        let mut stmt = conn.prepare(
            "SELECT name, coll, \"desc\" FROM pragma_index_xinfo(?1) WHERE key = 1 ORDER BY seqno",
        )?;
        let keys: Vec<(Option<String>, String, i64)> = stmt
            .query_map([name], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut found: Vec<String> = Vec::with_capacity(keys.len());
        for (column, coll, desc) in keys {
            // A key column with no name is an expression, and there is nothing to compare it to.
            let Some(column) = column else {
                return Err(not_ours(format!(
                    "index `{name}` is built over an expression"
                )));
            };
            if !coll.eq_ignore_ascii_case("BINARY") {
                return Err(not_ours(format!(
                    "index `{name}` collates `{column}` as {coll}, not BINARY"
                )));
            }
            if desc != 0 {
                return Err(not_ours(format!(
                    "index `{name}` sorts `{column}` descending"
                )));
            }
            found.push(column);
        }
        if found.iter().map(String::as_str).ne(columns.iter().copied()) {
            return Err(not_ours(format!(
                "index `{name}` covers ({}), not ({})",
                found.join(", "),
                columns.join(", ")
            )));
        }
    }
    Ok(())
}

/// Refuses a database that is not a checkpoint of the version it claims — BEFORE anything is
/// written to it.
///
/// The migration below is additive: it creates missing tables and adds missing later columns. On
/// a file that was never one of our checkpoints that is not a repair, it is adoption — the batch
/// would write our tables into someone else's database and the stamp at the end would declare it
/// v5. So the shape is judged first, and a database that fails keeps its bytes, its mtime and its
/// sidecar census exactly as they were.
///
/// Three rules, in order:
///
///   * a database with no user objects at all is a first run and passes — anything else in an
///     otherwise empty file means it is not ours;
///   * every table of the claimed version's floor must exist AND be a table: `PRAGMA table_info`
///     answers for a view as well, so the storage class is read from `sqlite_master` instead.
///     Names share one namespace in SQLite, so an index or trigger squatting a required name is
///     caught by the same test;
///   * every floor column must be present. Types and constraints are NOT checked: a declared type
///     is an affinity, and judging by it would refuse live databases over nothing;
///   * finally `ensure_no_squatted_name`: none of the 26 names the migration will create with
///     `IF NOT EXISTS` may be held by something that is not ours, and none of them may be present
///     at all if it was introduced after the version this checkpoint declares.
///
/// This is not proof of provenance. It proves only a minimally recognisable checkpoint shape.
/// Foreign objects whose names do not collide are left exactly as they are — an extra table is
/// not evidence that the database is someone else's, and refusing it would break real extended
/// databases for no gain.
pub fn ensure_recognisable_shape(conn: &Connection) -> Result<()> {
    // `sqlite_` is SQLite's own reserved prefix — sqlite_sequence, sqlite_stat1 and friends are
    // the engine's bookkeeping, not a user object. The comparison is on the literal seven
    // characters, NOT `LIKE 'sqlite_%'`: in LIKE the underscore matches any single character, so
    // that pattern also swallows a foreign table called `sqlitex` and would read a database
    // holding one as empty — and an empty database is one this function lets the migration adopt.
    let user_objects: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE substr(name, 1, 7) <> 'sqlite_'",
        [],
        |row| row.get(0),
    )?;
    if user_objects == 0 {
        return Ok(());
    }

    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    // The floor first: it answers «is this one of ours at all», and its diagnosis is the more
    // useful one when the answer is no. Only then the squatted-name pass, which answers the
    // narrower question of whether something else holds a name the migration is about to create.
    for (table, columns) in floor_for(version) {
        let kind: Option<String> = object_kind(conn, table)?;
        match kind.as_deref() {
            Some("table") => {}
            Some(other) => return Err(not_ours(format!("`{table}` is a {other}, not a table"))),
            None => return Err(not_ours(format!("table `{table}` is missing"))),
        }
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let present: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for column in columns {
            if !present.iter().any(|name| name == column) {
                return Err(not_ours(format!(
                    "table `{table}` has no column `{column}`"
                )));
            }
        }
    }
    ensure_no_squatted_name(conn, version)
}

/// Upgrades a checkpoint to the current schema. Runs only after `ensure_recognisable_shape` has
/// established that the database is one of ours — on its own this function would adopt a foreign
/// file and stamp it.
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
    // v3, physical objects. Purely additive: DEFAULT 0 already means «unknown» for every legacy
    // row and summary, so nothing sweeps the manifest and no old pathname-based reclaim is
    // promoted to a trusted figure. Fresh scans write real values; a migrated result stays
    // browseable and is reported as «unknown — rescan required».
    add_column_if_missing(&tx, "file", "nlink", "INTEGER NOT NULL DEFAULT 0")?;
    for column in ["object_count", "reclaim_state"] {
        add_column_if_missing(&tx, "file_group", column, "INTEGER NOT NULL DEFAULT 0")?;
    }
    add_column_if_missing(
        &tx,
        "scan_stats",
        "reclaim_state",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    // Scan-scoped physical identity. Both keys existed before v3, so the order relative to the
    // ALTERs above does not matter — they are grouped here because v3 is what needs them.
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS file_scan_identity ON file(scan_id, device, inode);
         CREATE INDEX IF NOT EXISTS file_hash_identity ON file(scan_id, hash, device, inode);",
    )?;
    // v4, the omission ledger, needs nothing here: `scan_root` and `dir_omission` are whole new
    // tables, so the `CREATE TABLE IF NOT EXISTS` batch above already brought them into an
    // existing DB. No column is added to any existing table, no row is read and none is rewritten
    // — a migrated scan simply has no `scan_root` row, which is exactly «completeness unknown».
    //
    // v5, membership, needs nothing here either, and for the same reason: `scan_membership`,
    // `file_group_member` and the one index arrived with the batch above. Nothing seeds them — a
    // migrated scan simply has no authority row, which is exactly «membership unknown». Inferring
    // an authority from the rows a v4 result already carries is the one thing this migration must
    // never do: those rows are what the raw-digest readers built, and stamping them `derived` would
    // hand a migrated checkpoint the destructive trust it was never granted.
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

    /// Column names of a table, in declaration order.
    fn columns_of(conn: &Connection, table: &str) -> Vec<String> {
        conn.prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    /// One column of `PRAGMA table_info`, as SQLite itself records it: declared name and type, the
    /// NOT NULL flag, the default, and the 1-based position in the primary key (0 = not part of
    /// it). Column names alone say nothing about which columns key a table, so a shape assertion
    /// that reads only names cannot notice a primary key being removed or reordered.
    #[derive(Debug, PartialEq)]
    struct ColumnInfo {
        name: String,
        decl_type: String,
        not_null: i64,
        default: Option<String>,
        pk_ordinal: i64,
    }

    fn table_info(conn: &Connection, table: &str) -> Vec<ColumnInfo> {
        conn.prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |row| {
                Ok(ColumnInfo {
                    name: row.get(1)?,
                    decl_type: row.get(2)?,
                    not_null: row.get(3)?,
                    default: row.get(4)?,
                    pk_ordinal: row.get(5)?,
                })
            })
            .unwrap()
            .map(|row| row.unwrap())
            .collect()
    }

    fn column(name: &str, decl_type: &str, pk_ordinal: i64) -> ColumnInfo {
        ColumnInfo {
            name: name.to_string(),
            decl_type: decl_type.to_string(),
            not_null: 1,
            default: None,
            pk_ordinal,
        }
    }

    /// One column pairing of `PRAGMA foreign_key_list`: which key it belongs to, its position
    /// within that key, and the exact endpoints and delete rule.
    #[derive(Debug, PartialEq)]
    struct ForeignKeyInfo {
        id: i64,
        seq: i64,
        parent_table: String,
        from: String,
        to: String,
        on_delete: String,
    }

    fn foreign_keys_of(conn: &Connection, table: &str) -> Vec<ForeignKeyInfo> {
        conn.prepare(&format!("PRAGMA foreign_key_list({table})"))
            .unwrap()
            .query_map([], |row| {
                Ok(ForeignKeyInfo {
                    id: row.get(0)?,
                    seq: row.get(1)?,
                    parent_table: row.get(2)?,
                    from: row.get(3)?,
                    to: row.get(4)?,
                    on_delete: row.get(6)?,
                })
            })
            .unwrap()
            .map(|row| row.unwrap())
            .collect()
    }

    fn foreign_key(id: i64, seq: i64, parent: &str, from: &str, to: &str) -> ForeignKeyInfo {
        ForeignKeyInfo {
            id,
            seq,
            parent_table: parent.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            on_delete: "CASCADE".to_string(),
        }
    }

    /// SQLite's extended result codes for the constraint classes these tables declare. A bare
    /// `is_err()` cannot tell them apart, and with foreign keys enforced one silently falls back to
    /// the other across an edit: while the CHECK exists an invalid value is rejected as CHECK 275,
    /// and if that CHECK is ever deleted the same deliberately parentless row falls through and is
    /// rejected as FK 787 instead. Both are errors, so `is_err()` stays green on either side of
    /// that transition and proves nothing about which constraint the table still has.
    const CONSTRAINT_CHECK: i32 = 275;
    const CONSTRAINT_FOREIGN_KEY: i32 = 787;
    const CONSTRAINT_PRIMARY_KEY: i32 = 1555;
    const CONSTRAINT_UNIQUE: i32 = 2067;

    /// Asserts that a statement failed as a constraint violation of exactly the intended class.
    #[track_caller]
    fn assert_constraint(result: rusqlite::Result<usize>, extended: i32, what: &str) {
        match result {
            Ok(_) => panic!("{what}: must be refused, but the statement succeeded"),
            Err(rusqlite::Error::SqliteFailure(err, detail)) => {
                assert_eq!(
                    err.code,
                    rusqlite::ErrorCode::ConstraintViolation,
                    "{what}: expected a constraint violation, got {err:?} ({detail:?})"
                );
                assert_eq!(
                    err.extended_code, extended,
                    "{what}: wrong constraint class ({detail:?})"
                );
            }
            Err(other) => panic!("{what}: expected a constraint violation, got {other}"),
        }
    }

    /// Names of every index in the DB.
    fn index_names(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT name FROM sqlite_master WHERE type = 'index'")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    fn user_version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    /// The whole schema as SQLite itself records it — the fingerprint an «idempotent reopen» test
    /// compares before and after.
    fn schema_fingerprint(conn: &Connection) -> Vec<String> {
        conn.prepare(
            "SELECT type || ' ' || name || ' ' || COALESCE(sql, '') FROM sqlite_master
             ORDER BY type, name",
        )
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// Manifest, marks, group summary and scan statistics as text — the representative data a
    /// «this check wrote nothing» assertion compares across a refused open.
    fn representative_data(conn: &Connection) -> Vec<String> {
        let mut rows = Vec::new();
        for sql in [
            "SELECT 'file|' || path || '|' || size || '|' || nlink || '|'
                    || COALESCE(hex(hash), '') FROM file ORDER BY path",
            "SELECT 'mark|' || path || '|' || is_keeper || '|' || COALESCE(action, '')
               FROM file_mark ORDER BY path",
            "SELECT 'group|' || rank || '|' || hash || '|' || file_count || '|' || size || '|'
                    || reclaim || '|' || object_count || '|' || reclaim_state
               FROM file_group ORDER BY rank",
            "SELECT 'stats|' || scan_id || '|' || files_scanned || '|' || bytes_hashed || '|'
                    || groups_found || '|' || reclaimable_bytes || '|' || results_materialized
                    || '|' || reclaim_state
               FROM scan_stats ORDER BY scan_id",
        ] {
            let mut stmt = conn.prepare(sql).unwrap();
            let mapped = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
            rows.extend(mapped.filter_map(|r| r.ok()));
        }
        rows
    }

    /// Names of every table in the DB.
    fn table_names(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    /// Strips what v5 adds. Written once, for the same reason `strip_v4` is: a rewind fixture that
    /// keeps a later version's tables is not that version's shape.
    fn strip_v5(conn: &Connection) {
        conn.execute_batch(
            "DROP TABLE file_group_member;
             DROP TABLE scan_membership;",
        )
        .unwrap();
        let tables = table_names(conn);
        assert!(!tables.contains(&"scan_membership".to_string()));
        assert!(!tables.contains(&"file_group_member".to_string()));
        assert!(!index_names(conn).contains(&"file_group_member_by_path".to_string()));
    }

    /// A genuinely v4-shaped DB: the current schema with every v5 addition taken away again and the
    /// stamp rewound.
    fn v4_shaped_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        strip_v5(&conn);
        conn.pragma_update(None, "user_version", 4i64).unwrap();
        conn
    }

    /// Strips what v4 adds. Shared by both rewind fixtures below, so «what v4 adds» is written
    /// once and neither shape can drift away from it.
    fn strip_v4(conn: &Connection) {
        conn.execute_batch(
            "DROP TABLE dir_omission;
             DROP TABLE scan_root;",
        )
        .unwrap();
        let tables = table_names(conn);
        assert!(!tables.contains(&"scan_root".to_string()));
        assert!(!tables.contains(&"dir_omission".to_string()));
        assert!(!index_names(conn).contains(&"dir_omission_by_root".to_string()));
    }

    /// A genuinely v3-shaped DB: the current schema with every v4 addition taken away again and
    /// the stamp rewound. Built rather than pasted from a frozen DDL, so whatever v4 adds is
    /// exactly what this removes.
    fn v3_shaped_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        strip_v5(&conn);
        strip_v4(&conn);
        conn.pragma_update(None, "user_version", 3i64).unwrap();
        conn
    }

    /// A genuinely v2-shaped DB: the current schema with every v3 and v4 addition taken away again
    /// and the stamp rewound. Built rather than pasted from a frozen DDL, so whatever those
    /// versions add is exactly what this removes — a v2 shape that cannot drift out of date.
    fn v2_shaped_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        strip_v5(&conn);
        strip_v4(&conn);
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
        // Self-check, so a fixture that quietly stopped being v2-shaped fails here and not as a
        // migration test that passes for the wrong reason.
        assert!(!columns_of(&conn, "file").contains(&"nlink".to_string()));
        assert!(!columns_of(&conn, "file_group").contains(&"object_count".to_string()));
        assert!(!columns_of(&conn, "file_group").contains(&"reclaim_state".to_string()));
        assert!(!columns_of(&conn, "scan_stats").contains(&"reclaim_state".to_string()));
        let indexes = index_names(&conn);
        assert!(!indexes.contains(&"file_scan_identity".to_string()));
        assert!(!indexes.contains(&"file_hash_identity".to_string()));
        conn
    }

    /// Seeds a completed scan: two pathnames of ONE allocation (`device/inode` 10/5) with the same
    /// hash, a keeper and a target mark, the materialized group summary and the scan statistics.
    /// The seeded `reclaim` of 100 is precisely the pathname-formula lie — one allocation counted
    /// as if removing the second name freed a file.
    fn seed_completed_scan(conn: &Connection) {
        conn.execute_batch(
            "INSERT INTO scan(id, created_at, updated_at, status, config_json)
                 VALUES (1, 'then', 'then', 'completed', '{\"roots\":[]}');
             INSERT INTO file(scan_id, path, size, mtime, device, inode, hash)
                 VALUES (1, '/tank/a', 100, 42, 10, 5, X'AABB'),
                        (1, '/tank/b', 100, 42, 10, 5, X'AABB');
             INSERT INTO file_mark(scan_id, path, is_keeper, action)
                 VALUES (1, '/tank/a', 1, NULL),
                        (1, '/tank/b', 0, 'delete');
             INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim)
                 VALUES (1, 0, 'aabb', 2, 100, 100);
             INSERT INTO scan_stats(scan_id, files_scanned, bytes_hashed, groups_found,
                                    reclaimable_bytes, results_materialized)
                 VALUES (1, 2, 200, 1, 100, 1);",
        )
        .unwrap();
    }

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

    /// A fresh writable DB is exactly schema v5: every new column, table and index comes from
    /// `CREATE TABLE`/`CREATE INDEX`, not only from the `ALTER` path a migrated DB takes.
    #[test]
    fn fresh_db_is_schema_v5_with_every_new_column_table_and_index() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        assert_eq!(SCHEMA_VERSION, 5, "v5 is the schema this build writes");
        let stamped: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stamped, 5, "a fresh DB is stamped v5");

        // v5: the membership authority and its members, with the one reverse index.
        let tables = table_names(&conn);
        for table in ["scan_membership", "file_group_member"] {
            assert!(
                tables.contains(&table.to_string()),
                "no table {table} in a fresh DB"
            );
        }
        assert_eq!(
            columns_of(&conn, "scan_membership"),
            vec!["scan_id", "mode", "generation"],
            "the authority's shape is part of the contract"
        );
        assert_eq!(
            columns_of(&conn, "file_group_member"),
            vec!["scan_id", "group_rank", "path", "generation"]
        );
        assert!(
            index_names(&conn).contains(&"file_group_member_by_path".to_string()),
            "no index file_group_member_by_path"
        );
        // Exactly one explicit index on the member table: the primary key already provides the
        // (scan_id, group_rank, path) order, so a second one over the same prefix would be dead
        // weight on every publication.
        let member_indexes: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = ?1")
            .unwrap()
            .query_map(["file_group_member"], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .filter(|name| !name.starts_with("sqlite_autoindex"))
            .collect();
        assert_eq!(
            member_indexes,
            vec!["file_group_member_by_path".to_string()]
        );

        // v4: the omission ledger, both tables and the root-keyed index.
        let tables = table_names(&conn);
        for table in ["scan_root", "dir_omission"] {
            assert!(
                tables.contains(&table.to_string()),
                "no table {table} in a fresh DB"
            );
        }
        assert_eq!(
            columns_of(&conn, "scan_root"),
            vec!["scan_id", "root_key", "generation"],
            "the per-root authority's shape is part of the contract"
        );
        assert_eq!(
            columns_of(&conn, "dir_omission"),
            vec![
                "scan_id",
                "root_key",
                "dir_key",
                "reason",
                "event_count",
                "generation"
            ]
        );
        assert!(
            index_names(&conn).contains(&"dir_omission_by_root".to_string()),
            "no index dir_omission_by_root"
        );
        // The rejected scan-wide marker must not exist: the authority is per root.
        assert!(
            !columns_of(&conn, "scan_stats").contains(&"omissions_recorded".to_string()),
            "a scan-wide completeness marker would reintroduce the trusted-empty window"
        );

        assert!(
            columns_of(&conn, "file").contains(&"nlink".to_string()),
            "no file.nlink in a fresh DB"
        );
        for column in ["object_count", "reclaim_state"] {
            assert!(
                columns_of(&conn, "file_group").contains(&column.to_string()),
                "no file_group.{column} in a fresh DB"
            );
        }
        assert!(
            columns_of(&conn, "scan_stats").contains(&"reclaim_state".to_string()),
            "no scan_stats.reclaim_state in a fresh DB"
        );

        let indexes = index_names(&conn);
        for index in ["file_scan_identity", "file_hash_identity"] {
            assert!(indexes.contains(&index.to_string()), "no index {index}");
        }
    }

    /// A real v2-shaped DB carrying real results migrates to the current schema in the one
    /// existing transaction: every row that made the result browseable survives unchanged —
    /// including the old positive reclaim — while everything v3 introduces stays at «unknown».
    /// Nothing rewrites the manifest, and the pathname formula is never promoted to a trusted
    /// figure.
    #[test]
    fn a_v2_db_migrates_and_keeps_its_results_untrusted() {
        let conn = v2_shaped_db();
        seed_completed_scan(&conn);
        assert_eq!(user_version(&conn), 2, "the fixture really is a v2 DB");

        migrate(&conn).unwrap();
        assert_eq!(
            user_version(&conn),
            SCHEMA_VERSION,
            "the stamp moves to the current schema"
        );

        // The manifest: both pathnames, both hashes, and a link count that is honestly unknown.
        let files: Vec<(String, i64, Vec<u8>, i64)> = conn
            .prepare("SELECT path, size, hash, nlink FROM file WHERE scan_id = 1 ORDER BY path")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            files,
            vec![
                ("/tank/a".to_string(), 100, vec![0xAA, 0xBB], 0),
                ("/tank/b".to_string(), 100, vec![0xAA, 0xBB], 0),
            ],
            "path rows and hashes survive; link counts are unknown, not invented"
        );

        // Marks survive, so the result stays browseable exactly as the operator left it.
        let marks: Vec<(String, i64, Option<String>)> = conn
            .prepare("SELECT path, is_keeper, action FROM file_mark ORDER BY path")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            marks,
            vec![
                ("/tank/a".to_string(), 1, None),
                ("/tank/b".to_string(), 0, Some("delete".to_string())),
            ]
        );

        // The group summary keeps its old numbers for browsing — and gains no trust.
        let (count, size, reclaim, objects, state): (i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT file_count, size, reclaim, object_count, reclaim_state
                   FROM file_group WHERE scan_id = 1 AND rank = 0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            (count, size, reclaim),
            (2, 100, 100),
            "the legacy summary is preserved for browsing, not rewritten"
        );
        assert_eq!(
            (objects, state),
            (0, 0),
            "object count and trust are unknown — the old 100 stays a claim, not a promise"
        );

        // Scan statistics survive with the same untrusted total.
        let (scanned, hashed, groups, bytes, prepared, total_state): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = conn
            .query_row(
                "SELECT files_scanned, bytes_hashed, groups_found, reclaimable_bytes,
                        results_materialized, reclaim_state
                   FROM scan_stats WHERE scan_id = 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            (scanned, hashed, groups, bytes, prepared),
            (2, 200, 1, 100, 1)
        );
        assert_eq!(
            total_state, 0,
            "the scan total is untrusted after migration"
        );

        // The scan row itself is intact, so the session still opens.
        let status: String = conn
            .query_row("SELECT status FROM scan WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "completed");

        // v4: the migrated scan gains no completeness authority. The tables exist, but this scan
        // has no root row and no ledger row — which is «unknown», the only honest answer. An empty
        // ledger is NOT what makes it unknown; the absent authority is. Nothing was backfilled,
        // and no old scan was rewritten as trusted.
        let roots: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_root WHERE scan_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let omissions: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM dir_omission WHERE scan_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            (roots, omissions),
            (0, 0),
            "a migrated scan has no authority and no ledger — it is unknown, not complete"
        );

        // v5: the same shape for membership. The migrated scan carries a `file_group` summary the
        // raw-digest readers built, and stamping that as `derived` would hand it destructive trust
        // it never earned. Absence of the authority row is the whole answer.
        let (authority, members): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM scan_membership WHERE scan_id = 1),
                        (SELECT COUNT(*) FROM file_group_member WHERE scan_id = 1)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (authority, members),
            (0, 0),
            "a migrated scan's membership is unknown; nothing may be inferred from its summaries"
        );
    }

    /// The v3→v4 step on its own, on a DB whose shape really is v3: two tables and one index
    /// appear, the stamp moves, and the existing result is untouched.
    #[test]
    fn a_v3_db_migrates_and_gains_no_authority() {
        let conn = v3_shaped_db();
        seed_completed_scan(&conn);
        assert_eq!(user_version(&conn), 3, "the fixture really is a v3 DB");
        let data_before = representative_data(&conn);
        assert!(!data_before.is_empty(), "there must be data to preserve");

        // A v3 DB is readable by this build, and migrating brings it to the current schema.
        assert!(ensure_version_supported(&conn).is_ok());
        migrate(&conn).unwrap();
        migrate(&conn).unwrap(); // idempotent

        assert_eq!(user_version(&conn), SCHEMA_VERSION, "the stamp moves");
        let tables = table_names(&conn);
        for table in ["scan_root", "dir_omission"] {
            assert!(
                tables.contains(&table.to_string()),
                "no table {table} after the v3→v4 migration"
            );
        }
        assert!(index_names(&conn).contains(&"dir_omission_by_root".to_string()));
        assert_eq!(
            representative_data(&conn),
            data_before,
            "the migration reads no data and rewrites no row"
        );

        let roots: i64 = conn
            .query_row("SELECT COUNT(*) FROM scan_root", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            roots, 0,
            "nothing is backfilled: the old scan stays unknown"
        );
    }

    /// Reopening a migrated DB changes neither schema nor data: `migrate` is the function every
    /// start runs, and a checkpoint must survive being opened as many times as the operator likes.
    #[test]
    fn reopening_a_migrated_db_changes_neither_schema_nor_data() {
        let conn = v2_shaped_db();
        seed_completed_scan(&conn);
        migrate(&conn).unwrap();

        let schema_before = schema_fingerprint(&conn);
        let rows_before: Vec<String> = conn
            .prepare(
                "SELECT path || '|' || size || '|' || nlink || '|' || COALESCE(hex(hash), '')
                   FROM file ORDER BY path",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        migrate(&conn).unwrap();
        migrate(&conn).unwrap();

        assert_eq!(user_version(&conn), SCHEMA_VERSION);
        assert_eq!(schema_fingerprint(&conn), schema_before, "schema drifted");
        let rows_after: Vec<String> = conn
            .prepare(
                "SELECT path || '|' || size || '|' || nlink || '|' || COALESCE(hex(hash), '')
                   FROM file ORDER BY path",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(rows_after, rows_before, "data drifted");
    }

    /// A DB from a future build is refused and left exactly as it was — no migration, no stamp
    /// rewrite, nothing an older build could damage.
    ///
    /// The stamp is `SCHEMA_VERSION + 1` rather than a literal, so this keeps meaning «a future
    /// DB» after every bump. With a literal it would silently become «the current DB», and the
    /// refusal it asserts would stop existing.
    ///
    /// Goes through the production entry point `ensure_version_supported`, which is
    /// `ensure_version_at_most(conn, SCHEMA_VERSION)` — the same comparison the older-build tests
    /// below drive with a different maximum. One implementation, both directions.
    #[test]
    fn a_future_db_is_refused_without_writing_to_it() {
        let conn = v2_shaped_db();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let before = schema_fingerprint(&conn);

        let err = ensure_version_supported(&conn).expect_err("a future schema must be refused");
        assert!(
            err.to_string().contains("newer version"),
            "the message must say why: {err}"
        );
        assert_eq!(
            user_version(&conn),
            SCHEMA_VERSION + 1,
            "the future stamp is left alone"
        );
        assert_eq!(schema_fingerprint(&conn), before, "nothing was migrated");
    }

    /// The v4 half of the same guarantee, executed rather than asserted: a build that only knows
    /// v3 must refuse a v4 DB rather than judge its directories by the hash-only completeness rule
    /// and hand back the false twins the ledger exists to suppress.
    ///
    /// For this purpose a v3 build differs from this one in exactly one number — the maximum
    /// schema it supports — so calling the same comparison production calls, with that maximum,
    /// *is* what a v3 build does to a v4 DB.
    #[test]
    fn a_v3_aware_build_refuses_a_v4_db() {
        // A real v4-shaped DB with real results.
        let conn = v4_shaped_db();
        seed_completed_scan(&conn);
        assert_eq!(user_version(&conn), 4, "the subject really is a v4 DB");

        let schema_before = schema_fingerprint(&conn);
        let data_before = representative_data(&conn);
        assert!(!data_before.is_empty(), "there must be data to compare");

        // This build's own maximum accepts it; that is the control.
        assert!(ensure_version_supported(&conn).is_ok());

        let err =
            ensure_version_at_most(&conn, 3).expect_err("a v3-aware build must refuse a v4 DB");
        let text = err.to_string();
        assert!(
            text.contains("schema v4"),
            "the database's own version must be named: {text}"
        );
        assert!(
            text.contains("supports v3"),
            "and the maximum the refusing build supports: {text}"
        );

        assert_eq!(user_version(&conn), 4, "a refusal must not restamp");
        assert_eq!(schema_fingerprint(&conn), schema_before, "nor migrate");
        assert_eq!(
            representative_data(&conn),
            data_before,
            "nor touch the data"
        );
    }

    /// The other direction, executed rather than asserted: a build that only knows v2 must refuse a
    /// v3 DB rather than re-materialize `file_group` with the pathname formula and re-inflate
    /// reclaim.
    ///
    /// For this purpose a v2 build differs from this one in exactly one number — the maximum schema
    /// it supports — so calling the same comparison production calls, with that maximum, *is* what
    /// a v2 build does to a v3 DB. The refusal must name both versions, and it must not write:
    /// version, schema and data are compared across it.
    #[test]
    fn a_v2_aware_build_refuses_a_v3_db() {
        // A real v3-shaped DB with real results.
        let conn = v3_shaped_db();
        seed_completed_scan(&conn);
        assert_eq!(user_version(&conn), 3, "the subject really is a v3 DB");

        let version_before = user_version(&conn);
        let schema_before = schema_fingerprint(&conn);
        let data_before = representative_data(&conn);
        assert!(
            !data_before.is_empty(),
            "the unchanged-data assertion must have something to compare"
        );

        // This build's own maximum accepts it; that is the control.
        assert!(ensure_version_supported(&conn).is_ok());

        // A build whose maximum is v2 refuses it.
        let err = ensure_version_at_most(&conn, 2)
            .expect_err("a v2-aware build must refuse a v3 database");
        let text = err.to_string();
        assert!(
            text.contains("schema v3"),
            "the database's own version must be named: {text}"
        );
        assert!(
            text.contains("supports v2"),
            "and the maximum the refusing build supports: {text}"
        );

        // The refused check performed no migration and no write of any kind.
        assert_eq!(
            user_version(&conn),
            version_before,
            "a refusal must not restamp"
        );
        assert_eq!(schema_fingerprint(&conn), schema_before, "nor migrate");
        assert_eq!(
            representative_data(&conn),
            data_before,
            "nor touch the data"
        );
    }

    /// The v5 half of the same guarantee: a build that only knows v4 must refuse a v5 DB rather
    /// than answer every membership question from raw digests and hand back the pathnames
    /// verification rejected.
    ///
    /// The refusing maximum is `SCHEMA_VERSION - 1`, not a literal: a literal 4 would quietly
    /// become «the current schema» at the next bump and the refusal it asserts would stop existing.
    #[test]
    fn a_v4_aware_build_refuses_a_v5_db() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        seed_completed_scan(&conn);
        assert_eq!(
            user_version(&conn),
            SCHEMA_VERSION,
            "the subject is a current-schema DB"
        );

        let schema_before = schema_fingerprint(&conn);
        let data_before = representative_data(&conn);
        assert!(!data_before.is_empty(), "there must be data to compare");

        // This build's own maximum accepts it; that is the control.
        assert!(ensure_version_supported(&conn).is_ok());

        let previous = SCHEMA_VERSION - 1;
        let err = ensure_version_at_most(&conn, previous)
            .expect_err("a build one version behind must refuse this DB");
        let text = err.to_string();
        assert!(
            text.contains(&format!("schema v{SCHEMA_VERSION}")),
            "the database's own version must be named: {text}"
        );
        assert!(
            text.contains(&format!("supports v{previous}")),
            "and the maximum the refusing build supports: {text}"
        );

        assert_eq!(
            user_version(&conn),
            SCHEMA_VERSION,
            "a refusal must not restamp"
        );
        assert_eq!(schema_fingerprint(&conn), schema_before, "nor migrate");
        assert_eq!(
            representative_data(&conn),
            data_before,
            "nor touch the data"
        );
    }

    /// The v4→v5 step on a DB whose shape really is v4 and which carries a real result: two tables
    /// and one index appear, the stamp moves, every pre-existing row survives byte for byte, and
    /// the new tables are empty — no authority is invented for a scan that never published one.
    #[test]
    fn a_v4_db_migrates_to_v5_additively_and_invents_no_authority() {
        let conn = v4_shaped_db();
        seed_completed_scan(&conn);
        assert_eq!(user_version(&conn), 4, "the fixture really is a v4 DB");
        let data_before = representative_data(&conn);
        assert!(!data_before.is_empty(), "there must be data to preserve");
        let tables_before = table_names(&conn);

        assert!(ensure_version_supported(&conn).is_ok());
        migrate(&conn).unwrap();
        let after_first = schema_fingerprint(&conn);
        migrate(&conn).unwrap(); // reopening a v5 DB is idempotent

        assert_eq!(user_version(&conn), SCHEMA_VERSION, "the stamp moves to v5");
        assert_eq!(
            schema_fingerprint(&conn),
            after_first,
            "a second open must not rewrite the schema"
        );
        for table in ["scan_membership", "file_group_member"] {
            assert!(
                !tables_before.contains(&table.to_string()),
                "{table} must be absent before the migration"
            );
            assert!(
                table_names(&conn).contains(&table.to_string()),
                "no table {table} after the v4→v5 migration"
            );
        }
        assert!(index_names(&conn).contains(&"file_group_member_by_path".to_string()));
        assert_eq!(
            representative_data(&conn),
            data_before,
            "the migration reads no data and rewrites no row"
        );

        let (authority, members): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM scan_membership),
                        (SELECT COUNT(*) FROM file_group_member)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (authority, members),
            (0, 0),
            "nothing is backfilled: a migrated scan's membership stays unknown"
        );
    }

    /// A migration that fails leaves the exact v4 state — no half-created table, no stamp. The
    /// failure is real SQLite behaviour rather than an injected seam: a database in which
    /// `file_group_member` already exists with a foreign shape takes `CREATE TABLE IF NOT EXISTS`
    /// as a no-op and then fails on the index over columns that table does not have, after
    /// `scan_membership` has already been created inside the same transaction.
    #[test]
    fn a_failed_migration_rolls_back_both_the_ddl_and_the_stamp() {
        let conn = v4_shaped_db();
        seed_completed_scan(&conn);
        conn.execute_batch("CREATE TABLE file_group_member (unrelated INTEGER);")
            .unwrap();
        let schema_before = schema_fingerprint(&conn);
        let data_before = representative_data(&conn);

        let err = migrate(&conn).expect_err("the index cannot be built over a foreign table");
        assert!(
            err.to_string().contains("scan_id"),
            "the failure must name the missing column: {err}"
        );

        assert_eq!(
            user_version(&conn),
            4,
            "a failed migration must not restamp"
        );
        assert!(
            !table_names(&conn).contains(&"scan_membership".to_string()),
            "the table created earlier in the same transaction must be rolled back"
        );
        assert_eq!(
            schema_fingerprint(&conn),
            schema_before,
            "the exact prior schema survives"
        );
        assert_eq!(representative_data(&conn), data_before, "and its data");
    }

    /// What SQLite itself records about the two v5 tables — keys, index and foreign keys, not only
    /// column names.
    ///
    /// A shape test that reads names alone cannot see a primary key disappear, and on
    /// `file_group_member` the stricter `(scan_id, path)` unique index would go on refusing the
    /// duplicate-path insert that every other test uses, so the composite key could be removed or
    /// reordered without a single existing assertion noticing. These are the declarations R4B's
    /// resolver will read the database through; pinning them means a later schema edit has to
    /// change this test on purpose rather than by accident.
    #[test]
    fn sqlite_records_the_exact_v5_keys_index_and_foreign_keys() {
        let conn = enforced_db();

        // The authority: one row per scan, keyed by the scan alone.
        assert_eq!(
            table_info(&conn, "scan_membership"),
            vec![
                column("scan_id", "INTEGER", 1),
                column("mode", "INTEGER", 0),
                column("generation", "INTEGER", 0),
            ]
        );

        // The members: the composite key is (scan_id, group_rank, path), in that order.
        assert_eq!(
            table_info(&conn, "file_group_member"),
            vec![
                column("scan_id", "INTEGER", 1),
                column("group_rank", "INTEGER", 2),
                column("path", "TEXT", 3),
                column("generation", "INTEGER", 0),
            ]
        );

        // Exactly one explicitly created index on the member table, and it is the unique reverse
        // lookup. Selected by `origin = 'c'` rather than by name, because the primary key's own
        // index is generated and its name is SQLite's to choose.
        let explicit: Vec<(String, i64)> = conn
            .prepare("PRAGMA index_list(file_group_member)")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .unwrap()
            .map(|row| row.unwrap())
            .filter(|(_, _, origin)| origin == "c")
            .map(|(name, unique, _)| (name, unique))
            .collect();
        assert_eq!(
            explicit,
            vec![("file_group_member_by_path".to_string(), 1)],
            "one explicitly created index, and it must be unique"
        );
        let columns: Vec<String> = conn
            .prepare("PRAGMA index_info(file_group_member_by_path)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(2))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert_eq!(
            columns,
            vec!["scan_id".to_string(), "path".to_string()],
            "the reverse lookup is (scan_id, path), in that order"
        );

        // The declared relationships. `scan_membership` hangs off the scan; a member hangs off the
        // summary it names, through the ordered pair (scan_id, group_rank) -> (scan_id, rank).
        assert_eq!(
            foreign_keys_of(&conn, "scan_membership"),
            vec![foreign_key(0, 0, "scan", "scan_id", "id")]
        );
        assert_eq!(
            foreign_keys_of(&conn, "file_group_member"),
            vec![
                foreign_key(0, 0, "file_group", "scan_id", "scan_id"),
                foreign_key(0, 1, "file_group", "group_rank", "rank"),
            ],
            "one composite relationship, both columns paired in order"
        );

        // And they are enforced on this connection, because `enforce_foreign_keys` said so and
        // read the answer back. Declared but unenforced would make every relationship above a
        // comment.
        let enforced: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(enforced, 1, "the proof must run with enforcement on");
    }

    /// The helper turns enforcement on rather than assuming it. The starting point is a connection
    /// explicitly set OFF, so this proves the production setup does the work — it does not lean on
    /// the bundled SQLite's compile-time default, which is exactly the accident being replaced.
    #[test]
    fn the_helper_turns_enforcement_on_from_off() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        let before: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, 0, "the fixture must really start with it off");

        enforce_foreign_keys(&conn).unwrap();

        let after: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, 1, "the helper must have turned it on");
    }

    /// And it fails closed. `PRAGMA foreign_keys` is a no-op inside a transaction, so a helper that
    /// only issued the write would report success over a setting that never applied. The read-back
    /// is what makes that impossible.
    #[test]
    fn the_helper_refuses_when_the_pragma_cannot_take_effect() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        conn.execute_batch("BEGIN").unwrap();

        let err = enforce_foreign_keys(&conn)
            .expect_err("a pragma that cannot apply must not be reported as applied");
        assert!(
            err.to_string().contains("foreign_keys = 0"),
            "the refusal must name what it observed: {err}"
        );
        let observed: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(observed, 0, "and the setting really is still off");

        conn.execute_batch("ROLLBACK").unwrap();
    }

    /// Seeds one scan with one group summary, the anchor every member row needs.
    fn seed_group_for_members(conn: &Connection, scan_id: i64, ranks: &[(i64, &str)]) {
        conn.execute(
            "INSERT OR IGNORE INTO scan(id, created_at, updated_at, status, config_json)
             VALUES (?1, 'then', 'then', 'completed', '{\"roots\":[]}')",
            [scan_id],
        )
        .unwrap();
        for (rank, hash) in ranks {
            conn.execute(
                "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim)
                 VALUES (?1, ?2, ?3, 2, 100, 100)",
                rusqlite::params![scan_id, rank, hash],
            )
            .unwrap();
        }
    }

    /// A migrated database on a connection that enforces foreign keys, which is what every
    /// `ScanStore` route gives its caller. Constraint tests must run this way or a competing key
    /// failure can stand in for the CHECK they mean to prove.
    fn enforced_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        enforce_foreign_keys(&conn).unwrap();
        migrate(&conn).unwrap();
        conn
    }

    /// Every declared CHECK, exercised on INSERT and on UPDATE, each proved by its own extended
    /// code. A CHECK that only holds on insert is a CHECK a later writer can walk around; a CHECK
    /// asserted with a bare `is_err()` over an absent parent is not asserted at all. While the
    /// CHECK is present that row is refused as CHECK 275; delete the CHECK and the same row is
    /// refused as FK 787 instead, so the bare assertion never notices the loss. Hence the valid
    /// parents seeded below — scan 2 for the authority, and a rank -1 summary for the member — so
    /// nothing can stand in for the CHECK, and hence the extended cause is pinned.
    #[test]
    fn membership_checks_hold_on_insert_and_update() {
        let conn = enforced_db();
        seed_group_for_members(&conn, 1, &[(0, "aabb")]);
        // Scan 2 exists, so an invalid authority row for it can only fail on its CHECKs.
        seed_group_for_members(&conn, 2, &[]);

        // The authority: modes 1 and 2 are accepted, everything else is not.
        for mode in [1i64, 2] {
            conn.execute(
                "INSERT OR REPLACE INTO scan_membership(scan_id, mode, generation)
                 VALUES (1, ?1, 1)",
                [mode],
            )
            .unwrap();
            let rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM scan_membership", [], |r| r.get(0))
                .unwrap();
            assert_eq!(rows, 1, "one scan keeps one authority row");
        }
        for mode in [0i64, 3, -1] {
            assert_constraint(
                conn.execute(
                    "INSERT INTO scan_membership(scan_id, mode, generation) VALUES (2, ?1, 1)",
                    [mode],
                ),
                CONSTRAINT_CHECK,
                &format!("mode {mode} — unknown is absence, not a value"),
            );
        }
        for generation in [0i64, -1] {
            assert_constraint(
                conn.execute(
                    "INSERT INTO scan_membership(scan_id, mode, generation) VALUES (2, 1, ?1)",
                    [generation],
                ),
                CONSTRAINT_CHECK,
                &format!("generation {generation}"),
            );
        }
        assert_constraint(
            conn.execute("UPDATE scan_membership SET mode = 3 WHERE scan_id = 1", []),
            CONSTRAINT_CHECK,
            "the mode CHECK on UPDATE",
        );
        assert_constraint(
            conn.execute(
                "UPDATE scan_membership SET generation = 0 WHERE scan_id = 1",
                [],
            ),
            CONSTRAINT_CHECK,
            "the generation CHECK on UPDATE",
        );

        // The members: rank >= 0, generation > 0, path non-empty. `file_group.rank` carries no
        // CHECK of its own, so a summary at rank -1 can exist purely to give the negative-rank
        // member a valid parent — which is what isolates its CHECK from the foreign key.
        conn.execute(
            "INSERT INTO file_group(scan_id, rank, hash, file_count, size, reclaim)
             VALUES (1, -1, 'aabb', 2, 100, 100)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
             VALUES (1, 0, '/tank/a', 1)",
            [],
        )
        .unwrap();
        for (rank, path, generation, why) in [
            (-1i64, "/tank/b", 1i64, "a negative rank"),
            (0, "", 1, "an empty path"),
            (0, "/tank/b", 0, "a zero generation"),
            (0, "/tank/b", -1, "a negative generation"),
        ] {
            assert_constraint(
                conn.execute(
                    "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                     VALUES (1, ?1, ?2, ?3)",
                    rusqlite::params![rank, path, generation],
                ),
                CONSTRAINT_CHECK,
                why,
            );
        }
        for (sql, why) in [
            ("UPDATE file_group_member SET group_rank = -1", "rank"),
            ("UPDATE file_group_member SET path = ''", "path"),
            ("UPDATE file_group_member SET generation = 0", "generation"),
        ] {
            assert_constraint(conn.execute(sql, []), CONSTRAINT_CHECK, why);
        }
    }

    /// The authority is one row per scan, and a second ordinary INSERT is refused by the primary
    /// key with the parent scan present — `INSERT OR REPLACE` would prove nothing, because it
    /// succeeds whether or not the key exists.
    #[test]
    fn a_scan_has_at_most_one_authority_row() {
        let conn = enforced_db();
        seed_group_for_members(&conn, 1, &[]);
        conn.execute(
            "INSERT INTO scan_membership(scan_id, mode, generation) VALUES (1, 2, 7)",
            [],
        )
        .unwrap();

        assert_constraint(
            conn.execute(
                "INSERT INTO scan_membership(scan_id, mode, generation) VALUES (1, 1, 9)",
                [],
            ),
            CONSTRAINT_PRIMARY_KEY,
            "a second authority row for one scan",
        );

        let (rows, mode, generation): (i64, i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM scan_membership), mode, generation
                   FROM scan_membership WHERE scan_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (rows, mode, generation),
            (1, 2, 7),
            "the original row must survive the refused insert exactly"
        );
    }

    /// The keys are enforced, not merely declared: a row whose values are all perfectly valid is
    /// still refused when its parent is absent, and the refusal is a foreign-key one rather than a
    /// CHECK borrowed from somewhere else.
    #[test]
    fn orphan_rows_are_refused_by_the_foreign_keys() {
        let conn = enforced_db();
        seed_group_for_members(&conn, 1, &[(0, "aabb")]);

        assert_constraint(
            conn.execute(
                "INSERT INTO scan_membership(scan_id, mode, generation) VALUES (99, 2, 1)",
                [],
            ),
            CONSTRAINT_FOREIGN_KEY,
            "an authority row for a scan that does not exist",
        );
        assert_constraint(
            conn.execute(
                "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                 VALUES (1, 42, '/tank/z', 1)",
                [],
            ),
            CONSTRAINT_FOREIGN_KEY,
            "a member of a group rank that does not exist",
        );
        // The v4 ledger, for the same reason and by the same rule.
        assert_constraint(
            conn.execute(
                "INSERT INTO dir_omission(scan_id, root_key, dir_key, reason, event_count,
                                          generation)
                 VALUES (1, '/tank', '/tank/a', 'min_size', 1, 1)",
                [],
            ),
            CONSTRAINT_FOREIGN_KEY,
            "a ledger row with no registered root",
        );
    }

    /// One pathname belongs to at most one group of a scan — the unique index is the structural
    /// form of that rule. The same pathname in a different scan is a different fact and stays
    /// legal, and two ranks of one scan may legitimately share a digest: that is the two-verified-
    /// subgroups shape the whole round exists to make representable.
    #[test]
    fn a_path_belongs_to_one_group_while_two_ranks_may_share_a_digest() {
        let conn = enforced_db();
        seed_group_for_members(&conn, 1, &[(0, "aabb"), (1, "aabb")]);
        seed_group_for_members(&conn, 2, &[(0, "aabb")]);

        conn.execute(
            "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
             VALUES (1, 0, '/tank/a', 7)",
            [],
        )
        .unwrap();
        assert_constraint(
            conn.execute(
                "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                 VALUES (1, 1, '/tank/a', 7)",
                [],
            ),
            CONSTRAINT_UNIQUE,
            "one path in two ranks of one scan — the corruption the index exists to refuse",
        );
        // A different scan is a different fact.
        conn.execute(
            "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
             VALUES (2, 0, '/tank/a', 7)",
            [],
        )
        .unwrap();
        // And two ranks sharing one digest, each with its own members, is legal.
        conn.execute(
            "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
             VALUES (1, 1, '/tank/b', 7)",
            [],
        )
        .unwrap();
        let shared: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_group WHERE scan_id = 1 AND hash = 'aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(shared, 2, "file_group.hash must stay non-unique");
    }

    /// The member domain is the manifest's domain: whatever spelling the walk yielded comes back
    /// byte for byte. A relative root is a supported scan, and LF is legal inside a pathname — one
    /// member with a newline in its name is one member, not two.
    #[test]
    fn member_paths_round_trip_exactly() {
        let conn = enforced_db();
        seed_group_for_members(&conn, 1, &[(0, "aabb")]);

        let paths = [
            "./dir-completeness-resume/a.bin",
            "relative/b.bin",
            "/tank/we\nird.bin",
            "/tank/ünïcødé.bin",
        ];
        for (index, path) in paths.iter().enumerate() {
            conn.execute(
                "INSERT INTO file_group_member(scan_id, group_rank, path, generation)
                 VALUES (1, 0, ?1, ?2)",
                rusqlite::params![path, index as i64 + 1],
            )
            .unwrap();
        }
        let stored: Vec<String> = conn
            .prepare("SELECT path FROM file_group_member WHERE scan_id = 1 ORDER BY generation")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(stored, paths, "no normalization, no canonicalization");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_group_member", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 4, "the LF name is one row, not two");
    }

    /// The staged apply-lease opener accepts exactly v5: an older and a newer file each get the
    /// direction's own wording, from one PRAGMA read, and `user_version` is left unchanged by
    /// the refusal.
    #[test]
    fn ensure_version_exact_accepts_only_the_current_schema() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        ensure_version_exact(&conn).unwrap();

        for (seeded, must_contain) in [
            (SCHEMA_VERSION - 1, "never migrates the checkpoint"),
            (0, "never migrates the checkpoint"),
            (SCHEMA_VERSION + 1, "created by a newer version"),
        ] {
            conn.pragma_update(None, "user_version", seeded).unwrap();
            let text = ensure_version_exact(&conn).unwrap_err().to_string();
            assert!(text.contains(must_contain), "v{seeded}: {text}");
            // The old wording sent an operator holding a READ_WRITE connection to «start
            // dedcom once as the operator». It must not come back.
            assert!(
                !text.contains("read-only mode"),
                "the apply refusal must not blame read-only mode: {text}"
            );
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, seeded, "the refusal writes nothing");
        }
    }
}
