// SPDX-License-Identifier: Apache-2.0
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

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
-- `move_event` is not here: `create_move_event` creates it from `MOVE_EVENT_V6_SQL`, the one text
-- the v6 migration also rebuilds it from, so a fresh table and a rebuilt one are byte-identical.
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

// The `move_event` table from its name on: the ONE text behind both ways the table comes to
// exist. `create_move_event` puts `CREATE TABLE IF NOT EXISTS ` in front of it on the ordinary
// path and `CREATE TABLE ` in the rebuild, and SQLite stores the statement as `CREATE TABLE ` +
// this text either way — so a fresh table and a rebuilt one carry byte for byte the same
// definition, which is what `move_event_state` compares against. A macro rather than a `const`
// because `concat!` takes literals only.
//
// No SQL comment inside: SQLite keeps everything between the parentheses verbatim, and a `CHECK`
// that only appears in a comment is stored as if it were a constraint while checking nothing.
// The columns are explained at `MOVE_EVENT_V6_SQL` instead.
macro_rules! move_event_v6_tail {
    () => {
        "move_event (
    id            INTEGER PRIMARY KEY,
    created_at    TEXT    NOT NULL,
    scan_id       INTEGER,
    source_path   BLOB    NOT NULL,
    target_path   BLOB    NOT NULL,
    hash          BLOB,
    duplicate     INTEGER NOT NULL,
    path_fidelity INTEGER NOT NULL DEFAULT 0,
    CHECK (path_fidelity IN (0, 1)),
    CHECK (path_fidelity = 0
           OR (typeof(source_path) = 'blob' AND typeof(target_path) = 'blob'))
)"
    };
}

/// The v6 `move_event` table exactly as `sqlite_master.sql` records it: `CREATE TABLE ` + the
/// tail, without `IF NOT EXISTS` and without the terminating `;`, which is how SQLite stores every
/// `CREATE TABLE`.
///
/// `source_path` and `target_path` are the raw bytes of the two pathnames the move handled, not
/// a lossy string of them. `path_fidelity` is 1 when a row's bytes are exactly what a v6 writer
/// handled and 0 for a row carried over from the v5 TEXT journal, whose writer went through
/// `to_string_lossy` — those bytes cannot be recovered, and the row says so. The first CHECK pins
/// the domain; the second is the honesty rule: TEXT with 0 is tolerated (a build from before
/// schema versioning writes exactly that), TEXT that claims exactness is refused.
pub const MOVE_EVENT_V6_SQL: &str = concat!("CREATE TABLE ", move_event_v6_tail!());

/// The v5 `move_event` table exactly as `sqlite_master.sql` records it, frozen. The first public
/// build wrote this text and no build before v6 changed it, so every v5 checkpoint the product
/// ever created carries these bytes. The migration rebuilds a table only when its stored text is
/// this, byte for byte (`move_event_state`); the whitespace is the old literal's, not a style.
pub const MOVE_EVENT_V5_SQL: &str = "CREATE TABLE move_event (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    scan_id     INTEGER,
    source_path TEXT NOT NULL,
    target_path TEXT NOT NULL,
    hash        BLOB,
    duplicate   INTEGER NOT NULL
)";

/// Creates the v6 `move_event` table from the one canonical tail. With `IF NOT EXISTS` on the
/// ordinary migration path, where the table is usually there already; without it in the rebuild,
/// where the name was freed a statement ago inside the same transaction and anything found under
/// it would be a defect, not something to adopt.
fn create_move_event(conn: &Connection, if_not_exists: bool) -> rusqlite::Result<()> {
    conn.execute_batch(if if_not_exists {
        concat!("CREATE TABLE IF NOT EXISTS ", move_event_v6_tail!(), ";")
    } else {
        concat!("CREATE TABLE ", move_event_v6_tail!(), ";")
    })
}

/// One row of `PRAGMA table_xinfo`, as SQLite records it: position, declared name and type, the
/// NOT NULL flag, the default expression, the 1-based place in the primary key (0 = none) and the
/// hidden kind — 0 ordinary, 2 a VIRTUAL generated column, 3 a STORED one. `table_info` omits
/// generated columns altogether; `xinfo` lists them, which is why the classifier reads this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnShape {
    pub cid: i64,
    pub name: String,
    pub decl_type: String,
    pub not_null: i64,
    pub default: Option<String>,
    pub pk: i64,
    pub hidden: i64,
}

/// A reference column: (cid, name, type, notnull, default, pk, hidden).
type ColumnRef = (
    i64,
    &'static str,
    &'static str,
    i64,
    Option<&'static str>,
    i64,
    i64,
);

/// `PRAGMA table_xinfo` of the v5 table, in full. Compared whole: seven rows, none hidden.
const XINFO_V5: &[ColumnRef] = &[
    (0, "id", "INTEGER", 0, None, 1, 0),
    (1, "created_at", "TEXT", 1, None, 0, 0),
    (2, "scan_id", "INTEGER", 0, None, 0, 0),
    (3, "source_path", "TEXT", 1, None, 0, 0),
    (4, "target_path", "TEXT", 1, None, 0, 0),
    (5, "hash", "BLOB", 0, None, 0, 0),
    (6, "duplicate", "INTEGER", 1, None, 0, 0),
];

/// `PRAGMA table_xinfo` of the v6 table, in full. Compared whole: eight rows, none hidden.
const XINFO_V6: &[ColumnRef] = &[
    (0, "id", "INTEGER", 0, None, 1, 0),
    (1, "created_at", "TEXT", 1, None, 0, 0),
    (2, "scan_id", "INTEGER", 0, None, 0, 0),
    (3, "source_path", "BLOB", 1, None, 0, 0),
    (4, "target_path", "BLOB", 1, None, 0, 0),
    (5, "hash", "BLOB", 0, None, 0, 0),
    (6, "duplicate", "INTEGER", 1, None, 0, 0),
    (7, "path_fidelity", "INTEGER", 1, Some("0"), 0, 0),
];

fn reference_shape(reference: &[ColumnRef]) -> Vec<ColumnShape> {
    reference
        .iter()
        .map(
            |&(cid, name, decl_type, not_null, default, pk, hidden)| ColumnShape {
                cid,
                name: name.to_string(),
                decl_type: decl_type.to_string(),
                not_null,
                default: default.map(str::to_string),
                pk,
                hidden,
            },
        )
        .collect()
}

/// `PRAGMA table_xinfo` of one table, every row. The name is one of ours, never user input.
pub fn table_xinfo(conn: &Connection, table: &str) -> Result<Vec<ColumnShape>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_xinfo({table})"))?;
    let rows = stmt.query_map([], |row| {
        Ok(ColumnShape {
            cid: row.get(0)?,
            name: row.get(1)?,
            decl_type: row.get(2)?,
            not_null: row.get(3)?,
            default: row.get(4)?,
            pk: row.get(5)?,
            hidden: row.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// What sits under the name `move_event`, judged by the stored definition and nothing weaker.
///
/// Column names are not a definition: a table with the seven v5 names could carry an eighth
/// column, a generated one, a foreign CHECK or a comment that looks like one, and a rebuild that
/// trusted the names would copy what it knows and drop the rest. So the verdict is the exact
/// stored text of `sqlite_master.sql` — SQLite keeps `CREATE TABLE ` plus everything from the
/// table's name on, verbatim, and only `ALTER TABLE` ever rewrites it — confirmed by the full
/// `PRAGMA table_xinfo`, generated and hidden columns included. Both must match one of the two
/// texts this product ever wrote; anything else is `Other`, and `Other` is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveEventState {
    /// No object of that name, in any letter case. Legitimate only on a first run.
    Absent,
    /// The v5 table, byte for byte: what every build before v6 wrote.
    ExactV5,
    /// The v6 table, byte for byte: what this build writes and rebuilds.
    ExactV6,
    /// Anything else, with the first difference found. Never the foreign text itself.
    Other(String),
}

impl std::fmt::Display for MoveEventState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MoveEventState::Absent => f.write_str("absent"),
            MoveEventState::ExactV5 => f.write_str("the v5 table"),
            MoveEventState::ExactV6 => f.write_str("the v6 table"),
            MoveEventState::Other(detail) => f.write_str(detail),
        }
    }
}

pub fn move_event_state(conn: &Connection) -> Result<MoveEventState> {
    // By name alone, without a type filter: names are one namespace, and a view or an index
    // squatting this one must read as «not a table», never as «absent» — absent is what would let
    // `CREATE TABLE IF NOT EXISTS` run against it. SQLite compares object names without case, so
    // the lookup does too.
    let mut stmt = conn.prepare(
        "SELECT type, name, sql FROM sqlite_master WHERE name = 'move_event' COLLATE NOCASE",
    )?;
    let objects: Vec<(String, String, Option<String>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let (kind, name, sql) = match objects.as_slice() {
        [] => return Ok(MoveEventState::Absent),
        [one] => one.clone(),
        many => {
            return Ok(MoveEventState::Other(format!(
                "{} objects answer to the name move_event",
                many.len()
            )))
        }
    };
    if kind != "table" {
        let article = if kind.starts_with('i') { "an" } else { "a" };
        return Ok(MoveEventState::Other(format!(
            "`{name}` is {article} {kind}, not a table"
        )));
    }
    let sql = sql.unwrap_or_default();
    let shape = table_xinfo(conn, "move_event")?;
    if sql == MOVE_EVENT_V5_SQL && shape == reference_shape(XINFO_V5) {
        return Ok(MoveEventState::ExactV5);
    }
    if sql == MOVE_EVENT_V6_SQL && shape == reference_shape(XINFO_V6) {
        return Ok(MoveEventState::ExactV6);
    }
    Ok(MoveEventState::Other(first_difference(&sql, &shape)))
}

/// The first place a stored definition parts from the nearest canon — the one sharing the longer
/// prefix with it — as lengths, a byte position and column names. Enough to say what is there and
/// where; deliberately not the foreign text itself.
fn first_difference(sql: &str, shape: &[ColumnShape]) -> String {
    let common = |canon: &str| {
        sql.bytes()
            .zip(canon.bytes())
            .take_while(|(a, b)| a == b)
            .count()
    };
    // The nearest canon is the one sharing the longer prefix; on a tie — the name itself differs,
    // as after a RENAME quoted it or under another letter case — the one whose columns match, and
    // failing that the v6 this build writes.
    let (common_v5, common_v6) = (common(MOVE_EVENT_V5_SQL), common(MOVE_EVENT_V6_SQL));
    let prefer_v6 =
        common_v6 > common_v5 || (common_v6 == common_v5 && shape != reference_shape(XINFO_V5));
    let (version, canon, reference) = if prefer_v6 {
        (6, MOVE_EVENT_V6_SQL, XINFO_V6)
    } else {
        (5, MOVE_EVENT_V5_SQL, XINFO_V5)
    };
    let mut found = Vec::new();
    if sql != canon {
        found.push(format!(
            "the stored definition ({} bytes) differs from the v{version} definition ({} bytes) at byte {}",
            sql.len(),
            canon.len(),
            common(canon)
        ));
    }
    let expected = reference_shape(reference);
    if shape != expected {
        let describe = |column: &ColumnShape| {
            let kind = match column.hidden {
                0 => "",
                2 => ", VIRTUAL generated",
                3 => ", STORED generated",
                _ => ", hidden",
            };
            let not_null = if column.not_null == 1 {
                " NOT NULL"
            } else {
                ""
            };
            let default = column
                .default
                .as_deref()
                .map(|value| format!(" DEFAULT {value}"))
                .unwrap_or_default();
            format!(
                "column {} `{}` ({}{not_null}{default}{kind})",
                column.cid, column.name, column.decl_type
            )
        };
        match shape.iter().zip(&expected).find(|(got, want)| got != want) {
            Some((got, _)) => found.push(format!(
                "{} is not the v{version} column at that position",
                describe(got)
            )),
            None if shape.len() > expected.len() => found.push(format!(
                "{} is not in the v{version} definition",
                describe(&shape[expected.len()])
            )),
            None => found.push(format!(
                "column `{}` of the v{version} definition is missing",
                expected[shape.len()].name
            )),
        }
    }
    found.join("; ")
}

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
///
/// v6 stores the two `move_event` pathnames as BLOB — the raw bytes the move handled — and adds
/// `path_fidelity`, which says whether a row's bytes are exact (written by a v6 build) or carried
/// over from the v5 TEXT journal, whose writer went through `to_string_lossy` and cannot be
/// undone. Not additive: the table is rebuilt inside the migration transaction, rows and ids
/// preserved, and only after its stored definition and its dependencies were verified to be
/// exactly what the product wrote — anything else cancels the upgrade before the rebuild, data
/// intact. A v5 build must not open a v6 DB: it has no production reader of the journal, but its
/// writer binds a String, so every triage move it recorded would land as TEXT again and the
/// journal would quietly lose the very property this version establishes.
pub const SCHEMA_VERSION: i64 = 6;

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
    refuse_if_newer(version, supported)
}

/// The refusal itself, for a stamp already read: above `supported` the checkpoint was written by
/// a newer build, and nothing of this build may touch it. One wording for every caller — the
/// opener's version guard and `migrate`, which reads the stamp inside its own transaction.
fn refuse_if_newer(version: i64, supported: i64) -> Result<()> {
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
const FLOOR_V6_COLUMNS: &[(&str, &str)] = &[("move_event", "path_fidelity")];

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
    // v6 adds a column to a v0 table, so it takes the column path; the steps are independent, so
    // its place among them is immaterial.
    if version >= 6 {
        add_columns(FLOOR_V6_COLUMNS);
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
/// v6 adds no name at all: `path_fidelity` is a column of a table that existed at v0, so it lives
/// in the floors, not here.
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

// Test seam: fires once, after the shape guard has read `PRAGMA user_version` and before it has
// looked up a single name. It exists so a test can commit a whole migration from a SECOND
// connection at exactly the moment that used to matter, and prove deterministically — no sleeps,
// no racing threads — that the guard judges one database snapshot from end to end. Not compiled
// into a production build at all.
#[cfg(test)]
thread_local! {
    static SHAPE_RACE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arms the one-shot shape-guard seam for this thread and disarms it on drop.
#[cfg(test)]
pub(crate) struct ShapeGuardRace;

#[cfg(test)]
impl ShapeGuardRace {
    pub(crate) fn armed(action: impl FnOnce() + 'static) -> Self {
        SHAPE_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
        ShapeGuardRace
    }

    /// Whether the armed shot was consumed. A test whose seam was never reached proved nothing.
    pub(crate) fn fired(&self) -> bool {
        SHAPE_RACE_HOOK.with(|slot| slot.borrow().is_none())
    }
}

#[cfg(test)]
impl Drop for ShapeGuardRace {
    fn drop(&mut self) {
        SHAPE_RACE_HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
fn take_shape_race_hook() {
    let action = SHAPE_RACE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
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
///
/// The whole judgement reads ONE snapshot. Every question below — how many user objects there
/// are, what version the checkpoint declares, which tables and columns its floor requires and
/// which of our names are already taken — used to be its own statement, and separate statements
/// outside a transaction are separate snapshots. A migration committing between two of them
/// showed this guard the stamp of the version it started at together with the names of the version
/// it ended at: a combination no committed database ever held, refused with a sentence that named
/// a real object and a real version and was still wrong. `ensure_version_exact` above already
/// states the narrow half of this rule for two reads of the stamp; this is the same rule over the
/// whole inspection.
pub fn ensure_recognisable_shape(conn: &Connection) -> Result<()> {
    // Deferred: the read lock is taken by the first statement and given back when the guard
    // returns. Nothing here writes, so every path out rolls back — and the rollback's own failure
    // must never mask a refusal.
    let tx = conn.unchecked_transaction()?;
    let verdict = judge_shape(&tx);
    let ended = tx.rollback();
    verdict?;
    ended?;
    Ok(())
}

/// The judgement itself, over whatever snapshot the caller has opened.
fn judge_shape(conn: &Connection) -> Result<()> {
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
    #[cfg(test)]
    take_shape_race_hook();
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

/// The v6 step's refusal, in words that stay true after it: the transaction rolled back, so the
/// checkpoint keeps its data and its stamp — but the opener switched the journal to WAL before the
/// migration began, so «nothing was changed» would be a lie. Names the step, the cause and what to
/// do; used for EVERY error inside the step, SQLite's own included.
fn upgrade_cancelled(step: &str, version: i64, cause: &str, advice: &str) -> AppError {
    AppError::msg(format!(
        "The schema v6 upgrade of dedcom.db was cancelled at {step}: {cause}. The checkpoint keeps \
         its data and stays at schema v{version}. This attempt may already have switched the file \
         to WAL mode (dedcom.db-wal and dedcom.db-shm may now exist next to it); that changes no \
         data. {advice}"
    ))
}

const ADVICE_ASIDE: &str = "Move dedcom.db aside to start with a fresh checkpoint, or restore \
                            the table to the definition this product writes and start dedcom \
                            again.";
const ADVICE_DEPENDENT: &str =
    "Drop it and re-create it after the upgrade, or move dedcom.db aside.";
const ADVICE_FOREIGN_KEY: &str = "Drop the referencing table's foreign key (rebuild that table \
                                  without it), or move dedcom.db aside.";
const ADVICE_TEMP_NAME: &str = "Rename that object, or move dedcom.db aside.";
const ADVICE_SQLITE: &str = "Repair or drop the object SQLite names, then start dedcom again.";

/// Why a step of the v6 upgrade stops: a refusal of ours, or SQLite's own error on the way.
enum Cancel {
    Refused { cause: String, advice: &'static str },
    Sqlite(rusqlite::Error),
}

impl From<rusqlite::Error> for Cancel {
    fn from(err: rusqlite::Error) -> Self {
        Cancel::Sqlite(err)
    }
}

fn refuse(cause: String, advice: &'static str) -> Cancel {
    Cancel::Refused { cause, advice }
}

fn cancelled(step: &str, version: i64, cancel: Cancel) -> AppError {
    match cancel {
        Cancel::Refused { cause, advice } => upgrade_cancelled(step, version, &cause, advice),
        Cancel::Sqlite(err) => upgrade_cancelled(step, version, &err.to_string(), ADVICE_SQLITE),
    }
}

/// The v6 step of `migrate`: judges what sits under `move_event` in this transaction's snapshot
/// and, for the v5 table and nothing else, rebuilds it as v6. Runs BEFORE the `SCHEMA` batch, so
/// the state is read before `IF NOT EXISTS` could have created anything under the name.
///
/// `version` is the stamp read inside the same transaction; a stamp above `SCHEMA_VERSION` was
/// refused before this runs. The stamp and the table have to agree: a v6 table under an older
/// stamp would mean `path_fidelity` was adopted from a checkpoint that never had it, a v5 table
/// under the v6 stamp means the file lies about itself. Both are refused.
fn upgrade_move_event(tx: &Connection, version: i64) -> Result<()> {
    let state = move_event_state(tx)
        .map_err(|err| upgrade_cancelled("precheck", version, &err.to_string(), ADVICE_SQLITE))?;
    match state {
        MoveEventState::Absent => Ok(()),
        MoveEventState::ExactV6 if version == SCHEMA_VERSION => Ok(()),
        MoveEventState::ExactV6 => Err(upgrade_cancelled(
            "precheck",
            version,
            &format!(
                "move_event already has the v6 definition while the checkpoint declares schema \
                 v{version}; path_fidelity is introduced by v6 and cannot be adopted from an older \
                 checkpoint"
            ),
            "Rebuild the table without that column, or move dedcom.db aside.",
        )),
        MoveEventState::ExactV5 if version >= SCHEMA_VERSION => Err(upgrade_cancelled(
            "precheck",
            version,
            &format!("the checkpoint declares schema v{version} but move_event is the v5 table"),
            ADVICE_ASIDE,
        )),
        MoveEventState::ExactV5 => {
            ensure_rebuild_is_safe(tx).map_err(|cancel| cancelled("precheck", version, cancel))?;
            rebuild_move_event(tx, version)
        }
        MoveEventState::Other(detail) => Err(upgrade_cancelled(
            "precheck",
            version,
            &format!("move_event is not the table this product wrote ({detail})"),
            ADVICE_ASIDE,
        )),
    }
}

/// What the rebuild may destroy: nothing that is not ours. `DROP TABLE` takes the table's indexes
/// and triggers with it, runs the `ON DELETE` clauses of every table whose foreign key points at
/// it, and leaves a view that named it dangling after `RENAME` rewrote the view onto the temporary
/// name; a copy by known column names loses unknown ones. The definition itself was judged by
/// `move_event_state` (P1); this reads the rest of the snapshot the rebuild will act on, inside
/// the same transaction, and refuses rather than converts — re-creating foreign objects would be
/// a converter with no specification.
fn ensure_rebuild_is_safe(tx: &Connection) -> std::result::Result<(), Cancel> {
    // P2: the canonical table has no index, not even an automatic one.
    let indexes: Vec<String> = tx
        .prepare("SELECT name FROM pragma_index_list('move_event')")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if let Some(index) = indexes.first() {
        return Err(refuse(
            format!("index `{index}` is defined on move_event"),
            ADVICE_DEPENDENT,
        ));
    }
    // P3: triggers and views that mention the table, without regard to case. A false hit on a
    // foreign object that merely contains the word costs a refusal with the data intact.
    let dependents: Vec<(String, String)> = tx
        .prepare(
            "SELECT type, name FROM sqlite_master
              WHERE type IN ('trigger', 'view') AND instr(lower(sql), 'move_event') > 0",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    if let Some((kind, name)) = dependents.first() {
        return Err(refuse(
            format!("{kind} `{name}` refers to move_event"),
            ADVICE_DEPENDENT,
        ));
    }
    // P4: no foreign key of any table points at it. The engine's own tables are skipped by the
    // literal seven-character prefix, as in `judge_shape` — `LIKE 'sqlite_%'` would also skip a
    // user table called `sqlitex_notes` and its foreign key with it. The parent name comes back as
    // it was written, so the comparison folds case.
    let tables: Vec<String> = tx
        .prepare(
            "SELECT name FROM sqlite_master
              WHERE type = 'table' AND substr(name, 1, 7) <> 'sqlite_'",
        )?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for table in &tables {
        let parents: Vec<String> = tx
            .prepare("SELECT \"table\" FROM pragma_foreign_key_list(?1)")?
            .query_map([table], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if parents
            .iter()
            .any(|parent| parent.eq_ignore_ascii_case("move_event"))
        {
            return Err(refuse(
                format!("table `{table}` has a foreign key referencing move_event"),
                ADVICE_FOREIGN_KEY,
            ));
        }
    }
    // P5: the temporary name is free, in any letter case. SQLite would refuse the RENAME in its
    // own words; this says whose object holds the name.
    let squatters: Vec<(String, String)> = tx
        .prepare(
            "SELECT type, name FROM sqlite_master WHERE name = 'move_event_v5' COLLATE NOCASE",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    if let Some((kind, name)) = squatters.first() {
        return Err(refuse(
            format!("the temporary name move_event_v5 is taken by {kind} `{name}`"),
            ADVICE_TEMP_NAME,
        ));
    }
    // P6: `CAST(text AS BLOB)` yields the bytes in the database's encoding; they are the original
    // pathname bytes only under UTF-8.
    let encoding: String = tx.query_row("PRAGMA encoding", [], |row| row.get(0))?;
    if encoding != "UTF-8" {
        return Err(refuse(
            format!("the database encoding is {encoding}, not UTF-8"),
            ADVICE_ASIDE,
        ));
    }
    Ok(())
}

/// Rebuilds the v5 table as v6 inside the caller's transaction. The old table steps aside under a
/// temporary name and the final one is created under its own name at once — never renamed into
/// place, because `RENAME` quotes the name in the stored text and the rebuilt table would stop
/// being equal to a fresh one. The rows are copied with their ids, marked as carried, counted, and
/// only then the old table goes. Only after `ensure_rebuild_is_safe`: P2–P4 are what make the
/// `DROP` take nothing else with it.
fn rebuild_move_event(tx: &Connection, version: i64) -> Result<()> {
    let at = |step: &'static str| {
        move |err: rusqlite::Error| cancelled(step, version, Cancel::Sqlite(err))
    };
    tx.execute_batch("ALTER TABLE move_event RENAME TO move_event_v5;")
        .map_err(at("rename"))?;
    create_move_event(tx, false).map_err(at("create"))?;
    tx.execute_batch(&format!(
        "INSERT INTO move_event
             (id, created_at, scan_id, source_path, target_path, hash, duplicate, path_fidelity)
         SELECT id, created_at, scan_id, CAST(source_path AS BLOB), CAST(target_path AS BLOB),
                hash, duplicate, {}
           FROM move_event_v5 ORDER BY id;",
        crate::model::action::PathFidelity::CarriedFromText.stored()
    ))
    .map_err(at("copy"))?;
    let (carried, copied): (i64, i64) = tx
        .query_row(
            "SELECT (SELECT COUNT(*) FROM move_event_v5), (SELECT COUNT(*) FROM move_event)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(at("copy"))?;
    if carried != copied {
        return Err(cancelled(
            "copy",
            version,
            refuse(
                format!("copied {copied} of {carried} journal rows"),
                ADVICE_ASIDE,
            ),
        ));
    }
    #[cfg(test)]
    take_migrate_fault(MigrateFaultPoint::RowsCopied, tx)
        .map_err(|err| upgrade_cancelled("copy", version, &err.to_string(), ADVICE_ASIDE))?;
    tx.execute_batch("DROP TABLE move_event_v5;")
        .map_err(at("drop"))?;
    #[cfg(test)]
    take_migrate_fault(MigrateFaultPoint::OldTableDropped, tx)
        .map_err(|err| upgrade_cancelled("drop", version, &err.to_string(), ADVICE_ASIDE))?;
    Ok(())
}

/// Upgrades a checkpoint to the current schema. Runs only after `ensure_recognisable_shape` has
/// established that the database is one of ours — on its own this function would adopt a foreign
/// file and stamp it. What it does NOT leave to the opener is the version rule: a stamp above
/// `SCHEMA_VERSION` is refused here too, inside the transaction and before anything is judged,
/// because this function is public and what it writes at the end is `SCHEMA_VERSION` — over a
/// file a newer build wrote that would be a downgrade in disguise.
///
/// One transaction, taken IMMEDIATE: the v6 step reads the definition of `move_event` and then
/// rewrites the table, and a deferred transaction that read under a shared lock could be denied
/// the write lock afterwards by a concurrent opener (`SQLITE_BUSY_SNAPSHOT`); holding the write
/// lock from the first statement means the snapshot the step judged is the snapshot it rewrites.
/// Every failure before `commit` — the v6 step's own refusals, SQLite's errors, the injected
/// faults of the tests — rolls the whole of it back, stamp included. What no test proves is a
/// process or power failure in the middle of the transaction: that is SQLite's WAL recovery, and
/// it is trusted rather than demonstrated here.
pub fn migrate(conn: &Connection) -> Result<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    refuse_if_newer(version, SCHEMA_VERSION)?;
    // v6, the move journal, BEFORE the batch: what sits under `move_event` has to be judged before
    // `IF NOT EXISTS` could have created anything under the name. Not additive — the table is
    // rebuilt — and every refusal inside it leaves the checkpoint exactly as it was.
    upgrade_move_event(&tx, version)?;
    tx.execute_batch(SCHEMA)?;
    create_move_event(&tx, true)?;
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
    // v6's post-condition, before the stamp: whichever path led here — fresh, rebuilt, or already
    // v6 — the table under `move_event` is now the v6 definition byte for byte, or the stamp is not
    // written.
    let state = move_event_state(&tx).map_err(|err| {
        upgrade_cancelled("postcondition", version, &err.to_string(), ADVICE_SQLITE)
    })?;
    if state != MoveEventState::ExactV6 {
        return Err(upgrade_cancelled(
            "postcondition",
            version,
            &format!("move_event is {state} after the upgrade, not the v6 table"),
            ADVICE_ASIDE,
        ));
    }
    // Stamp the current schema version (also upgrades a pre-versioning DB from 0).
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    #[cfg(test)]
    take_migrate_fault(MigrateFaultPoint::Stamped, &tx)?;
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

// Test seam: fires once, at one of three points inside the v6 step of `migrate` — the rows copied,
// the old table dropped, the stamp written — with the open transaction in
// hand, so a test can look at the database from INSIDE the transaction that is about to fail and
// then prove that everything it saw was rolled back. Absent from every non-test build.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrateFaultPoint {
    RowsCopied,
    OldTableDropped,
    Stamped,
}

#[cfg(test)]
type MigrateObserver = Box<dyn FnOnce(&Connection)>;

#[cfg(test)]
thread_local! {
    static MIGRATE_FAULT: std::cell::RefCell<Option<(MigrateFaultPoint, MigrateObserver)>> =
        const { std::cell::RefCell::new(None) };
}

/// Arms the one-shot migrate fault for this thread and disarms it on drop.
#[cfg(test)]
pub(crate) struct MigrateFault;

#[cfg(test)]
impl MigrateFault {
    pub(crate) fn armed(
        point: MigrateFaultPoint,
        observe: impl FnOnce(&Connection) + 'static,
    ) -> Self {
        MIGRATE_FAULT.with(|slot| *slot.borrow_mut() = Some((point, Box::new(observe))));
        MigrateFault
    }

    /// Whether the armed shot was consumed. A test whose seam was never reached proved nothing.
    pub(crate) fn fired(&self) -> bool {
        MIGRATE_FAULT.with(|slot| slot.borrow().is_none())
    }
}

#[cfg(test)]
impl Drop for MigrateFault {
    fn drop(&mut self) {
        MIGRATE_FAULT.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Consumes the armed fault if it is set for `point`: runs the observer on the open transaction,
/// then fails the step.
#[cfg(test)]
fn take_migrate_fault(point: MigrateFaultPoint, tx: &Connection) -> Result<()> {
    let armed = MIGRATE_FAULT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let hit = matches!(&*slot, Some((armed_point, _)) if *armed_point == point);
        if hit {
            slot.take()
        } else {
            None
        }
    });
    if let Some((_, observe)) = armed {
        observe(tx);
        return Err(AppError::msg("injected migrate fault"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::action::PathFidelity;
    use crate::testfixtures::{genuine_checkpoint, rebuild_move_event_as, strip_v6, ScratchDir};
    use rusqlite::Connection;
    use std::os::unix::ffi::OsStrExt;

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

    /// A genuinely v5-shaped DB: the current schema with the v6 rebuild of `move_event` undone —
    /// the v5 table, byte for byte — and the stamp rewound. Foreign keys are enforced, as on
    /// every `ScanStore` connection, so a fixture with a cascading key behaves as it would live.
    fn v5_shaped_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        enforce_foreign_keys(&conn).unwrap();
        migrate(&conn).unwrap();
        strip_v6(&conn);
        conn.pragma_update(None, "user_version", 5i64).unwrap();
        conn
    }

    /// A genuinely v4-shaped DB: the current schema with every v6 and v5 addition taken away again
    /// and the stamp rewound.
    fn v4_shaped_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        strip_v6(&conn);
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
        strip_v6(&conn);
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
        strip_v6(&conn);
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
        // Rewind to a v1 DB: the v5 move journal (a v6 table under an older stamp is refused, not
        // adopted), then drop the v2 column (SQLite 3.35+ supports DROP COLUMN) and restamp.
        strip_v6(&conn);
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

    // ------------------------------------------------------------------ move_event v6

    /// The stored definition of `move_event`, as SQLite records it — the text the classifier
    /// judges, found without regard to the letter case of the name.
    fn move_event_sql(conn: &Connection) -> String {
        conn.query_row(
            "SELECT sql FROM sqlite_master
              WHERE type = 'table' AND name = 'move_event' COLLATE NOCASE",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// Journal rows with EXPLICIT, non-consecutive ids, for a v5-era table (TEXT pathnames): a
    /// plain name, one with LF, and one that already holds U+FFFD — the character a lossy
    /// conversion leaves behind, which the migration must carry as it is, not «repair».
    const JOURNAL: &[(i64, &str)] = &[(3, "/a/x"), (7, "/a/we\nird"), (12, "/a/\u{FFFD}.bin")];

    fn seed_journal_rows(conn: &Connection, rows: &[(i64, &str)]) {
        for (id, path) in rows {
            conn.execute(
                "INSERT INTO move_event
                     (id, created_at, scan_id, source_path, target_path, hash, duplicate)
                 VALUES (?1, 'then', NULL, ?2, ?2 || '.moved', NULL, 0)",
                params![id, path],
            )
            .unwrap();
        }
    }

    /// The ids of the journal rows, in order.
    fn journal_ids(conn: &Connection) -> Vec<i64> {
        conn.prepare("SELECT id FROM move_event ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect()
    }

    /// The source pathnames of the journal, as the reader hands them back, in id order.
    fn journaled_sources(rows: &[crate::model::action::MoveEventRow]) -> Vec<Vec<u8>> {
        rows.iter()
            .map(|row| row.event.source_path.as_os_str().as_bytes().to_vec())
            .collect()
    }

    fn seeded_sources() -> Vec<Vec<u8>> {
        JOURNAL
            .iter()
            .map(|(_, path)| path.as_bytes().to_vec())
            .collect()
    }

    fn row_count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    /// Every column of every row of `move_event`, in id order, rendered by `quote()` so the storage
    /// class is part of the text (X'..' for a BLOB, '..' for TEXT). Reads the columns the table HAS
    /// — a user's column or a generated one is part of the dump — so «equal to its own state before
    /// the attempt» means all of it.
    fn journal_dump(conn: &Connection) -> Vec<String> {
        let columns: Vec<String> = table_xinfo(conn, "move_event")
            .unwrap()
            .into_iter()
            .map(|column| column.name)
            .collect();
        let select = columns
            .iter()
            .map(|column| format!("quote(\"{column}\")"))
            .collect::<Vec<_>>()
            .join(" || '|' || ");
        conn.prepare(&format!("SELECT {select} FROM move_event ORDER BY id"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect()
    }

    /// Everything the pre-check judges and a rebuild would touch: the table's own definition and
    /// full column list, its rows, the whole schema and the stamp. Compared before and after a
    /// refused upgrade — against the table's OWN prior state, not against a canon.
    #[derive(Debug, PartialEq)]
    struct TableState {
        sql: String,
        shape: Vec<ColumnShape>,
        rows: Vec<String>,
        schema: Vec<String>,
        version: i64,
    }

    fn table_state(conn: &Connection) -> TableState {
        TableState {
            sql: move_event_sql(conn),
            shape: table_xinfo(conn, "move_event").unwrap(),
            rows: journal_dump(conn),
            schema: schema_fingerprint(conn),
            version: user_version(conn),
        }
    }

    /// The eight v6 columns with both CHECKs only in comments: the shape of v6 and none of its
    /// rules. SQLite stores the comments in the text and enforces nothing.
    const V6_CHECKS_IN_COMMENTS: &str = "CREATE TABLE move_event (
    id            INTEGER PRIMARY KEY,
    created_at    TEXT    NOT NULL,
    scan_id       INTEGER,
    source_path   BLOB    NOT NULL,
    target_path   BLOB    NOT NULL,
    hash          BLOB,
    duplicate     INTEGER NOT NULL,
    path_fidelity INTEGER NOT NULL DEFAULT 0
    -- CHECK (path_fidelity IN (0, 1)),
    -- CHECK (path_fidelity = 0 OR (typeof(source_path) = 'blob' AND typeof(target_path) = 'blob'))
)";

    /// The v6 text with one extra space inside a CHECK — the same words, not the same bytes.
    fn v6_with_an_extra_space() -> String {
        MOVE_EVENT_V6_SQL.replacen("path_fidelity IN (0, 1)", "path_fidelity  IN (0, 1)", 1)
    }

    /// A fresh table and a v5 table are recognised, each from its full definition; nothing else
    /// answers to either name.
    #[test]
    fn move_event_state_recognises_exactly_the_two_canons() {
        let conn = Connection::open_in_memory().unwrap();
        assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::Absent);
        create_move_event(&conn, true).unwrap();
        assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV6);
        assert_eq!(
            move_event_sql(&conn),
            MOVE_EVENT_V6_SQL,
            "IF NOT EXISTS leaves no trace in the stored text"
        );
        assert_eq!(
            table_xinfo(&conn, "move_event").unwrap(),
            reference_shape(XINFO_V6)
        );

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MOVE_EVENT_V5_SQL).unwrap();
        assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV5);
        assert_eq!(
            table_xinfo(&conn, "move_event").unwrap(),
            reference_shape(XINFO_V5)
        );
    }

    /// Lookalikes are `Other`, each with the difference named: (a) the v6 columns with the CHECKs
    /// only in comments; (b) the v6 text with one extra space; (c) v5 plus a column added later;
    /// (d) v5 plus a VIRTUAL generated column, which `table_info` does not even list; (e) the v5
    /// body under the name in another letter case — found, but not the canon; (f) a view under the
    /// name, which a lookup filtered to tables would have mistaken for «absent»; (g) the v6 body
    /// under the quoted name a RENAME leaves behind — the v6 columns, not the v6 text.
    #[test]
    fn move_event_state_refuses_lookalikes() {
        let other = |conn: &Connection| match move_event_state(conn).unwrap() {
            MoveEventState::Other(detail) => detail,
            state => panic!("expected Other, got {state:?}"),
        };

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(V6_CHECKS_IN_COMMENTS).unwrap();
        let detail = other(&conn);
        assert!(
            detail.contains("differs from the v6 definition"),
            "(a) {detail}"
        );
        assert!(
            !detail.contains("column"),
            "(a) the columns are the v6 columns: {detail}"
        );

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&v6_with_an_extra_space()).unwrap();
        let detail = other(&conn);
        assert!(
            detail.contains("differs from the v6 definition"),
            "(b) {detail}"
        );

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MOVE_EVENT_V5_SQL).unwrap();
        conn.execute_batch("ALTER TABLE move_event ADD COLUMN note TEXT")
            .unwrap();
        let detail = other(&conn);
        assert!(
            detail.contains("differs from the v5 definition"),
            "(c) {detail}"
        );
        assert!(
            detail.contains("column 7 `note` (TEXT) is not in the v5 definition"),
            "(c) {detail}"
        );

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MOVE_EVENT_V5_SQL).unwrap();
        conn.execute_batch(
            "ALTER TABLE move_event ADD COLUMN v INTEGER GENERATED ALWAYS AS (duplicate + 2) VIRTUAL",
        )
        .unwrap();
        assert_eq!(
            columns_of(&conn, "move_event").len(),
            7,
            "(d) table_info does not list the generated column — names alone would pass it"
        );
        let detail = other(&conn);
        assert!(
            detail
                .contains("column 7 `v` (INTEGER, VIRTUAL generated) is not in the v5 definition"),
            "(d) {detail}"
        );

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&MOVE_EVENT_V5_SQL.replacen("move_event", "Move_Event", 1))
            .unwrap();
        let detail = other(&conn);
        assert_eq!(
            detail,
            format!(
                "the stored definition ({} bytes) differs from the v5 definition ({} bytes) at byte 13",
                MOVE_EVENT_V5_SQL.len(),
                MOVE_EVENT_V5_SQL.len()
            ),
            "(e)"
        );

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE VIEW move_event AS SELECT 1 AS one")
            .unwrap();
        assert_eq!(other(&conn), "`move_event` is a view, not a table", "(f)");

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&MOVE_EVENT_V6_SQL.replacen("move_event (", "\"move_event\" (", 1))
            .unwrap();
        let detail = other(&conn);
        assert_eq!(
            detail,
            format!(
                "the stored definition ({} bytes) differs from the v6 definition ({} bytes) at byte 13",
                MOVE_EVENT_V6_SQL.len() + 2,
                MOVE_EVENT_V6_SQL.len()
            ),
            "(g) the name quoted, as a RENAME leaves it: the v6 columns, not the v6 text"
        );
    }

    /// The rewind fixture really is the v5 table — byte for byte, and by its full column list —
    /// so the migration tests below start from what the old builds wrote, not from a paraphrase.
    /// (That the canon IS what the old builds wrote is evidence taken from a checkpoint one of them
    /// created, outside this crate; this only proves the fixture carries the canon.)
    #[test]
    fn the_v5_fixture_carries_the_v5_canon() {
        let conn = v5_shaped_db();
        assert_eq!(move_event_sql(&conn), MOVE_EVENT_V5_SQL);
        assert_eq!(
            table_xinfo(&conn, "move_event").unwrap(),
            reference_shape(XINFO_V5)
        );
        assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV5);
        assert_eq!(user_version(&conn), 5);
        assert!(!table_names(&conn).contains(&"move_event_v6_tmp".to_string()));
    }

    /// T4: the carried rows keep their ids and their bytes, and none of them claims exactness — a
    /// U+FFFD that a lossy writer left is carried as U+FFFD, not turned back into the byte it
    /// replaced. A second migration changes nothing and leaves no temporary table behind.
    #[test]
    fn carried_rows_keep_their_ids_and_never_claim_exactness() {
        let conn = v5_shaped_db();
        seed_journal_rows(&conn, JOURNAL);

        migrate(&conn).unwrap();

        assert_eq!(user_version(&conn), 6);
        assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV6);
        let rows: Vec<(i64, Vec<u8>, String, i64)> = conn
            .prepare(
                "SELECT id, source_path, typeof(source_path), path_fidelity
                   FROM move_event ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert_eq!(
            rows.iter().map(|row| row.0).collect::<Vec<_>>(),
            vec![3, 7, 12],
            "the ids are the old ids"
        );
        for ((id, path), (_, bytes, class, fidelity)) in JOURNAL.iter().zip(&rows) {
            assert_eq!(
                bytes,
                path.as_bytes(),
                "row {id}: the bytes are the UTF-8 of the old text"
            );
            assert_eq!(class, "blob", "row {id}: stored as BLOB");
            assert_eq!(
                *fidelity, 0,
                "row {id}: carried rows must not claim exactness"
            );
        }
        assert_ne!(
            rows[2].1,
            b"/a/\x80.bin".to_vec(),
            "the replacement character is carried as it is, not «recovered»"
        );

        let fingerprint = schema_fingerprint(&conn);
        migrate(&conn).unwrap();
        assert_eq!(
            schema_fingerprint(&conn),
            fingerprint,
            "a repeated migration rewrites nothing"
        );
        assert_eq!(journal_ids(&conn), vec![3, 7, 12]);
        assert!(
            !table_names(&conn).contains(&"move_event_v5".to_string()),
            "no temporary table is left behind"
        );
    }

    /// What the observer sees from inside the transaction at a fault point.
    #[derive(Debug)]
    struct Seen {
        version: i64,
        sql: String,
        temporary_table: bool,
        rows: i64,
    }

    fn observe(tx: &Connection) -> Seen {
        Seen {
            version: user_version(tx),
            sql: move_event_sql(tx),
            temporary_table: table_names(tx).contains(&"move_event_v5".to_string()),
            rows: row_count(tx, "move_event"),
        }
    }

    /// T5: a failure at any of the three points inside the v6 step — after the copy, after the old
    /// table is dropped, after the stamp — rolls everything back: the observer sees the half-done
    /// state from inside the transaction, and afterwards the table, its rows, the whole schema and
    /// the stamp are what they were. The next attempt completes the upgrade.
    #[test]
    fn a_fault_at_any_point_of_the_v6_step_rolls_everything_back() {
        use std::cell::RefCell;
        use std::rc::Rc;
        for point in [
            MigrateFaultPoint::RowsCopied,
            MigrateFaultPoint::OldTableDropped,
            MigrateFaultPoint::Stamped,
        ] {
            let conn = v5_shaped_db();
            seed_journal_rows(&conn, JOURNAL);
            let before = table_state(&conn);

            let seen: Rc<RefCell<Option<Seen>>> = Rc::new(RefCell::new(None));
            let slot = Rc::clone(&seen);
            let fault = MigrateFault::armed(point, move |tx| {
                *slot.borrow_mut() = Some(observe(tx));
            });
            let err = migrate(&conn).expect_err("the injected fault must cancel the upgrade");
            assert!(
                fault.fired(),
                "[{point:?}] the seam was never reached — the test proved nothing"
            );
            let text = err.to_string();
            assert!(
                text.contains("injected migrate fault"),
                "[{point:?}] {text}"
            );
            let seen = seen.borrow_mut().take().expect("the observer ran");
            assert_eq!(
                seen.sql, MOVE_EVENT_V6_SQL,
                "[{point:?}] inside the transaction the new table is in place"
            );
            assert_eq!(seen.rows, 3, "[{point:?}] with every row copied");
            match point {
                MigrateFaultPoint::RowsCopied => {
                    assert!(text.contains("cancelled at copy"), "{text}");
                    assert!(
                        seen.temporary_table,
                        "the old table still waits under its temporary name"
                    );
                    assert_eq!(seen.version, 5);
                }
                MigrateFaultPoint::OldTableDropped => {
                    assert!(text.contains("cancelled at drop"), "{text}");
                    assert!(!seen.temporary_table, "the old table is gone");
                    assert_eq!(seen.version, 5, "and the stamp is not yet written");
                }
                MigrateFaultPoint::Stamped => {
                    assert!(!seen.temporary_table);
                    assert_eq!(seen.version, 6, "the stamp is written, the commit is not");
                }
            }

            assert_eq!(
                table_state(&conn),
                before,
                "[{point:?}] the rollback restores everything the transaction touched"
            );
            assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV5);

            migrate(&conn).unwrap();
            assert_eq!(
                user_version(&conn),
                6,
                "[{point:?}] the next attempt completes"
            );
            assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV6);
            assert_eq!(journal_ids(&conn), vec![3, 7, 12]);
            assert!(!table_names(&conn).contains(&"move_event_v5".to_string()));
        }
    }

    /// T5, on a file: an interrupted upgrade returns the error to the opener and leaves a v5
    /// checkpoint that opens again — and the next open completes the upgrade with every row.
    #[test]
    fn an_interrupted_upgrade_leaves_a_reopenable_v5_file() {
        let _role = crate::state::store::role_guard();
        crate::state::store::set_observer_role(false);
        let dir = ScratchDir::new("interrupted-upgrade");
        let db = genuine_checkpoint(dir.path(), 5);
        seed_journal_rows(&Connection::open(&db).unwrap(), JOURNAL);

        let fault = MigrateFault::armed(MigrateFaultPoint::OldTableDropped, |_| {});
        let err = crate::state::ScanStore::open(&db)
            .err()
            .expect("an interrupted upgrade refuses the open");
        assert!(fault.fired(), "the seam was never reached");
        drop(fault);
        let text = err.to_string();
        assert!(text.contains("cancelled at drop"), "{text}");
        assert!(text.contains("stays at schema v5"), "{text}");
        {
            let conn = Connection::open(&db).unwrap();
            assert_eq!(user_version(&conn), 5);
            assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV5);
            assert_eq!(journal_ids(&conn), vec![3, 7, 12]);
        }

        let store =
            crate::state::ScanStore::open(&db).expect("the next open completes the upgrade");
        let rows = store.move_events().unwrap();
        assert_eq!(journaled_sources(&rows), seeded_sources());
        assert!(rows
            .iter()
            .all(|row| row.path_fidelity == PathFidelity::CarriedFromText));
        drop(store);
        let conn = Connection::open(&db).unwrap();
        assert_eq!(user_version(&conn), 6);
        assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV6);
    }

    /// T5b: the temporary name is taken, in another letter case — the upgrade is cancelled in our
    /// words at the pre-check, naming the object and its type, and that object keeps its row.
    #[test]
    fn a_taken_temporary_name_cancels_the_upgrade_and_keeps_the_foreign_table() {
        let conn = v5_shaped_db();
        seed_journal_rows(&conn, JOURNAL);
        conn.execute_batch(
            "CREATE TABLE Move_Event_V5 (z INTEGER); INSERT INTO Move_Event_V5 VALUES (42);",
        )
        .unwrap();
        let before = table_state(&conn);

        let err = migrate(&conn).expect_err("the temporary name is taken");
        let text = err.to_string();
        assert!(text.contains("cancelled at precheck"), "{text}");
        assert!(
            text.contains("the temporary name move_event_v5 is taken by table `Move_Event_V5`"),
            "{text}"
        );
        assert!(text.contains("stays at schema v5"), "{text}");

        assert_eq!(table_state(&conn), before);
        assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV5);
        let z: i64 = conn
            .query_row("SELECT z FROM Move_Event_V5", [], |row| row.get(0))
            .unwrap();
        assert_eq!(z, 42, "the foreign table keeps its row");
    }

    /// T6: the honesty rule of the journal, on INSERT and on UPDATE, each refusal pinned to the
    /// CHECK's own extended code. TEXT with 0 is tolerated (a build from before schema versioning
    /// writes that) and reads back as bytes; BLOB with 1 is the v6 writer's row; TEXT claiming
    /// exactness — both pathnames or one of them — is refused, and so is anything outside {0, 1}.
    #[test]
    fn fidelity_may_claim_exactness_only_for_blob_pathnames() {
        let conn = enforced_db();
        let insert = |id: i64, source: &str, target: &str, fidelity: i64| {
            conn.execute(
                &format!(
                    "INSERT INTO move_event
                         (id, created_at, source_path, target_path, duplicate, path_fidelity)
                     VALUES ({id}, 'then', {source}, {target}, 0, {fidelity})"
                ),
                [],
            )
        };
        insert(1, "'/a/x'", "'/b/x'", 0).expect("TEXT with 0 is tolerated");
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT source_path FROM move_event WHERE id = 1",
                [],
                |row| Ok(row.get_ref(0)?.as_bytes()?.to_vec()),
            )
            .unwrap();
        assert_eq!(bytes, b"/a/x", "and reads back as bytes");
        insert(2, "X'2F612F80'", "X'2F622F80'", 1).expect("BLOB with 1 is the v6 writer's row");

        assert_constraint(
            insert(3, "'/a/y'", "'/b/y'", 1),
            CONSTRAINT_CHECK,
            "TEXT pathnames claiming exactness",
        );
        assert_constraint(
            insert(3, "X'2F'", "'/b/y'", 1),
            CONSTRAINT_CHECK,
            "one TEXT pathname claiming exactness",
        );
        assert_constraint(
            insert(3, "X'2F'", "X'2F'", 2),
            CONSTRAINT_CHECK,
            "path_fidelity 2",
        );
        assert_constraint(
            insert(3, "X'2F'", "X'2F'", -1),
            CONSTRAINT_CHECK,
            "path_fidelity -1",
        );

        assert_constraint(
            conn.execute("UPDATE move_event SET path_fidelity = 1 WHERE id = 1", []),
            CONSTRAINT_CHECK,
            "promoting a TEXT row to exact",
        );
        assert_constraint(
            conn.execute(
                "UPDATE move_event SET source_path = '/a/text' WHERE id = 2",
                [],
            ),
            CONSTRAINT_CHECK,
            "an exact row rewritten as TEXT",
        );
        assert_constraint(
            conn.execute("UPDATE move_event SET path_fidelity = 2 WHERE id = 2", []),
            CONSTRAINT_CHECK,
            "an exact row moved outside the domain",
        );

        assert_eq!(
            journal_dump(&conn),
            vec![
                "1|'then'|NULL|'/a/x'|'/b/x'|NULL|0|0".to_string(),
                "2|'then'|NULL|X'2F612F80'|X'2F622F80'|NULL|0|1".to_string(),
            ],
            "what survived is exactly the two accepted rows"
        );
    }

    /// T7: a v5-aware build refuses a real v6 checkpoint and names both versions; the same
    /// comparison with this build's own maximum accepts it. Executed, not asserted from constants.
    #[test]
    fn a_v5_aware_build_refuses_a_v6_db_and_accepts_its_own() {
        let conn = v5_shaped_db();
        seed_journal_rows(&conn, JOURNAL);
        migrate(&conn).unwrap();
        let fingerprint = schema_fingerprint(&conn);

        let text = ensure_version_at_most(&conn, 5)
            .expect_err("a v5 build must refuse a v6 DB")
            .to_string();
        assert!(text.contains("schema v6"), "{text}");
        assert!(text.contains("supports v5"), "{text}");
        assert_eq!(user_version(&conn), 6, "a refusal must not restamp");
        assert_eq!(schema_fingerprint(&conn), fingerprint, "nor migrate");

        ensure_version_at_most(&conn, 6).expect("this build's own maximum accepts it");
        ensure_version_supported(&conn).expect("and so does the production entry point");
    }

    /// T8: the v6 definition is canonical on the bundled SQLite wherever a table can come from —
    /// fresh, migrated, migrated and reopened twice more, and on a file after `VACUUM` (which the
    /// product runs on its own schedule) and another open: the stored text equals the constant
    /// byte for byte, the full column list equals the reference, the classifier says v6, the rows
    /// keep their ids, and no path created the temporary table.
    #[test]
    fn the_v6_definition_is_canonical_fresh_migrated_reopened_and_after_vacuum() {
        let canonical = |conn: &Connection, what: &str| {
            assert_eq!(
                move_event_sql(conn),
                MOVE_EVENT_V6_SQL,
                "{what}: the stored text"
            );
            assert_eq!(
                table_xinfo(conn, "move_event").unwrap(),
                reference_shape(XINFO_V6),
                "{what}: the full column list"
            );
            assert_eq!(
                move_event_state(conn).unwrap(),
                MoveEventState::ExactV6,
                "{what}: the verdict"
            );
            assert!(
                !table_names(conn).contains(&"move_event_v5".to_string()),
                "{what}: no temporary table"
            );
        };

        let fresh = Connection::open_in_memory().unwrap();
        migrate(&fresh).unwrap();
        canonical(&fresh, "fresh");

        let migrated = v5_shaped_db();
        seed_journal_rows(&migrated, JOURNAL);
        migrate(&migrated).unwrap();
        canonical(&migrated, "migrated");
        migrate(&migrated).unwrap();
        migrate(&migrated).unwrap();
        canonical(&migrated, "reopened twice");
        assert_eq!(journal_ids(&migrated), vec![3, 7, 12]);

        let _role = crate::state::store::role_guard();
        crate::state::store::set_observer_role(false);
        let dir = ScratchDir::new("canon-vacuum");
        let db = genuine_checkpoint(dir.path(), 5);
        seed_journal_rows(&Connection::open(&db).unwrap(), JOURNAL);
        let store = crate::state::ScanStore::open(&db).unwrap();
        store.vacuum().unwrap();
        drop(store);
        {
            let conn = Connection::open(&db).unwrap();
            canonical(&conn, "after VACUUM");
            assert_eq!(journal_ids(&conn), vec![3, 7, 12]);
            assert_eq!(user_version(&conn), 6);
        }
        let store = crate::state::ScanStore::open(&db).unwrap();
        let rows = store.move_events().unwrap();
        assert_eq!(
            journaled_sources(&rows),
            seeded_sources(),
            "after VACUUM and another open: the rows"
        );
        assert!(rows
            .iter()
            .all(|row| row.path_fidelity == PathFidelity::CarriedFromText));
        drop(store);
        canonical(
            &Connection::open(&db).unwrap(),
            "after VACUUM and another open",
        );
    }

    /// T9: the shape guard knows v6. (a) A genuine v5 checkpoint opens and upgrades. (b) A file
    /// stamped v6 whose `move_event` lost `path_fidelity` is refused by the floor, in the guard's
    /// own words, and the refusal writes nothing.
    #[test]
    fn the_shape_guard_requires_path_fidelity_at_v6() {
        let _role = crate::state::store::role_guard();
        crate::state::store::set_observer_role(false);
        let dir = ScratchDir::new("floor-v6");
        let db = genuine_checkpoint(dir.path(), 5);

        drop(crate::state::ScanStore::open(&db).expect("(a) a genuine v5 checkpoint upgrades"));
        {
            let conn = Connection::open(&db).unwrap();
            assert_eq!(user_version(&conn), 6);
            assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV6);
            conn.execute_batch("ALTER TABLE move_event RENAME COLUMN path_fidelity TO fidelity_x")
                .unwrap();
        }
        let before = std::fs::read(&db).unwrap();
        let expected =
            format!("{NOT_A_CHECKPOINT}: table `move_event` has no column `path_fidelity`");
        {
            let conn = Connection::open(&db).unwrap();
            let text = ensure_recognisable_shape(&conn)
                .expect_err("(b) the floor requires the column")
                .to_string();
            assert!(text.starts_with(&expected), "(b) {text}");
        }
        let text = crate::state::ScanStore::open(&db)
            .err()
            .expect("(b) the production open refuses the same way")
            .to_string();
        assert!(text.starts_with(&expected), "(b) {text}");
        assert_eq!(
            std::fs::read(&db).unwrap(),
            before,
            "(b) a refused open leaves the file byte-identical"
        );
    }

    /// T11: the owner's counter-example — a v5 checkpoint whose user added a `path_fidelity` column
    /// of their own, defaulting to 1. The name alone would pass a floor; the definition does not
    /// pass the classifier. Refused at the pre-check with the column named, and the table equals
    /// its own state before the attempt: the eighth column and its values included.
    #[test]
    fn a_v5_checkpoint_with_a_foreign_path_fidelity_column_is_refused_intact() {
        let conn = v5_shaped_db();
        seed_journal_rows(&conn, JOURNAL);
        conn.execute_batch(
            "ALTER TABLE move_event ADD COLUMN path_fidelity INTEGER NOT NULL DEFAULT 1",
        )
        .unwrap();
        let before = table_state(&conn);
        assert_eq!(before.shape.len(), 8);
        assert!(
            before.rows.iter().all(|row| row.ends_with("|1")),
            "the user's values are in the dump: {:?}",
            before.rows
        );

        let outcome = migrate(&conn);

        // Preservation first, whatever the outcome said. A rebuild that trusted the column names
        // would have copied the seven it knows and dropped the eighth with its values — that loss,
        // not a missing refusal, is what a weaker classifier costs, so it is what this shows.
        assert_eq!(
            table_state(&conn),
            before,
            "the table equals its own state before the attempt"
        );
        assert_eq!(user_version(&conn), 5);
        let text = match outcome {
            Err(err) => err.to_string(),
            Ok(()) => panic!("a foreign path_fidelity must not be adopted"),
        };
        assert!(text.contains("cancelled at precheck"), "{text}");
        assert!(
            text.contains(
                "column 7 `path_fidelity` (INTEGER NOT NULL DEFAULT 1) is not in the v5 definition"
            ),
            "{text}"
        );
        assert!(text.contains("stays at schema v5"), "{text}");
    }

    /// T12: nothing foreign is destroyed. Extensions of the v5 table — a user column, a STORED
    /// generated column in the original definition, a VIRTUAL one added to a filled table, an
    /// index, a trigger, a view, and two tables whose foreign keys cascade from it (one of them
    /// named so that `LIKE 'sqlite_%'` would hide it) — each cancels the upgrade at the pre-check
    /// with the object named, and afterwards the extended table equals its OWN state before the
    /// attempt: definition, full column list, rows with the user's and the computed values, the
    /// whole schema, the stamp. The cascading rows are still there.
    #[test]
    fn extensions_of_move_event_cancel_the_upgrade_and_survive_it() {
        struct Case {
            tag: &'static str,
            /// Built before the rows are seeded — for a column that has to be in the original
            /// definition (a STORED generated column cannot be added to a filled table).
            before_rows: bool,
            build: fn(&Connection),
            named: &'static str,
            cascading: Option<&'static str>,
        }
        let cases = [
            Case {
                tag: "a: user column",
                before_rows: false,
                build: |conn| {
                    conn.execute_batch(
                        "ALTER TABLE move_event ADD COLUMN note TEXT;
                         UPDATE move_event SET note = 'keep' WHERE id = 7;",
                    )
                    .unwrap()
                },
                named: "column 7 `note` (TEXT) is not in the v5 definition",
                cascading: None,
            },
            Case {
                tag: "a2: STORED generated column in the original definition",
                before_rows: true,
                build: |conn| {
                    let ddl = format!(
                        "{},\n    g INTEGER GENERATED ALWAYS AS (duplicate + 1) STORED\n)",
                        &MOVE_EVENT_V5_SQL[..MOVE_EVENT_V5_SQL.len() - 2]
                    );
                    rebuild_move_event_as(conn, &ddl)
                },
                named: "column 7 `g` (INTEGER, STORED generated) is not in the v5 definition",
                cascading: None,
            },
            Case {
                tag: "a3: VIRTUAL generated column added to a filled table",
                before_rows: false,
                build: |conn| {
                    conn.execute_batch(
                        "ALTER TABLE move_event
                             ADD COLUMN v INTEGER GENERATED ALWAYS AS (duplicate + 2) VIRTUAL",
                    )
                    .unwrap()
                },
                named: "column 7 `v` (INTEGER, VIRTUAL generated) is not in the v5 definition",
                cascading: None,
            },
            Case {
                tag: "b: index",
                before_rows: false,
                build: |conn| {
                    conn.execute_batch("CREATE INDEX user_idx ON move_event(created_at)")
                        .unwrap()
                },
                named: "index `user_idx` is defined on move_event",
                cascading: None,
            },
            Case {
                tag: "c: trigger",
                before_rows: false,
                build: |conn| {
                    conn.execute_batch(
                        "CREATE TRIGGER user_trg AFTER INSERT ON move_event BEGIN SELECT 1; END",
                    )
                    .unwrap()
                },
                named: "trigger `user_trg` refers to move_event",
                cascading: None,
            },
            Case {
                tag: "d: view",
                before_rows: false,
                build: |conn| {
                    conn.execute_batch(
                        "CREATE VIEW user_view AS SELECT source_path FROM move_event",
                    )
                    .unwrap()
                },
                named: "view `user_view` refers to move_event",
                cascading: None,
            },
            Case {
                tag: "e: cascading foreign key, parent named in upper case",
                before_rows: false,
                build: |conn| {
                    conn.execute_batch(
                        "CREATE TABLE note(id INTEGER PRIMARY KEY,
                                           ev INTEGER REFERENCES MOVE_EVENT(id) ON DELETE CASCADE);
                         INSERT INTO note VALUES (1, 7);",
                    )
                    .unwrap()
                },
                named: "table `note` has a foreign key referencing move_event",
                cascading: Some("note"),
            },
            Case {
                tag: "e2: the same under a name LIKE 'sqlite_%' would hide",
                before_rows: false,
                build: |conn| {
                    conn.execute_batch(
                        "CREATE TABLE sqlitex_notes(id INTEGER PRIMARY KEY,
                                           ev INTEGER REFERENCES MOVE_EVENT(id) ON DELETE CASCADE);
                         INSERT INTO sqlitex_notes VALUES (1, 7);",
                    )
                    .unwrap()
                },
                named: "table `sqlitex_notes` has a foreign key referencing move_event",
                cascading: Some("sqlitex_notes"),
            },
        ];

        for case in &cases {
            let conn = v5_shaped_db();
            if case.before_rows {
                (case.build)(&conn);
            }
            seed_journal_rows(&conn, JOURNAL);
            if !case.before_rows {
                (case.build)(&conn);
            }
            if let Some(table) = case.cascading {
                assert_eq!(row_count(&conn, table), 1, "[{}] the fixture", case.tag);
            }
            let before = table_state(&conn);
            assert_eq!(before.version, 5, "[{}] the fixture", case.tag);

            let outcome = migrate(&conn);

            // Preservation first, whatever the outcome said: the cascading row (DROP TABLE under
            // enforced keys runs ON DELETE CASCADE), then the whole extended table. A pre-check
            // that lets one of these through costs exactly this, and this is what shows.
            if let Some(table) = case.cascading {
                assert_eq!(
                    row_count(&conn, table),
                    1,
                    "[{}] the cascading row survives",
                    case.tag
                );
            }
            assert_eq!(
                table_state(&conn),
                before,
                "[{}] the extended table equals its own state before the attempt",
                case.tag
            );
            let text = match outcome {
                Err(err) => err.to_string(),
                Ok(()) => panic!("[{}] the extension must cancel the upgrade", case.tag),
            };
            assert!(
                text.contains("cancelled at precheck"),
                "[{}] {text}",
                case.tag
            );
            assert!(
                text.contains(case.named),
                "[{}] the object must be named: {text}",
                case.tag
            );
            assert!(text.contains("stays at schema v5"), "[{}] {text}", case.tag);
        }
    }

    /// T13: a v6 stamp over a table that is not the v6 table is refused in `migrate` — the shape
    /// guard's floor is satisfied by the column names, so this is where a hand-stamped file stops:
    /// (a) the v5 table with a foreign `path_fidelity`; (b) the eight columns with the CHECKs only
    /// in comments — the fixture proves it accepts a TEXT row claiming exactness, which is what
    /// accepting it as v6 would let into the product; (c) the v6 text with one extra space.
    #[test]
    fn a_v6_stamp_over_a_non_canonical_table_is_refused() {
        let conn = v5_shaped_db();
        seed_journal_rows(&conn, JOURNAL);
        conn.execute_batch(
            "ALTER TABLE move_event ADD COLUMN path_fidelity INTEGER NOT NULL DEFAULT 1",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 6i64).unwrap();
        let before = table_state(&conn);
        let text = migrate(&conn).expect_err("(a)").to_string();
        assert!(
            text.contains("cancelled at precheck") && text.contains("`path_fidelity`"),
            "(a) {text}"
        );
        assert_eq!(table_state(&conn), before, "(a)");
        assert_eq!(user_version(&conn), 6, "(a) the stamp is left as it was");

        let conn = Connection::open_in_memory().unwrap();
        enforce_foreign_keys(&conn).unwrap();
        conn.execute_batch(V6_CHECKS_IN_COMMENTS).unwrap();
        conn.execute(
            "INSERT INTO move_event (id, created_at, source_path, target_path, duplicate)
             VALUES (7, 'then', X'2F61', X'2F62', 0)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 6i64).unwrap();
        let before = table_state(&conn);
        let text = migrate(&conn).expect_err("(b)").to_string();
        assert!(
            text.contains("cancelled at precheck")
                && text.contains("differs from the v6 definition"),
            "(b) {text}"
        );
        assert_eq!(table_state(&conn), before, "(b)");
        conn.execute(
            "INSERT INTO move_event (id, created_at, source_path, target_path, duplicate, path_fidelity)
             VALUES (99, 'then', '/text', '/text', 0, 1)",
            [],
        )
        .expect("(b) the lookalike has no CHECK: a TEXT row claiming exactness goes in");

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&v6_with_an_extra_space()).unwrap();
        conn.pragma_update(None, "user_version", 6i64).unwrap();
        let before = table_state(&conn);
        let text = migrate(&conn).expect_err("(c)").to_string();
        assert!(
            text.contains("cancelled at precheck")
                && text.contains("differs from the v6 definition"),
            "(c) {text}"
        );
        assert_eq!(table_state(&conn), before, "(c)");
    }

    /// T14: the refusal's promise is true on a file. A v5 checkpoint in rollback-journal mode with
    /// a cascading foreign key onto the journal: the open is refused with the step, the version the
    /// file stays at and the WAL caveat — never «nothing was changed» — the stamp, the schema and
    /// every row are as they were, the journal mode really is WAL now, and once the foreign key
    /// holder is gone the next open upgrades with every row.
    #[test]
    fn a_cancelled_upgrade_tells_the_truth_about_the_file() {
        let _role = crate::state::store::role_guard();
        crate::state::store::set_observer_role(false);
        let dir = ScratchDir::new("cancelled-truth");
        let db = genuine_checkpoint(dir.path(), 5);
        let (schema_before, rows_before) = {
            let conn = Connection::open(&db).unwrap();
            seed_journal_rows(&conn, JOURNAL);
            conn.execute_batch(
                "CREATE TABLE note(id INTEGER PRIMARY KEY,
                                   ev INTEGER REFERENCES MOVE_EVENT(id) ON DELETE CASCADE);
                 INSERT INTO note VALUES (1, 7);",
            )
            .unwrap();
            let mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            assert_eq!(mode, "delete", "the fixture rests in rollback-journal mode");
            (schema_fingerprint(&conn), journal_dump(&conn))
        };

        let text = crate::state::ScanStore::open(&db)
            .err()
            .expect("the cascading key cancels the upgrade")
            .to_string();
        for promise in [
            "cancelled at precheck",
            "table `note` has a foreign key referencing move_event",
            "stays at schema v5",
            "may already have switched the file to WAL mode",
        ] {
            assert!(text.contains(promise), "missing «{promise}»: {text}");
        }
        assert!(
            !text.contains("Nothing was changed"),
            "the journal mode did change: {text}"
        );

        {
            let conn = Connection::open(&db).unwrap();
            assert_eq!(user_version(&conn), 5);
            assert_eq!(schema_fingerprint(&conn), schema_before);
            assert_eq!(journal_dump(&conn), rows_before);
            assert_eq!(row_count(&conn, "note"), 1);
            let mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            assert_eq!(mode, "wal", "the flip happened, and the refusal said so");
            conn.execute_batch("DROP TABLE note").unwrap();
        }
        let store = crate::state::ScanStore::open(&db)
            .expect("without the foreign key the upgrade completes");
        assert_eq!(
            journaled_sources(&store.move_events().unwrap()),
            seeded_sources()
        );
        drop(store);
        assert_eq!(user_version(&Connection::open(&db).unwrap()), 6);
    }

    /// T15: `migrate` is public and stamps `SCHEMA_VERSION`; over a file a newer build wrote that
    /// would be a downgrade in disguise. So the refusal the opener makes is made here as well,
    /// inside the transaction and before anything is judged: (a) the canonical v6 table under a
    /// stamp one ahead — the shape a newer build may well leave — and (b) the v5 table under the
    /// same stamp are both left exactly as they are, stamp included, and the words are the
    /// version rule's, not the v6 step's.
    #[test]
    fn a_future_stamp_is_refused_by_migrate_itself() {
        let future = SCHEMA_VERSION + 1;

        let conn = Connection::open_in_memory().unwrap();
        enforce_foreign_keys(&conn).unwrap();
        migrate(&conn).unwrap();
        conn.execute(
            "INSERT INTO move_event
                 (id, created_at, source_path, target_path, duplicate, path_fidelity)
             VALUES (5, 'then', X'2F61', X'2F62', 0, 1)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", future).unwrap();
        let before = table_state(&conn);
        assert_eq!(before.version, future);

        let text = migrate(&conn)
            .expect_err("(a) a newer stamp must be refused, not restamped")
            .to_string();
        assert!(text.contains("newer version"), "(a) {text}");
        assert!(text.contains(&format!("schema v{future}")), "(a) {text}");
        assert!(
            text.contains(&format!("supports v{SCHEMA_VERSION}")),
            "(a) {text}"
        );
        assert_eq!(
            table_state(&conn),
            before,
            "(a) nothing judged, nothing written, the stamp stays"
        );
        assert_eq!(user_version(&conn), future);

        let conn = v5_shaped_db();
        seed_journal_rows(&conn, JOURNAL);
        conn.pragma_update(None, "user_version", future).unwrap();
        let before = table_state(&conn);

        let text = migrate(&conn).expect_err("(b)").to_string();
        assert!(text.contains("newer version"), "(b) {text}");
        assert!(
            !text.contains("cancelled at"),
            "(b) the stamp is refused before the v6 step judges anything: {text}"
        );
        assert_eq!(table_state(&conn), before, "(b)");
        assert_eq!(user_version(&conn), future);
    }

    /// A fresh writable DB is exactly schema v6: every new column, table and index comes from
    /// `CREATE TABLE`/`CREATE INDEX`, not only from the `ALTER` path a migrated DB takes.
    #[test]
    fn fresh_db_is_schema_v6_with_every_new_column_table_and_index() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        assert_eq!(SCHEMA_VERSION, 6, "v6 is the schema this build writes");
        let stamped: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stamped, 6, "a fresh DB is stamped v6");

        // v6: the move journal carries its fidelity column, and the table is the canon itself.
        assert!(columns_of(&conn, "move_event").contains(&"path_fidelity".to_string()));
        assert_eq!(move_event_state(&conn).unwrap(), MoveEventState::ExactV6);

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
        migrate(&conn).unwrap(); // reopening a current DB is idempotent

        assert_eq!(
            user_version(&conn),
            SCHEMA_VERSION,
            "the stamp moves to the current schema"
        );
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

    /// The incident the integration gate caught, reduced to two connections and a barrier.
    ///
    /// The guard reads the stamp; while it holds that answer a SECOND connection migrates the very
    /// same file and commits. Before this was one snapshot, the guard then looked the names up in a
    /// fresh one and refused a checkpoint that had never been anything but ours — naming
    /// `file_scan_identity`, an index the migration had created microseconds earlier, against the
    /// v0 the stamp had said. Deterministic by construction: the barrier is a seam, not a sleep.
    #[test]
    fn the_shape_guard_judges_one_snapshot_when_a_migration_commits_underneath_it() {
        let _role = crate::state::store::role_guard();
        crate::state::store::set_observer_role(false);
        let dir = ScratchDir::new("schema-barrier");
        let db = genuine_checkpoint(dir.path(), 0);
        // WAL is the mode every opener flips the checkpoint to, and the mode the incident happened
        // in: under WAL a writer does not wait for a reader, which is exactly how a migration got
        // in between two of the guard's reads.
        {
            let conn = Connection::open(&db).unwrap();
            let _: String = conn
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
                .unwrap();
        }

        let checking = Connection::open(&db).unwrap();
        checking.execute_batch("PRAGMA busy_timeout=5000;").unwrap();
        let migrating = db.clone();
        let race = ShapeGuardRace::armed(move || {
            let conn = Connection::open(&migrating).unwrap();
            conn.execute_batch("PRAGMA busy_timeout=5000;").unwrap();
            migrate(&conn).expect("the second opener migrates the same checkpoint");
        });

        let verdict = ensure_recognisable_shape(&checking);

        assert!(
            race.fired(),
            "the barrier was never reached — the test proved nothing"
        );
        verdict.expect(
            "a checkpoint migrated underneath the guard is still ours: the guard must judge the \
             snapshot it started on, not a sentence assembled out of two",
        );

        // The other half of «old or new, never a mixture»: the migration really did land, and the
        // guard accepts that state too when it is the one it starts on.
        let after = Connection::open(&db).unwrap();
        assert_eq!(
            user_version(&after),
            SCHEMA_VERSION,
            "the second opener's migration committed"
        );
        ensure_recognisable_shape(&after)
            .expect("and the migrated checkpoint is recognisable in its own right");
    }

    /// The rule the barrier must not have loosened: a v0 checkpoint that really does carry a name
    /// introduced at v3 is still refused, and still by that name.
    #[test]
    fn a_v3_name_in_a_resting_v0_checkpoint_is_still_refused() {
        let _role = crate::state::store::role_guard();
        crate::state::store::set_observer_role(false);
        let dir = ScratchDir::new("schema-squat");
        let db = genuine_checkpoint(dir.path(), 0);
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch("CREATE INDEX file_scan_identity ON file(scan_id, device, inode);")
                .unwrap();
        }

        let conn = Connection::open(&db).unwrap();
        let text = ensure_recognisable_shape(&conn)
            .expect_err("a v0 checkpoint carrying a v3 name is not ours to adopt")
            .to_string();

        assert!(text.starts_with(NOT_A_CHECKPOINT), "{text}");
        assert!(text.contains("file_scan_identity"), "{text}");
        assert!(text.contains("v3"), "{text}");
        assert!(text.contains("v0"), "{text}");
    }
}
