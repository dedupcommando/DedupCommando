// SPDX-License-Identifier: Apache-2.0
//! Test-only fixtures for the Phase 2 physical-object work: a hardlink forest on a real
//! filesystem, plus deterministic counting of the content reads the scan performs.
//!
//! Why a real forest instead of a hand-written manifest: the defect this phase fixes lives in the
//! relationship between pathnames and inodes as the walk actually sees them — `st_nlink`, a second
//! link outside the scan root, aliases that share every byte of their temporal identity. A synthetic
//! `ManifestRow` can assert none of that.
//!
//! The layout is the fixed fixture the Phase 2 plan measures against: **6 candidate pathnames over
//! 3 physical objects**.
//!
//! ```text
//! <base>/root/alias_0.bin   ┐
//! <base>/root/alias_1.bin   ├─ one inode, st_nlink = 4, every link inside the root
//! <base>/root/alias_2.bin   │
//! <base>/root/alias_3.bin   ┘
//! <base>/root/twin_a.bin    ── own inode, st_nlink = 1                     (plain control)
//! <base>/root/twin_b.bin    ── own inode, st_nlink = 2, one link OUTSIDE   (unobserved link)
//! <base>/out/external.bin   ── the second link of twin_b's inode, never scanned
//! <base>/root/unique.bin    ── different size and content: not a candidate at all
//! ```
//!
//! `alias_*`, `twin_a`, `twin_b` and `external.bin` are byte-identical, so the six pathnames inside
//! the root form one content group made of three allocations.

/// Directory pairs whose exact-twin claims depend on omitted files (`P-2`/`S-4`/`P-11`).
pub mod dir_completeness;

use std::cell::RefCell;
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::model::scan::ScanConfig;

/// One file of the user manual, read from the repository this test binary was built from.
///
/// The manual is part of the source tree, so a test may assert against it exactly as it asserts
/// against a constant. What the code does and what the manual says it does are two statements about
/// one thing; only an assertion keeps them the same statement. Nothing else in the build reads
/// `docs/` — not `fmt`, not `clippy`, not the compiler — so drift there is silent by default.
///
/// `CARGO_MANIFEST_DIR` is fixed at compile time, so the path does not depend on the directory the
/// test happens to run in.
pub fn manual(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("manual")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read the manual at {}: {err}", path.display()))
}

/// Size of the duplicated payload. Big enough that a read is a real read, small enough to be free.
const DUP_SIZE: usize = 4096;
/// How many pathnames point at the shared inode.
const ALIASES: usize = 4;

/// A hardlink forest on a real filesystem. Removed on drop.
pub struct HardlinkForest {
    /// Everything lives under here; `Drop` removes it.
    base: PathBuf,
    /// The directory to scan.
    pub root: PathBuf,
    /// A sibling of `root`, never inside it — holds the external link.
    pub outside: PathBuf,
    /// `ALIASES` pathnames, all links to ONE inode, all inside `root`.
    pub aliases: Vec<PathBuf>,
    /// Byte-identical to the aliases, own inode, `st_nlink == 1`.
    pub twin_a: PathBuf,
    /// Byte-identical, own inode, `st_nlink == 2` — its other link is `external`.
    pub twin_b: PathBuf,
    /// The second link of `twin_b`'s inode, outside every scan root.
    pub external: PathBuf,
    /// Different size and content: proves candidate selection is not "every file".
    pub unique: PathBuf,
}

impl HardlinkForest {
    /// Builds the forest and self-checks it. Panics with a named reason if the filesystem did not
    /// give us what the fixture promises — a silently degraded fixture is worse than no fixture.
    pub fn build(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before the epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "dedcom_forest_{tag}_{}_{nanos}",
            std::process::id()
        ));
        let root = base.join("root");
        let outside = base.join("out");
        std::fs::create_dir_all(&root).expect("create the scan root");
        std::fs::create_dir_all(&outside).expect("create the outside directory");

        let payload = vec![0x5Au8; DUP_SIZE];

        let mut aliases = Vec::with_capacity(ALIASES);
        let first = root.join("alias_0.bin");
        std::fs::write(&first, &payload).expect("write the shared inode");
        aliases.push(first.clone());
        for index in 1..ALIASES {
            let alias = root.join(format!("alias_{index}.bin"));
            std::fs::hard_link(&first, &alias).unwrap_or_else(|err| {
                panic!(
                    "hard_link {} -> {}: {err}",
                    first.display(),
                    alias.display()
                )
            });
            aliases.push(alias);
        }

        let twin_a = root.join("twin_a.bin");
        std::fs::write(&twin_a, &payload).expect("write twin_a");

        let twin_b = root.join("twin_b.bin");
        std::fs::write(&twin_b, &payload).expect("write twin_b");
        let external = outside.join("external.bin");
        std::fs::hard_link(&twin_b, &external).expect("link twin_b outside the root");

        let unique = root.join("unique.bin");
        std::fs::write(&unique, vec![0x11u8; DUP_SIZE / 2]).expect("write the unique file");

        let forest = HardlinkForest {
            base,
            root,
            outside,
            aliases,
            twin_a,
            twin_b,
            external,
            unique,
        };
        forest.verify();
        forest
    }

    /// The directory `Drop` removes — for a teardown test.
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// A scan config for `root` that does not filter the fixture away (the files are tiny and
    /// the default exclusions would not match, but both are made explicit on purpose).
    pub fn scan_config(&self) -> ScanConfig {
        let mut config = ScanConfig::new(vec![self.root.clone()]);
        config.min_size = 0;
        config.exclude_globs = Vec::new();
        config
    }

    /// The six pathnames inside the root that share one content: the candidate set today, and the
    /// membership the group must still show after the fix.
    pub fn duplicate_pathnames(&self) -> Vec<PathBuf> {
        let mut paths = self.aliases.clone();
        paths.push(self.twin_a.clone());
        paths.push(self.twin_b.clone());
        paths
    }

    /// How many distinct allocations those six pathnames occupy: three.
    pub fn duplicate_objects(&self) -> usize {
        self.duplicate_pathnames()
            .iter()
            .map(|path| self.object_of(path))
            .collect::<HashSet<_>>()
            .len()
    }

    /// `(device, inode)` of a path — the physical identity, by `lstat`.
    pub fn object_of(&self, path: &Path) -> (u64, u64) {
        let meta = std::fs::symlink_metadata(path)
            .unwrap_or_else(|err| panic!("lstat {}: {err}", path.display()));
        (meta.dev(), meta.ino())
    }

    /// `st_nlink` of a path — the total link count of its inode, including links we never saw.
    pub fn nlink_of(&self, path: &Path) -> u64 {
        std::fs::symlink_metadata(path)
            .unwrap_or_else(|err| panic!("lstat {}: {err}", path.display()))
            .nlink()
    }

    /// Everything the fixture claims about itself. Run at build time and asserted again by its own
    /// test, so a filesystem that quietly refuses hardlinks fails the fixture, not the fix.
    pub fn verify(&self) {
        assert_eq!(self.aliases.len(), ALIASES, "alias count");
        let shared = self.object_of(&self.aliases[0]);
        for alias in &self.aliases {
            assert_eq!(
                self.object_of(alias),
                shared,
                "{} is not the shared inode",
                alias.display()
            );
            assert_eq!(
                self.nlink_of(alias),
                ALIASES as u64,
                "{} must report st_nlink = {ALIASES}",
                alias.display()
            );
        }

        assert_ne!(
            self.object_of(&self.twin_a),
            shared,
            "twin_a must be its own inode"
        );
        assert_eq!(
            self.nlink_of(&self.twin_a),
            1,
            "twin_a must have a single link"
        );

        let linked = self.object_of(&self.twin_b);
        assert_ne!(linked, shared, "twin_b must be its own inode");
        assert_ne!(
            linked,
            self.object_of(&self.twin_a),
            "twin_b must differ from twin_a"
        );
        assert_eq!(self.nlink_of(&self.twin_b), 2, "twin_b must have two links");
        assert_eq!(
            self.object_of(&self.external),
            linked,
            "the external path must be the same inode as twin_b"
        );
        assert!(
            !self.external.starts_with(&self.root),
            "the external link must lie outside the scan root"
        );

        let content = std::fs::read(&self.aliases[0]).expect("read the shared inode");
        assert_eq!(content.len(), DUP_SIZE, "payload size");
        for path in self.duplicate_pathnames().iter().chain([&self.external]) {
            assert_eq!(
                std::fs::read(path).expect("read a duplicate"),
                content,
                "{} must be byte-identical",
                path.display()
            );
        }
        let unique = std::fs::read(&self.unique).expect("read the unique file");
        assert_ne!(
            unique.len(),
            content.len(),
            "the unique file must differ in size"
        );

        assert_eq!(
            self.duplicate_pathnames().len(),
            6,
            "six duplicate pathnames"
        );
        assert_eq!(self.duplicate_objects(), 3, "over three allocations");
    }
}

impl Drop for HardlinkForest {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.base).ok();
    }
}

/// Paths whose content the scan read, while a [`ReadLog`] is armed.
static CONTENT_READS: Mutex<Option<Vec<PathBuf>>> = Mutex::new(None);
/// Serializes the tests that arm the recorder.
static READ_LOG_LOCK: Mutex<()> = Mutex::new(());

/// Records every content read of the hashing phase for as long as it is alive.
///
/// Process-wide on purpose: the reads happen on rayon worker threads, so a thread-local would miss
/// them (the same reason `bench`'s capture cannot be shared). The flip side is that a parallel test
/// hashing its own files also lands in the log — assert with [`ReadLog::count_under`] over your
/// fixture's directory, never on the bare total.
pub struct ReadLog {
    _guard: MutexGuard<'static, ()>,
}

impl ReadLog {
    /// Arms the recorder. Blocks while another `ReadLog` is alive.
    pub fn start() -> Self {
        let guard = READ_LOG_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot() = Some(Vec::new());
        ReadLog { _guard: guard }
    }

    /// Every recorded read, in order.
    pub fn paths(&self) -> Vec<PathBuf> {
        slot().clone().unwrap_or_default()
    }

    /// Reads of paths under `prefix`.
    pub fn count_under(&self, prefix: &Path) -> usize {
        self.paths()
            .iter()
            .filter(|path| path.starts_with(prefix))
            .count()
    }

    /// Reads of exactly this path.
    pub fn count_of(&self, path: &Path) -> usize {
        self.paths().iter().filter(|read| *read == path).count()
    }
}

impl Drop for ReadLog {
    fn drop(&mut self) {
        *slot() = None;
    }
}

fn slot() -> MutexGuard<'static, Option<Vec<PathBuf>>> {
    CONTENT_READS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Called by the hashing path once per opened file, before its bytes are read. A no-op unless a
/// [`ReadLog`] is armed, and compiled out entirely in a release build.
pub fn note_content_read(path: &Path) {
    if let Some(reads) = slot().as_mut() {
        reads.push(path.to_path_buf());
    }
}

/// Which error branch an injected fault stands in for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkFault {
    /// A directory iterator yielded an error instead of an entry — the walk's own, or the
    /// `read_dir` the commander's merge reads a source directory with. Both discard the entry
    /// without ever learning its pathname, which is what makes the fault worth injecting.
    Iterator,
    /// The entry arrived, but its metadata could not be read.
    Metadata,
    /// The entry is still there, but the stat itself is refused: `EACCES` from a directory that
    /// lists but does not search, or `EIO`. Its own kind because the commander's duplicate check
    /// treats the two failures differently. `Metadata` stands in for `NotFound` there, the one
    /// stat failure it skips; a refusal must fail the whole listing, and a fixture running as
    /// root cannot produce one on cue by changing permissions. Only that check consumes it. The
    /// walk does not tell stat failures apart, so `Metadata` covers it there.
    MetadataRefused,
    /// The file is there and its metadata reads, but its CONTENT does not. The move's duplicate
    /// check hashes both the file being moved and every same-size candidate, and either read can
    /// fail on its own (`EACCES`, `EIO`) long after the directory listed cleanly. A separate kind
    /// because `Metadata` is consumed while the destination is listed, before any hashing starts,
    /// so one kind could not reach this branch at all.
    Content,
}

thread_local! {
    /// Faults armed for this thread that have not fired yet.
    static ARMED_FAULTS: RefCell<Vec<(PathBuf, WalkFault)>> = const { RefCell::new(Vec::new()) };
    /// Faults that fired, in the order they fired.
    static FIRED_FAULTS: RefCell<Vec<(PathBuf, WalkFault)>> = const { RefCell::new(Vec::new()) };
}

/// Arms walk faults for the current thread and disarms them on drop.
///
/// Thread-local, and that is the whole point: `walk` and the commander's `merge_dir` both iterate
/// on the caller's thread, so a fault cannot leak into a test running in parallel and nothing has
/// to be serialized. (`ReadLog` above has the opposite constraint — hashing happens on rayon
/// workers, so it must be process-wide.) Each fault fires at most once, and both what fired and
/// what did not are observable, so a test can prove a fault was consumed exactly once rather than
/// merely that a file went missing.
///
/// If `ignore` ever moved its iteration to another thread, the fault would simply never fire and the
/// test would fail — never silently pass.
pub struct WalkFaults;

impl WalkFaults {
    /// Arms `faults` for this thread, replacing anything armed before.
    pub fn arm(faults: &[(PathBuf, WalkFault)]) -> Self {
        ARMED_FAULTS.with(|armed| *armed.borrow_mut() = faults.to_vec());
        FIRED_FAULTS.with(|fired| fired.borrow_mut().clear());
        WalkFaults
    }

    /// Faults that have not fired.
    pub fn pending(&self) -> Vec<(PathBuf, WalkFault)> {
        ARMED_FAULTS.with(|armed| armed.borrow().clone())
    }

    /// Faults that fired, in order.
    pub fn fired(&self) -> Vec<(PathBuf, WalkFault)> {
        FIRED_FAULTS.with(|fired| fired.borrow().clone())
    }
}

impl Drop for WalkFaults {
    fn drop(&mut self) {
        ARMED_FAULTS.with(|armed| armed.borrow_mut().clear());
        FIRED_FAULTS.with(|fired| fired.borrow_mut().clear());
    }
}

/// Consumes a fault of exactly this kind for exactly this path, if one is armed.
fn take_fault(path: &Path, kind: WalkFault) -> bool {
    let taken = ARMED_FAULTS.with(|armed| {
        let mut armed = armed.borrow_mut();
        let found = armed
            .iter()
            .position(|(faulty, armed_kind)| *armed_kind == kind && faulty == path);
        found.map(|index| armed.remove(index))
    });
    match taken {
        Some(fault) => {
            FIRED_FAULTS.with(|fired| fired.borrow_mut().push(fault));
            true
        }
        None => false,
    }
}

/// Called where a directory-iteration error would have skipped the entry: the walk's `absorb`, and
/// the commander's `merge_dir`.
pub(crate) fn take_walk_fault(path: &Path) -> bool {
    take_fault(path, WalkFault::Iterator)
}

/// Called where a file's content could not be read: the move's duplicate check.
pub(crate) fn take_content_fault(path: &Path) -> bool {
    take_fault(path, WalkFault::Content)
}

/// Called where a metadata error would have skipped the entry: the walk, and the commander's
/// `same_size_files`, where it stands for `NotFound`.
pub(crate) fn take_metadata_fault(path: &Path) -> bool {
    take_fault(path, WalkFault::Metadata)
}

/// Called where a refused stat, anything but `NotFound`, would have failed the listing: the
/// commander's `same_size_files`.
pub(crate) fn take_metadata_refusal(path: &Path) -> bool {
    take_fault(path, WalkFault::MetadataRefused)
}

/// A real directory of byte-identical files — some of them hardlinked, some with a link outside the
/// scanned root — together with a store whose manifest describes them exactly as a walk would.
///
/// The plan authority `stat`s every pathname it plans and compares the full temporal identity
/// against the manifest, so its tests cannot be written against synthetic rows: the rows have to BE
/// the files. Everything is created before `seed` records the manifest, because a link made
/// afterwards changes the inode's `nlink` and `ctime` and the plan would rightly refuse the fixture.
pub struct PlanScenario {
    base: PathBuf,
    /// The scanned directory.
    pub root: PathBuf,
    /// A sibling of `root`, never scanned — for links the manifest can never see.
    pub outside: PathBuf,
    pub db_path: PathBuf,
}

impl PlanScenario {
    pub fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before the epoch")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("dedcom_plan_{tag}_{}_{nanos}", std::process::id()));
        let root = base.join("root");
        let outside = base.join("out");
        std::fs::create_dir_all(&root).expect("scenario root");
        std::fs::create_dir_all(&outside).expect("scenario outside");
        let db_path = base.join("dedcom.db");
        Self {
            base,
            root,
            outside,
            db_path,
        }
    }

    /// A file carrying the shared payload: every one of them is byte-identical, so they form one
    /// content group.
    pub fn file(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, vec![7u8; DUP_SIZE]).expect("scenario payload");
        path
    }

    /// Another pathname for the same allocation, inside the root.
    pub fn link(&self, source: &Path, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::hard_link(source, &path).expect("scenario alias");
        path
    }

    /// A link to the same allocation OUTSIDE the root: the manifest never sees it, `st_nlink` does.
    pub fn outside_link(&self, source: &Path, name: &str) -> PathBuf {
        let path = self.outside.join(name);
        std::fs::hard_link(source, &path).expect("scenario external link");
        path
    }

    /// A writable store on this scenario's database.
    pub fn store(&self) -> crate::state::ScanStore {
        crate::state::ScanStore::open_writable(&self.db_path).expect("scenario store")
    }

    /// Records `paths` as a completed, published scan: manifest rows from the real `stat`,
    /// fd-verified digests (so `identity_version = 1`), and the group figures the browser reads.
    pub fn seed(&self, store: &mut crate::state::ScanStore, paths: &[PathBuf]) -> i64 {
        use crate::model::scan::ScanStatus;
        use crate::state::store::ManifestRow;
        use std::sync::atomic::AtomicU64;

        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![self.root.clone()]))
            .expect("scenario scan");
        let rows: Vec<ManifestRow> = paths
            .iter()
            .map(|path| {
                let meta = std::fs::symlink_metadata(path).expect("scenario stat");
                ManifestRow {
                    path: path.clone(),
                    size: meta.size(),
                    mtime: meta.mtime(),
                    mtime_nsec: meta.mtime_nsec(),
                    ctime_sec: meta.ctime(),
                    ctime_nsec: meta.ctime_nsec(),
                    device: meta.dev(),
                    inode: meta.ino(),
                    nlink: meta.nlink(),
                }
            })
            .collect();
        store
            .record_files(scan_id, &rows)
            .expect("scenario manifest");
        let verified: Vec<(ManifestRow, [u8; 32])> = rows
            .into_iter()
            .map(|row| {
                let digest = crate::pipeline::hash::hash_file(&row.path, &AtomicU64::new(0))
                    .expect("scenario digest");
                (row, digest)
            })
            .collect();
        store
            .record_hashes_verified(scan_id, &verified)
            .expect("scenario digests");
        store
            .set_status(scan_id, ScanStatus::Complete)
            .expect("scenario status");
        // The fixture publishes exactly as an ordinary hash-only completion does, so every
        // reader in a test sees the same authority production would.
        store
            .publish_results(scan_id, crate::state::PublishMode::Derived)
            .expect("scenario publication");
        scan_id
    }

    /// Persists one mark, exactly as both windows do.
    pub fn mark(
        &self,
        store: &mut crate::state::ScanStore,
        scan_id: i64,
        path: &Path,
        is_keeper: bool,
        action: Option<crate::model::action::ActionKind>,
    ) {
        let entry = crate::model::duplicate::FileEntry {
            path: path.to_path_buf(),
            is_keeper,
            action,
            ..Default::default()
        };
        store
            .save_marks(scan_id, std::iter::once(&entry))
            .expect("scenario mark");
    }
}

impl Drop for PlanScenario {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.base).ok();
    }
}

/// A scratch directory that removes itself when the test returns: a green test may not leave a
/// persistent fixture behind merely because the cargo process eventually exits. The name carries
/// the pid and a timestamp, so tests running in parallel never share one.
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    pub fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before the epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "dedcom_scratch_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// A checkpoint the product itself wrote, carrying one completed scan, rewound to the shape a
/// build of `version` would have left behind. Rewinding the real schema is how the migration tests
/// build their legacy databases as well — hand-transcribed DDL in this role is precisely what the
/// gate's own masters got wrong.
///
/// The rollback journal is restored at the end: WAL is something an opener flips, not something a
/// resting checkpoint carries, and a fixture in WAL mode would blur the no-sidecar assertions its
/// callers make.
pub fn genuine_checkpoint(dir: &Path, version: i64) -> PathBuf {
    let db = dir.join("dedcom.db");
    {
        let mut store =
            crate::state::ScanStore::open(&db).expect("the product creates its own checkpoint");
        let scan = store
            .begin_scan(&ScanConfig::new(vec![dir.to_path_buf()]))
            .unwrap();
        store
            .set_status(scan, crate::model::scan::ScanStatus::Complete)
            .unwrap();
    }
    let conn = rusqlite::Connection::open(&db).unwrap();
    if version < 6 {
        strip_v6(&conn);
    }
    if version < 5 {
        conn.execute_batch("DROP TABLE file_group_member; DROP TABLE scan_membership;")
            .unwrap();
    }
    if version < 4 {
        conn.execute_batch("DROP TABLE dir_omission; DROP TABLE scan_root;")
            .unwrap();
    }
    if version < 3 {
        // The two v3 indexes go as well. They depend on no column dropped here, so they would
        // survive the rewind — and a checkpoint declaring v0 while carrying a name that only
        // arrived at v3 is exactly what the guard refuses. Dropping the v4/v5 TABLES above takes
        // their indexes with them; these two have to be named.
        conn.execute_batch(
            "DROP INDEX file_scan_identity;
             DROP INDEX file_hash_identity;
             ALTER TABLE file       DROP COLUMN nlink;
             ALTER TABLE file_group DROP COLUMN object_count;
             ALTER TABLE file_group DROP COLUMN reclaim_state;
             ALTER TABLE scan_stats DROP COLUMN reclaim_state;",
        )
        .unwrap();
    }
    if version < 2 {
        conn.execute_batch("ALTER TABLE scan_stats DROP COLUMN results_materialized;")
            .unwrap();
    }
    conn.pragma_update(None, "user_version", version).unwrap();
    let _: String = conn
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .unwrap();
    drop(conn);
    db
}

/// Rewinds `move_event` from v6 to a v5-era table: the v6 table steps aside, `ddl` — the v5 canon,
/// or a variant of it for a fixture that needs a column in the ORIGINAL definition — is created
/// under the name, the rows come back with their ids and their pathnames cast to TEXT, and the v6
/// table goes. A rebuild rather than `DROP COLUMN`: SQLite refuses to drop a column named in a
/// table CHECK, and `path_fidelity` is named in two.
pub fn rebuild_move_event_as(conn: &rusqlite::Connection, ddl: &str) {
    conn.execute_batch(&format!(
        "ALTER TABLE move_event RENAME TO move_event_v6_tmp;
         {ddl};
         INSERT INTO move_event (id, created_at, scan_id, source_path, target_path, hash, duplicate)
              SELECT id, created_at, scan_id, CAST(source_path AS TEXT), CAST(target_path AS TEXT),
                     hash, duplicate
                FROM move_event_v6_tmp ORDER BY id;
         DROP TABLE move_event_v6_tmp;"
    ))
    .expect("rewinding move_event to a v5-era table");
}

/// Strips what v6 adds: `move_event` becomes the v5 table, byte for byte the canon. The self-check
/// is what keeps every migration test honest — a fixture that quietly stopped being the v5 table
/// would make those tests pass for the wrong reason. It proves only that SQLite stored the text it
/// was given; that the canon is what the old builds wrote is evidence taken from a checkpoint one
/// of them created, outside this crate.
pub fn strip_v6(conn: &rusqlite::Connection) {
    rebuild_move_event_as(conn, crate::state::schema::MOVE_EVENT_V5_SQL);
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'move_event'",
            [],
            |row| row.get(0),
        )
        .expect("the rewound move_event exists");
    assert_eq!(
        sql,
        crate::state::schema::MOVE_EVENT_V5_SQL,
        "the rewound move_event must be the v5 canon byte for byte"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::hash::hash_file_verified;
    use std::sync::atomic::AtomicU64;

    /// The fixture's own promises, asserted after `build` already checked them — this is the test
    /// that fails when a filesystem (or a future edit) stops giving us a real hardlink forest.
    #[test]
    fn forest_holds_its_own_invariants() {
        let forest = HardlinkForest::build("selfcheck");
        forest.verify();

        // Pathnames inside the root: 4 aliases + 2 twins + 1 unique.
        let inside: Vec<PathBuf> = std::fs::read_dir(&forest.root)
            .expect("read the scan root")
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        assert_eq!(
            inside.len(),
            7,
            "seven pathnames inside the root: {inside:?}"
        );

        // Four allocations inside the root: the shared inode, both twins, the unique file.
        let objects: HashSet<(u64, u64)> = inside.iter().map(|p| forest.object_of(p)).collect();
        assert_eq!(objects.len(), 4, "four allocations inside the root");
    }

    /// The unobserved-link case: the scan root sees one of `twin_b`'s two links, so no byte of that
    /// allocation can be freed by acting on the visible pathname alone.
    #[test]
    fn external_link_is_invisible_to_the_scan_root() {
        let forest = HardlinkForest::build("external");
        assert_eq!(
            forest.nlink_of(&forest.twin_b),
            2,
            "the inode has two links"
        );
        let visible = std::fs::read_dir(&forest.root)
            .expect("read the scan root")
            .filter(|entry| {
                let path = entry.as_ref().expect("directory entry").path();
                forest.object_of(&path) == forest.object_of(&forest.twin_b)
            })
            .count();
        assert_eq!(
            visible, 1,
            "exactly one of the two links is inside the root"
        );
        assert!(
            !forest.external.starts_with(&forest.root),
            "the second link must not be under the scan root"
        );
        assert!(
            forest.external.starts_with(&forest.outside),
            "it lives in the sibling directory instead"
        );
    }

    #[test]
    fn teardown_removes_the_whole_forest() {
        let base;
        let outside;
        let external;
        {
            let forest = HardlinkForest::build("teardown");
            base = forest.base().to_path_buf();
            outside = forest.outside.clone();
            external = forest.external.clone();
            assert!(
                base.exists() && external.exists(),
                "the forest exists while alive"
            );
        }
        assert!(!base.exists(), "drop must remove {}", base.display());
        assert!(!outside.exists(), "including the outside directory");
        assert!(!external.exists(), "and the external link with it");
    }

    /// The counter records one entry per opened file, keyed by the path that was read — which is
    /// what lets a later commit prove that four aliases of one allocation are read once, not four
    /// times.
    #[test]
    fn read_log_records_one_entry_per_hashed_pathname() {
        let forest = HardlinkForest::build("readlog");
        let log = ReadLog::start();
        let progress = AtomicU64::new(0);
        for alias in forest.aliases.iter().take(2) {
            hash_file_verified(alias, &progress).expect("hash an alias");
        }

        assert_eq!(
            log.count_under(forest.base()),
            2,
            "two reads: {:?}",
            log.paths()
        );
        assert_eq!(log.count_of(&forest.aliases[0]), 1);
        assert_eq!(log.count_of(&forest.aliases[1]), 1);
        assert_eq!(log.count_of(&forest.twin_a), 0, "twin_a was not hashed");
    }

    /// The hash-once contract through a real scan: the hashing phase reads **one file per physical
    /// object** — three reads over the forest's three allocations, where it used to make six, one
    /// per duplicate pathname, reading the shared inode four times.
    ///
    /// Every pathname is still in the manifest; only the *reading* collapsed. That the aliases all
    /// end up carrying the digest is asserted next to the manifest itself, in the store tests.
    #[test]
    fn scan_reads_one_file_per_physical_object() {
        let forest = HardlinkForest::build("baseline");
        let mut store = crate::state::ScanStore::open_in_memory().expect("in-memory store");
        let cancel = std::sync::atomic::AtomicBool::new(false);

        let log = ReadLog::start();
        let outcome = crate::pipeline::run_scan(
            &mut store,
            &forest.scan_config(),
            None,
            false,
            &cancel,
            |_| {},
        )
        .expect("scan the forest");
        let reads = log.count_under(forest.base());
        let per_alias: Vec<usize> = forest
            .aliases
            .iter()
            .map(|alias| log.count_of(alias))
            .collect();
        let unique_reads = log.count_of(&forest.unique);
        let twin_reads = log.count_of(&forest.twin_a) + log.count_of(&forest.twin_b);
        drop(log);

        match outcome {
            crate::pipeline::ScanOutcome::Completed(_) => {}
            crate::pipeline::ScanOutcome::Cancelled => panic!("the scan must not cancel itself"),
        }
        assert_eq!(forest.duplicate_objects(), 3, "three allocations");
        assert_eq!(
            reads, 3,
            "one read per allocation, not per pathname: {reads} reads"
        );
        assert_eq!(
            per_alias.iter().sum::<usize>(),
            1,
            "the four aliases of one allocation are read exactly once between them: {per_alias:?}"
        );
        assert_eq!(twin_reads, 2, "and each independent object is read once");
        // A size nobody shares is not a candidate, so the unique file is never read.
        assert_eq!(unique_reads, 0, "the unique file must not be hashed");
        // Reading collapsed; the manifest did not.
        let scan_id = store.latest_scan_id().unwrap().expect("the scan exists");
        assert_eq!(
            store.manifest_count(scan_id).unwrap(),
            7,
            "every walked pathname keeps its row"
        );
    }

    #[test]
    fn read_log_is_disarmed_after_drop() {
        let forest = HardlinkForest::build("disarm");
        let progress = AtomicU64::new(0);
        {
            let _log = ReadLog::start();
        }
        hash_file_verified(&forest.twin_a, &progress).expect("hash twin_a");
        let log = ReadLog::start();
        assert_eq!(
            log.count_under(forest.base()),
            0,
            "reads before arming are not recorded"
        );
    }
}
