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

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::model::scan::ScanConfig;

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

    /// Baseline through the real scan, recorded so the next commit's change is visible: today the
    /// hashing phase reads **one file per pathname** — six reads over three allocations, the shared
    /// inode read four times. `R2B / C3` turns this into three reads, one per physical object, and
    /// owns the update of these numbers.
    #[test]
    fn scan_reads_one_file_per_pathname_today() {
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
        drop(log);

        match outcome {
            crate::pipeline::ScanOutcome::Completed(_) => {}
            crate::pipeline::ScanOutcome::Cancelled => panic!("the scan must not cancel itself"),
        }
        assert_eq!(
            reads,
            forest.duplicate_pathnames().len(),
            "today every duplicate pathname is read: {reads} reads"
        );
        assert_eq!(
            per_alias,
            vec![1, 1, 1, 1],
            "the same allocation is read once per alias"
        );
        assert_eq!(forest.duplicate_objects(), 3, "over three allocations");
        // A size nobody shares is not a candidate, so the unique file is never read.
        assert_eq!(unique_reads, 0, "the unique file must not be hashed");
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
