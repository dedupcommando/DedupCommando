// SPDX-License-Identifier: Apache-2.0
//! Test-only fixture for the directory-completeness work (`P-2`/`S-4`/`P-11`): pairs of
//! directories that are exact twins **only because something was left out of the scan**, plus the
//! omission ledger those pairs are supposed to produce.
//!
//! Each pair has a `left` side carrying one extra file and a `right` side without it. Every extra
//! file is invisible to the manifest today — filtered by size, filtered by extension, unnamable in
//! UTF-8, or lost to a walk error — so the two sides currently look byte-identical and earn a twin
//! claim they have not earned. That is the defect; this fixture is the ground truth to test it
//! against.
//!
//! ```text
//! <base>/root/pair_control/{left,right}/a.bin,b.bin   identical, nothing omitted (positive control)
//! <base>/root/pair_min/left/tiny.bin                  8 B, below min_size = 16
//! <base>/root/pair_max/left/huge.bin                  2048 B, above max_size = 1024
//! <base>/root/pair_ext/left/notes.log                 extension outside the allow-list
//! <base>/root/pair_utf8/left/bad\xffname.bin          name is not valid UTF-8
//! <base>/root/pair_error/left/dangling -> missing      stat fails while following symlinks
//! <base>/root/pair_error/left/loop -> pair_error/left  filesystem loop while following symlinks
//! <base>/root/pair_injected/left/walk_fault.bin       ordinary file, removed only by an injected
//! <base>/root/pair_injected/left/metadata_fault.bin   iterator fault / metadata fault
//! <base>/root/deep/a/b/c/d/tiny.bin                   deep omission; ancestors stop at the root
//! ```
//!
//! Deliberately no `chmod 000`: the gate runs as root, which walks straight through mode bits, so a
//! permission-based error would be a test that silently proves nothing. The symlink cases are shapes
//! the kernel refuses for everyone, and the `pair_injected` files are shapes the filesystem has no
//! reason to refuse at all — they carry the allowed extension, an admissible size and normal
//! permissions, so when one goes missing the injected fault is the only possible cause. See
//! [`super::WalkFaults`] for why the injection is thread-local rather than a process-wide failpoint.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::WalkFault;
use crate::model::scan::ScanConfig;

/// Smallest file the fixture's config accepts.
pub const MIN_SIZE: u64 = 16;
/// Largest file the fixture's config accepts.
pub const MAX_SIZE: u64 = 1024;
/// The only extension the fixture's config accepts.
pub const KEPT_EXTENSION: &str = "bin";
/// Size of the too-small file. Independent of `MIN_SIZE` on purpose: tying it to the threshold made
/// the file move with it, so raising the threshold could never expose a broken case.
pub const TINY_SIZE: u64 = 8;
/// Size of the too-large file, likewise independent of `MAX_SIZE`.
pub const HUGE_SIZE: u64 = 2048;

const PAYLOAD_A: &[u8] = b"payload a - between min_size and max_size, extension .bin";
const PAYLOAD_B: &[u8] = b"payload b - a second file so a directory holds more than one";

/// Why a file that exists on disk never reached the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OmissionReason {
    /// Smaller than `min_size`.
    BelowMin,
    /// Larger than `max_size`.
    AboveMax,
    /// Extension outside `include_extensions`.
    ExtensionFiltered,
    /// The name cannot be represented as UTF-8, so the walk refuses to touch it.
    NonUtf8,
    /// The walk iterator failed on the entry instead of yielding it.
    WalkError,
    /// The entry was yielded, but its metadata could not be read.
    MetadataError,
}

/// Directory pairs whose twin claims depend on omissions. Removed on drop.
pub struct DirTrees {
    base: PathBuf,
    /// The directory to scan.
    pub root: PathBuf,
    /// Both sides identical, nothing omitted: a twin claim here is correct.
    pub control: (PathBuf, PathBuf),
    /// `left` holds a file below `min_size`.
    pub below_min: (PathBuf, PathBuf),
    /// `left` holds a file above `max_size`.
    pub above_max: (PathBuf, PathBuf),
    /// `left` holds a file whose extension is filtered out.
    pub extension: (PathBuf, PathBuf),
    /// `left` holds a file whose name is not valid UTF-8.
    pub non_utf8: (PathBuf, PathBuf),
    /// `left` holds the two symlink shapes that make the walk fail.
    pub walk_error: (PathBuf, PathBuf),
    /// `left` holds two perfectly ordinary files that only an injected fault can remove.
    pub injected: (PathBuf, PathBuf),
    /// The deepest directory that actually contains an omitted file.
    pub deep_dir: PathBuf,
}

impl DirTrees {
    /// Builds the trees and self-checks them.
    pub fn build(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before the epoch")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("dedcom_dirs_{tag}_{}_{nanos}", std::process::id()));
        let root = base.join("root");

        let pair = |name: &str| -> (PathBuf, PathBuf) {
            let left = root.join(name).join("left");
            let right = root.join(name).join("right");
            for side in [&left, &right] {
                std::fs::create_dir_all(side).expect("create a pair side");
                std::fs::write(side.join("a.bin"), PAYLOAD_A).expect("write a.bin");
            }
            (left, right)
        };

        let control = pair("pair_control");
        // The control pair is the only one where both sides hold everything.
        for side in [&control.0, &control.1] {
            std::fs::write(side.join("b.bin"), PAYLOAD_B).expect("write b.bin");
        }

        let below_min = pair("pair_min");
        std::fs::write(below_min.0.join("tiny.bin"), vec![b't'; TINY_SIZE as usize])
            .expect("write tiny.bin");

        let above_max = pair("pair_max");
        std::fs::write(above_max.0.join("huge.bin"), vec![b'h'; HUGE_SIZE as usize])
            .expect("write huge.bin");

        let extension = pair("pair_ext");
        std::fs::write(extension.0.join("notes.log"), PAYLOAD_B).expect("write notes.log");

        let non_utf8 = pair("pair_utf8");
        std::fs::write(non_utf8.0.join(non_utf8_name()), PAYLOAD_B)
            .expect("write the non-UTF8 name");

        let walk_error = pair("pair_error");
        // Two shapes that fail for root as surely as for anyone else, both only while the walk
        // follows symlinks: a link to a name that does not exist, and a link back to its own parent.
        std::os::unix::fs::symlink(
            walk_error.0.join("missing_target.bin"),
            walk_error.0.join("dangling.bin"),
        )
        .expect("create the dangling symlink");
        std::os::unix::fs::symlink(&walk_error.0, walk_error.0.join("loop.bin"))
            .expect("create the looping symlink");

        // Two files nothing about the filesystem excludes: right extension, size inside the window,
        // ordinary regular files, readable. Only an injected fault can keep them out of a manifest,
        // which is what makes them evidence about the walk's two silent-skip branches.
        let injected = pair("pair_injected");
        for name in ["walk_fault.bin", "metadata_fault.bin"] {
            std::fs::write(injected.0.join(name), PAYLOAD_B).expect("write a nominated file");
        }

        // The deep case: the omitted file sits five levels under the root, so the ledger has a real
        // ancestor chain to mark - and a clear place to stop.
        let deep_dir = root.join("deep").join("a").join("b").join("c").join("d");
        std::fs::create_dir_all(&deep_dir).expect("create the deep directory");
        std::fs::write(deep_dir.join("kept.bin"), PAYLOAD_A).expect("write the deep kept file");
        std::fs::write(deep_dir.join("tiny.bin"), vec![b'd'; TINY_SIZE as usize])
            .expect("write the deep tiny file");

        let trees = DirTrees {
            base,
            root,
            control,
            below_min,
            above_max,
            extension,
            non_utf8,
            walk_error,
            injected,
            deep_dir,
        };
        trees.verify();
        trees
    }

    /// The ordinary file that only an injected walk-iterator fault removes.
    pub fn walk_fault_file(&self) -> PathBuf {
        self.injected.0.join("walk_fault.bin")
    }

    /// The ordinary file that only an injected metadata fault removes.
    pub fn metadata_fault_file(&self) -> PathBuf {
        self.injected.0.join("metadata_fault.bin")
    }

    /// The two faults to arm, one per branch, each naming a different file — so a fault firing at the
    /// wrong site, or firing twice, is visible rather than merely plausible.
    pub fn injected_faults(&self) -> Vec<(PathBuf, WalkFault)> {
        vec![
            (self.walk_fault_file(), WalkFault::Iterator),
            (self.metadata_fault_file(), WalkFault::Metadata),
        ]
    }

    /// What the injected faults mean for a ledger, once one exists.
    pub fn injected_omissions(&self) -> BTreeMap<PathBuf, OmissionReason> {
        BTreeMap::from([
            (self.walk_fault_file(), OmissionReason::WalkError),
            (self.metadata_fault_file(), OmissionReason::MetadataError),
        ])
    }

    /// The directory `Drop` removes.
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The config the fixture is built for: size window, one allowed extension, no default
    /// exclusions, symlinks not followed. The `pair_error` links are inert under it.
    pub fn scan_config(&self) -> ScanConfig {
        let mut config = ScanConfig::new(vec![self.root.clone()]);
        config.min_size = MIN_SIZE;
        config.max_size = Some(MAX_SIZE);
        config.include_extensions = vec![KEPT_EXTENSION.to_string()];
        config.exclude_globs = Vec::new();
        config.follow_symlinks = false;
        config
    }

    /// The same config with symlinks followed, which is what arms the two walk-error shapes.
    pub fn scan_config_following(&self) -> ScanConfig {
        let mut config = self.scan_config();
        config.follow_symlinks = true;
        config
    }

    /// Every file that exists on disk but never reaches the manifest, and why. `WalkError` entries
    /// only apply while symlinks are followed.
    pub fn expected_omissions(&self) -> BTreeMap<PathBuf, OmissionReason> {
        let mut out = BTreeMap::new();
        out.insert(self.below_min.0.join("tiny.bin"), OmissionReason::BelowMin);
        out.insert(self.above_max.0.join("huge.bin"), OmissionReason::AboveMax);
        out.insert(
            self.extension.0.join("notes.log"),
            OmissionReason::ExtensionFiltered,
        );
        out.insert(
            self.non_utf8.0.join(non_utf8_name()),
            OmissionReason::NonUtf8,
        );
        out.insert(self.deep_dir.join("tiny.bin"), OmissionReason::BelowMin);
        out.insert(
            self.walk_error.0.join("dangling.bin"),
            OmissionReason::WalkError,
        );
        out.insert(
            self.walk_error.0.join("loop.bin"),
            OmissionReason::WalkError,
        );
        out
    }

    /// The directories that must lose their exact-twin claim, because a file under them is missing
    /// from the manifest. Their `right` counterparts must keep theirs.
    pub fn incomplete_sides(&self) -> Vec<PathBuf> {
        vec![
            self.below_min.0.clone(),
            self.above_max.0.clone(),
            self.extension.0.clone(),
            self.non_utf8.0.clone(),
            self.walk_error.0.clone(),
            self.deep_dir.clone(),
        ]
    }

    /// The chain a ledger must mark for `path`: its directory, then every ancestor up to and
    /// including the scan root — never above it.
    pub fn ancestors_up_to_root(&self, path: &Path) -> Vec<PathBuf> {
        let mut chain = Vec::new();
        let mut current = path.parent();
        while let Some(dir) = current {
            chain.push(dir.to_path_buf());
            if dir == self.root {
                break;
            }
            current = dir.parent();
        }
        assert_eq!(
            chain.last().map(PathBuf::as_path),
            Some(self.root.as_path()),
            "{} is not under the scan root",
            path.display()
        );
        chain
    }

    /// Everything the fixture claims about itself.
    pub fn verify(&self) {
        // The control pair is genuinely identical, file for file.
        for name in ["a.bin", "b.bin"] {
            let left = std::fs::read(self.control.0.join(name)).expect("read the control left");
            let right = std::fs::read(self.control.1.join(name)).expect("read the control right");
            assert_eq!(
                left, right,
                "the control pair must be byte-identical: {name}"
            );
        }

        // Each omitted file exists on disk, and its size or name is the reason it will not be
        // scanned - asserted here so a future edit cannot quietly make a case vacuous. Both size
        // cases are checked against the live thresholds, so moving a threshold past its file fails
        // the fixture instead of silently emptying the case.
        for tiny in [
            self.below_min.0.join("tiny.bin"),
            self.deep_dir.join("tiny.bin"),
        ] {
            let meta = std::fs::metadata(&tiny).expect("stat a tiny file");
            assert!(
                meta.len() < MIN_SIZE,
                "{} must be below min_size {MIN_SIZE}, it is {}",
                tiny.display(),
                meta.len()
            );
        }
        let huge = std::fs::metadata(self.above_max.0.join("huge.bin")).expect("stat huge.bin");
        assert!(
            huge.len() > MAX_SIZE,
            "huge.bin must be above max_size {MAX_SIZE}, it is {}",
            huge.len()
        );
        let excluded = self.extension.0.join("notes.log");
        assert!(excluded.exists(), "notes.log must exist");
        assert_ne!(
            excluded.extension().and_then(OsStr::to_str),
            Some(KEPT_EXTENSION),
            "notes.log must not carry the allowed extension"
        );
        let bad = self.non_utf8.0.join(non_utf8_name());
        assert!(bad.exists(), "the non-UTF8 file must exist on disk");
        assert!(
            bad.to_str().is_none(),
            "its path must not be representable as UTF-8"
        );

        // Both error shapes exist as symlinks, and neither resolves to a regular file.
        for link in ["dangling.bin", "loop.bin"] {
            let path = self.walk_error.0.join(link);
            let meta = std::fs::symlink_metadata(&path).expect("lstat an error link");
            assert!(meta.file_type().is_symlink(), "{link} must be a symlink");
            assert!(
                !path.metadata().map(|m| m.is_file()).unwrap_or(false),
                "{link} must not resolve to a regular file"
            );
        }

        // The nominated files are ordinary in every way the walk cares about: the allowed extension,
        // a size inside the window, a regular file rather than a link, and readable. So an absence
        // cannot be blamed on filtering, symlink handling or permissions - only on the injection.
        for file in [self.walk_fault_file(), self.metadata_fault_file()] {
            let meta = std::fs::symlink_metadata(&file).expect("lstat a nominated file");
            assert!(
                meta.file_type().is_file(),
                "{} must be a regular file",
                file.display()
            );
            assert!(
                meta.len() >= MIN_SIZE && meta.len() <= MAX_SIZE,
                "{} must be admissible by size, it is {}",
                file.display(),
                meta.len()
            );
            assert_eq!(
                file.extension().and_then(OsStr::to_str),
                Some(KEPT_EXTENSION),
                "{} must carry the allowed extension",
                file.display()
            );
            assert_ne!(
                meta.permissions().mode() & 0o400,
                0,
                "{} must stay readable: no permission games",
                file.display()
            );
        }

        // Every `right` side holds exactly the files the manifest will see on the `left`.
        for (left, right) in [
            &self.below_min,
            &self.above_max,
            &self.extension,
            &self.non_utf8,
            &self.walk_error,
            &self.injected,
        ]
        .map(|pair| (&pair.0, &pair.1))
        {
            assert!(
                left.join("a.bin").exists() && right.join("a.bin").exists(),
                "both sides carry the scannable file"
            );
            assert_eq!(
                std::fs::read_dir(right).expect("read a right side").count(),
                1,
                "a right side holds only the scannable file: {}",
                right.display()
            );
        }

        // The deep chain reaches the root and stops there.
        let chain = self.ancestors_up_to_root(&self.deep_dir.join("tiny.bin"));
        assert_eq!(chain.len(), 6, "d, c, b, a, deep, root: {chain:?}");
        assert_eq!(chain[0], self.deep_dir, "the nearest directory comes first");
        assert_eq!(chain[5], self.root, "the chain stops at the scan root");
        assert!(
            !chain.contains(&self.base),
            "the chain must never leave the scan root"
        );
    }
}

impl Drop for DirTrees {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.base).ok();
    }
}

/// A file name with a byte no UTF-8 decoder accepts.
fn non_utf8_name() -> &'static OsStr {
    OsStr::from_bytes(b"bad\xffname.bin")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::walk::walk;
    use crate::testfixtures::WalkFaults;
    use std::collections::BTreeSet;
    use std::sync::atomic::AtomicBool;

    /// Walks `config` and returns the manifest paths, plus the non-UTF8 skip counter.
    fn walked(config: &ScanConfig) -> (BTreeSet<PathBuf>, u64) {
        let cancel = AtomicBool::new(false);
        let (files, skipped) = walk(config, &cancel, |_, _, _| {}).expect("walk the fixture");
        (files.into_iter().map(|file| file.path).collect(), skipped)
    }

    #[test]
    fn trees_hold_their_own_invariants() {
        let trees = DirTrees::build("selfcheck");
        trees.verify();
        assert_eq!(
            trees.expected_omissions().len(),
            7,
            "five filtered/unnamable files plus two error links"
        );
        assert_eq!(trees.incomplete_sides().len(), 6);
    }

    /// The positive control: nothing is omitted under the control pair, so both sides reach the
    /// manifest whole and a twin claim about them is honest.
    #[test]
    fn the_control_pair_is_scanned_whole() {
        let trees = DirTrees::build("control");
        let (paths, _) = walked(&trees.scan_config());
        for side in [&trees.control.0, &trees.control.1] {
            for name in ["a.bin", "b.bin"] {
                assert!(
                    paths.contains(&side.join(name)),
                    "{} must be in the manifest",
                    side.join(name).display()
                );
            }
        }
    }

    /// Every omitted file is absent from the manifest, and each `left` side is left looking exactly
    /// like its `right` side — the false-twin precondition the ledger has to break. Pinned as
    /// today's behavior; `R3` changes what the scan records about it, not this fixture's layout.
    #[test]
    fn each_omission_is_invisible_and_leaves_a_false_twin() {
        let trees = DirTrees::build("omissions");
        let (paths, _) = walked(&trees.scan_config());

        for (omitted, reason) in trees.expected_omissions() {
            if reason == OmissionReason::WalkError {
                continue; // inert unless symlinks are followed
            }
            assert!(
                !paths.contains(&omitted),
                "{} must not reach the manifest ({reason:?})",
                omitted.display()
            );
            assert!(
                omitted.exists() || reason == OmissionReason::NonUtf8,
                "but it does exist on disk"
            );
        }

        // Left and right now hold the same scanned content: an exact-twin claim today.
        for pair in [
            &trees.below_min,
            &trees.above_max,
            &trees.extension,
            &trees.non_utf8,
        ] {
            let names = |dir: &Path| -> BTreeSet<PathBuf> {
                paths
                    .iter()
                    .filter(|p| p.starts_with(dir))
                    .map(|p| p.strip_prefix(dir).expect("under the side").to_path_buf())
                    .collect()
            };
            assert_eq!(
                names(&pair.0),
                names(&pair.1),
                "{} and {} look identical to the scan",
                pair.0.display(),
                pair.1.display()
            );
            assert_eq!(names(&pair.0).len(), 1, "one scannable file per side");
        }
    }

    /// The non-UTF8 name is the one omission the walk already counts, and the counter is exactly
    /// one — the other cases must not inflate it.
    #[test]
    fn only_the_non_utf8_name_is_counted_today() {
        let trees = DirTrees::build("nonutf8");
        let (_, skipped) = walked(&trees.scan_config());
        assert_eq!(skipped, 1, "one non-UTF8 name, counted once");
    }

    /// The two symlink shapes really do make the walk fail while following links — verified against
    /// `ignore` itself, so the mechanism is proven independently of what our walk does with it. Our
    /// walk then drops those entries with no counter and no trace: that silence is the defect.
    #[test]
    fn following_symlinks_produces_real_walk_errors_that_vanish() {
        let trees = DirTrees::build("walkerr");

        let errors = ignore::WalkBuilder::new(&trees.walk_error.0)
            .standard_filters(false)
            .hidden(false)
            .follow_links(true)
            .build()
            .filter(|result| result.is_err())
            .count();
        assert!(
            errors >= 1,
            "the dangling and looping links must make ignore report an error"
        );

        let (paths, skipped) = walked(&trees.scan_config_following());
        for link in ["dangling.bin", "loop.bin"] {
            assert!(
                !paths.contains(&trees.walk_error.0.join(link)),
                "{link} must not reach the manifest"
            );
        }
        assert_eq!(
            skipped, 1,
            "and no counter grows for them: only the non-UTF8 name is counted"
        );

        // Pin exactly what the error side contributes while symlinks are followed, so a phantom
        // pathname reached through the loop cannot slip in unnoticed.
        let under_error: BTreeSet<PathBuf> = paths
            .iter()
            .filter(|path| path.starts_with(&trees.walk_error.0))
            .map(|path| {
                path.strip_prefix(&trees.walk_error.0)
                    .expect("under the error side")
                    .to_path_buf()
            })
            .collect();
        assert_eq!(
            under_error,
            BTreeSet::from([PathBuf::from("a.bin")]),
            "the error side contributes only its scannable file"
        );
    }

    /// The deep omission's ancestor chain is the ledger's marking target, and it stops at the scan
    /// root rather than walking out into the temp directory.
    #[test]
    fn the_deep_omission_marks_ancestors_only_up_to_the_root() {
        let trees = DirTrees::build("deep");
        let chain = trees.ancestors_up_to_root(&trees.deep_dir.join("tiny.bin"));
        assert_eq!(*chain.last().expect("a non-empty chain"), trees.root);
        assert!(chain.iter().all(|dir| dir.starts_with(&trees.root)));

        let (paths, _) = walked(&trees.scan_config());
        assert!(
            paths.contains(&trees.deep_dir.join("kept.bin")),
            "the deep directory is representable: it still has a scanned file"
        );
        assert!(
            !paths.contains(&trees.deep_dir.join("tiny.bin")),
            "while the deep omission is invisible"
        );
    }

    /// Control for both injected cases: with nothing armed, the two nominated files are ordinary
    /// duplicates and reach the manifest. Without this, an injected absence would prove nothing.
    #[test]
    fn without_injection_the_nominated_files_are_scanned() {
        let trees = DirTrees::build("inject_none");
        let (paths, _) = walked(&trees.scan_config());
        for file in [trees.walk_fault_file(), trees.metadata_fault_file()] {
            assert!(
                paths.contains(&file),
                "{} must be scanned when no fault is armed",
                file.display()
            );
        }
    }

    /// The iterator branch: one fault, armed for one ordinary file, fires exactly once at the
    /// iterator site and takes only that file out of the manifest.
    #[test]
    fn an_injected_walk_fault_removes_only_its_own_file() {
        let trees = DirTrees::build("inject_walk");
        let target = trees.walk_fault_file();
        let faults = WalkFaults::arm(&[(target.clone(), WalkFault::Iterator)]);
        let (paths, skipped) = walked(&trees.scan_config());

        assert_eq!(
            faults.fired(),
            vec![(target.clone(), WalkFault::Iterator)],
            "one fault, fired once, at the iterator site"
        );
        assert!(faults.pending().is_empty(), "nothing stayed armed");
        assert!(
            !paths.contains(&target),
            "{} must be missing for the injected walk error",
            target.display()
        );
        assert!(
            paths.contains(&trees.metadata_fault_file()),
            "the metadata-fault file is untouched by an iterator fault"
        );
        assert!(
            paths.contains(&trees.injected.0.join("a.bin")),
            "and so is its own directory's scannable file"
        );
        assert_eq!(
            skipped, 1,
            "no counter grows: only the non-UTF8 name is counted"
        );
    }

    /// The metadata branch, which no filesystem shape in this fixture can reach. The recorded kind is
    /// the call site: `Metadata` can only come from the `entry.metadata()` match.
    #[test]
    fn an_injected_metadata_fault_removes_only_its_own_file() {
        let trees = DirTrees::build("inject_meta");
        let target = trees.metadata_fault_file();
        let faults = WalkFaults::arm(&[(target.clone(), WalkFault::Metadata)]);
        let (paths, skipped) = walked(&trees.scan_config());

        assert_eq!(
            faults.fired(),
            vec![(target.clone(), WalkFault::Metadata)],
            "one fault, fired once, at the metadata site"
        );
        assert!(faults.pending().is_empty(), "nothing stayed armed");
        assert!(
            !paths.contains(&target),
            "{} must be missing for the injected metadata error",
            target.display()
        );
        assert!(
            paths.contains(&trees.walk_fault_file()),
            "the walk-fault file is untouched by a metadata fault"
        );
        assert_eq!(skipped, 1, "no counter grows for it either");
    }

    /// Both branches at once, alongside the real symlink errors: each fault fires exactly once, the
    /// two are separately identified, and the manifest loses precisely those two paths.
    #[test]
    fn both_injected_faults_fire_once_and_lose_nothing_else() {
        let trees = DirTrees::build("inject_both");
        let (baseline, baseline_skipped) = walked(&trees.scan_config_following());

        let faults = WalkFaults::arm(&trees.injected_faults());
        let (paths, skipped) = walked(&trees.scan_config_following());

        assert_eq!(faults.fired().len(), 2, "each fault fired exactly once");
        assert!(faults.pending().is_empty(), "and neither stayed armed");
        let fired: BTreeMap<PathBuf, WalkFault> = faults.fired().into_iter().collect();
        let armed: BTreeMap<PathBuf, WalkFault> = trees.injected_faults().into_iter().collect();
        assert_eq!(
            fired, armed,
            "each file lost its own, separately identified branch"
        );

        // Each file is missing for its declared reason: the branch that fired is the one the fixture
        // publishes as that file's omission reason, not merely some branch or other.
        let declared = trees.injected_omissions();
        for (file, kind) in trees.injected_faults() {
            let expected_reason = match kind {
                WalkFault::Iterator => OmissionReason::WalkError,
                WalkFault::Metadata => OmissionReason::MetadataError,
            };
            assert_eq!(
                declared.get(&file).copied(),
                Some(expected_reason),
                "{} must be declared as {expected_reason:?}",
                file.display()
            );
            assert_eq!(
                fired.get(&file),
                Some(&kind),
                "{} must be lost through exactly that branch",
                file.display()
            );
        }

        let mut expected = baseline.clone();
        for (file, _) in trees.injected_faults() {
            assert!(
                expected.remove(&file),
                "{} was in the manifest before injection",
                file.display()
            );
        }
        assert_eq!(
            paths, expected,
            "exactly the two nominated files are gone, nothing else"
        );
        assert_eq!(
            skipped, baseline_skipped,
            "the non-UTF8 counter is unaffected by injection"
        );

        // The real symlink shapes still behave as before: no phantom descendant through the loop.
        let under_error: BTreeSet<PathBuf> = paths
            .iter()
            .filter(|path| path.starts_with(&trees.walk_error.0))
            .map(|path| {
                path.strip_prefix(&trees.walk_error.0)
                    .expect("under the error side")
                    .to_path_buf()
            })
            .collect();
        assert_eq!(
            under_error,
            BTreeSet::from([PathBuf::from("a.bin")]),
            "the error side still contributes only its scannable file"
        );
    }

    #[test]
    fn teardown_removes_the_whole_tree() {
        let base;
        {
            let trees = DirTrees::build("teardown");
            base = trees.base().to_path_buf();
            assert!(base.exists(), "the trees exist while alive");
        }
        assert!(!base.exists(), "drop must remove {}", base.display());
    }
}
