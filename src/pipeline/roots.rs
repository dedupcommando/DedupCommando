// SPDX-License-Identifier: Apache-2.0
//! Scan-root validation: refuse a root set that would make one directory tree visible twice.
//!
//! Two pathnames can lead to the same directory — the same spelling twice, a symlinked root, a root
//! nested inside another, a bind mount or a second mount of one dataset. Every one of them makes the
//! walk record the same physical file under two pathnames, and everything downstream then counts it
//! twice: group membership, reclaim, the action plan. There is no honest number to report from such a
//! scan, so it is refused rather than adjusted.
//!
//! Two guards, because the two cases are visible at different times:
//!
//! - [`ensure_disjoint`] runs before `begin_scan`, on the roots the operator selected. Nothing is
//!   normalized away and no root is silently dropped: either the whole set is accepted as given, or
//!   the scan does not start and the error names both roots and how they collide.
//! - [`DirAliasGuard`] runs during the walk, where an alias inside a selected root first becomes
//!   visible (a bind mount under it, or a followed directory symlink). It fails the whole scan
//!   closed; a manifest that saw one tree twice must never be published as a complete result.
//!
//! One more check stands in front of both for `--scan`: [`ensure_reachable`] refuses a root the
//! walk could not enter at all.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};

/// How two selected roots collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootConflict {
    /// Byte-identical spelling, listed twice.
    DuplicateSpelling,
    /// Different spellings that resolve to the same canonical path (a symlinked or `..`-relative
    /// root, a trailing slash).
    CanonicalAlias,
    /// One canonical path lies inside the other.
    ParentChild,
    /// Different canonical paths, one directory: a bind mount, or one dataset mounted twice.
    SameObject,
}

impl RootConflict {
    /// Short name of the conflict class, as it appears in the error.
    pub fn label(self) -> &'static str {
        match self {
            RootConflict::DuplicateSpelling => "duplicate spelling",
            RootConflict::CanonicalAlias => "canonical alias",
            RootConflict::ParentChild => "nested roots",
            RootConflict::SameObject => "same directory object",
        }
    }
}

/// What the filesystem says about a selected root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoot {
    pub canonical: PathBuf,
    pub device: u64,
    pub inode: u64,
}

/// A selected root and its resolution. The given spelling is kept exactly as the operator wrote it —
/// it is what the error message has to name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDescriptor {
    pub given: PathBuf,
    /// `None` when the path cannot be resolved right now (it does not exist, or is unreadable). Such
    /// a root simply cannot be compared with the others; `--scan` has refused it by then
    /// ([`ensure_reachable`]), the interface still scans it.
    pub resolved: Option<ResolvedRoot>,
}

/// Reads what the filesystem knows about each root. Never fails and never drops a root: an
/// unresolvable path yields `resolved: None` and is simply not compared. Refusing a root the walk
/// cannot enter is [`ensure_reachable`]'s job before any `--scan`, a new one or a resume; only the
/// interface still gets here with one.
pub fn describe(paths: &[PathBuf]) -> Vec<RootDescriptor> {
    paths
        .iter()
        .map(|given| {
            let resolved = std::fs::canonicalize(given).ok().and_then(|canonical| {
                let meta = std::fs::metadata(&canonical).ok()?;
                use std::os::unix::fs::MetadataExt;
                Some(ResolvedRoot {
                    canonical,
                    device: meta.dev(),
                    inode: meta.ino(),
                })
            });
            RootDescriptor {
                given: given.clone(),
                resolved,
            }
        })
        .collect()
}

/// The pure core: rejects the first colliding pair it finds. Order-independent — a parent/child pair
/// is caught whichever way round it was listed.
pub fn validate(roots: &[RootDescriptor]) -> Result<()> {
    for (index, first) in roots.iter().enumerate() {
        for second in roots.iter().skip(index + 1) {
            if first.given == second.given {
                return Err(conflict(first, second, RootConflict::DuplicateSpelling));
            }
            let (Some(one), Some(other)) = (&first.resolved, &second.resolved) else {
                continue;
            };
            if one.canonical == other.canonical {
                return Err(conflict(first, second, RootConflict::CanonicalAlias));
            }
            if (one.device, one.inode) == (other.device, other.inode) {
                return Err(conflict(first, second, RootConflict::SameObject));
            }
            // Component-wise, so `/tank/a` does not look like a parent of `/tank/ab`.
            if one.canonical.starts_with(&other.canonical)
                || other.canonical.starts_with(&one.canonical)
            {
                return Err(conflict(first, second, RootConflict::ParentChild));
            }
        }
    }
    Ok(())
}

/// Validates the roots as selected. Called before `begin_scan`, so a rejected set leaves no scan row
/// and no result behind.
pub fn ensure_disjoint(paths: &[PathBuf]) -> Result<()> {
    validate(&describe(paths))
}

/// Refuses a root the walk could not enter: one that does not exist, cannot be read, or is neither
/// a directory nor a regular file.
///
/// Such a root used to become one walk error and a finished, empty scan with exit code 0 and the
/// reason nowhere. Worse, that scan counted toward the history kept, so two nights of a cron scan
/// over a root that was gone moved both good scans of it to the trash. `--scan` runs this before
/// it takes the lock, so a refusal leaves no lock and no database behind — only its line in the
/// log. The root is checked as given, the way the walk opens it: a relative root stays relative,
/// and a symbolic link is followed.
///
/// An empty directory passes, and so does the empty mount point a dataset that is not mounted
/// leaves behind: telling the two apart takes ZFS, not a path.
pub fn ensure_reachable(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        let reach = look(path, |dir| std::fs::read_dir(dir).map(drop));
        if let Some(refusal) = refusal(path, reach) {
            return Err(refusal);
        }
    }
    Ok(())
}

/// What the filesystem says about a root, as far as the walk is concerned.
#[derive(Debug)]
enum Reach {
    /// A directory that can be listed, or a regular file.
    Walkable,
    Missing,
    /// A symbolic link that leads nowhere.
    Dangling,
    /// `stat` failed for another reason: a loop of links, a file taken for a directory, no search
    /// permission on the way.
    Unreachable(std::io::Error),
    /// A directory that may not be listed.
    Unlistable(std::io::Error),
    /// A device, a FIFO, a socket.
    NotWalkable,
}

/// Looks at a root the way the walk will: its metadata through a symbolic link, and for a
/// directory whether `list` can list it. The listing is handed in, so a test can give the
/// filesystem's answer that root would never get — root lists every directory there is.
fn look(path: &Path, list: impl FnOnce(&Path) -> std::io::Result<()>) -> Reach {
    match std::fs::metadata(path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Reach::Unreachable(err),
        Err(_) if std::fs::symlink_metadata(path).is_ok() => Reach::Dangling,
        Err(_) => Reach::Missing,
        Ok(meta) if meta.is_dir() => match list(path) {
            Ok(()) => Reach::Walkable,
            Err(err) => Reach::Unlistable(err),
        },
        Ok(meta) if meta.is_file() => Reach::Walkable,
        Ok(_) => Reach::NotWalkable,
    }
}

/// The refusal for a root the walk could not enter, if it is one.
fn refusal(path: &Path, reach: Reach) -> Option<AppError> {
    let shown = show(path);
    let why = match reach {
        Reach::Walkable => return None,
        Reach::Missing => "does not exist, so nothing was scanned — check the spelling, and that \
                           the dataset is mounted"
            .to_string(),
        Reach::Dangling => "is a symbolic link to nothing, so nothing was scanned — check what it \
                            points to, and that the dataset there is mounted"
            .to_string(),
        Reach::Unreachable(err) => format!("cannot be reached ({err}), so nothing was scanned"),
        Reach::Unlistable(err) => format!("cannot be read ({err}), so nothing was scanned"),
        Reach::NotWalkable => {
            "is neither a directory nor a regular file, so nothing was scanned".to_string()
        }
    };
    Some(AppError::msg(format!("scan root {shown} {why}")))
}

/// Builds the rejection, naming both roots, the class and what to do about it.
fn conflict(first: &RootDescriptor, second: &RootDescriptor, class: RootConflict) -> AppError {
    let one = show(&first.given);
    let other = show(&second.given);
    let detail = match class {
        RootConflict::DuplicateSpelling => "the same path is listed twice".to_string(),
        RootConflict::CanonicalAlias => match &first.resolved {
            Some(resolved) => format!("both resolve to {}", show(&resolved.canonical)),
            None => "both resolve to the same directory".to_string(),
        },
        RootConflict::ParentChild => "one lies inside the other".to_string(),
        RootConflict::SameObject => match (&first.resolved, &second.resolved) {
            (Some(resolved), _) => format!(
                "different paths, one directory (device {}, inode {}) — a bind mount, or one dataset mounted twice",
                resolved.device, resolved.inode
            ),
            _ => "different paths, one directory".to_string(),
        },
    };
    AppError::msg(format!(
        "scan roots conflict ({}): {one} and {other} — {detail}. \
         Every file under it would be counted twice, so the scan was not started. \
         Select only one of the two.",
        class.label()
    ))
}

/// Directories already seen by this walk, keyed by physical identity.
///
/// A second pathname for a directory we already walked means the tree is reachable twice — a bind
/// mount inside a selected root, or a directory symlink being followed. The walk cannot repair that,
/// and a manifest holding one file under two pathnames is not a result worth publishing, so the scan
/// stops with both pathnames named.
#[derive(Default)]
pub struct DirAliasGuard {
    seen: HashMap<(u64, u64), PathBuf>,
}

impl DirAliasGuard {
    /// Records a directory. `Err` when a different pathname already owned the same directory.
    pub fn note(&mut self, path: &Path, device: u64, inode: u64) -> Result<()> {
        match self.seen.entry((device, inode)) {
            Entry::Vacant(slot) => {
                slot.insert(path.to_path_buf());
                Ok(())
            }
            // The same pathname twice is not an alias — nothing to report.
            Entry::Occupied(slot) if slot.get() == path => Ok(()),
            Entry::Occupied(slot) => Err(AppError::msg(format!(
                "scan aborted: {} and {} are the same directory (device {device}, inode {inode}) — \
                 a bind mount or a followed symlink makes one tree visible twice, so every file \
                 under it would be counted twice. Unmount the alias, or scan the tree by one path.",
                show(slot.get()),
                show(path),
            ))),
        }
    }
}

/// A path as it may appear in a message: control bytes escaped, like every other user-facing path.
fn show(path: &Path) -> String {
    crate::textsan::terminal(&path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(given: &str, canonical: &str, device: u64, inode: u64) -> RootDescriptor {
        RootDescriptor {
            given: PathBuf::from(given),
            resolved: Some(ResolvedRoot {
                canonical: PathBuf::from(canonical),
                device,
                inode,
            }),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before the epoch")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("dedcom_roots_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the fixture");
        dir
    }

    /// The control: unrelated roots on the same filesystem are accepted exactly as given.
    #[test]
    fn disjoint_roots_are_accepted() {
        let roots = [
            resolved("/tank/a", "/tank/a", 1, 10),
            resolved("/tank/b", "/tank/b", 1, 11),
            resolved("/other/c", "/other/c", 2, 10),
        ];
        assert!(
            validate(&roots).is_ok(),
            "no two of these are the same tree"
        );
    }

    #[test]
    fn the_same_spelling_twice_is_rejected() {
        let roots = [
            resolved("/tank/a", "/tank/a", 1, 10),
            resolved("/tank/a", "/tank/a", 1, 10),
        ];
        let err = validate(&roots).expect_err("a duplicate root must be refused");
        let text = err.to_string();
        assert!(text.contains("duplicate spelling"), "{text}");
        assert!(text.contains("/tank/a"), "{text}");
    }

    #[test]
    fn two_spellings_of_one_path_are_rejected() {
        let roots = [
            resolved("/tank/link", "/tank/a", 1, 10),
            resolved("/tank/a/", "/tank/a", 1, 10),
        ];
        let err = validate(&roots).expect_err("an alias must be refused");
        let text = err.to_string();
        assert!(text.contains("canonical alias"), "{text}");
        assert!(
            text.contains("/tank/link") && text.contains("/tank/a"),
            "{text}"
        );
    }

    #[test]
    fn a_nested_root_is_rejected_in_both_orders() {
        let parent = resolved("/tank/a", "/tank/a", 1, 10);
        let child = resolved("/tank/a/inner", "/tank/a/inner", 1, 11);
        for (first, second) in [(&parent, &child), (&child, &parent)] {
            let err = validate(&[first.clone(), second.clone()])
                .expect_err("nested roots must be refused");
            let text = err.to_string();
            assert!(text.contains("nested roots"), "{text}");
            assert!(
                text.contains("/tank/a/inner") && text.contains("/tank/a"),
                "both roots must be named: {text}"
            );
        }
    }

    /// A sibling whose name merely starts with the other's: `/tank/ab` is not inside `/tank/a`.
    #[test]
    fn a_name_prefix_is_not_a_nested_root() {
        let roots = [
            resolved("/tank/a", "/tank/a", 1, 10),
            resolved("/tank/ab", "/tank/ab", 1, 11),
        ];
        assert!(validate(&roots).is_ok(), "a name prefix is not containment");
    }

    /// The bind-mount shape: unrelated canonical paths, one directory object.
    #[test]
    fn one_directory_under_two_paths_is_rejected() {
        let roots = [
            resolved("/tank/data", "/tank/data", 259, 4242),
            resolved("/mnt/mirror", "/mnt/mirror", 259, 4242),
        ];
        let err = validate(&roots).expect_err("a bind-mounted alias must be refused");
        let text = err.to_string();
        assert!(text.contains("same directory object"), "{text}");
        assert!(
            text.contains("inode 4242"),
            "the object must be named: {text}"
        );
        assert!(
            text.contains("/tank/data") && text.contains("/mnt/mirror"),
            "{text}"
        );
    }

    /// An unresolvable root is kept and simply not compared — it must not turn into a rejection, and
    /// must not mask a conflict between the roots that did resolve.
    #[test]
    fn an_unresolvable_root_is_neither_dropped_nor_fatal() {
        let missing = RootDescriptor {
            given: PathBuf::from("/tank/gone"),
            resolved: None,
        };
        let roots = [
            missing.clone(),
            resolved("/tank/a", "/tank/a", 1, 10),
            resolved("/tank/b", "/tank/b", 1, 11),
        ];
        assert!(validate(&roots).is_ok(), "a missing root is not a conflict");

        let with_conflict = [
            missing,
            resolved("/tank/a", "/tank/a", 1, 10),
            resolved("/tank/a/inner", "/tank/a/inner", 1, 12),
        ];
        assert!(
            validate(&with_conflict).is_err(),
            "and it does not hide one either"
        );
    }

    /// `describe` on a real symlinked root: the given spelling survives, the resolution collapses to
    /// the same directory, and `ensure_disjoint` refuses the pair.
    #[test]
    fn a_real_symlinked_root_is_described_and_refused() {
        let base = temp_dir("symlink");
        let real = base.join("real");
        std::fs::create_dir_all(&real).expect("create the real root");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("create the symlinked root");

        let described = describe(&[real.clone(), link.clone()]);
        assert_eq!(described[0].given, real, "the given spelling is preserved");
        assert_eq!(described[1].given, link, "including the symlinked one");
        let (Some(one), Some(other)) = (&described[0].resolved, &described[1].resolved) else {
            panic!("both roots resolve");
        };
        assert_eq!(one.canonical, other.canonical, "to the same directory");

        let err = ensure_disjoint(&[real, link]).expect_err("the pair must be refused");
        assert!(err.to_string().contains("canonical alias"), "{err}");

        std::fs::remove_dir_all(&base).ok();
    }

    /// `describe` keeps an unresolvable root in place rather than dropping it, so the scan still
    /// covers exactly what the operator selected.
    #[test]
    fn describe_keeps_a_missing_root() {
        let described = describe(&[PathBuf::from("/dedcom-nonexistent-root")]);
        assert_eq!(described.len(), 1, "the root is kept");
        assert!(described[0].resolved.is_none(), "but not resolved");
        assert!(
            ensure_disjoint(&[PathBuf::from("/dedcom-nonexistent-root")]).is_ok(),
            "and a single missing root is not a conflict"
        );
    }

    #[test]
    fn the_walk_guard_accepts_distinct_directories() {
        let mut guard = DirAliasGuard::default();
        assert!(guard.note(Path::new("/tank/a"), 1, 10).is_ok());
        assert!(guard.note(Path::new("/tank/b"), 1, 11).is_ok());
        assert!(guard.note(Path::new("/other/c"), 2, 10).is_ok());
    }

    #[test]
    fn the_walk_guard_rejects_a_second_path_for_one_directory() {
        let mut guard = DirAliasGuard::default();
        guard
            .note(Path::new("/tank/data"), 259, 4242)
            .expect("the first pathname is fine");
        let err = guard
            .note(Path::new("/tank/data/mirror"), 259, 4242)
            .expect_err("the alias must abort the scan");
        let text = err.to_string();
        assert!(
            text.contains("/tank/data") && text.contains("/tank/data/mirror"),
            "{text}"
        );
        assert!(text.contains("inode 4242"), "{text}");
    }

    /// The same pathname arriving twice is not an alias: nothing to report.
    #[test]
    fn the_walk_guard_tolerates_the_same_path_twice() {
        let mut guard = DirAliasGuard::default();
        guard.note(Path::new("/tank/a"), 1, 10).expect("first");
        assert!(
            guard.note(Path::new("/tank/a"), 1, 10).is_ok(),
            "the same directory by the same name is not an alias"
        );
    }

    /// A directory that may not be listed is refused as unreadable, and only a directory is listed.
    /// Root lists every directory there is, so the filesystem's answer is handed in here rather
    /// than looked for on the machine.
    #[test]
    fn a_directory_that_may_not_be_listed_is_refused() {
        let base = temp_dir("unlistable");
        let file = base.join("file.bin");
        std::fs::write(&file, b"x").unwrap();
        let denied = |_: &Path| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));

        let refused = refusal(&base, look(&base, denied))
            .expect("a directory it may not list")
            .to_string();
        assert!(refused.contains("cannot be read"), "{refused}");
        assert!(refused.contains("nothing was scanned"), "{refused}");
        assert!(refused.contains(&show(&base)), "{refused}");

        let listed = look(&file, |_| panic!("a file is not listed"));
        assert!(refusal(&file, listed).is_none());
        std::fs::remove_dir_all(&base).ok();
    }

    /// Whatever the walk can enter passes: a directory, an empty one included, a regular file, a
    /// relative spelling, a symbolic link to a directory.
    #[test]
    fn a_root_the_walk_can_enter_is_reachable() {
        let base = temp_dir("reachable");
        let empty = base.join("empty");
        std::fs::create_dir(&empty).unwrap();
        let file = base.join("file.bin");
        std::fs::write(&file, b"x").unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&empty, &link).unwrap();
        let roots = [empty, file, link, PathBuf::from(".")];
        let reached = ensure_reachable(&roots);
        std::fs::remove_dir_all(&base).ok();
        reached.expect("every one of them can be walked");
    }

    /// A root that is not there, a link to nothing, a path the kernel will not follow (a loop of
    /// links, a file taken for a directory) and a device are each refused by name, first or second
    /// in the list, and a control character in the name is spelled out.
    #[test]
    fn a_root_the_walk_cannot_enter_is_refused_by_name() {
        let base = temp_dir("unreachable");
        let fine = base.join("fine");
        std::fs::create_dir(&fine).unwrap();
        let missing = base.join("miss\u{1b}[2Jing");
        let dangling = base.join("dangling");
        std::os::unix::fs::symlink(base.join("nowhere"), &dangling).unwrap();
        let (loop_a, loop_b) = (base.join("loop_a"), base.join("loop_b"));
        std::os::unix::fs::symlink(&loop_b, &loop_a).unwrap();
        std::os::unix::fs::symlink(&loop_a, &loop_b).unwrap();
        let file = base.join("file.bin");
        std::fs::write(&file, b"x").unwrap();
        let through_a_file = file.join("inside");
        // A character device, on every Linux: neither a directory nor a regular file.
        let device = PathBuf::from("/dev/null");

        let cases = [
            (
                &missing,
                "does not exist, so nothing was scanned — check the spelling, and that the \
                 dataset is mounted",
            ),
            (
                &dangling,
                "is a symbolic link to nothing, so nothing was scanned — check what it points \
                 to, and that the dataset there is mounted",
            ),
            (&loop_a, "cannot be reached"),
            (&through_a_file, "cannot be reached"),
            (&device, "is neither a directory nor a regular file"),
        ];
        for (root, says) in cases {
            for roots in [[fine.clone(), root.clone()], [root.clone(), fine.clone()]] {
                let refusal = ensure_reachable(&roots).expect_err(says).to_string();
                assert!(refusal.contains(says), "{refusal}");
                assert!(refusal.contains("nothing was scanned"), "{refusal}");
                assert!(refusal.contains(&show(root)), "{refusal}");
                assert!(!refusal.contains(char::is_control), "{refusal:?}");
            }
        }
        std::fs::remove_dir_all(&base).ok();
    }
}
