// SPDX-License-Identifier: Apache-2.0
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;

use crate::error::{AppError, Result};
use crate::model::scan::ScanConfig;

/// A file discovered during the walk.
pub struct WalkedFile {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    /// The sub-second and ctime components of the identity (walk snapshot).
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub device: u64,
    pub inode: u64,
    /// `st_nlink` — how many pathnames the inode has in total, including any this scan never
    /// sees. Comes from the metadata already fetched below; costs no extra syscall.
    pub nlink: u64,
}

/// Walks all roots from `config` and returns the matching files plus the number of files
/// skipped because of a non-UTF8 name.
/// The `.zfs` and quarantine directories are excluded. Aborts on `cancel`.
/// `on_progress` periodically receives (entries scanned, files found).
///
/// **Non-UTF8 guard:** a path that cannot be represented as
/// UTF-8 is skipped. Otherwise `to_string_lossy` would collapse different byte names
/// (`a\xFFb`, `a\xFEb`) into a single `a�b` → silent loss/corruption of the string in the PK
/// `(scan_id, path)`; and a `�`-path read back would miss the
/// real file on the action path. It is safer not to touch such a file at all.
pub fn walk(
    config: &ScanConfig,
    cancel: &AtomicBool,
    mut on_progress: impl FnMut(u64, u64, Option<&Path>),
) -> Result<(Vec<WalkedFile>, u64)> {
    let mut roots = config.roots.iter();
    let first = roots
        .next()
        .ok_or_else(|| AppError::msg("no scan root specified"))?;

    let mut builder = WalkBuilder::new(first);
    for root in roots {
        builder.add(root);
    }
    builder
        .standard_filters(false)
        .hidden(false)
        .follow_links(config.follow_symlinks);

    // Exclusions via Override: a glob with a "!" prefix means "ignore".
    let mut overrides = OverrideBuilder::new("/");
    for glob in &config.exclude_globs {
        overrides
            .add(&format!("!{glob}"))
            .map_err(|err| AppError::msg(format!("invalid glob '{glob}': {err}")))?;
    }
    let overrides = overrides
        .build()
        .map_err(|err| AppError::msg(format!("error building exclusions: {err}")))?;
    builder.overrides(overrides);

    let mut files: Vec<WalkedFile> = Vec::new();
    let mut entries: u64 = 0;
    let mut skipped_non_utf8: u64 = 0;
    // Directories seen so far, by physical identity. An alias inside a selected root (a bind mount,
    // or a directory symlink while following links) is only visible here, and it aborts the scan —
    // see `roots::DirAliasGuard`. Bounded by the number of directories, which is small next to the
    // file vector this walk already holds.
    let mut dirs = super::roots::DirAliasGuard::default();
    for result in builder.build() {
        if entries % 1024 == 0 {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            on_progress(
                entries,
                files.len() as u64,
                files.last().map(|file| file.path.as_path()),
            );
        }
        entries += 1;

        let entry = match result {
            // Test-only: reach the outcome of the `Err` arm below for a nominated path, without a
            // filesystem that has to misbehave. Absent from every non-test build.
            #[cfg(test)]
            Ok(ref entry) if crate::testfixtures::take_walk_fault(entry.path()) => continue,
            Ok(entry) => entry,
            Err(_) => continue, // no access / broken link — skip
        };
        match entry.file_type() {
            Some(file_type) if file_type.is_file() => {}
            // A directory: the only place an alias inside a root can be caught. Its metadata is the
            // one extra `stat` this guard costs, and only for directories.
            //
            // A failure here is fatal. It costs no file — the walker could still descend — but it
            // is the guard losing its evidence: without `(device, inode)` this directory is no
            // longer known NOT to be a second pathname for a tree already walked, and a manifest
            // holding one file under two pathnames is not a result worth publishing. The scan
            // stops for the same reason `DirAliasGuard::note` stops it.
            Some(file_type) if file_type.is_dir() => {
                // Test-only: reach the failure outcome below for a nominated directory, without a
                // filesystem that has to misbehave. Absent from every non-test build.
                #[cfg(test)]
                if crate::testfixtures::take_metadata_fault(entry.path()) {
                    return Err(unverifiable_directory(entry.path(), None));
                }
                let meta = entry
                    .metadata()
                    .map_err(|err| unverifiable_directory(entry.path(), Some(&err)))?;
                dirs.note(entry.path(), meta.dev(), meta.ino())?;
                continue;
            }
            _ => continue,
        }
        let meta = match entry.metadata() {
            // Test-only counterpart for the metadata error below, same reasoning.
            #[cfg(test)]
            Ok(_) if crate::testfixtures::take_metadata_fault(entry.path()) => continue,
            Ok(meta) => meta,
            Err(_) => continue,
        };

        let size = meta.size();
        if size < config.min_size {
            continue;
        }
        if let Some(max) = config.max_size {
            if size > max {
                continue;
            }
        }

        if !config.include_extensions.is_empty() {
            let ext = entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.to_ascii_lowercase());
            match ext {
                Some(ext) if config.include_extensions.contains(&ext) => {}
                _ => continue,
            }
        }

        // Non-UTF8 guard: skip files whose path cannot be represented
        // as UTF-8 (see the function doc comment). Count it last — after all the
        // other filters, so the counter means "would have made it into the manifest, but the name cannot
        // be saved without loss", not files filtered out by size/extension.
        if entry.path().to_str().is_none() {
            skipped_non_utf8 += 1;
            continue;
        }

        files.push(WalkedFile {
            path: entry.into_path(),
            size,
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            device: meta.dev(),
            inode: meta.ino(),
            nlink: meta.nlink(),
        });
    }

    on_progress(
        entries,
        files.len() as u64,
        files.last().map(|file| file.path.as_path()),
    );
    Ok((files, skipped_non_utf8))
}

/// A directory whose physical identity could not be read.
///
/// Names the directory and says what was lost, carrying the underlying error as context rather
/// than inspecting or re-parsing its text. Deliberately not an omission: no file went missing, and
/// calling it one would put a count on something that never happened.
fn unverifiable_directory(path: &Path, cause: Option<&ignore::Error>) -> AppError {
    let context = match cause {
        Some(err) => format!(" ({err})"),
        None => String::new(),
    };
    AppError::msg(format!(
        "scan aborted: cannot read the physical identity of directory {}{context} — without its \
         device and inode the same-directory guard cannot tell whether this tree has already been \
         walked under another pathname, and one tree counted twice is not a result worth \
         publishing. Fix access to the directory or exclude it, then rescan.",
        crate::textsan::terminal(&path.display().to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testfixtures::{WalkFault, WalkFaults};
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_walk_{tag}_{}_{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The walk-time half of the root guard: a directory symlink pointing at a sibling directory
    /// makes one tree visible under two pathnames as soon as links are followed. No privileges
    /// needed, so the bind-mount E2E is not the only coverage of this branch.
    #[test]
    fn a_followed_directory_alias_aborts_the_walk() {
        let root = temp_dir("dir_alias");
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("f.bin"), b"data").unwrap();
        std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();

        let mut config = ScanConfig::new(vec![root.clone()]);
        config.min_size = 0;
        config.exclude_globs.clear();
        config.follow_symlinks = true;

        let cancel = AtomicBool::new(false);
        // Not `expect_err`: that needs `Debug` on the success type, and `WalkedFile` has none.
        let text = match walk(&config, &cancel, |_, _, _| {}) {
            Err(err) => err.to_string(),
            Ok((files, _)) => panic!("the alias must abort the walk, got {} files", files.len()),
        };
        assert!(
            text.contains("same directory"),
            "the class must be named: {text}"
        );
        assert!(
            text.contains("alias") && text.contains("real"),
            "both pathnames must be named: {text}"
        );

        // Control: without following links the symlink is not a directory, and the same tree walks
        // exactly as it did before this guard existed.
        config.follow_symlinks = false;
        let (files, skipped) =
            walk(&config, &cancel, |_, _, _| {}).expect("no alias when links are not followed");
        assert_eq!(files.len(), 1, "exactly the one real file");
        assert_eq!(skipped, 0);

        fs::remove_dir_all(&root).ok();
    }

    /// A directory holding one child, plus a file beside it. `sub` is the directory whose metadata
    /// the fault removes; `sub/inner.bin` is what shows whether the walk descended into it anyway.
    fn guard_tree(tag: &str) -> (PathBuf, PathBuf) {
        let root = temp_dir(tag);
        fs::write(root.join("keep.bin"), b"beside").unwrap();
        let sub = root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("inner.bin"), b"inside").unwrap();
        (root, sub)
    }

    fn guard_config(root: &Path) -> ScanConfig {
        let mut config = ScanConfig::new(vec![root.to_path_buf()]);
        config.min_size = 0; // don't filter the small fixtures out by size
        config.exclude_globs.clear(); // no default exclusions — determinism
        config
    }

    /// Manifest pathnames relative to `root`, in the order the walk produced them.
    fn walked_names(files: &[WalkedFile], root: &Path) -> Vec<String> {
        files
            .iter()
            .map(|file| {
                file.path
                    .strip_prefix(root)
                    .expect("under the root")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// A directory whose physical identity cannot be read stops the scan.
    ///
    /// It costs no file — the walker could descend perfectly well — but `DirAliasGuard` has lost
    /// the one piece of evidence that tells a real directory from a second pathname for a tree
    /// already walked. Before this, the failure was swallowed by `if let Ok(meta)` and the walk
    /// carried on into the child with a blind guard.
    #[test]
    fn a_directory_whose_metadata_fails_aborts_the_walk() {
        let (root, sub) = guard_tree("dirmeta");
        let faults = WalkFaults::arm(&[(sub.clone(), WalkFault::Metadata)]);
        let cancel = AtomicBool::new(false);

        let text = match walk(&guard_config(&root), &cancel, |_, _, _| {}) {
            Err(err) => err.to_string(),
            Ok((files, _)) => panic!(
                "a directory whose identity cannot be read must abort the walk, got {} files",
                files.len()
            ),
        };

        assert_eq!(
            faults.fired(),
            vec![(sub.clone(), WalkFault::Metadata)],
            "the fault must fire exactly once, at the directory branch"
        );
        assert!(
            faults.pending().is_empty(),
            "nothing may stay armed: an unfired fault would mean the branch never looked"
        );
        assert!(
            text.contains(&sub.display().to_string()),
            "the directory must be named: {text}"
        );
        assert!(
            text.contains("physical identity"),
            "and what was lost must be plain: {text}"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// Positive control: the identical tree with nothing armed walks exactly as before — same
    /// manifest, same order. Without this the test above could be passing because the tree itself
    /// is unwalkable.
    #[test]
    fn without_injection_the_same_tree_walks_unchanged() {
        let (root, _) = guard_tree("dirmeta_control");
        let cancel = AtomicBool::new(false);

        let (files, skipped) =
            walk(&guard_config(&root), &cancel, |_, _, _| {}).expect("no fault, no abort");
        assert_eq!(
            walked_names(&files, &root),
            vec!["keep.bin".to_string(), "sub/inner.bin".to_string()],
            "both files, in traversal order"
        );
        assert_eq!(skipped, 0);

        fs::remove_dir_all(&root).ok();
    }

    /// The regular-file branch is untouched: an injected metadata fault on a known regular file
    /// still fires once and still only removes that file. Turning THAT into an abort is R3B-B's
    /// business — it becomes a typed `metadata_error` event, not a stopped scan.
    #[test]
    fn a_regular_file_metadata_fault_still_only_skips_that_file() {
        let (root, sub) = guard_tree("filemeta");
        let victim = sub.join("inner.bin");
        let faults = WalkFaults::arm(&[(victim.clone(), WalkFault::Metadata)]);
        let cancel = AtomicBool::new(false);

        let (files, skipped) = walk(&guard_config(&root), &cancel, |_, _, _| {})
            .expect("a file's metadata failure must not abort the walk");

        assert_eq!(
            faults.fired(),
            vec![(victim, WalkFault::Metadata)],
            "the fault fired once, at the file branch"
        );
        assert!(faults.pending().is_empty());
        assert_eq!(
            walked_names(&files, &root),
            vec!["keep.bin".to_string()],
            "only the nominated file is gone"
        );
        assert_eq!(
            skipped, 0,
            "and the non-UTF8 compatibility counter is unaffected"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// Non-UTF8 guard: a file with a non-UTF8 name is skipped and counted,
    /// a valid one makes it into the manifest.
    #[test]
    fn skips_and_counts_non_utf8_paths() {
        let root = temp_dir("nonutf8");

        let good = root.join("ok.bin");
        fs::write(&good, b"data").unwrap();

        // A name with byte 0xFF — valid UTF-8 cannot be made from it.
        let bad = root.join(OsStr::from_bytes(b"bad\xffname.bin"));
        fs::write(&bad, b"data").unwrap();
        assert!(
            bad.exists(),
            "the FS did not accept the non-UTF8 name — test not applicable"
        );

        let mut config = ScanConfig::new(vec![root.clone()]);
        config.min_size = 0; // don't filter out by size
        config.exclude_globs.clear(); // no default exclusions — determinism

        let cancel = AtomicBool::new(false);
        let (files, skipped) = walk(&config, &cancel, |_, _, _| {}).unwrap();

        assert_eq!(skipped, 1, "exactly one non-UTF8 file must be skipped");
        assert_eq!(
            files.len(),
            1,
            "the valid file must make it into the manifest"
        );
        assert_eq!(
            files[0].path, good,
            "the manifest holds exactly the valid file"
        );

        fs::remove_dir_all(&root).ok();
    }
}
