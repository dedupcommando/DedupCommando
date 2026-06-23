// SPDX-License-Identifier: Apache-2.0
//! Moving a whole directory (folder layout). Same dataset —
//! an atomic `rename` (O(1)). Different dataset (EXDEV) — REFUSAL:
//! copying would lose the owner/ACL/xattr, would inflate sparse images and would break
//! hardlinks (a space explosion, destruction of deduplication); instead we emit a clear
//! error with a ready-made `rsync` command. Pure FS (without ZFS), called from the background
//! move worker; snapshot/journal/Undo are the caller's concern.

use std::fs;
use std::path::{Path, PathBuf};

use crate::actions::move_file::{cross_device_error, is_cross_device, rename_noreplace, suffixed};
use crate::error::{AppError, Result};

/// Moves directory `src` ONTO path `dest`, uniquifying on a name collision
/// ATOMICALLY (without overwrite). Same dataset — `renameat2` without replacement; different —
/// atomic directory creation + recursive copy + deletion of the source.
pub fn move_dir_to(src: &Path, dest: &Path) -> Result<PathBuf> {
    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(AppError::msg("source is not a directory (or a symlink)"));
    }
    let parent = dest
        .parent()
        .ok_or_else(|| AppError::msg("destination has no parent directory"))?;
    if !parent.is_dir() {
        return Err(AppError::msg(format!(
            "destination directory does not exist: {}",
            parent.display()
        )));
    }
    if src.parent() == Some(parent) && dest.file_name() == src.file_name() {
        return Err(AppError::msg("directory is already in this destination"));
    }
    // Forbid moving a directory into itself (otherwise infinite recursion).
    if dest.starts_with(src) {
        return Err(AppError::msg("cannot move a directory into itself"));
    }

    // Atomic no-clobber for a directory: dest, dest.1, … without overwriting a neighbor.
    let mut n = 0u32;
    loop {
        let candidate = suffixed(dest, n);
        if candidate.starts_with(src) {
            n += 1;
            continue;
        }
        match rename_noreplace(src, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.raw_os_error() == Some(libc::EEXIST) => n += 1,
            // Cross-dataset (EXDEV): rename is impossible. REFUSAL —
            // copying the tree would lose metadata, would inflate sparse and would break
            // hardlinks; see cross_device_error.
            Err(err) if is_cross_device(&err) => return Err(cross_device_error(src, dest, true)),
            Err(err) => return Err(err.into()),
        }
    }
}

/// Moves directory `src` INTO directory `dir`, preserving the name.
pub fn move_dir_into(src: &Path, dir: &Path) -> Result<PathBuf> {
    let name = src
        .file_name()
        .ok_or_else(|| AppError::msg("directory has no name"))?;
    move_dir_to(src, &dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "dedcom_movedir_{tag}_{}_{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn moves_directory_with_contents() {
        let root = temp_dir("tree");
        let src = root.join("src");
        let dst = root.join("dst");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::create_dir_all(&dst).unwrap();
        let mut f = fs::File::create(src.join("sub").join("a.txt")).unwrap();
        f.write_all(b"hi").unwrap();

        let final_dest = move_dir_into(&src, &dst).unwrap();
        assert_eq!(final_dest, dst.join("src"));
        assert!(!src.exists());
        assert_eq!(
            fs::read(dst.join("src").join("sub").join("a.txt")).unwrap(),
            b"hi"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn collision_appends_suffix() {
        let root = temp_dir("coll");
        let src = root.join("src").join("data");
        let dst = root.join("dst");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(dst.join("data")).unwrap();

        let final_dest = move_dir_into(&src, &dst).unwrap();
        assert_eq!(final_dest, dst.join("data.1"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_into_itself() {
        let root = temp_dir("self");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        assert!(move_dir_to(&src, &src.join("inner")).is_err());
        fs::remove_dir_all(&root).ok();
    }

    /// Cross-dataset refusal: for a directory — `rm -rf`, an rsync command with
    /// trailing slashes (moves the directory's content).
    #[test]
    fn cross_device_error_dir_suggests_rsync() {
        let err = cross_device_error(Path::new("/a/d"), Path::new("/b/d"), true);
        let msg = err.to_string();
        assert!(
            msg.contains("rsync -aHAX --sparse"),
            "rsync command present: {msg}"
        );
        assert!(msg.contains("rm -rf"), "for a directory — rm -rf: {msg}");
        assert!(
            msg.contains("'/a/d'/ '/b/d'/"),
            "slashes for the directory's content: {msg}"
        );
    }
}
