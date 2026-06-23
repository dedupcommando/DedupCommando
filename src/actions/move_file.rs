// SPDX-License-Identifier: Apache-2.0
//! Moving a single file (manual layout v1). Same dataset — an atomic
//! `rename` without overwrite (O(1)). Different dataset (EXDEV) — REFUSAL:
//! copying would lose the owner/ACL/xattr and would inflate sparse images
//! into dense ones; instead a clear error + a ready-made `rsync` command.
//! Snapshot/journal/Undo are the caller's concern (the module is pure FS, without ZFS).

use std::fs;
use std::path::{Path, PathBuf};

use crate::actions::script_preview::sh_quote;
use crate::error::{AppError, Result};

/// Moves file `src` ONTO path `dest`, uniquifying on a name collision
/// (`dest`, then `dest.1`, `dest.2`, …) ATOMICALLY, without overwriting a neighbor.
/// Returns the final path.
pub fn move_to(src: &Path, dest: &Path) -> Result<PathBuf> {
    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        return Err(AppError::msg("source is a symbolic link, skipping"));
    }
    if !meta.is_file() {
        return Err(AppError::msg("only a file can be moved (v1)"));
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
    // Moving into the same directory under the same name is a no-op, we reject it.
    if src.parent() == Some(parent) && dest.file_name() == src.file_name() {
        return Err(AppError::msg("source is already in this directory"));
    }

    // Atomic no-clobber: we try dest, dest.1, dest.2, … — the name is claimed BY US
    // at the kernel level (renameat2 RENAME_NOREPLACE), without a TOCTOU race or overwrite.
    let mut n = 0u32;
    loop {
        let candidate = suffixed(dest, n);
        match rename_noreplace(src, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.raw_os_error() == Some(libc::EEXIST) => n += 1,
            // Cross-dataset (EXDEV): rename is impossible. REFUSAL —
            // copying would lose metadata and inflate sparse; see cross_device_error.
            Err(err) if is_cross_device(&err) => return Err(cross_device_error(src, dest, false)),
            Err(err) => return Err(err.into()),
        }
    }
}

/// Candidate name with a collision suffix: `n == 0` → `base`, otherwise `base.N`.
pub(crate) fn suffixed(base: &Path, n: u32) -> PathBuf {
    if n == 0 {
        return base.to_path_buf();
    }
    match base.file_name() {
        Some(name) => base.with_file_name(format!("{}.{n}", name.to_string_lossy())),
        None => base.to_path_buf(),
    }
}

/// Atomic `rename` without overwrite (Linux `renameat2` + `RENAME_NOREPLACE`):
/// if `dest` exists — `EEXIST`, the target is not overwritten. The check and the move are
/// a single kernel operation, the TOCTOU race is eliminated.
pub(crate) fn rename_noreplace(src: &Path, dest: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    // RENAME_NOREPLACE = 1 — stable in the Linux ABI (not exposed as a const in all libc versions).
    const RENAME_NOREPLACE: libc::c_uint = 1;
    let src_c = CString::new(src.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let dest_c = CString::new(dest.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dest_c.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Unique temporary name in directory `parent` (hidden prefix + pid + time +
/// counter): for atomic publication — evacuation of the original during hardlink/reflink
/// (`actions/mod.rs`).
pub(crate) fn staging_path(parent: &Path, name: Option<&std::ffi::OsStr>) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = name
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "item".to_string());
    parent.join(format!(
        ".dedcom-tmp-{}-{nanos}-{seq}-{base}",
        std::process::id()
    ))
}

/// Moves file `src` INTO directory `dir`, preserving the name.
pub fn move_into_dir(src: &Path, dir: &Path) -> Result<PathBuf> {
    let name = src
        .file_name()
        .ok_or_else(|| AppError::msg("source has no file name"))?;
    move_to(src, &dir.join(name))
}

/// `true` if the `rename` error means cross-device (EXDEV = raw os error
/// 18 on Linux; the crate builds only for Linux).
pub(crate) fn is_cross_device(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(18)
}

/// Refusal of a cross-dataset move: source and destination
/// are on different filesystems, so `rename` is impossible. By copying we would lose the
/// owner/permissions/ACL/xattr, inflate sparse images into dense ones and (for a directory)
/// break hardlinks — a space explosion and destruction of deduplication. Instead of silent
/// corruption — a clear error with a ready-made move command using a proven tool
/// (`rsync`, which preserves all of this). `is_dir` controls the slashes and `rm -rf`/`rm -f`.
pub(crate) fn cross_device_error(src: &Path, dest: &Path, is_dir: bool) -> AppError {
    let s = sh_quote(&src.to_string_lossy());
    let d = sh_quote(&dest.to_string_lossy());
    let cmd = if is_dir {
        format!("rsync -aHAX --sparse {s}/ {d}/ && rm -rf {s}")
    } else {
        format!("rsync -aHAX --sparse {s} {d} && rm -f {s}")
    };
    AppError::msg(format!(
        "source and destination are on different filesystems (ZFS datasets): {} -> {}; \
         moving by copying would lose the owner/permissions/ACL/xattr, would inflate \
         sparse images and would break hardlinks. Move within a single \
         dataset or do it manually:  {cmd}",
        src.display(),
        dest.display()
    ))
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
        dir.push(format!("dedcom_move_{tag}_{}_{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, content: &[u8]) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(content).unwrap();
    }

    #[test]
    fn moves_file_into_other_dir() {
        let root = temp_dir("into");
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&dst_dir).unwrap();
        let src = src_dir.join("a.txt");
        write_file(&src, b"hello");

        let final_dest = move_into_dir(&src, &dst_dir).unwrap();
        assert_eq!(final_dest, dst_dir.join("a.txt"));
        assert!(!src.exists());
        assert_eq!(fs::read(&final_dest).unwrap(), b"hello");

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_move_into_same_dir() {
        let root = temp_dir("same");
        let src = root.join("a.txt");
        write_file(&src, b"x");
        assert!(move_into_dir(&src, &root).is_err());
        assert!(src.exists());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn collision_appends_suffix() {
        let root = temp_dir("coll");
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&dst_dir).unwrap();
        let src = src_dir.join("a.txt");
        write_file(&src, b"new");
        write_file(&dst_dir.join("a.txt"), b"old");

        let final_dest = move_into_dir(&src, &dst_dir).unwrap();
        assert_eq!(final_dest, dst_dir.join("a.txt.1"));
        assert_eq!(fs::read(dst_dir.join("a.txt")).unwrap(), b"old"); // original intact
        assert_eq!(fs::read(&final_dest).unwrap(), b"new");
        assert!(!src.exists());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_directory() {
        let root = temp_dir("dir");
        let src = root.join("sub");
        fs::create_dir_all(&src).unwrap();
        let dst = root.join("dst");
        fs::create_dir_all(&dst).unwrap();
        assert!(move_into_dir(&src, &dst).is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_symlink() {
        let root = temp_dir("link");
        let target = root.join("real.txt");
        write_file(&target, b"r");
        let link = root.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let dst = root.join("dst");
        fs::create_dir_all(&dst).unwrap();
        assert!(move_to(&link, &dst.join("link.txt")).is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn is_cross_device_detects_exdev() {
        assert!(is_cross_device(&std::io::Error::from_raw_os_error(18)));
        assert!(!is_cross_device(&std::io::Error::from_raw_os_error(2)));
    }

    /// Cross-dataset refusal: the message carries a ready-made rsync command;
    /// for a file — `rm -f`, paths escaped.
    #[test]
    fn cross_device_error_file_suggests_rsync() {
        let err = cross_device_error(Path::new("/a/x.bin"), Path::new("/b/x.bin"), false);
        let msg = err.to_string();
        assert!(
            msg.contains("rsync -aHAX --sparse"),
            "rsync command present: {msg}"
        );
        assert!(
            msg.contains("rm -f") && !msg.contains("rm -rf"),
            "for a file — rm -f: {msg}"
        );
        assert!(
            msg.contains("'/a/x.bin'") && msg.contains("'/b/x.bin'"),
            "paths escaped and present: {msg}"
        );
    }
}
