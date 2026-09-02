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
///
/// The suffix is appended to the name's raw bytes, never to a `String`. A Unix filename is
/// arbitrary non-NUL bytes, and going through `to_string_lossy` would corrupt the survivor two
/// ways at once: it renames the file, so `b"\x80.bin"` would land as `"\u{FFFD}.bin.1"` — bytes
/// the operator never chose, with no way back to the original from the name alone — and it
/// collapses distinct names onto one, so `b"\x80.bin"` and `b"\xff.bin"` colliding in the same
/// directory would queue up as `.1` and `.2` of a name neither of them ever had.
pub(crate) fn suffixed(base: &Path, n: u32) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    if n == 0 {
        return base.to_path_buf();
    }
    match base.file_name() {
        Some(name) => {
            let name = name.as_bytes();
            let suffix = format!(".{n}");
            let mut out = Vec::with_capacity(name.len() + suffix.len());
            out.extend_from_slice(name);
            out.extend_from_slice(suffix.as_bytes());
            base.with_file_name(OsString::from_vec(out))
        }
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
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // The name's own bytes, like everywhere else: this one is a temporary, but the cleanup
    // after a failed build is best-effort, and a leftover has to stay greppable back to the
    // file it was staged for.
    let base: &[u8] = name.map(OsStr::as_bytes).unwrap_or(b"item");
    let prefix = format!(".dedcom-tmp-{}-{nanos}-{seq}-", std::process::id());
    let mut out = Vec::with_capacity(prefix.len() + base.len());
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(base);
    parent.join(OsString::from_vec(out))
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

    /// A collision suffix is appended to the name's own bytes. Composed through
    /// `to_string_lossy` the candidate came back with U+FFFD in place of every byte the decoder
    /// refused, so the moved file landed under a name the operator never chose — and one nothing
    /// can read back to the original.
    #[test]
    fn suffixed_preserves_non_utf8_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let base = PathBuf::from(OsStr::from_bytes(b"/somewhere/\x80.bin"));
        // `n == 0` is the common path and stays byte-exact by construction.
        assert_eq!(suffixed(&base, 0), base);
        assert_eq!(
            suffixed(&base, 1),
            PathBuf::from(OsStr::from_bytes(b"/somewhere/\x80.bin.1"))
        );
        assert_eq!(
            suffixed(&base, 12),
            PathBuf::from(OsStr::from_bytes(b"/somewhere/\x80.bin.12"))
        );

        // An invalid byte in the extension survives just as literally.
        let base = PathBuf::from(OsStr::from_bytes(b"/somewhere/photo.\xff"));
        assert_eq!(
            suffixed(&base, 1),
            PathBuf::from(OsStr::from_bytes(b"/somewhere/photo.\xff.1"))
        );
    }

    /// The suffix is only ever reached through `EEXIST`, so the guarantee has to hold across a
    /// real `renameat2` — an occupied destination (a dangling symlink `exists()` reported as
    /// absent, or a lost race) sends the move to `dest.1`, and those must be the operator's bytes.
    #[test]
    fn collision_suffix_keeps_non_utf8_name() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let root = temp_dir("coll_bytes");
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&dst_dir).unwrap();
        let name = OsStr::from_bytes(b"\x80.bin");
        let src = src_dir.join(name);
        write_file(&src, b"new");
        write_file(&dst_dir.join(name), b"old");

        let final_dest = move_into_dir(&src, &dst_dir).unwrap();
        assert_eq!(final_dest, dst_dir.join(OsStr::from_bytes(b"\x80.bin.1")));
        assert_eq!(fs::read(dst_dir.join(name)).unwrap(), b"old"); // neighbor intact
        assert_eq!(fs::read(&final_dest).unwrap(), b"new");
        assert!(!src.exists());

        fs::remove_dir_all(&root).ok();
    }

    /// Two names that differ only outside UTF-8 keep their own slots. Lossy composition mapped
    /// `\x80` and `\xff` alike onto U+FFFD, so the second survivor queued up as `.2` of the first
    /// one's name: two unrelated files sharing a name neither of them ever had.
    #[test]
    fn distinct_non_utf8_collisions_do_not_collapse() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let root = temp_dir("coll_collapse");
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&dst_dir).unwrap();
        let first = OsStr::from_bytes(b"\x80.bin");
        let second = OsStr::from_bytes(b"\xff.bin");
        // The premise, stated before it is relied on: to the lossy decoder these two names ARE
        // one string. Without that the assertions below would hold on the old code too.
        assert_eq!(
            first.to_string_lossy(),
            second.to_string_lossy(),
            "both names decode to a single lossy string — that is the collapse being ruled out"
        );
        for name in [first, second] {
            write_file(&src_dir.join(name), b"new");
            write_file(&dst_dir.join(name), b"old");
        }

        let moved_first = move_into_dir(&src_dir.join(first), &dst_dir).unwrap();
        let moved_second = move_into_dir(&src_dir.join(second), &dst_dir).unwrap();

        // Each one takes the `.1` of its OWN name, not `.1` and `.2` of an invented one.
        assert_eq!(moved_first, dst_dir.join(OsStr::from_bytes(b"\x80.bin.1")));
        assert_eq!(moved_second, dst_dir.join(OsStr::from_bytes(b"\xff.bin.1")));
        assert_ne!(
            moved_first, moved_second,
            "distinct names do not share a slot"
        );
        assert!(moved_first.is_file() && moved_second.is_file());

        fs::remove_dir_all(&root).ok();
    }

    /// The evacuation temp carries the original's bytes as well. It is a generated name that
    /// never becomes anyone's final resting place — publication renames it onto the caller's
    /// `target`, and every failure arm unlinks it — but that unlink is best-effort, so a leftover
    /// has to name the file it was staged for.
    #[test]
    fn staging_path_preserves_non_utf8_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = staging_path(Path::new("/tank"), Some(OsStr::from_bytes(b"\x80.bin")));
        let name = path.file_name().unwrap().as_bytes();
        assert!(
            name.starts_with(b".dedcom-tmp-"),
            "hidden staging prefix kept: {}",
            path.display()
        );
        assert!(
            name.ends_with(b"\x80.bin"),
            "original bytes kept: {}",
            path.display()
        );

        // No name at all still yields the neutral placeholder.
        let path = staging_path(Path::new("/tank"), None);
        assert!(path.file_name().unwrap().as_bytes().ends_with(b"-item"));
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
