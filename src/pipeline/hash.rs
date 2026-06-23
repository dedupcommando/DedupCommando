// SPDX-License-Identifier: Apache-2.0
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::safe_open::open_regular_nofollow;
use crate::model::action::FileIdentity;

const BUFFER_SIZE: usize = 256 * 1024;

/// Computes the blake3 hash over the entire file contents (by path, without fd identity guarantees).
/// `progress` is incremented by the number of bytes read — for live progress.
/// Used outside the scan phase (the move path), where the file has just been obtained
/// under the caller's control; on the scan path use `hash_file_verified`.
/// Opening via `open_regular_nofollow` (`O_NOFOLLOW|O_NONBLOCK` +
/// `S_ISREG` check) — does not follow a symlink and does not hang on a FIFO/device.
pub fn hash_file(path: &Path, progress: &AtomicU64) -> io::Result<[u8; 32]> {
    let mut file = open_regular_nofollow(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        progress.fetch_add(read as u64, Ordering::Relaxed);
    }

    Ok(*hasher.finalize().as_bytes())
}

/// Fd-verified hashing on the scan path. Opens the file via
/// `open_regular_nofollow` (`O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` — symlink → rejected right at
/// open, FIFO/device don't hang, non-regular is rejected via `fstat`), takes the
/// identity BY DESCRIPTOR before and after reading (the full identity must not change — catches
/// an in-place edit within the same second of the same length via `mtime_nsec`/`ctime`), and checks
/// that the path still resolves to the same `dev/inode` (path swap via `unlink`+`create`).
/// Returns (hash, identity by descriptor AFTER reading) — trusts no walk metadata whatsoever.
pub fn hash_file_verified(
    path: &Path,
    progress: &AtomicU64,
) -> io::Result<([u8; 32], FileIdentity)> {
    hash_file_verified_hooked(path, progress, || {})
}

/// Implementation of `hash_file_verified` with a deterministic test seam `after_before_snapshot`,
/// called AFTER the `before`-identity snapshot and BEFORE the read/final snapshot. In production the seam is a
/// no-op (`|| {}`, inlined to nothing); in tests an edit/swap of the file during
/// hashing is slipped in there, to verify rejection end-to-end (through the function itself), not
/// just the `identity_stable`/`path_object_matches` predicates.
fn hash_file_verified_hooked(
    path: &Path,
    progress: &AtomicU64,
    after_before_snapshot: impl FnOnce(),
) -> io::Result<([u8; 32], FileIdentity)> {
    let file = open_regular_nofollow(path)?;
    let before = FileIdentity::from_metadata(&file.metadata()?);

    after_before_snapshot();

    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut reader = &file;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        progress.fetch_add(read as u64, Ordering::Relaxed);
    }

    let after = FileIdentity::from_metadata(&file.metadata()?);
    identity_stable(&before, &after)?;
    path_object_matches(path, before.dev, before.ino)?;
    Ok((*hasher.finalize().as_bytes(), after))
}

/// The full identity by descriptor did not change during the read (an in-place edit
/// is caught via `mtime_nsec`/`ctime`, even within the same second of the same length).
fn identity_stable(before: &FileIdentity, after: &FileIdentity) -> io::Result<()> {
    if before == after {
        Ok(())
    } else {
        Err(io::Error::other("file changed during hashing"))
    }
}

/// The path still points at the same object (`dev/inode`) that was hashed — otherwise it was
/// swapped (`unlink`+`create` at the same path). `lstat` without resolving the symlink.
fn path_object_matches(path: &Path, dev: u64, ino: u64) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.dev() == dev && meta.ino() == ino {
        Ok(())
    } else {
        Err(io::Error::other("path swapped during hashing"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_hash_{tag}_{}_{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn verified_hashes_regular_file() {
        let dir = temp_dir("ok");
        let p = dir.join("a.bin");
        fs::write(&p, b"hello").unwrap();
        let (h, id) = hash_file_verified(&p, &AtomicU64::new(0)).unwrap();
        assert_eq!(h, *blake3::hash(b"hello").as_bytes());
        assert_eq!(id.size, 5);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn symlink_is_rejected() {
        // O_NOFOLLOW → open of a symlink fails (ELOOP), the hash is not computed.
        let dir = temp_dir("sym");
        let target = dir.join("real.bin");
        fs::write(&target, b"data").unwrap();
        let link = dir.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(hash_file_verified(&link, &AtomicU64::new(0)).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn non_regular_is_rejected() {
        // A directory is not a regular file: open succeeds, but the fstat type rejects it.
        let dir = temp_dir("nonreg");
        assert!(hash_file_verified(&dir, &AtomicU64::new(0)).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mutation_during_hashing_is_rejected() {
        // An in-place edit (identity before≠after) is rejected — testing the
        // stability predicate (unit). The end-to-end variant is `verified_rejects_inplace_mutation_via_hook`.
        let a = FileIdentity {
            size: 10,
            mtime_sec: 1,
            mtime_nsec: 0,
            ..Default::default()
        };
        let b = FileIdentity { mtime_nsec: 5, ..a };
        assert!(identity_stable(&a, &a).is_ok());
        assert!(identity_stable(&a, &b).is_err());
    }

    #[test]
    fn path_replacement_during_hashing_is_rejected() {
        // The path is swapped to a different inode → rejected. We keep the descriptor open,
        // as hash_file_verified does during the read: while the fd is open, the old inode is NOT
        // freed, so the path swap takes a DIFFERENT inode (without a held inode it would be
        // reused, and the (dev,ino) check would falsely pass). Predicate (unit);
        // end-to-end — `verified_rejects_path_replacement_via_hook`.
        let dir = temp_dir("repl");
        let p = dir.join("f.bin");
        fs::write(&p, b"one").unwrap();
        let held = std::fs::File::open(&p).unwrap();
        let meta = held.metadata().unwrap();
        let (dev, ino) = (meta.dev(), meta.ino());
        assert!(path_object_matches(&p, dev, ino).is_ok());
        fs::remove_file(&p).unwrap();
        fs::write(&p, b"two different").unwrap();
        assert!(path_object_matches(&p, dev, ino).is_err());
        drop(held);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verified_rejects_inplace_mutation_via_hook() {
        // A1 end-to-end: an in-place edit DURING hashing (same inode,
        // without unlink) changes size/mtime → `before` ≠ `after` → `hash_file_verified` returns
        // Err. Run through the real function (test-hook), not just the predicate.
        let dir = temp_dir("mut_hook");
        let p = dir.join("f.bin");
        fs::write(&p, b"original").unwrap();
        let p2 = p.clone();
        let res = hash_file_verified_hooked(&p, &AtomicU64::new(0), move || {
            use std::io::Write;
            // Same inode (without unlink): overwrite with larger content → size+mtime change.
            let mut f = fs::OpenOptions::new().write(true).open(&p2).unwrap();
            f.write_all(b"original + extra mutated bytes").unwrap();
        });
        assert!(res.is_err(), "an edit during hashing must be rejected");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verified_rejects_path_replacement_via_hook() {
        // A1 end-to-end: path swap (unlink+create) DURING hashing.
        // The held fd holds the old inode, the path resolves to a new one → rejection
        // (`path_object_matches` by inode, or `identity_stable` by ctime from the unlink).
        let dir = temp_dir("repl_hook");
        let p = dir.join("f.bin");
        fs::write(&p, b"one").unwrap();
        let p2 = p.clone();
        let res = hash_file_verified_hooked(&p, &AtomicU64::new(0), move || {
            fs::remove_file(&p2).unwrap();
            fs::write(&p2, b"two different bytes").unwrap();
        });
        assert!(res.is_err(), "a path swap during hashing must be rejected");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verified_rejects_fifo_without_blocking() {
        // A1 () end-to-end: a FIFO with no writer does NOT hang the worker — `open_regular_nofollow`
        // (`O_NONBLOCK`) returns immediately, `fstat` rejects the non-regular file. Without
        // O_NONBLOCK `open(O_RDONLY)` would hang forever (Esc dead, thread unkillable).
        use std::os::unix::ffi::OsStrExt;
        let dir = temp_dir("fifo");
        let fifo = dir.join("pipe");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: cpath is a valid C-string of an existing path; mode 0o600.
        let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo did not create the FIFO");
        assert!(hash_file_verified(&fifo, &AtomicU64::new(0)).is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
