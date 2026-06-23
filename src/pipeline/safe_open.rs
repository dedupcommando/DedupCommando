// SPDX-License-Identifier: Apache-2.0
//! Safe opening of regular files on the read path (hashing, byte-for-byte comparison).
//!
//! A bare `File::open` on the scan worker is dangerous under root:
//! - it follows symlinks — `follow_symlinks=false` only covers the walk traversal, not the
//!   actual open during the hashing phase (walk→hash race: `unlink F; ln -s /etc/secret F`);
//! - it **blocks forever** on a FIFO with no writer (`open(O_RDONLY)` waits for an open for writing);
//!   the pipeline's cancel is only checked at the chunk boundary, so Esc is dead and the thread
//!   is unkillable without SIGKILL.
//!
//! `open_regular_nofollow` opens with `O_NOFOLLOW` (symlink → `ELOOP`) and `O_NONBLOCK`
//! (FIFO/device return an fd immediately, don't hang), then via `fstat` on the ALREADY-open
//! descriptor rejects everything but a regular file. The check is by fd, not by path,
//! so a path swap after `open` won't fool it. For a regular file Linux ignores `O_NONBLOCK`
//! on the subsequent `read` — the read proceeds as usual.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Opens a regular file for reading, without following a symlink and without hanging on a FIFO/device.
///
/// Errors (instead of hanging/following the link) if `path` is a symlink (`ELOOP`), FIFO,
/// socket, or device. The returned `File` is guaranteed to point at a regular file.
pub(crate) fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "not a regular file (FIFO/device/socket) — skipping",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "dedcom_safeopen_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn opens_regular_file() {
        let root = temp_dir("reg");
        let path = root.join("a.bin");
        File::create(&path).unwrap().write_all(b"data").unwrap();

        let mut file = open_regular_nofollow(&path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"data");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_symlink() {
        let root = temp_dir("link");
        let target = root.join("real.bin");
        File::create(&target).unwrap().write_all(b"r").unwrap();
        let link = root.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // O_NOFOLLOW → ELOOP: we don't follow the symbolic link.
        assert!(open_regular_nofollow(&link).is_err());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_fifo_without_blocking() {
        let root = temp_dir("fifo");
        let fifo = root.join("pipe");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: cpath is a valid C-string from an existing path; mode 0o600.
        let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo did not create the FIFO");

        // Without a writer a bare File::open(O_RDONLY) would hang forever; O_NONBLOCK
        // returns the fd immediately, and the S_ISREG check rejects the FIFO.
        let err = open_regular_nofollow(&fifo).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);

        std::fs::remove_dir_all(&root).ok();
    }
}
