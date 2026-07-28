// SPDX-License-Identifier: Apache-2.0
//! Carrying a replaced file's identity onto its replacement.
//!
//! A reflink replacement is a fresh inode: the clone gets the blocks of the keeper and the
//! identity of the process that made it — under root that is `root:root` with the umask's mode.
//! Publishing it as it comes silently changed the owner, mode, ACL and extended attributes of the
//! file being replaced. The original kept them, but only in quarantine, and `--purge-quarantine`
//! then takes them away for good.
//!
//! A hardlink replacement is deliberately NOT covered here: it IS the keeper's inode, so its
//! metadata is the keeper's by definition — writing the target's onto it would change the keeper
//! for every other path too.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::error::{AppError, Result};

/// Extended attributes as names and values.
type Xattrs = Vec<(OsString, Vec<u8>)>;

/// Owner, mode, timestamps and extended attributes of a file. POSIX ACLs travel as xattrs
/// (`system.posix_acl_access`), so they need no separate handling.
pub struct FileMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
    atime: libc::timespec,
    mtime: libc::timespec,
    xattrs: Vec<(OsString, Vec<u8>)>,
}

/// Reads what has to survive the replacement. Called while the original is still in place —
/// after it is evacuated to quarantine there is nothing left at that path to read.
pub fn read(path: &Path) -> Result<FileMetadata> {
    read_with(path, read_xattr_value)
}

/// `read_value` is the read of one enumerated attribute. Production hands it the libc one; the
/// tests hand in a failing and a forever-racing one, because an attribute that was listed and then
/// cannot be read has to fail the action — dropping it would put us back to losing metadata
/// quietly, only in a narrower spot.
fn read_with(
    path: &Path,
    read_value: impl Fn(&CStr, &CStr) -> Result<XattrValue>,
) -> Result<FileMetadata> {
    let meta = std::fs::symlink_metadata(path)?;
    Ok(FileMetadata {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
        atime: timespec(meta.atime(), meta.atime_nsec()),
        mtime: timespec(meta.mtime(), meta.mtime_nsec()),
        xattrs: read_xattrs(path, read_value)?,
    })
}

/// Writes it onto the freshly built replacement, before it is published into the target's slot.
/// By descriptor: the file is ours and not yet visible under the target's name.
///
/// A failure here fails the action — the replacement is thrown away and the original is left
/// untouched, which is the whole point: metadata must not go missing without anyone noticing.
pub fn apply(path: &Path, meta: &FileMetadata) -> Result<()> {
    let file = open_no_follow(path)?;
    let fd = file.as_raw_fd();
    // A descriptor to something that is not the plain file we just built — a fifo, a device — is
    // not ours to hand someone else's owner and mode to.
    if !file.metadata()?.is_file() {
        return Err(AppError::msg(format!(
            "{} is not a regular file — refusing to write the replaced file's metadata onto it",
            path.display()
        )));
    }

    // Owner first: chown clears the set-user-ID/set-group-ID bits, so the mode goes after it.
    // Only when it would actually change something — an unprivileged run that already owns the
    // file must not fail on a chown it does not need.
    let current = file.metadata()?;
    if current.uid() != meta.uid || current.gid() != meta.gid {
        // SAFETY: `fd` is owned by `file` and stays open for the whole call.
        if unsafe { libc::fchown(fd, meta.uid, meta.gid) } != 0 {
            return Err(errno_error(path, "owner"));
        }
    }
    // SAFETY: same descriptor; the file-type bits are not ours to set.
    if unsafe { libc::fchmod(fd, (meta.mode & 0o7777) as libc::mode_t) } != 0 {
        return Err(errno_error(path, "mode"));
    }
    // After the mode: a POSIX ACL rewrites the permission bits it implies, and the source file's
    // own ACL is what should win.
    for (name, value) in &meta.xattrs {
        set_xattr(fd, name, value, path)?;
    }
    // Last: everything above only moves ctime, and this is what the operator sees in `ls -l`.
    let times = [meta.atime, meta.mtime];
    // SAFETY: `times` is the two-element array futimens expects, valid for the call.
    if unsafe { libc::futimens(fd, times.as_ptr()) } != 0 {
        return Err(errno_error(path, "timestamps"));
    }
    Ok(())
}

/// `O_NOFOLLOW`: between building the replacement and writing its metadata, the staging path must
/// still be the file we made. A symlink slipped in there would send `fchown`/`fchmod` to whatever
/// it points at.
fn open_no_follow(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| {
            AppError::msg(format!(
                "cannot open the replacement {} to write its metadata: {err}",
                path.display()
            ))
        })
}

fn timespec(sec: i64, nsec: i64) -> libc::timespec {
    libc::timespec {
        tv_sec: sec as libc::time_t,
        tv_nsec: nsec as _,
    }
}

fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| AppError::msg(format!("{} contains a NUL byte", path.display())))
}

/// How the value of one enumerated attribute came back.
enum XattrValue {
    Read(Vec<u8>),
    /// It changed between the listing and the read. The snapshot is stale, not incomplete —
    /// the whole pass is taken again.
    Raced,
}

/// A file whose attributes keep moving under us is not one we can copy faithfully. Bounded, so a
/// pathological case ends in an error instead of a loop.
const XATTR_ATTEMPTS: u32 = 3;

/// Extended attributes of `path`, names and values. A filesystem that does not do xattrs at all
/// has nothing to carry over; everything else is an error, because a missing attribute on the
/// published clone is exactly the silent loss this module exists to stop.
fn read_xattrs(
    path: &Path,
    read_value: impl Fn(&CStr, &CStr) -> Result<XattrValue>,
) -> Result<Xattrs> {
    let target = c_path(path)?;
    for _ in 0..XATTR_ATTEMPTS {
        if let Some(xattrs) = snapshot_xattrs(path, &target, &read_value)? {
            return Ok(xattrs);
        }
    }
    Err(AppError::msg(format!(
        "the extended attributes of {} keep changing while being read — \
         refusing to publish a clone without them",
        path.display()
    )))
}

/// One pass over the attributes. `None` — the set changed under us; repeat it.
fn snapshot_xattrs(
    path: &Path,
    target: &CStr,
    read_value: impl Fn(&CStr, &CStr) -> Result<XattrValue>,
) -> Result<Option<Xattrs>> {
    let Some(names) = list_xattr_names(path, target)? else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for name in names {
        let name_c = CString::new(name.clone())
            .map_err(|_| AppError::msg(format!("{}: unreadable xattr name", path.display())))?;
        match read_value(target, &name_c)? {
            XattrValue::Read(value) => out.push((OsString::from_vec(name), value)),
            XattrValue::Raced => return Ok(None),
        }
    }
    Ok(Some(out))
}

/// Names only. `None` — the list grew between the size probe and the read.
fn list_xattr_names(path: &Path, target: &CStr) -> Result<Option<Vec<Vec<u8>>>> {
    // SAFETY: a null buffer with size 0 is the documented way to ask for the length.
    let size = unsafe { libc::llistxattr(target.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        if no_xattr_support() {
            return Ok(Some(Vec::new()));
        }
        return Err(errno_error(path, "list of extended attributes"));
    }
    if size == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut names = vec![0u8; size as usize];
    // SAFETY: the buffer is `names.len()` bytes long and lives across the call.
    let size = unsafe {
        libc::llistxattr(
            target.as_ptr(),
            names.as_mut_ptr() as *mut libc::c_char,
            names.len(),
        )
    };
    if size < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ERANGE) {
            return Ok(None);
        }
        if no_xattr_support() {
            return Ok(Some(Vec::new()));
        }
        return Err(errno_error(path, "list of extended attributes"));
    }
    names.truncate(size as usize);
    Ok(Some(
        names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
    ))
}

/// The libc read used in production.
fn read_xattr_value(target: &CStr, name: &CStr) -> Result<XattrValue> {
    // SAFETY: null buffer with size 0 — the length probe.
    let size = unsafe { libc::lgetxattr(target.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return raced_or_error(name);
    }
    let mut value = vec![0u8; size as usize];
    // SAFETY: the buffer is `value.len()` bytes long and lives across the call.
    let size = unsafe {
        libc::lgetxattr(
            target.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr() as *mut libc::c_void,
            value.len(),
        )
    };
    if size < 0 {
        return raced_or_error(name);
    }
    value.truncate(size as usize);
    Ok(XattrValue::Read(value))
}

/// An attribute that was listed and then vanished or resized is a race; anything else is a read we
/// are not allowed to shrug off.
fn raced_or_error(name: &CStr) -> Result<XattrValue> {
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENODATA) | Some(libc::ERANGE) => Ok(XattrValue::Raced),
        _ => Err(AppError::msg(format!(
            "cannot read the extended attribute {}: {err}",
            name.to_string_lossy()
        ))),
    }
}

fn set_xattr(fd: libc::c_int, name: &OsStr, value: &[u8], path: &Path) -> Result<()> {
    let name_c = CString::new(name.as_bytes())
        .map_err(|_| AppError::msg(format!("{}: unwritable xattr name", path.display())))?;
    // SAFETY: `fd` is open, and the name/value pointers are valid for the length given.
    let rc = unsafe {
        libc::fsetxattr(
            fd,
            name_c.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(AppError::msg(format!(
            "cannot carry over the extended attribute {} of {}: {}",
            name.to_string_lossy(),
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// The filesystem does not do extended attributes at all — there is nothing to lose. Only this
/// one errno counts as that: everything else means we failed to read something that exists.
fn no_xattr_support() -> bool {
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTSUP)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `FileMetadata` is deliberately not `Debug` (it carries the file's xattr values), so the
    /// failing cases unwrap by hand.
    fn expect_failure(result: Result<FileMetadata>) -> AppError {
        match result {
            Ok(_) => panic!("reading the metadata must fail here"),
            Err(err) => err,
        }
    }

    fn temp_file(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("dedcom_meta_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("target.bin");
        std::fs::write(&path, b"content").unwrap();
        let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
        let name_c = CString::new("user.dedcom_test").unwrap();
        // SAFETY: both strings live across the call; the value is passed with its length.
        let rc = unsafe {
            libc::lsetxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                b"v".as_ptr() as *const libc::c_void,
                1,
                0,
            )
        };
        assert_eq!(
            rc, 0,
            "the test filesystem must store user xattrs, otherwise this proves nothing"
        );
        path
    }

    /// An attribute that was listed and then cannot be read must fail the whole read. Skipping it
    /// would publish the clone with metadata quietly missing — the bug this module exists for.
    #[test]
    fn an_unreadable_attribute_fails_the_read() {
        let path = temp_file("unreadable");
        let err = expect_failure(read_with(&path, |_, name| {
            Err(AppError::msg(format!(
                "cannot read the extended attribute {}: Operation not permitted",
                name.to_string_lossy()
            )))
        }));
        assert!(
            err.to_string().contains("user.dedcom_test"),
            "the error names the attribute: {err}"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// A file whose attributes keep moving is retried, and then refused — never silently copied
    /// without them.
    #[test]
    fn an_attribute_that_keeps_racing_is_refused_after_retries() {
        let path = temp_file("racing");
        let attempts = std::cell::Cell::new(0u32);
        let err = expect_failure(read_with(&path, |_, _| {
            attempts.set(attempts.get() + 1);
            Ok(XattrValue::Raced)
        }));
        assert_eq!(attempts.get(), XATTR_ATTEMPTS, "the snapshot is retried");
        assert!(
            err.to_string().contains("keep changing"),
            "and then gives up loudly: {err}"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// The normal path still works: the attribute is read and comes back in the snapshot.
    #[test]
    fn a_readable_attribute_lands_in_the_snapshot() {
        let path = temp_file("readable");
        let meta = read(&path).unwrap();
        assert_eq!(
            meta.xattrs
                .iter()
                .map(|(name, value)| (name.to_string_lossy().into_owned(), value.clone()))
                .collect::<Vec<_>>(),
            vec![("user.dedcom_test".to_string(), b"v".to_vec())]
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}

fn errno_error(path: &Path, what: &str) -> AppError {
    AppError::msg(format!(
        "cannot carry over the {what} of {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    ))
}
