// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use crate::error::{AppError, Result};

use super::meta;

/// Replaces `target` with a reflink copy (CoW clone) of `keeper` WITHOUT destroy-in-place.
///
/// The content is identical, but on ZFS 2.2+ the blocks are shared (space is freed),
/// while the files remain independent (unlike hardlink). Previously publication
/// used `fs::rename(temp, target)` and **overwrote** `target`; now the original
/// is evacuated to quarantine (recoverable) before the clone is published, with restoration
/// on failure. See [`super::evacuate_then_publish`].
pub fn reflink(
    target: &Path,
    keeper: &Path,
    mountpoint: &Path,
    quarantine_dir: &Path,
) -> Result<()> {
    publish_clone(
        target,
        keeper,
        mountpoint,
        quarantine_dir,
        |keeper, temp| {
            reflink_copy::reflink(keeper, temp)
                .map_err(|err| AppError::msg(format!("reflink failed: {err}")))
        },
    )
}

/// Builds the replacement, gives it the identity of the file it replaces, and publishes it.
///
/// The clone is a NEW inode and comes out owned by this process with the umask's mode, so the
/// target's owner, mode, ACL, xattrs and timestamps are carried over before it is published —
/// otherwise a duplicate belonging to someone else would quietly come back as `root:root 0644`.
/// They are read while the original is still in place, and written before it is published.
///
/// `clone` is the block-sharing step. The real one needs a filesystem with FICLONE, so the tests
/// hand in a plain copy: it produces the same fresh inode with this process's identity, which is
/// exactly what the carry-over is about.
fn publish_clone(
    target: &Path,
    keeper: &Path,
    mountpoint: &Path,
    quarantine_dir: &Path,
    clone: impl FnOnce(&Path, &Path) -> Result<()>,
) -> Result<()> {
    let metadata = meta::read(target)?;
    super::evacuate_then_publish(
        target,
        |temp| {
            clone(keeper, temp)?;
            meta::apply(temp, &metadata)
        },
        mountpoint,
        quarantine_dir,
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "dedcom_reflink_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Sets an extended attribute, reporting whether the filesystem under the test does them at
    /// all — tmpfs and overlayfs differ, and a missing xattr there is not a failure of ours.
    fn set_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let name_c = std::ffi::CString::new(name).unwrap();
        // SAFETY: both strings live across the call, and the value slice is passed with its len.
        unsafe {
            libc::lsetxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            ) == 0
        }
    }

    fn xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let name_c = std::ffi::CString::new(name).unwrap();
        // SAFETY: length probe, then a read into a buffer of exactly that length.
        unsafe {
            let size = libc::lgetxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0);
            if size < 0 {
                return None;
            }
            let mut value = vec![0u8; size as usize];
            let size = libc::lgetxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_mut_ptr() as *mut libc::c_void,
                value.len(),
            );
            if size < 0 {
                return None;
            }
            value.truncate(size as usize);
            Some(value)
        }
    }

    /// The published clone must look like the file it replaced, not like the process that built
    /// it. Without the carry-over the operator's `report.pdf` comes back with the umask's mode
    /// (and, under root, `root:root`), and its ACL and xattrs are gone with the quarantined
    /// original.
    #[test]
    fn the_published_clone_keeps_the_identity_of_the_file_it_replaces() {
        let mountpoint = temp_dir("identity");
        let quarantine = mountpoint.join(".dedcom-quarantine");
        let target = mountpoint.join("target.bin");
        let keeper = mountpoint.join("keeper.bin");
        std::fs::write(&target, b"duplicate content").unwrap();
        std::fs::write(&keeper, b"duplicate content").unwrap();
        // The file being replaced is private and old; the keeper is neither.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&keeper, std::fs::Permissions::from_mode(0o644)).unwrap();
        let carried = set_xattr(&target, "user.dedcom_test", b"carry me");
        let before = std::fs::symlink_metadata(&target).unwrap();
        let (mtime, mtime_nsec) = (before.mtime(), before.mtime_nsec());
        let original_inode = before.ino();

        publish_clone(
            &target,
            &keeper,
            &mountpoint,
            &quarantine,
            |keeper, temp| {
                std::fs::copy(keeper, temp)?;
                Ok(())
            },
        )
        .unwrap();

        let after = std::fs::symlink_metadata(&target).unwrap();
        assert_ne!(
            after.ino(),
            original_inode,
            "the replacement really was published"
        );
        assert_eq!(
            after.permissions().mode() & 0o7777,
            0o600,
            "the mode of the replaced file, not the umask's"
        );
        assert_eq!((after.mtime(), after.mtime_nsec()), (mtime, mtime_nsec));
        if carried {
            assert_eq!(
                xattr(&target, "user.dedcom_test").as_deref(),
                Some(&b"carry me"[..]),
                "extended attributes (and with them POSIX ACLs) come along"
            );
        }
        // The original is recoverable, as for every other action.
        assert!(quarantine.join("target.bin").exists());

        std::fs::remove_dir_all(&mountpoint).ok();
    }

    /// Ownership is the half that bites hardest: a duplicate owned by a user comes back owned by
    /// whoever ran the tool. Only checkable with the privilege to hand a file to someone else.
    #[test]
    fn the_published_clone_keeps_the_owner() {
        // SAFETY: euid is a plain read of process state.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let mountpoint = temp_dir("owner");
        let quarantine = mountpoint.join(".dedcom-quarantine");
        let target = mountpoint.join("target.bin");
        let keeper = mountpoint.join("keeper.bin");
        std::fs::write(&target, b"duplicate content").unwrap();
        std::fs::write(&keeper, b"duplicate content").unwrap();
        let target_c = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        // SAFETY: the path string lives across the call.
        assert_eq!(unsafe { libc::lchown(target_c.as_ptr(), 12345, 12345) }, 0);

        publish_clone(
            &target,
            &keeper,
            &mountpoint,
            &quarantine,
            |keeper, temp| {
                std::fs::copy(keeper, temp)?;
                Ok(())
            },
        )
        .unwrap();

        let after = std::fs::symlink_metadata(&target).unwrap();
        assert_eq!(
            (after.uid(), after.gid()),
            (12345, 12345),
            "the duplicate stays with its owner"
        );

        std::fs::remove_dir_all(&mountpoint).ok();
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The clone was built, the metadata could not be written onto it. Nothing may be published:
    /// the original stays where it is, nothing goes to quarantine, and no staging file is left.
    #[test]
    fn a_replacement_that_is_not_a_regular_file_is_refused() {
        let mountpoint = temp_dir("not_regular");
        let quarantine = mountpoint.join(".dedcom-quarantine");
        let target = mountpoint.join("target.bin");
        let keeper = mountpoint.join("keeper.bin");
        std::fs::write(&target, b"duplicate content").unwrap();
        std::fs::write(&keeper, b"duplicate content").unwrap();
        let before = std::fs::symlink_metadata(&target).unwrap().ino();

        let result = publish_clone(&target, &keeper, &mountpoint, &quarantine, |_, temp| {
            // A fifo stands in for a "clone" that is not a plain file: it opens, so only the
            // regular-file check can catch it.
            let temp_c = std::ffi::CString::new(temp.as_os_str().as_bytes()).unwrap();
            // SAFETY: the path string lives across the call.
            assert_eq!(unsafe { libc::mkfifo(temp_c.as_ptr(), 0o600) }, 0);
            Ok(())
        });

        let err = result.unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");
        assert_eq!(std::fs::symlink_metadata(&target).unwrap().ino(), before);
        assert!(!quarantine.exists(), "nothing was evacuated");
        assert_eq!(
            entries(&mountpoint),
            vec!["keeper.bin".to_string(), "target.bin".to_string()],
            "the staging file is cleaned up"
        );

        std::fs::remove_dir_all(&mountpoint).ok();
    }

    /// A symlink slipped into the staging path must not send the chown/chmod to its referent.
    #[test]
    fn a_symlink_at_the_staging_path_is_refused() {
        let mountpoint = temp_dir("staging_symlink");
        let quarantine = mountpoint.join(".dedcom-quarantine");
        let target = mountpoint.join("target.bin");
        let keeper = mountpoint.join("keeper.bin");
        let bystander = mountpoint.join("bystander.bin");
        std::fs::write(&target, b"duplicate content").unwrap();
        std::fs::write(&keeper, b"duplicate content").unwrap();
        std::fs::write(&bystander, b"do not touch me").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&bystander, std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = std::fs::symlink_metadata(&target).unwrap().ino();

        let bystander_for_clone = bystander.clone();
        let result = publish_clone(
            &target,
            &keeper,
            &mountpoint,
            &quarantine,
            move |_, temp| {
                std::os::unix::fs::symlink(&bystander_for_clone, temp)?;
                Ok(())
            },
        );

        assert!(result.is_err());
        let after = std::fs::symlink_metadata(&bystander).unwrap();
        assert_eq!(
            after.permissions().mode() & 0o7777,
            0o644,
            "the referent keeps its own mode"
        );
        assert_eq!(
            std::fs::read(&bystander).unwrap(),
            b"do not touch me",
            "and its content"
        );
        assert_eq!(std::fs::symlink_metadata(&target).unwrap().ino(), before);
        assert!(!quarantine.exists(), "nothing was evacuated");
        assert_eq!(
            entries(&mountpoint),
            vec![
                "bystander.bin".to_string(),
                "keeper.bin".to_string(),
                "target.bin".to_string()
            ],
            "the staging symlink is cleaned up"
        );

        std::fs::remove_dir_all(&mountpoint).ok();
    }

    /// The carry-over runs before publication, so a failure leaves the original where it is.
    #[test]
    fn a_failed_clone_leaves_the_target_alone() {
        let mountpoint = temp_dir("failed");
        let quarantine = mountpoint.join(".dedcom-quarantine");
        let target = mountpoint.join("target.bin");
        let keeper = mountpoint.join("keeper.bin");
        std::fs::write(&target, b"duplicate content").unwrap();
        std::fs::write(&keeper, b"duplicate content").unwrap();
        let before = std::fs::symlink_metadata(&target).unwrap().ino();

        let result = publish_clone(&target, &keeper, &mountpoint, &quarantine, |_, _| {
            Err(AppError::msg("reflink failed: no block cloning here"))
        });

        assert!(result.is_err());
        assert_eq!(
            std::fs::symlink_metadata(&target).unwrap().ino(),
            before,
            "the file being replaced is untouched"
        );
        assert!(!quarantine.exists(), "and nothing went to quarantine");

        std::fs::remove_dir_all(&mountpoint).ok();
    }
}
