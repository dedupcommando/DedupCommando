// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};

/// Moves a file to quarantine: an atomic `rename` within the dataset,
/// preserving the relative path. This is not `rm` — the file is recoverable. Returns
/// the final path in quarantine (with a collision suffix, if there was one) — needed by
/// `evacuate_then_publish` to restore the original on a publication failure.
pub fn delete_to_quarantine(
    target: &Path,
    mountpoint: &Path,
    quarantine_dir: &Path,
) -> Result<PathBuf> {
    if fs::symlink_metadata(target)?.file_type().is_symlink() {
        return Err(AppError::msg("target is a symbolic link, skipping"));
    }

    let relative = target.strip_prefix(mountpoint).map_err(|_| {
        AppError::msg(format!(
            "{} is outside dataset {}",
            target.display(),
            mountpoint.display()
        ))
    })?;

    let base = quarantine_dir.join(relative);
    if let Some(parent) = base.parent() {
        fs::create_dir_all(parent)?;
    }
    // Atomic no-clobber (as in move_file): we don't overwrite a file already placed in
    // quarantine, and without a TOCTOU race exists()+rename (P3). Quarantine is in the same
    // dataset as the target → rename without EXDEV.
    let mut n = 0u32;
    loop {
        let candidate = crate::actions::move_file::suffixed(&base, n);
        match crate::actions::move_file::rename_noreplace(target, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.raw_os_error() == Some(libc::EEXIST) => n += 1,
            // The quarantine already holds this pathname, and the name has no room for `.N`.
            Err(err) if n > 0 && crate::actions::move_file::is_name_too_long(&err) => {
                return Err(crate::actions::move_file::suffix_too_long(
                    &base,
                    &format!(".{n}"),
                    &err,
                ))
            }
            Err(err) => return Err(crate::actions::move_file::rename_failure(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The quarantine is a rename too, and a file of the open database does not go there.
    ///
    /// Red on the parent: it went. (A batch of actions never got this far with such a file —
    /// the check before an action reads the target, and that read is refused; this is the door
    /// itself.)
    #[test]
    fn a_file_of_the_open_database_does_not_go_to_quarantine() {
        let _role = crate::state::store::role_guard();
        let scratch = crate::testfixtures::ScratchDir::new("quarantine_own_db");
        let mountpoint = scratch.path();
        let db = mountpoint.join("state").join("dedcom.db");
        fs::create_dir_all(db.parent().expect("the state directory")).unwrap();
        let store = crate::state::store::ScanStore::open_writable(&db).unwrap();

        let quarantine = mountpoint.join(".dedcom-quarantine");
        let outcome =
            delete_to_quarantine(&db, mountpoint, &quarantine).map_err(|err| err.to_string());

        assert_eq!(
            outcome,
            Err(crate::actions::move_file::OPEN_DATABASE_MOVE_REFUSAL.to_string()),
            "refused, and for this reason"
        );
        assert!(db.is_file(), "the database stays at its name");
        drop(store);
    }

    /// Nor does the lock file this process holds the lock on.
    ///
    /// Red on the parent: it went, and the name it left was free for a second operator.
    #[test]
    fn the_lock_file_does_not_go_to_quarantine() {
        let scratch = crate::testfixtures::ScratchDir::new("quarantine_own_lock");
        let mountpoint = scratch.path();
        let state = mountpoint.join("state");
        fs::create_dir_all(&state).unwrap();
        let held = match crate::lock::try_acquire(&state).unwrap() {
            crate::lock::Acquire::Operator(lock) => lock,
            crate::lock::Acquire::Busy(_) => panic!("a fresh directory's lock is free"),
        };
        let lock = crate::lock::lock_path(&state);

        let quarantine = mountpoint.join(".dedcom-quarantine");
        let outcome =
            delete_to_quarantine(&lock, mountpoint, &quarantine).map_err(|err| err.to_string());

        assert_eq!(
            outcome,
            Err(crate::actions::move_file::LOCK_FILE_MOVE_REFUSAL.to_string()),
            "refused, and for this reason"
        );
        assert!(lock.is_file(), "the lock file stays at its name");
        drop(held);
    }
}
