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
            Err(err) => return Err(err.into()),
        }
    }
}
