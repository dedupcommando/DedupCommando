// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use crate::error::{AppError, Result};

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
    super::evacuate_then_publish(
        target,
        |temp| {
            reflink_copy::reflink(keeper, temp)
                .map_err(|err| AppError::msg(format!("reflink failed: {err}")))
        },
        mountpoint,
        quarantine_dir,
    )
    .map(|_| ())
}
