// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use super::{ApplyOps, Publication};

/// Replaces `target` with a hard link to `keeper` WITHOUT destroy-in-place.
///
/// Previously publication used `fs::rename(temp, target)` — atomically, but it **overwrote**
/// `target`: a change to the target after the safety snapshot was lost irrecoverably
/// (only delete was safe — via quarantine). Now the original `target`
/// is evacuated to quarantine (recoverable), and only then is the link published; on
/// a publication failure the original is restored. See [`super::evacuate_then_publish`].
///
/// The [`Publication`] it returns says where the original ended up, so the caller never has to
/// guess that from a message.
pub fn hardlink(
    ops: &dyn ApplyOps,
    target: &Path,
    keeper: &Path,
    mountpoint: &Path,
    quarantine_dir: &Path,
) -> Publication {
    super::evacuate_then_publish(
        ops,
        target,
        |temp| {
            std::fs::hard_link(keeper, temp)?;
            Ok(())
        },
        mountpoint,
        quarantine_dir,
    )
}
