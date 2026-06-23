// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use crate::model::scan::QUARANTINE_DIR_NAME;

/// The dataset's quarantine directory for a specific timestamp.
pub fn quarantine_dir(mountpoint: &Path, timestamp: &str) -> PathBuf {
    mountpoint.join(QUARANTINE_DIR_NAME).join(timestamp)
}

/// The dataset's root quarantine directory (contains all timestamps).
pub fn quarantine_root(mountpoint: &Path) -> PathBuf {
    mountpoint.join(QUARANTINE_DIR_NAME)
}
