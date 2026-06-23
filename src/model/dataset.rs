// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

/// A single mounted ZFS filesystem dataset.
#[derive(Debug, Clone)]
pub struct Dataset {
    /// Full name, e.g. "rpool/data".
    pub name: String,
    /// Mount point.
    pub mountpoint: PathBuf,
    /// st_dev of the mount point — ties a file to a dataset
    /// (protection against cross-dataset hardlink).
    pub device_id: Option<u64>,
    /// snapdir=visible — the `.zfs` directory is visible as a regular one.
    pub snapdir_visible: bool,
}

impl Dataset {
    /// The pool name — the part of the name before the first `/`.
    pub fn pool_name(&self) -> &str {
        self.name.split('/').next().unwrap_or(&self.name)
    }
}

/// A ZFS pool with the datasets that belong to it.
#[derive(Debug, Clone)]
pub struct Pool {
    pub name: String,
    pub datasets: Vec<Dataset>,
}

/// OpenZFS capabilities, determined at startup — they govern reflink availability.
#[derive(Debug, Clone, Default)]
pub struct ZfsCapabilities {
    /// OpenZFS version, e.g. "2.3.1".
    pub zfs_version: Option<String>,
    /// The module supports block cloning (>= 2.2).
    pub block_cloning_supported: bool,
    /// zfs_bclone_enabled == 1.
    pub block_cloning_enabled: bool,
    /// Final gate: reflink is safe on this host.
    pub reflink_safe: bool,
}
