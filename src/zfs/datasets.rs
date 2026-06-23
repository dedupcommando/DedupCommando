// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use crate::error::Result;
use crate::model::dataset::Dataset;

use super::zfs_command;

/// Enumerates the mounted ZFS filesystem datasets.
pub fn list_datasets() -> Result<Vec<Dataset>> {
    let snapdirs = snapdir_map().unwrap_or_default();

    let raw = zfs_command(&[
        "list",
        "-H",
        "-p",
        "-o",
        "name,mountpoint,mounted",
        "-t",
        "filesystem",
    ])?;

    let mut datasets = Vec::new();
    for line in raw.lines() {
        let mut cols = line.split('\t');
        let (name, mountpoint, mounted) = match (cols.next(), cols.next(), cols.next()) {
            (Some(name), Some(mountpoint), Some(mounted)) => (name, mountpoint, mounted),
            _ => continue,
        };

        // Skip datasets without a normal mountpoint and those not mounted.
        if matches!(mountpoint, "none" | "legacy" | "-") || mounted != "yes" {
            continue;
        }

        let mountpoint = PathBuf::from(mountpoint);
        let device_id = std::fs::metadata(&mountpoint).map(|meta| meta.dev()).ok();

        datasets.push(Dataset {
            name: name.to_string(),
            mountpoint,
            device_id,
            snapdir_visible: snapdirs.get(name).copied().unwrap_or(false),
        });
    }

    Ok(datasets)
}

/// Map of "dataset name → snapdir == visible".
fn snapdir_map() -> Result<HashMap<String, bool>> {
    let raw = zfs_command(&[
        "get",
        "-H",
        "-o",
        "name,value",
        "-t",
        "filesystem",
        "snapdir",
    ])?;

    let mut map = HashMap::new();
    for line in raw.lines() {
        let mut cols = line.split('\t');
        if let (Some(name), Some(value)) = (cols.next(), cols.next()) {
            map.insert(name.to_string(), value == "visible");
        }
    }
    Ok(map)
}
