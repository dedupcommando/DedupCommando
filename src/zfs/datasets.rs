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
    // One question for every pool: a reflink on a pool that cannot clone is refused before its
    // batch takes a snapshot, not by the kernel after it.
    let cloning =
        super::pool::zpool_output(&["get", "-H", "-o", "name,value", "feature@block_cloning"])
            .map(|text| block_cloning_by_pool(&text))
            .unwrap_or_default();

    let raw = zfs_command(&[
        "list",
        "-H",
        "-p",
        "-o",
        "name,mountpoint,mounted",
        "-t",
        "filesystem",
    ])?;
    Ok(datasets_from(&raw, &snapdirs, &cloning))
}

/// The mounted datasets in the output of `zfs list -H -p -o name,mountpoint,mounted`, each with its
/// `snapdir` and its pool's block cloning.
fn datasets_from(
    raw: &str,
    snapdirs: &HashMap<String, bool>,
    cloning: &HashMap<String, bool>,
) -> Vec<Dataset> {
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
        let pool = name.split('/').next().unwrap_or(name);

        datasets.push(Dataset {
            name: name.to_string(),
            mountpoint,
            device_id,
            snapdir_visible: snapdirs.get(name).copied().unwrap_or(false),
            block_cloning: cloning.get(pool).copied(),
        });
    }
    datasets
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

/// "pool → can it clone blocks", from `zpool get -H -o name,value feature@block_cloning`. A pool
/// whose value is neither state (an older pool may print `-`) is left out: unknown, not refused.
fn block_cloning_by_pool(text: &str) -> HashMap<String, bool> {
    text.lines()
        .filter_map(|line| {
            let (pool, value) = line.split_once('\t')?;
            let cloning = match value.trim() {
                "enabled" | "active" => true,
                "disabled" => false,
                _ => return None,
            };
            Some((pool.to_string(), cloning))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{block_cloning_by_pool, datasets_from};
    use std::collections::HashMap;

    /// Every mounted dataset carries its own pool's block cloning; a pool `zpool` did not report
    /// leaves it unknown, and a dataset that is not mounted is not listed.
    #[test]
    fn a_dataset_carries_its_pools_block_cloning() {
        let mount = crate::testfixtures::ScratchDir::new("datasets_from");
        let at = mount.path().display();
        let raw = format!(
            "tank\t{at}\tyes\ntank/vm\t{at}\tyes\nrpool/data\t{at}\tyes\ntank/off\t{at}\tno\n\
             tank/none\tnone\tyes\n"
        );
        let cloning = block_cloning_by_pool("tank\tdisabled\n");
        let datasets = datasets_from(&raw, &HashMap::new(), &cloning);
        let found: Vec<(&str, Option<bool>)> = datasets
            .iter()
            .map(|dataset| (dataset.name.as_str(), dataset.block_cloning))
            .collect();
        assert_eq!(
            found,
            [
                ("tank", Some(false)),
                ("tank/vm", Some(false)),
                ("rpool/data", None)
            ]
        );
    }

    #[test]
    fn block_cloning_is_read_per_pool_and_an_unknown_value_is_left_out() {
        let map = block_cloning_by_pool("tank\tactive\nrpool\tenabled\nold\tdisabled\nodd\t-\n");
        assert_eq!(map.get("tank"), Some(&true));
        assert_eq!(map.get("rpool"), Some(&true));
        assert_eq!(map.get("old"), Some(&false));
        assert_eq!(map.get("odd"), None, "neither state is not a refusal");
        assert_eq!(map.len(), 3);
    }
}
