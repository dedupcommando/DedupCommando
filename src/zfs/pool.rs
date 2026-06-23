// SPDX-License-Identifier: Apache-2.0
use std::process::Command;

use crate::model::scan::ScanEnvironment;

/// Runs `zpool <args>` and returns stdout. `None` on any error —
/// on a non-ZFS host the environment simply stays "unknown".
fn zpool_output(args: &[&str]) -> Option<String> {
    let output = Command::new(crate::zfs::zpool_bin())
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Detects the scan environment: OpenZFS version, pool layout, media type.
/// Never fails — undetermined values are returned as "unknown".
pub fn scan_environment(storage_type_override: Option<&str>) -> ScanEnvironment {
    let zfs_version = crate::zfs::version::detect()
        .zfs_version
        .unwrap_or_else(|| "unknown".to_string());

    // A single `zpool status` call (-L: real device paths, -P: full paths).
    let status = zpool_output(&["status", "-L", "-P"]);

    let pool_layout = match &status {
        Some(text) => {
            let layouts: Vec<String> = pool_blocks(text)
                .iter()
                .map(|b| classify_layout(b))
                .collect();
            aggregate(&layouts)
        }
        None => "unknown".to_string(),
    };

    let storage_type = match storage_type_override {
        Some(value) if !value.trim().is_empty() => value.trim().to_ascii_lowercase(),
        _ => match &status {
            Some(text) => {
                let kinds: Vec<String> = text.split_whitespace().filter_map(device_kind).collect();
                aggregate(&kinds)
            }
            None => "unknown".to_string(),
        },
    };

    ScanEnvironment {
        storage_type,
        pool_layout,
        zfs_version,
    }
}

/// Splits the output of `zpool status` into blocks — one per pool.
fn pool_blocks(status: &str) -> Vec<String> {
    let mut blocks: Vec<String> = Vec::new();
    for line in status.lines() {
        if line.trim_start().starts_with("pool:") {
            blocks.push(String::new());
        }
        if let Some(block) = blocks.last_mut() {
            block.push_str(line);
            block.push('\n');
        }
    }
    blocks
}

/// Classifies the pool layout by the first vdev keyword in the block.
fn classify_layout(block: &str) -> String {
    for line in block.lines() {
        let token = line.split_whitespace().next().unwrap_or("");
        if token.starts_with("raidz3") {
            return "raidz3".to_string();
        }
        if token.starts_with("raidz2") {
            return "raidz2".to_string();
        }
        if token.starts_with("raidz") {
            return "raidz1".to_string();
        }
        if token.starts_with("mirror") {
            return "mirror".to_string();
        }
    }
    "stripe".to_string()
}

/// If the token is a path to a block device, classifies its media
/// via `/sys/block/<dev>/queue/rotational`.
fn device_kind(token: &str) -> Option<String> {
    // `-P` prints full device paths — only those are of interest.
    if !token.starts_with('/') {
        return None;
    }
    let real = std::fs::canonicalize(token).ok()?;
    let name = real.file_name()?.to_str()?;
    let base = block_device_base(name);
    let rotational = std::fs::read_to_string(format!("/sys/block/{base}/queue/rotational")).ok()?;
    match rotational.trim() {
        "1" => Some("hdd".to_string()),
        "0" if base.starts_with("nvme") => Some("nvme".to_string()),
        "0" => Some("ssd".to_string()),
        _ => None,
    }
}

/// Top-level block device name: "sda3" → "sda", "nvme0n1p2" → "nvme0n1".
fn block_device_base(name: &str) -> String {
    if name.starts_with("nvme") {
        if let Some(idx) = name.rfind('p') {
            let suffix = &name[idx + 1..];
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return name[..idx].to_string();
            }
        }
        return name.to_string();
    }
    name.trim_end_matches(|c: char| c.is_ascii_digit())
        .to_string()
}

/// Reduces a set of values into one: empty → "unknown", all equal → that value, otherwise → "mixed".
fn aggregate(values: &[String]) -> String {
    match values.split_first() {
        None => "unknown".to_string(),
        Some((first, rest)) => {
            if rest.iter().all(|value| value == first) {
                first.clone()
            } else {
                "mixed".to_string()
            }
        }
    }
}
