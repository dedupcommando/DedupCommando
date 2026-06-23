// SPDX-License-Identifier: Apache-2.0
use std::fs;

use crate::model::dataset::ZfsCapabilities;

/// Detects the OpenZFS version and the state of block cloning.
pub fn detect() -> ZfsCapabilities {
    let zfs_version = detect_version();
    let triple = zfs_version.as_deref().and_then(parse_triple);

    let block_cloning_supported = triple.map(|t| t >= (2, 2, 0)).unwrap_or(false);
    let block_cloning_enabled = bclone_enabled();

    // Reflink gate (see the plan, section "Integration with ZFS").
    let reflink_safe = match triple {
        Some(t) if t >= (2, 3, 0) => block_cloning_enabled,
        Some(t) if t >= (2, 2, 1) => block_cloning_enabled,
        _ => false, // < 2.2 or exactly 2.2.0 — historical data-corruption bug
    };

    ZfsCapabilities {
        zfs_version,
        block_cloning_supported,
        block_cloning_enabled,
        reflink_safe,
    }
}

fn detect_version() -> Option<String> {
    if let Ok(text) = super::zfs_command(&["version"]) {
        if let Some(version) = text.lines().find_map(parse_version_line) {
            return Some(version);
        }
    }
    // Fallback source if `zfs version` is unavailable.
    if let Ok(content) = fs::read_to_string("/sys/module/zfs/version") {
        return parse_semver(content.trim());
    }
    None
}

/// "zfs-2.3.1-1" -> Some("2.3.1"); skips the "zfs-kmod-..." line.
fn parse_version_line(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix("zfs-")?;
    if rest.starts_with("kmod-") {
        return None;
    }
    parse_semver(rest)
}

/// Extracts the leading "X.Y[.Z]" from the string.
fn parse_semver(s: &str) -> Option<String> {
    let version: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let looks_like_version =
        version.split('.').count() >= 2 && version.starts_with(|c: char| c.is_ascii_digit());
    looks_like_version.then_some(version)
}

fn parse_triple(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

fn bclone_enabled() -> bool {
    fs::read_to_string("/sys/module/zfs/parameters/zfs_bclone_enabled")
        .map(|content| content.trim() == "1")
        .unwrap_or(false)
}
