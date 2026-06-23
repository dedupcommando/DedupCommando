// SPDX-License-Identifier: Apache-2.0
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use crate::error::{AppError, Result};
use crate::model::dataset::{Dataset, Pool, ZfsCapabilities};

pub mod datasets;
pub mod pool;
pub mod snapshots;
pub mod version;

/// Snapshot of the host's ZFS environment, captured once at startup.
pub struct ZfsEnvironment {
    pub pools: Vec<Pool>,
    pub capabilities: ZfsCapabilities,
    pub warnings: Vec<String>,
}

impl ZfsEnvironment {
    /// Detects datasets and ZFS capabilities. Does not fail: problems
    /// are collected into `warnings`, so that delete/hardlink work even without ZFS.
    pub fn detect() -> Self {
        let mut warnings = Vec::new();

        let capabilities = version::detect();
        if capabilities.zfs_version.is_none() {
            warnings.push(
                "ZFS not detected (the `zfs` command is unavailable) — ZFS features are disabled"
                    .to_string(),
            );
        }

        let datasets = match datasets::list_datasets() {
            Ok(datasets) => datasets,
            Err(err) => {
                warnings.push(format!("failed to obtain the list of datasets: {err}"));
                Vec::new()
            }
        };

        for dataset in &datasets {
            if dataset.snapdir_visible {
                warnings.push(format!(
                    "{}: snapdir=visible — snapshots will be excluded from scanning",
                    dataset.name
                ));
            }
        }

        Self {
            pools: group_into_pools(datasets),
            capabilities,
            warnings,
        }
    }

    /// Total number of datasets across all pools.
    pub fn dataset_count(&self) -> usize {
        self.pools.iter().map(|pool| pool.datasets.len()).sum()
    }
}

/// Groups datasets by pool name.
fn group_into_pools(datasets: Vec<Dataset>) -> Vec<Pool> {
    let mut pools: Vec<Pool> = Vec::new();
    for dataset in datasets {
        let pool_name = dataset.pool_name().to_string();
        match pools.iter_mut().find(|pool| pool.name == pool_name) {
            Some(pool) => pool.datasets.push(dataset),
            None => pools.push(Pool {
                name: pool_name,
                datasets: vec![dataset],
            }),
        }
    }
    pools
}

/// Absolute path to the binary `name`: we search among the standard system
/// directories ONCE and cache the result. If no candidate exists — fall back to the bare name
/// (resolved via PATH). An absolute path removes the risk of binary substitution through
/// `$PATH` under elevated privileges. `exists` is injected for the sake of the unit test.
fn resolve_bin(name: &str, exists: impl Fn(&Path) -> bool) -> OsString {
    const DIRS: [&str; 3] = ["/usr/sbin", "/sbin", "/usr/local/sbin"];
    for dir in DIRS {
        let cand = Path::new(dir).join(name);
        if exists(&cand) {
            return cand.into_os_string();
        }
    }
    OsString::from(name)
}

/// The binary was found via a trusted absolute path (and not via a bare name, which
/// is resolved through `$PATH`).
fn is_trusted_bin(bin: &OsString) -> bool {
    Path::new(bin).is_absolute()
}

/// `zfs` resolved to a trusted system path. Operator/destructive
/// calls (the insurance snapshot) must fail-closed if this is not the case — otherwise
/// under elevated privileges `zfs` can be substituted through `$PATH`.
pub(crate) fn zfs_bin_is_trusted() -> bool {
    is_trusted_bin(zfs_bin())
}

/// Trusted absolute path to `zfs` for embedding into the exported `.sh` plan.
/// `None` if `zfs` resolved only to a bare name (resolved via `$PATH`) — in that case
/// a safe snapshot insurance cannot be generated in the script, and the plan must
/// fail-closed: do not emit destructive actions without a snapshot.
pub(crate) fn trusted_zfs_bin() -> Option<&'static str> {
    let bin = zfs_bin();
    if is_trusted_bin(bin) {
        bin.to_str()
    } else {
        None
    }
}

fn zfs_bin() -> &'static OsString {
    static BIN: OnceLock<OsString> = OnceLock::new();
    BIN.get_or_init(|| resolve_bin("zfs", |p| p.exists()))
}

/// Absolute path to `zpool` (see [`resolve_bin`]) — for `pool.rs` and `host_profile.rs`.
pub(crate) fn zpool_bin() -> &'static OsString {
    static BIN: OnceLock<OsString> = OnceLock::new();
    BIN.get_or_init(|| resolve_bin("zpool", |p| p.exists()))
}

/// Runs `zfs <args>` and returns stdout. Error if the command
/// is not found or returned a non-zero code.
pub(crate) fn zfs_command(args: &[&str]) -> Result<String> {
    let output = Command::new(zfs_bin())
        .args(args)
        .output()
        .map_err(|err| AppError::msg(format!("failed to launch `zfs`: {err}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::msg(format!(
            "`zfs {}` finished unsuccessfully: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{is_trusted_bin, resolve_bin};
    use std::ffi::OsString;
    use std::path::Path;

    #[test]
    fn resolve_bin_prefers_absolute_then_falls_back() {
        // All "exist" → the first directory by priority (/usr/sbin).
        assert_eq!(
            resolve_bin("zfs", |_| true),
            OsString::from("/usr/sbin/zfs")
        );
        // Exists only in /sbin → exactly that one.
        assert_eq!(
            resolve_bin("zfs", |p| p == Path::new("/sbin/zfs")),
            OsString::from("/sbin/zfs")
        );
        // Nothing present → fall back to the bare name (resolved via PATH).
        assert_eq!(resolve_bin("zpool", |_| false), OsString::from("zpool"));
    }

    #[test]
    fn untrusted_bare_bin_is_rejected() {
        // A bare name (fallback from $PATH) — not a trusted binary;
        // an absolute system path — trusted.
        assert!(!is_trusted_bin(&resolve_bin("zfs", |_| false)));
        assert!(is_trusted_bin(
            &resolve_bin("zfs", |p| p == Path::new("/usr/sbin/zfs"))
        ));
    }
}
