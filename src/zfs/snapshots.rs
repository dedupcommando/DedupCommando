// SPDX-License-Identifier: Apache-2.0
use crate::error::{AppError, Result};

use super::{zfs_bin_is_trusted, zfs_command};

/// Outcome of a single attempt to atomically create a candidate in [`claim_unique`].
enum ClaimOutcome {
    /// The name was successfully claimed by this attempt.
    Created,
    /// The name already exists — a retry with a different name is needed (another process / pre-existing).
    Exists,
    /// A different primitive error — propagate it without a retry.
    Error(AppError),
}

/// Upper bound on create-and-retry repetitions. In practice it is not reached (the base carries
/// time+nanos+PID+counter); a backstop against an infinite loop on a misbehaving primitive.
const MAX_CLAIM_RETRIES: u32 = 10_000;

/// Atomically claims a unique name on top of `base`: tries `try_create(candidate)`, and as long
/// as it reports [`ClaimOutcome::Exists`] — appends a retry counter (`base`, `base-r1`,
/// `base-r2`, …) and tries again.
///
/// This is precisely the **cross-process guarantee** of uniqueness: the primitive is
/// atomic (the ZFS kernel for `zfs snapshot`, `O_EXCL` on the FS), so out of two processes with
/// the same `base` exactly one will claim `base`, the second will move on to `-r1`. `base`
/// (time+nanos+PID+counter) only MINIMIZES the number of retries and is not a guarantee in itself.
fn claim_unique<F>(base: &str, mut try_create: F) -> Result<String>
where
    F: FnMut(&str) -> ClaimOutcome,
{
    let mut attempt = 0u32;
    loop {
        let candidate = if attempt == 0 {
            base.to_string()
        } else {
            format!("{base}-r{attempt}")
        };
        match try_create(&candidate) {
            ClaimOutcome::Created => return Ok(candidate),
            ClaimOutcome::Error(err) => return Err(err),
            ClaimOutcome::Exists => {
                if attempt >= MAX_CLAIM_RETRIES {
                    return Err(AppError::msg(format!(
                        "failed to claim a unique name within {MAX_CLAIM_RETRIES} attempts: {base}"
                    )));
                }
                attempt += 1;
            }
        }
    }
}

/// A snapshot with this name exists — we determine this **language-INDEPENDENTLY**, by the return
/// code of `zfs list`, and not by the error text of `zfs snapshot`. OpenZFS runs "already exists"
/// through `dgettext` (the message depends on the locale), so the collision cannot be classified by
/// the string — under a different locale the retry would not fire and a false refusal would be
/// returned. `zfs list` of an existing snapshot → exit 0; of a missing one →
/// a non-zero code, which is exactly what we distinguish via `is_ok()` (without parsing the
/// localizable text).
fn snapshot_exists(name: &str) -> bool {
    zfs_command(&["list", "-t", "snapshot", "-H", "-o", "name", name]).is_ok()
}

/// Creates an insurance snapshot of the dataset. Returns the full snapshot name
/// (`<dataset>@dedcom-<suffix>`, with a `-rN` retry on a name collision).
///
/// An operator (writing) call — fail-closed if `zfs` is not found
/// via a trusted absolute path. Without a snapshot the destructive action is cancelled,
/// rather than executed on a `zfs` from an unverified `$PATH` under elevated privileges.
///
/// The name is claimed via **atomic create-and-retry** — `zfs snapshot` is atomic (the
/// kernel rejects a duplicate), so a name collision (another process within the same second or a
/// pre-existing snapshot) leads to a retry with a new name, rather than to a false refusal of the
/// action. The suffix itself (`snapshot_suffix`: time+nanos+PID+counter) only reduces the chance of
/// a collision; the guarantee is precisely the retry on top of atomic creation.
pub fn create_snapshot(dataset: &str, suffix: &str) -> Result<String> {
    if !zfs_bin_is_trusted() {
        return Err(AppError::msg(
            "`zfs` not found in the system directories (/usr/sbin, /sbin, /usr/local/sbin); \
             the insurance snapshot was not created, the action was cancelled",
        ));
    }
    let base = format!("{dataset}@dedcom-{suffix}");
    claim_unique(&base, |name| match zfs_command(&["snapshot", name]) {
        Ok(_) => ClaimOutcome::Created,
        // We classify the collision by the ACTUAL existence of the snapshot (language-independently),
        // and not by the localizable error string: the name is already taken → retry; otherwise — a different error.
        Err(err) => {
            if snapshot_exists(name) {
                ClaimOutcome::Exists
            } else {
                ClaimOutcome::Error(err)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Atomic name claiming via the FS primitive `O_EXCL` (`create_new`) — a stand-in for
    /// the atomicity of `zfs snapshot`, testable without zfs installed.
    fn fs_claim(dir: &Path, name: &str) -> ClaimOutcome {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))
        {
            Ok(_) => ClaimOutcome::Created,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => ClaimOutcome::Exists,
            Err(e) => ClaimOutcome::Error(AppError::msg(e.to_string())),
        }
    }

    fn test_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_snap_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn claim_unique_resolves_collision_with_retry_suffix() {
        // We claim the same base twice via a shared atomic primitive → different names
        // (`base`, then `base-r1`): create-and-retry, rather than failing on "already exists".
        let dir = test_dir("claim_solo");
        let a = claim_unique("base", |n| fs_claim(&dir, n)).unwrap();
        let b = claim_unique("base", |n| fs_claim(&dir, n)).unwrap();
        assert_eq!(a, "base");
        assert_eq!(b, "base-r1");
        assert_ne!(a, b);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn claim_unique_propagates_non_exists_error() {
        // A primitive error unrelated to existence is propagated without a retry.
        let err = claim_unique("base", |_| ClaimOutcome::Error(AppError::msg("disk full")));
        assert!(err.is_err());
    }

    // --- A genuinely cross-process create-and-retry test ---
    //
    // The children are real OS processes (a re-exec of this same test binary, filtered to THIS
    // test). All of them contend for ONE base in a shared namespace directory; the atomic primitive
    // is `OpenOptions::create_new` (`O_EXCL`, atomic between processes on the same FS). Each
    // process that successfully claims creates EXACTLY one name-file. The parent checks: all children
    // exited with code 0 (none received a false refusal) AND there are exactly K files in the
    // directory. Were retry to break — the 2nd+ child would fail on AlreadyExists (non-zero code) → the test goes red.
    const KIDS: usize = 8;
    const NS_ENV: &str = "DEDCOM_CLAIM_TEST_NS";

    #[test]
    fn claim_unique_is_unique_across_real_processes() {
        if let Ok(ns) = std::env::var(NS_ENV) {
            // Child mode: claim a name in the shared directory and exit with the corresponding code.
            let dir = PathBuf::from(ns);
            let ok = claim_unique("shared-base", |n| fs_claim(&dir, n)).is_ok();
            std::process::exit(if ok { 0 } else { 1 });
        }

        // Parent mode: a namespace directory + K children for one base.
        let ns = test_dir("claim_mp");
        let exe = std::env::current_exe().expect("current_exe");
        let mut kids = Vec::new();
        for _ in 0..KIDS {
            let child = std::process::Command::new(&exe)
                .args(["claim_unique_is_unique_across_real_processes", "--quiet"])
                .env(NS_ENV, &ns)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn child");
            kids.push(child);
        }
        for mut kid in kids {
            let status = kid.wait().expect("wait child");
            assert!(
                status.success(),
                "a child failed — create-and-retry did not resolve the cross-process collision"
            );
        }
        let claimed: Vec<_> = std::fs::read_dir(&ns)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            claimed.len(),
            KIDS,
            "exactly K unique names must be claimed by K processes: {claimed:?}"
        );
        std::fs::remove_dir_all(&ns).ok();
    }
}
