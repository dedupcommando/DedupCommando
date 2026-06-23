// SPDX-License-Identifier: Apache-2.0
//! Preview of the action plan as a shell script.
//! The "paranoid" user reads the real commands before [Y] — or saves (`S`) and
//! runs them himself. The script is best-effort, NOT a full equivalent of [Y]:
//! it makes a safety ZFS snapshot of the affected datasets, then moves duplicates to
//! quarantine (delete) or links/copies (hardlink/reflink). The guard guarantees per
//! action are DIFFERENT: **Delete — evacuation of target to quarantine WITHOUT a size/
//! content check (recoverable); hardlink/reflink — a check of ONLY the size (`stat -c%s`),
//! without re-hashing the content** (only the application does that on [Y]). The timestamp
//! is baked in at the moment of rendering — paths can safely be enclosed in single quotes.

use std::path::{Path, PathBuf};

use crate::model::action::{ActionKind, PlannedAction};
use crate::model::dataset::Dataset;
use crate::model::scan::QUARANTINE_DIR_NAME;
use crate::tui::human_bytes;

/// Renders the plan into a bash script. `datasets` are needed for the mountpoints
/// (quarantine path) and dataset names (snapshots) — as in `apply_batch`.
///
/// `zfs_bin` — the trusted absolute path to `zfs` (`crate::zfs::trusted_zfs_bin()`);
/// `None` if `zfs` was found only as a bare name from `$PATH`. In that case, when snapshots
/// are needed, generation is **fail-closed**: destructive actions without snapshot safety
/// are not emitted. The parameter is injected for the sake of unit tests.
pub fn render_script(
    actions: &[PlannedAction],
    datasets: &[Dataset],
    zfs_bin: Option<&str>,
) -> String {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let mut out = String::new();
    out.push_str("#!/usr/bin/env bash\n");
    out.push_str("# dedcom — preview of the action plan (best-effort, NOT equivalent to [Y]).\n");
    out.push_str(&format!(
        "# Plan snapshot from {ts}. Delete — evacuation of target to quarantine WITHOUT a\n"
    ));
    out.push_str(
        "# size/content check (recoverable). Hardlink/reflink — a check of ONLY the size\n",
    );
    out.push_str(
        "# (stat -c%s), WITHOUT re-hashing the content (only [Y] does that); if the file changes\n",
    );
    out.push_str(
        "# with the same size the result may differ from [Y]. Recovery — from quarantine/snapshot.\n",
    );
    out.push_str("set -euo pipefail\n\n");

    if actions.is_empty() {
        out.push_str("# Plan is empty — no actions.\n");
        return out;
    }

    // 1. Safety snapshots of the affected datasets (by target_device).
    let mut snap_targets: Vec<String> = Vec::new();
    for action in actions {
        if let Some(dataset) = dataset_for(datasets, action.target_device) {
            if !snap_targets.contains(&dataset.name) {
                snap_targets.push(dataset.name.clone());
            }
        }
    }
    out.push_str("# 1. Safety ZFS snapshots (rollback: zfs rollback <snapshot>):\n");
    if snap_targets.is_empty() {
        out.push_str("#    (datasets not determined — snapshots skipped)\n");
    } else {
        // The snapshot MUST be called via the trusted absolute path to `zfs`
        // (a bare `zfs` would execute from $PATH under root → injection). No such path →
        // fail-closed: we do NOT emit destructive actions without snapshot safety.
        let Some(zfs) = zfs_bin else {
            out.push_str("#    REFUSAL: trusted absolute path to `zfs` not found.\n");
            out.push_str(
                "#    The snapshot safety cannot be generated, and we don't emit destructive ops without it.\n",
            );
            out.push_str(
                "echo 'dedcom: trusted zfs not found — plan not generated (fail-closed)' >&2\n",
            );
            out.push_str("exit 1\n");
            return out;
        };
        for name in &snap_targets {
            out.push_str(&format!(
                "{zfs} snapshot {}\n",
                sh_quote(&format!("{name}@dedcom-{ts}"))
            ));
        }
    }
    out.push('\n');

    // 2. The actions themselves.
    let reclaim: u64 = actions.iter().map(|action| action.size).sum();
    out.push_str(&format!(
        "# 2. Actions: {} total. Approximately freed: {}.\n",
        actions.len(),
        human_bytes(reclaim)
    ));
    for action in actions {
        let target = action.target.to_string_lossy();
        let keeper = action.keeper.to_string_lossy();
        // A file name in .sh comments/echo may contain a newline or a
        // single quote → command injection under root when the plan is saved and run.
        // For DISPLAY we take the sanitized label; the real command arguments — via sh_quote
        // (where a newline inside '…' stays a literal and is safe).
        let target_label = crate::textsan::shell_label(&target);
        match action.kind {
            ActionKind::Delete => {
                out.push_str(&format!("# delete (move to quarantine): {target_label}\n"));
                match dataset_for(datasets, action.target_device) {
                    Some(dataset) => {
                        let rel: PathBuf = match action.target.strip_prefix(&dataset.mountpoint) {
                            Ok(rel) => rel.to_path_buf(),
                            // Not under the mountpoint (doesn't happen in practice —
                            // the dataset is chosen by device): we place it by file name.
                            Err(_) => action
                                .target
                                .file_name()
                                .map(PathBuf::from)
                                .unwrap_or_else(|| action.target.clone()),
                        };
                        let dest = dataset
                            .mountpoint
                            .join(QUARANTINE_DIR_NAME)
                            .join(&ts)
                            .join(&rel);
                        if let Some(parent) = dest.parent() {
                            out.push_str(&format!(
                                "mkdir -p {}\n",
                                sh_quote(&parent.to_string_lossy())
                            ));
                        }
                        out.push_str(&format!(
                            "mv -n -- {} {}\n",
                            sh_quote(&target),
                            sh_quote(&dest.to_string_lossy())
                        ));
                    }
                    None => out.push_str(&format!(
                        "#    SKIP: dataset for {target_label} not determined\n"
                    )),
                }
            }
            ActionKind::Hardlink => {
                out.push_str(&format!(
                    "# hardlink to keeper (quarantine target + ln): {target_label}\n"
                ));
                match quarantine_dest(action, datasets, &ts) {
                    Some(dest) => {
                        let target_q = sh_quote(&target);
                        out.push_str(&format!(
                            "if [ \"$(stat -c%s -- {target_q})\" = \"{}\" ]; then\n",
                            action.size
                        ));
                        emit_quarantine(&mut out, &target_q, &dest, "  ");
                        out.push_str(&format!("  ln -- {} {target_q}\n", sh_quote(&keeper)));
                        out.push_str(&format!(
                            "else echo 'dedcom: {target_label} changed after the plan — skip' >&2; fi\n"
                        ));
                    }
                    None => out.push_str(&format!(
                        "#    SKIP: dataset for {target_label} not determined (without quarantine we don't link)\n"
                    )),
                }
            }
            ActionKind::Reflink => {
                out.push_str(&format!(
                    "# reflink (quarantine target + cp --reflink): {target_label}\n"
                ));
                match quarantine_dest(action, datasets, &ts) {
                    Some(dest) => {
                        let target_q = sh_quote(&target);
                        out.push_str(&format!(
                            "if [ \"$(stat -c%s -- {target_q})\" = \"{}\" ]; then\n",
                            action.size
                        ));
                        emit_quarantine(&mut out, &target_q, &dest, "  ");
                        out.push_str(&format!(
                            "  cp --reflink=always -- {} {target_q}\n",
                            sh_quote(&keeper)
                        ));
                        out.push_str(&format!(
                            "else echo 'dedcom: {target_label} changed after the plan — skip' >&2; fi\n"
                        ));
                    }
                    None => out.push_str(&format!(
                        "#    SKIP: dataset for {target_label} not determined\n"
                    )),
                }
            }
        }
    }
    out.push_str("\necho 'dedcom: plan executed.'\n");
    out
}

/// The dataset that device `device` belongs to (as in `apply_batch`).
fn dataset_for(datasets: &[Dataset], device: u64) -> Option<&Dataset> {
    datasets
        .iter()
        .find(|dataset| dataset.device_id == Some(device))
}

/// The destination path in quarantine for `target` (like the delete branch of `apply_batch`): under the
/// dataset's mountpoint; if target is outside the mountpoint — by file name. `None` —
/// the dataset is not determined (then we SKIP the action rather than perform it blindly).
fn quarantine_dest(action: &PlannedAction, datasets: &[Dataset], ts: &str) -> Option<PathBuf> {
    let dataset = dataset_for(datasets, action.target_device)?;
    let rel: PathBuf = match action.target.strip_prefix(&dataset.mountpoint) {
        Ok(rel) => rel.to_path_buf(),
        Err(_) => action
            .target
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| action.target.clone()),
    };
    Some(
        dataset
            .mountpoint
            .join(QUARANTINE_DIR_NAME)
            .join(ts)
            .join(&rel),
    )
}

/// Emits the "evacuation of target to quarantine" (`mkdir -p` + `mv -n --`) with indent `pad`.
/// `target_q` — the already sh-quoted target path. Recoverable (as in-app), without `rm`.
fn emit_quarantine(out: &mut String, target_q: &str, dest: &Path, pad: &str) {
    if let Some(parent) = dest.parent() {
        out.push_str(&format!(
            "{pad}mkdir -p {}\n",
            sh_quote(&parent.to_string_lossy())
        ));
    }
    out.push_str(&format!(
        "{pad}mv -n -- {target_q} {}\n",
        sh_quote(&dest.to_string_lossy())
    ));
}

/// Safe single-quoting for bash: wraps in `'…'`, escaping
/// embedded single quotes as `'\''`. Also used for the `rsync`
/// hint when a cross-dataset move is refused.
pub(crate) fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trusted absolute path to zfs for tests: in the Docker image zfs is not installed,
    // so the real `trusted_zfs_bin()` would return None — we inject the path explicitly.
    const ZFS: Option<&str> = Some("/usr/sbin/zfs");

    fn dataset(name: &str, mountpoint: &str, device: u64) -> Dataset {
        Dataset {
            name: name.to_string(),
            mountpoint: PathBuf::from(mountpoint),
            device_id: Some(device),
            snapdir_visible: false,
        }
    }

    fn action(kind: ActionKind, target: &str, keeper: &str, device: u64) -> PlannedAction {
        PlannedAction {
            kind,
            target: PathBuf::from(target),
            keeper: PathBuf::from(keeper),
            target_device: device,
            keeper_device: device,
            size: 1024,
            expected_hash: "deadbeef".to_string(),
        }
    }

    #[test]
    fn delete_renders_snapshot_and_quarantine_move() {
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        let plan = vec![action(
            ActionKind::Delete,
            "/tank/dir/dup.bin",
            "/tank/keep.bin",
            42,
        )];
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("zfs snapshot"));
        assert!(script.contains("tank/data@dedcom-"));
        assert!(script.contains("mv -n --"));
        assert!(script.contains(QUARANTINE_DIR_NAME));
        assert!(script.contains("/tank/dir/dup.bin"));
    }

    #[test]
    fn hardlink_and_reflink_render_expected_commands() {
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = vec![
            action(ActionKind::Hardlink, "/tank/a.bin", "/tank/keep.bin", 7),
            action(ActionKind::Reflink, "/tank/b.bin", "/tank/keep.bin", 7),
        ];
        let script = render_script(&plan, &datasets, ZFS);
        assert!(
            !script.contains("rm -f"),
            "hardlink no longer destroys in place"
        );
        assert!(
            script.contains("mv -n --"),
            "target is evacuated to quarantine"
        );
        assert!(
            script.contains("stat -c%s"),
            "size-guard before a destructive action"
        );
        assert!(script.contains("ln --"));
        assert!(script.contains("cp --reflink=always"));
    }

    #[test]
    fn hardlink_without_dataset_is_skipped_not_rm() {
        // No dataset for the device → SKIP, no blind rm/ln.
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = vec![action(
            ActionKind::Hardlink,
            "/other/a.bin",
            "/other/k.bin",
            99,
        )];
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("SKIP"));
        assert!(!script.contains("rm -f"));
        assert!(!script.contains("ln --"));
    }

    #[test]
    fn unknown_dataset_is_commented_not_executed() {
        // Device 99 does not match any dataset.
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = vec![action(
            ActionKind::Delete,
            "/other/x.bin",
            "/other/k.bin",
            99,
        )];
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("SKIP"));
        assert!(!script.contains("mv -n --"));
    }

    #[test]
    fn empty_plan_is_noop_script() {
        let script = render_script(&[], &[], ZFS);
        assert!(script.contains("Plan is empty"));
    }

    #[test]
    fn paths_with_spaces_are_quoted() {
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = vec![action(
            ActionKind::Hardlink,
            "/tank/a b.bin",
            "/tank/keep.bin",
            7,
        )];
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("'/tank/a b.bin'"));
    }

    #[test]
    fn control_bytes_in_filename_are_sanitized_in_comments() {
        // A name with a newline is an attempt to inject a command into the saved .sh.
        let datasets = vec![dataset("tank", "/tank", 7)];
        let evil = "/tank/x\nzfs destroy tank\n#.bin";
        let plan = vec![action(ActionKind::Hardlink, evil, "/tank/keep.bin", 7)];
        let script = render_script(&plan, &datasets, ZFS);
        // Newlines in the name are replaced with '?', the name stays one line in the comment.
        assert!(
            script.contains("/tank/x?zfs destroy tank?#.bin"),
            "the name in the comment must be cleaned of control bytes"
        );
        // Without cleaning, a raw newline would cut off the comment — that's no longer the case.
        assert!(!script.contains("ln): /tank/x\nzfs"));
        // The real ln command is still present.
        assert!(script.contains("ln --"));
    }

    #[test]
    fn single_quote_in_filename_does_not_break_echo() {
        // A single quote in the name must not break out of echo '…' (the label is cleaned).
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = vec![action(
            ActionKind::Hardlink,
            "/tank/a'b.bin",
            "/tank/keep.bin",
            7,
        )];
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("dedcom: /tank/a?b.bin changed"));
    }

    #[test]
    fn untrusted_zfs_refuses_to_emit_actions() {
        // No trusted absolute zfs → fail-closed. The script exits with
        // exit 1 BEFORE any actions; no mv/ln/cp (we don't emit destructive ops without a snapshot).
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        let plan = vec![
            action(
                ActionKind::Delete,
                "/tank/dir/dup.bin",
                "/tank/keep.bin",
                42,
            ),
            action(ActionKind::Hardlink, "/tank/a.bin", "/tank/keep.bin", 42),
        ];
        let script = render_script(&plan, &datasets, None);
        assert!(
            script.contains("exit 1"),
            "fail-closed: the script must exit with an error"
        );
        assert!(!script.contains("mv -n --"));
        assert!(!script.contains("ln --"));
        assert!(!script.contains("cp --reflink"));
    }

    #[test]
    fn trusted_zfs_uses_absolute_path_not_bare() {
        // The snapshot goes via the trusted absolute path, not a bare `zfs`
        // (otherwise PATH-injection under root). There's no bare `zfs snapshot` string at the start.
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        let plan = vec![action(
            ActionKind::Delete,
            "/tank/dir/dup.bin",
            "/tank/keep.bin",
            42,
        )];
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("/usr/sbin/zfs snapshot"));
        assert!(
            !script.lines().any(|l| l.starts_with("zfs snapshot")),
            "the snapshot must not be called via a bare `zfs`"
        );
    }

    #[test]
    fn delete_has_no_size_guard_but_hardlink_does() {
        // Delete — evacuation to quarantine without a size-guard
        // (recoverable); only hardlink/reflink have a `$(stat -c%s)` check. We match
        // specifically the command-substitution `$(stat -c%s`, not the mention of `(stat -c%s)` in the header.
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        let del = vec![action(ActionKind::Delete, "/tank/d.bin", "/tank/k.bin", 42)];
        let del_script = render_script(&del, &datasets, ZFS);
        assert!(
            !del_script.contains("$(stat -c%s"),
            "Delete does not perform a size-guard (evacuation to quarantine is recoverable)"
        );
        // The header no longer falsely claims "each action: size check".
        assert!(!del_script.contains("Each action: SIZE check"));

        // hardlink — on the contrary, has a size-guard before a destructive action.
        let hl = vec![action(
            ActionKind::Hardlink,
            "/tank/a.bin",
            "/tank/k.bin",
            42,
        )];
        let hl_script = render_script(&hl, &datasets, ZFS);
        assert!(
            hl_script.contains("$(stat -c%s"),
            "hardlink has a size-guard"
        );
    }
}
