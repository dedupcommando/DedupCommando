// SPDX-License-Identifier: Apache-2.0
//! Preview of the action plan as a shell script.
//!
//! The "paranoid" user reads the real commands before [Y] — or saves (`S`) and runs them himself,
//! which makes this a real apply route and not a picture of one. It therefore carries the same
//! whole-plan structural preflight the interactive path runs, emitted twice: once before the
//! snapshot section and once after it, immediately before the first destructive command. What the
//! shell can check is structure — `stat -c '%d %i %s %h %Y %Z'`, all integers, GNU coreutils only.
//! What it cannot check is the blake3 content digest and the nanosecond halves of the timestamps,
//! so the generated header says so beside the TOCTOU warning rather than implying parity with [Y].
//! The per-action size guards stay as defence in depth. The timestamp is baked in at the moment of
//! rendering — paths can safely be enclosed in single quotes.

use std::path::{Path, PathBuf};

use crate::model::action::ActionKind;
use crate::model::dataset::Dataset;
use crate::model::plan::{ActionPlan, PlanAction, PlannedObject};
use crate::model::scan::QUARANTINE_DIR_NAME;

/// Renders the plan into a bash script. `datasets` are needed for the mountpoints
/// (quarantine path) and dataset names (snapshots) — as in `apply_batch`.
///
/// `zfs_bin` — the trusted absolute path to `zfs` (`crate::zfs::trusted_zfs_bin()`);
/// `None` if `zfs` was found only as a bare name from `$PATH`. In that case, when snapshots
/// are needed, generation is **fail-closed**: destructive actions without snapshot safety
/// are not emitted. The parameter is injected for the sake of unit tests.
pub fn render_script(plan: &ActionPlan, datasets: &[Dataset], zfs_bin: Option<&str>) -> String {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let mut out = String::new();
    out.push_str("#!/usr/bin/env bash\n");
    out.push_str("# dedcom — the action plan as a shell script.\n");
    out.push_str(&format!("# Plan snapshot from {ts}.\n"));
    out.push_str(&format!(
        "# {} action(s) over {} allocation(s). {}\n",
        plan.summary().actions(),
        plan.summary().covered_objects(),
        crate::tui::reclaim_phrase(plan.summary().estimate()),
    ));
    for warning in plan.summary().warnings() {
        out.push_str(&format!(
            "# {}\n",
            crate::textsan::shell_label(&warning.message())
        ));
    }
    out.push_str(
        "# This script verifies STRUCTURE only: device, inode, size, link count and the SECONDS\n",
    );
    out.push_str(
        "# of mtime/ctime. It cannot verify the blake3 content digest, and GNU stat does not\n",
    );
    out.push_str(
        "# expose the nanosecond halves as integers; interactive apply ([Y]) re-hashes content.\n",
    );
    out.push_str(
        "# Between this check and each command there is still a window (TOCTOU); recovery is\n",
    );
    out.push_str("# from the quarantine and the safety snapshot.\n");
    out.push_str("set -euo pipefail\n\n");

    // 1. Safety snapshots of the affected datasets (by the target allocation's device).
    let mut snap_targets: Vec<String> = Vec::new();
    for action in plan.actions() {
        if let Some(dataset) = dataset_for(datasets, plan.target_object_of(action).key().device) {
            if !snap_targets.contains(&dataset.name) {
                snap_targets.push(dataset.name.clone());
            }
        }
    }
    // The snapshot MUST be called via the trusted absolute path to `zfs` (a bare `zfs` would
    // execute from $PATH under root → injection). No such path → fail-closed: we do NOT emit
    // destructive actions without snapshot safety, and nothing above this point has touched
    // anything.
    let zfs = match (snap_targets.is_empty(), zfs_bin) {
        (false, None) => {
            out.push_str("# REFUSAL: trusted absolute path to `zfs` not found.\n");
            out.push_str(
                "# The snapshot safety cannot be generated, and we don't emit destructive ops without it.\n",
            );
            out.push_str(
                "echo 'dedcom: trusted zfs not found — plan not generated (fail-closed)' >&2\n",
            );
            out.push_str("exit 1\n");
            return out;
        }
        (_, zfs) => zfs,
    };

    out.push_str(&preflight_definition(plan));
    out.push_str("# 1. Structural preflight, before anything exists.\n");
    out.push_str("dedcom_preflight\n\n");

    out.push_str("# 2. Safety ZFS snapshots (rollback: zfs rollback <snapshot>):\n");
    if snap_targets.is_empty() {
        out.push_str("#    (datasets not determined — snapshots skipped)\n");
    } else {
        let zfs = zfs.expect("a missing zfs with datasets already returned above");
        for name in &snap_targets {
            out.push_str(&format!(
                "{zfs} snapshot {}\n",
                sh_quote(&format!("{name}@dedcom-{ts}"))
            ));
        }
    }
    out.push('\n');

    // The second call: the snapshots exist, and this is the last statement before the first
    // command that moves anything.
    out.push_str("# 3. The same preflight again, immediately before the first change.\n");
    out.push_str("dedcom_preflight\n\n");

    out.push_str(&format!("# 4. Actions: {} total.\n", plan.actions().len()));
    for action in plan.actions() {
        let device = plan.target_object_of(action).key().device;
        let target = action.target().to_string_lossy();
        let keeper = action.keeper().to_string_lossy();
        // A file name in .sh comments/echo may contain a newline or a
        // single quote → command injection under root when the plan is saved and run.
        // For DISPLAY we take the sanitized label; the real command arguments — via sh_quote
        // (where a newline inside '…' stays a literal and is safe).
        let target_label = crate::textsan::shell_label(&target);
        match action.kind() {
            ActionKind::Delete => {
                out.push_str(&format!("# delete (move to quarantine): {target_label}\n"));
                match quarantine_dest(action, device, datasets, &ts) {
                    Some(dest) => {
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
                match quarantine_dest(action, device, datasets, &ts) {
                    Some(dest) => {
                        let target_q = sh_quote(&target);
                        out.push_str(&format!(
                            "if [ \"$(stat -c%s -- {target_q})\" = \"{}\" ]; then\n",
                            action.size()
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
                match quarantine_dest(action, device, datasets, &ts) {
                    Some(dest) => {
                        let target_q = sh_quote(&target);
                        out.push_str(&format!(
                            "if [ \"$(stat -c%s -- {target_q})\" = \"{}\" ]; then\n",
                            action.size()
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

/// The preflight itself: every unique pathname the plan rests on, checked exactly once, plus D-4.
///
/// Every persisted member of every referenced allocation is here, not only targets and keepers —
/// an unmarked alias is precisely what decides whether removing its sibling releases anything, so a
/// script that does not check it is a script whose arithmetic nobody verified.
fn preflight_definition(plan: &ActionPlan) -> String {
    let mut out = String::new();
    out.push_str("# 0. Structural preflight. The whole plan is refused if anything moved.\n");
    out.push_str("dedcom_fail() { echo \"dedcom: $1\" >&2; exit 1; }\n");
    out.push_str("dedcom_expect() {\n");
    out.push_str(
        "  got=$(stat -c '%d %i %s %h %Y %Z' -- \"$1\" 2>/dev/null) || dedcom_fail \"missing since the plan: $1\"\n",
    );
    out.push_str(
        "  [ \"$got\" = \"$2\" ] || dedcom_fail \"changed since the plan: $1 (expected $2, got $got)\"\n",
    );
    out.push_str("}\n");
    out.push_str("dedcom_preflight() {\n");
    for object in plan.objects() {
        for path in object.members() {
            out.push_str(&format!(
                "  dedcom_expect {} {}\n",
                sh_quote(&path.to_string_lossy()),
                sh_quote(&expected_fields(object))
            ));
        }
    }
    for action in plan.actions() {
        let target = plan.target_object_of(action).key();
        let keeper = plan.keeper_object_of(action).key();
        out.push_str(&format!(
            "  [ '{} {}' != '{} {}' ] || dedcom_fail {}\n",
            target.device,
            target.inode,
            keeper.device,
            keeper.inode,
            sh_quote(&format!(
                "target and keeper are the same allocation: {}",
                crate::textsan::shell_label(&action.target().to_string_lossy())
            ))
        ));
    }
    out.push_str("}\n\n");
    out
}

/// The six integers GNU `stat` prints for `%d %i %s %h %Y %Z`, as the manifest recorded them.
fn expected_fields(object: &PlannedObject) -> String {
    let key = object.key();
    format!(
        "{} {} {} {} {} {}",
        key.device,
        key.inode,
        key.size,
        object.links(),
        key.mtime,
        key.ctime_sec
    )
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
fn quarantine_dest(
    action: &PlanAction,
    device: u64,
    datasets: &[Dataset],
    ts: &str,
) -> Option<PathBuf> {
    let dataset = dataset_for(datasets, device)?;
    let rel: PathBuf = match action.target().strip_prefix(&dataset.mountpoint) {
        Ok(rel) => rel.to_path_buf(),
        Err(_) => action
            .target()
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| action.target().to_path_buf()),
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
    use crate::model::plan::{
        MarkIntent, PlanGroupInput, PlanMemberEvidence, PlanObjectKey, RequestedMark,
    };
    use crate::model::reclaim::LinkCount;
    use crate::testfixtures::PlanScenario;
    use std::os::unix::fs::MetadataExt;

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

    fn key(device: u64, inode: u64) -> PlanObjectKey {
        PlanObjectKey {
            device,
            inode,
            size: 1024,
            mtime: 1_700_000_000,
            mtime_nsec: 0,
            ctime_sec: 1_700_000_001,
            ctime_nsec: 0,
            identity_version: 1,
        }
    }

    fn member(path: &str, key: PlanObjectKey, mark: Option<MarkIntent>) -> PlanMemberEvidence {
        PlanMemberEvidence::new(PathBuf::from(path), key, LinkCount::Known(1), mark)
            .expect("well-formed fixture member")
    }

    /// One keeper plus one target of the given kind, on one device.
    fn plan_of(kind: ActionKind, target: &str, keeper: &str, device: u64) -> ActionPlan {
        ActionPlan::try_new(
            1,
            vec![PlanGroupInput {
                hash: "ab".repeat(32),
                members: vec![
                    member(keeper, key(device, 10), Some(MarkIntent::Keeper)),
                    member(target, key(device, 11), Some(MarkIntent::Act(kind))),
                ],
            }],
        )
        .expect("a well-formed fixture plan")
    }

    #[test]
    fn delete_renders_snapshot_and_quarantine_move() {
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        let plan = plan_of(
            ActionKind::Delete,
            "/tank/dir/dup.bin",
            "/tank/keep.bin",
            42,
        );
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
        for (kind, expected) in [
            (ActionKind::Hardlink, "ln --"),
            (ActionKind::Reflink, "cp --reflink=always"),
        ] {
            let plan = plan_of(kind, "/tank/a.bin", "/tank/keep.bin", 7);
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
                script.contains("$(stat -c%s"),
                "size-guard before a destructive action"
            );
            assert!(script.contains(expected), "{kind:?}");
        }
    }

    #[test]
    fn an_action_without_a_dataset_is_skipped_not_executed() {
        // No dataset for the device → SKIP, no blind mv/ln.
        let datasets = vec![dataset("tank", "/tank", 7)];
        for kind in [ActionKind::Delete, ActionKind::Hardlink] {
            let plan = plan_of(kind, "/other/a.bin", "/other/k.bin", 99);
            let script = render_script(&plan, &datasets, ZFS);
            assert!(script.contains("SKIP"), "{kind:?}");
            assert!(!script.contains("rm -f"), "{kind:?}");
            assert!(!script.contains("ln --"), "{kind:?}");
            assert!(!script.contains("mv -n --"), "{kind:?}");
        }
    }

    #[test]
    fn paths_with_spaces_are_quoted() {
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = plan_of(ActionKind::Hardlink, "/tank/a b.bin", "/tank/keep.bin", 7);
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("'/tank/a b.bin'"));
    }

    #[test]
    fn control_bytes_in_filename_are_sanitized_in_comments() {
        // A name with a newline is an attempt to inject a command into the saved .sh.
        let datasets = vec![dataset("tank", "/tank", 7)];
        let evil = "/tank/x\nzfs destroy tank\n#.bin";
        let plan = plan_of(ActionKind::Hardlink, evil, "/tank/keep.bin", 7);
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
        let plan = plan_of(ActionKind::Hardlink, "/tank/a'b.bin", "/tank/keep.bin", 7);
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("dedcom: /tank/a?b.bin changed"));
    }

    #[test]
    fn untrusted_zfs_refuses_to_emit_actions() {
        // No trusted absolute zfs → fail-closed. The script exits with
        // exit 1 BEFORE any actions; no mv/ln/cp, and no preflight either — nothing runs.
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        let plan = plan_of(
            ActionKind::Delete,
            "/tank/dir/dup.bin",
            "/tank/keep.bin",
            42,
        );
        let script = render_script(&plan, &datasets, None);
        assert!(
            script.contains("exit 1"),
            "fail-closed: the script must exit with an error"
        );
        assert!(!script.contains("mv -n --"));
        assert!(!script.contains("dedcom_preflight"));
    }

    #[test]
    fn trusted_zfs_uses_absolute_path_not_bare() {
        // The snapshot goes via the trusted absolute path, not a bare `zfs`
        // (otherwise PATH-injection under root). There's no bare `zfs snapshot` string at the start.
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        let plan = plan_of(
            ActionKind::Delete,
            "/tank/dir/dup.bin",
            "/tank/keep.bin",
            42,
        );
        let script = render_script(&plan, &datasets, ZFS);
        assert!(script.contains("/usr/sbin/zfs snapshot"));
        assert!(
            !script.lines().any(|l| l.starts_with("zfs snapshot")),
            "the snapshot must not be called via a bare `zfs`"
        );
    }

    #[test]
    fn delete_has_no_size_guard_but_hardlink_does() {
        // Delete — evacuation to quarantine without a per-action size-guard (recoverable); only
        // hardlink/reflink have one. The whole-plan preflight covers both either way.
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        let del = plan_of(ActionKind::Delete, "/tank/d.bin", "/tank/k.bin", 42);
        let del_script = render_script(&del, &datasets, ZFS);
        let guards = del_script
            .lines()
            .filter(|line| line.contains("$(stat -c%s"))
            .count();
        assert_eq!(
            guards, 0,
            "Delete does not perform a per-action size-guard (evacuation is recoverable)"
        );

        let hl = plan_of(ActionKind::Hardlink, "/tank/a.bin", "/tank/k.bin", 42);
        let hl_script = render_script(&hl, &datasets, ZFS);
        assert!(
            hl_script.contains("$(stat -c%s"),
            "hardlink has a size-guard"
        );
    }

    /// The preflight has to be in both places, and it has to check every persisted pathname —
    /// including the alias nobody marked, which is what makes the plan's figure a zero.
    #[test]
    fn the_preflight_is_emitted_before_and_after_the_snapshots() {
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = ActionPlan::try_new(
            1,
            vec![PlanGroupInput {
                hash: "cd".repeat(32),
                members: vec![
                    member("/tank/keep.bin", key(7, 10), Some(MarkIntent::Keeper)),
                    PlanMemberEvidence::new(
                        PathBuf::from("/tank/alias_a.bin"),
                        key(7, 11),
                        LinkCount::Known(2),
                        Some(MarkIntent::Act(ActionKind::Delete)),
                    )
                    .unwrap(),
                    PlanMemberEvidence::new(
                        PathBuf::from("/tank/alias_b.bin"),
                        key(7, 11),
                        LinkCount::Known(2),
                        None,
                    )
                    .unwrap(),
                ],
            }],
        )
        .unwrap();
        let script = render_script(&plan, &datasets, ZFS);

        let calls: Vec<usize> = script
            .lines()
            .enumerate()
            .filter(|(_, line)| line.trim() == "dedcom_preflight")
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            calls.len(),
            2,
            "one before the snapshots, one after:\n{script}"
        );
        let snapshot = script
            .lines()
            .position(|line| line.contains("zfs snapshot"))
            .expect("a snapshot line");
        let first_mutation = script
            .lines()
            .position(|line| line.starts_with("mv -n --"))
            .expect("a destructive line");
        assert!(calls[0] < snapshot, "the first call precedes the snapshot");
        assert!(
            snapshot < calls[1] && calls[1] < first_mutation,
            "the second call sits between the snapshot and the first change"
        );
        // Every pathname exactly once, the unmarked alias included.
        for path in ["/tank/keep.bin", "/tank/alias_a.bin", "/tank/alias_b.bin"] {
            assert_eq!(
                script
                    .lines()
                    .filter(|line| line.trim_start().starts_with("dedcom_expect")
                        && line.contains(path))
                    .count(),
                1,
                "{path} is checked exactly once"
            );
        }
        assert!(
            script.contains("7 11 1024 2 1700000000 1700000001"),
            "the expectation is the six integers GNU stat prints:\n{script}"
        );
        assert!(script.contains("dedcom_fail 'target and keeper are the same allocation"));
    }

    /// The saved script is a real apply route, so its preflight has to actually run: on a drifted
    /// fixture it must exit non-zero before the snapshot command and before anything is moved.
    #[test]
    fn a_drifted_fixture_stops_the_script_before_the_snapshot() {
        let scenario = PlanScenario::new("script_drift");
        let keeper = scenario.file("keeper.bin");
        let alias_a = scenario.file("alias_a.bin");
        let alias_b = scenario.link(&alias_a, "alias_b.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_a.clone(), alias_b.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_a,
            false,
            Some(ActionKind::Delete),
        );
        scenario.mark(
            &mut store,
            scan_id,
            &alias_b,
            false,
            Some(ActionKind::Delete),
        );
        drop(store);
        let plan = store_plan(&scenario, scan_id);

        let datasets = vec![Dataset {
            name: "tank".to_string(),
            mountpoint: scenario.root.clone(),
            device_id: Some(std::fs::symlink_metadata(&scenario.root).unwrap().dev()),
            snapdir_visible: false,
        }];
        // `echo` stands in for `zfs`: if the snapshot section is ever reached it says so on stdout.
        let script = render_script(&plan, &datasets, Some("/bin/echo"));
        let path = scenario.root.join("plan.sh");
        std::fs::write(&path, &script).unwrap();

        let parsed = std::process::Command::new("bash")
            .arg("-n")
            .arg(&path)
            .status()
            .expect("bash is available in the build image");
        assert!(
            parsed.success(),
            "the generated script must parse:\n{script}"
        );

        // One alias goes away after the script was written — exactly the drift row 9 describes.
        std::fs::remove_file(&alias_b).unwrap();
        let run = std::process::Command::new("bash")
            .arg(&path)
            .output()
            .expect("bash is available in the build image");
        assert!(!run.status.success(), "a drifted plan must not run");
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            !stdout.contains("snapshot"),
            "it must stop before the snapshot section: {stdout}"
        );
        // Unlinking one pathname of an allocation moves its siblings' link count and `ctime`, so
        // the preflight reaches `alias_a` first and reports the change there.
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            stderr.contains("since the plan") && stderr.contains("alias_a.bin"),
            "and say what moved: {stderr}"
        );
        assert!(alias_a.exists(), "nothing was moved");
    }

    /// The plan the store builds from the marks a scenario already holds.
    fn store_plan(scenario: &PlanScenario, scan_id: i64) -> ActionPlan {
        let requested: Vec<RequestedMark> = Vec::new();
        scenario
            .store()
            .build_action_plan(scan_id, &requested)
            .expect("the scenario's marks make a plan")
    }
}
