// SPDX-License-Identifier: Apache-2.0
//! Preview of the action plan as a shell script.
//!
//! The "paranoid" user reads the real commands before [Y] — or saves (`S`) and runs them himself,
//! which makes this a real apply route and not a picture of one. It therefore takes the steps [Y]
//! takes. The whole-plan structural preflight runs twice: once before the snapshot section and once
//! after it, immediately before the first action — `stat -c '%d %i %s %h %Y %Z'`, all integers.
//! Each action then refuses a file or keeper that has become a symbolic link and compares the file
//! with the keeper byte for byte (`cmp`, where [Y] re-hashes), builds the replacement in the file's
//! own directory, moves the file to the quarantine only when that worked and the quarantine is on
//! the mount the file is reached through, and brings it back when publishing fails; a reflink copy
//! gets the replaced file's owner, mode, times, xattrs and ACL. `mv -n` exits 0 when it moved
//! nothing, so a move counts only by the inode it left in its destination. An action that fails is
//! named and does not stop the others; the run then ends with status 1. GNU coreutils, `cmp` and
//! `findmnt` only. The timestamp is baked in at the moment of rendering — paths can safely be
//! enclosed in single quotes.

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
    out.push_str(SCRIPT_HEADER);
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
    out.push_str(&action_definitions(plan, datasets));
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

    let total = plan.actions().len();
    out.push_str(&format!("# 4. Actions: {total} total.\n"));
    out.push_str("dedcom_failed=0\n");
    for action in plan.actions() {
        let device = plan.target_object_of(action).key().device;
        let target = action.target().to_string_lossy();
        let keeper = action.keeper().to_string_lossy();
        // A file name in .sh comments/echo may contain a newline or a
        // single quote → command injection under root when the plan is saved and run.
        // For DISPLAY we take the sanitized label; the real command arguments — via sh_quote
        // (where a newline inside '…' stays a literal and is safe).
        let target_label = crate::textsan::shell_label(&target);
        let (step, what) = match action.kind() {
            ActionKind::Delete => ("dedcom_delete", "delete (move to quarantine)"),
            ActionKind::Hardlink => (
                "dedcom_hardlink",
                "hardlink to keeper (link beside it, then the file to quarantine)",
            ),
            ActionKind::Reflink => (
                "dedcom_reflink",
                "reflink (clone beside it, then the file to quarantine)",
            ),
        };
        out.push_str(&format!("# {what}: {target_label}\n"));
        let Some(dest) = quarantine_dest(action, device, datasets, &ts) else {
            // Without a dataset there is no quarantine, and nothing is done blindly.
            out.push_str(&format!(
                "#    SKIP: dataset for {target_label} not determined\n"
            ));
            out.push_str(&format!(
                "echo {} >&2\ndedcom_failed=$((dedcom_failed + 1))\n",
                sh_quote(&format!(
                    "dedcom: skip {target_label}: its dataset was not determined"
                ))
            ));
            continue;
        };
        let dest = dest.to_string_lossy();
        let mut call = format!(
            "{step} {} {} {} {}",
            sh_quote(&target),
            sh_quote(&keeper),
            sh_quote(&dest),
            sh_quote(&target_label)
        );
        if action.kind() != ActionKind::Delete {
            // The replacement is made in the file's own directory — `/` for a file at the root,
            // which is exactly what a shell stripping the last name would get wrong.
            let dir = action.target().parent().unwrap_or(Path::new("/"));
            call.push(' ');
            call.push_str(&sh_quote(&crate::textsan::shell_label(&dest)));
            call.push(' ');
            call.push_str(&sh_quote(&dir.to_string_lossy()));
        }
        out.push_str(&format!("{call} || dedcom_failed=$((dedcom_failed + 1))\n"));
    }
    out.push_str(&format!(
        "\nif [ \"$dedcom_failed\" -ne 0 ]; then\n  echo \"dedcom: $dedcom_failed of {total} {} \
         not carried out — each is named above\" >&2\n  exit 1\nfi\n",
        if total == 1 { "action" } else { "actions" }
    ));
    out.push_str("echo 'dedcom: plan executed.'\n");
    out
}

/// What the script's reader is told before anything runs.
const SCRIPT_HEADER: &str = "\
# Before anything moves, the script checks the STRUCTURE of every file of the plan: device,
# inode, size, link count and the SECONDS of mtime/ctime. Before each action it compares the
# file with its keeper byte for byte (cmp) — for a file it acts on, that reads both in full,
# as `dedcom --strict-verify` does — and leaves alone a file that differs or has become a
# symbolic link. A replacement is made beside the file first; the file goes to the quarantine
# only when that worked and comes back if publishing fails. A reflink copy gets the owner,
# mode, times, extended attributes and ACL of the file it replaces. An action that fails is
# named and does not stop the others; the run then ends with exit status 1. Between a check
# and its command there is still a window (TOCTOU); recovery is from the quarantine and the
# safety snapshot.
";

/// The steps every action shares, as [Y] takes them. The symbolic-link check and `cmp` stand for
/// [Y]'s checks at the moment of the action (a link swapped in, a re-hash). `mv -n` exits 0 when
/// its destination was taken and it moved nothing (GNU coreutils 9.1 and 9.7), so a move into the
/// quarantine counts only when the quarantine holds the file's inode. Across mounts `mv` copies and
/// deletes where [Y]'s `renameat2` refuses — and not only across filesystems: a file reached
/// through a bind mount carries its dataset's device number, yet the quarantine under the
/// dataset's own mountpoint is another mount. So the move goes ahead only when `findmnt` finds the
/// file and the quarantine directory on one mount, and a refusal says so: no tool line names that
/// reason. Every step is checked by hand: the functions run behind `||`, where bash ignores
/// `set -e`.
const SHELL_COMMON: &str = r#"dedcom_note() { echo "dedcom: $*" >&2; }
dedcom_id() { stat -c '%d %i' -- "$1" 2>/dev/null; }
dedcom_mount() { findmnt -n -o ID -T "$1"; }
dedcom_same() {
  if [ -L "$1" ] || [ -L "$2" ]; then
    dedcom_note "skip $3: it or its keeper is a symbolic link"
    return 1
  fi
  cmp -s -- "$2" "$1"
  case $? in
    0) return 0 ;;
    1) dedcom_note "skip $3: its content is no longer the keeper's" ;;
    *) dedcom_note "skip $3: it could not be compared with its keeper" ;;
  esac
  return 1
}
dedcom_evacuate() {
  local here there
  mkdir -p -- "${3%/*}" && here=$(dedcom_mount "$1") && there=$(dedcom_mount "${3%/*}") &&
    [ -n "$here" ] || return 1
  if [ "$there" != "$here" ]; then
    dedcom_note "$4: the quarantine is on another mount than the file (a bind mount?)"
    return 1
  fi
  mv -n -- "$1" "$3" && [ "$(dedcom_id "$3")" = "$2" ]
}
"#;

const SHELL_DELETE: &str = r#"dedcom_delete() {
  local id
  dedcom_same "$1" "$2" "$4" || return 1
  if id=$(dedcom_id "$1") && dedcom_evacuate "$1" "$id" "$3" "$4"; then
    return 0
  fi
  dedcom_note "not moved to the quarantine: $4"
  return 1
}
"#;

/// A replacement is built beside the file, the file goes to the quarantine, the replacement takes
/// its place — and when that last step fails, the file comes back (`evacuate_then_publish` in
/// `actions/mod.rs`). Only a replacement this script made is ever removed, told by its inode: a
/// file renamed over its name is named and left. (An inode number is all a script has; a file made
/// after somebody deleted the replacement could reuse it — within milliseconds, under a random
/// name, which no one does by chance.)
const SHELL_REPLACE: &str = r#"dedcom_drop() {
  if [ "$(dedcom_id "$1")" = "$2" ] && rm -f -- "$1"; then
    return 0
  fi
  [ -e "$1" ] || [ -L "$1" ] || return 0
  dedcom_note "$3: the temporary file ${1##*/} beside it is left behind — delete it by hand"
}
dedcom_publish() {
  if ! dedcom_evacuate "$1" "$2" "$3" "$6"; then
    dedcom_drop "$4" "$5" "$6"
    dedcom_note "not replaced: $6 — it could not be moved to the quarantine"
    return 1
  fi
  mv -n -- "$4" "$1"
  if [ "$(dedcom_id "$1")" = "$5" ] && ! [ -e "$4" ]; then
    return 0
  fi
  dedcom_drop "$4" "$5" "$6"
  mv -n -- "$3" "$1"
  if [ "$(dedcom_id "$1")" = "$2" ]; then
    dedcom_note "not replaced: $6 — the replacement could not be published; the original is back in its place"
  else
    dedcom_note "not replaced: $6 — the replacement could not be published; the original stays in the quarantine: $7"
  fi
  return 1
}
"#;

/// `ln` refuses a name that exists, so the unique name `mktemp -u` offers is never somebody's file.
/// The replacement goes into the file's own directory, `$6`, which the renderer works out.
const SHELL_HARDLINK: &str = r#"dedcom_hardlink() {
  local id stage
  dedcom_same "$1" "$2" "$4" || return 1
  if id=$(dedcom_id "$1") && stage=$(mktemp -u -p "$6" --suffix=.tmp .dedcom-XXXXXXXXXX) &&
    ln -- "$2" "$stage"; then
    dedcom_publish "$1" "$id" "$3" "$stage" "$(dedcom_id "$stage")" "$4" "$5"
    return
  fi
  dedcom_note "not replaced: $4 — the link could not be made beside it"
  return 1
}
"#;

/// `cp --reflink=always` writes over whatever is at its destination, so the clone goes into a file
/// `mktemp` has just made. Over such a file overlayfs answers 0 and leaves it empty, and coreutils
/// 9.1 leaves an empty file behind a failed clone — the size is what says the clone happened.
/// `cp --attributes-only` then carries the replaced file's owner, mode (with its ACL), times and
/// xattrs, read while it is still in place; without root it skips the owner silently, so the owner
/// and mode are compared afterwards.
const SHELL_REFLINK: &str = r#"dedcom_reflink() {
  local id stage made
  dedcom_same "$1" "$2" "$4" || return 1
  if ! id=$(dedcom_id "$1") || ! stage=$(mktemp -p "$6" --suffix=.tmp .dedcom-XXXXXXXXXX); then
    dedcom_note "not replaced: $4 — the clone could not be made beside it"
    return 1
  fi
  made=$(dedcom_id "$stage")
  if ! cp --reflink=always -- "$2" "$stage" ||
    [ "$(stat -c %s -- "$stage")" != "$(stat -c %s -- "$2")" ]; then
    dedcom_drop "$stage" "$made" "$4"
    dedcom_note "not replaced: $4 — the clone could not be made beside it"
    return 1
  fi
  if ! cp --attributes-only --preserve=mode,ownership,timestamps,xattr -- "$1" "$stage" ||
    [ "$(stat -c '%u %g %a' -- "$stage")" != "$(stat -c '%u %g %a' -- "$1")" ]; then
    dedcom_drop "$stage" "$made" "$4"
    dedcom_note "not replaced: $4 — its owner, mode, times or extended attributes could not be carried over"
    return 1
  fi
  dedcom_publish "$1" "$id" "$3" "$stage" "$made" "$4" "$5"
}
"#;

/// The functions the plan's actions call, defined once before the first of them runs. Only what the
/// plan uses is written, so the script of a plan of deletes carries no clone machinery. An action
/// whose dataset was not determined calls nothing.
fn action_definitions(plan: &ActionPlan, datasets: &[Dataset]) -> String {
    let mut kinds: Vec<ActionKind> = Vec::new();
    for action in plan.actions() {
        let device = plan.target_object_of(action).key().device;
        if dataset_for(datasets, device).is_some() && !kinds.contains(&action.kind()) {
            kinds.push(action.kind());
        }
    }
    if kinds.is_empty() {
        return String::new();
    }
    let mut out = String::from("# 0b. Each action, step by step as applying with [Y] takes it.\n");
    out.push_str(SHELL_COMMON);
    if kinds.contains(&ActionKind::Delete) {
        out.push_str(SHELL_DELETE);
    }
    if kinds.contains(&ActionKind::Hardlink) || kinds.contains(&ActionKind::Reflink) {
        out.push_str(SHELL_REPLACE);
    }
    if kinds.contains(&ActionKind::Hardlink) {
        out.push_str(SHELL_HARDLINK);
    }
    if kinds.contains(&ActionKind::Reflink) {
        out.push_str(SHELL_REFLINK);
    }
    out.push('\n');
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
        GroupId, MarkIntent, PlanGroupInput, PlanMemberEvidence, PlanObjectKey, RequestedMark,
    };
    use crate::model::reclaim::LinkCount;
    use crate::testfixtures::PlanScenario;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Trusted absolute path to zfs for tests: in the Docker image zfs is not installed,
    // so the real `trusted_zfs_bin()` would return None — we inject the path explicitly.
    const ZFS: Option<&str> = Some("/usr/sbin/zfs");

    fn dataset(name: &str, mountpoint: &str, device: u64) -> Dataset {
        Dataset {
            name: name.to_string(),
            mountpoint: PathBuf::from(mountpoint),
            device_id: Some(device),
            snapdir_visible: false,
            block_cloning: None,
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
                id: GroupId {
                    scan_id: 1,
                    rank: 0,
                    generation: 1,
                },
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

    /// Hardlink and reflink build the replacement beside the file and only then move the file to
    /// the quarantine. The one removal in the script is of a replacement the script made itself.
    #[test]
    fn hardlink_and_reflink_render_expected_commands() {
        let datasets = vec![dataset("tank", "/tank", 7)];
        for (kind, step, expected) in [
            (
                ActionKind::Hardlink,
                "dedcom_hardlink",
                "ln -- \"$2\" \"$stage\"",
            ),
            (
                ActionKind::Reflink,
                "dedcom_reflink",
                "cp --reflink=always -- \"$2\" \"$stage\"",
            ),
        ] {
            let plan = plan_of(kind, "/tank/a.bin", "/tank/keep.bin", 7);
            let script = render_script(&plan, &datasets, ZFS);
            assert!(script.contains(expected), "{kind:?}:\n{script}");
            assert!(
                script.contains("mv -n -- \"$1\" \"$3\""),
                "the file is moved to the quarantine"
            );
            let call = script
                .lines()
                .find(|line| line.starts_with(&format!("{step} ")))
                .unwrap_or_else(|| panic!("a call of {step}:\n{script}"));
            assert!(
                call.starts_with(&format!(
                    "{step} '/tank/a.bin' '/tank/keep.bin' '/tank/{QUARANTINE_DIR_NAME}/"
                )),
                "{call}"
            );
            assert!(
                call.ends_with(" '/tank' || dedcom_failed=$((dedcom_failed + 1))"),
                "the replacement is made in the file's own directory: {call}"
            );
            let removals: Vec<&str> = script
                .lines()
                .filter(|line| line.split_whitespace().any(|word| word == "rm"))
                .collect();
            assert_eq!(
                removals,
                ["  if [ \"$(dedcom_id \"$1\")\" = \"$2\" ] && rm -f -- \"$1\"; then"],
                "only dedcom_drop removes anything, and only by inode"
            );
        }
    }

    #[test]
    fn an_action_without_a_dataset_is_skipped_not_executed() {
        // No dataset for the device → SKIP, no blind mv/ln, and the run counts it as not done.
        let datasets = vec![dataset("tank", "/tank", 7)];
        for kind in [ActionKind::Delete, ActionKind::Hardlink] {
            let plan = plan_of(kind, "/other/a.bin", "/other/k.bin", 99);
            let script = render_script(&plan, &datasets, ZFS);
            assert!(script.contains("SKIP"), "{kind:?}");
            assert!(!script.contains("rm -f"), "{kind:?}");
            assert!(!script.contains("ln --"), "{kind:?}");
            assert!(!script.contains("mv -n --"), "{kind:?}");
            assert!(
                script.contains(
                    "echo 'dedcom: skip /other/a.bin: its dataset was not determined' >&2\n\
                     dedcom_failed=$((dedcom_failed + 1))\n"
                ),
                "{kind:?}:\n{script}"
            );
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
    fn single_quote_in_filename_does_not_break_the_script() {
        // A single quote in the name must not break out of its quoting: the path travels as
        // `'\''`, the label the messages print is cleaned, and the whole script still parses.
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = plan_of(ActionKind::Hardlink, "/tank/a'b.bin", "/tank/keep.bin", 7);
        let script = render_script(&plan, &datasets, ZFS);
        assert!(
            script.contains("dedcom_hardlink '/tank/a'\\''b.bin' '/tank/keep.bin' "),
            "{script}"
        );
        assert!(
            script.contains(" '/tank/a?b.bin' "),
            "the label is cleaned: {script}"
        );
        assert_parses(&script);
    }

    /// `bash -n` over the script: it has to parse whatever the plan holds.
    fn assert_parses(script: &str) {
        let scratch = crate::testfixtures::ScratchDir::new("script_parse");
        let path = scratch.path().join("plan.sh");
        std::fs::write(&path, script).unwrap();
        let parsed = std::process::Command::new("bash")
            .arg("-n")
            .arg(&path)
            .output()
            .expect("bash is available in the build image");
        assert!(
            parsed.status.success(),
            "{}\n{script}",
            String::from_utf8_lossy(&parsed.stderr)
        );
    }

    /// The script of every kind of action parses, and so does one that holds all three.
    #[test]
    fn the_script_of_every_kind_parses() {
        let datasets = vec![dataset("tank", "/tank", 7)];
        for kind in [
            ActionKind::Delete,
            ActionKind::Hardlink,
            ActionKind::Reflink,
        ] {
            assert_parses(&render_script(
                &plan_of(kind, "/tank/a.bin", "/tank/keep.bin", 7),
                &datasets,
                ZFS,
            ));
        }
        let stand = Stand::new("script_parse_all");
        let keeper = stand.file("keep.bin", b"bytes");
        let deleted = stand.file("d.bin", b"bytes");
        let linked = stand.file("h.bin", b"bytes");
        let cloned = stand.file("r.bin", b"bytes");
        let script = stand.render(&real_plan(
            &keeper,
            &[
                (&deleted, ActionKind::Delete),
                (&linked, ActionKind::Hardlink),
                (&cloned, ActionKind::Reflink),
            ],
        ));
        for step in [
            "dedcom_delete() {",
            "dedcom_hardlink() {",
            "dedcom_reflink() {",
        ] {
            assert_eq!(script.matches(step).count(), 1, "{step} is defined once");
        }
        assert_parses(&script);
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

    /// Every kind compares the file with its keeper before anything else — the check `Y` makes by
    /// re-hashing, which the old per-action size guard stood in for only for hardlink and reflink.
    #[test]
    fn every_action_compares_the_file_with_its_keeper_first() {
        let datasets = vec![dataset("tank/data", "/tank", 42)];
        for (kind, step) in [
            (ActionKind::Delete, "dedcom_delete() {"),
            (ActionKind::Hardlink, "dedcom_hardlink() {"),
            (ActionKind::Reflink, "dedcom_reflink() {"),
        ] {
            let script = render_script(
                &plan_of(kind, "/tank/d.bin", "/tank/k.bin", 42),
                &datasets,
                ZFS,
            );
            let first_step = script
                .lines()
                .skip_while(|line| *line != step)
                .skip(1)
                .find(|line| !line.trim_start().starts_with("local "))
                .unwrap_or_else(|| panic!("{step} is defined:\n{script}"));
            assert_eq!(
                first_step.trim(),
                "dedcom_same \"$1\" \"$2\" \"$4\" || return 1",
                "{kind:?}"
            );
            assert!(!script.contains("$(stat -c%s"), "the size guard is gone");
        }
    }

    /// The preflight has to be in both places, and it has to check every persisted pathname —
    /// including the alias nobody marked, which is what makes the plan's figure a zero.
    #[test]
    fn the_preflight_is_emitted_before_and_after_the_snapshots() {
        let datasets = vec![dataset("tank", "/tank", 7)];
        let plan = ActionPlan::try_new(
            1,
            vec![PlanGroupInput {
                id: GroupId {
                    scan_id: 1,
                    rank: 0,
                    generation: 1,
                },
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
        let first_action = script
            .lines()
            .position(|line| line.starts_with("dedcom_delete "))
            .expect("the call of the first action");
        assert!(calls[0] < snapshot, "the first call precedes the snapshot");
        assert!(
            snapshot < calls[1] && calls[1] < first_action,
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
            block_cloning: None,
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

    // The saved script run for real: `bash`, the build image's coreutils and `findmnt` (which reads
    // `/proc/self/mountinfo`), files on disk. A tool whose answer depends on the filesystem or the
    // mounts under the test — `cp --reflink=always`, `findmnt` for another mount — is stood in for
    // on `PATH`, so no test here depends on what the machine running it can clone or mount.

    /// Real files a generated script runs against: the dataset's directory (`pool`), stand-in
    /// tools put first on `PATH` (`bin`), and the script itself beside them.
    struct Stand {
        scratch: crate::testfixtures::ScratchDir,
    }

    impl Stand {
        fn new(tag: &str) -> Self {
            let scratch = crate::testfixtures::ScratchDir::new(tag);
            std::fs::create_dir_all(scratch.path().join("pool")).unwrap();
            std::fs::create_dir_all(scratch.path().join("bin")).unwrap();
            Self { scratch }
        }

        fn pool(&self) -> PathBuf {
            self.scratch.path().join("pool")
        }

        fn file(&self, name: &str, content: &[u8]) -> PathBuf {
            let path = self.pool().join(name);
            std::fs::write(&path, content).unwrap();
            path
        }

        fn datasets(&self) -> Vec<Dataset> {
            vec![Dataset {
                name: "tank".to_string(),
                mountpoint: self.pool(),
                device_id: Some(std::fs::symlink_metadata(self.pool()).unwrap().dev()),
                snapdir_visible: false,
                block_cloning: None,
            }]
        }

        /// `tool` answers with `body`, a `sh` script first on `PATH`; `$REAL` in it is the tool
        /// `bash` would have run.
        fn stand_in(&self, tool: &str, body: &str) {
            let path = self.scratch.path().join("bin").join(tool);
            let real = real_tool(tool);
            std::fs::write(
                &path,
                format!("#!/bin/sh\nREAL='{}'\n{body}\n", real.display()),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        /// `echo` stands in for `zfs`, as in the drift test above.
        fn render(&self, plan: &ActionPlan) -> String {
            render_script(plan, &self.datasets(), Some("/bin/echo"))
        }

        fn run(&self, script: &str) -> std::process::Output {
            let path = self.scratch.path().join("plan.sh");
            std::fs::write(&path, script).unwrap();
            let search = format!(
                "{}:{}",
                self.scratch.path().join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            );
            std::process::Command::new("bash")
                .arg(&path)
                .env("PATH", search)
                .output()
                .expect("bash is available in the build image")
        }

        /// Every file under the dataset's quarantine.
        fn quarantined(&self) -> Vec<PathBuf> {
            fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk(&path, found);
                    } else {
                        found.push(path);
                    }
                }
            }
            let mut found = Vec::new();
            walk(&self.pool().join(QUARANTINE_DIR_NAME), &mut found);
            found
        }
    }

    /// The tool `bash` finds on `PATH` without the stand-ins.
    fn real_tool(tool: &str) -> PathBuf {
        std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .map(|dir| Path::new(dir).join(tool))
            .find(|path| path.is_file())
            .unwrap_or_else(|| panic!("{tool} is on PATH in the build image"))
    }

    /// `cp --reflink=always` answering as it does on a pool without block cloning.
    const CP_CANNOT_CLONE: &str = "for arg; do\n  [ \"$arg\" = --reflink=always ] && { echo 'cp: failed to clone: Operation not supported' >&2; exit 1; }\ndone\nexec \"$REAL\" \"$@\"";

    /// `cp --reflink=always` as a plain copy: the same fresh inode with the runner's identity that
    /// a clone gives, which is what carrying the metadata over is about (as in `reflink.rs`).
    const CP_CLONE_AS_COPY: &str = "for arg; do\n  shift\n  [ \"$arg\" = --reflink=always ] || set -- \"$@\" \"$arg\"\ndone\nexec \"$REAL\" \"$@\"";

    /// A plan over real files, each member keyed by its real `stat` — what a scan would have
    /// recorded, whatever the files hold now. The plan never reads content, so files of different
    /// content can stand for one group: exactly the case only a check of the content sees.
    fn real_plan(keeper: &Path, targets: &[(&Path, ActionKind)]) -> ActionPlan {
        let mut members = vec![real_member(keeper, Some(MarkIntent::Keeper))];
        for (target, kind) in targets {
            members.push(real_member(target, Some(MarkIntent::Act(*kind))));
        }
        ActionPlan::try_new(
            1,
            vec![PlanGroupInput {
                id: GroupId {
                    scan_id: 1,
                    rank: 0,
                    generation: 1,
                },
                hash: "ef".repeat(32),
                members,
            }],
        )
        .expect("a well-formed plan over real files")
    }

    fn real_member(path: &Path, mark: Option<MarkIntent>) -> PlanMemberEvidence {
        let meta = std::fs::symlink_metadata(path).unwrap();
        let key = PlanObjectKey {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            identity_version: 1,
        };
        PlanMemberEvidence::new(
            path.to_path_buf(),
            key,
            LinkCount::Known(meta.nlink()),
            mark,
        )
        .expect("a well-formed member")
    }

    fn inode(path: &Path) -> u64 {
        std::fs::symlink_metadata(path).unwrap().ino()
    }

    /// The quarantine path the script uses for `name` — the render's own timestamp is in it.
    fn quarantine_path_in(script: &str, name: &str) -> PathBuf {
        let marker = format!("/{QUARANTINE_DIR_NAME}/");
        script
            .split('\'')
            .find(|piece| piece.contains(&marker) && piece.ends_with(name))
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("no quarantine path for {name} in:\n{script}"))
    }

    /// Sets an extended attribute, reporting whether the filesystem under the test does them at
    /// all — a missing xattr there is not a failure of ours.
    fn set_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let name_c = std::ffi::CString::new(name).unwrap();
        // SAFETY: both strings live across the call, and the value slice is passed with its len.
        unsafe {
            libc::lsetxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            ) == 0
        }
    }

    fn xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let name_c = std::ffi::CString::new(name).unwrap();
        let mut value = vec![0u8; 256];
        // SAFETY: the buffer is passed with its real length and outlives the call.
        let size = unsafe {
            libc::lgetxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_mut_ptr() as *mut libc::c_void,
                value.len(),
            )
        };
        (size >= 0).then(|| {
            value.truncate(size as usize);
            value
        })
    }

    /// Both timestamps of `path`, to the nanosecond.
    fn set_times(path: &Path, sec: i64, nsec: i64) {
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let time = libc::timespec {
            tv_sec: sec as _,
            tv_nsec: nsec as _,
        };
        let times = [time, time];
        // SAFETY: the path string and the two-element array live across the call.
        let set = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                path_c.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        assert_eq!(set, 0, "utimensat {}", path.display());
    }

    /// A clone that cannot be made leaves the file where it was. The script used to move the
    /// file into the quarantine first and clone it after, so a pool without block cloning left the
    /// path empty and stopped the rest of the plan there.
    #[test]
    fn a_reflink_that_cannot_be_made_leaves_the_file_in_place() {
        let stand = Stand::new("script_clone_refused");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);
        stand.stand_in("cp", CP_CANNOT_CLONE);

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Reflink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(target.exists(), "the file is still in its place: {stderr}");
        assert_eq!(inode(&target), original, "the original itself, not a copy");
        assert_eq!(std::fs::read(&target).unwrap(), b"the same bytes");
        assert!(
            stand.quarantined().is_empty(),
            "nothing went to the quarantine: {:?}",
            stand.quarantined()
        );
        assert!(
            !run.status.success(),
            "an action not carried out fails the run"
        );
        assert!(
            stderr.contains("dup.bin"),
            "the line names the file: {stderr}"
        );
    }

    /// The plan's structure still matches, the content does not — a rewrite of the same size
    /// inside the second the scan recorded. `Y` re-hashes and cancels; the script must not link
    /// over such a file or move it away either.
    #[test]
    fn a_file_whose_content_is_no_longer_the_keepers_is_left_alone() {
        let stand = Stand::new("script_content");
        let keeper = stand.file("keep.bin", b"keeper bytes");
        let linked = stand.file("link-me.bin", b"other  bytes");
        let deleted = stand.file("delete-me.bin", b"third  bytes");
        let plan = real_plan(
            &keeper,
            &[
                (&linked, ActionKind::Hardlink),
                (&deleted, ActionKind::Delete),
            ],
        );

        let run = stand.run(&stand.render(&plan));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert_eq!(
            std::fs::read(&linked).ok().as_deref(),
            Some(&b"other  bytes"[..]),
            "not linked over: {stderr}"
        );
        assert_eq!(
            std::fs::read(&deleted).ok().as_deref(),
            Some(&b"third  bytes"[..]),
            "not moved away: {stderr}"
        );
        assert!(stand.quarantined().is_empty(), "{:?}", stand.quarantined());
        assert!(!run.status.success(), "{stderr}");
        assert!(
            stderr.contains("link-me.bin") && stderr.contains("delete-me.bin"),
            "{stderr}"
        );
    }

    /// One action that cannot run does not stop the rest, as with `Y`: the delete still happens,
    /// the refused clone keeps its file, and the run says how many were not carried out.
    #[test]
    fn one_action_that_cannot_run_does_not_stop_the_others() {
        let stand = Stand::new("script_goes_on");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let cloned = stand.file("clone-me.bin", b"the same bytes");
        let deleted = stand.file("delete-me.bin", b"the same bytes");
        stand.stand_in("cp", CP_CANNOT_CLONE);
        let plan = real_plan(
            &keeper,
            &[
                (&cloned, ActionKind::Reflink),
                (&deleted, ActionKind::Delete),
            ],
        );

        let run = stand.run(&stand.render(&plan));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(cloned.exists(), "the refused clone kept its file: {stderr}");
        assert!(!deleted.exists(), "the delete ran: {stderr}");
        assert_eq!(stand.quarantined().len(), 1, "{:?}", stand.quarantined());
        assert!(!run.status.success(), "{stderr}");
        assert!(
            stderr.contains("1 of 2 actions not carried out"),
            "{stderr}"
        );
    }

    /// The clone the script publishes carries the replaced file's mode, times and extended
    /// attributes — and its owner, when the run may hand files to others — as `Y` does.
    #[test]
    fn a_reflinked_file_keeps_its_owner_mode_times_and_attributes() {
        let stand = Stand::new("script_clone_identity");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        std::fs::set_permissions(&keeper, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let carried = set_xattr(&target, "user.dedcom_test", b"carry me");
        // SAFETY: euid is a plain read of process state.
        let root = unsafe { libc::geteuid() } == 0;
        if root {
            let target_c = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
            // SAFETY: the path string lives across the call.
            assert_eq!(unsafe { libc::lchown(target_c.as_ptr(), 12345, 12345) }, 0);
        }
        set_times(&target, 1_000_000_000, 123_456_789);
        let original = inode(&target);
        stand.stand_in("cp", CP_CLONE_AS_COPY);

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Reflink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(run.status.success(), "{stderr}");
        let after = std::fs::symlink_metadata(&target).unwrap();
        assert_ne!(after.ino(), original, "the replacement was published");
        assert_eq!(after.mode() & 0o7777, 0o640, "the replaced file's mode");
        assert_eq!(
            (after.mtime(), after.mtime_nsec()),
            (1_000_000_000, 123_456_789),
            "the replaced file's modification time"
        );
        if root {
            assert_eq!((after.uid(), after.gid()), (12345, 12345), "its owner");
        }
        if carried {
            assert_eq!(
                xattr(&target, "user.dedcom_test").as_deref(),
                Some(&b"carry me"[..]),
                "its extended attributes (POSIX ACLs travel the same way)"
            );
        }
        assert_eq!(stand.quarantined().len(), 1, "the original is recoverable");
    }

    /// `mv -n` exits 0 when it moved nothing, as when the quarantine slot is taken. The script has
    /// to see that the file is still where it was and not count the delete as done.
    #[test]
    fn a_taken_quarantine_slot_is_not_counted_as_a_delete() {
        let stand = Stand::new("script_slot_taken");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let script = stand.render(&real_plan(&keeper, &[(&target, ActionKind::Delete)]));
        let slot = quarantine_path_in(&script, "dup.bin");
        std::fs::create_dir_all(slot.parent().unwrap()).unwrap();
        std::fs::write(&slot, b"somebody else").unwrap();

        let run = stand.run(&script);

        let stderr = String::from_utf8_lossy(&run.stderr);
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            !run.status.success(),
            "a delete that moved nothing is not done: {stdout}{stderr}"
        );
        assert!(target.exists(), "{stderr}");
        assert_eq!(
            std::fs::read(&slot).unwrap(),
            b"somebody else",
            "the occupant is not overwritten"
        );
        assert!(stderr.contains("dup.bin"), "{stderr}");
    }

    /// `mv` refusing to move the replacement onto the file's place, as a lost race or a dying disk
    /// would. `mv -n -- SOURCE DEST` is the only form the script uses.
    const MV_CANNOT_PUBLISH: &str = "seen=; src=\nfor arg; do\n  if [ -n \"$seen\" ]; then src=$arg; break; fi\n  [ \"$arg\" = -- ] && seen=1\ndone\ncase $src in\n  */.dedcom-*.tmp) echo \"mv: cannot move '$src': Permission denied\" >&2; exit 1 ;;\nesac\nexec \"$REAL\" \"$@\"";

    /// As above, and the file cannot come back out of the quarantine either.
    const MV_CANNOT_PUBLISH_OR_RETURN: &str = "seen=; src=\nfor arg; do\n  if [ -n \"$seen\" ]; then src=$arg; break; fi\n  [ \"$arg\" = -- ] && seen=1\ndone\ncase $src in\n  */.dedcom-*.tmp|*/.dedcom-quarantine/*) echo \"mv: cannot move '$src': Permission denied\" >&2; exit 1 ;;\nesac\nexec \"$REAL\" \"$@\"";

    /// Temporary replacements left in `dir`.
    fn replacements_in(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name.starts_with(".dedcom-") && name.ends_with(".tmp")
            })
            .collect()
    }

    /// The whole route with the real tools: the file becomes a link to the keeper, the original
    /// sits in the quarantine under its own inode, nothing temporary is left, the run succeeds.
    #[test]
    fn a_hardlink_replaces_the_file_and_keeps_the_original() {
        let stand = Stand::new("script_hardlink");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Hardlink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(run.status.success(), "{stderr}");
        assert_eq!(inode(&target), inode(&keeper), "the file is the keeper now");
        let quarantined = stand.quarantined();
        assert_eq!(quarantined.len(), 1, "{quarantined:?}");
        assert_eq!(
            inode(&quarantined[0]),
            original,
            "the original, recoverable"
        );
        assert!(replacements_in(&stand.pool()).is_empty());
        assert!(String::from_utf8_lossy(&run.stdout).contains("dedcom: plan executed."));
    }

    #[test]
    fn a_delete_moves_the_file_to_the_quarantine() {
        let stand = Stand::new("script_delete");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Delete)])));

        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(!target.exists());
        let quarantined = stand.quarantined();
        assert_eq!(quarantined.len(), 1, "{quarantined:?}");
        assert_eq!(inode(&quarantined[0]), original);
    }

    /// The step after the move fails: the replacement cannot take the file's place, so the file
    /// comes back from the quarantine and the replacement goes — for a link and for a clone alike.
    #[test]
    fn a_replacement_that_cannot_be_published_puts_the_file_back() {
        for kind in [ActionKind::Hardlink, ActionKind::Reflink] {
            let stand = Stand::new("script_put_back");
            let keeper = stand.file("keep.bin", b"the same bytes");
            let target = stand.file("dup.bin", b"the same bytes");
            let original = inode(&target);
            stand.stand_in("mv", MV_CANNOT_PUBLISH);
            stand.stand_in("cp", CP_CLONE_AS_COPY);

            let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, kind)])));

            let stderr = String::from_utf8_lossy(&run.stderr);
            assert!(!run.status.success(), "{kind:?}: {stderr}");
            assert_eq!(
                inode(&target),
                original,
                "{kind:?}: the original is back: {stderr}"
            );
            assert!(stand.quarantined().is_empty(), "{kind:?}");
            assert!(replacements_in(&stand.pool()).is_empty(), "{kind:?}");
            assert!(
                stderr.contains("not replaced: ")
                    && stderr.contains("dup.bin — the replacement could not be published; the original is back in its place"),
                "{kind:?}: {stderr}"
            );
        }
    }

    /// When the file cannot come back either, the run says where it is and where it belongs.
    #[test]
    fn a_file_that_cannot_come_back_is_named_in_the_quarantine() {
        let stand = Stand::new("script_stranded");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);
        stand.stand_in("mv", MV_CANNOT_PUBLISH_OR_RETURN);

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Hardlink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{stderr}");
        assert!(!target.exists(), "{stderr}");
        let quarantined = stand.quarantined();
        assert_eq!(quarantined.len(), 1, "{quarantined:?}");
        assert_eq!(inode(&quarantined[0]), original);
        assert!(
            stderr.contains(&format!(
                "the original stays in the quarantine: {}",
                quarantined[0].display()
            )),
            "{stderr}"
        );
        assert!(
            replacements_in(&stand.pool()).is_empty(),
            "the link beside it is gone"
        );
    }

    /// Over a file `mktemp` made, overlayfs answers `cp --reflink=always` with 0 and leaves the file
    /// empty. Its size gives it away: nothing is published, and the empty file does not stay.
    #[test]
    fn a_clone_that_came_out_empty_is_not_published() {
        let stand = Stand::new("script_empty_clone");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);
        stand.stand_in(
            "cp",
            "for arg; do\n  [ \"$arg\" = --reflink=always ] && exit 0\ndone\nexec \"$REAL\" \"$@\"",
        );

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Reflink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{stderr}");
        assert_eq!(inode(&target), original);
        assert!(stand.quarantined().is_empty());
        assert!(replacements_in(&stand.pool()).is_empty(), "{stderr}");
        assert!(
            stderr.contains("not replaced: ")
                && stderr.contains("the clone could not be made beside it"),
            "{stderr}"
        );
    }

    /// A clone `cp` reports as failed is not published, even when the bytes look right: the
    /// failure is `cp`'s to report, and a partial write is not something a size can see.
    #[test]
    fn a_clone_that_cp_reports_as_failed_is_not_published() {
        let stand = Stand::new("script_clone_failed");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);
        stand.stand_in(
            "cp",
            &format!(
                "for arg; do\n  [ \"$arg\" = --reflink=always ] && {{ (\n{CP_CLONE_AS_COPY}\n); exit 1; }}\ndone\nexec \"$REAL\" \"$@\""
            ),
        );

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Reflink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{stderr}");
        assert_eq!(inode(&target), original, "{stderr}");
        assert!(stand.quarantined().is_empty());
        assert!(replacements_in(&stand.pool()).is_empty(), "{stderr}");
        assert!(
            stderr.contains("the clone could not be made beside it"),
            "{stderr}"
        );
    }

    /// A link the kernel refuses — too many links, a second mount — leaves the file untouched
    /// and says so; nothing goes through the quarantine.
    #[test]
    fn a_link_that_cannot_be_made_leaves_the_file_in_place() {
        let stand = Stand::new("script_link_refused");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);
        stand.stand_in(
            "ln",
            "echo \"ln: failed to create hard link: Too many links\" >&2\nexit 1",
        );

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Hardlink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{stderr}");
        assert_eq!(inode(&target), original);
        assert!(stand.quarantined().is_empty());
        assert!(
            stderr.contains("not replaced: ")
                && stderr.contains("dup.bin — the link could not be made beside it"),
            "{stderr}"
        );
        assert!(
            !stderr.contains("could not be published"),
            "it never reached the publication: {stderr}"
        );
        assert!(
            stderr.contains("dedcom: 1 of 1 action not carried out — each is named above"),
            "one action, said as one: {stderr}"
        );
    }

    /// The quarantine slot of a hardlink or a clone is taken: the file stays, the replacement
    /// built beside it goes, and the occupant is not touched.
    #[test]
    fn a_taken_quarantine_slot_stops_a_replacement_too() {
        for kind in [ActionKind::Hardlink, ActionKind::Reflink] {
            let stand = Stand::new("script_slot_taken_replace");
            let keeper = stand.file("keep.bin", b"the same bytes");
            let target = stand.file("dup.bin", b"the same bytes");
            let original = inode(&target);
            stand.stand_in("cp", CP_CLONE_AS_COPY);
            let script = stand.render(&real_plan(&keeper, &[(&target, kind)]));
            let slot = quarantine_path_in(&script, "dup.bin");
            std::fs::create_dir_all(slot.parent().unwrap()).unwrap();
            std::fs::write(&slot, b"somebody else").unwrap();

            let run = stand.run(&script);

            let stderr = String::from_utf8_lossy(&run.stderr);
            assert!(!run.status.success(), "{kind:?}: {stderr}");
            assert_eq!(inode(&target), original, "{kind:?}");
            assert_eq!(std::fs::read(&slot).unwrap(), b"somebody else", "{kind:?}");
            assert!(
                replacements_in(&stand.pool()).is_empty(),
                "{kind:?}: {stderr}"
            );
            assert!(
                stderr.contains("dup.bin — it could not be moved to the quarantine"),
                "{kind:?}: {stderr}"
            );
        }
    }

    /// A comparison that could not be made is no licence to act: the file stays, the reason is
    /// not dressed up as a difference.
    #[test]
    fn a_file_that_cannot_be_compared_is_left_alone() {
        let stand = Stand::new("script_cmp_error");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        stand.stand_in("cmp", "echo 'cmp: Input/output error' >&2\nexit 2");

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Delete)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{stderr}");
        assert!(target.exists());
        assert!(stand.quarantined().is_empty());
        assert!(
            stderr.contains("skip ")
                && stderr.contains("dup.bin: it could not be compared with its keeper"),
            "{stderr}"
        );
    }

    /// Only a replacement this script made is removed. A file renamed over its name is named and
    /// left alone. The file is renamed in while the script's own still exists, so the two can
    /// never share an inode number: one deleted first may hand its number to the next file made,
    /// and an inode is all the script can tell its own file by.
    #[test]
    fn a_temporary_file_that_is_no_longer_ours_is_not_removed() {
        let stand = Stand::new("script_foreign_temp");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        stand.stand_in(
            "cp",
            "for arg; do dest=$arg; done\nfor arg; do\n  if [ \"$arg\" = --reflink=always ]; then\n    echo foreign > \"$dest.new\" && mv -f -- \"$dest.new\" \"$dest\"\n    echo 'cp: failed to clone' >&2; exit 1\n  fi\ndone\nexec \"$REAL\" \"$@\"",
        );

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Reflink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{stderr}");
        let left = replacements_in(&stand.pool());
        assert_eq!(left.len(), 1, "{stderr}");
        assert_eq!(std::fs::read(&left[0]).unwrap(), b"foreign\n");
        let name = left[0].file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            stderr.contains(&format!(
                "the temporary file {name} beside it is left behind"
            )),
            "{stderr}"
        );
        assert!(target.exists());
    }

    /// Metadata that did not come along stops the clone before the file is touched: whether `cp`
    /// says it failed, or says nothing and carries nothing, as it does with an owner it may not set.
    #[test]
    fn metadata_that_is_not_carried_stops_the_clone() {
        for (answer, how) in [
            (
                "\"$REAL\" \"$@\"; exit 1",
                "carries it and reports a failure",
            ),
            ("exit 0", "carries nothing"),
        ] {
            let stand = Stand::new("script_no_metadata");
            let keeper = stand.file("keep.bin", b"the same bytes");
            let target = stand.file("dup.bin", b"the same bytes");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
            let original = inode(&target);
            stand.stand_in(
                "cp",
                &format!(
                    "for arg; do\n  [ \"$arg\" = --attributes-only ] && {{ {answer}; }}\ndone\n{CP_CLONE_AS_COPY}"
                ),
            );

            let run =
                stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Reflink)])));

            let stderr = String::from_utf8_lossy(&run.stderr);
            assert!(!run.status.success(), "{how}: {stderr}");
            assert_eq!(inode(&target), original, "{how}");
            assert!(stand.quarantined().is_empty(), "{how}");
            assert!(replacements_in(&stand.pool()).is_empty(), "{how}");
            assert!(
                stderr.contains(
                    "its owner, mode, times or extended attributes could not be carried over"
                ),
                "{how}: {stderr}"
            );
        }
    }

    /// A file at the very root of a filesystem gets its replacement at the root: the renderer
    /// hands the script the file's directory, where a shell cutting the last name off `/x.bin`
    /// would be left with nothing.
    #[test]
    fn a_file_at_the_root_gets_its_replacement_at_the_root() {
        let datasets = vec![dataset("rpool/ROOT/pve-1", "/", 7)];
        for kind in [ActionKind::Hardlink, ActionKind::Reflink] {
            let script = render_script(&plan_of(kind, "/x.bin", "/k.bin", 7), &datasets, ZFS);
            let call = script
                .lines()
                .find(|line| line.starts_with("dedcom_") && line.contains(" '/x.bin' "))
                .unwrap_or_else(|| panic!("{kind:?}: the call:\n{script}"));
            assert!(
                call.ends_with(" '/' || dedcom_failed=$((dedcom_failed + 1))"),
                "{kind:?}: {call}"
            );
        }
    }

    /// Somebody removed the replacement before it could take the file's place. The publication is
    /// judged by the inode now at the file's place, not by the replacement's name being gone, so
    /// the file comes back and nothing is claimed.
    #[test]
    fn a_replacement_that_vanished_before_publishing_puts_the_file_back() {
        let stand = Stand::new("script_vanished");
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);
        stand.stand_in(
            "mv",
            "seen=; src=\nfor arg; do\n  if [ -n \"$seen\" ]; then src=$arg; break; fi\n  [ \"$arg\" = -- ] && seen=1\ndone\ncase $src in\n  */.dedcom-*.tmp) rm -f -- \"$src\"; echo \"mv: cannot stat '$src': No such file or directory\" >&2; exit 1 ;;\nesac\nexec \"$REAL\" \"$@\"",
        );

        let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, ActionKind::Hardlink)])));

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{stderr}");
        assert_eq!(inode(&target), original, "{stderr}");
        assert!(stand.quarantined().is_empty());
        assert!(
            stderr.contains("the original is back in its place"),
            "{stderr}"
        );
    }

    /// A file or its keeper that turned into a symbolic link after the structural check is left
    /// alone, as `Y` leaves it: the check is made again at each action. The link is swapped in by
    /// `mv` during the first action, when both preflights have long passed.
    #[test]
    fn a_link_swapped_in_between_actions_is_left_alone() {
        for keeper_swapped in [false, true] {
            let stand = Stand::new("script_link_swap");
            let keeper = stand.file("keep.bin", b"the same bytes");
            let a = stand.file("a.bin", b"the same bytes");
            let b = stand.file("b.bin", b"the same bytes");
            let mark = stand.scratch.path().join("swapped");
            let victim = if keeper_swapped {
                format!("victim='{}'", keeper.display())
            } else {
                format!(
                    "case $src in *'/a.bin') victim='{}' ;; *) victim='{}' ;; esac",
                    b.display(),
                    a.display()
                )
            };
            stand.stand_in(
                "mv",
                &format!(
                    "seen=; src=\nfor arg; do\n  if [ -n \"$seen\" ]; then src=$arg; break; fi\n  [ \"$arg\" = -- ] && seen=1\ndone\nif [ ! -e '{mark}' ]; then\n  : > '{mark}'\n  {victim}\n  \"$REAL\" -f -- \"$victim\" \"$victim.real\" && ln -s -- \"$victim.real\" \"$victim\"\nfi\nexec \"$REAL\" \"$@\"",
                    mark = mark.display()
                ),
            );
            let plan = real_plan(
                &keeper,
                &[(&a, ActionKind::Delete), (&b, ActionKind::Delete)],
            );

            let run = stand.run(&stand.render(&plan));

            let stderr = String::from_utf8_lossy(&run.stderr);
            let what = if keeper_swapped { "keeper" } else { "file" };
            assert!(!run.status.success(), "{what}: {stderr}");
            let quarantined = stand.quarantined();
            assert_eq!(
                quarantined.len(),
                1,
                "{what}: only the first delete ran: {quarantined:?}"
            );
            assert!(
                stderr.contains("it or its keeper is a symbolic link"),
                "{what}: {stderr}"
            );
            if !keeper_swapped {
                let moved = quarantined[0].file_name().unwrap().to_owned();
                let other = if moved == "a.bin" { &b } else { &a };
                assert!(
                    std::fs::symlink_metadata(other)
                        .unwrap()
                        .file_type()
                        .is_symlink(),
                    "the link stays where it was: {stderr}"
                );
            }
        }
    }

    /// Removes a directory outside the scratch area when the test ends, however it ends.
    struct RemovedOnDrop(PathBuf);

    impl Drop for RemovedOnDrop {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Across filesystems `mv` copies and deletes where `Y`'s `renameat2` refuses. A quarantine
    /// that is not on the file's filesystem — the very directory the file would land in turned
    /// into a link to another one, so only a check that follows the link sees it — is refused
    /// before anything moves.
    #[test]
    fn a_quarantine_on_another_filesystem_is_refused_before_the_move() {
        let stand = Stand::new("script_foreign_quarantine");
        let elsewhere = Path::new("/dev/shm");
        let device = |path: &Path| std::fs::metadata(path).unwrap().dev();
        if !elsewhere.is_dir() || device(elsewhere) == device(&stand.pool()) {
            eprintln!("/dev/shm is not a second filesystem here — nothing to show");
            return;
        }
        let foreign = RemovedOnDrop(
            elsewhere.join(
                stand
                    .scratch
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            ),
        );
        std::fs::create_dir_all(&foreign.0).unwrap();
        let keeper = stand.file("keep.bin", b"the same bytes");
        let target = stand.file("dup.bin", b"the same bytes");
        let original = inode(&target);
        let script = stand.render(&real_plan(&keeper, &[(&target, ActionKind::Delete)]));
        let landing = quarantine_path_in(&script, "dup.bin")
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(landing.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&foreign.0, &landing).unwrap();

        let run = stand.run(&script);

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{stderr}");
        assert_eq!(inode(&target), original, "the file never left: {stderr}");
        assert!(
            stderr.contains("not moved to the quarantine: ") && stderr.contains("dup.bin"),
            "{stderr}"
        );
        assert!(
            stand.quarantined().is_empty(),
            "nothing reached the other filesystem: {:?}",
            stand.quarantined()
        );
    }

    /// Two mounts of one filesystem — the file reached through a bind mount — share a device
    /// number, and between them `mv` copies and deletes just as it does between filesystems: the
    /// file left its place while the script said it had not moved, and a Reflink or Hardlink threw
    /// its replacement away as well, leaving the place empty. The mount is what has to match.
    /// `findmnt` stands in here, answering for the quarantine from another mount, because a bind
    /// mount takes privileges a test does not have. It lies only when asked for the mount ID: a
    /// script comparing any other column — the device number again — gets the real answer and
    /// moves the file. A `findmnt` that says nothing or fails refuses the move too, without the
    /// line about another mount: the tool's own line names that reason.
    #[test]
    fn a_quarantine_on_another_mount_is_refused_before_the_move() {
        let answers = [
            (
                "another mount",
                "case $id$path in\n  yes*/.dedcom-quarantine/*) echo 4242 ;;\n  *) exec \"$REAL\" \"$@\" ;;\nesac",
            ),
            ("no answer", "exit 0"),
            (
                "a failure",
                "echo 'findmnt: cannot read /proc/self/mountinfo' >&2\nexit 1",
            ),
        ];
        for (answer, body) in answers {
            for kind in [
                ActionKind::Delete,
                ActionKind::Hardlink,
                ActionKind::Reflink,
            ] {
                let stand = Stand::new("script_other_mount");
                let keeper = stand.file("keep.bin", b"the same bytes");
                let target = stand.file("dup.bin", b"the same bytes");
                let original = inode(&target);
                stand.stand_in(
                    "findmnt",
                    &format!(
                        "id=; path=\nfor arg; do\n  [ \"$path\" = -o ] && [ \"$arg\" = ID ] && id=yes\n  path=$arg\ndone\n{body}"
                    ),
                );
                stand.stand_in("cp", CP_CLONE_AS_COPY);

                let run = stand.run(&stand.render(&real_plan(&keeper, &[(&target, kind)])));

                let stderr = String::from_utf8_lossy(&run.stderr);
                assert!(!run.status.success(), "{answer}, {kind:?}: {stderr}");
                assert_eq!(
                    inode(&target),
                    original,
                    "{answer}, {kind:?}: the file never left: {stderr}"
                );
                assert_eq!(std::fs::read(&target).unwrap(), b"the same bytes");
                assert!(
                    stand.quarantined().is_empty(),
                    "{answer}, {kind:?}: {:?}",
                    stand.quarantined()
                );
                assert!(
                    replacements_in(&stand.pool()).is_empty(),
                    "{answer}, {kind:?}: no replacement is left behind: {stderr}"
                );
                let line = if kind == ActionKind::Delete {
                    "not moved to the quarantine: "
                } else {
                    " — it could not be moved to the quarantine"
                };
                assert!(
                    stderr.contains(line) && stderr.contains("dup.bin"),
                    "{answer}, {kind:?}: {stderr}"
                );
                assert_eq!(
                    stderr.contains("dup.bin: the quarantine is on another mount than the file"),
                    answer == "another mount",
                    "{answer}, {kind:?}: the reason is named when it is the mount: {stderr}"
                );
            }
        }
    }

    /// Chapter 13 quotes every line the script prints about an action, as the script prints it:
    /// the file's label and the quarantine path become `…`, as in the chapter's other quotes.
    #[test]
    fn the_manual_quotes_every_line_the_script_prints() {
        let mut quoted: Vec<String> = [
            SHELL_COMMON,
            SHELL_DELETE,
            SHELL_REPLACE,
            SHELL_HARDLINK,
            SHELL_REFLINK,
        ]
        .iter()
        .flat_map(|text| text.lines())
        .filter_map(|line| line.split("dedcom_note \"").nth(1))
        .map(|note| {
            let mut note = note
                .split('"')
                .next()
                .unwrap()
                .replace("${1##*/}", ".dedcom-….tmp");
            for argument in ["$3", "$4", "$6", "$7"] {
                note = note.replace(argument, "…");
            }
            note
        })
        .collect();
        assert_eq!(
            quoted.len(),
            13,
            "every note of the shell functions: {quoted:#?}"
        );

        // The two lines the renderer writes itself.
        let datasets = vec![dataset("tank", "/tank", 7)];
        let skipped = render_script(
            &plan_of(ActionKind::Delete, "/other/a.bin", "/other/k.bin", 99),
            &datasets,
            ZFS,
        );
        let skip = skipped
            .lines()
            .find_map(|line| line.strip_prefix("echo 'dedcom: "))
            .and_then(|rest| rest.strip_suffix("' >&2"))
            .expect("the line of an action without a dataset");
        quoted.push(skip.replace("/other/a.bin", "…"));
        let stand = Stand::new("script_manual_summary");
        let keeper = stand.file("keep.bin", b"bytes");
        let one = stand.file("one.bin", b"bytes");
        let two = stand.file("two.bin", b"bytes");
        let script = stand.render(&real_plan(
            &keeper,
            &[(&one, ActionKind::Delete), (&two, ActionKind::Delete)],
        ));
        let summary = script
            .lines()
            .find_map(|line| line.trim().strip_prefix("echo \"dedcom: "))
            .and_then(|rest| rest.strip_suffix("\" >&2"))
            .expect("the summary line");
        quoted.push(summary.replace("$dedcom_failed of 2 actions", "N of M actions"));

        let chapter = crate::testfixtures::manual("13-troubleshooting.md");
        let chapter = chapter.split_whitespace().collect::<Vec<_>>().join(" ");
        for quote in &quoted {
            assert!(
                chapter.contains(quote.as_str()),
                "13-troubleshooting.md must quote: {quote}"
            );
        }
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
