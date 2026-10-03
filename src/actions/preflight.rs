// SPDX-License-Identifier: Apache-2.0
//! What stands in the way of an action, found before its batch takes the first snapshot.
//!
//! A snapshot is the batch's insurance, so a dataset gets one only when something on it will really
//! change; an action that cannot be carried out is refused while nothing exists yet, and without its
//! files being read. Two layers: what the plan alone decides — where the target's dataset is,
//! whether the host and the pool can clone — and what the filesystem says about the pathnames
//! without anything being opened or changed: read-only, full, immutable or append-only, reached
//! through another mount. Neither layer guesses. Whatever the kernel does not say is no reason to
//! refuse; the action itself still meets the kernel's own answer, after its snapshot.

use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::model::action::ActionKind;
use crate::model::dataset::Dataset;
use crate::model::plan::{ActionPlan, PlanAction, Unrunnable};

use super::{dataset_by_device, quarantine, ApplyOps, RealOps};

/// What a host needs before `dedcom` reflinks on it — the gate of `zfs::version::detect`.
pub const CLONE_NEEDS: &str = "needs OpenZFS 2.2.1 or newer with zfs_bclone_enabled=1";

/// The refusal of an action the plan's confirmation counted out, when nothing stands in its way any
/// more: it does not run behind the operator's back, and its mark stays for the next plan while
/// nothing else in its group ran.
pub const SET_ASIDE: &str = "set aside by the confirmation — build the plan again";

/// Which kind of pathname a probe asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A file the action moves or links. Not followed through a symbolic link, and only its own
    /// flags and mount count.
    File,
    /// A directory something is moved out of or made in. Followed through a symbolic link, as the
    /// kernel follows it when it moves or links there, and its filesystem is read as well.
    Directory,
}

/// One pathname's standing, as far as it can be read without opening or changing anything.
///
/// A field the kernel would not fill keeps its default — not read-only, not full, no flag, no
/// mount — so an unknown never refuses anything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Probe {
    /// On a read-only mount (`ST_RDONLY`). Read for a directory only.
    pub read_only: bool,
    /// Nothing is left to write there (`f_bavail == 0`): a full pool, a quota, a refquota. Read
    /// for a directory only.
    pub full: bool,
    /// `chattr +i`.
    pub immutable: bool,
    /// `chattr +a`.
    pub append_only: bool,
    /// The mount it is reached through (`statx`, `STATX_MNT_ID`).
    pub mount: Option<u64>,
}

impl Probe {
    /// What the kernel says about `path`: one `statx` for the flags and the mount, and for a
    /// directory one `statvfs` for its filesystem. Nothing is opened, so nothing that watches opens
    /// — a virus scanner, a lease — is woken.
    pub fn of(path: &Path, role: Role) -> Self {
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return Self::default();
        };
        let mut probe = Self::default();

        let follow = match role {
            Role::File => libc::AT_SYMLINK_NOFOLLOW,
            Role::Directory => 0,
        };
        // SAFETY: a valid C string and a zeroed repr(C) struct that statx fills in.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        let found = unsafe {
            libc::statx(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                follow | libc::AT_STATX_DONT_SYNC,
                libc::STATX_MNT_ID,
                &mut stx,
            )
        };
        if found == 0 {
            if stx.stx_mask & libc::STATX_MNT_ID != 0 {
                probe.mount = Some(stx.stx_mnt_id);
            }
            let known = stx.stx_attributes_mask & stx.stx_attributes;
            probe.immutable = known & libc::STATX_ATTR_IMMUTABLE as u64 != 0;
            probe.append_only = known & libc::STATX_ATTR_APPEND as u64 != 0;
        }

        if role == Role::Directory {
            // SAFETY: a valid C string and a zeroed repr(C) struct that statvfs fills in.
            let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) } == 0 {
                probe.read_only = vfs.f_flag & libc::ST_RDONLY != 0;
                probe.full = vfs.f_bavail == 0;
            }
        }
        probe
    }
}

/// [`ApplyOps::probe`] for one pass: a directory is looked at once however many actions live in
/// it, a file every time — each target is met once. Dropped with the pass.
struct Probes<'a> {
    ops: &'a dyn ApplyOps,
    directories: HashMap<PathBuf, Probe>,
    /// Where each mountpoint's quarantine is made: inside its root when that exists, inside the
    /// mountpoint while it does not.
    nests: HashMap<PathBuf, PathBuf>,
}

impl<'a> Probes<'a> {
    fn new(ops: &'a dyn ApplyOps) -> Self {
        Self {
            ops,
            directories: HashMap::new(),
            nests: HashMap::new(),
        }
    }

    fn directory(&mut self, path: &Path) -> Probe {
        if let Some(probe) = self.directories.get(path) {
            return *probe;
        }
        let probe = self.ops.probe(path, Role::Directory);
        self.directories.insert(path.to_path_buf(), probe);
        probe
    }

    fn file(&self, path: &Path) -> Probe {
        self.ops.probe(path, Role::File)
    }

    fn nest(&mut self, mountpoint: &Path) -> PathBuf {
        if let Some(nest) = self.nests.get(mountpoint) {
            return nest.clone();
        }
        let root = quarantine::quarantine_root(mountpoint);
        let nest = if std::fs::symlink_metadata(&root).is_ok_and(|meta| meta.is_dir()) {
            root
        } else {
            mountpoint.to_path_buf()
        };
        self.nests.insert(mountpoint.to_path_buf(), nest.clone());
        nest
    }
}

/// What stands in the way of each action of `plan` as the kernel says it now: the pass the batch
/// makes before its snapshots, made when the plan is built, so its confirmation can name what will
/// not run. It reads every target — never on the interface thread.
pub(crate) fn unrunnable(
    plan: &ActionPlan,
    datasets: &[Dataset],
    reflink_safe: bool,
) -> Unrunnable {
    Unrunnable::new(obstacles(&RealOps, plan, datasets, reflink_safe))
}

/// The obstacle of every action of `plan`, in the plan's order — one pass, before any snapshot.
pub(super) fn obstacles(
    ops: &dyn ApplyOps,
    plan: &ActionPlan,
    datasets: &[Dataset],
    reflink_safe: bool,
) -> Vec<Option<String>> {
    let mut probes = Probes::new(ops);
    plan.actions()
        .iter()
        .map(|action| obstacle(&mut probes, plan, action, datasets, reflink_safe))
        .collect()
}

/// The dataset `action` changes, or what the plan alone says against it: a reflink the host or the
/// pool cannot make, a link between two datasets, a target on no dataset the host reported —
/// without which neither a snapshot nor a quarantine can exist. Pure, so the pass before the
/// snapshots and the action itself get the same answer.
pub(super) fn place<'d>(
    plan: &ActionPlan,
    action: &PlanAction,
    datasets: &'d [Dataset],
    reflink_safe: bool,
) -> Result<&'d Dataset, String> {
    let kind = action.kind();
    let device = plan.target_object_of(action).key().device;
    if kind == ActionKind::Reflink && !reflink_safe {
        return Err(format!(
            "reflink is unavailable on this host — {CLONE_NEEDS}"
        ));
    }
    // The plan already refuses a link across datasets (`ActionPlan::try_new`); this is the last
    // line, not the check an operator meets.
    if kind != ActionKind::Delete && plan.keeper_object_of(action).key().device != device {
        return Err(format!(
            "cross-dataset {} is impossible — files are in different datasets",
            kind.as_str()
        ));
    }
    let Some(dataset) = dataset_by_device(datasets, device) else {
        return Err(match kind {
            ActionKind::Delete => "target file's dataset could not be determined".to_string(),
            kind => format!(
                "target file's dataset could not be determined — {} is not performed without a \
                 ZFS snapshot",
                kind.as_str()
            ),
        });
    };
    if kind == ActionKind::Reflink && dataset.block_cloning == Some(false) {
        return Err(format!(
            "reflink is unavailable on pool {} — its block_cloning feature is disabled",
            dataset.pool_name()
        ));
    }
    Ok(dataset)
}

/// Everything that can be seen against `action` before its snapshot: the plan's own answer, then
/// what the filesystem says about the pathnames the action would move or create. `None` — nothing
/// in the way that can be seen without changing anything. Each reason is short: the summary prints
/// it after the pathname.
fn obstacle(
    probes: &mut Probes<'_>,
    plan: &ActionPlan,
    action: &PlanAction,
    datasets: &[Dataset],
    reflink_safe: bool,
) -> Option<String> {
    let dataset = match place(plan, action, datasets, reflink_safe) {
        Ok(dataset) => dataset,
        Err(reason) => return Some(reason),
    };
    let target = action.target();
    let mountpoint = &dataset.mountpoint;
    // The quarantine is under the dataset's own mountpoint, and a rename does not cross mounts —
    // not even two mounts of one dataset.
    if target.strip_prefix(mountpoint).is_err() {
        return Some(format!(
            "outside the mountpoint of {} ({})",
            dataset.name,
            mountpoint.display()
        ));
    }
    let Some(dir) = target.parent() else {
        return Some("target file has no parent directory".to_string());
    };
    let home = probes.directory(mountpoint);
    let here = probes.directory(dir);
    if differ(here.mount, home.mount) {
        return Some(format!(
            "reached through another mount of {} (a bind mount?)",
            dataset.name
        ));
    }
    if home.read_only || here.read_only {
        return Some(format!("read-only filesystem ({})", dataset.name));
    }
    if home.full {
        return Some(format!(
            "no space left on {} (full pool or quota)",
            dataset.name
        ));
    }
    let nest = probes.nest(mountpoint);
    if probes.directory(&nest).immutable {
        return Some(format!(
            "the quarantine cannot be made in {}: it is immutable (chattr +i)",
            nest.display()
        ));
    }
    if here.immutable {
        return Some("the directory is immutable (chattr +i)".to_string());
    }
    if here.append_only {
        return Some("the directory is append-only (chattr +a)".to_string());
    }
    let file = probes.file(target);
    if file.immutable {
        return Some("the file is immutable (chattr +i)".to_string());
    }
    if file.append_only {
        return Some("the file is append-only (chattr +a)".to_string());
    }
    // A hardlink is made next to the target out of the keeper, and `link` crosses neither mounts —
    // not even two mounts of one dataset — nor the keeper's own flags. A clone crosses mounts of one
    // filesystem (Linux 5.18 and newer) and only reads the keeper.
    if action.kind() != ActionKind::Hardlink {
        return None;
    }
    let keeper = action.keeper();
    if let Some(keeper_dir) = keeper.parent() {
        if differ(probes.directory(keeper_dir).mount, here.mount) {
            return Some("the keeper is reached through another mount (a bind mount?)".to_string());
        }
    }
    let source = probes.file(keeper);
    if source.immutable {
        return Some("the keeper is immutable (chattr +i)".to_string());
    }
    if source.append_only {
        return Some("the keeper is append-only (chattr +a)".to_string());
    }
    None
}

/// Two mounts known to be different. An unknown is never a difference.
fn differ(one: Option<u64>, other: Option<u64>) -> bool {
    matches!((one, other), (Some(one), Some(other)) if one != other)
}

/// The refusal of a batch in which no action can run: it takes no snapshot, changes nothing and
/// keeps the marks. `None` while at least one action can run, and for obstacles read for another
/// plan. The count and the first reason come before the pathname: the status line does not wrap.
/// Said by the batch, and before it by the plan's confirmation, which then does not open.
pub(crate) fn nothing_can_run(plan: &ActionPlan, obstacles: &[Option<String>]) -> Option<String> {
    if obstacles.len() != plan.actions().len() || obstacles.iter().any(Option::is_none) {
        return None;
    }
    // A cause that appeared since the plan was built is what the operator has to hear about; the
    // confirmation's own setting aside only when there is nothing else to name.
    let first = |skip_set_aside: bool| {
        plan.actions()
            .iter()
            .zip(obstacles)
            .find_map(|(action, obstacle)| {
                obstacle
                    .as_deref()
                    .filter(|reason| !(skip_set_aside && *reason == SET_ASIDE))
                    .map(|reason| (action, reason))
            })
    };
    let (action, reason) = first(true).or_else(|| first(false))?;
    Some(format!(
        "nothing done — {} cannot run: {reason}; no snapshot taken, marks kept; first: {}",
        counted(obstacles.len(), "action"),
        action.target().display()
    ))
}

/// Why a plan cannot be confirmed as it stands: reflinks the host or a pool cannot make. Asked when
/// the plan arrives, before its confirmation opens — once confirmed, the batch could only refuse
/// them. The reason, the count and the way out come before the pathname: the status line does not
/// wrap.
pub fn reflink_refusal(
    plan: &ActionPlan,
    datasets: &[Dataset],
    reflink_safe: bool,
) -> Option<String> {
    let reflinks: Vec<&PlanAction> = plan
        .actions()
        .iter()
        .filter(|action| action.kind() == ActionKind::Reflink)
        .collect();
    let first = reflinks.first()?;
    if !reflink_safe {
        return Some(format!(
            "cannot reflink on this host ({}) — {CLONE_NEEDS}; mark HARDLINK or DELETE, or unmark; \
             first: {}",
            counted(reflinks.len(), "mark"),
            first.target().display()
        ));
    }
    let pool_of = |action: &PlanAction| {
        dataset_by_device(datasets, plan.target_object_of(action).key().device)
            .filter(|dataset| dataset.block_cloning == Some(false))
            .map(Dataset::pool_name)
    };
    let (blocked, pool) = reflinks
        .iter()
        .find_map(|action| pool_of(action).map(|pool| (*action, pool)))?;
    let count = reflinks
        .iter()
        .filter(|action| pool_of(action) == Some(pool))
        .count();
    Some(format!(
        "cannot reflink on pool {pool} ({}) — its block_cloning feature is disabled; mark HARDLINK \
         or DELETE, or unmark; first: {}",
        counted(count, "mark"),
        blocked.target().display()
    ))
}

/// «1 mark», «3 marks».
fn counted(count: usize, what: &str) -> String {
    match count {
        1 => format!("1 {what}"),
        count => format!("{count} {what}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::tests::{dataset_over, plan_of};
    use crate::testfixtures::PlanScenario;

    /// A plan of one keeper and `marks` twins, marked in order.
    fn marked(tag: &str, marks: &[ActionKind]) -> (PlanScenario, ActionPlan) {
        let scenario = PlanScenario::new(tag);
        let keeper = scenario.file("keeper.bin");
        let twins: Vec<PathBuf> = (0..marks.len())
            .map(|index| scenario.file(&format!("twin_{index}.bin")))
            .collect();
        let mut store = scenario.store();
        let mut paths = vec![keeper.clone()];
        paths.extend(twins.iter().cloned());
        let scan_id = scenario.seed(&mut store, &paths);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        for (twin, kind) in twins.iter().zip(marks) {
            scenario.mark(&mut store, scan_id, twin, false, Some(*kind));
        }
        drop(store);
        let plan = plan_of(&scenario, scan_id);
        (scenario, plan)
    }

    fn cloning(scenario: &PlanScenario, block_cloning: Option<bool>) -> Vec<Dataset> {
        let mut dataset = dataset_over(&scenario.root, "tank/test");
        dataset.block_cloning = block_cloning;
        vec![dataset]
    }

    /// A host that cannot clone refuses the plan before its confirmation, with every reflink
    /// counted and the first one named; the other kinds are not counted.
    #[test]
    fn a_host_that_cannot_clone_refuses_the_plan_with_its_reflinks_counted() {
        let (scenario, plan) = marked(
            "refusal_host",
            &[ActionKind::Delete, ActionKind::Reflink, ActionKind::Reflink],
        );
        let refusal = reflink_refusal(&plan, &cloning(&scenario, None), false)
            .expect("a host that cannot clone refuses the reflinks");
        let first = scenario.root.join("twin_1.bin");
        assert_eq!(
            refusal,
            format!(
                "cannot reflink on this host (2 marks) — needs OpenZFS 2.2.1 or newer with \
                 zfs_bclone_enabled=1; mark HARDLINK or DELETE, or unmark; first: {}",
                first.display()
            )
        );
    }

    /// A pool whose block cloning is disabled refuses the plan and is named; a pool that did not
    /// say is not a refusal, and neither is one that can clone.
    #[test]
    fn a_pool_that_cannot_clone_refuses_the_plan_and_an_unknown_one_does_not() {
        let (scenario, plan) = marked("refusal_pool", &[ActionKind::Reflink, ActionKind::Hardlink]);
        let refusal = reflink_refusal(&plan, &cloning(&scenario, Some(false)), true)
            .expect("a pool that cannot clone refuses the reflink");
        assert_eq!(
            refusal,
            format!(
                "cannot reflink on pool tank (1 mark) — its block_cloning feature is disabled; \
                 mark HARDLINK or DELETE, or unmark; first: {}",
                scenario.root.join("twin_0.bin").display()
            )
        );
        for known in [None, Some(true)] {
            assert_eq!(
                reflink_refusal(&plan, &cloning(&scenario, known), true),
                None,
                "block_cloning {known:?} is no refusal"
            );
        }
    }

    /// The count is of the named pool's reflinks: one on a pool that can clone is not in it. Two
    /// groups on two filesystems — the scenario's root and a directory on `/dev/shm` — so two
    /// datasets of two pools.
    #[test]
    fn a_pool_refusal_counts_only_that_pools_reflinks() {
        let shm = crate::actions::tests::ShmDir::new("refusal_pools");
        let scenario = PlanScenario::new("refusal_pools");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let other_keeper = shm.path.join("keeper.bin");
        let other_twin = shm.path.join("twin.bin");
        for path in [&other_keeper, &other_twin] {
            std::fs::write(path, vec![9u8; 4096]).unwrap();
        }
        let mut store = scenario.store();
        let paths = [
            keeper.clone(),
            twin.clone(),
            other_keeper.clone(),
            other_twin.clone(),
        ];
        let scan_id = scenario.seed(&mut store, &paths);
        for (keeper, twin) in [(&keeper, &twin), (&other_keeper, &other_twin)] {
            scenario.mark(&mut store, scan_id, keeper, true, None);
            scenario.mark(&mut store, scan_id, twin, false, Some(ActionKind::Reflink));
        }
        drop(store);
        let plan = plan_of(&scenario, scan_id);
        let mut datasets = cloning(&scenario, Some(false));
        let mut other = dataset_over(&shm.path, "rpool/data");
        other.block_cloning = Some(true);
        datasets.push(other);
        assert_eq!(
            reflink_refusal(&plan, &datasets, true),
            Some(format!(
                "cannot reflink on pool tank (1 mark) — its block_cloning feature is disabled; \
                 mark HARDLINK or DELETE, or unmark; first: {}",
                twin.display()
            ))
        );
    }

    /// A plan without a reflink is never refused for cloning, whatever the host.
    #[test]
    fn a_plan_without_a_reflink_is_not_refused_for_cloning() {
        let (scenario, plan) = marked("refusal_none", &[ActionKind::Delete, ActionKind::Hardlink]);
        for (safe, pool) in [(false, Some(false)), (true, Some(false)), (false, None)] {
            assert_eq!(
                reflink_refusal(&plan, &cloning(&scenario, pool), safe),
                None
            );
        }
    }

    /// The refusal of an action the confirmation counted out, word for word where the manual
    /// describes the checks and where an operator looks the message up.
    #[test]
    fn the_manual_quotes_the_set_aside_refusal() {
        for chapter in ["08-actions.md", "13-troubleshooting.md"] {
            let text = crate::testfixtures::manual(chapter);
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                text.contains(SET_ASIDE),
                "{chapter} must quote: {SET_ASIDE}"
            );
        }
    }

    /// The manual quotes both refusals word for word, the count, the pool and the pathname aside,
    /// where it describes a reflink and where an operator looks the message up.
    #[test]
    fn the_manual_quotes_the_reflink_refusals() {
        let (scenario, plan) = marked("refusal_manual", &[ActionKind::Reflink]);
        let first = scenario.root.join("twin_0.bin").display().to_string();
        let host = reflink_refusal(&plan, &cloning(&scenario, None), false).unwrap();
        let pool = reflink_refusal(&plan, &cloning(&scenario, Some(false)), true).unwrap();
        for refusal in [host, pool] {
            let quoted = refusal
                .replace("(1 mark)", "(N marks)")
                .replace("pool tank", "pool <pool>")
                .replace(&first, "…");
            for chapter in ["08-actions.md", "13-troubleshooting.md"] {
                let text = crate::testfixtures::manual(chapter);
                let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(text.contains(&quoted), "{chapter} must quote: {quoted}");
            }
        }
    }
}
