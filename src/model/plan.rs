// SPDX-License-Identifier: Apache-2.0
//! What a destructive plan is allowed to claim.
//!
//! A plan removes pathnames; a filesystem frees allocations. The two are the same number only when
//! every link of an allocation is in the plan, which is why every figure here is derived from the
//! allocations behind the selected pathnames rather than from the pathnames themselves. Summing one
//! file size per selected pathname — what every current confirmation, review, script header and
//! batch result does — claims an allocation once per alias.
//!
//! The types are deliberately plan-specific rather than an extension of `FileEntry` and
//! `DuplicateGroup`: the accepted browsing and grouping behaviour must not move while the trust
//! boundary is being introduced. `PlanMemberEvidence` therefore carries its own eight-field key and
//! refuses, at construction, both an unrecorded link count and a digest this build never verified.
//!
//! Inert in R2D-C5-1: nothing in production builds an `ActionPlan` yet. R2D-C5-2 switches classic
//! and the commander onto it and retires the two pathname-based builders.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::error::AppError;
use crate::model::action::ActionKind;
use crate::model::reclaim::{LinkCount, ReclaimEstimate};

pub type PlanResult<T> = std::result::Result<T, PlanRefusal>;

/// Why a plan may not be built.
///
/// Every variant is a refusal of the WHOLE plan. A destructive plan that quietly drops the part it
/// could not justify is the defect this type exists to prevent: the operator would confirm a screen
/// that no longer describes what they marked.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlanRefusal {
    #[error("this scan's results were never established well enough to act on — rescan required")]
    RescanRequired,
    #[error("no files are marked for an action")]
    NoMarks,
    #[error("nothing left to do: every marked file is already the keeper's own allocation")]
    NothingToDo,
    #[error("{} is marked in this window but the database holds no such mark — re-mark it", .path.display())]
    MarkNotPersisted { path: PathBuf },
    #[error("{} carries a mark but has no row in this scan's manifest. Rescan, or move the old dedcom.db aside.", .path.display())]
    NotInManifest { path: PathBuf },
    #[error("{} is marked but has no digest in this scan — rescan required", .path.display())]
    MissingDigest { path: PathBuf },
    #[error(
        "the group {hash} has files marked for an action and no keeper — choose the file to keep"
    )]
    MissingKeeper { hash: String },
    #[error("the group {hash} holds different sizes for one digest. Rescan, or move the old dedcom.db aside.")]
    InconsistentGroupSize { hash: String },
    #[error("{} has no recorded link count, so nothing can tell an alias from an independent copy — rescan required", .path.display())]
    UnrecordedLinkCount { path: PathBuf },
    #[error("dedcom.db holds a corrupt link count for {} ({detail}). Rescan, or move the old dedcom.db aside.", .path.display())]
    CorruptLinkCount { path: PathBuf, detail: String },
    #[error("dedcom.db holds different link counts ({low} and {high}) for the one allocation behind {}; its pathnames are the same inode and cannot disagree. Rescan, or move the old dedcom.db aside.", .path.display())]
    DisagreeingLinkCounts { path: PathBuf, low: u64, high: u64 },
    #[error("{} is one of {observed} pathnames of an allocation whose inode reports only {links} links; that manifest cannot be right. Rescan, or move the old dedcom.db aside.", .path.display())]
    ImpossibleManifest {
        path: PathBuf,
        observed: u64,
        links: u64,
    },
    #[error("{} carries a digest that was never verified against the file itself — rescan required", .path.display())]
    UnverifiedIdentity { path: PathBuf },
    #[error("{} is gone since the scan — rescan required", .path.display())]
    Vanished { path: PathBuf },
    #[error("{} is a symbolic link now — rescan required", .path.display())]
    Symlink { path: PathBuf },
    #[error("{} changed since the scan ({field}) — rescan required", .path.display())]
    Drifted { path: PathBuf, field: &'static str },
    #[error("{detail}")]
    Arithmetic { detail: String },
    #[error("dedcom.db could not be read while building the plan: {detail}")]
    Store { detail: String },
}

impl From<PlanRefusal> for AppError {
    fn from(refusal: PlanRefusal) -> Self {
        AppError::msg(refusal.to_string())
    }
}

/// The complete scan-local temporal identity of one allocation, plus the trust of the digest that
/// named it.
///
/// Eight fields, not the seven of `FileEntry::object_key`: a row whose digest this build never
/// verified against the file (`identity_version = 0`) must never fold into the same allocation as a
/// verified one. The whole claim of a plan is that two pathnames really are one inode, and an
/// unverified row is not evidence of that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanObjectKey {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    /// `1` = the digest was established against the file itself; `0` = it was not.
    pub identity_version: i64,
}

/// A live `stat` of a pathname, in the fields the persisted key records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub nlink: u64,
}

impl PlanObjectKey {
    /// The first field where a live `stat` disagrees with this key and the agreed link count, or
    /// `None` when the file on disk is still the one the plan measured.
    ///
    /// `identity_version` is not compared: it records how the digest was established, not anything
    /// `stat` can answer. The comparison order is fixed so the same drift always reports the same
    /// field.
    pub fn first_drift(&self, live: &LiveIdentity, links: u64) -> Option<&'static str> {
        let fields: [(&'static str, bool); 8] = [
            ("device", self.device == live.device),
            ("inode", self.inode == live.inode),
            ("size", self.size == live.size),
            ("mtime", self.mtime == live.mtime),
            ("mtime_nsec", self.mtime_nsec == live.mtime_nsec),
            ("ctime", self.ctime_sec == live.ctime_sec),
            ("ctime_nsec", self.ctime_nsec == live.ctime_nsec),
            ("link count", links == live.nlink),
        ];
        fields
            .into_iter()
            .find(|(_, agrees)| !agrees)
            .map(|(name, _)| name)
    }
}

/// One persisted pathname of a referenced group, as the plan is allowed to read it.
///
/// The constructor is the trust boundary: a row without a recorded link count, or with a digest
/// this build never verified, cannot become evidence at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanMemberEvidence {
    path: PathBuf,
    key: PlanObjectKey,
    links: u64,
    is_keeper: bool,
    action: Option<ActionKind>,
}

impl PlanMemberEvidence {
    pub fn new(
        path: PathBuf,
        key: PlanObjectKey,
        links: LinkCount,
        is_keeper: bool,
        action: Option<ActionKind>,
    ) -> PlanResult<Self> {
        if key.identity_version != 1 {
            return Err(PlanRefusal::UnverifiedIdentity { path });
        }
        let links = match links {
            LinkCount::Known(links) => links,
            LinkCount::Unknown => return Err(PlanRefusal::UnrecordedLinkCount { path }),
        };
        Ok(Self {
            path,
            key,
            links,
            is_keeper,
            action,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn key(&self) -> PlanObjectKey {
        self.key
    }

    pub fn links(&self) -> u64 {
        self.links
    }

    pub fn is_keeper(&self) -> bool {
        self.is_keeper
    }

    pub fn action(&self) -> Option<ActionKind> {
        self.action
    }
}

/// One referenced content group, with every persisted member — not only the marked ones.
///
/// Completeness is the point: an unmarked alias is exactly the evidence that decides whether the
/// selected pathnames free anything at all, and a vector built from a panel's marks cannot contain
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanGroupInput {
    pub hash: String,
    pub members: Vec<PlanMemberEvidence>,
}

/// What an object is doing in this plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRole {
    /// The allocation the group keeps; never a target.
    Keeper,
    /// At least one of its pathnames is being removed.
    Target,
    /// Neither — it is in the plan because its pathnames are what makes a target's claim true or
    /// false.
    Bystander,
}

/// One physical allocation behind the plan, with the evidence its figure rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedObject {
    key: PlanObjectKey,
    hash: String,
    representative: PathBuf,
    members: Vec<PathBuf>,
    links: u64,
    covered_links: u64,
    role: ObjectRole,
}

impl PlannedObject {
    pub fn key(&self) -> PlanObjectKey {
        self.key
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// The object's smallest pathname — how it is named to the operator.
    pub fn representative(&self) -> &Path {
        &self.representative
    }

    pub fn members(&self) -> &[PathBuf] {
        &self.members
    }

    /// The link count its inode reports, agreed across every alias.
    pub fn links(&self) -> u64 {
        self.links
    }

    /// Pathnames of this allocation the scan holds.
    pub fn observed_links(&self) -> u64 {
        self.members.len() as u64
    }

    /// Pathnames of this allocation this plan moves to quarantine.
    pub fn covered_links(&self) -> u64 {
        self.covered_links
    }

    /// Observed pathnames the plan leaves in place — each one keeps the allocation alive.
    pub fn remaining_inside(&self) -> u64 {
        self.observed_links().saturating_sub(self.covered_links)
    }

    /// Links the inode reports that this scan never saw.
    pub fn unobserved_links(&self) -> u64 {
        self.links.saturating_sub(self.observed_links())
    }

    pub fn role(&self) -> ObjectRole {
        self.role
    }

    /// What removing this object's covered pathnames is worth, and how far that is established.
    ///
    /// Exact zero rather than unknown when a pathname stays: an allocation with a link the plan
    /// does not touch keeps every block, and that is a measurement, not an absence of one. An
    /// upper bound is for the case the scan genuinely cannot settle — links outside it.
    pub fn estimate(&self) -> ReclaimEstimate {
        if self.covered_links == 0 || self.remaining_inside() > 0 {
            return ReclaimEstimate::exact(0);
        }
        if self.unobserved_links() > 0 {
            return ReclaimEstimate::upper_bound(self.key.size);
        }
        ReclaimEstimate::exact(self.key.size)
    }

    /// The sentence that explains a zero, or an upper bound, to the operator.
    pub fn warning(&self) -> Option<PlanWarning> {
        if self.covered_links == 0 {
            return None;
        }
        let remaining = self.remaining_inside();
        if remaining > 0 {
            return Some(PlanWarning::UncoveredAlias {
                representative: self.representative.clone(),
                remaining,
            });
        }
        let outside = self.unobserved_links();
        if outside > 0 {
            return Some(PlanWarning::ExternalLinks {
                representative: self.representative.clone(),
                outside,
            });
        }
        None
    }
}

/// Something the operator has to read before confirming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanWarning {
    /// The marked pathname is the keeper's own allocation — the D-4 case, kept visible rather than
    /// dropped in silence.
    AlreadyLinkedWithKeeper { path: PathBuf },
    /// A pathname of this allocation stays behind, so removing the others releases nothing.
    UncoveredAlias {
        representative: PathBuf,
        remaining: u64,
    },
    /// The inode has links this scan never saw; they keep the allocation alive whatever the plan
    /// does.
    ExternalLinks {
        representative: PathBuf,
        outside: u64,
    },
}

impl PlanWarning {
    /// The wording, in one place. No figure on this path is ever called freed: nothing is released
    /// until the quarantine is purged.
    pub fn message(&self) -> String {
        match self {
            Self::AlreadyLinkedWithKeeper { path } => format!(
                "already linked — 0 payoff: {} is the keeper's own allocation",
                path.display()
            ),
            Self::UncoveredAlias {
                representative,
                remaining,
            } => format!(
                "zero guaranteed reclaim — {}: {remaining} pathname(s) of this allocation stay outside the plan",
                representative.display()
            ),
            Self::ExternalLinks {
                representative,
                outside,
            } => format!(
                "zero guaranteed reclaim — {}: {outside} link(s) outside this scan keep this allocation alive",
                representative.display()
            ),
        }
    }
}

/// One action of a plan. It cannot exist without the objects it refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanAction {
    kind: ActionKind,
    target: PathBuf,
    keeper: PathBuf,
    target_object: usize,
    keeper_object: usize,
    size: u64,
    expected_hash: String,
}

impl PlanAction {
    pub fn kind(&self) -> ActionKind {
        self.kind
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn keeper(&self) -> &Path {
        &self.keeper
    }

    /// Index into `ActionPlan::objects`.
    pub fn target_object(&self) -> usize {
        self.target_object
    }

    /// Index into `ActionPlan::objects`.
    pub fn keeper_object(&self) -> usize {
        self.keeper_object
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn expected_hash(&self) -> &str {
        &self.expected_hash
    }
}

/// What the whole plan claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSummary {
    actions: usize,
    covered_objects: usize,
    estimate: ReclaimEstimate,
    warnings: Vec<PlanWarning>,
}

impl PlanSummary {
    pub fn actions(&self) -> usize {
        self.actions
    }

    /// Allocations at least one of whose pathnames this plan removes.
    pub fn covered_objects(&self) -> usize {
        self.covered_objects
    }

    /// The figure and its trust, in the accepted shape: `reclaim_phrase`/`reclaim_cell` render it.
    pub fn estimate(&self) -> ReclaimEstimate {
        self.estimate
    }

    pub fn guaranteed_bytes(&self) -> u64 {
        self.estimate.guaranteed_bytes()
    }

    pub fn potential_bytes(&self) -> Option<u64> {
        self.estimate.potential_bytes()
    }

    pub fn warnings(&self) -> &[PlanWarning] {
        &self.warnings
    }
}

/// A destructive plan: its actions, the allocations they touch, and one summary derived from both.
///
/// Private fields and a single fallible constructor, so an action can never be separated from the
/// evidence that justifies it and a total can never disagree with the objects it was folded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPlan {
    scan_id: i64,
    objects: Vec<PlannedObject>,
    actions: Vec<PlanAction>,
    summary: PlanSummary,
}

impl ActionPlan {
    /// Folds complete group evidence into a plan, or refuses.
    ///
    /// The caller hands over every persisted member of every referenced digest; which of them
    /// become actions is decided here, once, so two windows cannot reach different answers from the
    /// same database.
    pub fn try_new(scan_id: i64, mut groups: Vec<PlanGroupInput>) -> PlanResult<Self> {
        if groups.is_empty() {
            return Err(PlanRefusal::NoMarks);
        }
        groups.sort_by(|left, right| left.hash.cmp(&right.hash));

        let mut objects: Vec<PlannedObject> = Vec::new();
        let mut actions: Vec<PlanAction> = Vec::new();
        let mut warnings: Vec<PlanWarning> = Vec::new();

        for group in &groups {
            if group.members.is_empty() {
                return Err(PlanRefusal::MissingKeeper {
                    hash: group.hash.clone(),
                });
            }
            let mut members: Vec<&PlanMemberEvidence> = group.members.iter().collect();
            members.sort_by(|left, right| left.path.cmp(&right.path));

            // One digest is one content, so one size. Two sizes under one digest is a damaged
            // manifest, and the plan's arithmetic would be built on whichever row it read first.
            let size = members[0].key.size;
            if members.iter().any(|member| member.key.size != size) {
                return Err(PlanRefusal::InconsistentGroupSize {
                    hash: group.hash.clone(),
                });
            }

            let keeper = members.iter().find(|member| member.is_keeper).copied();
            let targets: Vec<&PlanMemberEvidence> = members
                .iter()
                .filter(|member| !member.is_keeper && member.action.is_some())
                .copied()
                .collect();
            let keeper = match (keeper, targets.is_empty()) {
                (Some(keeper), _) => keeper,
                // Nothing is being removed from this group; it contributes evidence only.
                (None, true) => {
                    push_objects(&mut objects, group, &members, None, &[])?;
                    continue;
                }
                (None, false) => {
                    return Err(PlanRefusal::MissingKeeper {
                        hash: group.hash.clone(),
                    })
                }
            };

            // D-4: a pathname that is already the keeper's own allocation is not removed — the
            // content has one copy on disk either way. It is reported rather than dropped, because
            // the operator marked it and has to see what became of the mark.
            let (covered, skipped): (Vec<&PlanMemberEvidence>, Vec<&PlanMemberEvidence>) = targets
                .into_iter()
                .partition(|target| target.key != keeper.key);
            for target in skipped {
                warnings.push(PlanWarning::AlreadyLinkedWithKeeper {
                    path: target.path.clone(),
                });
            }

            let first_object = objects.len();
            push_objects(&mut objects, group, &members, Some(keeper), &covered)?;
            let index_of = |key: PlanObjectKey| -> Option<usize> {
                objects[first_object..]
                    .iter()
                    .position(|object| object.key == key)
                    .map(|offset| offset + first_object)
            };
            let keeper_object = index_of(keeper.key).expect("the keeper is one of the members");
            for target in covered {
                let target_object = index_of(target.key).expect("a target is one of the members");
                actions.push(PlanAction {
                    kind: target.action.expect("targets carry an action"),
                    target: target.path.clone(),
                    keeper: keeper.path.clone(),
                    target_object,
                    keeper_object,
                    size,
                    expected_hash: group.hash.clone(),
                });
            }
        }

        if actions.is_empty() {
            return Err(if warnings.is_empty() {
                PlanRefusal::NoMarks
            } else {
                PlanRefusal::NothingToDo
            });
        }

        // The accepted scan-level fold: guaranteed sums what is established, the ceiling sums every
        // trusted bound, and the whole thing fails closed if it leaves the persisted integer domain.
        let estimate = ReclaimEstimate::for_fresh_scan(objects.iter().map(PlannedObject::estimate))
            .map_err(|err| PlanRefusal::Arithmetic {
                detail: err.to_string(),
            })?;
        warnings.extend(objects.iter().filter_map(PlannedObject::warning));

        let summary = PlanSummary {
            actions: actions.len(),
            covered_objects: objects
                .iter()
                .filter(|object| object.covered_links > 0)
                .count(),
            estimate,
            warnings,
        };
        Ok(Self {
            scan_id,
            objects,
            actions,
            summary,
        })
    }

    pub fn scan_id(&self) -> i64 {
        self.scan_id
    }

    pub fn objects(&self) -> &[PlannedObject] {
        &self.objects
    }

    /// Borrowed, never handed over: an action separated from its object evidence is a byte figure
    /// nobody can check.
    pub fn actions(&self) -> &[PlanAction] {
        &self.actions
    }

    pub fn summary(&self) -> &PlanSummary {
        &self.summary
    }

    /// The object an action removes a pathname of.
    pub fn target_object_of(&self, action: &PlanAction) -> &PlannedObject {
        &self.objects[action.target_object]
    }

    /// What a confirmation screen shows, derived from this plan and nothing else.
    pub fn digest(&self) -> PlanDigest {
        let mut counts = Vec::new();
        for kind in [
            ActionKind::Delete,
            ActionKind::Hardlink,
            ActionKind::Reflink,
        ] {
            let count = self
                .actions
                .iter()
                .filter(|action| action.kind == kind)
                .count();
            if count > 0 {
                counts.push((kind, count));
            }
        }
        let samples: Vec<(ActionKind, PathBuf)> = self
            .actions
            .iter()
            .take(PlanDigest::SAMPLES)
            .map(|action| (action.kind, action.target.clone()))
            .collect();
        PlanDigest {
            counts,
            hidden: self.actions.len() - samples.len(),
            samples,
            covered_objects: self.summary.covered_objects,
            estimate: self.summary.estimate,
            warnings: self.summary.warnings.clone(),
        }
    }
}

/// Everything a confirmation needs, quoted from one plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanDigest {
    pub counts: Vec<(ActionKind, usize)>,
    pub samples: Vec<(ActionKind, PathBuf)>,
    pub hidden: usize,
    pub covered_objects: usize,
    pub estimate: ReclaimEstimate,
    pub warnings: Vec<PlanWarning>,
}

impl PlanDigest {
    pub const SAMPLES: usize = 5;
}

/// Folds one group's members into objects and appends them in a stable order.
///
/// `covered` is the set of pathnames this plan removes from that group; every other member is
/// evidence. The link count is agreed across an object's aliases before anything is counted, by the
/// same rule the SQL and RAM group paths use.
fn push_objects(
    objects: &mut Vec<PlannedObject>,
    group: &PlanGroupInput,
    members: &[&PlanMemberEvidence],
    keeper: Option<&PlanMemberEvidence>,
    covered: &[&PlanMemberEvidence],
) -> PlanResult<()> {
    let mut by_key: BTreeMap<PlanObjectKey, Vec<&PlanMemberEvidence>> = BTreeMap::new();
    for member in members {
        by_key.entry(member.key).or_default().push(member);
    }

    let mut built: Vec<PlannedObject> = Vec::with_capacity(by_key.len());
    for (key, aliases) in by_key {
        let low = aliases
            .iter()
            .map(|alias| alias.links)
            .min()
            .expect("a key exists because a member has it");
        let high = aliases
            .iter()
            .map(|alias| alias.links)
            .max()
            .expect("a key exists because a member has it");
        let representative = aliases[0].path.clone();
        // The accepted gate, in typed form: one allocation cannot report two link counts.
        LinkCount::agreed(
            LinkCount::Known(low),
            LinkCount::Known(high),
            &representative.display().to_string(),
        )
        .map_err(|_| PlanRefusal::DisagreeingLinkCounts {
            path: representative.clone(),
            low,
            high,
        })?;
        let observed = aliases.len() as u64;
        if observed > low {
            return Err(PlanRefusal::ImpossibleManifest {
                path: representative,
                observed,
                links: low,
            });
        }
        let covered_links = covered.iter().filter(|target| target.key == key).count() as u64;
        let role = match keeper {
            Some(keeper) if keeper.key == key => ObjectRole::Keeper,
            _ if covered_links > 0 => ObjectRole::Target,
            _ => ObjectRole::Bystander,
        };
        built.push(PlannedObject {
            key,
            hash: group.hash.clone(),
            representative,
            members: aliases.iter().map(|alias| alias.path.clone()).collect(),
            links: low,
            covered_links,
            role,
        });
    }
    // Named by their smallest pathname, so a report reads in the order an operator would expect.
    built.sort_by(|left, right| left.representative.cmp(&right.representative));
    objects.extend(built);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 4096;

    fn key(inode: u64, size: u64) -> PlanObjectKey {
        PlanObjectKey {
            device: 66310,
            inode,
            size,
            mtime: 1_700_000_000,
            mtime_nsec: 123,
            ctime_sec: 1_700_000_001,
            ctime_nsec: 456,
            identity_version: 1,
        }
    }

    fn member(
        path: &str,
        key: PlanObjectKey,
        links: u64,
        is_keeper: bool,
        action: Option<ActionKind>,
    ) -> PlanMemberEvidence {
        PlanMemberEvidence::new(
            PathBuf::from(path),
            key,
            LinkCount::Known(links),
            is_keeper,
            action,
        )
        .expect("the fixture is well formed")
    }

    fn group(members: Vec<PlanMemberEvidence>) -> PlanGroupInput {
        PlanGroupInput {
            hash: "ab".repeat(32),
            members,
        }
    }

    /// The defect the whole checkpoint exists for: two pathnames of ONE allocation, and only one of
    /// them selected. The other pathname keeps every block, so the plan is worth nothing — and the
    /// unmarked alias is evidence the plan only has because the store hands over complete groups.
    #[test]
    fn one_selected_alias_of_two_guarantees_nothing() {
        let alias = key(11, S);
        let plan = ActionPlan::try_new(
            1,
            vec![group(vec![
                member("/x/keeper.bin", key(10, S), 1, true, None),
                member("/x/alias_0.bin", alias, 2, false, Some(ActionKind::Delete)),
                member("/x/alias_1.bin", alias, 2, false, None),
            ])],
        )
        .expect("a plan is allowed, it is simply worth nothing");

        assert_eq!(plan.actions().len(), 1);
        assert_eq!(plan.summary().guaranteed_bytes(), 0);
        assert_eq!(plan.summary().potential_bytes(), Some(0));
        let object = plan.target_object_of(&plan.actions()[0]);
        assert_eq!(
            (
                object.links(),
                object.observed_links(),
                object.covered_links(),
                object.remaining_inside()
            ),
            (2, 2, 1, 1)
        );
        assert_eq!(
            plan.summary().warnings(),
            &[PlanWarning::UncoveredAlias {
                representative: PathBuf::from("/x/alias_0.bin"),
                remaining: 1,
            }]
        );
        assert!(plan.summary().warnings()[0]
            .message()
            .starts_with("zero guaranteed reclaim"));
    }

    /// Both pathnames of the allocation selected: one allocation goes, so the plan is worth one
    /// size — never two, however many pathnames were marked.
    #[test]
    fn both_selected_aliases_are_one_allocation_not_two() {
        let alias = key(11, S);
        let plan = ActionPlan::try_new(
            1,
            vec![group(vec![
                member("/x/keeper.bin", key(10, S), 1, true, None),
                member("/x/alias_0.bin", alias, 2, false, Some(ActionKind::Delete)),
                member("/x/alias_1.bin", alias, 2, false, Some(ActionKind::Delete)),
            ])],
        )
        .expect("a fully covered allocation is plannable");

        assert_eq!(plan.actions().len(), 2, "two pathnames are removed");
        assert_eq!(
            plan.summary().covered_objects(),
            1,
            "one allocation is freed"
        );
        assert_eq!(plan.summary().guaranteed_bytes(), S);
        assert_eq!(plan.summary().potential_bytes(), Some(S));
        assert!(plan.summary().warnings().is_empty());
    }

    /// A link the scan never saw keeps the allocation alive, so nothing is guaranteed — but the
    /// ceiling stays, because the scan cannot settle what is outside it.
    #[test]
    fn an_unobserved_external_link_guarantees_nothing_and_says_so() {
        let twin = key(11, S);
        let plan = ActionPlan::try_new(
            1,
            vec![group(vec![
                member("/x/keeper.bin", key(10, S), 1, true, None),
                member("/x/twin_b.bin", twin, 2, false, Some(ActionKind::Delete)),
            ])],
        )
        .expect("an upper-bound plan is allowed");

        assert_eq!(plan.summary().guaranteed_bytes(), 0);
        assert_eq!(plan.summary().potential_bytes(), Some(S));
        assert_eq!(
            plan.summary().warnings(),
            &[PlanWarning::ExternalLinks {
                representative: PathBuf::from("/x/twin_b.bin"),
                outside: 1,
            }]
        );
        assert!(
            !plan.summary().warnings()[0].message().contains("freed"),
            "nothing is freed before the quarantine is purged"
        );
    }

    /// The positive control: two independent files, one removed, one size guaranteed.
    #[test]
    fn independent_twins_guarantee_their_size() {
        let plan = ActionPlan::try_new(
            1,
            vec![group(vec![
                member("/x/keeper.bin", key(10, S), 1, true, None),
                member(
                    "/x/twin.bin",
                    key(11, S),
                    1,
                    false,
                    Some(ActionKind::Delete),
                ),
            ])],
        )
        .expect("the ordinary case");

        assert_eq!(plan.summary().guaranteed_bytes(), S);
        assert_eq!(plan.summary().potential_bytes(), Some(S));
        assert_eq!(plan.summary().covered_objects(), 1);
        assert!(plan.summary().warnings().is_empty());
    }

    /// D-4: a marked pathname that is already the keeper's own allocation produces no action, and
    /// says so instead of disappearing.
    #[test]
    fn a_target_that_is_the_keepers_own_allocation_is_reported_not_dropped() {
        let shared = key(10, S);
        let refusal = ActionPlan::try_new(
            1,
            vec![group(vec![
                member("/x/keeper.bin", shared, 2, true, None),
                member("/x/linked.bin", shared, 2, false, Some(ActionKind::Delete)),
            ])],
        )
        .expect_err("nothing is left to do");
        assert_eq!(refusal, PlanRefusal::NothingToDo);

        // With one real target beside it the plan stands, and the skip is still visible.
        let plan = ActionPlan::try_new(
            1,
            vec![group(vec![
                member("/x/keeper.bin", shared, 2, true, None),
                member("/x/linked.bin", shared, 2, false, Some(ActionKind::Delete)),
                member(
                    "/x/twin.bin",
                    key(11, S),
                    1,
                    false,
                    Some(ActionKind::Delete),
                ),
            ])],
        )
        .expect("the independent twin is still worth removing");
        assert_eq!(plan.actions().len(), 1);
        assert_eq!(plan.actions()[0].target(), Path::new("/x/twin.bin"));
        assert!(plan
            .summary()
            .warnings()
            .contains(&PlanWarning::AlreadyLinkedWithKeeper {
                path: PathBuf::from("/x/linked.bin"),
            }));
        assert_eq!(plan.summary().guaranteed_bytes(), S);
    }

    /// The two rows that may never become evidence at all.
    #[test]
    fn evidence_refuses_an_unrecorded_count_and_an_unverified_digest() {
        assert_eq!(
            PlanMemberEvidence::new(
                PathBuf::from("/x/a.bin"),
                key(10, S),
                LinkCount::Unknown,
                false,
                Some(ActionKind::Delete),
            )
            .expect_err("a legacy row"),
            PlanRefusal::UnrecordedLinkCount {
                path: PathBuf::from("/x/a.bin")
            }
        );
        let unverified = PlanObjectKey {
            identity_version: 0,
            ..key(10, S)
        };
        assert_eq!(
            PlanMemberEvidence::new(
                PathBuf::from("/x/a.bin"),
                unverified,
                LinkCount::Known(1),
                false,
                Some(ActionKind::Delete),
            )
            .expect_err("a digest nobody verified"),
            PlanRefusal::UnverifiedIdentity {
                path: PathBuf::from("/x/a.bin")
            }
        );
    }

    /// Manifests that cannot be right refuse the plan rather than being reasoned around.
    #[test]
    fn impossible_and_disagreeing_manifests_refuse() {
        let alias = key(11, S);
        assert_eq!(
            ActionPlan::try_new(
                1,
                vec![group(vec![
                    member("/x/keeper.bin", key(10, S), 1, true, None),
                    member("/x/alias_0.bin", alias, 1, false, Some(ActionKind::Delete)),
                    member("/x/alias_1.bin", alias, 1, false, None),
                ])],
            )
            .expect_err("two pathnames, one link"),
            PlanRefusal::ImpossibleManifest {
                path: PathBuf::from("/x/alias_0.bin"),
                observed: 2,
                links: 1,
            }
        );
        assert_eq!(
            ActionPlan::try_new(
                1,
                vec![group(vec![
                    member("/x/keeper.bin", key(10, S), 1, true, None),
                    member("/x/alias_0.bin", alias, 2, false, Some(ActionKind::Delete)),
                    member("/x/alias_1.bin", alias, 3, false, None),
                ])],
            )
            .expect_err("one inode, two counts"),
            PlanRefusal::DisagreeingLinkCounts {
                path: PathBuf::from("/x/alias_0.bin"),
                low: 2,
                high: 3,
            }
        );
    }

    /// A group with targets and no keeper, and a digest whose rows disagree on size.
    #[test]
    fn a_missing_keeper_and_a_split_size_refuse() {
        assert_eq!(
            ActionPlan::try_new(
                1,
                vec![group(vec![member(
                    "/x/twin.bin",
                    key(11, S),
                    1,
                    false,
                    Some(ActionKind::Delete)
                )])],
            )
            .expect_err("nothing says what to keep"),
            PlanRefusal::MissingKeeper {
                hash: "ab".repeat(32)
            }
        );
        assert_eq!(
            ActionPlan::try_new(
                1,
                vec![group(vec![
                    member("/x/keeper.bin", key(10, S), 1, true, None),
                    member(
                        "/x/twin.bin",
                        key(11, S * 2),
                        1,
                        false,
                        Some(ActionKind::Delete)
                    ),
                ])],
            )
            .expect_err("one digest cannot have two sizes"),
            PlanRefusal::InconsistentGroupSize {
                hash: "ab".repeat(32)
            }
        );
    }

    /// A total that would leave the persisted integer domain fails closed, in the same checked
    /// arithmetic the scan total uses.
    #[test]
    fn a_total_beyond_the_persisted_domain_refuses() {
        let huge = i64::MAX as u64;
        let mut first = group(vec![
            member("/x/a_keeper.bin", key(10, huge), 1, true, None),
            member(
                "/x/a_twin.bin",
                key(11, huge),
                1,
                false,
                Some(ActionKind::Delete),
            ),
        ]);
        first.hash = "aa".repeat(32);
        let mut second = group(vec![
            member("/x/b_keeper.bin", key(20, huge), 1, true, None),
            member(
                "/x/b_twin.bin",
                key(21, huge),
                1,
                false,
                Some(ActionKind::Delete),
            ),
        ]);
        second.hash = "bb".repeat(32);
        let refusal = ActionPlan::try_new(1, vec![first, second]).expect_err("two maxima");
        assert!(
            matches!(refusal, PlanRefusal::Arithmetic { .. }),
            "{refusal:?}"
        );
    }

    /// Nothing marked at all is not a plan.
    #[test]
    fn an_empty_input_refuses() {
        assert_eq!(
            ActionPlan::try_new(1, Vec::new()).expect_err("no groups"),
            PlanRefusal::NoMarks
        );
        assert_eq!(
            ActionPlan::try_new(
                1,
                vec![group(vec![member(
                    "/x/keeper.bin",
                    key(10, S),
                    1,
                    true,
                    None
                )])]
            )
            .expect_err("a keeper alone removes nothing"),
            PlanRefusal::NoMarks
        );
    }

    /// The same evidence in a different order is the same plan, in the same order.
    #[test]
    fn identical_evidence_builds_an_equal_plan_in_a_stable_order() {
        let alias = key(11, S);
        let forward = vec![
            member("/x/keeper.bin", key(10, S), 1, true, None),
            member("/x/alias_0.bin", alias, 2, false, Some(ActionKind::Delete)),
            member("/x/alias_1.bin", alias, 2, false, Some(ActionKind::Delete)),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();

        let left = ActionPlan::try_new(1, vec![group(forward)]).unwrap();
        let right = ActionPlan::try_new(1, vec![group(reversed)]).unwrap();
        assert_eq!(left, right, "the input order is not part of the answer");
        let targets: Vec<&Path> = left.actions().iter().map(PlanAction::target).collect();
        assert_eq!(
            targets,
            vec![Path::new("/x/alias_0.bin"), Path::new("/x/alias_1.bin")],
            "actions read in pathname order"
        );
    }

    /// The digest is derived, so it cannot describe a different plan than the one it came from.
    #[test]
    fn the_digest_cannot_disagree_with_its_plan() {
        let alias = key(11, S);
        let plan = ActionPlan::try_new(
            1,
            vec![group(vec![
                member("/x/keeper.bin", key(10, S), 1, true, None),
                member("/x/alias_0.bin", alias, 2, false, Some(ActionKind::Delete)),
                member("/x/alias_1.bin", alias, 2, false, Some(ActionKind::Delete)),
            ])],
        )
        .unwrap();
        let digest = plan.digest();
        assert_eq!(digest.counts, vec![(ActionKind::Delete, 2)]);
        assert_eq!(
            digest.counts.iter().map(|(_, count)| count).sum::<usize>(),
            plan.actions().len()
        );
        assert_eq!(digest.estimate, plan.summary().estimate());
        assert_eq!(digest.covered_objects, plan.summary().covered_objects());
        assert_eq!(digest.hidden, 0);
        assert_eq!(digest.samples.len(), 2);
        assert_eq!(digest.warnings, plan.summary().warnings());
    }

    /// The live comparison names the first field that moved, and ignores the one `stat` cannot
    /// answer.
    #[test]
    fn the_live_comparison_names_what_moved() {
        let persisted = key(11, S);
        let live = LiveIdentity {
            device: persisted.device,
            inode: persisted.inode,
            size: persisted.size,
            mtime: persisted.mtime,
            mtime_nsec: persisted.mtime_nsec,
            ctime_sec: persisted.ctime_sec,
            ctime_nsec: persisted.ctime_nsec,
            nlink: 2,
        };
        assert_eq!(persisted.first_drift(&live, 2), None);
        assert_eq!(persisted.first_drift(&live, 3), Some("link count"));
        assert_eq!(
            persisted.first_drift(&LiveIdentity { inode: 12, ..live }, 2),
            Some("inode")
        );
        assert_eq!(
            persisted.first_drift(
                &LiveIdentity {
                    ctime_nsec: 999,
                    ..live
                },
                2
            ),
            Some("ctime_nsec")
        );
        assert_eq!(
            PlanObjectKey {
                identity_version: 0,
                ..persisted
            }
            .first_drift(&live, 2),
            None,
            "how a digest was established is not something stat can disagree with"
        );
    }
}
