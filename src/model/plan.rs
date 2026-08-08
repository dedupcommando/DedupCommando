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
//! Since R2D-C5-2 this is the only shape a destructive plan has: both windows, the review, both
//! confirmations, the saved script and the apply worker read this one value, and the pathname-based
//! builders it replaced are gone. The same module also owns what happens to the plan afterwards —
//! the structural preflight, the runtime ledger that tracks the batch's own transitions, and the
//! realization that says what was achieved rather than what was attempted.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
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
    #[error("{} is marked as {} in this window and as {} in the database — re-mark it", .path.display(), .requested.describe(), .durable.describe())]
    MarkDisagrees {
        path: PathBuf,
        requested: MarkIntent,
        durable: MarkIntent,
    },
    #[error("{} was requested twice with two different meanings", .path.display())]
    RequestContradictsItself { path: PathBuf },
    #[error("dedcom.db holds an unreadable mark for {} ({field}: {detail}). Rescan, or move the old dedcom.db aside.", .path.display())]
    CorruptMark {
        path: PathBuf,
        field: &'static str,
        detail: String,
    },
    #[error("{} is marked both as the keeper and for an action. Re-mark it, or move the old dedcom.db aside.", .path.display())]
    ContradictoryMark { path: PathBuf },
    #[error("{} is marked but belongs to no published group — the results changed since it was marked; rescan required", .path.display())]
    NotAMember { path: PathBuf },
    #[error("the plan references scan {found} while planning scan {expected} — rescan required")]
    ForeignScan { expected: i64, found: i64 },
    #[error("the plan mixes publication generations {expected} and {found} — rescan required")]
    MixedGeneration { expected: i64, found: i64 },
    #[error("the plan references an invalid group rank {rank} — rescan required")]
    NegativeRank { rank: i64 },
    #[error("the group {hash} has two keepers ({} and {}) — exactly one file is kept", .first.display(), .second.display())]
    MultipleKeepers {
        hash: String,
        first: PathBuf,
        second: PathBuf,
    },
    #[error("the group {hash} was handed to the plan twice")]
    DuplicateGroupInput { hash: String },
    #[error("{} appears twice in the plan's evidence", .path.display())]
    DuplicatePathEvidence { path: PathBuf },
    #[error("{} is one allocation carrying two digests ({first} and {second}). Rescan, or move the old dedcom.db aside.", .path.display())]
    ObjectInTwoGroups {
        path: PathBuf,
        first: String,
        second: String,
    },
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
    #[error("{} is now the same allocation as its keeper {} — rescan required", .target.display(), .keeper.display())]
    AlreadyLinkedNow { target: PathBuf, keeper: PathBuf },
    #[error("{} moved while the batch was running ({field}) — action cancelled", .path.display())]
    ExternalChange { path: PathBuf, field: &'static str },
    #[error("{} was left in a state this batch cannot account for — nothing more is applied to it", .path.display())]
    UnsettledObject { path: PathBuf },
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

/// What a mark means. The two states are exclusive by construction, so «keeper AND delete» is a
/// shape this type cannot hold — the database can, and decoding one refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkIntent {
    /// The file that stays; no action is applied to it.
    Keeper,
    /// The action the operator asked for on this pathname.
    Act(ActionKind),
}

impl MarkIntent {
    /// How the mark reads in a refusal.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Keeper => "the keeper",
            Self::Act(kind) => kind.label(),
        }
    }
}

/// One mark exactly as the window that asks for a plan believes it stands.
///
/// The store compares this with the durable mark for the same pathname, so a mark whose write to
/// the database failed cannot be quietly replaced by the older meaning it was supposed to overwrite
/// — the operator would confirm a screen that says DELETE over a database that still says HARDLINK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedMark {
    pub path: PathBuf,
    pub intent: MarkIntent,
}

impl RequestedMark {
    pub fn keeper(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            intent: MarkIntent::Keeper,
        }
    }

    pub fn acting(path: impl Into<PathBuf>, kind: ActionKind) -> Self {
        Self {
            path: path.into(),
            intent: MarkIntent::Act(kind),
        }
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
    /// `None` — a member of the group nobody marked. It is evidence all the same: it is what
    /// decides whether removing its siblings releases anything.
    mark: Option<MarkIntent>,
}

impl PlanMemberEvidence {
    pub fn new(
        path: PathBuf,
        key: PlanObjectKey,
        links: LinkCount,
        mark: Option<MarkIntent>,
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
            mark,
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

    pub fn mark(&self) -> Option<MarkIntent> {
        self.mark
    }

    pub fn is_keeper(&self) -> bool {
        matches!(self.mark, Some(MarkIntent::Keeper))
    }

    pub fn action(&self) -> Option<ActionKind> {
        match self.mark {
            Some(MarkIntent::Act(kind)) => Some(kind),
            _ => None,
        }
    }
}

/// One referenced content group, with every persisted member — not only the marked ones.
///
/// Completeness is the point: an unmarked alias is exactly the evidence that decides whether the
/// selected pathnames free anything at all, and a vector built from a panel's marks cannot contain
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanGroupInput {
    /// The authoritative identity of the published group this evidence came from. The plan is
    /// keyed by it — never by the digest, which two Explicit ranks may legitimately share.
    pub id: GroupId,
    /// The digest the group's CURRENT summary carried at planning time (lower hex).
    pub hash: String,
    pub members: Vec<PlanMemberEvidence>,
}

/// The authoritative identity of one published group: which scan, which rank in that scan's
/// current publication, and which publication (generation) assigned the rank. Rank alone is not
/// identity — every publication reassigns ranks by payoff — so the generation travels with every
/// rank; and the digest is deliberately NOT here — it is content, not identity, and two explicit
/// ranks may legitimately share one.
///
/// Since R4B-2c this is the key of `PlanGroupInput`, of every published summary row the UI
/// holds, and of every group answer the browsing actor gives — including the cross-panel match
/// set, which is why it hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId {
    pub scan_id: i64,
    pub rank: i64,
    pub generation: i64,
}

/// One planned group as the plan remembers it: the identity, the digest the summary carried at
/// planning time (lower hex, the `file_group.hash` domain), and the exact member pathnames in
/// their persisted `file.path` spelling. The witness owns the digest so the lease can compare
/// what the plan remembered against what the CURRENT summary says — a substituted digest is
/// caught rather than followed.
///
/// Staged by R4B-1 with no production caller; R4B-2 puts the witness into `ActionPlan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupWitness {
    pub id: GroupId,
    pub digest: String,
    pub members: Vec<PathBuf>,
}

/// Everything the membership lease revalidates against the live database before a destructive
/// batch may begin. Pathname boundaries are vector boundaries: a member containing LF is one
/// member here and one row in storage, never a delimited list.
///
/// Staged by R4B-1 with no production caller; R4B-2 puts the witness into `ActionPlan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanWitness {
    pub scan_id: i64,
    pub generation: i64,
    pub groups: Vec<GroupWitness>,
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

    /// The same statement without the pathname.
    ///
    /// A deep pathname is longer than a panel is wide, and a line clipped at the right edge loses
    /// the half that explains the zero — which is the half the operator needs. The screens that
    /// name the pathname elsewhere (the review list, the confirmation's quoted targets) print
    /// this; the script header and the final summary, which have no width to fight over, print
    /// the whole sentence.
    pub fn reason(&self) -> String {
        match self {
            Self::AlreadyLinkedWithKeeper { .. } => {
                "already linked — 0 payoff: the keeper's own allocation".to_string()
            }
            Self::UncoveredAlias { remaining, .. } => format!(
                "zero guaranteed reclaim — {remaining} pathname(s) of this allocation stay outside the plan"
            ),
            Self::ExternalLinks { outside, .. } => format!(
                "zero guaranteed reclaim — {outside} link(s) outside this scan keep this allocation alive"
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    /// What the apply lease revalidates before the batch may begin. Derived from the same
    /// group inputs the actions were folded from, so the plan and its witness cannot describe
    /// two different populations.
    witness: PlanWitness,
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
        // Identity first: every group must belong to THIS scan and to ONE publication, and a
        // rank below zero names nothing. Checked before any evidence is read, so nothing can
        // be folded from a group the plan had no right to reference.
        let generation = groups[0].id.generation;
        for group in &groups {
            if group.id.scan_id != scan_id {
                return Err(PlanRefusal::ForeignScan {
                    expected: scan_id,
                    found: group.id.scan_id,
                });
            }
            if group.id.rank < 0 {
                return Err(PlanRefusal::NegativeRank {
                    rank: group.id.rank,
                });
            }
            if group.id.generation != generation {
                return Err(PlanRefusal::MixedGeneration {
                    expected: generation,
                    found: group.id.generation,
                });
            }
        }
        // One normalisation up front, so every check below and every figure that follows reads the
        // same evidence in the same order. Rank is the identity order of one publication.
        groups.sort_by_key(|group| group.id.rank);
        for group in &mut groups {
            group
                .members
                .sort_by(|left, right| left.path.cmp(&right.path));
        }
        Self::check_global_evidence(&groups)?;
        // The witness is derived from the same inputs the actions are folded from below —
        // one source, so the lease revalidates exactly what was planned.
        let witness = PlanWitness {
            scan_id,
            generation,
            groups: groups
                .iter()
                .map(|group| GroupWitness {
                    id: group.id,
                    digest: group.hash.clone(),
                    members: group
                        .members
                        .iter()
                        .map(|member| member.path.clone())
                        .collect(),
                })
                .collect(),
        };

        let mut objects: Vec<PlannedObject> = Vec::new();
        let mut actions: Vec<PlanAction> = Vec::new();
        let mut warnings: Vec<PlanWarning> = Vec::new();

        for group in &groups {
            let members = &group.members;
            if members.is_empty() {
                return Err(PlanRefusal::MissingKeeper {
                    hash: group.hash.clone(),
                });
            }

            // One digest is one content, so one size. Two sizes under one digest is a damaged
            // manifest, and the plan's arithmetic would be built on whichever row it read first.
            let size = members[0].key.size;
            if members.iter().any(|member| member.key.size != size) {
                return Err(PlanRefusal::InconsistentGroupSize {
                    hash: group.hash.clone(),
                });
            }

            // Exactly one file is kept. Two keeper marks are not a preference to resolve by sort
            // order — they are two different plans, and only the operator knows which one they
            // meant. `file_mark` has no constraint against it and the commander writes one pathname
            // at a time, so this is reachable without touching the database by hand.
            let keepers: Vec<&PlanMemberEvidence> =
                members.iter().filter(|member| member.is_keeper()).collect();
            if keepers.len() > 1 {
                return Err(PlanRefusal::MultipleKeepers {
                    hash: group.hash.clone(),
                    first: keepers[0].path.clone(),
                    second: keepers[1].path.clone(),
                });
            }
            let targets: Vec<&PlanMemberEvidence> = members
                .iter()
                .filter(|member| !member.is_keeper() && member.action().is_some())
                .collect();
            let keeper = match (keepers.first().copied(), targets.is_empty()) {
                (Some(keeper), _) => keeper,
                // Nothing is being removed from this group; it contributes evidence only.
                (None, true) => {
                    push_objects(&mut objects, group, members, None, &[])?;
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
            push_objects(&mut objects, group, members, Some(keeper), &covered)?;
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
                    kind: target.action().expect("targets carry an action"),
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
            witness,
        })
    }

    /// The invariants that hold over the WHOLE input rather than inside one group.
    ///
    /// A plan is arithmetic over evidence, so evidence that says one thing twice is not something to
    /// merge, pick a winner from or count twice — it is a damaged database, and the plan refuses.
    /// Checked before any total or action is folded, so nothing is derived from it first.
    fn check_global_evidence(groups: &[PlanGroupInput]) -> PlanResult<()> {
        // Input identity is the GroupId, not the digest: two Explicit ranks may legitimately
        // share one digest and are two different groups.
        for pair in groups.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(PlanRefusal::DuplicateGroupInput {
                    hash: pair[0].hash.clone(),
                });
            }
        }
        let mut paths: BTreeSet<&Path> = BTreeSet::new();
        let mut owner: BTreeMap<PlanObjectKey, (&str, &Path)> = BTreeMap::new();
        for group in groups {
            for member in &group.members {
                if !paths.insert(member.path.as_path()) {
                    return Err(PlanRefusal::DuplicatePathEvidence {
                        path: member.path.clone(),
                    });
                }
                match owner.entry(member.key) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert((group.hash.as_str(), member.path.as_path()));
                    }
                    std::collections::btree_map::Entry::Occupied(slot) => {
                        let (first_hash, first_path) = *slot.get();
                        // One inode holds one content. The same allocation under two digests would
                        // be counted — and acted on — as two groups.
                        if first_hash != group.hash {
                            return Err(PlanRefusal::ObjectInTwoGroups {
                                path: first_path.to_path_buf(),
                                first: first_hash.to_string(),
                                second: group.hash.clone(),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn scan_id(&self) -> i64 {
        self.scan_id
    }

    /// The witness the guarded apply revalidates. Borrowed: it lives and dies with the plan.
    pub fn witness(&self) -> &PlanWitness {
        &self.witness
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

    /// The object an action links or clones from.
    pub fn keeper_object_of(&self, action: &PlanAction) -> &PlannedObject {
        &self.objects[action.keeper_object]
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

    /// The one structural check over the whole plan, against the disk.
    ///
    /// Every target, every keeper and every other persisted member of every referenced object: it
    /// exists, it is not a symlink, its complete temporal identity is the one the manifest recorded,
    /// its inode still reports the agreed link count, and no target is the keeper's own allocation.
    /// A mismatch anywhere refuses the WHOLE plan and names the pathname and the field — a claim
    /// that spans two aliases is not something to discover halfway through.
    ///
    /// The store calls it before it hands a plan out, and `apply_batch` calls it twice more: once
    /// before the first snapshot, and once after every snapshot immediately before the first
    /// mutation. The second reading is what the runtime ledger starts from, because a scan-time row
    /// is stale by construction.
    pub fn preflight(&self) -> PlanResult<PlanLiveState> {
        let mut objects: Vec<ObjectState> = Vec::with_capacity(self.objects.len());
        for object in &self.objects {
            let mut identity: Option<LiveIdentity> = None;
            for path in object.members() {
                let live = live_identity(path)?;
                if let Some(field) = object.key().first_drift(&live, object.links()) {
                    return Err(PlanRefusal::Drifted {
                        path: path.clone(),
                        field,
                    });
                }
                identity = Some(live);
            }
            // The plan counted pathnames of this allocation; the inode has to be able to hold them.
            // Checked again here rather than trusted from build time: `links` is what the live
            // `stat` just agreed to, and coverage is what the figure rests on.
            let live = identity.ok_or_else(|| PlanRefusal::MissingKeeper {
                hash: object.hash().to_string(),
            })?;
            if object.observed_links() > live.nlink
                || object.covered_links() > object.observed_links()
            {
                return Err(PlanRefusal::ImpossibleManifest {
                    path: object.representative().to_path_buf(),
                    observed: object.observed_links(),
                    links: live.nlink,
                });
            }
            objects.push(ObjectState {
                identity: live,
                paths: object.members().to_vec(),
                settled: true,
            });
        }
        // D-4, live: an action whose target became the keeper's own allocation after the plan was
        // built would push the keeper's own data through the evacuate/publish cycle.
        for action in &self.actions {
            let target = &objects[action.target_object].identity;
            let keeper = &objects[action.keeper_object].identity;
            if (target.device, target.inode) == (keeper.device, keeper.inode) {
                return Err(PlanRefusal::AlreadyLinkedNow {
                    target: action.target.clone(),
                    keeper: action.keeper.clone(),
                });
            }
        }
        Ok(PlanLiveState { objects })
    }

    /// What the batch achieved, object by object, from this plan and the typed outcomes of its
    /// actions — never from pathname sizes.
    ///
    /// `outcomes` is parallel to [`ActionPlan::actions`] and may be shorter: a cancelled batch never
    /// reached the rest. An object whose actions all succeeded keeps its own figure even when
    /// another object failed, because they are different allocations.
    pub fn realize(
        &self,
        outcomes: &[ActionResult],
    ) -> PlanResult<(Vec<(PlanObjectKey, ObjectRealization)>, RealizedSummary)> {
        let mut realized = Vec::new();
        for (index, object) in self.objects.iter().enumerate() {
            if object.covered_links() == 0 {
                continue;
            }
            let mine: Vec<Option<&ActionResult>> = self
                .actions
                .iter()
                .enumerate()
                .filter(|(_, action)| action.target_object == index)
                .map(|(position, _)| outcomes.get(position))
                .collect();
            realized.push((object.key(), object_realization(object, &mine)));
        }
        // A pathname the plan skipped because it was already the keeper's own allocation is still
        // something the operator marked. It reports its own zero rather than vanishing from the
        // result the way it used to vanish from the plan.
        for warning in &self.summary.warnings {
            if let PlanWarning::AlreadyLinkedWithKeeper { path } = warning {
                if let Some(object) = self
                    .objects
                    .iter()
                    .find(|object| object.members().iter().any(|member| member == path))
                {
                    realized.push((
                        object.key(),
                        ObjectRealization::Zero {
                            reason: ZeroReason::AlreadyLinked,
                        },
                    ));
                }
            }
        }
        let summary = RealizedSummary::fold(realized.iter().map(|(_, state)| state))?;
        Ok((realized, summary))
    }
}

/// The verdict for one covered object, in a fixed order so the same run always reads the same way.
///
/// Ambiguity first, then what the batch did, then what the plan itself already knew: an operator
/// who has a stranded original needs to be told that before anything else on the screen.
fn object_realization(
    object: &PlannedObject,
    results: &[Option<&ActionResult>],
) -> ObjectRealization {
    for result in results.iter().flatten() {
        if let ActionResult::Stranded { quarantine, detail }
        | ActionResult::Unsettled { quarantine, detail } = result
        {
            return ObjectRealization::Unknown {
                reason: detail.clone(),
                quarantine: Some(quarantine.clone()),
            };
        }
    }
    if results.iter().any(Option::is_none) {
        return ObjectRealization::Zero {
            reason: ZeroReason::Cancelled,
        };
    }
    let removed = results
        .iter()
        .flatten()
        .filter(|result| matches!(result, ActionResult::Removed))
        .count();
    if results
        .iter()
        .flatten()
        .any(|result| matches!(result, ActionResult::Refused { rolled_back: true }))
    {
        return ObjectRealization::Zero {
            reason: ZeroReason::RolledBack,
        };
    }
    if results
        .iter()
        .flatten()
        .any(|result| matches!(result, ActionResult::Refused { .. }))
    {
        return ObjectRealization::Zero {
            reason: if removed > 0 {
                ZeroReason::PartialCoverage
            } else {
                ZeroReason::Refused
            },
        };
    }
    // Everything the plan asked for happened. What the allocation is worth is still the plan's
    // arithmetic: a pathname left behind, or a link outside the scan, keeps every block.
    if object.remaining_inside() > 0 {
        return ObjectRealization::Zero {
            reason: ZeroReason::NotFullyCovered,
        };
    }
    if object.unobserved_links() > 0 {
        return ObjectRealization::Zero {
            reason: ZeroReason::ExternalLinks,
        };
    }
    ObjectRealization::Completed {
        guaranteed_bytes: object.key().size,
    }
}

/// One pathname's live `stat`, or the refusal that pathname earns.
fn live_identity(path: &Path) -> PlanResult<LiveIdentity> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| PlanRefusal::Vanished {
        path: path.to_path_buf(),
    })?;
    if meta.file_type().is_symlink() {
        return Err(PlanRefusal::Symlink {
            path: path.to_path_buf(),
        });
    }
    Ok(LiveIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        size: meta.size(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        ctime_sec: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
        nlink: meta.nlink(),
    })
}

/// Everything a confirmation needs, quoted from one plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

/// One allocation of the plan as the disk reports it right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectState {
    identity: LiveIdentity,
    /// Where this allocation's pathnames are — the manifest's locations at preflight time, and the
    /// quarantine locations the batch itself moves them to afterwards.
    paths: Vec<PathBuf>,
    /// `false` once a transition on this allocation could not be accounted for. The ledger then
    /// holds a reading that no longer describes the disk, and a later action checked against it
    /// would be authorized by state nobody can vouch for.
    settled: bool,
}

impl ObjectState {
    /// The eight fields, as the last reading of this allocation left them.
    #[cfg(test)]
    pub fn identity(&self) -> LiveIdentity {
        self.identity
    }

    /// Where this allocation's pathnames are now.
    #[cfg(test)]
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
}

/// What one whole-plan preflight established, in plan-object order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanLiveState {
    objects: Vec<ObjectState>,
}

impl PlanLiveState {
    #[cfg(test)]
    pub fn objects(&self) -> &[ObjectState] {
        &self.objects
    }
}

/// The live state of the plan's allocations as the batch itself has driven them.
///
/// The point of the type is the difference between a change this program made and a change somebody
/// else made. Both look identical in a `stat`: applying a hardlink raises the keeper's link count
/// and moves its `ctime`, and so does an outsider linking the same file. So every transition below
/// predicts exactly what the kernel does and adopts only the fields the kernel picks — anything else
/// that moved is external drift and refuses the next action on that allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLedger {
    objects: Vec<ObjectState>,
}

impl RuntimeLedger {
    /// Opens the ledger on the reading of the second successful whole-plan preflight — the last
    /// moment before the first mutation, and the only reading that is not already stale.
    pub fn open(state: PlanLiveState) -> Self {
        Self {
            objects: state.objects,
        }
    }

    /// The allocations as the ledger currently believes them to stand.
    #[cfg(test)]
    pub fn objects(&self) -> &[ObjectState] {
        &self.objects
    }

    /// Every pathname of this allocation is where the ledger put it, and still the same inode with
    /// the same eight fields. Called for the target's allocation and the keeper's alike before every
    /// action — a keeper nobody checked is how a batch links to a file that was replaced underneath
    /// it.
    pub fn check(&self, object: usize) -> PlanResult<()> {
        let entry = self.entry(object)?;
        // An allocation whose last transition could not be accounted for is not something a later
        // action may be authorized against: the reading here is stale by admission.
        if !entry.settled {
            return Err(PlanRefusal::UnsettledObject {
                path: entry.paths.first().cloned().unwrap_or_default(),
            });
        }
        for path in &entry.paths {
            let live = live_identity(path)?;
            if let Some(field) = drift_between(&entry.identity, &live) {
                return Err(PlanRefusal::ExternalChange {
                    path: path.clone(),
                    field,
                });
            }
        }
        Ok(())
    }

    /// A pathname of `object` was renamed into quarantine by this batch.
    ///
    /// A rename does not touch the inode's contents or its link count; it does move `ctime`. So the
    /// other seven fields are a prediction — a mismatch is somebody else's change — and `ctime` is
    /// adopted from the file at its new location.
    pub fn quarantined(&mut self, object: usize, from: &Path, to: &Path) -> PlanResult<()> {
        let entry = self.entry_mut(object)?;
        let live = live_identity(to)?;
        let expected = LiveIdentity {
            ctime_sec: live.ctime_sec,
            ctime_nsec: live.ctime_nsec,
            ..entry.identity
        };
        if let Some(field) = drift_between(&expected, &live) {
            return Err(PlanRefusal::ExternalChange {
                path: to.to_path_buf(),
                field,
            });
        }
        entry.identity = live;
        replace_path(&mut entry.paths, from, to.to_path_buf());
        Ok(())
    }

    /// This batch touched `object` and left it structurally as it was.
    ///
    /// A hardlink attempt that fails after its temporary link was made and unmade moves the
    /// keeper's `ctime` twice by our own hand; a rollback moves the original's `ctime` by moving it
    /// out and back. Nothing else about either allocation changed, and refusing the NEXT action
    /// over a `ctime` this batch caused itself is exactly the false alarm the ledger exists to
    /// avoid. Anything but `ctime` having moved is left unadopted, so the next check refuses.
    pub fn settled(&mut self, object: usize, path: &Path) -> PlanResult<()> {
        let entry = self.entry_mut(object)?;
        let live = live_identity(path)?;
        let expected = LiveIdentity {
            ctime_sec: live.ctime_sec,
            ctime_nsec: live.ctime_nsec,
            ..entry.identity
        };
        if let Some(field) = drift_between(&expected, &live) {
            return Err(PlanRefusal::ExternalChange {
                path: path.to_path_buf(),
                field,
            });
        }
        entry.identity = live;
        Ok(())
    }

    /// Stops trusting this allocation. Every later check of it refuses.
    pub fn poison(&mut self, object: usize) {
        if let Some(entry) = self.objects.get_mut(object) {
            entry.settled = false;
        }
    }

    /// A hardlink to `keeper_path` was published at `published`.
    ///
    /// The keeper's allocation gains exactly one link and a new `ctime`; nothing else about it may
    /// move. The published pathname is then `stat`ed in its own right and must BE that allocation —
    /// a risen link count on the keeper alone does not say the new pathname is the link we made,
    /// only that the count went up, which is exactly what an outsider's link looks like too.
    pub fn linked(
        &mut self,
        object: usize,
        keeper_path: &Path,
        published: &Path,
    ) -> PlanResult<()> {
        let before = self.entry(object)?.identity;
        let live = live_identity(keeper_path)?;
        let expected = LiveIdentity {
            nlink: before.nlink.saturating_add(1),
            ctime_sec: live.ctime_sec,
            ctime_nsec: live.ctime_nsec,
            ..before
        };
        if let Some(field) = drift_between(&expected, &live) {
            return Err(PlanRefusal::ExternalChange {
                path: keeper_path.to_path_buf(),
                field,
            });
        }
        // The same allocation, read from the other end.
        let landed = live_identity(published)?;
        if let Some(field) = drift_between(&live, &landed) {
            return Err(PlanRefusal::ExternalChange {
                path: published.to_path_buf(),
                field,
            });
        }
        let entry = self.entry_mut(object)?;
        entry.identity = live;
        entry.paths.push(published.to_path_buf());
        Ok(())
    }

    /// A block clone of `keeper_path` was published at the pathname `target` used to hold.
    ///
    /// Two allocations have to agree for this to be a reflink publication. The keeper's must come
    /// back bit for bit identical, link count and `ctime` included — it was only read. The
    /// published pathname must be what the publication actually produces: a FRESH allocation
    /// carrying the replaced file's own identity, because the clone is given the target's owner,
    /// mode, xattrs and timestamps before it is published (`actions::meta`). So it is checked
    /// against the target's allocation as this batch last left it — in quarantine — not against
    /// the keeper's.
    ///
    /// Device, size and both halves of `mtime` are that identity. `ctime` is not compared: a new
    /// inode's is new by construction, and it is adopted from the live read. A pathname that has
    /// the right size and link count but somebody else's modification time is not the file that
    /// was replaced, and booking it as correctly published is how a swap after the copy becomes
    /// invisible.
    pub fn cloned(
        &mut self,
        keeper_object: usize,
        target_object: usize,
        keeper_path: &Path,
        published: &Path,
    ) -> PlanResult<()> {
        let keeper = self.entry(keeper_object)?.identity;
        let original = self.entry(target_object)?.identity;
        let live = live_identity(keeper_path)?;
        if let Some(field) = drift_between(&keeper, &live) {
            return Err(PlanRefusal::ExternalChange {
                path: keeper_path.to_path_buf(),
                field,
            });
        }
        let identity = live_identity(published)?;
        let allocation = (identity.device, identity.inode);
        let wrong = [
            // Freshness first: an allocation that is the keeper's is a hardlink, and one that is
            // still the original's means nothing was published at all.
            (
                "inode",
                allocation == (keeper.device, keeper.inode)
                    || allocation == (original.device, original.inode),
            ),
            ("device", identity.device != original.device),
            ("size", identity.size != original.size),
            ("mtime", identity.mtime != original.mtime),
            ("mtime_nsec", identity.mtime_nsec != original.mtime_nsec),
            ("link count", identity.nlink != 1),
        ]
        .into_iter()
        .find(|(_, bad)| *bad)
        .map(|(field, _)| field);
        if let Some(field) = wrong {
            return Err(PlanRefusal::ExternalChange {
                path: published.to_path_buf(),
                field,
            });
        }
        self.objects.push(ObjectState {
            identity,
            paths: vec![published.to_path_buf()],
            settled: true,
        });
        Ok(())
    }

    /// Whether this allocation is still trusted. Test-only: poisoning and ordinary live drift both
    /// refuse a later action, and the tests have to be able to tell them apart.
    #[cfg(test)]
    pub fn is_settled(&self, object: usize) -> bool {
        self.objects
            .get(object)
            .map(|entry| entry.settled)
            .unwrap_or(false)
    }

    fn entry(&self, object: usize) -> PlanResult<&ObjectState> {
        self.objects
            .get(object)
            .ok_or_else(|| PlanRefusal::Arithmetic {
                detail: format!("the plan has no allocation {object}"),
            })
    }

    fn entry_mut(&mut self, object: usize) -> PlanResult<&mut ObjectState> {
        self.objects
            .get_mut(object)
            .ok_or_else(|| PlanRefusal::Arithmetic {
                detail: format!("the plan has no allocation {object}"),
            })
    }
}

/// The first of the eight fields where two live readings of one allocation disagree.
fn drift_between(expected: &LiveIdentity, live: &LiveIdentity) -> Option<&'static str> {
    let fields: [(&'static str, bool); 8] = [
        ("device", expected.device == live.device),
        ("inode", expected.inode == live.inode),
        ("size", expected.size == live.size),
        ("mtime", expected.mtime == live.mtime),
        ("mtime_nsec", expected.mtime_nsec == live.mtime_nsec),
        ("ctime", expected.ctime_sec == live.ctime_sec),
        ("ctime_nsec", expected.ctime_nsec == live.ctime_nsec),
        ("link count", expected.nlink == live.nlink),
    ];
    fields
        .into_iter()
        .find(|(_, agrees)| !agrees)
        .map(|(name, _)| name)
}

/// Moves one pathname of an allocation to its new location, keeping the rest.
fn replace_path(paths: &mut Vec<PathBuf>, from: &Path, to: PathBuf) {
    match paths.iter().position(|path| path == from) {
        Some(index) => paths[index] = to,
        None => paths.push(to),
    }
}

/// What one action did, in the terms object accounting needs — never a parsed error string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionResult {
    /// The target pathname no longer holds this allocation: it is in quarantine, and whatever was
    /// meant to replace it is published.
    Removed,
    /// Nothing was published. `rolled_back` — the original had been evacuated and was put back.
    Refused { rolled_back: bool },
    /// The original is neither where it was nor back again; it is at this exact quarantine path.
    Stranded { quarantine: PathBuf, detail: String },
    /// The filesystem did what it was asked, but the state it left could not be reconciled with
    /// what the batch itself had done. The pathname moved, and yet nothing may be claimed for the
    /// allocation: the very reading that would justify a claim is the one that disagreed.
    Unsettled { quarantine: PathBuf, detail: String },
}

/// Why an allocation is worth nothing after the batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroReason {
    /// A pathname of it was never in the plan, so it keeps every block whatever the plan did.
    NotFullyCovered,
    /// Links outside this scan keep it alive.
    ExternalLinks,
    /// Some of its pathnames went and some did not.
    PartialCoverage,
    /// The batch stopped before its last action.
    Cancelled,
    /// It was the keeper's own allocation.
    AlreadyLinked,
    /// A publication failed and the original was restored.
    RolledBack,
    /// Every action on it was refused before anything moved.
    Refused,
}

impl ZeroReason {
    pub fn describe(self) -> &'static str {
        match self {
            Self::NotFullyCovered => "a pathname of this allocation was never in the plan",
            Self::ExternalLinks => "links outside this scan keep this allocation alive",
            Self::PartialCoverage => "some pathnames of this allocation were not removed",
            Self::Cancelled => "the batch was stopped before this allocation was finished",
            Self::AlreadyLinked => "it is the keeper's own allocation",
            Self::RolledBack => "the action was undone and the original restored",
            Self::Refused => "the action was refused before anything moved",
        }
    }
}

/// What one allocation is worth after the batch, as opposed to what it was planned to be worth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectRealization {
    /// Fully covered, every action succeeded, and no link keeps it alive.
    Completed { guaranteed_bytes: u64 },
    /// Nothing is guaranteed, and this is why.
    Zero { reason: ZeroReason },
    /// The final allocation state cannot be settled from here — the original is neither in place
    /// nor restored.
    Unknown {
        reason: String,
        quarantine: Option<PathBuf>,
    },
}

impl ObjectRealization {
    /// What this allocation really releases once the quarantine is purged.
    pub fn guaranteed_bytes(&self) -> u64 {
        match self {
            Self::Completed { guaranteed_bytes } => *guaranteed_bytes,
            _ => 0,
        }
    }
}

/// The checked total over the realizations — folded, never re-derived from pathnames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RealizedSummary {
    guaranteed_bytes: u64,
    completed_objects: usize,
    zero_objects: usize,
    unknown_objects: usize,
}

impl RealizedSummary {
    /// Sums what was achieved. Overflow fails closed for the same reason the plan's own arithmetic
    /// does: a wrapped byte count is a number the filesystem will not honour.
    pub fn fold<'a>(states: impl IntoIterator<Item = &'a ObjectRealization>) -> PlanResult<Self> {
        let mut out = Self::default();
        for state in states {
            match state {
                ObjectRealization::Completed { guaranteed_bytes } => {
                    out.guaranteed_bytes = out
                        .guaranteed_bytes
                        .checked_add(*guaranteed_bytes)
                        .ok_or_else(|| PlanRefusal::Arithmetic {
                            detail: "the realized total does not fit an integer".to_string(),
                        })?;
                    out.completed_objects += 1;
                }
                ObjectRealization::Zero { .. } => out.zero_objects += 1,
                ObjectRealization::Unknown { .. } => out.unknown_objects += 1,
            }
        }
        Ok(out)
    }

    pub fn guaranteed_bytes(&self) -> u64 {
        self.guaranteed_bytes
    }

    pub fn completed_objects(&self) -> usize {
        self.completed_objects
    }

    pub fn zero_objects(&self) -> usize {
        self.zero_objects
    }

    pub fn unknown_objects(&self) -> usize {
        self.unknown_objects
    }
}

/// Folds one group's members into objects and appends them in a stable order.
///
/// `covered` is the set of pathnames this plan removes from that group; every other member is
/// evidence. The link count is agreed across an object's aliases before anything is counted, by the
/// same rule the SQL and RAM group paths use.
fn push_objects(
    objects: &mut Vec<PlannedObject>,
    group: &PlanGroupInput,
    members: &[PlanMemberEvidence],
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

    /// The fixture still spells a mark as the database does — a flag and an action — and translates
    /// it into the intent the evidence now carries. The fourth arm is the combination `MarkIntent`
    /// made unrepresentable: it can no longer be constructed, only refused while decoding a row.
    fn member(
        path: &str,
        key: PlanObjectKey,
        links: u64,
        is_keeper: bool,
        action: Option<ActionKind>,
    ) -> PlanMemberEvidence {
        let mark = match (is_keeper, action) {
            (true, None) => Some(MarkIntent::Keeper),
            (false, Some(kind)) => Some(MarkIntent::Act(kind)),
            (false, None) => None,
            (true, Some(_)) => panic!("a keeper that also acts is not a state this type can hold"),
        };
        PlanMemberEvidence::new(PathBuf::from(path), key, LinkCount::Known(links), mark)
            .expect("the fixture is well formed")
    }

    fn gid(rank: i64) -> GroupId {
        GroupId {
            scan_id: 1,
            rank,
            generation: 1,
        }
    }

    fn group(members: Vec<PlanMemberEvidence>) -> PlanGroupInput {
        PlanGroupInput {
            id: gid(0),
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
                Some(MarkIntent::Act(ActionKind::Delete)),
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
                Some(MarkIntent::Act(ActionKind::Delete)),
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
        second.id = gid(1);
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

    /// Two keeper marks are two different plans. The sort order is not allowed to pick one.
    #[test]
    fn two_keepers_in_one_group_refuse() {
        let refusal = ActionPlan::try_new(
            1,
            vec![group(vec![
                member("/x/a_keeper.bin", key(10, S), 1, true, None),
                member("/x/b_keeper.bin", key(11, S), 1, true, None),
                member(
                    "/x/c_twin.bin",
                    key(12, S),
                    1,
                    false,
                    Some(ActionKind::Delete),
                ),
            ])],
        )
        .expect_err("nothing says which file is kept");
        assert_eq!(
            refusal,
            PlanRefusal::MultipleKeepers {
                hash: "ab".repeat(32),
                first: PathBuf::from("/x/a_keeper.bin"),
                second: PathBuf::from("/x/b_keeper.bin"),
            }
        );

        // A group with no targets is refused just the same: it is still evidence the plan reads.
        assert!(matches!(
            ActionPlan::try_new(
                1,
                vec![group(vec![
                    member("/x/a_keeper.bin", key(10, S), 1, true, None),
                    member("/x/b_keeper.bin", key(11, S), 1, true, None),
                ])],
            ),
            Err(PlanRefusal::MultipleKeepers { .. })
        ));
    }

    /// One inode holds one content. The same allocation under two digests would be counted, and
    /// acted on, as two groups — the refusal comes before any total is folded.
    #[test]
    fn one_allocation_under_two_digests_refuses() {
        let shared = key(11, S);
        let mut first = group(vec![
            member("/x/a_keeper.bin", key(10, S), 1, true, None),
            member("/x/alias_0.bin", shared, 2, false, Some(ActionKind::Delete)),
        ]);
        first.hash = "aa".repeat(32);
        let mut second = group(vec![
            member("/x/b_keeper.bin", key(20, S), 1, true, None),
            member("/x/alias_1.bin", shared, 2, false, Some(ActionKind::Delete)),
        ]);
        second.hash = "bb".repeat(32);
        second.id = gid(1);

        assert_eq!(
            ActionPlan::try_new(1, vec![first, second]).expect_err("one inode, two digests"),
            PlanRefusal::ObjectInTwoGroups {
                path: PathBuf::from("/x/alias_0.bin"),
                first: "aa".repeat(32),
                second: "bb".repeat(32),
            }
        );
    }

    /// Evidence handed in twice is refused rather than folded twice.
    #[test]
    fn duplicate_evidence_refuses() {
        let twice = || {
            group(vec![
                member("/x/keeper.bin", key(10, S), 1, true, None),
                member(
                    "/x/twin.bin",
                    key(11, S),
                    1,
                    false,
                    Some(ActionKind::Delete),
                ),
            ])
        };
        assert_eq!(
            ActionPlan::try_new(1, vec![twice(), twice()]).expect_err("one digest, two inputs"),
            PlanRefusal::DuplicateGroupInput {
                hash: "ab".repeat(32)
            }
        );

        let mut second = twice();
        second.hash = "cd".repeat(32);
        second.id = gid(1);
        assert_eq!(
            ActionPlan::try_new(1, vec![twice(), second])
                .expect_err("one pathname under two digests"),
            PlanRefusal::DuplicatePathEvidence {
                path: PathBuf::from("/x/keeper.bin")
            }
        );
    }

    /// The plan is keyed by identity: a foreign scan, a mixed generation and a negative rank
    /// each refuse the whole plan, typed, before any evidence is folded.
    #[test]
    fn plan_identity_refusals_are_typed() {
        let well_formed = || {
            vec![
                member("/x/keeper.bin", key(10, S), 1, true, None),
                member(
                    "/x/twin.bin",
                    key(11, S),
                    1,
                    false,
                    Some(ActionKind::Delete),
                ),
            ]
        };
        let mut foreign = group(well_formed());
        foreign.id = GroupId {
            scan_id: 2,
            rank: 0,
            generation: 1,
        };
        assert_eq!(
            ActionPlan::try_new(1, vec![foreign]).expect_err("scan 2 in a plan for scan 1"),
            PlanRefusal::ForeignScan {
                expected: 1,
                found: 2
            }
        );

        let mut negative = group(well_formed());
        negative.id = gid(-1);
        assert_eq!(
            ActionPlan::try_new(1, vec![negative]).expect_err("rank -1 names nothing"),
            PlanRefusal::NegativeRank { rank: -1 }
        );

        let first = group(well_formed());
        let mut second = group(vec![
            member("/y/keeper.bin", key(20, S), 1, true, None),
            member(
                "/y/twin.bin",
                key(21, S),
                1,
                false,
                Some(ActionKind::Delete),
            ),
        ]);
        second.hash = "cd".repeat(32);
        second.id = GroupId {
            scan_id: 1,
            rank: 1,
            generation: 2,
        };
        assert_eq!(
            ActionPlan::try_new(1, vec![first, second]).expect_err("two publications"),
            PlanRefusal::MixedGeneration {
                expected: 1,
                found: 2
            }
        );
    }

    /// The witness is derived from the same inputs the actions were folded from: same scan,
    /// same generation, one entry per group with its digest and every member pathname in
    /// member order — so the lease revalidates exactly what was planned.
    #[test]
    fn the_plan_owns_the_witness_it_was_folded_from() {
        let mut second = group(vec![
            member(
                "/y/b_twin.bin",
                key(21, S),
                1,
                false,
                Some(ActionKind::Delete),
            ),
            member("/y/a_keeper.bin", key(20, S), 1, true, None),
        ]);
        second.hash = "cd".repeat(32);
        second.id = gid(1);
        let plan = ActionPlan::try_new(
            1,
            vec![
                second,
                group(vec![
                    member("/x/keeper.bin", key(10, S), 1, true, None),
                    member(
                        "/x/twin.bin",
                        key(11, S),
                        1,
                        false,
                        Some(ActionKind::Delete),
                    ),
                ]),
            ],
        )
        .unwrap();
        let witness = plan.witness();
        assert_eq!(witness.scan_id, 1);
        assert_eq!(witness.generation, 1);
        assert_eq!(witness.groups.len(), 2);
        assert_eq!(witness.groups[0].id, gid(0), "rank order, not input order");
        assert_eq!(witness.groups[0].digest, "ab".repeat(32));
        assert_eq!(
            witness.groups[0].members,
            vec![PathBuf::from("/x/keeper.bin"), PathBuf::from("/x/twin.bin")]
        );
        assert_eq!(witness.groups[1].id, gid(1));
        assert_eq!(witness.groups[1].digest, "cd".repeat(32));
        assert_eq!(
            witness.groups[1].members,
            vec![
                PathBuf::from("/y/a_keeper.bin"),
                PathBuf::from("/y/b_twin.bin")
            ],
            "member pathnames travel sorted"
        );
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
