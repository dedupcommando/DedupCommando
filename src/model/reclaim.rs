// SPDX-License-Identifier: Apache-2.0
//! How far a stored reclaim figure can be trusted, and what that means for destructive planning.
//!
//! Reclaim is a property of a physical allocation, not of a pathname, so a stored byte count only
//! means something together with what was known when it was written. That trust marker is
//! persisted as a small integer in `file_group.reclaim_state` and `scan_stats.reclaim_state`; this
//! module is the only place that maps those integers onto meaning, so no caller has to remember
//! that 2 means «up to».
//!
//! The arithmetic lives here too, so exactly one place turns physical objects into bytes; `R2D`
//! owns the action glue that will read the verdict.

use crate::error::{AppError, Result};

/// Trust in a persisted reclaim figure.
///
/// `Unknown` is the default for everything written before schema v3: those figures came from the
/// pathname formula `size × (paths − 1)` and cannot be re-derived without a rescan, because the
/// link counts they would need were never recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReclaimState {
    /// Not established — a legacy result, or a scan that has not computed it yet.
    #[default]
    Unknown,
    /// Every link of every affected allocation was observed; the figure is the real one.
    Exact,
    /// Some links live outside the scan; the figure is a ceiling, never a promise.
    UpperBound,
}

impl ReclaimState {
    /// The persisted representation.
    pub const fn as_i64(self) -> i64 {
        match self {
            Self::Unknown => 0,
            Self::Exact => 1,
            Self::UpperBound => 2,
        }
    }

    /// Reads a persisted value. An integer this build does not know is an error, not a silent
    /// `Unknown`: it means the row was written by something else, and guessing would be the first
    /// step towards a wrong byte count.
    pub fn from_i64(raw: i64) -> Result<Self> {
        match raw {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Exact),
            2 => Ok(Self::UpperBound),
            other => Err(AppError::msg(format!(
                "dedcom.db holds an unknown reclaim state ({other}). Rescan, or move the old dedcom.db aside."
            ))),
        }
    }

    /// Whether a byte figure carrying this state may be presented as established.
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::Exact | Self::UpperBound)
    }
}

/// A link count as persisted in `file.nlink`.
///
/// The column is SQLite's signed `INTEGER` and carries no domain constraint, so a damaged or
/// externally modified DB can hold a value `st_nlink` could never produce. This type is the one
/// gate between that column and the rest of the program: the accepted domain is exactly `0` for a
/// row whose count was never recorded and `>= 1` for a real count. Anything negative is corruption
/// and is refused — never reinterpreted as a large positive number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCount {
    /// Never recorded — a legacy pre-v3 row.
    Unknown,
    /// The real `st_nlink` the walk observed; always `>= 1`.
    Known(u64),
}

impl LinkCount {
    /// Decodes a value read from `file.nlink`.
    pub fn from_i64(raw: i64) -> Result<Self> {
        match raw {
            0 => Ok(Self::Unknown),
            count if count > 0 => Ok(Self::Known(count as u64)),
            negative => Err(AppError::msg(format!(
                "dedcom.db holds a corrupt link count ({negative}); a link count is never negative. Rescan, or move the old dedcom.db aside."
            ))),
        }
    }

    /// Reads the manifest convention, where `0` stands for a count that was never recorded.
    pub const fn from_u64(value: u64) -> Self {
        match value {
            0 => Self::Unknown,
            count => Self::Known(count),
        }
    }

    /// Encodes for storage. A count too large for the signed column is refused here rather than
    /// wrapped into the negative a reader would then have to call corrupt.
    pub fn to_i64(self) -> Result<i64> {
        match self {
            Self::Unknown => Ok(0),
            Self::Known(count) => i64::try_from(count).map_err(|_| {
                AppError::msg(format!(
                    "link count {count} does not fit dedcom.db's integer column"
                ))
            }),
        }
    }

    /// The manifest convention again: the real count, or `0` when it was never recorded.
    pub const fn to_u64(self) -> u64 {
        match self {
            Self::Unknown => 0,
            Self::Known(count) => count,
        }
    }

    /// Whether this row's allocation has a link count anyone can reason about.
    pub const fn is_known(self) -> bool {
        matches!(self, Self::Known(_))
    }
}

/// Whether a scan's results may be turned into a destructive plan.
///
/// A pre-v3 scan stays fully browseable, but its link counts were never recorded, so nothing can
/// tell an alias from an independent copy in it. Acting on that would remove the last link of an
/// allocation while claiming to free bytes another link still holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructivePlanVerdict {
    /// Link counts and trust state are both established; planning may proceed.
    Allowed,
    /// Fail closed — the operator has to rescan before anything is deleted or linked.
    RescanRequired,
}

impl DestructivePlanVerdict {
    /// Fail-closed by construction: planning needs both an established trust state and a manifest
    /// where every row's link count is known. Either one missing refuses.
    pub const fn of(state: ReclaimState, link_counts_known: bool) -> Self {
        if link_counts_known && state.is_trusted() {
            Self::Allowed
        } else {
            Self::RescanRequired
        }
    }
}

/// What one physical object contributes to a group: how many of its pathnames this scan saw,
/// and how many links its inode actually has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectLinks {
    /// Pathnames of this object inside the group. Never a link count.
    pub observed: u64,
    /// The object's own `st_nlink`, validated as one value for the whole object.
    pub links: LinkCount,
}

/// A reclaim figure together with the trust that makes it mean something.
///
/// Two numbers, never one: `guaranteed` is what removing the extra copies really frees, `ceiling`
/// is the most that could ever be freed. They coincide only when every link of every allocation
/// was observed. Keeping them apart is the whole point — a single unnamed `reclaim` number is what
/// let an upper bound be printed next to the word «free».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReclaimEstimate {
    state: ReclaimState,
    guaranteed_bytes: u64,
    /// The physical-object ceiling. Never read while `state` is `Unknown`.
    ceiling_bytes: u64,
}

impl ReclaimEstimate {
    /// Nothing established — a legacy row, or a manifest whose link counts were never recorded.
    pub const fn unknown() -> Self {
        Self {
            state: ReclaimState::Unknown,
            guaranteed_bytes: 0,
            ceiling_bytes: 0,
        }
    }

    /// Every link of every allocation was observed: the ceiling is the real figure.
    pub const fn exact(bytes: u64) -> Self {
        Self {
            state: ReclaimState::Exact,
            guaranteed_bytes: bytes,
            ceiling_bytes: bytes,
        }
    }

    /// Some links live outside the scan. Nothing is guaranteed; the ceiling is a ceiling.
    pub const fn upper_bound(ceiling: u64) -> Self {
        Self {
            state: ReclaimState::UpperBound,
            guaranteed_bytes: 0,
            ceiling_bytes: ceiling,
        }
    }

    pub const fn state(self) -> ReclaimState {
        self.state
    }

    /// What removing the extra copies really frees. Zero for an upper-bound or unknown figure.
    pub const fn guaranteed_bytes(self) -> u64 {
        self.guaranteed_bytes
    }

    /// The trusted ceiling, or `None` when nothing about this figure is established.
    pub const fn potential_bytes(self) -> Option<u64> {
        match self.state {
            ReclaimState::Unknown => None,
            _ => Some(self.ceiling_bytes),
        }
    }

    /// The figure the `reclaim` / `reclaimable_bytes` column carries: the ceiling when trusted,
    /// and a hard zero otherwise, so an unestablished result can never persist a positive number
    /// a later reader might headline.
    pub const fn persisted_bytes(self) -> u64 {
        match self.state {
            ReclaimState::Unknown => 0,
            _ => self.ceiling_bytes,
        }
    }

    /// The deterministic order of results: guaranteed bytes first, the ceiling as the tiebreak,
    /// and (at the call site) the hash last. Untrusted figures rank as zero rather than jumping
    /// the queue on a number nobody stands behind.
    pub const fn order_key(self) -> (u64, u64) {
        (self.guaranteed_bytes, self.persisted_bytes())
    }

    /// The physical-object ceiling `size × (objects − 1)`, in checked integer arithmetic.
    ///
    /// A product that leaves the persisted integer domain fails closed here. Neither wrapping nor
    /// saturating is acceptable: both would hand the operator a byte count that is not the one the
    /// filesystem would free, and SQLite's own answer to an overflowing `*` is to switch to `REAL`,
    /// which is how a byte count silently becomes an approximation.
    pub fn object_ceiling(size: u64, object_count: u64) -> Result<u64> {
        let overflow = || {
            AppError::msg(format!(
                "reclaim of {object_count} allocations of {size} bytes does not fit dedcom.db's integer column"
            ))
        };
        let extra = object_count.checked_sub(1).ok_or_else(|| {
            AppError::msg("a duplicate-content group with no physical allocations".to_string())
        })?;
        let ceiling = size.checked_mul(extra).ok_or_else(overflow)?;
        i64::try_from(ceiling).map_err(|_| overflow())?;
        Ok(ceiling)
    }

    /// The estimate for one group, from one validated link count per distinct physical object.
    ///
    /// The rules are the checkpoint's, in order: an object claiming more pathnames than its inode
    /// has links is an impossible manifest and fails closed; one unknown count makes the whole
    /// group unknown; one partially observed object makes it an upper bound; only when every
    /// object is fully observed is the figure exact. `named` is a sanitized pathname of the group,
    /// used to point the operator at the row.
    pub fn for_objects(size: u64, objects: &[ObjectLinks], named: &str) -> Result<Self> {
        let ceiling = Self::object_ceiling(size, objects.len() as u64)?;
        let mut unknown = false;
        let mut partial = false;
        for object in objects {
            match object.links {
                LinkCount::Unknown => unknown = true,
                LinkCount::Known(links) => {
                    if object.observed > links {
                        return Err(AppError::msg(format!(
                            "{named} is one of {} pathnames of an allocation whose inode reports only {links} links; that manifest cannot be right. Rescan, or move the old dedcom.db aside.",
                            object.observed
                        )));
                    }
                    if object.observed < links {
                        partial = true;
                    }
                }
            }
        }
        Ok(if unknown {
            Self::unknown()
        } else if partial {
            Self::upper_bound(ceiling)
        } else {
            Self::exact(ceiling)
        })
    }

    /// The scan-level figure of a freshly computed result.
    ///
    /// The guaranteed total comes from the exact groups alone; the ceiling sums every trusted
    /// ceiling. One unknown group makes the whole total unknown — an operator cannot act on a sum
    /// that silently omits a group nobody could measure. An empty result is exact zero.
    pub fn for_fresh_scan(groups: impl IntoIterator<Item = Self>) -> Result<Self> {
        let overflow =
            || AppError::msg("the scan's reclaim total does not fit dedcom.db's integer column");
        let mut state = ReclaimState::Exact;
        let (mut guaranteed, mut ceiling) = (0u64, 0u64);
        for group in groups {
            match group.state {
                ReclaimState::Unknown => return Ok(Self::unknown()),
                ReclaimState::UpperBound => state = ReclaimState::UpperBound,
                ReclaimState::Exact => {}
            }
            guaranteed = guaranteed
                .checked_add(group.guaranteed_bytes)
                .ok_or_else(overflow)?;
            ceiling = ceiling
                .checked_add(group.persisted_bytes())
                .ok_or_else(overflow)?;
        }
        i64::try_from(ceiling).map_err(|_| overflow())?;
        Ok(Self {
            state,
            guaranteed_bytes: guaranteed,
            ceiling_bytes: ceiling,
        })
    }

    /// Decodes a persisted group row. An unknown row's stored bytes are deliberately dropped
    /// rather than carried: for a migrated v2 summary that number is the old pathname formula,
    /// and the row stays in the database as browseable history exactly because nothing may read
    /// it as a byte promise.
    pub fn from_persisted(reclaim: i64, state: i64) -> Result<Self> {
        let state = ReclaimState::from_i64(state)?;
        if state == ReclaimState::Unknown {
            return Ok(Self::unknown());
        }
        let ceiling = u64::try_from(reclaim).map_err(|_| {
            AppError::msg(format!(
                "dedcom.db holds a negative reclaim figure ({reclaim}). Rescan, or move the old dedcom.db aside."
            ))
        })?;
        Ok(Self {
            state,
            guaranteed_bytes: match state {
                ReclaimState::Exact => ceiling,
                _ => 0,
            },
            ceiling_bytes: ceiling,
        })
    }

    /// Decodes a persisted scan total. Unlike a group, a trusted scan may carry both a positive
    /// guaranteed sum (from its exact groups) and a larger ceiling, which is exactly the mixed
    /// result the operator has to be able to tell apart.
    pub fn from_persisted_scan(guaranteed: i64, ceiling: i64, state: i64) -> Result<Self> {
        let whole = Self::from_persisted(ceiling, state)?;
        if whole.state != ReclaimState::UpperBound {
            return Ok(whole);
        }
        let guaranteed = u64::try_from(guaranteed).map_err(|_| {
            AppError::msg(format!(
                "dedcom.db holds a negative guaranteed total ({guaranteed}). Rescan, or move the old dedcom.db aside."
            ))
        })?;
        Ok(Self {
            guaranteed_bytes: guaranteed,
            ..whole
        })
    }
}

/// Everything a duplicate-content group says about the allocations behind it.
///
/// The three counts are separate on purpose: pathnames are what the operator sees, allocations are
/// what the filesystem frees, and the link total is what says whether the two agree. Summing
/// `nlink` once per pathname — the shape this type exists to make impossible — multiplies an
/// allocation's link count by its own alias count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupReclaim {
    /// Pathnames observed in this group.
    pub observed_paths: u64,
    /// Distinct scan-local temporal physical objects behind them.
    pub object_count: u64,
    /// One validated link count per distinct object, summed. `Unknown` if any object's is.
    pub total_links: LinkCount,
    /// State, guaranteed bytes and the trusted ceiling.
    pub estimate: ReclaimEstimate,
}

impl GroupReclaim {
    /// Builds the group's figures from one validated link count per distinct physical object.
    pub fn of_objects(size: u64, objects: &[ObjectLinks], named: &str) -> Result<Self> {
        let estimate = ReclaimEstimate::for_objects(size, objects, named)?;
        let observed_paths = objects.iter().map(|object| object.observed).sum();
        let total_links = objects
            .iter()
            .try_fold(0u64, |sum, object| match object.links {
                LinkCount::Unknown => None,
                LinkCount::Known(links) => sum.checked_add(links),
            })
            .map_or(LinkCount::Unknown, LinkCount::Known);
        Ok(Self {
            observed_paths,
            object_count: objects.len() as u64,
            total_links,
            estimate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_round_trips_through_its_persisted_integer() {
        for state in [
            ReclaimState::Unknown,
            ReclaimState::Exact,
            ReclaimState::UpperBound,
        ] {
            assert_eq!(ReclaimState::from_i64(state.as_i64()).unwrap(), state);
        }
        assert_eq!(ReclaimState::default(), ReclaimState::Unknown);
        assert_eq!(
            ReclaimState::Unknown.as_i64(),
            0,
            "0 is the column DEFAULT, so a legacy row decodes as unknown"
        );
    }

    #[test]
    fn an_unrecognised_persisted_state_is_an_error_not_a_guess() {
        for raw in [-1, 3, 99] {
            let err = ReclaimState::from_i64(raw).expect_err("this must not decode");
            assert!(
                err.to_string().contains("unknown reclaim state"),
                "the message must name the cause: {err}"
            );
        }
    }

    #[test]
    fn only_an_established_state_is_trusted() {
        assert!(!ReclaimState::Unknown.is_trusted());
        assert!(ReclaimState::Exact.is_trusted());
        assert!(ReclaimState::UpperBound.is_trusted());
    }

    #[test]
    fn a_link_count_round_trips_across_the_accepted_domain() {
        assert_eq!(LinkCount::from_i64(0).unwrap(), LinkCount::Unknown);
        assert_eq!(LinkCount::from_i64(1).unwrap(), LinkCount::Known(1));
        assert_eq!(
            LinkCount::from_i64(i64::MAX).unwrap(),
            LinkCount::Known(i64::MAX as u64)
        );
        for count in [LinkCount::Unknown, LinkCount::Known(1), LinkCount::Known(9)] {
            assert_eq!(LinkCount::from_i64(count.to_i64().unwrap()).unwrap(), count);
            assert_eq!(LinkCount::from_u64(count.to_u64()), count);
        }
        assert!(!LinkCount::Unknown.is_known());
        assert!(LinkCount::Known(1).is_known());
    }

    /// The defect this type exists for: an unchecked cast would turn `-1` into `u64::MAX` and hand
    /// the program a link count no filesystem could report.
    #[test]
    fn a_negative_link_count_is_corruption_not_a_large_count() {
        for raw in [-1, -42, i64::MIN] {
            let err = LinkCount::from_i64(raw).expect_err("a negative count must not decode");
            assert!(
                err.to_string().contains("corrupt link count"),
                "the message must name the cause: {err}"
            );
        }
    }

    /// The write side: a count the signed column cannot hold is refused rather than wrapped.
    #[test]
    fn a_link_count_too_large_for_the_column_is_refused() {
        assert!(LinkCount::Known(u64::MAX).to_i64().is_err());
        assert_eq!(
            LinkCount::Known(i64::MAX as u64).to_i64().unwrap(),
            i64::MAX,
            "the largest storable count still encodes"
        );
    }

    fn seen(observed: u64, links: u64) -> ObjectLinks {
        ObjectLinks {
            observed,
            links: LinkCount::from_u64(links),
        }
    }

    /// The whole point of the type: reclaim counts allocations, and the count of pathnames the
    /// operator sees has no place in the arithmetic.
    #[test]
    fn a_group_is_worth_one_allocation_however_many_pathnames_it_shows() {
        // Two aliases of one fully observed object plus one independent identical object:
        // three pathnames, two allocations, exactly one allocation's worth of bytes.
        let mixed = ReclaimEstimate::for_objects(4096, &[seen(2, 2), seen(1, 1)], "/x/a").unwrap();
        assert_eq!(mixed.state(), ReclaimState::Exact);
        assert_eq!(mixed.guaranteed_bytes(), 4096);
        assert_eq!(mixed.potential_bytes(), Some(4096));
        assert_eq!(mixed.persisted_bytes(), 4096);
    }

    /// One link outside the scan poisons the whole group's promise: the ceiling survives, the
    /// guarantee does not.
    #[test]
    fn an_object_with_an_unobserved_link_guarantees_nothing() {
        let bounded =
            ReclaimEstimate::for_objects(4096, &[seen(1, 2), seen(1, 1)], "/x/seen").unwrap();
        assert_eq!(bounded.state(), ReclaimState::UpperBound);
        assert_eq!(bounded.guaranteed_bytes(), 0);
        assert_eq!(bounded.potential_bytes(), Some(4096));
        assert_eq!(
            bounded.persisted_bytes(),
            4096,
            "the ceiling is what the column carries; the state is what makes it readable"
        );
    }

    /// A count that was never recorded cannot be argued with: no ceiling, no guarantee.
    #[test]
    fn an_unrecorded_link_count_makes_the_whole_group_unknown() {
        let unknown =
            ReclaimEstimate::for_objects(4096, &[seen(1, 0), seen(1, 1)], "/x/legacy").unwrap();
        assert_eq!(unknown.state(), ReclaimState::Unknown);
        assert_eq!(unknown.guaranteed_bytes(), 0);
        assert_eq!(unknown.potential_bytes(), None);
        assert_eq!(unknown.persisted_bytes(), 0);
    }

    /// More pathnames than the inode has links is not a big number, it is a broken manifest.
    #[test]
    fn more_pathnames_than_links_is_an_error_not_a_bound() {
        let err = ReclaimEstimate::for_objects(4096, &[seen(3, 2), seen(1, 1)], "/x/a")
            .expect_err("an impossible manifest must not produce a figure");
        assert!(
            err.to_string().contains("cannot be right"),
            "the message must name the cause: {err}"
        );
    }

    /// The ceiling is checked arithmetic: a product outside the persisted domain fails closed
    /// rather than wrapping, saturating, or turning into an approximation.
    #[test]
    fn a_ceiling_outside_the_integer_domain_fails_closed() {
        assert_eq!(ReclaimEstimate::object_ceiling(4096, 3).unwrap(), 8192);
        for (size, objects) in [(u64::MAX, 3u64), (i64::MAX as u64, 3), (u64::MAX / 2, 4)] {
            assert!(
                ReclaimEstimate::object_ceiling(size, objects).is_err(),
                "size {size} over {objects} allocations must not produce a number"
            );
        }
        assert!(
            ReclaimEstimate::object_ceiling(4096, 0).is_err(),
            "a group with no allocations is not a group"
        );
    }

    /// A mixed scan headlines what its exact groups guarantee and keeps the larger ceiling apart.
    #[test]
    fn a_mixed_scan_total_separates_the_guarantee_from_the_ceiling() {
        let total = ReclaimEstimate::for_fresh_scan([
            ReclaimEstimate::exact(100),
            ReclaimEstimate::upper_bound(70),
        ])
        .unwrap();
        assert_eq!(total.state(), ReclaimState::UpperBound);
        assert_eq!(total.guaranteed_bytes(), 100);
        assert_eq!(total.potential_bytes(), Some(170));

        let all_exact =
            ReclaimEstimate::for_fresh_scan([ReclaimEstimate::exact(5), ReclaimEstimate::exact(7)])
                .unwrap();
        assert_eq!(all_exact.state(), ReclaimState::Exact);
        assert_eq!(all_exact.guaranteed_bytes(), 12);

        let empty = ReclaimEstimate::for_fresh_scan([]).unwrap();
        assert_eq!(empty.state(), ReclaimState::Exact);
        assert_eq!(empty.guaranteed_bytes(), 0);
        assert_eq!(empty.potential_bytes(), Some(0));
    }

    /// One group nobody could measure makes the whole total unmeasured — a sum that quietly
    /// omitted it would read as complete.
    #[test]
    fn one_unknown_group_makes_the_scan_total_unknown() {
        let total = ReclaimEstimate::for_fresh_scan([
            ReclaimEstimate::exact(100),
            ReclaimEstimate::unknown(),
        ])
        .unwrap();
        assert_eq!(total.state(), ReclaimState::Unknown);
        assert_eq!(total.guaranteed_bytes(), 0);
        assert_eq!(total.potential_bytes(), None);
    }

    /// A migrated v2 row keeps its stored number in the database and gets none of it back.
    #[test]
    fn a_legacy_rows_stored_bytes_are_never_handed_back_as_a_figure() {
        let legacy = ReclaimEstimate::from_persisted(999_999, ReclaimState::Unknown.as_i64())
            .expect("a legacy row still decodes");
        assert_eq!(legacy, ReclaimEstimate::unknown());
        assert_eq!(legacy.potential_bytes(), None);

        for estimate in [
            ReclaimEstimate::exact(4096),
            ReclaimEstimate::upper_bound(4096),
        ] {
            let round_tripped = ReclaimEstimate::from_persisted(
                estimate.persisted_bytes() as i64,
                estimate.state().as_i64(),
            )
            .unwrap();
            assert_eq!(round_tripped, estimate, "a fresh row survives the column");
        }
        assert!(
            ReclaimEstimate::from_persisted(-1, ReclaimState::Exact.as_i64()).is_err(),
            "a negative byte count is corruption"
        );
    }

    /// The scan decoder is the only one that may carry a guarantee alongside a bigger ceiling.
    #[test]
    fn a_persisted_scan_total_keeps_its_guaranteed_sum() {
        let mixed =
            ReclaimEstimate::from_persisted_scan(100, 170, ReclaimState::UpperBound.as_i64())
                .unwrap();
        assert_eq!(mixed.guaranteed_bytes(), 100);
        assert_eq!(mixed.potential_bytes(), Some(170));
        let exact =
            ReclaimEstimate::from_persisted_scan(0, 170, ReclaimState::Exact.as_i64()).unwrap();
        assert_eq!(
            exact.guaranteed_bytes(),
            170,
            "an exact total guarantees its whole ceiling, whatever the stored guaranteed column says"
        );
        let unknown =
            ReclaimEstimate::from_persisted_scan(0, 170, ReclaimState::Unknown.as_i64()).unwrap();
        assert_eq!(unknown.potential_bytes(), None);
    }

    /// Ordering is a total function of the two byte figures, so both paths can implement it.
    #[test]
    fn results_order_by_guarantee_then_ceiling() {
        let mut estimates = [
            ReclaimEstimate::upper_bound(900),
            ReclaimEstimate::exact(100),
            ReclaimEstimate::unknown(),
            ReclaimEstimate::upper_bound(400),
        ];
        estimates.sort_by_key(|estimate| {
            let (guaranteed, ceiling) = estimate.order_key();
            (std::cmp::Reverse(guaranteed), std::cmp::Reverse(ceiling))
        });
        assert_eq!(
            estimates.map(|estimate| estimate.order_key()),
            [(100, 100), (0, 900), (0, 400), (0, 0)],
            "the guarantee leads, the ceiling breaks the tie, the unmeasured sink"
        );
    }

    /// Link counts are summed once per allocation. Once per pathname is the defect.
    #[test]
    fn link_totals_are_summed_once_per_allocation() {
        let group = GroupReclaim::of_objects(4096, &[seen(2, 2), seen(1, 1)], "/x/a").unwrap();
        assert_eq!(group.observed_paths, 3);
        assert_eq!(group.object_count, 2);
        assert_eq!(
            group.total_links,
            LinkCount::Known(3),
            "2 + 1, not 2 + 2 + 1: the alias set contributes its count once"
        );
        assert_eq!(group.estimate.guaranteed_bytes(), 4096);

        let legacy = GroupReclaim::of_objects(4096, &[seen(1, 0), seen(1, 1)], "/x/a").unwrap();
        assert_eq!(
            legacy.total_links,
            LinkCount::Unknown,
            "one unrecorded count makes the total unknown, not smaller"
        );
    }

    /// Both inputs must hold: an unknown state, or a manifest with unrecorded link counts, refuses
    /// on its own.
    #[test]
    fn planning_is_refused_unless_state_and_link_counts_are_both_known() {
        assert_eq!(
            DestructivePlanVerdict::of(ReclaimState::Exact, true),
            DestructivePlanVerdict::Allowed
        );
        assert_eq!(
            DestructivePlanVerdict::of(ReclaimState::UpperBound, true),
            DestructivePlanVerdict::Allowed
        );
        assert_eq!(
            DestructivePlanVerdict::of(ReclaimState::Unknown, true),
            DestructivePlanVerdict::RescanRequired
        );
        assert_eq!(
            DestructivePlanVerdict::of(ReclaimState::Exact, false),
            DestructivePlanVerdict::RescanRequired
        );
    }
}
