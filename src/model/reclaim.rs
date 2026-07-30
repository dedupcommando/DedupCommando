// SPDX-License-Identifier: Apache-2.0
//! How far a stored reclaim figure can be trusted, and what that means for destructive planning.
//!
//! Reclaim is a property of a physical allocation, not of a pathname, so a stored byte count only
//! means something together with what was known when it was written. That trust marker is
//! persisted as a small integer in `file_group.reclaim_state` and `scan_stats.reclaim_state`; this
//! module is the only place that maps those integers onto meaning, so no caller has to remember
//! that 2 means «up to».
//!
//! Nothing here computes reclaim: `R2C` owns the arithmetic that will write these states, `R2D`
//! the action and UI glue that will read the verdict.

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
    /// The persisted representation. Written by `R2C`, which is what computes a state other than
    /// `Unknown`; until then the column default carries the same meaning.
    #[allow(dead_code)]
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
