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
