// SPDX-License-Identifier: Apache-2.0
pub mod host_profile;
pub mod move_track;
pub mod schema;
pub mod store;

pub use host_profile::HostProfile;
pub use store::{
    set_observer_role, AttributedDirGroupSummary, DedupRow, GroupClaim, GroupLinks, GroupSummary,
    LiveDirSignature, ManifestRow, ScanStore,
};
// R4B-1 staging: the consumer-facing half of the membership authority. Re-exported here for the
// same reason as everything above — consumers reach store types through `crate::state` — while
// the resolver internals stay in `store`. No production consumer exists until R4B-2.
#[allow(unused_imports)] // R4B-2 gives every one of these a production consumer.
pub use store::{
    CandidateView, DigestCandidate, LeaseRefusal, MembershipLease, MembershipMiss, MembershipMode,
    MembershipSnapshot, MembershipSummaries, PublishMode, ResolvedGroup,
};
