// SPDX-License-Identifier: Apache-2.0
// The serialized browsing actor: since R4B-2c it is the ONLY production owner of a browsing
// connection — every completed-scan read and every mark travels through its typed protocol.
pub mod browse;
pub mod host_profile;
pub mod move_track;
pub mod schema;
pub mod store;

pub use host_profile::HostProfile;
pub use store::{
    set_observer_role, AttributedDirGroupSummary, GroupClaim, GroupLinks, GroupSummary,
    LiveDirSignature, ManifestRow, ScanStore,
};
// The consumer-facing half of the membership authority — consumers reach store types through
// `crate::state`, while the resolver internals stay in `store`.
pub use store::{
    CandidateView, MembershipMiss, MembershipMode, MembershipSummaries, PublishMode, ResolvedGroup,
};
// The typed surface the browsing actor reads through.
pub use store::{
    DirGroupAnswer, FileInfoAnswer, FileMembership, MarkWriteError, PanelFile, PanelFileStatus,
};
