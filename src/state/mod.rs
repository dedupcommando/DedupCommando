// SPDX-License-Identifier: Apache-2.0
// R4B-2b staging: the serialized browsing actor. Public so the dormant `App` field and the
// dormant `AppEvent` carrier can name its types; nothing in production spawns it until R4B-2c,
// so the whole surface is dead to the binary today — the tests at the bottom of `browse.rs`
// are its only driver.
#[allow(dead_code)] // R4B-2c gives every piece of the actor a production caller.
pub mod browse;
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
// R4B-2a staging: the typed surface the future browsing actor reads through. Same reason again —
// consumers reach store types through `crate::state` — and again with no production consumer, so
// the actor commit changes call sites rather than paths.
#[allow(unused_imports)] // R4B-2b/2c give every one of these a production consumer.
pub use store::{
    DirGroupAnswer, FileGroupInfo, FileInfoAnswer, FileMembership, InnerDupe, MarkDecodeError,
    MarkWriteError, PanelFile, PanelFileStatus, PanelMiss, DIR_INNER_CAP, FILE_INFO_PEER_CAP,
};
