// SPDX-License-Identifier: Apache-2.0
//! What a scan left out, and how much of that the checkpoint is entitled to claim.
//!
//! A directory can only be called an exact twin of another if the scan saw all of it. Six
//! branches of the walk drop a file that exists on disk, and today five of them leave no trace at
//! all, so two directories differing only by such a file look identical. This module owns the
//! types the checkpoint stores to answer «what was left out here», and the tri-state verdict a
//! reader gets back — including the honest «nobody recorded that» for a scan produced before the
//! ledger existed.
//!
//! Nothing here decides what to DO with a verdict. Suppressing a signature, wording a warning and
//! refusing a destructive plan belong to the later integration; this module stays policy-neutral
//! so those decisions are made in one place rather than three.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use crate::error::{AppError, Result};

/// The one storage representation of a scan root and of an affected directory.
///
/// Roots are persisted exactly as the operator typed them (`pipeline::roots::describe` keeps the
/// given spelling, and nothing rewrites it), while directory pathnames come out of the walk
/// already joined component by component. Comparing the two as raw strings therefore fails on an
/// ordinary root with a trailing slash. This type is the single normalization both sides pass
/// through, so an insert, a range query and the SQL constraint all speak one representation.
///
/// Purely lexical — it never touches the filesystem, so a root that does not exist yet still has a
/// key. `Path::components` already collapses repeated separators, drops `.` and drops a trailing
/// separator; this type refuses everything it would keep.
///
/// `..` is refused rather than resolved. Popping a component lexically disagrees with the
/// filesystem as soon as a symlink is involved, and root validation compares canonicalized paths:
/// a lexical `/tank/../other` would be canonically disjoint from `/tank` while sharing its lexical
/// prefix, which is exactly how a directory would end up attributed to a root it is not under.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathKey(String);

impl PathKey {
    /// The sole constructor. `None` for anything this contract will not store: a relative path, a
    /// `..` component, a Windows-style prefix, or a component that is not valid UTF-8.
    pub fn new(path: &Path) -> Option<Self> {
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return None;
        }
        let mut key = String::new();
        for component in components {
            match component {
                Component::Normal(name) => {
                    key.push('/');
                    key.push_str(name.to_str()?);
                }
                _ => return None,
            }
        }
        if key.is_empty() {
            key.push('/');
        }
        Some(Self(key))
    }

    /// Decodes a key read back out of the checkpoint. A stored value that is not already in
    /// normalized form is corruption — refused, never silently re-normalized, because a row whose
    /// key differs from what a query would build is a row no query can find.
    pub fn from_stored(raw: &str) -> Result<Self> {
        match Self::new(Path::new(raw)) {
            Some(key) if key.0 == raw => Ok(key),
            _ => Err(AppError::msg(format!(
                "dedcom.db holds a malformed path key ({}); rescan, or move the old dedcom.db aside.",
                crate::textsan::terminal(raw)
            ))),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this key is `other` or lies below it. Component containment: `/tank/ab` is not
    /// under `/tank/a`, because the comparison is against `other` plus a separator.
    pub fn is_at_or_under(&self, other: &Self) -> bool {
        self == other || other.0 == "/" || self.0.starts_with(&format!("{}/", other.0))
    }

    /// Half-open `[lo, hi)` range covering this key's strict descendants.
    ///
    /// Deliberately not `store::prefix_bounds`: that helper serves the `file` manifest, whose keys
    /// are raw walk strings passed through `to_string_lossy`. The lower bound carries the
    /// separator because `-` (0x2D) sorts below `0` (0x30), so a sibling `…/a-old` would otherwise
    /// fall inside the range asked about `…/a`.
    pub fn subtree_bounds(&self) -> (String, String) {
        if self.0 == "/" {
            (String::from("/"), String::from("0"))
        } else {
            (format!("{}/", self.0), format!("{}0", self.0))
        }
    }
}

/// What one recorded event of a reason stands for.
///
/// Three kinds, not two: «is it a file?» and «is the count known?» are different questions, and an
/// unsupported directory entry answers them differently. Folding it in with a walk error would
/// forbid presenting an exact figure for a count that is exact; folding it in with the file
/// reasons would call a socket an omitted file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventKind {
    /// Exactly one omitted regular file.
    OmittedFile,
    /// Exactly one directory entry the scan has no way to represent: a symlink it does not
    /// follow, a FIFO, a socket, or a block or character device. Known, finite, and not a file.
    UnsupportedEntry,
    /// One error whose hidden file count nobody can state.
    UnknownCardinality,
}

/// Why a directory entry that exists on disk never became a manifest row.
///
/// One per branch of the walk that drops something. There is deliberately no variant for an
/// intentional exclusion (`.zfs`, the quarantine directory, an operator exclusion glob): those are
/// applied before an entry is ever yielded, so they cannot reach any of these branches, and giving
/// them a variant would let a deliberate narrowing masquerade as user-data incompleteness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OmissionReason {
    /// Smaller than the configured minimum size.
    MinSize,
    /// Larger than the configured maximum size.
    MaxSize,
    /// Extension outside the configured allow-list.
    ExtensionFiltered,
    /// The pathname cannot be represented as UTF-8, so the walk refuses to touch the file.
    NonUtf8,
    /// The walk iterator produced an error instead of an entry.
    WalkError,
    /// The entry arrived and was already typed as a regular file, but its metadata failed.
    MetadataError,
    /// The entry arrived and is neither a regular file nor a directory: a symlink the scan does
    /// not follow, a FIFO, a socket, or a block or character device. Nothing failed and nothing
    /// was filtered by configuration — the scan simply has no way to represent it, and a directory
    /// holding one is not an exact twin of a directory that does not.
    UnsupportedEntry,
}

impl OmissionReason {
    /// Every reason, in the order they are stored and reported.
    pub const ALL: [Self; 7] = [
        Self::MinSize,
        Self::MaxSize,
        Self::ExtensionFiltered,
        Self::NonUtf8,
        Self::WalkError,
        Self::MetadataError,
        Self::UnsupportedEntry,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MinSize => "min_size",
            Self::MaxSize => "max_size",
            Self::ExtensionFiltered => "extension_filtered",
            Self::NonUtf8 => "non_utf8",
            Self::WalkError => "walk_error",
            Self::MetadataError => "metadata_error",
            Self::UnsupportedEntry => "unsupported_entry",
        }
    }

    /// `None` for anything this build does not know. There is no fallback variant, so an
    /// unrecognized value can never be quietly folded into a known one.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// What one event of this reason stands for.
    ///
    /// [`Self::WalkError`] is the only unknown-cardinality reason: that branch is reached before
    /// the entry's type is known, so a single error may stand for one file, one directory, or an
    /// entire unreadable subtree whose contents nobody can count. An unsupported entry, by
    /// contrast, is exactly one entry — it is simply not a file.
    pub const fn event_kind(self) -> EventKind {
        match self {
            Self::MinSize
            | Self::MaxSize
            | Self::ExtensionFiltered
            | Self::NonUtf8
            | Self::MetadataError => EventKind::OmittedFile,
            Self::UnsupportedEntry => EventKind::UnsupportedEntry,
            Self::WalkError => EventKind::UnknownCardinality,
        }
    }

    /// Whether one recorded event of this reason stands for exactly one omitted file. Derived from
    /// [`Self::event_kind`], so the two can never disagree.
    pub const fn one_event_is_one_file(self) -> bool {
        matches!(self.event_kind(), EventKind::OmittedFile)
    }

    /// Whether this reason is an operator-chosen narrowing of the scan rather than a failure to
    /// read user data. Both kinds make a directory incomplete; only the second is a warning about
    /// the scan itself.
    pub const fn is_intentional_filter(self) -> bool {
        matches!(
            self,
            Self::MinSize | Self::MaxSize | Self::ExtensionFiltered
        )
    }
}

/// Test-only bridge to the directory-completeness fixture's own enum.
///
/// Exhaustive on purpose: adding or renaming a variant on either side becomes a compile error
/// rather than a test that quietly stops covering a case. The fixture is accepted work owned by a
/// later commit, so the single definition is asserted here instead of edited there.
#[cfg(test)]
impl From<crate::testfixtures::dir_completeness::OmissionReason> for OmissionReason {
    fn from(fixture: crate::testfixtures::dir_completeness::OmissionReason) -> Self {
        use crate::testfixtures::dir_completeness::OmissionReason as Fixture;
        match fixture {
            Fixture::BelowMin => Self::MinSize,
            Fixture::AboveMax => Self::MaxSize,
            Fixture::ExtensionFiltered => Self::ExtensionFiltered,
            Fixture::NonUtf8 => Self::NonUtf8,
            Fixture::WalkError => Self::WalkError,
            Fixture::MetadataError => Self::MetadataError,
        }
    }
}

/// A count of omission events as persisted in `dir_omission.event_count`.
///
/// The unit is events, not files: see [`OmissionReason::one_event_is_one_file`]. The accepted
/// domain is `>= 1` — a row exists only because something happened — so there is no «unknown»
/// variant to confuse with a real zero. The column is SQLite's signed `INTEGER` and carries no
/// domain of its own, so this type is the one gate between it and the rest of the program, the
/// same role `reclaim::LinkCount` plays for `file.nlink`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventCount(u64);

impl EventCount {
    /// A single event.
    pub const ONE: Self = Self(1);

    /// Refuses zero, which no real row can carry.
    pub fn new(count: u64) -> Result<Self> {
        match count {
            0 => Err(AppError::msg(
                "an omission row cannot record zero events; nothing was omitted",
            )),
            count => Ok(Self(count)),
        }
    }

    /// Decodes a value read from the checkpoint. Zero and negatives are corruption and are
    /// refused — never reinterpreted as a large positive number.
    pub fn from_i64(raw: i64) -> Result<Self> {
        match raw {
            count if count > 0 => Ok(Self(count as u64)),
            invalid => Err(AppError::msg(format!(
                "dedcom.db holds a corrupt omission count ({invalid}); a recorded omission is never zero or negative. Rescan, or move the old dedcom.db aside."
            ))),
        }
    }

    /// Encodes for storage. A count too large for the signed column is refused here rather than
    /// wrapped into the negative a reader would then have to call corrupt.
    pub fn to_i64(self) -> Result<i64> {
        i64::try_from(self.0).map_err(|_| {
            AppError::msg(format!(
                "omission count {} does not fit dedcom.db's integer column",
                self.0
            ))
        })
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// Checked throughout: an aggregation that would wrap refuses instead of reporting a smaller
    /// number than the truth.
    pub fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or_else(|| AppError::msg("omission counts overflowed while aggregating"))
    }
}

/// One scan root's omissions, aggregated by affected directory and reason.
///
/// A map rather than a list of rows: two entries for the same `(directory, reason)` are
/// unrepresentable, so a producer cannot double-count by writing the same cell twice, and a
/// repeated commit of the same walk yields the same stored state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OmissionCounts(BTreeMap<(PathKey, OmissionReason), EventCount>);

impl OmissionCounts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one event. Checked, so an aggregation that would wrap is an error rather than a
    /// count that silently restarts near zero.
    pub fn bump(&mut self, directory: PathKey, reason: OmissionReason) -> Result<()> {
        self.add(directory, reason, EventCount::ONE)
    }

    /// Records `count` events at once.
    pub fn add(
        &mut self,
        directory: PathKey,
        reason: OmissionReason,
        count: EventCount,
    ) -> Result<()> {
        let cell = (directory, reason);
        let total = match self.0.get(&cell) {
            Some(existing) => existing.checked_add(count)?,
            None => count,
        };
        self.0.insert(cell, total);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Every recorded cell, in a deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&PathKey, OmissionReason, EventCount)> {
        self.0
            .iter()
            .map(|((directory, reason), count)| (directory, *reason, *count))
    }
}

/// What was omitted at or under one directory, per reason.
///
/// There is deliberately no combined total. The three [`EventKind`]s answer different questions —
/// how many files went missing, how many entries could not be represented, and how many errors hid
/// an unknowable amount — and one number covering all three would be a claim the scan cannot
/// support. A caller cannot print one it has no way to obtain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OmissionSummary {
    per_reason: BTreeMap<OmissionReason, EventCount>,
}

impl OmissionSummary {
    /// Folds one reason's events in. Checked.
    pub fn add(&mut self, reason: OmissionReason, count: EventCount) -> Result<()> {
        match self.per_reason.get(&reason) {
            Some(existing) => {
                let total = existing.checked_add(count)?;
                self.per_reason.insert(reason, total);
            }
            None => {
                self.per_reason.insert(reason, count);
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.per_reason.is_empty()
    }

    /// Files known to be omitted: the five reasons where one event is one file.
    pub fn known_omitted_files(&self) -> Result<u64> {
        self.total_of(EventKind::OmittedFile)
    }

    /// Directory entries the scan has no way to represent — a symlink it does not follow, a FIFO,
    /// a socket, a device. An exact count of ENTRIES, deliberately outside every file total.
    pub fn unsupported_entries(&self) -> Result<u64> {
        self.total_of(EventKind::UnsupportedEntry)
    }

    /// The events of one kind. Checked, so an aggregate that cannot be represented is an error
    /// rather than a smaller number than the truth.
    fn total_of(&self, kind: EventKind) -> Result<u64> {
        let mut total: u64 = 0;
        for (reason, count) in &self.per_reason {
            if reason.event_kind() == kind {
                total = total
                    .checked_add(count.get())
                    .ok_or_else(|| AppError::msg("omission counts overflowed while aggregating"))?;
            }
        }
        Ok(total)
    }

    /// Error events whose hidden file count is unknowable — `walk_error` alone. An unsupported
    /// entry is exactly one entry, so counting it here would forbid an exact figure that is exact.
    pub fn unknown_cardinality_events(&self) -> u64 {
        self.per_reason
            .iter()
            .filter(|(reason, _)| reason.event_kind() == EventKind::UnknownCardinality)
            .map(|(_, count)| count.get())
            .sum()
    }

    /// Whether any recorded event hides an unknown number of files. While this is true, no total
    /// may be presented as an exact count of omitted files.
    pub fn has_unknown_cardinality(&self) -> bool {
        self.unknown_cardinality_events() > 0
    }

    /// Every reason recorded here, in a deterministic order.
    pub fn per_reason(&self) -> impl Iterator<Item = (OmissionReason, EventCount)> + '_ {
        self.per_reason
            .iter()
            .map(|(reason, count)| (*reason, *count))
    }
}

/// What the checkpoint knows about one directory's completeness.
///
/// Policy-neutral on purpose: there is no accessor answering «may this claim to be a twin?».
/// `Unknown` is not a degraded `Complete` and not a quiet `Incomplete`; deciding what each verdict
/// means for a signature, a displayed figure or a destructive plan belongs to the integration that
/// wires all three together, so that the live and the materialized paths cannot answer
/// differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirCompleteness {
    /// This root's ledger is trusted, and nothing was omitted at or under this directory.
    Complete,
    /// This root's ledger is trusted, and at least one omission event lies at or under it.
    Incomplete(OmissionSummary),
    /// No trusted ledger covers this directory: the scan predates the ledger, its walk never
    /// committed one, a clear invalidated it, or the directory is outside every selected root.
    Unknown,
}

/// Why a scan has no completeness authority, as an expected outcome rather than a failure.
///
/// These are states of the operator's own configuration, not faults: the scan runs exactly as it
/// always did and simply cannot claim anything about completeness. A SQLite, I/O or constraint
/// failure is never one of these — those stay real errors, so a broken checkpoint can never be
/// mistaken for a merely unkeyable one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityUnavailable {
    /// A configured root has no lexical key: relative, containing `..`, or not valid UTF-8.
    UnkeyableRoot { given: String },
    /// Two configured roots normalize to keys where one contains the other. Root validation skips
    /// its canonical comparison when either path cannot be resolved, so a pair that does not exist
    /// yet reaches this point.
    AmbiguousRoots { outer: String, inner: String },
    /// The scan has no configured roots at all.
    NoRoots,
}

impl AuthorityUnavailable {
    /// One line naming the configuration that cannot be keyed, for a log or a later notice.
    pub fn explain(&self) -> String {
        match self {
            Self::UnkeyableRoot { given } => format!(
                "scan root {} cannot be stored as a completeness key (it must be absolute, free of '..', and valid UTF-8)",
                crate::textsan::terminal(given)
            ),
            Self::AmbiguousRoots { outer, inner } => format!(
                "scan roots {} and {} overlap once normalized, so a directory under them cannot be attributed to one root",
                crate::textsan::terminal(outer),
                crate::textsan::terminal(inner)
            ),
            Self::NoRoots => String::from("the scan has no selected roots"),
        }
    }
}

/// The outcome of registering a scan's roots as completeness authorities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootRegistration {
    /// Every configured root has a key, the keys are mutually disjoint, and a row exists for each.
    Registered { roots: usize },
    /// Expected: the scan keeps working and simply has no completeness authority.
    Unavailable(AuthorityUnavailable),
}

impl RootRegistration {
    pub fn is_registered(&self) -> bool {
        matches!(self, Self::Registered { .. })
    }
}

// -------------------------------------------------------------------------------------------
// Signature policy: what a completeness verdict means for a directory signature, and the one
// context a signature build consults for it.
//
// Inert here as everywhere else in this module — nothing in production builds a context or asks
// for a disposition until R3D.
// -------------------------------------------------------------------------------------------

/// What a completeness verdict means for a directory signature.
///
/// Three values, not a boolean: `Trusted` and `Untrusted` both emit a signature, and collapsing
/// them would destroy exactly the distinction a destructive gate needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirDisposition {
    /// The ledger vouches for this directory: emit a signature, and a group built from it may be
    /// acted on.
    Trusted,
    /// Emit no signature and no group. The scan did not see all of this directory, so it is not
    /// an exact twin of anything.
    Suppressed,
    /// No trusted ledger covers it. Emit exactly as a pre-ledger build would, so nothing an
    /// operator can browse disappears, but carry «not trusted» so a destructive path can say
    /// `rescan required` rather than a saving.
    Untrusted,
}

impl DirCompleteness {
    /// The ONE mapping from a verdict to a signature disposition. Both the live and the
    /// materialized paths go through it, so they cannot answer differently.
    pub fn disposition(&self) -> DirDisposition {
        match self {
            Self::Complete => DirDisposition::Trusted,
            Self::Incomplete(_) => DirDisposition::Suppressed,
            Self::Unknown => DirDisposition::Untrusted,
        }
    }
}

/// Where a path sits relative to the scan's selected roots.
///
/// `Unbounded` is explicit rather than modelled as a root of `/`: a relative or `..`-spelled
/// manifest pathname is not under `/` in the component sense, so a fake `/` root would classify
/// exactly the spellings that need legacy treatment as `Outside`. Unboundedness is a state, not a
/// wide root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirScope<'a> {
    /// Inside this selected root; frames and accumulators start there and go no higher.
    Root(&'a PathKey),
    /// No root bounding at all — the pre-ledger behavior, ancestors to the filesystem root.
    Unbounded,
    /// Under no selected root. A manifest file here is a wiring failure, not something to drop.
    Outside,
}

/// Everything a signature build needs to know about scope and completeness, from one load.
///
/// One object, because scope and completeness supplied separately can be built from different
/// configurations or generations and disagree about the same directory.
pub trait SignatureContext {
    fn scope(&self, path: &Path) -> DirScope<'_>;
    /// Total: every path has an answer.
    fn disposition(&self, path: &Path) -> DirDisposition;
}

/// The pre-ledger context: no bounding, nothing trusted.
///
/// The only other implementation of [`SignatureContext`], and the one the compatibility wrappers
/// use, so today's behavior is the general path with different data rather than a special branch.
pub struct LegacyContext;

impl SignatureContext for LegacyContext {
    fn scope(&self, _path: &Path) -> DirScope<'_> {
        DirScope::Unbounded
    }

    fn disposition(&self, _path: &Path) -> DirDisposition {
        DirDisposition::Untrusted
    }
}

/// One stored omission row, as a bounded loader hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOmission {
    pub root_key: String,
    pub dir_key: String,
    pub reason: String,
    pub event_count: i64,
    pub generation: i64,
}

/// The result of building a snapshot: a usable authority, or the typed reason there is none.
///
/// Typed so a caller selects [`LegacyContext`] by matching this, never by inspecting private
/// fields, parsing an error string or guessing from a `None` scope.
#[derive(Debug)]
pub enum SnapshotOutcome {
    Bounded(CompletenessSnapshot),
    Unavailable(AuthorityUnavailable),
}

/// Scan-wide omission accounting. Exact totals exist only under full authority — anything less is
/// typed [`ScanAccounting::Unavailable`], never an exact zero read off an empty or partial fold.
/// `Bounded` alone proves the roots are keyable scope; whether the ledger may be summed is a
/// separate fact, and this type is the only way to obtain the sum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanAccounting {
    /// Every stored current-generation cell folded exactly once, checked. A committed empty
    /// ledger is a genuine exact zero.
    Exact(OmissionSummary),
    /// Pre-ledger scans (no registration), registration drift, any generation-zero root, mixed
    /// authority. Browseable, but no figure may be presented.
    Unavailable,
}

/// One scan's completeness authority, loaded once and answerable offline.
///
/// Holds the scan's own persisted configured roots, the registered generations, the checked
/// current-generation omission summaries and the root-wide sentinels. It is the total classifier:
/// once built, any path can be answered without touching the database, which is what removes both
/// the per-directory SQL and the need for a caller to enumerate candidates in advance.
#[derive(Debug)]
pub struct CompletenessSnapshot {
    /// Normalized, sorted, mutually disjoint.
    configured: Vec<PathKey>,
    /// Registered authority: root key → generation (>= 0).
    registered: BTreeMap<PathKey, i64>,
    /// Current-generation rows, keyed by the normalized directory string for range lookup.
    rows: BTreeMap<String, (PathKey, OmissionSummary)>,
    /// Roots holding a current-generation `walk_error` row at `dir_key == root_key`, with that
    /// row's checked event count. A root here means the walk may have missed entries anywhere
    /// under it, so membership suppresses the whole root and the count reaches every strict
    /// descendant's detailed verdict. A query OF the root folds the same cell through its exact
    /// row in `rows` instead — one or the other, never both.
    sentinels: BTreeMap<PathKey, EventCount>,
    /// Whether the configured and registered root sets are the same. False ⇒ nothing is trusted,
    /// but the scan stays root-bounded: a drifted registration is not an unbounded scan.
    agrees: bool,
}

impl CompletenessSnapshot {
    /// Validates and owns one bounded load. Pure — no SQLite.
    ///
    /// A configuration this build cannot speak for is an expected outcome; malformed stored data
    /// is an error. The two never swap places. Stale-generation rows are ignored rather than
    /// allowed to reach a verdict, so a superseded row can never be read as evidence.
    pub fn build(
        configured_roots: &[PathBuf],
        registered: Vec<(String, i64)>,
        rows: Vec<StoredOmission>,
    ) -> Result<SnapshotOutcome> {
        if configured_roots.is_empty() {
            return Ok(SnapshotOutcome::Unavailable(AuthorityUnavailable::NoRoots));
        }
        let mut configured: Vec<PathKey> = Vec::with_capacity(configured_roots.len());
        for root in configured_roots {
            match PathKey::new(root) {
                Some(key) => configured.push(key),
                None => {
                    return Ok(SnapshotOutcome::Unavailable(
                        AuthorityUnavailable::UnkeyableRoot {
                            given: root.display().to_string(),
                        },
                    ))
                }
            }
        }
        for (index, outer) in configured.iter().enumerate() {
            for inner in configured.iter().skip(index + 1) {
                if inner.is_at_or_under(outer) || outer.is_at_or_under(inner) {
                    let (outer, inner) = if inner.is_at_or_under(outer) {
                        (outer, inner)
                    } else {
                        (inner, outer)
                    };
                    return Ok(SnapshotOutcome::Unavailable(
                        AuthorityUnavailable::AmbiguousRoots {
                            outer: outer.as_str().to_string(),
                            inner: inner.as_str().to_string(),
                        },
                    ));
                }
            }
        }
        configured.sort();

        let mut generations: BTreeMap<PathKey, i64> = BTreeMap::new();
        for (raw, generation) in registered {
            if generation < 0 {
                return Err(AppError::msg(format!(
                    "dedcom.db holds a corrupt completeness generation ({generation}); rescan, or move the old dedcom.db aside."
                )));
            }
            generations.insert(PathKey::from_stored(&raw)?, generation);
        }
        let agrees = generations.len() == configured.len()
            && configured.iter().all(|root| generations.contains_key(root));

        let mut summaries: BTreeMap<String, (PathKey, OmissionSummary)> = BTreeMap::new();
        let mut sentinels: BTreeMap<PathKey, EventCount> = BTreeMap::new();
        for row in rows {
            let root = PathKey::from_stored(&row.root_key)?;
            // A superseded or unregistered row is ignored, never validated into an error and never
            // allowed to reach a verdict.
            match generations.get(&root) {
                Some(current) if *current > 0 && *current == row.generation => {}
                _ => continue,
            }
            let directory = PathKey::from_stored(&row.dir_key)?;
            if !directory.is_at_or_under(&root) {
                return Err(AppError::msg(format!(
                    "dedcom.db places {} outside its scan root {}; rescan, or move the old dedcom.db aside.",
                    crate::textsan::terminal(directory.as_str()),
                    crate::textsan::terminal(root.as_str())
                )));
            }
            let reason = OmissionReason::parse(&row.reason).ok_or_else(|| {
                AppError::msg(format!(
                    "dedcom.db records an omission reason this build does not know ({}); upgrade dedcom, or move the old dedcom.db aside.",
                    crate::textsan::terminal(&row.reason)
                ))
            })?;
            let count = EventCount::from_i64(row.event_count)?;
            if reason == OmissionReason::WalkError && directory == root {
                let total = match sentinels.get(&root) {
                    Some(existing) => existing.checked_add(count)?,
                    None => count,
                };
                sentinels.insert(root.clone(), total);
            }
            let slot = summaries
                .entry(directory.as_str().to_string())
                .or_insert_with(|| (root.clone(), OmissionSummary::default()));
            slot.1.add(reason, count)?;
        }

        Ok(SnapshotOutcome::Bounded(Self {
            configured,
            registered: generations,
            rows: summaries,
            sentinels,
            agrees,
        }))
    }

    /// The selected root containing `path`, if any. Component-wise, so `/tank/ab` is not under
    /// `/tank/a`.
    fn owning_root(&self, path: &Path) -> Option<&PathKey> {
        self.configured
            .iter()
            .find(|root| path.starts_with(Path::new(root.as_str())))
    }

    /// Whether this root's ledger may be trusted at all.
    fn trusted_root(&self, root: &PathKey) -> bool {
        self.agrees && self.registered.get(root).copied().unwrap_or(0) > 0
    }

    /// Whether an omission lies at or under `key`, within `root`. Existence only: construction has
    /// already rejected malformed current data, so a verdict needs no re-validation.
    fn omitted_at_or_under(&self, root: &PathKey, key: &PathKey) -> bool {
        if self.sentinels.contains_key(root) {
            return true;
        }
        if let Some((stored, _)) = self.rows.get(key.as_str()) {
            if stored == root {
                return true;
            }
        }
        let (lo, hi) = key.subtree_bounds();
        self.rows
            .range(lo..hi)
            .any(|(_, (stored, _))| stored == root)
    }

    /// The full tri-state with its summary — for a reader that wants the detail, never once per
    /// candidate. Total over paths, and in agreement with [`SignatureContext::disposition`]: both
    /// classifiers fold the same rows and the same root sentinel.
    pub fn verdict(&self, path: &Path) -> Result<DirCompleteness> {
        let Some(key) = PathKey::new(path) else {
            return Ok(DirCompleteness::Unknown);
        };
        let Some(root) = self.owning_root(path) else {
            return Ok(DirCompleteness::Unknown);
        };
        if !self.trusted_root(root) {
            return Ok(DirCompleteness::Unknown);
        }
        let mut summary = OmissionSummary::default();
        let mut fold = |stored: &PathKey, found: &OmissionSummary| -> Result<()> {
            if stored != root {
                return Ok(());
            }
            for (reason, count) in found.per_reason() {
                summary.add(reason, count)?;
            }
            Ok(())
        };
        if let Some((stored, found)) = self.rows.get(key.as_str()) {
            fold(stored, found)?;
        }
        let (lo, hi) = key.subtree_bounds();
        for (_, (stored, found)) in self.rows.range(lo..hi) {
            fold(stored, found)?;
        }
        // A current root sentinel is root-wide: the walk may have missed entries anywhere under
        // this root, so its `walk_error` count reaches every descendant — while the root's other
        // reasons stay ordinary local rows that travel only by containment. A query OF the root
        // has already folded that same cell through its exact row, so only a strict descendant
        // adds it here.
        if key != *root {
            if let Some(count) = self.sentinels.get(root) {
                summary.add(OmissionReason::WalkError, *count)?;
            }
        }
        if summary.is_empty() {
            Ok(DirCompleteness::Complete)
        } else {
            Ok(DirCompleteness::Incomplete(summary))
        }
    }

    /// The one authority predicate: the configured and registered root sets agree AND every
    /// registered root carries a positive generation. `agrees` already pins set equality, so the
    /// second clause reads the registered generations directly. This is what separates «bounded
    /// scope» from «a ledger whose totals may be spoken»: pre-ledger scans, drift, a cleared root
    /// and mixed authority all answer false here while still constructing a bounded snapshot.
    pub fn fully_authoritative(&self) -> bool {
        self.agrees && self.registered.values().all(|generation| *generation > 0)
    }

    /// Scan-wide accounting, gated by [`Self::fully_authoritative`]. The fold itself is private:
    /// no caller can obtain totals without passing the authority gate, and authority is never
    /// inferred from whether the totals happen to be empty.
    pub fn scan_accounting(&self) -> Result<ScanAccounting> {
        if !self.fully_authoritative() {
            return Ok(ScanAccounting::Unavailable);
        }
        Ok(ScanAccounting::Exact(self.fold_totals()?))
    }

    /// Folds each stored current-generation cell exactly once, checked. Deliberately iterates the
    /// rows and never calls [`Self::verdict`]: a root sentinel is one stored cell, and its
    /// root-wide reach is verdict-time semantics that must not multiply it here.
    fn fold_totals(&self) -> Result<OmissionSummary> {
        let mut totals = OmissionSummary::default();
        for (_, summary) in self.rows.values() {
            for (reason, count) in summary.per_reason() {
                totals.add(reason, count)?;
            }
        }
        Ok(totals)
    }
}

impl SignatureContext for CompletenessSnapshot {
    fn scope(&self, path: &Path) -> DirScope<'_> {
        match self.owning_root(path) {
            Some(root) => DirScope::Root(root),
            None => DirScope::Outside,
        }
    }

    fn disposition(&self, path: &Path) -> DirDisposition {
        let Some(key) = PathKey::new(path) else {
            return DirDisposition::Untrusted;
        };
        let Some(root) = self.owning_root(path) else {
            return DirDisposition::Untrusted;
        };
        if !self.trusted_root(root) {
            return DirDisposition::Untrusted;
        }
        if self.omitted_at_or_under(root, &key) {
            DirDisposition::Suppressed
        } else {
            DirDisposition::Trusted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn key(path: &str) -> PathKey {
        PathKey::new(Path::new(path)).expect("a keyable path")
    }

    #[test]
    fn path_key_normalizes_the_shapes_std_already_folds() {
        for (given, expected) in [
            ("/tmp/root", "/tmp/root"),
            ("/tmp/root/", "/tmp/root"),
            ("/tmp//root///sub/", "/tmp/root/sub"),
            ("/tmp/./root/./sub", "/tmp/root/sub"),
            ("/", "/"),
            ("//", "/"),
            ("/tmp/root/.", "/tmp/root"),
        ] {
            assert_eq!(
                key(given).as_str(),
                expected,
                "{given} must normalize to {expected}"
            );
        }
    }

    #[test]
    fn path_key_refuses_what_it_cannot_attribute() {
        for given in ["/tmp/../other", "..", "tmp/root", "relative/sub", ""] {
            assert!(
                PathKey::new(Path::new(given)).is_none(),
                "{given} must have no key"
            );
        }
    }

    #[test]
    fn path_key_refuses_a_non_utf8_component() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let path = PathBuf::from(OsStr::from_bytes(b"/tmp/bad\xffname"));
        assert!(
            PathKey::new(&path).is_none(),
            "a non-UTF8 component has no key"
        );
    }

    /// A root that does not exist yet still has a key: the contract is lexical, and refusing an
    /// unresolvable root here would make completeness depend on when the scan was configured.
    #[test]
    fn path_key_does_not_need_the_path_to_exist() {
        assert_eq!(
            key("/definitely/not/here/at/all").as_str(),
            "/definitely/not/here/at/all"
        );
    }

    #[test]
    fn containment_is_component_wise() {
        let root = key("/tank");
        assert!(root.is_at_or_under(&root), "a root contains itself");
        assert!(key("/tank/a").is_at_or_under(&root));
        assert!(key("/tank/a/b/c").is_at_or_under(&root));
        // The prefix sibling that a bare string comparison would swallow.
        assert!(!key("/tanker").is_at_or_under(&root));
        assert!(!key("/tanker/x").is_at_or_under(&root));
        assert!(!key("/other").is_at_or_under(&root));
        // And the directory above it is not under it.
        assert!(!key("/").is_at_or_under(&root));
    }

    #[test]
    fn the_filesystem_root_contains_every_absolute_path() {
        let root = key("/");
        for path in ["/", "/tank", "/tank/a/b", "/zzz"] {
            assert!(key(path).is_at_or_under(&root), "{path} must be under /");
        }
    }

    #[test]
    fn subtree_bounds_exclude_self_and_prefix_siblings() {
        let (lo, hi) = key("/tank/a").subtree_bounds();
        assert_eq!((lo.as_str(), hi.as_str()), ("/tank/a/", "/tank/a0"));
        assert!("/tank/a/x" >= lo.as_str() && "/tank/a/x" < hi.as_str());
        // The directory itself is outside the range: a reader asks for it separately.
        assert!(!("/tank/a" >= lo.as_str() && "/tank/a" < hi.as_str()));
        // `-` sorts below `0`, which is why the lower bound carries the separator.
        assert!(!("/tank/a-old" >= lo.as_str() && "/tank/a-old" < hi.as_str()));
        assert!(!("/tank/ab" >= lo.as_str() && "/tank/ab" < hi.as_str()));

        let (lo, hi) = key("/").subtree_bounds();
        assert_eq!((lo.as_str(), hi.as_str()), ("/", "0"));
        for path in ["/a", "/tank/file", "/zzz/deep"] {
            assert!(
                path >= lo.as_str() && path < hi.as_str(),
                "{path} outside /"
            );
        }
    }

    #[test]
    fn a_stored_key_must_already_be_normalized() {
        assert_eq!(PathKey::from_stored("/tank/a").unwrap().as_str(), "/tank/a");
        assert_eq!(PathKey::from_stored("/").unwrap().as_str(), "/");
        for raw in ["/tank/a/", "/tank//a", "/tank/./a", "tank/a", "/tank/../a"] {
            let err = PathKey::from_stored(raw).expect_err("must refuse {raw}");
            assert!(
                err.to_string().contains("malformed path key"),
                "the reason must be plain: {err}"
            );
        }
    }

    #[test]
    fn every_reason_round_trips_through_its_wire_value() {
        for reason in OmissionReason::ALL {
            assert_eq!(OmissionReason::parse(reason.as_str()), Some(reason));
        }
        assert_eq!(
            OmissionReason::ALL.map(OmissionReason::as_str),
            [
                "min_size",
                "max_size",
                "extension_filtered",
                "non_utf8",
                "walk_error",
                "metadata_error",
                "unsupported_entry"
            ]
        );
    }

    #[test]
    fn an_unknown_reason_has_no_variant() {
        for text in ["quota_error", "", "MIN_SIZE", "min size"] {
            assert_eq!(OmissionReason::parse(text), None, "{text} must not parse");
        }
    }

    /// The three kinds partition every reason, and each answers a different question. Written as
    /// an exhaustive table rather than a predicate, so adding a reason without deciding its kind
    /// fails here instead of quietly joining whichever bucket a boolean happened to put it in.
    #[test]
    fn every_reason_has_exactly_one_event_kind() {
        use EventKind::*;
        let table = [
            (OmissionReason::MinSize, OmittedFile),
            (OmissionReason::MaxSize, OmittedFile),
            (OmissionReason::ExtensionFiltered, OmittedFile),
            (OmissionReason::NonUtf8, OmittedFile),
            (OmissionReason::MetadataError, OmittedFile),
            (OmissionReason::WalkError, UnknownCardinality),
            (OmissionReason::UnsupportedEntry, UnsupportedEntry),
        ];
        assert_eq!(
            table.len(),
            OmissionReason::ALL.len(),
            "every reason must appear exactly once"
        );
        for (reason, kind) in table {
            assert_eq!(reason.event_kind(), kind, "{reason:?}");
            assert_eq!(
                reason.one_event_is_one_file(),
                kind == OmittedFile,
                "{reason:?}: the predicate must follow the kind"
            );
        }
    }

    /// Only the iterator branch can hide a subtree. The metadata branch is reached after the entry
    /// was already typed as a regular file, and an unsupported entry is exactly one entry.
    #[test]
    fn only_a_walk_error_hides_an_unknown_number_of_files() {
        for reason in OmissionReason::ALL {
            assert_eq!(
                reason.event_kind() == EventKind::UnknownCardinality,
                reason == OmissionReason::WalkError,
                "{reason:?}"
            );
        }
    }

    /// The three counters never borrow from each other: a file total excludes entries and errors,
    /// an entry total excludes files, and neither is allowed to make the exact count inexact.
    #[test]
    fn the_three_counters_stay_separate() {
        let mut summary = OmissionSummary::default();
        summary
            .add(OmissionReason::MinSize, EventCount::new(2).unwrap())
            .unwrap();
        summary
            .add(
                OmissionReason::UnsupportedEntry,
                EventCount::new(3).unwrap(),
            )
            .unwrap();

        assert_eq!(summary.known_omitted_files().unwrap(), 2);
        assert_eq!(summary.unsupported_entries().unwrap(), 3);
        assert_eq!(
            summary.unknown_cardinality_events(),
            0,
            "an unsupported entry is a known quantity"
        );
        assert!(
            !summary.has_unknown_cardinality(),
            "three sockets do not make a count inexact"
        );

        summary
            .add(OmissionReason::WalkError, EventCount::ONE)
            .unwrap();
        assert_eq!(summary.known_omitted_files().unwrap(), 2, "still two files");
        assert_eq!(
            summary.unsupported_entries().unwrap(),
            3,
            "still three entries"
        );
        assert_eq!(summary.unknown_cardinality_events(), 1);
        assert!(summary.has_unknown_cardinality());
    }

    #[test]
    fn intentional_filters_are_exactly_the_three_config_narrowings() {
        let intentional: Vec<_> = OmissionReason::ALL
            .into_iter()
            .filter(|reason| reason.is_intentional_filter())
            .collect();
        assert_eq!(
            intentional,
            vec![
                OmissionReason::MinSize,
                OmissionReason::MaxSize,
                OmissionReason::ExtensionFiltered
            ]
        );
    }

    #[test]
    fn event_count_refuses_a_value_no_real_row_can_hold() {
        assert!(EventCount::new(0).is_err());
        assert_eq!(EventCount::new(3).unwrap().get(), 3);
        assert!(EventCount::from_i64(0).is_err());
        assert!(EventCount::from_i64(-1).is_err());
        assert_eq!(EventCount::from_i64(7).unwrap().get(), 7);
    }

    #[test]
    fn event_count_persistence_boundary() {
        let biggest = EventCount::new(i64::MAX as u64).unwrap();
        assert_eq!(biggest.to_i64().unwrap(), i64::MAX);
        let too_big = EventCount::new(i64::MAX as u64 + 1).unwrap();
        let err = too_big.to_i64().expect_err("must not fit the column");
        assert!(err.to_string().contains("does not fit"), "{err}");
    }

    #[test]
    fn aggregation_is_checked_rather_than_wrapping() {
        let big = EventCount::new(u64::MAX).unwrap();
        assert!(big.checked_add(EventCount::ONE).is_err());

        let mut counts = OmissionCounts::new();
        counts
            .add(key("/tank/a"), OmissionReason::MinSize, big)
            .unwrap();
        let err = counts
            .bump(key("/tank/a"), OmissionReason::MinSize)
            .expect_err("bumping past u64::MAX must refuse");
        assert!(err.to_string().contains("overflow"), "{err}");
    }

    #[test]
    fn counts_aggregate_per_directory_and_reason() {
        let mut counts = OmissionCounts::new();
        counts
            .bump(key("/tank/a"), OmissionReason::MinSize)
            .unwrap();
        counts
            .bump(key("/tank/a"), OmissionReason::MinSize)
            .unwrap();
        counts
            .bump(key("/tank/a"), OmissionReason::MinSize)
            .unwrap();
        counts
            .bump(key("/tank/a"), OmissionReason::NonUtf8)
            .unwrap();
        counts
            .bump(key("/tank/b"), OmissionReason::MinSize)
            .unwrap();

        assert_eq!(counts.len(), 3, "three distinct (directory, reason) cells");
        let cells: Vec<_> = counts
            .iter()
            .map(|(dir, reason, count)| (dir.as_str().to_string(), reason, count.get()))
            .collect();
        assert_eq!(
            cells,
            vec![
                ("/tank/a".to_string(), OmissionReason::MinSize, 3),
                ("/tank/a".to_string(), OmissionReason::NonUtf8, 1),
                ("/tank/b".to_string(), OmissionReason::MinSize, 1),
            ]
        );
    }

    #[test]
    fn a_summary_separates_known_files_from_unknowable_events() {
        let mut summary = OmissionSummary::default();
        summary
            .add(OmissionReason::MinSize, EventCount::new(2).unwrap())
            .unwrap();
        summary
            .add(OmissionReason::MetadataError, EventCount::ONE)
            .unwrap();
        assert_eq!(summary.known_omitted_files().unwrap(), 3);
        assert_eq!(summary.unknown_cardinality_events(), 0);
        assert!(!summary.has_unknown_cardinality());

        summary
            .add(OmissionReason::WalkError, EventCount::new(4).unwrap())
            .unwrap();
        assert_eq!(
            summary.known_omitted_files().unwrap(),
            3,
            "a walk error never joins the known file count"
        );
        assert_eq!(summary.unknown_cardinality_events(), 4);
        assert!(
            summary.has_unknown_cardinality(),
            "no total may be shown as exact while this holds"
        );
    }

    #[test]
    fn summary_aggregation_is_checked() {
        let mut summary = OmissionSummary::default();
        summary
            .add(OmissionReason::MinSize, EventCount::new(u64::MAX).unwrap())
            .unwrap();
        assert!(summary
            .add(OmissionReason::MinSize, EventCount::ONE)
            .is_err());
    }

    /// The fixture's ground truth and this module's enum are one definition. The conversion is
    /// exhaustive, so drift is a compile error; this test proves the mapping is also correct.
    #[test]
    fn the_fixture_reasons_map_onto_the_stored_ones() {
        use crate::testfixtures::dir_completeness::OmissionReason as Fixture;
        for (fixture, expected) in [
            (Fixture::BelowMin, OmissionReason::MinSize),
            (Fixture::AboveMax, OmissionReason::MaxSize),
            (
                Fixture::ExtensionFiltered,
                OmissionReason::ExtensionFiltered,
            ),
            (Fixture::NonUtf8, OmissionReason::NonUtf8),
            (Fixture::WalkError, OmissionReason::WalkError),
            (Fixture::MetadataError, OmissionReason::MetadataError),
        ] {
            assert_eq!(OmissionReason::from(fixture), expected, "{fixture:?}");
        }
    }

    /// The whole point of the fixture: every file it declares omitted is attributed to its parent
    /// directory, and no child pathname is needed to say so.
    #[test]
    fn fixture_omissions_key_on_the_parent_directory() {
        let trees = crate::testfixtures::dir_completeness::DirTrees::build("keys");
        let root = PathKey::new(&trees.root).expect("the fixture root is keyable");
        for (file, reason) in trees.expected_omissions() {
            let parent = file.parent().expect("an omitted file has a parent");
            let directory = PathKey::new(parent)
                .unwrap_or_else(|| panic!("{} must be keyable", parent.display()));
            assert!(
                directory.is_at_or_under(&root),
                "{} must lie inside the scan root",
                directory.as_str()
            );
            // The non-UTF8 child is the case that matters: its own name has no key, its parent does.
            if OmissionReason::from(reason) == OmissionReason::NonUtf8 {
                assert!(
                    PathKey::new(&file).is_none(),
                    "the non-UTF8 child itself must have no key"
                );
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // R3C: the signature context.
    // ---------------------------------------------------------------------------------------

    fn stored(root: &str, dir: &str, reason: &str, count: i64, generation: i64) -> StoredOmission {
        StoredOmission {
            root_key: root.to_string(),
            dir_key: dir.to_string(),
            reason: reason.to_string(),
            event_count: count,
            generation,
        }
    }

    fn built(
        roots: &[&str],
        gens: &[(&str, i64)],
        rows: Vec<StoredOmission>,
    ) -> Result<SnapshotOutcome> {
        let configured: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
        let registered = gens.iter().map(|(k, g)| (k.to_string(), *g)).collect();
        CompletenessSnapshot::build(&configured, registered, rows)
    }

    fn bounded(
        roots: &[&str],
        gens: &[(&str, i64)],
        rows: Vec<StoredOmission>,
    ) -> CompletenessSnapshot {
        match built(roots, gens, rows).unwrap() {
            SnapshotOutcome::Bounded(snapshot) => snapshot,
            SnapshotOutcome::Unavailable(why) => panic!("expected bounded: {why:?}"),
        }
    }

    /// The one mapping from a verdict to a disposition, exhaustively.
    #[test]
    fn every_verdict_maps_to_one_disposition() {
        assert_eq!(
            DirCompleteness::Complete.disposition(),
            DirDisposition::Trusted
        );
        assert_eq!(
            DirCompleteness::Incomplete(OmissionSummary::default()).disposition(),
            DirDisposition::Suppressed
        );
        assert_eq!(
            DirCompleteness::Unknown.disposition(),
            DirDisposition::Untrusted
        );
    }

    /// A configuration this build cannot speak for is a typed outcome a caller can match on —
    /// never an error string to parse and never a guess from an absent scope.
    #[test]
    fn an_unusable_configuration_is_a_typed_outcome() {
        for (roots, expected) in [
            (vec![], "no roots"),
            (vec!["relative/root"], "unkeyable"),
            (vec!["/tank/../tank"], "unkeyable"),
            (vec!["/a", "/a/inner"], "ambiguous"),
        ] {
            match built(&roots, &[], Vec::new()).unwrap() {
                SnapshotOutcome::Unavailable(why) => assert!(
                    matches!(
                        (&why, expected),
                        (AuthorityUnavailable::NoRoots, "no roots")
                            | (AuthorityUnavailable::UnkeyableRoot { .. }, "unkeyable")
                            | (AuthorityUnavailable::AmbiguousRoots { .. }, "ambiguous")
                    ),
                    "{roots:?} expected {expected}, got {why:?}"
                ),
                SnapshotOutcome::Bounded(_) => panic!("{roots:?} must not be usable"),
            }
        }
    }

    /// Malformed stored data is an error, never a quiet degradation to legacy.
    #[test]
    fn malformed_stored_data_is_an_error() {
        // A stored key that is not in normalized form.
        assert!(built(&["/r"], &[("/r/", 1)], Vec::new()).is_err());
        // A negative generation.
        assert!(built(&["/r"], &[("/r", -1)], Vec::new()).is_err());
        // A reason this build does not know, at the current generation.
        let err = built(
            &["/r"],
            &[("/r", 1)],
            vec![stored("/r", "/r/a", "quota_error", 1, 1)],
        )
        .expect_err("an unknown reason must not be summarised")
        .to_string();
        assert!(err.contains("does not know"), "{err}");
        // An impossible count.
        assert!(built(
            &["/r"],
            &[("/r", 1)],
            vec![stored("/r", "/r/a", "min_size", 0, 1)]
        )
        .is_err());
        // A row placed outside its own root.
        assert!(built(
            &["/r"],
            &[("/r", 1)],
            vec![stored("/r", "/elsewhere", "min_size", 1, 1)]
        )
        .is_err());
    }

    /// A superseded row is ignored rather than allowed to reach a verdict — and ignoring it means
    /// its contents are never validated into an error either.
    #[test]
    fn stale_generation_rows_are_ignored() {
        let snapshot = bounded(
            &["/r"],
            &[("/r", 2)],
            vec![
                stored("/r", "/r/old", "min_size", 1, 1),
                stored("/r", "/r/gone", "quota_error", -5, 1),
            ],
        );
        assert_eq!(
            snapshot.disposition(Path::new("/r/old")),
            DirDisposition::Trusted,
            "a generation-1 row says nothing about generation 2"
        );
        assert_eq!(
            snapshot.disposition(Path::new("/r")),
            DirDisposition::Trusted
        );
    }

    /// Aggregation across a subtree is checked.
    #[test]
    fn subtree_aggregation_is_checked() {
        // Two `i64::MAX` cells still fit a `u64` — barely, one short of its maximum — so it takes
        // three to leave the domain. Pinning the boundary rather than assuming it.
        let two = bounded(
            &["/r"],
            &[("/r", 1)],
            vec![
                stored("/r", "/r/a", "min_size", i64::MAX, 1),
                stored("/r", "/r/b", "min_size", i64::MAX, 1),
            ],
        );
        match two.verdict(Path::new("/r")).unwrap() {
            DirCompleteness::Incomplete(summary) => assert_eq!(
                summary.known_omitted_files().unwrap(),
                (i64::MAX as u64) * 2,
                "two maxima still fit"
            ),
            other => panic!("expected incomplete, got {other:?}"),
        }

        let snapshot = bounded(
            &["/r"],
            &[("/r", 1)],
            vec![
                stored("/r", "/r/a", "min_size", i64::MAX, 1),
                stored("/r", "/r/b", "min_size", i64::MAX, 1),
                stored("/r", "/r/c", "min_size", i64::MAX, 1),
            ],
        );
        assert!(
            snapshot.verdict(Path::new("/r")).is_err(),
            "three i64::MAX cells cannot be summed into one figure"
        );
        // The disposition needs no sum, so suppression still answers.
        assert_eq!(
            snapshot.disposition(Path::new("/r")),
            DirDisposition::Suppressed
        );
    }

    /// Scope and disposition come from the one object, and every path has an answer.
    #[test]
    fn scope_and_disposition_are_total() {
        let snapshot = bounded(
            &["/a", "/b"],
            &[("/a", 1), ("/b", 1)],
            vec![stored("/a", "/a/deep/x", "non_utf8", 1, 1)],
        );
        assert!(matches!(
            snapshot.scope(Path::new("/a/deep/x")),
            DirScope::Root(_)
        ));
        assert_eq!(snapshot.scope(Path::new("/elsewhere")), DirScope::Outside);
        assert_eq!(snapshot.scope(Path::new("relative")), DirScope::Outside);

        // Suppression reaches every ancestor through the root, from the ledger alone.
        for dir in ["/a/deep/x", "/a/deep", "/a"] {
            assert_eq!(
                snapshot.disposition(Path::new(dir)),
                DirDisposition::Suppressed,
                "{dir}"
            );
        }
        // A sibling and the other root are untouched.
        assert_eq!(
            snapshot.disposition(Path::new("/a/other")),
            DirDisposition::Trusted
        );
        assert_eq!(
            snapshot.disposition(Path::new("/b")),
            DirDisposition::Trusted
        );
        // Outside every root, and unkeyable: untrusted, never trusted.
        assert_eq!(
            snapshot.disposition(Path::new("/elsewhere")),
            DirDisposition::Untrusted
        );
        assert_eq!(
            snapshot.disposition(Path::new("relative")),
            DirDisposition::Untrusted
        );

        // The detailed verdict agrees and carries the reason.
        match snapshot.verdict(Path::new("/a")).unwrap() {
            DirCompleteness::Incomplete(summary) => {
                assert_eq!(summary.known_omitted_files().unwrap(), 1)
            }
            other => panic!("expected incomplete, got {other:?}"),
        }
        assert_eq!(
            snapshot.verdict(Path::new("/b")).unwrap(),
            DirCompleteness::Complete
        );
        assert_eq!(
            snapshot.verdict(Path::new("/elsewhere")).unwrap(),
            DirCompleteness::Unknown
        );
    }

    /// Drift and a generation of 0 keep the root bounds and answer untrusted.
    #[test]
    fn drift_and_generation_zero_are_bounded_but_untrusted() {
        for snapshot in [
            bounded(&["/r"], &[("/r", 0)], Vec::new()),
            bounded(&["/r"], &[("/other", 3)], Vec::new()),
        ] {
            assert!(matches!(
                snapshot.scope(Path::new("/r/a")),
                DirScope::Root(_)
            ));
            assert_eq!(
                snapshot.disposition(Path::new("/r/a")),
                DirDisposition::Untrusted
            );
            assert_eq!(
                snapshot.verdict(Path::new("/r/a")).unwrap(),
                DirCompleteness::Unknown
            );
        }
    }

    /// The legacy context is unbounded and trusts nothing — and unboundedness is its own state,
    /// not a root of `/`, so a relative pathname is in scope rather than outside it.
    #[test]
    fn the_legacy_context_is_unbounded_not_a_root() {
        let ctx = LegacyContext;
        for path in ["/a/b", "relative/x", "/x/../x/y"] {
            assert_eq!(ctx.scope(Path::new(path)), DirScope::Unbounded, "{path}");
            assert_eq!(
                ctx.disposition(Path::new(path)),
                DirDisposition::Untrusted,
                "{path}"
            );
        }
        // The distinction that matters, and the reason unboundedness is its own state rather than
        // a root of `/`: a real `/` root puts a relative pathname OUTSIDE, which would make the
        // compatibility wrapper refuse a manifest a pre-R3C build walks happily.
        let rooted = bounded(&["/"], &[("/", 1)], Vec::new());
        assert_eq!(rooted.scope(Path::new("relative/x")), DirScope::Outside);
        // A `..`-spelled ABSOLUTE path is in scope under `/` — components put it below the root —
        // but it has no key, so it can never be trusted. In scope and untrusted, not outside.
        assert!(matches!(
            rooted.scope(Path::new("/x/../x/y")),
            DirScope::Root(_)
        ));
        assert_eq!(
            rooted.disposition(Path::new("/x/../x/y")),
            DirDisposition::Untrusted
        );
    }

    /// A root-wide `walk_error` sentinel suppresses every directory of its root.
    #[test]
    fn a_root_sentinel_suppresses_the_whole_root() {
        let snapshot = bounded(
            &["/a", "/b"],
            &[("/a", 1), ("/b", 1)],
            vec![stored("/a", "/a", "walk_error", 1, 1)],
        );
        for dir in ["/a", "/a/deep", "/a/deep/deeper"] {
            assert_eq!(
                snapshot.disposition(Path::new(dir)),
                DirDisposition::Suppressed,
                "{dir}"
            );
        }
        assert_eq!(
            snapshot.disposition(Path::new("/b/x")),
            DirDisposition::Trusted
        );
    }

    /// The deep case, against the fixture's own accepted ancestor chain: every ancestor up to and
    /// including the root sees the omission, and the boundary is the root — the directory above it
    /// is outside the scan and gets no verdict from containment at all.
    #[test]
    fn the_deep_chain_stops_at_the_root() {
        let trees = crate::testfixtures::dir_completeness::DirTrees::build("chain");
        let omitted = trees.deep_dir.join("tiny.bin");
        let directory = PathKey::new(&trees.deep_dir).expect("keyable");
        let root = PathKey::new(&trees.root).expect("keyable root");

        let chain = trees.ancestors_up_to_root(&omitted);
        assert_eq!(chain.len(), 6, "d, c, b, a, deep, root: {chain:?}");
        for ancestor in &chain {
            let key = PathKey::new(ancestor).expect("keyable ancestor");
            assert!(
                directory.is_at_or_under(&key),
                "{} must see the omission",
                key.as_str()
            );
            assert!(
                key.is_at_or_under(&root),
                "{} must itself lie inside the scan root",
                key.as_str()
            );
        }

        // The directory above the root is where propagation stops: it is not inside the root, so
        // no root-keyed lookup can ever reach it.
        let above = PathKey::new(trees.base()).expect("keyable base");
        assert!(
            !above.is_at_or_under(&root),
            "the base must lie outside the scan root"
        );
        assert!(
            root.is_at_or_under(&above),
            "sanity: the base really is an ancestor of the root"
        );
    }

    /// A current root sentinel reaches every descendant's detailed verdict — exactly once, and
    /// alone. The compact classifier already suppressed the whole root; the R3C `verdict` still
    /// answered `Complete` below the root, and R3C-C1 pins both classifiers to one contract: the
    /// sentinel's `walk_error` count arrives in a descendant verdict once, the root's other,
    /// root-local reasons do not travel down with it, a local omission below the queried
    /// directory composes with the sentinel through the same checked aggregation, and the other
    /// root hears nothing.
    #[test]
    fn a_root_sentinel_reaches_every_descendant_verdict() {
        let snapshot = bounded(
            &["/a", "/b"],
            &[("/a", 1), ("/b", 1)],
            vec![
                // The sentinel: a walk error AT `/a` hides an unknown amount anywhere below.
                stored("/a", "/a", "walk_error", 3, 1),
                // A root-local reason on the same directory; it stays where it was stored.
                stored("/a", "/a", "min_size", 7, 1),
                // A local omission deep under one branch, to compose with the sentinel.
                stored("/a", "/a/x/y/z", "walk_error", 10, 1),
            ],
        );

        // The blocker itself, as one comparison: on the defective parent `/a/q` answered
        // `(Complete, Suppressed)` — trusted in detail, suppressed in compact form. The fixed
        // pair is incomplete by exactly the sentinel's own count.
        let mut sentinel_only = OmissionSummary::default();
        sentinel_only
            .add(OmissionReason::WalkError, EventCount::new(3).unwrap())
            .unwrap();
        assert_eq!(
            (
                snapshot.verdict(Path::new("/a/q")).unwrap(),
                snapshot.disposition(Path::new("/a/q")),
            ),
            (
                DirCompleteness::Incomplete(sentinel_only),
                DirDisposition::Suppressed,
            )
        );

        // Per-reason cells, so «exactly once» is a number rather than a mood.
        let cells = |path: &str| match snapshot.verdict(Path::new(path)).unwrap() {
            DirCompleteness::Incomplete(summary) => summary
                .per_reason()
                .map(|(reason, count)| (reason, count.get()))
                .collect::<Vec<_>>(),
            other => panic!("{path} expected incomplete, got {other:?}"),
        };
        // The root folds each stored cell once: 3 + 10 walk errors and 7 min_size — its own
        // sentinel must not be added a second time on top of the exact row.
        assert_eq!(
            cells("/a"),
            vec![
                (OmissionReason::MinSize, 7),
                (OmissionReason::WalkError, 13)
            ]
        );
        // A descendant above the local row: 3 root-wide + 10 at or under it — and no min_size,
        // which is the root's own business.
        assert_eq!(cells("/a/x/y"), vec![(OmissionReason::WalkError, 13)]);

        // The other root never hears about `/a`'s sentinel.
        assert_eq!(
            snapshot.verdict(Path::new("/b/keep")).unwrap(),
            DirCompleteness::Complete
        );

        // The one mapping agrees with the compact classifier for every asserted path.
        for dir in ["/a", "/a/q", "/a/x/y", "/a/x/y/z", "/b", "/b/keep"] {
            let path = Path::new(dir);
            assert_eq!(
                snapshot.verdict(path).unwrap().disposition(),
                snapshot.disposition(path),
                "{dir}"
            );
        }

        // The sentinel travels through the same checked aggregation as every other cell: two
        // `i64::MAX` rows under the queried child still fit a `u64`, the sentinel's own maximum
        // is the third cell that cannot, and that is an error — never a saturated figure. The
        // compact classifier needs no sum and still suppresses.
        let maxed = bounded(
            &["/a"],
            &[("/a", 1)],
            vec![
                stored("/a", "/a", "walk_error", i64::MAX, 1),
                stored("/a", "/a/q/one", "walk_error", i64::MAX, 1),
                stored("/a", "/a/q/two", "walk_error", i64::MAX, 1),
            ],
        );
        assert!(maxed.verdict(Path::new("/a/q")).is_err());
        assert_eq!(
            maxed.disposition(Path::new("/a/q")),
            DirDisposition::Suppressed
        );
    }

    /// `Bounded` is scope; authority is this separate predicate. Pre-ledger, drift, a zeroed root
    /// and MIXED generations all construct a bounded snapshot and must all answer false — only
    /// full agreement with every generation positive answers true.
    #[test]
    fn full_authority_requires_agreement_and_every_generation_positive() {
        fn check(roots: &[&str], gens: &[(&str, i64)], expect: bool, label: &str) {
            let snapshot = bounded(roots, gens, Vec::new());
            assert_eq!(snapshot.fully_authoritative(), expect, "{label}");
        }
        check(&["/a"], &[("/a", 1)], true, "one trusted root");
        check(
            &["/a", "/b"],
            &[("/a", 1), ("/b", 2)],
            true,
            "two trusted roots",
        );
        check(&["/a"], &[], false, "pre-ledger: no registration at all");
        check(&["/a"], &[("/other", 1)], false, "registration drift");
        check(&["/a"], &[("/a", 0)], false, "generation zero");
        check(
            &["/a", "/b"],
            &[("/a", 1), ("/b", 0)],
            false,
            "mixed authority: one positive root cannot vouch for the scan",
        );
    }

    /// Accounting is gated by the predicate, never inferred from empty totals: a committed empty
    /// ledger is a genuine exact zero, while a pre-ledger or partially cleared scan folding to
    /// the very same emptiness is `Unavailable`.
    #[test]
    fn exact_accounting_exists_only_under_full_authority() {
        let committed_empty = bounded(&["/a"], &[("/a", 1)], Vec::new());
        match committed_empty.scan_accounting().unwrap() {
            ScanAccounting::Exact(totals) => assert!(totals.is_empty(), "a genuine exact zero"),
            ScanAccounting::Unavailable => panic!("a committed empty ledger is exact"),
        }

        for (gens, label) in [
            (&[][..], "pre-ledger"),
            (&[("/a", 0)][..], "generation zero"),
        ] {
            let snapshot = bounded(&["/a"], gens, Vec::new());
            assert_eq!(
                snapshot.scan_accounting().unwrap(),
                ScanAccounting::Unavailable,
                "{label} folds to the same emptiness and must NOT read as an exact zero"
            );
        }
    }

    /// The totals fold each stored cell exactly once. The mutation this exists to catch is a
    /// fold written over per-directory verdicts: the root sentinel reaches every descendant
    /// there, so such a fold would multiply it — here it is one stored cell, once.
    #[test]
    fn scan_totals_fold_each_stored_cell_once() {
        let snapshot = bounded(
            &["/a", "/b"],
            &[("/a", 1), ("/b", 1)],
            vec![
                stored("/a", "/a", "walk_error", 3, 1),
                stored("/a", "/a/x/y/z", "walk_error", 10, 1),
                stored("/a", "/a/x", "min_size", 7, 1),
                stored("/b", "/b/q", "unsupported_entry", 2, 1),
            ],
        );
        match snapshot.scan_accounting().unwrap() {
            ScanAccounting::Exact(totals) => {
                assert_eq!(
                    totals.per_reason().collect::<Vec<_>>(),
                    vec![
                        (OmissionReason::MinSize, EventCount::new(7).unwrap()),
                        (OmissionReason::WalkError, EventCount::new(13).unwrap()),
                        (
                            OmissionReason::UnsupportedEntry,
                            EventCount::new(2).unwrap()
                        ),
                    ],
                    "3 + 10 walk errors, once each — never the sentinel times its descendants"
                );
            }
            ScanAccounting::Unavailable => panic!("fully authoritative by construction"),
        }
    }
}
