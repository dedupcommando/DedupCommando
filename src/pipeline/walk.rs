// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;

use crate::error::{AppError, Result};
use crate::model::omission::{
    AuthorityUnavailable, EventCount, OmissionCounts, OmissionReason, OmissionSummary, PathKey,
};
use crate::model::scan::ScanConfig;

/// A file discovered during the walk.
pub struct WalkedFile {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    /// The sub-second and ctime components of the identity (walk snapshot).
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub device: u64,
    pub inode: u64,
    /// `st_nlink` — how many pathnames the inode has in total, including any this scan never
    /// sees. Comes from the metadata already fetched below; costs no extra syscall.
    pub nlink: u64,
}

/// Everything one walk produced.
///
/// `Cancelled` deliberately has no omission snapshot: a walk that stopped early saw only part of
/// the tree, so there is no state in which a cancelled run can be published as a complete account
/// of what was left out. The absence of the field is the guarantee — not a flag beside it.
///
/// There is deliberately no separate non-UTF8 counter either: the count lives in the ledger map
/// or the observed tally like every other reason, so a third parallel tally cannot drift from
/// them. A cancelled walk reports no counts at all, which is the same rule.
pub enum WalkOutcome {
    Finished {
        files: Vec<WalkedFile>,
        omissions: OmissionSnapshot,
    },
    Cancelled {
        files: Vec<WalkedFile>,
    },
}

#[cfg(test)]
impl WalkOutcome {
    /// A short name for a panic message, so a failing test says what it got instead.
    fn kind(&self) -> &'static str {
        match self {
            Self::Finished {
                omissions: OmissionSnapshot::Publishable(_),
                ..
            } => "Finished(publishable)",
            Self::Finished { .. } => "Finished(unavailable)",
            Self::Cancelled { .. } => "Cancelled",
        }
    }
}

/// What the walk can say about completeness.
pub enum OmissionSnapshot {
    /// Exactly one entry per selected root — including a root that omitted nothing, whose entry is
    /// an empty map. That explicit empty entry is what `ScanStore::commit_omissions` requires as
    /// proof the root was walked under the contract at all.
    Publishable(BTreeMap<PathKey, OmissionCounts>),
    /// Not publishable, typed. Only the `Roots` variant is an expected state a consumer may
    /// degrade on; every other variant means the collector could not truthfully represent what
    /// the walk saw, and the scan must fail loudly rather than complete with the counters lost.
    Unavailable(SnapshotUnavailable),
}

/// Why a walk produced no publishable omission snapshot.
pub enum SnapshotUnavailable {
    /// A non-empty configured root set that cannot all be keyed, or whose keys overlap. An empty
    /// root set is not one of these — it is still the outer `no scan root specified` error.
    /// `observed` is everything the walk still saw and could not ledger: per-reason checked
    /// counts, no paths and no attribution, so a real omission survives as a warning even though
    /// no authority can be published for it.
    Roots {
        why: AuthorityUnavailable,
        observed: OmissionSummary,
    },
    /// Aggregating one cell would have wrapped `u64`.
    CountOverflow {
        root: PathKey,
        directory: PathKey,
        reason: OmissionReason,
    },
    /// A cell holds a real number that the checkpoint's signed `INTEGER` column cannot store.
    CountNotStorable {
        root: PathKey,
        directory: PathKey,
        reason: OmissionReason,
    },
    /// An event arrived for a root the collector was never seeded with. Today's wiring builds both
    /// from the same key slice, so nothing can produce it — but the alternative to naming it is
    /// dropping the event, and a snapshot that is short one omission while still calling itself
    /// publishable is a false claim of completeness. A wiring regression must surface here rather
    /// than as a directory that quietly looks whole.
    UnregisteredRoot {
        root: PathKey,
        directory: PathKey,
        reason: OmissionReason,
    },
    /// The global no-attribution tally overflowed `u64` while counting `reason`. There is no root
    /// or path to name — the configuration is precisely the one that cannot attribute — and
    /// inventing one would be a false claim. Note the narrower domain than the ledgered variants:
    /// the observed tally is never stored, so a value above `i64::MAX` is valid here and only a
    /// real `u64` aggregation overflow is the failure.
    ObservedOverflow { reason: OmissionReason },
}

/// The no-ledger tally: per-reason checked counts for a walk whose roots carry no completeness
/// authority. Mirrors `Collector`'s failure discipline — the first overflow is held, later events
/// are ignored only because `finish` is then structurally forced to report the failure, and the
/// previous count is never silently frozen as if it were the total.
#[derive(Default)]
struct ObservedTally {
    summary: OmissionSummary,
    failure: Option<OmissionReason>,
}

impl ObservedTally {
    fn record(&mut self, reason: OmissionReason) {
        if self.failure.is_some() {
            return;
        }
        if self.summary.add(reason, EventCount::ONE).is_err() {
            self.failure = Some(reason);
        }
    }

    /// The snapshot this walk can publish: the expected no-authority fallback carrying what was
    /// observed, or the loud overflow state.
    fn finish(self, why: AuthorityUnavailable) -> OmissionSnapshot {
        match self.failure {
            Some(reason) => {
                OmissionSnapshot::Unavailable(SnapshotUnavailable::ObservedOverflow { reason })
            }
            None => OmissionSnapshot::Unavailable(SnapshotUnavailable::Roots {
                why,
                observed: self.summary,
            }),
        }
    }
}

/// Accumulates one walk's omissions, one entry per selected root.
struct Collector {
    per_root: BTreeMap<PathKey, OmissionCounts>,
    /// The first aggregation failure. Kept rather than returned: a count that cannot be added is a
    /// reason the SNAPSHOT is unavailable, never a reason to stop walking files.
    failure: Option<SnapshotUnavailable>,
}

impl Collector {
    fn new(roots: &[PathKey]) -> Self {
        Self {
            per_root: roots
                .iter()
                .map(|root| (root.clone(), OmissionCounts::new()))
                .collect(),
            failure: None,
        }
    }

    /// Records one event.
    ///
    /// Every way this can fail is a reason the SNAPSHOT is unavailable, never a reason to drop the
    /// event or to stop walking files. Returning early once a failure is held is safe only because
    /// `finish` is then structurally forced to return `Unavailable`: there is no path back to
    /// `Publishable` for a collector that has recorded a failure.
    fn record(&mut self, root: &PathKey, directory: PathKey, reason: OmissionReason) {
        if self.failure.is_some() {
            return;
        }
        let Some(counts) = self.per_root.get_mut(root) else {
            self.failure = Some(SnapshotUnavailable::UnregisteredRoot {
                root: root.clone(),
                directory,
                reason,
            });
            return;
        };
        if counts.bump(directory.clone(), reason).is_err() {
            self.failure = Some(SnapshotUnavailable::CountOverflow {
                root: root.clone(),
                directory,
                reason,
            });
        }
    }

    /// Validates the storage domain before promising anything is publishable. `EventCount` accepts
    /// the whole `u64` range while the checkpoint column is a signed `INTEGER`, so a cell can be a
    /// perfectly real number the store still cannot write — and finding that out inside the
    /// store's transaction would be finding out too late.
    fn finish(self) -> OmissionSnapshot {
        if let Some(why) = self.failure {
            return OmissionSnapshot::Unavailable(why);
        }
        for (root, counts) in &self.per_root {
            for (directory, reason, count) in counts.iter() {
                if count.to_i64().is_err() {
                    return OmissionSnapshot::Unavailable(SnapshotUnavailable::CountNotStorable {
                        root: root.clone(),
                        directory: directory.clone(),
                        reason,
                    });
                }
            }
        }
        OmissionSnapshot::Publishable(self.per_root)
    }
}

/// One root's ledger while its tree is being walked.
struct Ledger<'a> {
    root: PathKey,
    collector: &'a mut Collector,
}

/// Where one walk's omission events are counted: a per-root ledger, or the global observed tally
/// of a walk whose roots carry no authority. One of the two always exists, so an event can be
/// unattributable but never uncounted.
enum Account<'a> {
    Ledger(Ledger<'a>),
    Observed(&'a mut ObservedTally),
}

/// Where one iteration's results go.
struct Sink<'a> {
    files: &'a mut Vec<WalkedFile>,
    dirs: &'a mut super::roots::DirAliasGuard,
    account: Account<'a>,
}

impl Sink<'_> {
    /// An omission whose entry is known: attribute it to the entry's parent, inside the root —
    /// or count it without attribution when there is no root to attribute to.
    fn record_child(&mut self, path: &Path, reason: OmissionReason) {
        match &mut self.account {
            Account::Ledger(ledger) => {
                let directory = attribute_child(path, &ledger.root);
                ledger.collector.record(&ledger.root, directory, reason);
            }
            Account::Observed(tally) => tally.record(reason),
        }
    }

    /// An iterator error: exactly one event, at one cell.
    fn record_error(&mut self, err: &ignore::Error) {
        match &mut self.account {
            Account::Ledger(ledger) => {
                let cell = error_cell(err, &ledger.root);
                ledger
                    .collector
                    .record(&ledger.root, cell, OmissionReason::WalkError);
            }
            Account::Observed(tally) => tally.record(OmissionReason::WalkError),
        }
    }
}

/// The directory a known entry's omission belongs to: its parent, or the nearest keyable ancestor
/// above that, never leaving the selected root.
///
/// Falls back to the root itself, which is what a selected root that is a regular file needs — its
/// only entry's parent lies outside the root, and the schema's `dir_key = root_key` is a legal
/// location. Total: the ancestor chain terminates, and the fallback always exists.
fn attribute_child(path: &Path, root: &PathKey) -> PathKey {
    let mut current = path.parent();
    while let Some(candidate) = current {
        if let Some(key) = PathKey::new(candidate) {
            if key.is_at_or_under(root) {
                return key;
            }
        }
        current = candidate.parent();
    }
    root.clone()
}

/// The location an error path names, starting at the path ITSELF.
///
/// An iterator error is raised before the entry's type is known, so its path may name a file, a
/// directory, a symlink or the selected root. Climbing from the parent — right for a known regular
/// file — would step outside the root the moment the path IS the root, which is exactly what an
/// unresolvable root produces.
fn attribute_error_path(path: &Path, root: &PathKey) -> Option<PathKey> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if let Some(key) = PathKey::new(candidate) {
            if key.is_at_or_under(root) {
                return Some(key);
            }
        }
        current = candidate.parent();
    }
    None
}

/// Every pathname an `ignore::Error` structurally carries, without going through `Display`.
///
/// Exhaustive on `ignore 0.4.25`, so a new variant is a compile error rather than a silently
/// ignored path.
fn error_paths(err: &ignore::Error, out: &mut Vec<PathBuf>) {
    match err {
        ignore::Error::Partial(list) => {
            for inner in list {
                error_paths(inner, out);
            }
        }
        ignore::Error::WithPath { path, err } => {
            out.push(path.clone());
            error_paths(err, out);
        }
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            error_paths(err, out)
        }
        ignore::Error::Loop { ancestor, child } => {
            out.push(ancestor.clone());
            out.push(child.clone());
        }
        ignore::Error::Io(_)
        | ignore::Error::Glob { .. }
        | ignore::Error::UnrecognizedFileType(_)
        | ignore::Error::InvalidDefinition => {}
    }
}

/// The single cell one yielded `Err` becomes.
///
/// One error is one event, so it may not be written to more than one cell — a reader sums rows,
/// and two rows for one failure would report two failures. With several candidate locations the
/// choice is the one that lies at-or-under every other, because the ledger propagates a row
/// UPWARD: such a row marks each of the others on its way to the root. Where no candidate covers
/// the rest, and where none is in-root at all, the answer is the root's own `walk_error` sentinel,
/// which taints the whole root — deliberately coarse, and truthful about the count.
fn error_cell(err: &ignore::Error, root: &PathKey) -> PathKey {
    let mut paths = Vec::new();
    error_paths(err, &mut paths);

    let mut locations: Vec<PathKey> = Vec::new();
    for path in &paths {
        if let Some(key) = attribute_error_path(path, root) {
            if !locations.contains(&key) {
                locations.push(key);
            }
        }
    }
    match locations.len() {
        0 => root.clone(),
        1 => locations.swap_remove(0),
        _ => locations
            .iter()
            .find(|candidate| {
                locations
                    .iter()
                    .all(|other| candidate.is_at_or_under(other))
            })
            .cloned()
            .unwrap_or_else(|| root.clone()),
    }
}

/// The scan's roots as keys, or the typed reason there is no authority to be had. The root list is
/// known non-empty here: an empty one is the caller's outer error, not an unavailable snapshot.
fn root_keys(roots: &[PathBuf]) -> std::result::Result<Vec<PathKey>, AuthorityUnavailable> {
    let mut keys: Vec<PathKey> = Vec::with_capacity(roots.len());
    for root in roots {
        match PathKey::new(root) {
            Some(key) => keys.push(key),
            None => {
                return Err(AuthorityUnavailable::UnkeyableRoot {
                    given: root.display().to_string(),
                })
            }
        }
    }
    // Root validation compares canonicalized paths and skips the comparison when either path
    // cannot be resolved, so two overlapping roots that do not exist yet arrive here undetected.
    // A directory under both of them could not be attributed to one, so neither gets an authority.
    for (index, outer) in keys.iter().enumerate() {
        for inner in keys.iter().skip(index + 1) {
            if inner.is_at_or_under(outer) || outer.is_at_or_under(inner) {
                let (outer, inner) = if inner.is_at_or_under(outer) {
                    (outer, inner)
                } else {
                    (inner, outer)
                };
                return Err(AuthorityUnavailable::AmbiguousRoots {
                    outer: outer.as_str().to_string(),
                    inner: inner.as_str().to_string(),
                });
            }
        }
    }
    Ok(keys)
}

/// The order two sibling names are yielded in: raw bytes, ascending.
///
/// Bytes because that is the only total order a Linux filename has. Anything routed through
/// `to_string_lossy` maps distinct byte names onto one `U+FFFD` string and then calls them equal,
/// which hands their relative order straight back to `readdir` — the same collapse
/// `walk_collecting` refuses to let near the manifest.
///
/// A free function rather than a closure so the order can be tested for what it is — a decision
/// about bytes — without a filesystem, a fixture or a `readdir` anywhere in the test.
fn by_name_bytes(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> std::cmp::Ordering {
    use std::os::unix::ffi::OsStrExt;
    a.as_bytes().cmp(b.as_bytes())
}

/// The shared builder settings. `standard_filters(false)` also turns off parent-ignore reading, so
/// a per-root builder and the multi-root one behave identically apart from which paths they cover.
///
/// `sort_by_file_name` is what makes traversal order a property of this program instead of a
/// property of the disk it is pointed at: within every directory, at every depth, siblings are
/// yielded in byte order of their names. Without it the order is whatever `readdir` returns, which
/// differs between filesystems — the same fixture that lists as expected under one `/tmp` lists
/// shuffled under another. What gets persisted is keyed by path and so came out the same either
/// way; what varied is the sequence the walk hands to its caller, and every reading of it that
/// treats a sequence as one.
/// Roots are NOT sorted: `ignore` drains the paths it was handed in the order they were added,
/// which is the order the scan was configured with, and `walk_collecting` zips that order against
/// the root keys.
///
/// The comparison itself is `by_name_bytes`, and dropping this line would leave that function with
/// no caller outside the test module — a `dead_code` warning in the ordinary build, which this
/// project gates on.
///
/// This is a mechanism of the SERIAL walker alone. `ignore` keeps no sorter on `WalkParallel`, so
/// setting one and then calling `build_parallel()` compiles and silently does nothing; a parallel
/// walk would have to re-establish the order itself, by a deterministic merge of the per-directory
/// results.
///
/// The traversal-order tests are the tripwire for that on the ledgered branch, which builds one
/// walker per root — and only there. The branch for roots that cannot be keyed builds a single
/// multi-root walker, and its one test holds a single file, so switching THAT walker to
/// `build_parallel()` would drop the sorter without failing anything. Both branches go through
/// this function, so the mechanism is shared; the coverage is not.
fn configure(
    builder: &mut WalkBuilder,
    config: &ScanConfig,
    overrides: &ignore::overrides::Override,
) {
    builder
        .standard_filters(false)
        .hidden(false)
        .follow_links(config.follow_symlinks)
        .sort_by_file_name(by_name_bytes)
        .overrides(overrides.clone());
}

/// Handles one item from a walk iterator.
///
/// A yielded `Err` does NOT abort anything: it is recorded as one `walk_error` event and this
/// returns `Ok(())`, because a file the walk could not reach is an omission like any other. The
/// two cases that do return `Err` are the ones that are not omissions at all — a directory whose
/// physical identity cannot be read, and a `DirAliasGuard` refusal. Both mean the walk can no
/// longer tell one tree from two, which is not a result worth publishing at any size.
fn absorb(
    result: std::result::Result<ignore::DirEntry, ignore::Error>,
    config: &ScanConfig,
    sink: &mut Sink<'_>,
) -> Result<()> {
    let entry = match result {
        // Test-only: reach the outcome of the `Err` arm below for a nominated path, without a
        // filesystem that has to misbehave. Absent from every non-test build. Built as the error
        // `ignore` itself would produce, so the injected case goes through the real reduction.
        #[cfg(test)]
        Ok(ref entry) if crate::testfixtures::take_walk_fault(entry.path()) => {
            let injected = ignore::Error::WithPath {
                path: entry.path().to_path_buf(),
                err: Box::new(ignore::Error::Io(std::io::Error::other(
                    "injected walk fault",
                ))),
            };
            sink.record_error(&injected);
            return Ok(());
        }
        Ok(entry) => entry,
        Err(err) => {
            // No access, a broken link, a symlink loop: no file is named, and the entry type is
            // unknown. One error, one event.
            sink.record_error(&err);
            return Ok(());
        }
    };

    // Test-only stand-in for the entry types that cannot be created without privileges — a block
    // or character device node. It diverts a real entry into the unsupported arm, so what it
    // exercises is the recording path for a nominated entry, not a synthetic `FileType`. The real
    // symlink, FIFO, socket and `/dev/null` cases are the primary evidence.
    #[cfg(test)]
    if take_special_entry_fault(entry.path()) {
        sink.record_child(entry.path(), OmissionReason::UnsupportedEntry);
        return Ok(());
    }

    match entry.file_type() {
        Some(file_type) if file_type.is_file() => {}
        // A directory: the only place an alias inside a root can be caught. Its metadata is the
        // one extra `stat` this guard costs, and only for directories.
        //
        // A failure here is fatal. It costs no file — the walker could still descend — but it
        // is the guard losing its evidence: without `(device, inode)` this directory is no
        // longer known NOT to be a second pathname for a tree already walked, and a manifest
        // holding one file under two pathnames is not a result worth publishing. The scan
        // stops for the same reason `DirAliasGuard::note` stops it.
        Some(file_type) if file_type.is_dir() => {
            // Test-only: reach the failure outcome below for a nominated directory, without a
            // filesystem that has to misbehave. Absent from every non-test build.
            #[cfg(test)]
            if crate::testfixtures::take_metadata_fault(entry.path()) {
                return Err(unverifiable_directory(entry.path(), None));
            }
            let meta = entry
                .metadata()
                .map_err(|err| unverifiable_directory(entry.path(), Some(&err)))?;
            sink.dirs.note(entry.path(), meta.dev(), meta.ino())?;
            return Ok(());
        }
        // Neither a regular file nor a directory: a symlink this scan does not follow, a FIFO, a
        // socket, a device — or, when links are followed, a link resolving to one of those. The
        // manifest has no way to hold it and the signature has no way to see it, so a directory
        // containing one is not an exact twin of a directory that does not. Nothing failed and
        // nothing was filtered by configuration, which is why it is its own reason rather than a
        // walk error or an extension filter.
        _ => {
            sink.record_child(entry.path(), OmissionReason::UnsupportedEntry);
            return Ok(());
        }
    }
    let meta = match entry.metadata() {
        // Test-only counterpart for the metadata error below, same reasoning.
        #[cfg(test)]
        Ok(_) if crate::testfixtures::take_metadata_fault(entry.path()) => {
            sink.record_child(entry.path(), OmissionReason::MetadataError);
            return Ok(());
        }
        Ok(meta) => meta,
        Err(_) => {
            // The entry was already typed as a regular file, so this is exactly one file.
            sink.record_child(entry.path(), OmissionReason::MetadataError);
            return Ok(());
        }
    };

    let size = meta.size();
    if size < config.min_size {
        sink.record_child(entry.path(), OmissionReason::MinSize);
        return Ok(());
    }
    if let Some(max) = config.max_size {
        if size > max {
            sink.record_child(entry.path(), OmissionReason::MaxSize);
            return Ok(());
        }
    }

    if !config.include_extensions.is_empty() {
        let ext = entry
            .path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase());
        match ext {
            Some(ext) if config.include_extensions.contains(&ext) => {}
            _ => {
                sink.record_child(entry.path(), OmissionReason::ExtensionFiltered);
                return Ok(());
            }
        }
    }

    // Non-UTF8 guard: skip files whose path cannot be represented
    // as UTF-8 (see the function doc comment). Count it last — after all the
    // other filters, so the event means "would have made it into the manifest, but the name cannot
    // be saved without loss", not files filtered out by size/extension.
    if entry.path().to_str().is_none() {
        sink.record_child(entry.path(), OmissionReason::NonUtf8);
        return Ok(());
    }

    sink.files.push(WalkedFile {
        path: entry.into_path(),
        size,
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        ctime_sec: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
        device: meta.dev(),
        inode: meta.ino(),
        nlink: meta.nlink(),
    });
    Ok(())
}

/// Walks all roots from `config` and returns the matching files, the non-UTF8 compatibility count,
/// and — when the roots can carry one — an account of everything the walk left out.
///
/// **The order of the returned files is a guarantee, not an accident.** Roots are reported in the
/// order they were configured, and within each root the tree is walked depth-first with every
/// directory's entries taken in byte order of their names, so one tree yields the same file
/// sequence on any machine.
///
/// The guarantee covers the files this returns and nothing else. Entries the walk could not read
/// are not files it returns: `ignore` hands errors over before the sorted entries and treats two
/// of them as equal, so the order of several errors inside one directory is still whatever
/// `readdir` gave. That costs no determinism where it matters — an error is counted into a
/// `BTreeMap` cell, never appended to a sequence — but the sequence of error EVENTS is not
/// something to build on. See `configure` for the mechanism.
///
/// Each keyable root is walked by its own `WalkBuilder`, in configured order. `ignore::Walk`
/// already drains its paths one after another, so this changes no traversal order; what it changes
/// is that the active root becomes a fact rather than something an error has to be guessed into.
/// The entries counter, the files vector, the cancellation state and — most importantly — the one
/// `DirAliasGuard` are shared across every root, because a tree reachable twice THROUGH TWO ROOTS
/// is exactly what that guard exists to catch.
///
/// The `.zfs` and quarantine directories are excluded. Aborts on `cancel`.
/// `on_progress` periodically receives (entries scanned, files found).
///
/// **Non-UTF8 guard:** a path that cannot be represented as
/// UTF-8 is skipped. Otherwise `to_string_lossy` would collapse different byte names
/// (`a\xFFb`, `a\xFEb`) into a single `a�b` → silent loss/corruption of the string in the PK
/// `(scan_id, path)`; and a `�`-path read back would miss the
/// real file on the action path. It is safer not to touch such a file at all.
pub fn walk_collecting(
    config: &ScanConfig,
    cancel: &AtomicBool,
    mut on_progress: impl FnMut(u64, u64, Option<&Path>),
) -> Result<WalkOutcome> {
    if config.roots.is_empty() {
        return Err(AppError::msg("no scan root specified"));
    }

    // Exclusions via Override: a glob with a "!" prefix means "ignore". Built once and cloned into
    // every builder, so per-root traversal cannot change what an exclusion matches.
    let mut overrides = OverrideBuilder::new("/");
    for glob in &config.exclude_globs {
        overrides
            .add(&format!("!{glob}"))
            .map_err(|err| AppError::msg(format!("invalid glob '{glob}': {err}")))?;
    }
    let overrides = overrides
        .build()
        .map_err(|err| AppError::msg(format!("error building exclusions: {err}")))?;

    let mut files: Vec<WalkedFile> = Vec::new();
    let mut entries: u64 = 0;
    // Directories seen so far, by physical identity. An alias inside a selected root (a bind mount,
    // or a directory symlink while following links) is only visible here, and it aborts the scan —
    // see `roots::DirAliasGuard`. Bounded by the number of directories, which is small next to the
    // file vector this walk already holds.
    let mut dirs = super::roots::DirAliasGuard::default();
    let mut cancelled = false;

    let snapshot = match root_keys(&config.roots) {
        // No authority to be had. The scan still walks exactly as it always did — this is a verdict
        // about completeness, not a gate on scanning — so the original multi-root builder is used
        // and no partial ledger is recorded. Every event is still counted, without attribution,
        // so a real omission cannot vanish just because the roots cannot be keyed.
        Err(why) => {
            let mut tally = ObservedTally::default();
            let mut builder = WalkBuilder::new(&config.roots[0]);
            for root in &config.roots[1..] {
                builder.add(root);
            }
            configure(&mut builder, config, &overrides);
            let mut sink = Sink {
                files: &mut files,
                dirs: &mut dirs,
                account: Account::Observed(&mut tally),
            };
            // Test-only: the same iterator-error seam the ledgered branch has, so the observed
            // tally's walk-error counting is provable without a filesystem that misbehaves.
            #[cfg(test)]
            for root in &config.roots {
                if let Some(injected) = take_iterator_error_fault(root) {
                    sink.record_error(&injected);
                }
            }
            for result in builder.build() {
                if entries % 1024 == 0 {
                    if cancel.load(Ordering::Relaxed) {
                        cancelled = true;
                        break;
                    }
                    on_progress(
                        entries,
                        sink.files.len() as u64,
                        sink.files.last().map(|file| file.path.as_path()),
                    );
                }
                entries += 1;
                absorb(result, config, &mut sink)?;
            }
            tally.finish(why)
        }
        Ok(keys) => {
            let mut collector = Collector::new(&keys);
            'roots: for (root_path, root_key) in config.roots.iter().zip(keys.iter()) {
                let mut builder = WalkBuilder::new(root_path);
                configure(&mut builder, config, &overrides);
                let mut sink = Sink {
                    files: &mut files,
                    dirs: &mut dirs,
                    account: Account::Ledger(Ledger {
                        root: root_key.clone(),
                        collector: &mut collector,
                    }),
                };
                // Test-only: an iterator error this root's filesystem has no way to produce —
                // pathless, or nested inside `Partial`. Fires once, and only for this root.
                #[cfg(test)]
                if let Some(injected) = take_iterator_error_fault(root_path) {
                    sink.record_error(&injected);
                }
                for result in builder.build() {
                    if entries % 1024 == 0 {
                        if cancel.load(Ordering::Relaxed) {
                            cancelled = true;
                            break 'roots;
                        }
                        on_progress(
                            entries,
                            sink.files.len() as u64,
                            sink.files.last().map(|file| file.path.as_path()),
                        );
                    }
                    entries += 1;
                    absorb(result, config, &mut sink)?;
                }
            }
            collector.finish()
        }
    };

    on_progress(
        entries,
        files.len() as u64,
        files.last().map(|file| file.path.as_path()),
    );
    if cancelled {
        // A partial walk saw part of the tree, so whatever was accumulated is not an account of
        // what the scan left out. It is dropped here rather than carried: `Cancelled` has no field
        // to put it in, which is what makes publishing it impossible rather than merely wrong.
        drop(snapshot);
        return Ok(WalkOutcome::Cancelled { files });
    }
    Ok(WalkOutcome::Finished {
        files,
        omissions: snapshot,
    })
}

// Test-only seams for the two states no fixture can create deterministically: an iterator error
// this filesystem has no way to produce (pathless, or nested inside `Partial`), and an entry type
// that cannot be made without privileges. Both are thread-local — the walk iterates on the
// caller's thread, so a fault cannot leak into a parallel test and nothing has to be serialized —
// each fires at most once, and both fired and pending are observable, so a test can prove the
// fault was consumed rather than merely that something went missing. Absent from every non-test
// build.
#[cfg(test)]
thread_local! {
    static ITERATOR_ERROR_FAULTS: std::cell::RefCell<Vec<(PathBuf, ignore::Error)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static FIRED_ITERATOR_ERRORS: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static SPECIAL_ENTRY_FAULTS: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static FIRED_SPECIAL_ENTRIES: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Arms an iterator error for a nominated ROOT, disarming on drop. Keyed by root because the state
/// worth testing is precisely an error with no path of its own.
#[cfg(test)]
struct IteratorErrorFaults;

#[cfg(test)]
impl IteratorErrorFaults {
    fn arm(faults: Vec<(PathBuf, ignore::Error)>) -> Self {
        ITERATOR_ERROR_FAULTS.with(|armed| *armed.borrow_mut() = faults);
        FIRED_ITERATOR_ERRORS.with(|fired| fired.borrow_mut().clear());
        IteratorErrorFaults
    }

    fn pending(&self) -> usize {
        ITERATOR_ERROR_FAULTS.with(|armed| armed.borrow().len())
    }

    fn fired(&self) -> Vec<PathBuf> {
        FIRED_ITERATOR_ERRORS.with(|fired| fired.borrow().clone())
    }
}

#[cfg(test)]
impl Drop for IteratorErrorFaults {
    fn drop(&mut self) {
        ITERATOR_ERROR_FAULTS.with(|armed| armed.borrow_mut().clear());
        FIRED_ITERATOR_ERRORS.with(|fired| fired.borrow_mut().clear());
    }
}

#[cfg(test)]
fn take_iterator_error_fault(root: &Path) -> Option<ignore::Error> {
    let taken = ITERATOR_ERROR_FAULTS.with(|armed| {
        let mut armed = armed.borrow_mut();
        let found = armed.iter().position(|(path, _)| path == root);
        found.map(|index| armed.remove(index))
    });
    taken.map(|(path, err)| {
        FIRED_ITERATOR_ERRORS.with(|fired| fired.borrow_mut().push(path));
        err
    })
}

/// Arms a path to be classified as an unsupported entry, disarming on drop. It stands in for a
/// block or character device node, which cannot be created without privileges.
#[cfg(test)]
struct SpecialEntryFaults;

#[cfg(test)]
impl SpecialEntryFaults {
    fn arm(paths: &[PathBuf]) -> Self {
        SPECIAL_ENTRY_FAULTS.with(|armed| *armed.borrow_mut() = paths.to_vec());
        FIRED_SPECIAL_ENTRIES.with(|fired| fired.borrow_mut().clear());
        SpecialEntryFaults
    }

    fn pending(&self) -> usize {
        SPECIAL_ENTRY_FAULTS.with(|armed| armed.borrow().len())
    }

    fn fired(&self) -> Vec<PathBuf> {
        FIRED_SPECIAL_ENTRIES.with(|fired| fired.borrow().clone())
    }
}

#[cfg(test)]
impl Drop for SpecialEntryFaults {
    fn drop(&mut self) {
        SPECIAL_ENTRY_FAULTS.with(|armed| armed.borrow_mut().clear());
        FIRED_SPECIAL_ENTRIES.with(|fired| fired.borrow_mut().clear());
    }
}

#[cfg(test)]
fn take_special_entry_fault(path: &Path) -> bool {
    let taken = SPECIAL_ENTRY_FAULTS.with(|armed| {
        let mut armed = armed.borrow_mut();
        let found = armed.iter().position(|armed_path| armed_path == path);
        found.map(|index| armed.remove(index))
    });
    match taken {
        Some(path) => {
            FIRED_SPECIAL_ENTRIES.with(|fired| fired.borrow_mut().push(path));
            true
        }
        None => false,
    }
}

/// A directory whose physical identity could not be read.
///
/// Names the directory and says what was lost, carrying the underlying error as context rather
/// than inspecting or re-parsing its text. Deliberately not an omission: no file went missing, and
/// calling it one would put a count on something that never happened.
fn unverifiable_directory(path: &Path, cause: Option<&ignore::Error>) -> AppError {
    let context = match cause {
        Some(err) => format!(" ({err})"),
        None => String::new(),
    };
    AppError::msg(format!(
        "scan aborted: cannot read the physical identity of directory {}{context} — without its \
         device and inode the same-directory guard cannot tell whether this tree has already been \
         walked under another pathname, and one tree counted twice is not a result worth \
         publishing. Fix access to the directory or exclude it, then rescan.",
        crate::textsan::terminal(&path.display().to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::omission::EventCount;
    use crate::testfixtures::{WalkFault, WalkFaults};
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    // -----------------------------------------------------------------------------------------
    // Collection helpers.
    // -----------------------------------------------------------------------------------------

    fn key(path: &Path) -> PathKey {
        PathKey::new(path).expect("a keyable path")
    }

    fn collect(config: &ScanConfig) -> WalkOutcome {
        let cancel = AtomicBool::new(false);
        walk_collecting(config, &cancel, |_, _, _| {}).expect("the walk must not abort")
    }

    /// The publishable per-root map, or a panic naming what came back instead.
    fn publishable(outcome: &WalkOutcome) -> &BTreeMap<PathKey, OmissionCounts> {
        match outcome {
            WalkOutcome::Finished {
                omissions: OmissionSnapshot::Publishable(map),
                ..
            } => map,
            WalkOutcome::Finished { .. } => panic!("the snapshot is unavailable"),
            WalkOutcome::Cancelled { .. } => panic!("the walk was cancelled"),
        }
    }

    /// The finished manifest, or a panic naming what came back instead.
    fn finished(outcome: &WalkOutcome) -> &Vec<WalkedFile> {
        match outcome {
            WalkOutcome::Finished { files, .. } => files,
            WalkOutcome::Cancelled { .. } => panic!("the walk was cancelled"),
        }
    }

    /// One root's cells as `(directory relative to the root, reason, count)`, sorted.
    fn cells(outcome: &WalkOutcome, root: &Path) -> Vec<(String, OmissionReason, u64)> {
        let map = publishable(outcome);
        let root_key = key(root);
        let counts = map
            .get(&root_key)
            .unwrap_or_else(|| panic!("no entry for root {}", root_key.as_str()));
        let mut out: Vec<(String, OmissionReason, u64)> = counts
            .iter()
            .map(|(directory, reason, count)| {
                let relative = directory
                    .as_str()
                    .strip_prefix(root_key.as_str())
                    .map(|rest| rest.trim_start_matches('/').to_string())
                    .unwrap_or_else(|| directory.as_str().to_string());
                (relative, reason, count.get())
            })
            .collect();
        out.sort();
        out
    }

    /// A whole root's events folded into one summary — what a reader aggregating rows would see.
    fn summary(outcome: &WalkOutcome, root: &Path) -> crate::model::omission::OmissionSummary {
        let mut summary = crate::model::omission::OmissionSummary::default();
        for (_, reason, count) in cells(outcome, root) {
            summary
                .add(reason, EventCount::new(count).unwrap())
                .unwrap();
        }
        summary
    }

    fn base_config(root: &Path) -> ScanConfig {
        let mut config = ScanConfig::new(vec![root.to_path_buf()]);
        config.min_size = 0;
        config.exclude_globs.clear();
        config
    }

    fn make_fifo(path: &Path) {
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // 0o644: a plain FIFO. Not opened, so nothing can block on it.
        let rc = unsafe { libc::mkfifo(name.as_ptr(), 0o644) };
        assert_eq!(rc, 0, "mkfifo failed for {}", path.display());
    }

    fn make_socket(path: &Path) -> std::os::unix::net::UnixListener {
        std::os::unix::net::UnixListener::bind(path).expect("bind a unix socket")
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_walk_{tag}_{}_{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The walk-time half of the root guard: a directory symlink pointing at a sibling directory
    /// makes one tree visible under two pathnames as soon as links are followed. No privileges
    /// needed, so the bind-mount E2E is not the only coverage of this branch.
    #[test]
    fn a_followed_directory_alias_aborts_the_walk() {
        let root = temp_dir("dir_alias");
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("f.bin"), b"data").unwrap();
        std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();

        let mut config = ScanConfig::new(vec![root.clone()]);
        config.min_size = 0;
        config.exclude_globs.clear();
        config.follow_symlinks = true;

        let cancel = AtomicBool::new(false);
        // Not `expect_err`: that needs `Debug` on the success type, and `WalkOutcome` has none.
        let text = match walk_collecting(&config, &cancel, |_, _, _| {}) {
            Err(err) => err.to_string(),
            Ok(outcome) => panic!("the alias must abort the walk, got {}", outcome.kind()),
        };
        assert!(
            text.contains("same directory"),
            "the class must be named: {text}"
        );
        assert!(
            text.contains("alias") && text.contains("real"),
            "both pathnames must be named: {text}"
        );

        // Control: without following links the symlink is not a directory, and the same tree walks
        // exactly as it did before this guard existed — the link itself is an unsupported entry.
        config.follow_symlinks = false;
        let outcome = collect(&config);
        assert_eq!(finished(&outcome).len(), 1, "exactly the one real file");
        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::UnsupportedEntry, 1)]
        );

        fs::remove_dir_all(&root).ok();
    }

    /// A directory holding one child, plus a file beside it. `sub` is the directory whose metadata
    /// the fault removes; `sub/inner.bin` is what shows whether the walk descended into it anyway.
    fn guard_tree(tag: &str) -> (PathBuf, PathBuf) {
        let root = temp_dir(tag);
        fs::write(root.join("keep.bin"), b"beside").unwrap();
        let sub = root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("inner.bin"), b"inside").unwrap();
        (root, sub)
    }

    fn guard_config(root: &Path) -> ScanConfig {
        let mut config = ScanConfig::new(vec![root.to_path_buf()]);
        config.min_size = 0; // don't filter the small fixtures out by size
        config.exclude_globs.clear(); // no default exclusions — determinism
        config
    }

    /// Manifest pathnames relative to `root`, in the order the walk produced them.
    fn walked_names(files: &[WalkedFile], root: &Path) -> Vec<String> {
        files
            .iter()
            .map(|file| {
                file.path
                    .strip_prefix(root)
                    .expect("under the root")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// A directory whose physical identity cannot be read stops the scan.
    ///
    /// It costs no file — the walker could descend perfectly well — but `DirAliasGuard` has lost
    /// the one piece of evidence that tells a real directory from a second pathname for a tree
    /// already walked. Before this, the failure was swallowed by `if let Ok(meta)` and the walk
    /// carried on into the child with a blind guard.
    #[test]
    fn a_directory_whose_metadata_fails_aborts_the_walk() {
        let (root, sub) = guard_tree("dirmeta");
        let faults = WalkFaults::arm(&[(sub.clone(), WalkFault::Metadata)]);
        let cancel = AtomicBool::new(false);

        let text = match walk_collecting(&guard_config(&root), &cancel, |_, _, _| {}) {
            Err(err) => err.to_string(),
            Ok(outcome) => panic!(
                "a directory whose identity cannot be read must abort the walk, got {}",
                outcome.kind()
            ),
        };

        assert_eq!(
            faults.fired(),
            vec![(sub.clone(), WalkFault::Metadata)],
            "the fault must fire exactly once, at the directory branch"
        );
        assert!(
            faults.pending().is_empty(),
            "nothing may stay armed: an unfired fault would mean the branch never looked"
        );
        assert!(
            text.contains(&sub.display().to_string()),
            "the directory must be named: {text}"
        );
        assert!(
            text.contains("physical identity"),
            "and what was lost must be plain: {text}"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// Positive control: the identical tree with nothing armed walks exactly as before — same
    /// manifest, same order. Without this the test above could be passing because the tree itself
    /// is unwalkable.
    #[test]
    fn without_injection_the_same_tree_walks_unchanged() {
        let (root, _) = guard_tree("dirmeta_control");

        let outcome = collect(&guard_config(&root));
        assert_eq!(
            walked_names(finished(&outcome), &root),
            vec!["keep.bin".to_string(), "sub/inner.bin".to_string()],
            "both files, in traversal order"
        );
        assert_eq!(cells(&outcome, &root), Vec::new(), "and nothing omitted");

        fs::remove_dir_all(&root).ok();
    }

    /// The regular-file branch is untouched: an injected metadata fault on a known regular file
    /// still fires once and still only removes that file. Turning THAT into an abort is R3B-B's
    /// business — it becomes a typed `metadata_error` event, not a stopped scan.
    #[test]
    fn a_regular_file_metadata_fault_still_only_skips_that_file() {
        let (root, sub) = guard_tree("filemeta");
        let victim = sub.join("inner.bin");
        let faults = WalkFaults::arm(&[(victim.clone(), WalkFault::Metadata)]);

        let outcome = collect(&guard_config(&root));

        assert_eq!(
            faults.fired(),
            vec![(victim, WalkFault::Metadata)],
            "the fault fired once, at the file branch"
        );
        assert!(faults.pending().is_empty());
        assert_eq!(
            walked_names(finished(&outcome), &root),
            vec!["keep.bin".to_string()],
            "only the nominated file is gone"
        );
        assert_eq!(
            cells(&outcome, &root),
            vec![("sub".to_string(), OmissionReason::MetadataError, 1)],
            "and it is accounted, in the directory that holds it"
        );

        fs::remove_dir_all(&root).ok();
    }

    // -----------------------------------------------------------------------------------------
    // Every reason, and where it lands.
    // -----------------------------------------------------------------------------------------

    /// One tree holding every reason the filesystem can produce on its own, each recorded once, in
    /// the directory that owns it.
    #[test]
    fn every_reason_lands_in_its_own_directory() {
        let root = temp_dir("reasons");
        let sub = root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(root.join("ok.bin"), vec![b'k'; 20]).unwrap();
        fs::write(root.join("small.bin"), b"x").unwrap();
        fs::write(root.join("big.bin"), vec![b'b'; 200]).unwrap();
        fs::write(root.join("notes.log"), vec![b'l'; 20]).unwrap();
        fs::write(
            root.join(OsStr::from_bytes(b"bad\xffname.bin")),
            vec![b'n'; 20],
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("ok.bin"), root.join("link.bin")).unwrap();
        fs::write(sub.join("tiny.bin"), b"y").unwrap();

        let mut config = base_config(&root);
        config.min_size = 4;
        config.max_size = Some(100);
        config.include_extensions = vec!["bin".to_string()];
        let outcome = collect(&config);

        assert_eq!(
            cells(&outcome, &root),
            vec![
                (String::new(), OmissionReason::MinSize, 1),
                (String::new(), OmissionReason::MaxSize, 1),
                (String::new(), OmissionReason::ExtensionFiltered, 1),
                (String::new(), OmissionReason::NonUtf8, 1),
                (String::new(), OmissionReason::UnsupportedEntry, 1),
                ("sub".to_string(), OmissionReason::MinSize, 1),
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>(),
            "each reason once, in the directory that holds it"
        );

        let whole = summary(&outcome, &root);
        assert_eq!(whole.known_omitted_files().unwrap(), 5, "five files");
        assert_eq!(whole.unsupported_entries().unwrap(), 1, "one symlink");
        assert!(!whole.has_unknown_cardinality(), "no errors here");

        fs::remove_dir_all(&root).ok();
    }

    /// Repeated special entries aggregate as ENTRIES: three, no files, and nothing inexact.
    #[test]
    fn repeated_special_entries_aggregate_as_entries() {
        let root = temp_dir("special_many");
        fs::write(root.join("ok.bin"), b"data").unwrap();
        std::os::unix::fs::symlink(root.join("ok.bin"), root.join("a.link")).unwrap();
        make_fifo(&root.join("b.fifo"));
        let _socket = make_socket(&root.join("c.sock"));

        let outcome = collect(&base_config(&root));
        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::UnsupportedEntry, 3)],
            "one cell, three entries"
        );
        let whole = summary(&outcome, &root);
        assert_eq!(whole.unsupported_entries().unwrap(), 3);
        assert_eq!(
            whole.known_omitted_files().unwrap(),
            0,
            "none of them is a file"
        );
        assert!(
            !whole.has_unknown_cardinality(),
            "three sockets are three sockets, not an unknown amount"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// A special entry in one child leaves its sibling eligible.
    #[test]
    fn an_unsupported_entry_is_localized_to_its_own_directory() {
        let root = temp_dir("special_local");
        let left = root.join("left");
        let right = root.join("right");
        for side in [&left, &right] {
            fs::create_dir_all(side).unwrap();
            fs::write(side.join("a.bin"), b"same").unwrap();
        }
        make_fifo(&left.join("pipe"));

        let outcome = collect(&base_config(&root));
        assert_eq!(
            cells(&outcome, &root),
            vec![("left".to_string(), OmissionReason::UnsupportedEntry, 1)],
            "only the left side is marked; the right side has no cell at all"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// The non-UTF8 child is attributed to its representable parent, and no lossy key is stored.
    #[test]
    fn a_non_utf8_child_is_attributed_to_its_parent() {
        let root = temp_dir("nonutf8_attr");
        let sub = root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(OsStr::from_bytes(b"bad\xffname.bin")), b"data").unwrap();

        let outcome = collect(&base_config(&root));
        assert_eq!(
            cells(&outcome, &root),
            vec![("sub".to_string(), OmissionReason::NonUtf8, 1)]
        );
        // Nothing resembling the child's name is anywhere in the snapshot.
        for (directory, _, _) in publishable(&outcome)[&key(&root)].iter() {
            assert!(
                !directory.as_str().contains("bad"),
                "no child pathname may be stored: {}",
                directory.as_str()
            );
        }

        fs::remove_dir_all(&root).ok();
    }

    /// A selected root that is itself a regular file: its only entry has no parent inside the
    /// root, so the event lands on the root itself rather than escaping it.
    #[test]
    fn a_regular_file_root_records_at_the_root() {
        let holder = temp_dir("file_root");
        let root = holder.join("only.bin");
        fs::write(&root, b"x").unwrap();

        let mut config = base_config(&root);
        config.min_size = 4096;
        let outcome = collect(&config);
        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::MinSize, 1)],
            "the root itself is the only in-root location"
        );

        // And the same root with the metadata fault armed on the file.
        let _faults = WalkFaults::arm(&[(root.clone(), WalkFault::Metadata)]);
        let outcome = collect(&base_config(&root));
        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::MetadataError, 1)]
        );

        fs::remove_dir_all(&holder).ok();
    }

    // -----------------------------------------------------------------------------------------
    // Iterator errors: one yielded `Err`, one event.
    // -----------------------------------------------------------------------------------------

    /// An unresolvable root: the error names the root itself, so the location is the root and the
    /// row is its `walk_error` sentinel — not an attribution that escapes upward.
    #[test]
    fn an_error_naming_the_root_becomes_the_root_sentinel() {
        let holder = temp_dir("missing_root");
        let root = holder.join("not-there");
        let outcome = collect(&base_config(&root));

        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::WalkError, 1)],
            "one event, at the root"
        );
        assert!(summary(&outcome, &root).has_unknown_cardinality());

        fs::remove_dir_all(&holder).ok();
    }

    /// A pathless error under one root becomes that root's sentinel.
    #[test]
    fn a_pathless_error_becomes_the_root_sentinel() {
        let root = temp_dir("pathless");
        fs::write(root.join("ok.bin"), b"data").unwrap();

        let faults = IteratorErrorFaults::arm(vec![(
            root.clone(),
            ignore::Error::Io(std::io::Error::other("no path at all")),
        )]);
        let outcome = collect(&base_config(&root));

        assert_eq!(faults.fired(), vec![root.clone()], "the fault fired once");
        assert_eq!(faults.pending(), 0);
        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::WalkError, 1)]
        );
        // The manifest is unaffected: a pathless error costs no known file.
        match &outcome {
            WalkOutcome::Finished { files, .. } => assert_eq!(files.len(), 1),
            other => panic!("expected a finished walk, got {:?}", other.kind()),
        }

        fs::remove_dir_all(&root).ok();
    }

    /// Two roots, a pathless error while walking the second: it lands on the root being walked and
    /// leaves the other explicitly empty. Under one shared builder that root could only be guessed.
    #[test]
    fn a_pathless_error_lands_on_the_root_being_walked() {
        let holder = temp_dir("pathless_two");
        let one = holder.join("one");
        let two = holder.join("two");
        for root in [&one, &two] {
            fs::create_dir_all(root).unwrap();
            fs::write(root.join("a.bin"), b"data").unwrap();
        }

        let mut config = base_config(&one);
        config.roots = vec![one.clone(), two.clone()];
        let faults = IteratorErrorFaults::arm(vec![(
            two.clone(),
            ignore::Error::Io(std::io::Error::other("no path at all")),
        )]);
        let outcome = collect(&config);

        assert_eq!(faults.fired(), vec![two.clone()]);
        assert_eq!(
            cells(&outcome, &one),
            Vec::new(),
            "the first root is explicitly present and empty"
        );
        assert_eq!(
            cells(&outcome, &two),
            vec![(String::new(), OmissionReason::WalkError, 1)]
        );

        fs::remove_dir_all(&holder).ok();
    }

    /// A nested `Partial` naming two unrelated in-root directories: neither covers the other, so
    /// one root sentinel — and the summary reports ONE event for one yielded error, not two.
    #[test]
    fn a_partial_error_with_unrelated_paths_yields_one_root_event() {
        let root = temp_dir("partial_wide");
        for name in ["a", "b"] {
            fs::create_dir_all(root.join(name)).unwrap();
            fs::write(root.join(name).join("f.bin"), b"data").unwrap();
        }

        let injected = ignore::Error::Partial(vec![
            ignore::Error::WithPath {
                path: root.join("a"),
                err: Box::new(ignore::Error::Io(std::io::Error::other("one"))),
            },
            ignore::Error::WithDepth {
                depth: 2,
                err: Box::new(ignore::Error::WithPath {
                    path: root.join("b"),
                    err: Box::new(ignore::Error::Io(std::io::Error::other("two"))),
                }),
            },
        ]);
        let _faults = IteratorErrorFaults::arm(vec![(root.clone(), injected)]);
        let outcome = collect(&base_config(&root));

        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::WalkError, 1)],
            "one error is one event, at the sentinel"
        );
        assert_eq!(
            summary(&outcome, &root).unknown_cardinality_events(),
            1,
            "a reader summing rows must see one error, not two"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// A `Partial` whose paths nest: the deeper location covers the shallower one on its way up,
    /// so it is used instead of the coarser sentinel — still exactly one event.
    #[test]
    fn a_partial_error_with_nested_paths_uses_the_deeper_location() {
        let root = temp_dir("partial_deep");
        let deep = root.join("a").join("b");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("f.bin"), b"data").unwrap();

        let injected = ignore::Error::Partial(vec![
            ignore::Error::WithPath {
                path: root.join("a"),
                err: Box::new(ignore::Error::Io(std::io::Error::other("outer"))),
            },
            ignore::Error::WithPath {
                path: deep.clone(),
                err: Box::new(ignore::Error::Io(std::io::Error::other("inner"))),
            },
        ]);
        let _faults = IteratorErrorFaults::arm(vec![(root.clone(), injected)]);
        let outcome = collect(&base_config(&root));

        assert_eq!(
            cells(&outcome, &root),
            vec![("a/b".to_string(), OmissionReason::WalkError, 1)],
            "the deeper location taints the shallower one on its way to the root"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// A path the error carries that lies outside the root is context, not a location: it is
    /// discarded rather than dragging the event out of its root.
    #[test]
    fn an_error_path_outside_the_root_is_discarded() {
        let holder = temp_dir("outside");
        let root = holder.join("root");
        fs::create_dir_all(root.join("inside")).unwrap();
        fs::write(root.join("inside").join("f.bin"), b"data").unwrap();

        let injected = ignore::Error::Loop {
            ancestor: holder.join("elsewhere"),
            child: root.join("inside"),
        };
        let _faults = IteratorErrorFaults::arm(vec![(root.clone(), injected)]);
        let outcome = collect(&base_config(&root));

        assert_eq!(
            cells(&outcome, &root),
            vec![("inside".to_string(), OmissionReason::WalkError, 1)],
            "only the in-root path is a location"
        );

        fs::remove_dir_all(&holder).ok();
    }

    /// A real symlink loop, produced by the filesystem rather than constructed: `ignore` reports
    /// `WithDepth{Loop{..}}`, the child lies under the ancestor, and it stays one event.
    #[test]
    fn a_real_loop_yields_one_event() {
        let root = temp_dir("real_loop");
        let inner = root.join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(inner.join("f.bin"), b"data").unwrap();
        std::os::unix::fs::symlink(&inner, inner.join("loop")).unwrap();

        let mut config = base_config(&root);
        config.follow_symlinks = true;
        let outcome = collect(&config);

        let recorded = cells(&outcome, &root);
        assert_eq!(recorded.len(), 1, "one cell: {recorded:?}");
        assert_eq!(recorded[0].1, OmissionReason::WalkError);
        assert_eq!(recorded[0].2, 1, "one yielded error is one event");
        assert!(
            recorded[0].0.starts_with("inner"),
            "attributed inside the loop, not at the root: {recorded:?}"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// A broken link under `follow_symlinks` is an iterator error, not an unsupported entry: the
    /// walker never learns what it pointed at.
    #[test]
    fn a_broken_link_is_a_walk_error_when_followed() {
        let root = temp_dir("broken_link");
        fs::write(root.join("ok.bin"), b"data").unwrap();
        std::os::unix::fs::symlink(root.join("missing"), root.join("dangling")).unwrap();

        let mut config = base_config(&root);
        config.follow_symlinks = true;
        let outcome = collect(&config);

        assert_eq!(
            cells(&outcome, &root),
            vec![("dangling".to_string(), OmissionReason::WalkError, 1)],
            "a broken target is an error, never an unsupported entry"
        );
        // The location is the link itself, because an error path starts at its own path — the
        // entry's type was never learned. A row there taints the directory holding it on its way
        // up, which is the effect wanted.
        assert!(summary(&outcome, &root).has_unknown_cardinality());

        fs::remove_dir_all(&root).ok();
    }

    // -----------------------------------------------------------------------------------------
    // Following links.
    // -----------------------------------------------------------------------------------------

    /// Following links resolves the type: a link to a regular file enters the manifest and records
    /// nothing, while a link to a character device is still an entry the scan cannot represent.
    /// `/dev/null` is a real character device present in every Linux environment, so this needs no
    /// privileges and no injected type.
    #[test]
    fn following_links_resolves_the_target_type() {
        let root = temp_dir("followed");
        fs::write(root.join("real.bin"), b"data").unwrap();
        std::os::unix::fs::symlink(root.join("real.bin"), root.join("to_file")).unwrap();
        std::os::unix::fs::symlink("/dev/null", root.join("to_device")).unwrap();

        let mut config = base_config(&root);
        config.follow_symlinks = true;
        let outcome = collect(&config);

        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::UnsupportedEntry, 1)],
            "only the device link is unrepresentable"
        );
        match &outcome {
            WalkOutcome::Finished { files, .. } => {
                let mut names: Vec<String> = files
                    .iter()
                    .map(|f| {
                        f.path
                            .strip_prefix(&root)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect();
                names.sort();
                assert_eq!(
                    names,
                    vec!["real.bin".to_string(), "to_file".to_string()],
                    "the followed regular target enters the manifest under the link's pathname"
                );
            }
            other => panic!("expected a finished walk, got {:?}", other.kind()),
        }

        // The same tree without following: the links are entries, not files.
        let outcome = collect(&base_config(&root));
        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::UnsupportedEntry, 2)],
            "the verdict is configuration-dependent, and this pins it"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// Block and character device NODES cannot be created without privileges, so the seam stands
    /// in for one. What it proves is the recording path for a nominated entry; the real symlink,
    /// FIFO, socket and `/dev/null` cases above are the evidence that the arm itself is reached.
    #[test]
    fn an_injected_device_entry_is_recorded_as_unsupported() {
        let root = temp_dir("device");
        let sub = root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        let node = sub.join("blk0");
        fs::write(&node, b"stands in for a device node").unwrap();
        fs::write(root.join("ok.bin"), b"data").unwrap();

        let faults = SpecialEntryFaults::arm(std::slice::from_ref(&node));
        let outcome = collect(&base_config(&root));

        assert_eq!(faults.fired(), vec![node], "the seam fired once");
        assert_eq!(faults.pending(), 0);
        assert_eq!(
            cells(&outcome, &root),
            vec![("sub".to_string(), OmissionReason::UnsupportedEntry, 1)]
        );

        fs::remove_dir_all(&root).ok();
    }

    // -----------------------------------------------------------------------------------------
    // Roots, exclusions, cancellation and the storage domain.
    // -----------------------------------------------------------------------------------------

    /// Two roots are both present, the clean one explicitly empty, and neither sees the other.
    #[test]
    fn two_roots_are_both_present_and_do_not_leak() {
        let holder = temp_dir("two_roots");
        let one = holder.join("one");
        let two = holder.join("two");
        for root in [&one, &two] {
            fs::create_dir_all(root).unwrap();
            fs::write(root.join("a.bin"), b"data").unwrap();
        }
        make_fifo(&one.join("pipe"));

        let mut config = base_config(&one);
        config.roots = vec![one.clone(), two.clone()];
        let outcome = collect(&config);

        assert_eq!(publishable(&outcome).len(), 2, "both roots present");
        assert_eq!(
            cells(&outcome, &one),
            vec![(String::new(), OmissionReason::UnsupportedEntry, 1)]
        );
        assert_eq!(
            cells(&outcome, &two),
            Vec::new(),
            "explicitly empty, not absent"
        );

        fs::remove_dir_all(&holder).ok();
    }

    /// Overridden entries never reach the consumer, so they cannot produce a row — including a
    /// special entry, which is the case that would otherwise look like a silent drop.
    #[test]
    fn excluded_entries_produce_no_row() {
        let root = temp_dir("excluded");
        fs::write(root.join("ok.bin"), vec![b'k'; 20]).unwrap();
        // The two defaults, by their real names, plus one operator glob. Each holds exactly the
        // shapes that WOULD be recorded anywhere else: an undersized file and a special entry.
        for dir in [".zfs", crate::model::scan::QUARANTINE_DIR_NAME, "skipme"] {
            fs::create_dir_all(root.join(dir)).unwrap();
            fs::write(root.join(dir).join("tiny.bin"), b"x").unwrap();
            make_fifo(&root.join(dir).join("pipe"));
        }

        let mut config = ScanConfig::new(vec![root.clone()]);
        config.min_size = 4;
        config.exclude_globs.push("**/skipme/**".to_string());
        let outcome = collect(&config);

        assert_eq!(
            cells(&outcome, &root),
            Vec::new(),
            "an excluded subtree is never yielded, so it can never be an omission"
        );
        // Control: the very same shapes outside an exclusion do produce rows, so the assertion
        // above is about exclusion and not about the shapes being invisible.
        fs::write(root.join("visible.tiny"), b"x").unwrap();
        make_fifo(&root.join("visible.pipe"));
        let outcome = collect(&config);
        assert_eq!(
            cells(&outcome, &root),
            vec![
                (String::new(), OmissionReason::MinSize, 1),
                (String::new(), OmissionReason::UnsupportedEntry, 1),
            ]
        );

        fs::remove_dir_all(&root).ok();
    }

    /// A cancelled walk carries no snapshot at all — the variant has nowhere to put one.
    #[test]
    fn cancellation_carries_no_snapshot() {
        let root = temp_dir("cancel");
        fs::write(root.join("ok.bin"), b"data").unwrap();
        make_fifo(&root.join("pipe"));

        let cancel = AtomicBool::new(true); // already cancelled: the first cadence check trips
        let outcome = walk_collecting(&base_config(&root), &cancel, |_, _, _| {}).unwrap();
        match outcome {
            WalkOutcome::Cancelled { files } => assert!(files.is_empty()),
            WalkOutcome::Finished { .. } => panic!("a cancelled walk must not finish"),
        }

        fs::remove_dir_all(&root).ok();
    }

    /// An empty root list is still the same outer error it always was, not an unavailable snapshot.
    #[test]
    fn an_empty_root_list_is_still_the_old_error() {
        let config = ScanConfig::new(Vec::new());
        let cancel = AtomicBool::new(false);
        // Not `expect_err`: that needs `Debug` on the success type, and neither `WalkOutcome` nor
        // `WalkedFile` has one.
        let err = match walk_collecting(&config, &cancel, |_, _, _| {}) {
            Err(err) => err.to_string(),
            Ok(outcome) => panic!("an empty root list must not walk, got {}", outcome.kind()),
        };
        assert!(err.contains("no scan root specified"), "{err}");
    }

    /// A root set that cannot be keyed still walks: the manifest is what it always was, and only
    /// the snapshot is unavailable.
    #[test]
    fn unkeyable_roots_keep_the_manifest() {
        let root = temp_dir("unkeyable");
        fs::write(root.join("ok.bin"), b"data").unwrap();
        make_fifo(&root.join("pipe"));

        let mut config = base_config(&root);
        config.roots = vec![root.join("..").join(root.file_name().unwrap())];
        let outcome = collect(&config);

        match &outcome {
            WalkOutcome::Finished {
                files,
                omissions:
                    OmissionSnapshot::Unavailable(SnapshotUnavailable::Roots { why, observed }),
            } => {
                assert!(matches!(why, AuthorityUnavailable::UnkeyableRoot { .. }));
                assert_eq!(files.len(), 1, "the manifest is untouched");
                // The events the ledger could not attribute are still counted, globally.
                assert_eq!(
                    observed.unsupported_entries().unwrap(),
                    1,
                    "the fifo survives as an observed event"
                );
                assert!(!observed.has_unknown_cardinality());
            }
            other => panic!("expected an unavailable snapshot, got {:?}", other.kind()),
        }

        fs::remove_dir_all(&root).ok();
    }

    /// Lexically overlapping roots get no authority either — and no partial one.
    #[test]
    fn overlapping_roots_yield_no_authority() {
        let holder = temp_dir("overlap");
        let outer = holder.join("outer");
        let inner = outer.join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(inner.join("a.bin"), b"data").unwrap();

        let mut config = base_config(&outer);
        config.roots = vec![outer.clone(), inner.clone()];
        let outcome = collect(&config);

        match &outcome {
            WalkOutcome::Finished {
                omissions: OmissionSnapshot::Unavailable(SnapshotUnavailable::Roots { why, .. }),
                ..
            } => assert!(matches!(why, AuthorityUnavailable::AmbiguousRoots { .. })),
            other => panic!("expected an unavailable snapshot, got {:?}", other.kind()),
        }

        fs::remove_dir_all(&holder).ok();
    }

    /// The storage domain is checked before anything is called publishable: `i64::MAX` is a real
    /// count the checkpoint can hold, one more is not, and a `u64` wrap is a different state again.
    #[test]
    fn the_count_boundaries_are_three_distinct_states() {
        let root = key(Path::new("/tank"));
        let directory = key(Path::new("/tank/a"));

        let seeded = |count: u64| {
            let mut collector = Collector::new(std::slice::from_ref(&root));
            collector
                .per_root
                .get_mut(&root)
                .unwrap()
                .add(
                    directory.clone(),
                    OmissionReason::MinSize,
                    EventCount::new(count).unwrap(),
                )
                .unwrap();
            collector
        };

        assert!(
            matches!(
                seeded(i64::MAX as u64).finish(),
                OmissionSnapshot::Publishable(_)
            ),
            "exactly i64::MAX is storable"
        );
        assert!(
            matches!(
                seeded(i64::MAX as u64 + 1).finish(),
                OmissionSnapshot::Unavailable(SnapshotUnavailable::CountNotStorable { .. })
            ),
            "one more is a real number the column cannot hold"
        );

        // The arithmetic state is reached through the collector's own recording path.
        let mut collector = seeded(u64::MAX);
        collector.record(&root, directory.clone(), OmissionReason::MinSize);
        assert!(matches!(
            collector.finish(),
            OmissionSnapshot::Unavailable(SnapshotUnavailable::CountOverflow { .. })
        ));
    }

    /// An event for a root the collector was never seeded with cannot be dropped.
    ///
    /// Today's wiring builds `Ledger.root` from the same key slice that seeds the collector, so
    /// nothing reaches this branch — which is exactly why it needs a test. A future wiring mistake
    /// must surface as an unavailable snapshot naming the root, not as a directory that quietly
    /// looks whole because its omission went missing.
    #[test]
    fn an_event_under_an_unregistered_root_makes_the_snapshot_unavailable() {
        let a = key(Path::new("/tank/a"));
        let b = key(Path::new("/tank/b"));
        let inner = key(Path::new("/tank/b/inner"));

        // Control: the same collector without the mismatched event is publishable, and the seeded
        // root is present with an explicitly empty map.
        match Collector::new(std::slice::from_ref(&a)).finish() {
            OmissionSnapshot::Publishable(map) => {
                assert_eq!(map.len(), 1, "exactly the seeded root");
                assert!(map[&a].is_empty(), "A is present and explicitly empty");
            }
            OmissionSnapshot::Unavailable(_) => panic!("a clean collector must be publishable"),
        }

        let mut mismatched = Collector::new(std::slice::from_ref(&a));
        mismatched.record(&b, inner.clone(), OmissionReason::MinSize);
        match mismatched.finish() {
            OmissionSnapshot::Unavailable(SnapshotUnavailable::UnregisteredRoot {
                root,
                directory,
                reason,
            }) => {
                assert_eq!(root, b, "the missing root must be named");
                assert_eq!(directory, inner, "and the event that could not be placed");
                assert_eq!(reason, OmissionReason::MinSize);
            }
            OmissionSnapshot::Publishable(_) => panic!(
                "an event under an unregistered root was dropped and the snapshot still claims \
                 to be publishable"
            ),
            OmissionSnapshot::Unavailable(_) => panic!("the wrong unavailable state"),
        }
    }

    /// First failure wins, and nothing recovers a failed collector: a later, perfectly ordinary
    /// event may be ignored only because `finish` can no longer return `Publishable`.
    #[test]
    fn a_failed_collector_never_becomes_publishable_again() {
        let a = key(Path::new("/tank/a"));
        let b = key(Path::new("/tank/b"));

        let mut collector = Collector::new(std::slice::from_ref(&a));
        collector.record(&b, key(Path::new("/tank/b/x")), OmissionReason::MinSize);
        // A valid event afterwards must not paper over the failure.
        collector.record(&a, key(Path::new("/tank/a/y")), OmissionReason::NonUtf8);
        match collector.finish() {
            OmissionSnapshot::Unavailable(SnapshotUnavailable::UnregisteredRoot {
                root, ..
            }) => {
                assert_eq!(root, b, "the FIRST failure is the one reported")
            }
            OmissionSnapshot::Publishable(_) => panic!("a failed collector must stay unavailable"),
            OmissionSnapshot::Unavailable(_) => panic!("the wrong unavailable state"),
        }
    }

    /// The manifest is exactly what the accepted parent produced: same files, same order — over a
    /// tree that exercises the filters and both root shapes. What the wrapper used to return as a
    /// bare count is now the ledger's own `non_utf8` cell, one per root.
    #[test]
    fn the_manifest_membership_and_order_are_unchanged() {
        let holder = temp_dir("wrapper");
        let one = holder.join("one");
        let two = holder.join("two");
        for root in [&one, &two] {
            fs::create_dir_all(root.join("sub")).unwrap();
            fs::write(root.join("keep.bin"), vec![b'k'; 20]).unwrap();
            fs::write(root.join("sub").join("deep.bin"), vec![b'd'; 20]).unwrap();
            fs::write(root.join("tiny.bin"), b"x").unwrap();
            fs::write(
                root.join(OsStr::from_bytes(b"bad\xffname.bin")),
                vec![b'n'; 20],
            )
            .unwrap();
            make_fifo(&root.join("pipe"));
        }

        let mut config = base_config(&one);
        config.roots = vec![one.clone(), two.clone()];
        config.min_size = 4;
        let outcome = collect(&config);

        let names: Vec<String> = finished(&outcome)
            .iter()
            .map(|f| {
                f.path
                    .strip_prefix(&holder)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "one/keep.bin".to_string(),
                "one/sub/deep.bin".to_string(),
                "two/keep.bin".to_string(),
                "two/sub/deep.bin".to_string(),
            ],
            "root order preserved, traversal order preserved"
        );
        for root in [&one, &two] {
            assert_eq!(
                summary(&outcome, root).per_reason().collect::<Vec<_>>(),
                vec![
                    (OmissionReason::MinSize, EventCount::ONE),
                    (OmissionReason::NonUtf8, EventCount::ONE),
                    (OmissionReason::UnsupportedEntry, EventCount::ONE),
                ],
                "each root accounts its own tiny file, bad name and fifo"
            );
        }

        fs::remove_dir_all(&holder).ok();
    }

    /// Non-UTF8 guard: a file with a non-UTF8 name is skipped and accounted,
    /// a valid one makes it into the manifest.
    #[test]
    fn skips_and_counts_non_utf8_paths() {
        let root = temp_dir("nonutf8");

        let good = root.join("ok.bin");
        fs::write(&good, b"data").unwrap();

        // A name with byte 0xFF — valid UTF-8 cannot be made from it.
        let bad = root.join(OsStr::from_bytes(b"bad\xffname.bin"));
        fs::write(&bad, b"data").unwrap();
        assert!(
            bad.exists(),
            "the FS did not accept the non-UTF8 name — test not applicable"
        );

        let mut config = ScanConfig::new(vec![root.clone()]);
        config.min_size = 0; // don't filter out by size
        config.exclude_globs.clear(); // no default exclusions — determinism

        let outcome = collect(&config);

        assert_eq!(
            cells(&outcome, &root),
            vec![(String::new(), OmissionReason::NonUtf8, 1)],
            "exactly one non-UTF8 file, accounted where it lives"
        );
        let files = finished(&outcome);
        assert_eq!(
            files.len(),
            1,
            "the valid file must make it into the manifest"
        );
        assert_eq!(
            files[0].path, good,
            "the manifest holds exactly the valid file"
        );

        fs::remove_dir_all(&root).ok();
    }

    // -----------------------------------------------------------------------------------------
    // Traversal order.
    // -----------------------------------------------------------------------------------------

    /// One copy of the order fixture, in the sequence a byte-sorted depth-first walk must produce.
    ///
    /// Two properties are readable straight off it. It is BYTE order, not a natural or a
    /// locale-aware one: `10.bin` precedes `2.bin`, and `Beta.bin` precedes `_tail.bin` precedes
    /// `alpha.bin` (0x42 < 0x5F < 0x61). And the sorting happens DURING the walk rather than over
    /// the finished vector: `sub/A.bin` comes before `sub.bin`, because the walk descends into
    /// `sub` the moment it reaches it, while as flat strings `sub.bin` sorts first (`.` is 0x2E,
    /// `/` is 0x2F). Sorting the result afterwards fails on that pair alone.
    const ORDERED_WALK: [&str; 9] = [
        "10.bin",
        "2.bin",
        "Beta.bin",
        "_tail.bin",
        "alpha.bin",
        "sub/A.bin",
        "sub/m.bin",
        "sub/z.bin",
        "sub.bin",
    ];

    /// The same nine pathnames in an order that is neither the walk order nor its reverse.
    const CREATION_ORDER: [&str; 9] = [
        "sub.bin",
        "alpha.bin",
        "sub/z.bin",
        "Beta.bin",
        "sub/A.bin",
        "2.bin",
        "sub/m.bin",
        "_tail.bin",
        "10.bin",
    ];

    /// `ORDERED_WALK` as owned strings. Nothing here sorts: the expectation is a literal.
    fn ordered_walk() -> Vec<String> {
        ORDERED_WALK.iter().map(|name| name.to_string()).collect()
    }

    /// `ORDERED_WALK` under a directory name, as a multi-root walk reports it.
    fn ordered_walk_under(dir: &str) -> Vec<String> {
        ORDERED_WALK
            .iter()
            .map(|name| format!("{dir}/{name}"))
            .collect()
    }

    /// Builds one copy of the order fixture. `reversed` flips the creation order of every entry in
    /// both directories, `sub` included — it comes into being with whichever of its children is
    /// created first. Where listing order follows the order entries were made, the two copies
    /// enumerate in opposite directions and only a walk that imposes an order of its own can
    /// report them alike. Which filesystems do that is deliberately not claimed here: it varies by
    /// filesystem, by mount option and by kernel version, and no assertion depends on it — the
    /// expectation the test compares against is a literal, which holds whatever the listing order
    /// turns out to be.
    fn build_order_tree(root: &Path, reversed: bool) {
        fs::create_dir_all(root).unwrap();
        let mut order: Vec<&str> = CREATION_ORDER.to_vec();
        if reversed {
            order.reverse();
        }
        for name in order {
            let path = root.join(name);
            fs::create_dir_all(path.parent().expect("a name under the root")).unwrap();
            fs::write(&path, name.as_bytes()).unwrap();
        }
    }

    /// The order the walk imposes is decided by `by_name_bytes`, so it can be tested for what it
    /// is — a decision about bytes — with no filesystem, no fixture and no `readdir` involved.
    /// Every assertion here holds identically on every machine.
    #[test]
    fn the_name_comparator_orders_raw_bytes() {
        // Byte order, spelled out: digits before letters and "10" before "2", so not numeric;
        // uppercase (0x42) before underscore (0x5F) before lowercase (0x61), so neither case
        // folding nor a locale collation; and a prefix before the name that extends it.
        let expected: Vec<&OsStr> = [
            &b"10.bin"[..],
            &b"2.bin"[..],
            &b"Beta.bin"[..],
            &b"_tail.bin"[..],
            &b"alpha.bin"[..],
            &b"sub"[..],
            &b"sub.bin"[..],
        ]
        .into_iter()
        .map(OsStr::from_bytes)
        .collect();

        let mut shuffled: Vec<&OsStr> = vec![
            expected[4],
            expected[6],
            expected[0],
            expected[5],
            expected[2],
            expected[1],
            expected[3],
        ];
        assert!(
            shuffled.iter().zip(expected.iter()).all(|(a, b)| a != b),
            "the input must not already sit in the expected order at any position"
        );

        shuffled.sort_by(|a, b| by_name_bytes(a, b));
        assert_eq!(
            shuffled, expected,
            "the comparator orders raw bytes, ascending"
        );
    }

    /// Two names no `str` can hold are still ordered, and ordered APART.
    ///
    /// This is the whole reason the comparator reads bytes rather than text. The first assertion
    /// establishes the premise — `to_string_lossy` genuinely cannot tell these two names apart —
    /// and the rest show that the comparator can. A lossy comparator would call them equal, and
    /// equal siblings keep whatever order `readdir` gave them, which is exactly the
    /// filesystem-dependence the sorter exists to remove.
    #[test]
    fn two_distinct_non_utf8_names_are_ordered_apart() {
        let lower = OsStr::from_bytes(b"bad\xfename.bin");
        let upper = OsStr::from_bytes(b"bad\xffname.bin");

        assert_eq!(
            lower.to_string_lossy(),
            upper.to_string_lossy(),
            "the premise: lossy conversion cannot tell these two names apart"
        );
        assert_ne!(lower, upper, "but they are two different names");

        assert_eq!(by_name_bytes(lower, upper), std::cmp::Ordering::Less);
        assert_eq!(by_name_bytes(upper, lower), std::cmp::Ordering::Greater);
        assert_eq!(by_name_bytes(lower, lower), std::cmp::Ordering::Equal);
    }

    /// Traversal order belongs to this program, not to `readdir`.
    ///
    /// Two copies of one logical tree, created in deliberately opposite orders, must walk in the
    /// SAME sequence, and that sequence must be the byte-sorted depth-first one. Both assertions
    /// hold on every filesystem once the walk sorts; neither asks the filesystem to behave in any
    /// particular way, so this test is not the place a shuffling `readdir` shows up. What it does
    /// catch, on any machine, is a walk whose order stops matching the one this program promises.
    #[test]
    fn the_walk_order_is_sorted_and_independent_of_creation_order() {
        // The expectation is a traversal sequence, not a sorted list: `sub/A.bin` precedes
        // `sub.bin` although as flat strings `sub.bin` sorts first. Sorting both sides of the
        // comparisons below could therefore never turn this test green.
        let mut flat = ordered_walk();
        flat.sort();
        assert_ne!(
            flat,
            ordered_walk(),
            "ORDERED_WALK must stay a traversal sequence, never a sorted list of strings"
        );

        let holder = temp_dir("order");
        let forward = holder.join("forward");
        let backward = holder.join("backward");
        build_order_tree(&forward, false);
        build_order_tree(&backward, true);

        let outcome = collect(&base_config(&forward));
        let walked_forward = walked_names(finished(&outcome), &forward);
        let walked_backward = walked_names(finished(&collect(&base_config(&backward))), &backward);

        assert_eq!(
            walked_forward, walked_backward,
            "opposite creation orders must not produce different walks"
        );
        assert_eq!(
            walked_forward,
            ordered_walk(),
            "and the shared sequence is the byte-sorted, depth-first one"
        );

        // Completeness, asserted APART from order: delete both assertions above and losing a file
        // still fails here.
        assert_eq!(walked_forward.len(), 9, "nine files: {walked_forward:?}");
        assert_eq!(
            walked_forward
                .iter()
                .collect::<std::collections::BTreeSet<_>>(),
            ordered_walk()
                .iter()
                .collect::<std::collections::BTreeSet<_>>(),
            "every pathname of the fixture reached the manifest"
        );
        assert_eq!(
            cells(&outcome, &forward),
            Vec::new(),
            "and nothing was omitted on the way"
        );

        // Mutation control: one file taken out of the middle of the nested directory. Without it
        // the completeness assertions above are untested claims.
        fs::remove_file(backward.join("sub/m.bin")).unwrap();
        let after = walked_names(finished(&collect(&base_config(&backward))), &backward);
        assert_eq!(
            after,
            vec![
                "10.bin".to_string(),
                "2.bin".to_string(),
                "Beta.bin".to_string(),
                "_tail.bin".to_string(),
                "alpha.bin".to_string(),
                "sub/A.bin".to_string(),
                "sub/z.bin".to_string(),
                "sub.bin".to_string(),
            ],
            "one file removed, eight left, the order of the rest unchanged"
        );

        fs::remove_dir_all(&holder).ok();
    }

    /// Roots keep the order they were configured in; sorting happens INSIDE a root, never across
    /// them. `the_manifest_membership_and_order_are_unchanged` also walks two roots, but its `one`
    /// and `two` are alphabetical, so it cannot tell a preserved order from a sorted one. These are
    /// deliberately anti-alphabetical.
    ///
    /// The order matters outside this file: `walk_collecting` zips `config.roots` against the keys
    /// `root_keys` returns in the same order, and a stored checkpoint is matched to a scan by
    /// comparing the two root vectors for equality — a sorted root list would silently stop
    /// resuming.
    #[test]
    fn the_walk_keeps_the_roots_in_configured_order() {
        let holder = temp_dir("order_roots");
        let zz = holder.join("zz_first");
        let aa = holder.join("aa_second");
        build_order_tree(&zz, false);
        build_order_tree(&aa, true);

        let mut config = base_config(&zz);
        config.roots = vec![zz.clone(), aa.clone()];
        let outcome = collect(&config);

        let mut expected = ordered_walk_under("zz_first");
        expected.extend(ordered_walk_under("aa_second"));
        assert_eq!(
            walked_names(finished(&outcome), &holder),
            expected,
            "configured root order survives; only entries within a directory are sorted"
        );

        fs::remove_dir_all(&holder).ok();
    }

    // -----------------------------------------------------------------------------------------
    // The no-authority observed tally.
    // -----------------------------------------------------------------------------------------

    /// A walk whose roots cannot be keyed still counts every event it would have ledgered —
    /// filters, a bad name, a special entry and a walk error — once each, without attribution.
    #[test]
    fn an_unkeyable_walk_counts_every_event_it_observes() {
        let root = temp_dir("observed_all");
        fs::write(root.join("ok.bin"), vec![b'k'; 20]).unwrap();
        fs::write(root.join("tiny.bin"), b"x").unwrap();
        fs::write(
            root.join(OsStr::from_bytes(b"bad\xffname.bin")),
            vec![b'n'; 20],
        )
        .unwrap();
        make_fifo(&root.join("pipe"));

        let mut config = base_config(&root);
        config.min_size = 4;
        config.roots = vec![root.join("..").join(root.file_name().unwrap())];
        let faults = IteratorErrorFaults::arm(vec![(
            config.roots[0].clone(),
            ignore::Error::Io(std::io::Error::other("no path at all")),
        )]);
        let outcome = collect(&config);
        assert_eq!(faults.fired().len(), 1, "the injected error fired");

        match &outcome {
            WalkOutcome::Finished {
                files,
                omissions:
                    OmissionSnapshot::Unavailable(SnapshotUnavailable::Roots { observed, .. }),
            } => {
                assert_eq!(files.len(), 1, "only ok.bin passes the filters");
                assert_eq!(
                    observed.per_reason().collect::<Vec<_>>(),
                    vec![
                        (OmissionReason::MinSize, EventCount::ONE),
                        (OmissionReason::NonUtf8, EventCount::ONE),
                        (OmissionReason::WalkError, EventCount::ONE),
                        (OmissionReason::UnsupportedEntry, EventCount::ONE),
                    ],
                    "each event once, no attribution invented"
                );
            }
            other => panic!("expected the Roots fallback, got {:?}", other.kind()),
        }

        fs::remove_dir_all(&root).ok();
    }

    /// The observed tally holds its FIRST `u64` overflow and reports it as the typed loud state —
    /// never a silently frozen previous count, and never a fake root or path.
    #[test]
    fn the_observed_tally_overflow_is_loud_and_first_wins() {
        let mut tally = ObservedTally::default();
        tally
            .summary
            .add(OmissionReason::MinSize, EventCount::new(u64::MAX).unwrap())
            .unwrap();
        tally.record(OmissionReason::MinSize); // overflows
        tally.record(OmissionReason::NonUtf8); // ignored: the failure is already held
        match tally.finish(AuthorityUnavailable::NoRoots) {
            OmissionSnapshot::Unavailable(SnapshotUnavailable::ObservedOverflow { reason }) => {
                assert_eq!(
                    reason,
                    OmissionReason::MinSize,
                    "the first failure is named"
                )
            }
            OmissionSnapshot::Unavailable(_) => panic!("the wrong unavailable state"),
            OmissionSnapshot::Publishable(_) => {
                panic!("an overflowed tally must never look publishable")
            }
        }

        // Control: a value of exactly `u64::MAX` is valid — the tally is session-only and the
        // storable-column rule deliberately does not apply to it.
        let mut fine = ObservedTally::default();
        fine.summary
            .add(OmissionReason::MinSize, EventCount::new(u64::MAX).unwrap())
            .unwrap();
        match fine.finish(AuthorityUnavailable::NoRoots) {
            OmissionSnapshot::Unavailable(SnapshotUnavailable::Roots { observed, .. }) => {
                assert_eq!(observed.known_omitted_files().unwrap(), u64::MAX)
            }
            _ => panic!("a full-range count is still an expected fallback"),
        }
    }
}
