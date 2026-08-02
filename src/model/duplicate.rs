// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::model::action::ActionKind;
use crate::model::omission::{DirDisposition, DirScope, LegacyContext, SignatureContext};
use crate::model::reclaim::{GroupReclaim, LinkCount, ObjectLinks};

/// A file that is part of a duplicate group.
///
/// The identity fields are the complete scan-local temporal one, not bare `(device, inode)`: an
/// inode number is reused after a delete, and a same-second in-place edit would otherwise look
/// unchanged. `nlink` travels with the row because reclaim is a question about the allocation, and
/// the answer needs the links this scan never saw.
#[derive(Debug, Clone, Default)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub device: u64,
    pub inode: u64,
    /// `st_nlink` as the walk observed it; `0` = never recorded (a legacy pre-v3 row).
    pub nlink: u64,
    /// The "keeper" file — it remains, no action is applied to it.
    pub is_keeper: bool,
    /// The planned action on the file (if marked by the user).
    pub action: Option<ActionKind>,
}

impl FileEntry {
    /// Files with identical (device, inode) are the same physical file
    /// (already hardlinked): deleting one will not free any space.
    pub fn same_physical(&self, other: &FileEntry) -> bool {
        self.device == other.device && self.inode == other.inode
    }

    /// The complete scan-local temporal physical identity — the key that decides whether two
    /// pathnames are the same allocation *right now*.
    pub fn object_key(&self) -> (u64, u64, u64, i64, i64, i64, i64) {
        (
            self.device,
            self.inode,
            self.size,
            self.mtime,
            self.mtime_nsec,
            self.ctime_sec,
            self.ctime_nsec,
        )
    }
}

/// A group of byte-for-byte identical files.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    pub id: usize,
    /// The size of one file (the same for all in the group).
    pub size_bytes: u64,
    /// blake3 hash of the contents in hex.
    pub hash: String,
    pub files: Vec<FileEntry>,
}

impl DuplicateGroup {
    /// What this group's pathnames say about the allocations behind them.
    ///
    /// Computed from the files rather than stored, so a group that verification split cannot keep
    /// a figure that belonged to its old membership. There is deliberately no pathname-based
    /// counterpart: `size × (paths − 1)` is the P-1 defect, and leaving that seam anywhere invites
    /// a caller to revive it.
    ///
    /// Only meaningful for a COMPLETE group. The browser pages a large group's files, so a display
    /// path must read the materialized summary instead of calling this on a partial `files`.
    pub fn physical_reclaim(&self) -> Result<GroupReclaim> {
        // Keyed rather than scanned: a top /tank group holds tens of thousands of pathnames, and
        // an inner search per file would make publishing the result quadratic in the group size.
        let mut objects: std::collections::HashMap<ObjectKey, ObjectEvidence> =
            std::collections::HashMap::new();
        for file in &self.files {
            let links = LinkCount::from_u64(file.nlink);
            match objects.entry(file.object_key()) {
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    let seen = slot.get_mut();
                    // Checked: a pathname count is what the manifest holds, and no arithmetic on
                    // the way to a byte figure may wrap corrupt input into a trusted one.
                    seen.observed = seen.observed.checked_add(1).ok_or_else(|| {
                        AppError::msg(
                            "a duplicate-content group with more pathnames than a count can hold"
                                .to_string(),
                        )
                    })?;
                    // Extremes, not a running value: every alias is weighed, and the object's
                    // smallest pathname names it however the rows arrived.
                    if file.path < seen.representative {
                        seen.representative = file.path.clone();
                    }
                    if links.to_u64() < seen.low.to_u64() {
                        seen.low = links;
                    }
                    if links.to_u64() > seen.high.to_u64() {
                        seen.high = links;
                    }
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(ObjectEvidence {
                        representative: file.path.clone(),
                        observed: 1,
                        low: links,
                        high: links,
                    });
                }
            }
        }

        // Sorted before anything is judged, so a group with two damaged allocations reports the
        // same one every time — a hash map's iteration order is not an order.
        let mut evidence: Vec<ObjectEvidence> = objects.into_values().collect();
        evidence.sort_by(|left, right| left.representative.cmp(&right.representative));
        let named = evidence
            .first()
            .map(|first| crate::textsan::terminal(&first.representative.display().to_string()))
            .unwrap_or_default();

        let mut links = Vec::with_capacity(evidence.len());
        for object in &evidence {
            let object_named =
                crate::textsan::terminal(&object.representative.display().to_string());
            links.push(ObjectLinks {
                observed: object.observed,
                links: LinkCount::agreed(object.low, object.high, &object_named)?,
            });
        }
        GroupReclaim::of_objects(self.size_bytes, &links, &named)
    }
}

/// The complete scan-local temporal physical identity of a manifest row.
type ObjectKey = (u64, u64, u64, i64, i64, i64, i64);

/// What one temporal object's pathnames collectively reported, folded so that neither the verdict
/// nor the message depends on the order they arrived in.
struct ObjectEvidence {
    /// The object's smallest pathname — the same representative the SQL path picks with
    /// `MIN(path)`.
    representative: PathBuf,
    /// Pathnames of this object inside the group.
    observed: u64,
    /// The lowest and highest link count its aliases reported. Unequal means they disagree, and
    /// an unrecorded count sorts below every real one, exactly as the `0` it is stored as does.
    low: LinkCount,
    high: LinkCount,
}

/// A group of directories with matching SCANNED contents. The signature is the blake3 of the sorted list (relative path, file hash)
/// over all files under the directory; the same for directories with the same tree. It is emitted ONLY
/// for COMPLETE directories (every file under them has a hash) — a directory with an unhashed
/// (unique-size / failure) file is suppressed, so that an extra such file does not produce a false twin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirGroup {
    pub id: u32,
    pub signature: String,
    pub paths: Vec<PathBuf>,
    /// Files in one directory of the group (the same for all — same signature).
    pub file_count: u32,
    /// Total size of files in one directory (the same for all in the group).
    pub size_per_dir: u64,
}

impl DirGroup {
    /// How much space is freed if one directory from the group is kept.
    pub fn reclaimable_bytes(&self) -> u64 {
        let extra = self.paths.len().saturating_sub(1) as u64;
        self.size_per_dir.saturating_mul(extra)
    }
}

/// The one benefit ordering, shared by the plain and the marker-aware sorters so they cannot drift.
fn by_benefit(a: &DirGroup, b: &DirGroup) -> std::cmp::Ordering {
    b.reclaimable_bytes()
        .cmp(&a.reclaimable_bytes())
        .then_with(|| a.signature.cmp(&b.signature))
}

/// Sorts directory groups by descending benefit and reassigns `id`.
pub fn sort_dir_groups_by_benefit(groups: &mut [DirGroup]) {
    groups.sort_by(by_benefit);
    for (index, group) in groups.iter_mut().enumerate() {
        group.id = index as u32;
    }
}

/// Trust in an emitted signature. `Suppressed` never reaches here — it produces no signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum DirTrust {
    Trusted,
    Untrusted,
}

/// A directory group plus the trust the ledger vouched for at build time.
///
/// Transient: nothing persists it, and `dir_dedup` has no column for it. A later decision
/// revalidates against the ledger's current state rather than trusting a stored value. `DirGroup`
/// itself is unchanged, so every existing constructor and every database reader is untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct AttributedDirGroup {
    pub group: DirGroup,
    /// One entry per member, in exactly `group.paths` order.
    pub member_trust: Vec<DirTrust>,
    /// Trusted only when every member is: a directory whose ledger cannot vouch for it may not be
    /// vouched for by a sibling that happens to sit under a trusted root.
    pub trust: DirTrust,
}

/// What the marker-aware streaming build emits.
///
/// A struct rather than a fifth positional argument, so the existing four-argument producer in
/// `store::materialize_dir_groups` needs no change in this commit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct DirSignature {
    pub path: PathBuf,
    pub signature: String,
    pub size: u64,
    pub file_count: u32,
    pub trust: DirTrust,
}

/// Sorts marker-aware groups by the same benefit ordering, carrying each member's trust with its
/// path so the two vectors cannot fall out of step.
#[allow(dead_code)]
fn sort_attributed_by_benefit(groups: &mut [AttributedDirGroup]) {
    groups.sort_by(|a, b| by_benefit(&a.group, &b.group));
    for (index, attributed) in groups.iter_mut().enumerate() {
        attributed.group.id = index as u32;
    }
}

/// The ancestors of `path` that a build may account for, deepest first.
///
/// Under `Root` the chain stops at the selected root — component-wise, so a spelling with `.` or a
/// trailing separator still matches. Under `Unbounded` it is exactly `path.ancestors().skip(1)`,
/// which is what a pre-ledger build walks, including for a relative or `..`-spelled pathname.
#[allow(dead_code)]
fn accountable_ancestors<'p>(path: &'p Path, scope: DirScope<'_>) -> Vec<&'p Path> {
    match scope {
        DirScope::Outside => Vec::new(),
        DirScope::Unbounded => path.ancestors().skip(1).collect(),
        DirScope::Root(root) => {
            let bound = Path::new(root.as_str());
            path.ancestors()
                .skip(1)
                .take_while(|dir| dir.starts_with(bound))
                .collect()
        }
    }
}

/// The error a manifest file under no selected root produces. Unreachable when the manifest and
/// the configured roots come from the same scan, which is exactly why it must be loud rather than
/// a silent skip.
#[allow(dead_code)]
fn outside_every_root(path: &Path) -> AppError {
    AppError::msg(format!(
        "{} is not inside any selected scan root, so its directories cannot be attributed",
        crate::textsan::terminal(&path.display().to_string())
    ))
}

/// Marker-aware Old: the same top-down accumulation, with the context deciding scope and
/// suppression.
///
/// Under a valid snapshot the ledger's own subtree aggregation already marks every ancestor
/// through the owning root, so there is deliberately no second upward pass — the unhashed-file
/// rule still propagates by its own file row, exactly as before.
#[allow(dead_code)]
pub fn build_dir_groups_in_context(
    files: &[(PathBuf, u64, Option<String>)],
    ctx: &dyn SignatureContext,
) -> Result<Vec<AttributedDirGroup>> {
    use std::collections::HashMap;

    type DirAccum = (Vec<(String, String)>, u64, u32, bool);
    let mut by_dir: HashMap<PathBuf, DirAccum> = HashMap::new();
    for (path, size, hash) in files {
        let scope = ctx.scope(path);
        if matches!(scope, DirScope::Outside) {
            return Err(outside_every_root(path));
        }
        for dir in accountable_ancestors(path, scope) {
            if let Ok(rel) = path.strip_prefix(dir) {
                let entry = by_dir.entry(dir.to_path_buf()).or_default();
                match hash {
                    Some(h) => {
                        entry
                            .0
                            .push((rel.to_string_lossy().into_owned(), h.clone()));
                        entry.1 += size;
                        entry.2 += 1;
                    }
                    None => entry.3 = true,
                }
            }
        }
    }

    let mut by_sig: HashMap<String, Vec<(PathBuf, u64, u32, DirTrust)>> = HashMap::new();
    for (dir, (entries, total, count, incomplete)) in by_dir {
        if incomplete {
            continue;
        }
        let trust = match ctx.disposition(&dir) {
            DirDisposition::Suppressed => continue,
            DirDisposition::Trusted => DirTrust::Trusted,
            DirDisposition::Untrusted => DirTrust::Untrusted,
        };
        let sig = signature_of(&entries);
        by_sig
            .entry(sig)
            .or_default()
            .push((dir, total, count, trust));
    }

    let mut groups: Vec<AttributedDirGroup> = by_sig
        .into_iter()
        .filter(|(_, dirs)| dirs.len() >= 2)
        .map(|(signature, dirs)| {
            let size_per_dir = dirs[0].1;
            let file_count = dirs[0].2;
            // Sorted as pairs, so each member's trust travels with its own pathname.
            let mut members: Vec<(PathBuf, DirTrust)> = dirs
                .into_iter()
                .map(|(dir, _, _, trust)| (dir, trust))
                .collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            let trust = if members.iter().all(|(_, t)| *t == DirTrust::Trusted) {
                DirTrust::Trusted
            } else {
                DirTrust::Untrusted
            };
            let (paths, member_trust): (Vec<PathBuf>, Vec<DirTrust>) = members.into_iter().unzip();
            AttributedDirGroup {
                group: DirGroup {
                    id: 0,
                    signature,
                    paths,
                    file_count,
                    size_per_dir,
                },
                member_trust,
                trust,
            }
        })
        .collect();
    sort_attributed_by_benefit(&mut groups);
    Ok(groups)
}

/// hex-encoding of hash bytes (the single source for the whole project).
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The signature of a directory's contents: blake3 of the SORTED list
/// `(relative path, file hex hash)`. Two directories with the same tree
/// (same relative paths and hashes) get the same signature. A pure
/// function — the single core for `build_dir_groups` and `store::dir_signatures_under`.
pub fn signature_of(entries: &[(String, String)]) -> String {
    let mut entries = entries.to_vec();
    entries.sort();
    let mut hasher = blake3::Hasher::new();
    for (rel, hash) in &entries {
        hasher.update(rel.as_bytes());
        hasher.update(&[0]);
        hasher.update(hash.as_bytes());
        hasher.update(&[0]);
    }
    hasher.finalize().to_hex().to_string()
}

/// Builds groups of duplicate directories from a list of hashed files
/// `(path, size, hex hash)`. A directory gets a signature from its subtree;
/// directories with the same signature and count >= 2 form a group.
/// A pure function — tested without a DB.
/// Compatibility wrapper: today's signature and today's output, delegating through the explicit
/// unbounded, nothing-trusted context. Byte-, membership- and order-identical to the pre-R3C
/// build, including its above-root output and relative or `..`-spelled inputs.
pub fn build_dir_groups(files: &[(PathBuf, u64, Option<String>)]) -> Vec<DirGroup> {
    build_dir_groups_in_context(files, &LegacyContext)
        .expect("the unbounded context puts no file outside a root")
        .into_iter()
        .map(|attributed| attributed.group)
        .collect()
}

/// Directory-signature algorithm (the `ScanConfig.dir_sig_algo` field).
/// `Old` — the current top-down `build_dir_groups` (the default). `Merkle` —
/// a streaming walk with O(depth) memory (see `build_dir_signatures_streaming`).
/// Both produce IDENTICAL equivalence classes (group memberships); per-row
/// hex values differ. `#[serde(other)]` is NOT needed — for old
/// checkpoints `#[serde(default)]` on the `ScanConfig.dir_sig_algo` field will kick in
/// (→ `Old`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DirSigAlgo {
    /// Default: top-down — `build_dir_groups` collects all `(rel_path, file_hash)`
    /// under each directory and hashes them. Peak memory ≈ 2.5 KiB/file × depth.
    #[default]
    Old,
    /// Opt-in (the `--merkle-dirs` flag): streaming bottom-up Merkle — memory
    /// O(depth × width of the current path). See `build_dir_signatures_streaming`.
    Merkle,
}

/// Streaming bottom-up Merkle dir-signatures. Reads `files` in
/// path-sorted order (ASC by `path`); keeps a stack of open
/// ancestors (one entry per level); emit is called on the CLOSING of a
/// directory (when the cursor leaves its subtree) and at EOF.
///
/// Each directory's signature = `signature_of(sorted [(basename(child), child_sig)])`,
/// where `child_sig` = `file_hash_hex` for a file, `MerkleSig` for a subdirectory.
/// The group membership is identical to `build_dir_groups`. The per-row hex values
/// differ (Merkle vs top-down).
///
/// Memory: the stack is O(depth); each frame holds the `(basename, hash)` of its DIRECT
/// children. At EOF the stack is merged bottom-up.
///
/// `emit(path, sig, total_size, file_count)` — a callback: called on the CLOSING of
/// each directory; the caller usually streams into `materialize_dir_groups`.
/// Errors from `emit` are propagated.
pub fn build_dir_signatures_streaming<I, F>(files: I, mut emit: F) -> Result<()>
where
    I: IntoIterator<Item = (PathBuf, u64, Option<String>)>,
    F: FnMut(PathBuf, String, u64, u32) -> Result<()>,
{
    // The unbounded, nothing-trusted context reproduces the pre-R3C walk exactly, including the
    // ancestors it opens up to the filesystem root. The trust value is dropped here, deliberately
    // and in one named place, so the existing four-argument producer is unaffected.
    build_dir_signatures_streaming_in_context(files, &LegacyContext, |signature| {
        emit(
            signature.path,
            signature.signature,
            signature.size,
            signature.file_count,
        )
    })
}

/// Marker-aware streaming Merkle: the same bottom-up walk, bounded to the selected roots.
///
/// Frames are opened from the owning root downward and never from the filesystem root. That is
/// deliberate rather than filtering at emit time: an above-root frame, once created, still absorbs
/// its children's `(basename, signature)` pairs and their incompleteness, so filtering it later
/// would leave it contaminating exactly what root bounding exists to prevent.
///
/// Moving between roots flushes every frame first, so no frame is ever shared and neither
/// suppression nor trust can leak from one root into another. Sorted input keeps a root's files
/// contiguous, so this happens at most once per root.
///
/// Retained directory state is the frame stack plus whatever the supplied context owns — there is
/// no candidate-directory index anywhere in this function or its signature.
#[allow(dead_code)]
pub fn build_dir_signatures_streaming_in_context<I, F>(
    files: I,
    ctx: &dyn SignatureContext,
    mut emit: F,
) -> Result<()>
where
    I: IntoIterator<Item = (PathBuf, u64, Option<String>)>,
    F: FnMut(DirSignature) -> Result<()>,
{
    struct Frame {
        path: PathBuf,
        entries: Vec<(String, String)>,
        size: u64,
        count: u32,
        incomplete: bool,
    }
    let mut stack: Vec<Frame> = Vec::new();
    // The bound the open frames belong to. `None` is unbounded, which only `LegacyContext` gives.
    let mut bound: Option<PathBuf> = None;
    let mut bound_set = false;

    // A frame that is NOT emitted always marks its parent incomplete, whatever kept it from being
    // emitted. That is an invariant of the algorithm rather than a policy: the parent's signature
    // is built from its children's signatures, so a missing child would otherwise make the parent
    // hash as if that subtree had never existed.
    let mut close = |stack: &mut Vec<Frame>, popped: Frame| -> Result<()> {
        let trust = match ctx.disposition(&popped.path) {
            DirDisposition::Suppressed => None,
            DirDisposition::Trusted => Some(DirTrust::Trusted),
            DirDisposition::Untrusted => Some(DirTrust::Untrusted),
        };
        let Some(trust) = trust.filter(|_| !popped.incomplete) else {
            if let Some(parent) = stack.last_mut() {
                parent.incomplete = true;
            }
            return Ok(());
        };
        let sig = signature_of(&popped.entries);
        emit(DirSignature {
            path: popped.path.clone(),
            signature: sig.clone(),
            size: popped.size,
            file_count: popped.count,
            trust,
        })?;
        if let Some(parent) = stack.last_mut() {
            let basename = popped
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            parent.entries.push((basename, sig));
            parent.size += popped.size;
            parent.count += popped.count;
        }
        Ok(())
    };

    for (path, size, hash_hex) in files {
        let scope = ctx.scope(&path);
        if matches!(scope, DirScope::Outside) {
            return Err(outside_every_root(&path));
        }
        let file_bound = match scope {
            DirScope::Root(root) => Some(PathBuf::from(root.as_str())),
            _ => None,
        };
        // Root transition: everything open belongs to the previous root, so it all closes first.
        if bound_set && file_bound != bound {
            while let Some(popped) = stack.pop() {
                close(&mut stack, popped)?;
            }
        }
        bound = file_bound;
        bound_set = true;

        while let Some(top) = stack.last() {
            if path.starts_with(&top.path) {
                break;
            }
            let popped = stack.pop().expect("non-empty by the while condition");
            close(&mut stack, popped)?;
        }
        let mut parent_dirs: Vec<PathBuf> = accountable_ancestors(&path, scope)
            .into_iter()
            .map(|p| p.to_path_buf())
            .collect();
        parent_dirs.reverse(); // root first
        for dir in parent_dirs {
            if stack.iter().any(|frame| frame.path == dir) {
                continue;
            }
            note_frame(&dir);
            stack.push(Frame {
                path: dir,
                entries: Vec::new(),
                size: 0,
                count: 0,
                incomplete: false,
            });
        }
        if let Some(top) = stack.last_mut() {
            match hash_hex {
                Some(h) => {
                    let basename = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    top.entries.push((basename, h));
                    top.size += size;
                    top.count += 1;
                }
                None => top.incomplete = true,
            }
        }
    }
    while let Some(popped) = stack.pop() {
        close(&mut stack, popped)?;
    }
    Ok(())
}

// Test-only: which frames the streaming build ever opened. «No above-root frame» is a claim about
// creation, not about emission — a frame that exists absorbs its children's signatures and their
// incompleteness even if it is never emitted — so proving it needs the frames themselves. Absent
// from every non-test build.
#[cfg(test)]
thread_local! {
    static FRAMES_OPENED: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(not(test))]
fn note_frame(_dir: &Path) {}

#[cfg(test)]
fn note_frame(dir: &Path) {
    FRAMES_OPENED.with(|opened| opened.borrow_mut().push(dir.to_path_buf()));
}

/// Records every frame the next build opens, clearing on construction and on drop.
#[cfg(test)]
struct FrameLog;

#[cfg(test)]
impl FrameLog {
    fn start() -> Self {
        FRAMES_OPENED.with(|opened| opened.borrow_mut().clear());
        FrameLog
    }

    fn opened(&self) -> Vec<PathBuf> {
        FRAMES_OPENED.with(|opened| opened.borrow().clone())
    }
}

#[cfg(test)]
impl Drop for FrameLog {
    fn drop(&mut self) {
        FRAMES_OPENED.with(|opened| opened.borrow_mut().clear());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A group of `files` pathnames, each its own allocation with exactly one link.
    fn group(id: usize, size: u64, files: usize) -> DuplicateGroup {
        DuplicateGroup {
            id,
            size_bytes: size,
            hash: format!("h{id}"),
            files: (0..files)
                .map(|n| FileEntry {
                    path: PathBuf::from(format!("/f{id}_{n}")),
                    size,
                    inode: n as u64,
                    nlink: 1,
                    ..Default::default()
                })
                .collect(),
        }
    }

    /// Aliases of one allocation are one allocation, however many pathnames point at them.
    #[test]
    fn a_group_counts_allocations_not_pathnames() {
        let mut aliases = group(0, 100, 3);
        for file in &mut aliases.files {
            file.inode = 7;
            file.nlink = 3;
        }
        let reclaim = aliases.physical_reclaim().unwrap();
        assert_eq!(reclaim.observed_paths, 3);
        assert_eq!(reclaim.object_count, 1, "one inode, one allocation");
        assert_eq!(reclaim.total_links, LinkCount::Known(3), "counted once");
        assert_eq!(
            reclaim.estimate.guaranteed_bytes(),
            0,
            "keeping the one allocation frees nothing"
        );
    }

    /// The same inode number with a different temporal identity is a different allocation — the
    /// complete key is what rejects inode reuse.
    #[test]
    fn the_temporal_key_separates_a_reused_inode() {
        let mut reused = group(0, 100, 2);
        reused.files[0].inode = 7;
        reused.files[1].inode = 7;
        reused.files[1].ctime_sec = 999;
        let reclaim = reused.physical_reclaim().unwrap();
        assert_eq!(
            reclaim.object_count, 2,
            "same (device, inode), different ctime: two allocations"
        );
        assert_eq!(reclaim.estimate.guaranteed_bytes(), 100);
    }

    /// Two pathnames of one inode cannot report two different link counts, and which of them the
    /// grouping happened to meet first must make no difference. Keeping the first and ignoring the
    /// rest is what let a corrupt manifest publish an exact figure.
    #[test]
    fn aliases_that_disagree_about_the_link_count_refuse_in_either_order() {
        for (first, second) in [(2u64, 1u64), (1, 2)] {
            let mut aliases = group(0, 100, 3);
            aliases.files[0].inode = 7;
            aliases.files[0].nlink = first;
            aliases.files[1].inode = 7;
            aliases.files[1].nlink = second;
            // A third, independent object, so the group is a real one and the refusal cannot be
            // mistaken for «not a duplicate group».
            aliases.files[2].inode = 9;
            aliases.files[2].nlink = 1;
            let err = aliases
                .physical_reclaim()
                .expect_err("disagreeing aliases must not produce a figure");
            assert!(
                err.to_string().contains("different link counts (1 and 2)"),
                "the message names both counts, in a stable order: {err}"
            );
        }
    }

    /// An unrecorded count against a real one is a disagreement too: half a manifest is not a
    /// measurement, and reading the recorded half as the truth is how an unmeasured allocation
    /// acquires an exact figure.
    #[test]
    fn an_unrecorded_count_beside_a_real_one_refuses_in_either_order() {
        for (first, second) in [(0u64, 1u64), (1, 0)] {
            let mut aliases = group(0, 100, 3);
            aliases.files[0].inode = 7;
            aliases.files[0].nlink = first;
            aliases.files[1].inode = 7;
            aliases.files[1].nlink = second;
            aliases.files[2].inode = 9;
            aliases.files[2].nlink = 1;
            let err = aliases
                .physical_reclaim()
                .expect_err("an unrecorded count beside a real one must not produce a figure");
            assert!(
                err.to_string()
                    .contains("different link counts (unrecorded and 1)"),
                "the message admits which half is missing: {err}"
            );
        }
    }

    /// The message names the object's own smallest pathname, whatever order its aliases arrived
    /// in — so two runs over the same damaged manifest read identically.
    #[test]
    fn the_refusal_names_the_objects_smallest_pathname() {
        let mut aliases = group(0, 100, 3);
        aliases.files[0].path = PathBuf::from("/x/zebra");
        aliases.files[0].inode = 7;
        aliases.files[0].nlink = 2;
        aliases.files[1].path = PathBuf::from("/x/alpha");
        aliases.files[1].inode = 7;
        aliases.files[1].nlink = 1;
        aliases.files[2].inode = 9;
        aliases.files[2].nlink = 1;
        let err = aliases.physical_reclaim().unwrap_err().to_string();
        assert!(err.contains("/x/alpha"), "{err}");
        assert!(!err.contains("/x/zebra"), "{err}");
    }

    /// The control the refusal must not swallow: aliases that agree are still an ordinary
    /// fully observed allocation.
    #[test]
    fn aliases_that_agree_are_untouched_by_the_check() {
        let mut aliases = group(0, 100, 3);
        for index in 0..2 {
            aliases.files[index].inode = 7;
            aliases.files[index].nlink = 2;
        }
        aliases.files[2].inode = 9;
        aliases.files[2].nlink = 1;
        let reclaim = aliases.physical_reclaim().unwrap();
        assert_eq!((reclaim.observed_paths, reclaim.object_count), (3, 2));
        assert_eq!(reclaim.total_links, LinkCount::Known(3));
        assert_eq!(reclaim.estimate.guaranteed_bytes(), 100);
    }

    /// Independent copies are exactly the case the old pathname formula got right, and it must
    /// keep getting it right.
    #[test]
    fn independent_copies_still_free_one_allocation_each() {
        let reclaim = group(1, 100, 3).physical_reclaim().unwrap();
        assert_eq!(reclaim.object_count, 3);
        assert_eq!(reclaim.estimate.guaranteed_bytes(), 200);
        assert_eq!(
            reclaim.estimate.state(),
            crate::model::reclaim::ReclaimState::Exact
        );
    }

    #[test]
    fn dir_group_reclaimable() {
        let g = DirGroup {
            id: 0,
            signature: "s".into(),
            paths: vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c"),
            ],
            file_count: 4,
            size_per_dir: 100,
        };
        // keep one of three → free 2 × 100.
        assert_eq!(g.reclaimable_bytes(), 200);
    }

    // ---------------------------------------------------------------------------------------
    // R3C: marker-aware builds.
    // ---------------------------------------------------------------------------------------

    use crate::model::omission::{
        CompletenessSnapshot, OmissionReason, SnapshotOutcome, StoredOmission,
    };

    fn files(spec: &[(&str, u64, Option<&str>)]) -> Vec<(PathBuf, u64, Option<String>)> {
        spec.iter()
            .map(|(p, s, h)| (PathBuf::from(p), *s, h.map(str::to_string)))
            .collect()
    }

    fn row(root: &str, dir: &str, reason: &str, count: i64, generation: i64) -> StoredOmission {
        StoredOmission {
            root_key: root.to_string(),
            dir_key: dir.to_string(),
            reason: reason.to_string(),
            event_count: count,
            generation,
        }
    }

    /// A bounded snapshot, or a panic naming the unavailable reason.
    fn snap(
        roots: &[&str],
        gens: &[(&str, i64)],
        rows: Vec<StoredOmission>,
    ) -> CompletenessSnapshot {
        let configured: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
        let registered = gens.iter().map(|(k, g)| (k.to_string(), *g)).collect();
        match CompletenessSnapshot::build(&configured, registered, rows).unwrap() {
            SnapshotOutcome::Bounded(snapshot) => snapshot,
            SnapshotOutcome::Unavailable(why) => panic!("expected a bounded snapshot: {why:?}"),
        }
    }

    /// Every directory the streaming build emitted, with its trust, sorted.
    fn merkle(
        input: Vec<(PathBuf, u64, Option<String>)>,
        ctx: &dyn SignatureContext,
    ) -> Result<Vec<(String, DirTrust)>> {
        let mut out = Vec::new();
        build_dir_signatures_streaming_in_context(input, ctx, |sig| {
            out.push((sig.path.to_string_lossy().into_owned(), sig.trust));
            Ok(())
        })?;
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn emitted_paths(rows: &[(String, DirTrust)]) -> Vec<&str> {
        rows.iter().map(|(p, _)| p.as_str()).collect()
    }

    /// Group memberships, sorted — the equivalence classes both algorithms must agree on.
    fn old_memberships(groups: &[AttributedDirGroup]) -> Vec<Vec<String>> {
        let mut out: Vec<Vec<String>> = groups
            .iter()
            .map(|g| {
                g.group
                    .paths
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect()
            })
            .collect();
        out.sort();
        out
    }

    const TWINS: &[(&str, u64, Option<&str>)] = &[
        ("/r/left/a.bin", 10, Some("aa")),
        ("/r/left/b.bin", 20, Some("bb")),
        ("/r/right/a.bin", 10, Some("aa")),
        ("/r/right/b.bin", 20, Some("bb")),
    ];

    /// Positive control: complete twins under a trusted root group, and are trusted.
    #[test]
    fn complete_twins_group_and_are_trusted() {
        let ctx = snap(&["/r"], &[("/r", 1)], Vec::new());
        let groups = build_dir_groups_in_context(&files(TWINS), &ctx).unwrap();
        assert_eq!(
            old_memberships(&groups),
            vec![vec!["/r/left".to_string(), "/r/right".to_string()]]
        );
        assert_eq!(groups[0].trust, DirTrust::Trusted);
        assert_eq!(
            groups[0].member_trust,
            vec![DirTrust::Trusted, DirTrust::Trusted]
        );
        let emitted = merkle(files(TWINS), &ctx).unwrap();
        assert_eq!(emitted_paths(&emitted), vec!["/r", "/r/left", "/r/right"]);
        assert!(emitted.iter().all(|(_, t)| *t == DirTrust::Trusted));
    }

    /// Every reason suppresses its own directory and every ancestor through the root — from the
    /// ledger's own subtree aggregation, with no second upward pass.
    #[test]
    fn every_reason_suppresses_through_the_root() {
        for reason in OmissionReason::ALL {
            let ctx = snap(
                &["/r"],
                &[("/r", 1)],
                vec![row("/r", "/r/left", reason.as_str(), 1, 1)],
            );
            let groups = build_dir_groups_in_context(&files(TWINS), &ctx).unwrap();
            assert!(
                groups.is_empty(),
                "{reason:?}: the left side must lose its twin claim"
            );
            let emitted = merkle(files(TWINS), &ctx).unwrap();
            assert_eq!(
                emitted_paths(&emitted),
                vec!["/r/right"],
                "{reason:?}: only the untouched sibling survives; the root is suppressed too"
            );
        }
    }

    /// A root-wide `walk_error` sentinel suppresses the whole root and leaves a second root alone.
    #[test]
    fn a_root_sentinel_suppresses_its_whole_root_only() {
        let input = files(&[
            ("/a/one/x.bin", 10, Some("aa")),
            ("/a/two/x.bin", 10, Some("aa")),
            ("/b/one/x.bin", 10, Some("aa")),
            ("/b/two/x.bin", 10, Some("aa")),
        ]);
        let ctx = snap(
            &["/a", "/b"],
            &[("/a", 1), ("/b", 1)],
            vec![row("/a", "/a", "walk_error", 1, 1)],
        );
        let emitted = merkle(input.clone(), &ctx).unwrap();
        assert!(
            emitted.iter().all(|(p, _)| p.starts_with("/b")),
            "nothing of root /a may be emitted: {emitted:?}"
        );
        let groups = build_dir_groups_in_context(&input, &ctx).unwrap();
        assert_eq!(
            old_memberships(&groups),
            vec![vec!["/b/one".to_string(), "/b/two".to_string()]]
        );
    }

    /// No frame is ever CREATED above a selected root, which is stronger than not emitting one: a
    /// created frame would still absorb its children's signatures and their incompleteness.
    #[test]
    fn no_above_root_frame_is_ever_created() {
        let ctx = snap(&["/r/inner"], &[("/r/inner", 1)], Vec::new());
        let input = files(&[
            ("/r/inner/a/x.bin", 10, Some("aa")),
            ("/r/inner/b/x.bin", 10, Some("aa")),
        ]);
        let log = FrameLog::start();
        let emitted = merkle(input, &ctx).unwrap();
        let opened: Vec<String> = log
            .opened()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            opened,
            vec![
                "/r/inner".to_string(),
                "/r/inner/a".to_string(),
                "/r/inner/b".to_string()
            ],
            "frames open from the root downward only"
        );
        assert!(emitted.iter().all(|(p, _)| p.starts_with("/r/inner")));
    }

    /// Two disjoint roots: every frame of the first closes before the second opens, no common
    /// frame exists above them, and neither suppression nor trust crosses.
    #[test]
    fn multiple_roots_flush_between_transitions() {
        let input = files(&[
            ("/a/one/x.bin", 10, Some("aa")),
            ("/a/two/x.bin", 10, Some("aa")),
            ("/b/one/x.bin", 10, Some("aa")),
            ("/b/two/x.bin", 10, Some("aa")),
        ]);
        let ctx = snap(
            &["/a", "/b"],
            &[("/a", 1), ("/b", 1)],
            vec![row("/a", "/a/one", "min_size", 1, 1)],
        );
        let log = FrameLog::start();
        let emitted = merkle(input.clone(), &ctx).unwrap();
        let opened: Vec<String> = log
            .opened()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert!(
            !opened.iter().any(|p| p == "/"),
            "no common frame above the two roots: {opened:?}"
        );
        assert_eq!(
            emitted_paths(&emitted),
            vec!["/a/two", "/b", "/b/one", "/b/two"],
            "/a and /a/one are suppressed; root /b is untouched"
        );
        let groups = build_dir_groups_in_context(&input, &ctx).unwrap();
        assert_eq!(
            old_memberships(&groups),
            vec![vec![
                "/a/two".to_string(),
                "/b/one".to_string(),
                "/b/two".to_string()
            ]],
            "the survivors group by content, and Old agrees with Merkle"
        );
    }

    /// A manifest file under no selected root is refused by BOTH builders, never silently dropped.
    #[test]
    fn a_file_outside_every_root_is_refused() {
        let ctx = snap(&["/r"], &[("/r", 1)], Vec::new());
        let input = files(&[
            ("/r/a.bin", 10, Some("aa")),
            ("/elsewhere/b.bin", 10, Some("bb")),
        ]);
        let old = build_dir_groups_in_context(&input, &ctx)
            .expect_err("Old must refuse an outside file")
            .to_string();
        assert!(old.contains("/elsewhere/b.bin"), "{old}");
        let streamed = match merkle(input, &ctx) {
            Err(err) => err.to_string(),
            Ok(rows) => panic!("Merkle must refuse an outside file, got {rows:?}"),
        };
        assert!(streamed.contains("/elsewhere/b.bin"), "{streamed}");
    }

    /// A selected regular-file root is valid input and yields no directory at all.
    #[test]
    fn a_regular_file_root_yields_no_directory() {
        let ctx = snap(&["/r/only.bin"], &[("/r/only.bin", 1)], Vec::new());
        let input = files(&[("/r/only.bin", 10, Some("aa"))]);
        assert!(build_dir_groups_in_context(&input, &ctx)
            .unwrap()
            .is_empty());
        let log = FrameLog::start();
        assert!(merkle(input, &ctx).unwrap().is_empty());
        assert!(log.opened().is_empty(), "no frame for a file root");
    }

    /// Root `/` keeps the absolute-path behavior: everything is in scope, nothing is above it.
    #[test]
    fn the_filesystem_root_bounds_everything() {
        let ctx = snap(&["/"], &[("/", 1)], Vec::new());
        let emitted = merkle(files(TWINS), &ctx).unwrap();
        assert_eq!(
            emitted_paths(&emitted),
            vec!["/", "/r", "/r/left", "/r/right"]
        );
    }

    /// A drifted registration and a generation of 0 stay ROOT-BOUNDED and answer untrusted — they
    /// do not become unbounded, so no above-root directory reappears.
    #[test]
    fn drift_and_generation_zero_stay_bounded_and_untrusted() {
        for ctx in [
            snap(&["/r"], &[("/r", 0)], Vec::new()),
            snap(&["/r"], &[("/other", 3)], Vec::new()),
        ] {
            let emitted = merkle(files(TWINS), &ctx).unwrap();
            assert_eq!(
                emitted_paths(&emitted),
                vec!["/r", "/r/left", "/r/right"],
                "still bounded to /r — nothing above it"
            );
            assert!(
                emitted.iter().all(|(_, t)| *t == DirTrust::Untrusted),
                "and nothing is trusted"
            );
            let groups = build_dir_groups_in_context(&files(TWINS), &ctx).unwrap();
            assert_eq!(groups[0].trust, DirTrust::Untrusted);
        }
    }

    /// Mixed member trust: the aggregate is conservative, and each member's trust travels with its
    /// own pathname through the sort.
    #[test]
    fn mixed_member_trust_is_conservatively_aggregated_and_ordered() {
        let input = files(&[("/zz/x.bin", 10, Some("aa")), ("/aa/x.bin", 10, Some("aa"))]);
        let ctx = snap(&["/aa", "/zz"], &[("/aa", 0), ("/zz", 1)], Vec::new());
        let groups = build_dir_groups_in_context(&input, &ctx).unwrap();
        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(
            group.group.paths,
            vec![PathBuf::from("/aa"), PathBuf::from("/zz")],
            "paths are sorted"
        );
        assert_eq!(
            group.member_trust,
            vec![DirTrust::Untrusted, DirTrust::Trusted],
            "and each member's trust followed its own path through the sort"
        );
        assert_eq!(
            group.member_trust.len(),
            group.group.paths.len(),
            "one trust per member, always"
        );
        assert_eq!(
            group.trust,
            DirTrust::Untrusted,
            "trusted only when every member is"
        );
    }

    /// The unhashed-file rule and the ledger compose as a union; neither undoes the other.
    #[test]
    fn unhashed_and_ledger_incompleteness_compose() {
        let unhashed = files(&[
            ("/r/left/a.bin", 10, Some("aa")),
            ("/r/left/u.bin", 10, None),
            ("/r/right/a.bin", 10, Some("aa")),
        ]);
        let clean = snap(&["/r"], &[("/r", 1)], Vec::new());
        assert!(
            build_dir_groups_in_context(&unhashed, &clean)
                .unwrap()
                .is_empty(),
            "an unhashed file still suppresses under a trusted ledger"
        );
        let both = snap(
            &["/r"],
            &[("/r", 1)],
            vec![row("/r", "/r/left", "min_size", 1, 1)],
        );
        assert!(build_dir_groups_in_context(&unhashed, &both)
            .unwrap()
            .is_empty());
        assert!(build_dir_groups_in_context(&files(TWINS), &both)
            .unwrap()
            .is_empty());
    }

    /// The compatibility wrappers keep the unbounded behavior, including for spellings a `PathKey`
    /// would refuse — a relative path and a `..`-spelled one. A fake root of `/` could not model
    /// this: neither spelling is under `/` component-wise.
    #[test]
    fn the_wrappers_stay_unbounded_for_relative_and_dotdot_spellings() {
        let awkward = files(&[
            ("rel/left/a.bin", 10, Some("aa")),
            ("rel/right/a.bin", 10, Some("aa")),
            ("/x/../x/left/a.bin", 10, Some("bb")),
            ("/x/../x/right/a.bin", 10, Some("bb")),
        ]);
        let groups = build_dir_groups(&awkward);
        let mut members: Vec<Vec<String>> = groups
            .iter()
            .map(|g| {
                g.paths
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect()
            })
            .collect();
        members.sort();
        assert_eq!(
            members,
            vec![
                vec!["/x/../x/left".to_string(), "/x/../x/right".to_string()],
                vec!["rel/left".to_string(), "rel/right".to_string()],
            ],
            "both spellings still group, exactly as a pre-R3C build does"
        );

        let attributed = build_dir_groups_in_context(&awkward, &LegacyContext).unwrap();
        assert_eq!(old_memberships(&attributed), members);
        assert!(attributed.iter().all(|g| g.trust == DirTrust::Untrusted));

        let mut emitted = Vec::new();
        build_dir_signatures_streaming(awkward, |path, _, _, _| {
            emitted.push(path.to_string_lossy().into_owned());
            Ok(())
        })
        .unwrap();
        assert!(
            emitted.iter().any(|p| p == "rel/left"),
            "the relative tree is walked: {emitted:?}"
        );
    }

    /// Old and Merkle agree on equivalence classes under an authoritative snapshot.
    #[test]
    fn old_and_merkle_agree_under_a_snapshot() {
        let input = files(&[
            ("/r/one/x.bin", 10, Some("aa")),
            ("/r/two/x.bin", 10, Some("aa")),
            ("/r/three/x.bin", 10, Some("bb")),
            ("/r/deep/a/b/x.bin", 10, Some("cc")),
        ]);
        let ctx = snap(
            &["/r"],
            &[("/r", 1)],
            vec![row("/r", "/r/deep/a/b", "unsupported_entry", 2, 1)],
        );
        let groups = build_dir_groups_in_context(&input, &ctx).unwrap();
        let emitted: Vec<String> = merkle(input, &ctx)
            .unwrap()
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(
            old_memberships(&groups),
            vec![vec!["/r/one".to_string(), "/r/two".to_string()]]
        );
        assert_eq!(
            emitted,
            vec![
                "/r/one".to_string(),
                "/r/three".to_string(),
                "/r/two".to_string()
            ],
            "the deep chain and the root are suppressed; untouched siblings survive"
        );
    }

    /// Degenerate inputs stay quiet.
    #[test]
    fn degenerate_inputs_are_quiet() {
        let ctx = snap(&["/r"], &[("/r", 1)], Vec::new());
        assert!(build_dir_groups_in_context(&[], &ctx).unwrap().is_empty());
        assert!(merkle(Vec::new(), &ctx).unwrap().is_empty());
        let one = files(&[("/r/only/x.bin", 10, Some("aa"))]);
        assert!(build_dir_groups_in_context(&one, &ctx).unwrap().is_empty());
        assert_eq!(merkle(one, &ctx).unwrap().len(), 2, "/r and /r/only");
    }

    #[test]
    fn build_dir_groups_finds_identical_trees() {
        // /x/a and /x/b — identical contents (f1,f2 with the same hashes);
        // /x/c — an extra file, a different signature.
        let files = vec![
            (PathBuf::from("/x/a/f1"), 100, Some("h1".to_string())),
            (PathBuf::from("/x/a/f2"), 200, Some("h2".to_string())),
            (PathBuf::from("/x/b/f1"), 100, Some("h1".to_string())),
            (PathBuf::from("/x/b/f2"), 200, Some("h2".to_string())),
            (PathBuf::from("/x/c/f1"), 100, Some("h1".to_string())),
        ];
        let groups = build_dir_groups(&files);
        // There should be at least the group {/x/a, /x/b}. /x (the root) contains
        // the whole tree and is unique, /x/c is unique.
        let ab = groups
            .iter()
            .find(|g| g.paths.contains(&PathBuf::from("/x/a")))
            .expect("group with /x/a");
        assert!(ab.paths.contains(&PathBuf::from("/x/b")));
        assert_eq!(ab.file_count, 2);
        assert_eq!(ab.size_per_dir, 300);
        assert_eq!(ab.reclaimable_bytes(), 300);
        // /x/c must not end up in any group with /x/a.
        assert!(!ab.paths.contains(&PathBuf::from("/x/c")));
    }

    // === Merkle streaming tests ===

    #[test]
    fn merkle_sig_matches_old_sig_for_leaf_only_dir() {
        // Induction base: a directory with file children on one level produces the SAME
        // hex in Old and Merkle (entries are the same `(basename, file_hash)` pairs).
        let files = vec![
            (PathBuf::from("/d/a"), 10, Some("AAA".to_string())),
            (PathBuf::from("/d/b"), 20, Some("BBB".to_string())),
        ];
        // The old path will not return a group for /d (needs ≥2 directories), but the signature
        // of /d we can compute directly via signature_of — it should match.
        let expected = signature_of(&[
            ("a".to_string(), "AAA".to_string()),
            ("b".to_string(), "BBB".to_string()),
        ]);
        let mut got: Option<String> = None;
        build_dir_signatures_streaming(files, |path, sig, _, _| {
            if path == Path::new("/d") {
                got = Some(sig);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(got.as_deref(), Some(expected.as_str()), "/d: Merkle == Old");
    }

    #[test]
    fn merkle_equivalence_with_build_dir_groups_on_synthetic_tree() {
        // Plan §A equivalence: both algorithms produce the SAME group membership
        // (sorted path-sets). The per-row hex may differ.
        let files = vec![
            (PathBuf::from("/a/x.bin"), 10, Some("H1".to_string())),
            (PathBuf::from("/a/y.bin"), 20, Some("H2".to_string())),
            (PathBuf::from("/b/x.bin"), 10, Some("H1".to_string())),
            (PathBuf::from("/b/y.bin"), 20, Some("H2".to_string())),
            (PathBuf::from("/c/z.bin"), 5, Some("H3".to_string())),
        ];
        // Old: only groups ≥2.
        let old_groups = build_dir_groups(&files);
        let mut old_membership: Vec<Vec<PathBuf>> = old_groups
            .iter()
            .map(|g| {
                let mut paths = g.paths.clone();
                paths.sort();
                paths
            })
            .collect();
        old_membership.sort();
        // Merkle: collect all sigs, group by signature, filter count>=2.
        let mut rows: Vec<(PathBuf, String)> = Vec::new();
        build_dir_signatures_streaming(files, |path, sig, _, _| {
            rows.push((path, sig));
            Ok(())
        })
        .unwrap();
        let mut by_sig: std::collections::HashMap<String, Vec<PathBuf>> =
            std::collections::HashMap::new();
        for (path, sig) in rows {
            by_sig.entry(sig).or_default().push(path);
        }
        let mut merkle_membership: Vec<Vec<PathBuf>> = by_sig
            .into_values()
            .filter(|paths| paths.len() >= 2)
            .map(|mut paths| {
                paths.sort();
                paths
            })
            .collect();
        merkle_membership.sort();
        assert_eq!(
            merkle_membership, old_membership,
            "group membership must match: Merkle={:?} vs Old={:?}",
            merkle_membership, old_membership
        );
    }

    #[test]
    fn merkle_root_level_file_emits_sig_for_slash() {
        let files = vec![(PathBuf::from("/foo.bin"), 10, Some("H".to_string()))];
        let mut order: Vec<PathBuf> = Vec::new();
        build_dir_signatures_streaming(files, |path, _, _, _| {
            order.push(path);
            Ok(())
        })
        .unwrap();
        assert_eq!(order, vec![PathBuf::from("/")]);
    }

    #[test]
    fn merkle_lcp_churn_basic() {
        // /x/y/* come in a row (close once together), then /x/z/3 → /x/y closes,
        // /x/z opens; at EOF /x/z and /x and / merge.
        let files = vec![
            (PathBuf::from("/x/y/1"), 1, Some("A".to_string())),
            (PathBuf::from("/x/y/2"), 1, Some("B".to_string())),
            (PathBuf::from("/x/z/3"), 1, Some("C".to_string())),
        ];
        let mut order: Vec<PathBuf> = Vec::new();
        build_dir_signatures_streaming(files, |path, _, _, _| {
            order.push(path);
            Ok(())
        })
        .unwrap();
        // /x/y closed first (when /x/z arrived), then /x/z, /x, / at EOF.
        assert_eq!(
            order,
            vec![
                PathBuf::from("/x/y"),
                PathBuf::from("/x/z"),
                PathBuf::from("/x"),
                PathBuf::from("/"),
            ]
        );
    }

    #[test]
    fn merkle_single_file_dir_emits_sig() {
        // A directory with a single child is still emitted; the count>=2 filter is on the
        // materialize_dir_groups side, not here.
        let files = vec![(PathBuf::from("/lonely/only.bin"), 1, Some("H".to_string()))];
        let mut sigs: Vec<(PathBuf, u64, u32)> = Vec::new();
        build_dir_signatures_streaming(files, |path, _, size, count| {
            sigs.push((path, size, count));
            Ok(())
        })
        .unwrap();
        let lonely = sigs.iter().find(|(p, _, _)| p == Path::new("/lonely"));
        assert!(lonely.is_some(), "/lonely is emitted");
        let (_, size, count) = lonely.unwrap();
        assert_eq!(*size, 1);
        assert_eq!(*count, 1);
    }

    // === The completeness rule for dir-signatures ===
    // A `None` hash in the model represents ANY scanned file without a committed
    // hash: unique-size (not hashed) OR a hash failure. Both reasons suppress
    // a directory the same way.

    /// Old group membership (sorted path-sets) — for cross-checking with Merkle.
    fn membership_old(files: &[(PathBuf, u64, Option<String>)]) -> Vec<Vec<PathBuf>> {
        let mut m: Vec<Vec<PathBuf>> = build_dir_groups(files)
            .iter()
            .map(|g| {
                let mut p = g.paths.clone();
                p.sort();
                p
            })
            .collect();
        m.sort();
        m
    }

    /// Merkle group membership (≥2 directories with one signature) — for cross-checking with Old.
    fn membership_merkle(files: Vec<(PathBuf, u64, Option<String>)>) -> Vec<Vec<PathBuf>> {
        use std::collections::HashMap;
        let mut sorted = files;
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut rows: Vec<(PathBuf, String)> = Vec::new();
        build_dir_signatures_streaming(sorted, |path, sig, _, _| {
            rows.push((path, sig));
            Ok(())
        })
        .unwrap();
        let mut by_sig: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for (path, sig) in rows {
            by_sig.entry(sig).or_default().push(path);
        }
        let mut m: Vec<Vec<PathBuf>> = by_sig
            .into_values()
            .filter(|p| p.len() >= 2)
            .map(|mut p| {
                p.sort();
                p
            })
            .collect();
        m.sort();
        m
    }

    #[test]
    fn unique_size_extra_file_suppresses_false_dir_twin() {
        // (6a) ORIGINAL DEFECT: /x/a and /x/b have identical HASHED contents
        // (f1,f2); /x/b ADDITIONALLY contains a unique-size file z without a hash. Before the fix z was
        // invisible to the signature → sig(/x/a) == sig(/x/b) → a FALSE twin. Now /x/b
        // is incomplete and suppressed — there is no false group.
        let files = vec![
            (PathBuf::from("/x/a/f1"), 100, Some("h1".to_string())),
            (PathBuf::from("/x/a/f2"), 200, Some("h2".to_string())),
            (PathBuf::from("/x/b/f1"), 100, Some("h1".to_string())),
            (PathBuf::from("/x/b/f2"), 200, Some("h2".to_string())),
            (PathBuf::from("/x/b/z"), 7, None), // unique-size: not hashed
        ];
        let groups = build_dir_groups(&files);
        assert!(
            !groups
                .iter()
                .any(|g| g.paths.contains(&PathBuf::from("/x/b"))),
            "/x/b is incomplete (unique-size z) → suppressed, no false twin"
        );
        assert!(
            !groups
                .iter()
                .any(|g| g.paths.contains(&PathBuf::from("/x/a"))),
            "/x/a without a complete pair → not in a group"
        );
        // Control: REMOVE z — /x/a and /x/b become complete and form a group.
        let complete = &files[..4];
        let g = build_dir_groups(complete);
        assert!(
            g.iter().any(|g| g.paths.contains(&PathBuf::from("/x/a"))
                && g.paths.contains(&PathBuf::from("/x/b"))),
            "(6b) without unique-size — an exact pair produces a group"
        );
    }

    #[test]
    fn nested_unhashed_file_invalidates_all_ancestors() {
        // (6d) an unhashed file DEEP DOWN makes ALL ancestor directories incomplete.
        // /p/a contains a deep file without a hash → /p/a, /p/a/sub and /p are incomplete and suppressed;
        // the complete neighbor /p/b is emitted. Old and Merkle are consistent.
        let files = vec![
            (PathBuf::from("/p/a/x"), 10, Some("h".to_string())),
            (PathBuf::from("/p/a/sub/deep"), 20, None), // deep, without a hash
            (PathBuf::from("/p/b/x"), 10, Some("h".to_string())),
        ];
        // Old: /p/a is suppressed.
        let groups = build_dir_groups(&files);
        assert!(
            !groups
                .iter()
                .any(|g| g.paths.contains(&PathBuf::from("/p/a"))),
            "Old: /p/a is incomplete (a nested file without a hash)"
        );
        // Merkle: /p/a, /p/a/sub, /p are suppressed; /p/b is emitted.
        let mut sorted = files.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut emitted: Vec<PathBuf> = Vec::new();
        build_dir_signatures_streaming(sorted, |path, _, _, _| {
            emitted.push(path);
            Ok(())
        })
        .unwrap();
        for suppressed in ["/p/a", "/p/a/sub", "/p"] {
            assert!(
                !emitted.contains(&PathBuf::from(suppressed)),
                "Merkle: {suppressed} is suppressed"
            );
        }
        assert!(
            emitted.contains(&PathBuf::from("/p/b")),
            "Merkle: /p/b is complete → emitted"
        );
    }

    #[test]
    fn old_and_merkle_agree_with_incomplete_dirs() {
        // (6e) with incomplete directories Old and Merkle produce the SAME group membership.
        let files = vec![
            // Complete pair /t/a ≡ /t/b.
            (PathBuf::from("/t/a/p"), 10, Some("H1".to_string())),
            (PathBuf::from("/t/a/q"), 20, Some("H2".to_string())),
            (PathBuf::from("/t/b/p"), 10, Some("H1".to_string())),
            (PathBuf::from("/t/b/q"), 20, Some("H2".to_string())),
            // /t/c looks like a twin, but has a unique-size file without a hash → incomplete.
            (PathBuf::from("/t/c/p"), 10, Some("H1".to_string())),
            (PathBuf::from("/t/c/q"), 20, Some("H2".to_string())),
            (PathBuf::from("/t/c/u"), 7, None),
        ];
        let old = membership_old(&files);
        let merkle = membership_merkle(files.clone());
        assert_eq!(
            merkle, old,
            "Old and Merkle are consistent with incomplete directories"
        );
        assert!(
            !old.iter().flatten().any(|p| p == &PathBuf::from("/t/c")),
            "/t/c is suppressed (incomplete) — not a false twin"
        );
        assert!(
            old.iter()
                .any(|g| g.contains(&PathBuf::from("/t/a")) && g.contains(&PathBuf::from("/t/b"))),
            "complete pair {{/t/a,/t/b}} — a group"
        );
    }
}
