// SPDX-License-Identifier: Apache-2.0
//! State of the multi-panel interface: panels and their contents.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crossbeam_channel::Sender;
use ratatui::widgets::ListState;

use crate::model::action::{ActionKind, PlannedAction};
use crate::model::duplicate::{DirGroup, DuplicateGroup};
use crate::model::scan::ResumeInfo;
use crate::state::GroupSummary;

use super::dedup::DedupCache;
use super::layout::max_panels;

/// Kind of an entry in a panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// The `..` entry — navigates up to the parent directory.
    Parent,
    Dir,
    File,
}

/// User mark on a file in a panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Selected,
    Keeper,
    Delete,
    Hardlink,
    Reflink,
}

impl Mark {
    /// Mark glyph for the panel column.
    pub fn glyph(self) -> char {
        match self {
            Mark::Selected => '*',
            Mark::Keeper => 'K',
            Mark::Delete => 'D',
            Mark::Hardlink => 'H',
            Mark::Reflink => 'C',
        }
    }

    /// Dedup action corresponding to the mark (for F11).
    pub fn action(self) -> Option<ActionKind> {
        match self {
            Mark::Delete => Some(ActionKind::Delete),
            Mark::Hardlink => Some(ActionKind::Hardlink),
            Mark::Reflink => Some(ActionKind::Reflink),
            Mark::Selected | Mark::Keeper => None,
        }
    }
}

/// Sort key for panel entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortKey {
    #[default]
    Name,
    Size,
    Type,
    Date,
}

impl SortKey {
    /// Next key in the cycle — for the `s` key.
    pub fn next(self) -> Self {
        match self {
            SortKey::Name => SortKey::Size,
            SortKey::Size => SortKey::Type,
            SortKey::Type => SortKey::Date,
            SortKey::Date => SortKey::Name,
        }
    }

    /// Short caption for the panel header.
    pub fn label(self) -> &'static str {
        match self {
            SortKey::Name => "name",
            SortKey::Size => "size",
            SortKey::Type => "type",
            SortKey::Date => "date",
        }
    }
}

/// Panel view mode — what it shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanelView {
    /// Files and directories — the ordinary navigator.
    #[default]
    Files,
    /// Directories only.
    DirsOnly,
    /// List of duplicate groups of the loaded scan.
    GroupList,
    /// Files of the group selected in the neighbouring GroupList panel on the left.
    GroupFiles,
    /// Duplicates of the file under the cursor of the source panel.
    DuplicatesOfCursor,
    /// List of duplicate-directory groups.
    DirGroupList,
    /// Directory paths of the group selected in the neighbouring DirGroupList on the left.
    DirGroupFiles,
}

impl PanelView {
    /// Next mode in the cycle — for the `v` key.
    pub fn next(self) -> Self {
        match self {
            PanelView::Files => PanelView::DirsOnly,
            PanelView::DirsOnly => PanelView::GroupList,
            PanelView::GroupList => PanelView::GroupFiles,
            PanelView::GroupFiles => PanelView::DuplicatesOfCursor,
            PanelView::DuplicatesOfCursor => PanelView::DirGroupList,
            PanelView::DirGroupList => PanelView::DirGroupFiles,
            PanelView::DirGroupFiles => PanelView::Files,
        }
    }

    /// Short mode caption for the panel header.
    pub fn label(self) -> &'static str {
        match self {
            PanelView::Files => "files",
            PanelView::DirsOnly => "directories",
            PanelView::GroupList => "groups",
            PanelView::GroupFiles => "group files",
            PanelView::DuplicatesOfCursor => "duplicates",
            PanelView::DirGroupList => "directory groups",
            PanelView::DirGroupFiles => "group directories",
        }
    }
}

/// A single directory entry.
#[derive(Debug, Clone)]
pub struct PanelEntry {
    pub path: PathBuf,
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: i64,
    pub device: u64,
    pub inode: u64,
}

impl PanelEntry {
    /// A directory or `..` — can be entered with Enter.
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, EntryKind::Dir | EntryKind::Parent)
    }
}

/// A single panel — an independent navigator over the real filesystem.
#[derive(Debug, Clone)]
pub struct Panel {
    pub cwd: PathBuf,
    pub entries: Vec<PanelEntry>,
    pub list: ListState,
    /// File marks by absolute path — survive moving to another directory.
    pub marks: HashMap<PathBuf, Mark>,
    /// Directory is being read in the background — UI shows "loading…".
    pub loading: bool,
    /// Navigation counter: a background result with a stale `generation`
    /// is discarded (the user has already moved to another directory).
    pub generation: u64,
    /// Sort key for panel entries.
    pub sort: SortKey,
    /// Panel view mode — what it shows.
    pub view: PanelView,
}

impl Panel {
    /// Creates a panel in directory `start` (falls back to the FS root if unavailable).
    ///
    /// Used only for the initial startup setup (`CommanderState::new`),
    /// when the background reader worker does not yet exist. To add a panel
    /// at runtime use `Panel::empty` + asynchronous loading via
    /// `reload_panel` — otherwise a slow directory (e.g. `/mnt`) hangs
    /// the UI for tens of seconds.
    pub fn new(start: PathBuf) -> Self {
        let mut panel = Self::empty(PathBuf::from("/"));
        panel.load_sync(start);
        if panel.entries.is_empty() {
            panel.load_sync(PathBuf::from("/"));
        }
        panel
    }

    /// Creates an empty panel with `cwd = start` and `loading = true`. No I/O:
    /// the content is filled by the background worker on a `reload_panel` /
    /// `navigate_panel` request. Used when adding a panel dynamically.
    pub fn empty(start: PathBuf) -> Self {
        Self {
            cwd: start,
            entries: Vec::new(),
            list: ListState::default(),
            marks: HashMap::new(),
            loading: true,
            generation: 0,
            sort: SortKey::Name,
            view: PanelView::Files,
        }
    }

    /// Index of the current entry under the cursor.
    pub fn cursor(&self) -> usize {
        self.list.selected().unwrap_or(0)
    }

    /// The entry under the cursor.
    pub fn selected(&self) -> Option<&PanelEntry> {
        self.entries.get(self.cursor())
    }

    /// Moves the cursor by `delta` within the entry list.
    pub fn move_cursor(&mut self, delta: i32) {
        self.move_cursor_within(delta, self.entries.len());
    }

    /// Moves the cursor by `delta` in a list of length `len` (panel
    /// modes may show a list of a different length than `entries`).
    pub fn move_cursor_within(&mut self, delta: i32, len: usize) {
        if len == 0 {
            self.list.select(None);
            return;
        }
        let last = len as i32 - 1;
        let next = (self.cursor() as i32 + delta).clamp(0, last);
        self.list.select(Some(next as usize));
    }

    /// Places the cursor on the entry at index `index`.
    pub fn select(&mut self, index: usize) {
        self.select_within(index, self.entries.len());
    }

    /// Places the cursor on `index` in a list of length `len`.
    pub fn select_within(&mut self, index: usize, len: usize) {
        if len == 0 {
            self.list.select(None);
        } else {
            self.list.select(Some(index.min(len - 1)));
        }
    }

    /// Synchronously reads directory `target` — only for the initial startup
    /// setup of a panel (`Panel::new`). Runtime navigation is asynchronous (`navigate_panel`).
    fn load_sync(&mut self, target: PathBuf) {
        if !target.is_dir() {
            return;
        }
        let previous = std::mem::replace(&mut self.cwd, target);
        self.entries = read_panel_dir(&self.cwd);
        sort_entries(&mut self.entries, self.sort);
        let index = self
            .entries
            .iter()
            .position(|entry| entry.path == previous)
            .unwrap_or(0);
        self.select(index);
        self.loading = false;
    }
}

/// Reads directory `dir`: the `..` entry, then directories, then files (alphabetically).
///
/// Uses a direct `libc::lstat` (== `newfstatat AT_SYMLINK_NOFOLLOW`) instead of
/// `std::fs::DirEntry::metadata()`. The std wrapper calls
/// `statx(... STATX_ALL | AT_STATX_SYNC_AS_STAT)` — it requests every field and
/// forces the kernel to sync with the server; on unreachable CIFS mounts
/// this yields a network timeout of ~6 s per entry. `lstat` returns the kernel
/// cache from the parent readdir instantly (from cache).
pub fn read_panel_dir(dir: &Path) -> Vec<PanelEntry> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut bench = crate::bench::start("read_panel_dir").attach_dir(dir);
    let mut dirs: Vec<PanelEntry> = Vec::new();
    let mut files: Vec<PanelEntry> = Vec::new();

    let read_result = std::fs::read_dir(dir);
    if read_result.is_err() {
        bench.fail();
    }
    if let Ok(read) = read_result {
        for entry in read.flatten() {
            let path = entry.path();
            // Direct lstat bypassing the std wrapper (which does statx STATX_ALL
            // and hangs on CIFS mounts with an unreachable server).
            let cpath = match CString::new(path.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::lstat(cpath.as_ptr(), &mut st) };
            if rc != 0 {
                continue;
            }
            let kind = if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let item = PanelEntry {
                path,
                name: entry.file_name().to_string_lossy().into_owned(),
                kind,
                size: st.st_size as u64,
                mtime: st.st_mtime as i64,
                device: st.st_dev as u64,
                inode: st.st_ino as u64,
            };
            match kind {
                EntryKind::Dir => dirs.push(item),
                _ => files.push(item),
            }
        }
    }

    dirs.sort_by(|a, b| a.name.cmp(&b.name));
    files.sort_by(|a, b| a.name.cmp(&b.name));

    let mut out = Vec::with_capacity(dirs.len() + files.len() + 1);
    if let Some(parent) = dir.parent() {
        out.push(PanelEntry {
            path: parent.to_path_buf(),
            name: "..".to_string(),
            kind: EntryKind::Parent,
            size: 0,
            mtime: 0,
            device: 0,
            inode: 0,
        });
    }
    out.extend(dirs);
    out.extend(files);
    bench.set_entries(out.len() as u64);
    out
}

/// Sorts panel entries: `..` first, directories above files, within groups —
/// by the `sort` key.
pub fn sort_entries(entries: &mut [PanelEntry], sort: SortKey) {
    entries.sort_by(|a, b| {
        kind_rank(a.kind)
            .cmp(&kind_rank(b.kind))
            .then_with(|| compare_by(a, b, sort))
    });
}

/// Rank of an entry kind: `..` (0) above directories (1), directories — above files (2).
fn kind_rank(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::Parent => 0,
        EntryKind::Dir => 1,
        EntryKind::File => 2,
    }
}

/// Compares entries of the same rank by the sort key. Size and Date — in
/// descending order (large/recent on top); ties broken by name.
fn compare_by(a: &PanelEntry, b: &PanelEntry, sort: SortKey) -> std::cmp::Ordering {
    match sort {
        SortKey::Name => a.name.cmp(&b.name),
        SortKey::Size => b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)),
        SortKey::Date => b.mtime.cmp(&a.mtime).then_with(|| a.name.cmp(&b.name)),
        SortKey::Type => {
            let ext = |entry: &PanelEntry| {
                Path::new(&entry.name)
                    .extension()
                    .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default()
            };
            ext(a).cmp(&ext(b)).then_with(|| a.name.cmp(&b.name))
        }
    }
}

/// Where to route the result of a background directory load (Triage Board):
/// a panel of the old commander, the Board source, or one of the 4 Board receivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadTarget {
    Commander(usize),
    BoardSource,
    BoardReceiver(usize),
}

/// Request to the background worker: read directory `dir` for the `target` addressee.
/// `generation` — the navigation version (a stale response is discarded),
/// `previous` — the path to return the cursor to after loading.
#[derive(Debug, Clone)]
pub struct PanelLoadRequest {
    pub target: LoadTarget,
    pub generation: u64,
    pub dir: PathBuf,
    pub previous: Option<PathBuf>,
}

/// Request to the single background move worker: a batch of `sources` →
/// `dest_dir`. The worker processes requests ONE AT A TIME (serialization — parallel
/// copies don't hammer the disk, no races between batches). `reload`/`label` — for
/// applying the result to the UI after completion; `scan_id` — for the journal.
#[derive(Debug, Clone)]
pub struct MoveRequest {
    pub sources: Vec<PathBuf>,
    pub dest_dir: PathBuf,
    pub scan_id: Option<i64>,
    pub reload: Vec<(LoadTarget, Option<PathBuf>)>,
    pub label: String,
}

/// Applies the result of a background directory load to panel `p`: checks
/// `generation` (a stale response is discarded), the DirsOnly mode filter,
/// sorting, and restoring the cursor to `previous`. Shared code for commander
/// and Board panels.
pub fn apply_panel_load(
    p: &mut Panel,
    generation: u64,
    entries: Vec<PanelEntry>,
    previous: Option<PathBuf>,
) {
    if p.generation != generation {
        return;
    }
    p.entries = entries;
    if p.view == PanelView::DirsOnly {
        p.entries.retain(|entry| entry.is_dir());
    }
    sort_entries(&mut p.entries, p.sort);
    p.loading = false;
    let index = previous
        .and_then(|prev| p.entries.iter().position(|entry| entry.path == prev))
        .unwrap_or(0);
    p.select(index);
}

/// Tab of the F11 confirmation overlay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConfirmTab {
    /// Human-readable summary: how many actions and how much will be freed.
    #[default]
    Summary,
    /// Full shell-script of the plan — for audit and manual launch.
    Commands,
}

/// Modal overlay on top of the commander panels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Overlay {
    /// No overlay.
    #[default]
    None,
    /// F9 dropdown menu; stores the cursor position.
    Menu { cursor: usize },
    /// Confirmation of executing F11 actions; `tab` — the active tab.
    Confirm {
        files: usize,
        reclaim: u64,
        tab: ConfirmTab,
    },
    /// File info (F3).
    FileInfo,
    /// F2: summary over the roots (an unfinished session and/or the last completed
    /// scan) + selection. The data is in `CommanderState.resume_unfinished/resume_complete`
    /// (earlier the variant carried scan_id/percent itself).
    ResumeScan,
}

/// Comparison mode of neighbouring panels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CompareMode {
    /// Ordinary view without comparison.
    #[default]
    Off,
    /// Side-by-side: each file gets a match glyph against the neighbouring panel
    /// (diff comparison scheme: `=` identical, `≈` similar, `~` differs, `+` only here).
    SideBySide,
}

/// Pending triage move (triage v1): the source is fixed by the `m` key,
/// awaiting the digit of the receiver panel. `sources` — a batch (or a single file under the cursor).
#[derive(Debug, Clone)]
pub struct TriagePending {
    pub sources: Vec<PathBuf>,
    pub source_panel: usize,
}

/// A move-journal record for Undo (`u`): (from, to) pairs of a single operation.
#[derive(Debug, Clone)]
pub struct MoveRecord {
    pub items: Vec<(PathBuf, PathBuf)>,
}

/// Triage Board state — a separate screen for manual sorting of files.
/// The centre is the source (the cursor lives here and never leaves it), 4 receivers in the corners
/// with labels 1–4. These are OWN panels, they do NOT overlap with the `panels` of the old commander.
pub struct BoardState {
    /// The source in the centre — the "inbox" being sorted.
    pub source: Panel,
    /// 4 receivers: 0=top-left(1), 1=bottom-left(2), 2=top-right(3), 3=bottom-right(4).
    pub receivers: [Panel; 4],
    /// The focused panel: 0 = source, 1–4 = receivers `receivers[focus-1]`.
    /// Navigation and move act on the focused panel.
    pub focus: usize,
    /// The receiver-directory-assignment mode is armed: `a` was pressed, awaiting digit 1–4 —
    /// the current directory of the focused panel becomes this receiver's directory.
    pub assign_pending: bool,
}

impl BoardState {
    /// Builds the Board from starting directories. The panels are empty (`Panel::empty`) —
    /// the content is loaded by the background worker; no I/O here.
    pub fn new(source: PathBuf, receivers: [PathBuf; 4]) -> Self {
        Self {
            source: Panel::empty(source),
            receivers: receivers.map(Panel::empty),
            focus: 0,
            assign_pending: false,
        }
    }
}

/// Cache key for the resolved group of a "watching" panel: so render does not
/// open the DB every frame, only on a source change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchKey {
    /// GroupFiles: index of the selected group in the neighbouring GroupList panel.
    Group(usize),
    /// DuplicatesOfCursor: path of the file under the cursor of the neighbouring panel.
    DupOf(PathBuf),
    /// DuplicatesOfCursor for a directory-cursor — twins from dir_dedup
    /// or (fallback) duplicate files inside.
    DirOf(PathBuf),
}

/// What resolved for a "watching" panel — a file group, a group
/// of twin directories, or (fallback) duplicate files inside the dir-cursor.
#[derive(Debug, Clone)]
pub enum WatchResult {
    /// The old path (GroupFiles / DupOf): a group of duplicate files.
    FileGroup(DuplicateGroup),
    /// Cursor on a directory that has a twin in `dir_dedup`.
    DirGroup(DirGroup),
    /// Cursor on a directory WITHOUT a twin, but with duplicate files
    /// inside (their hash occurs SOMEWHERE in the scan).
    InnerDupes(Vec<PathBuf>),
}

/// The reason `WatchEntry.result` is empty. Before this, render lumped all
/// 3 cases into a single "no source" message — which was misleading if
/// the source AND the cursor exist, but the directory is simply not covered by a scan. Now render
/// distinguishes: no source / outside the scan / in the scan but without duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchEmpty {
    /// No neighbouring Files/DirsOnly panel on the left, or the source cursor is on `..`,
    /// or the panel is not in `DuplicatesOfCursor`/`GroupFiles` mode (then the field
    /// is simply not read).
    #[default]
    NoSource,
    /// The source and cursor exist, but the file/directory under the cursor is not covered by the active
    /// scan (`hash_for_path = None` for a file; not a single `file` row under
    /// the prefix for a directory).
    NotInScan,
    /// Covered by a scan, but no duplicates were found — neither in `dir_dedup` (for a directory),
    /// nor in `file_group` (for a file or files inside a directory).
    NoDuplicates,
}

/// Cache entry of a "watching" panel: the source key + the resolved result +
/// the reason for emptiness, for a targeted fallback in render.
#[derive(Debug, Clone, Default)]
pub struct WatchEntry {
    pub key: Option<WatchKey>,
    pub result: Option<WatchResult>,
    pub empty: WatchEmpty,
}

impl WatchEntry {
    /// Backward-compatibility helper: the file group from the result, if
    /// it is `FileGroup`. Existing GroupFiles/DupOf call-sites keep reading
    /// through this helper, unaware of DirGroup/InnerDupes.
    pub fn as_file_group(&self) -> Option<&DuplicateGroup> {
        match &self.result {
            Some(WatchResult::FileGroup(g)) => Some(g),
            _ => None,
        }
    }
}

/// A pending jump on the `o` key — needed for the "not found" status
/// after the async load of the target panel. The cursor landing on `file` itself
/// is done by `apply_panel_load` via `PanelLoadRequest.previous`; here we keep
/// the context only to check "hit/missed".
#[derive(Debug, Clone)]
pub struct PendingJump {
    /// Index of the target commander panel.
    pub panel: usize,
    /// Navigation version (for discarding stale responses).
    pub generation: u64,
    /// Path of the file the cursor is expected to land on.
    pub file: PathBuf,
}

/// State of the commander interface.
pub struct CommanderState {
    /// Panels — from 2 to 4.
    pub panels: Vec<Panel>,
    /// Roots of the ZFS datasets — for quickly changing a panel's root (Alt+F1/F2).
    pub roots: Vec<PathBuf>,
    /// Index of the focused panel.
    pub active: usize,
    /// Status line (empty — the active panel's directory is shown).
    pub status: String,
    /// The wizard was opened from the commander — exiting the wizard returns here.
    pub return_to_commander: bool,
    /// Dedup cache over the directories of the visible panels — an overlay of file attributes from the DB
    /// on demand (previously the whole scan lived in RAM).
    pub dedup: DedupCache,
    /// scan_id of the scan the dedup overlay is read from (`None` — no data).
    pub dedup_scan_id: Option<i64>,
    /// Scan group summaries for the GroupList/GroupFiles modes — loaded on
    /// the first entry into a panel's groups mode (see `groups_loaded_for`).
    pub group_summaries: Vec<GroupSummary>,
    /// Groups of duplicate directories for DirGroupList/DirGroupFiles.
    pub dir_groups: Vec<DirGroup>,
    /// scan_id for which the summaries/directory groups are loaded (`None` — not loaded).
    pub groups_loaded_for: Option<i64>,
    /// Cache of `latest_scan_covering(cwd)` for each cwd —
    /// `maybe_auto_switch_scan` does not poke the DB every frame, only when
    /// it sees a new cwd. A value of `None` — "no covering scan" (also cached,
    /// so misses aren't repeated). Cleared on `spawn_dedup_load` (a new scan
    /// → old coverages may have changed).
    pub scan_coverage_cache: HashMap<PathBuf, Option<i64>>,
    /// Cache of the resolved groups of "watching" panels (GroupFiles/DuplicatesOfCursor) by
    /// panel index — the DB is read only on a source change, not every frame.
    pub watch_cache: Vec<WatchEntry>,
    /// Cache of the resolved directory groups of "watching" panels (DirGroupFiles) by panel.
    pub watch_dir_cache: Vec<Option<DirGroup>>,
    /// Cache of background sizes of directories not covered by a scan.
    pub dir_size_cache: HashMap<PathBuf, u64>,
    /// Directories with an already-started background size computation — to avoid duplication.
    pub dir_size_pending: HashSet<PathBuf>,
    /// Queue to the single background directory-size computation worker
    /// — started lazily on the first Shift+F6.
    pub dir_sizer: Option<Sender<PathBuf>>,
    /// Queue to the background panel-directory reader worker —
    /// started lazily on the first navigation.
    pub panel_loader: Option<Sender<PanelLoadRequest>>,
    /// Queue to the single background move worker — batches are
    /// processed one at a time (serialization); started lazily.
    pub move_worker: Option<Sender<MoveRequest>>,
    /// The second layer of F-keys is armed: the footer shows layer 2,
    /// the next F-key executes a layer-2 command. Armed by the prefix
    /// key ` — xterm.js (the Proxmox web console) does not transmit holding Shift.
    pub second_layer: bool,
    /// Terminal width from the previous render — for computing panel capacity.
    pub term_width: u16,
    /// Terminal height from the previous render — for parsing mouse clicks.
    pub term_height: u16,
    /// The open modal overlay (menu, etc.).
    pub overlay: Overlay,
    /// Comparison mode of neighbouring panels — the `,` key.
    pub compare_mode: CompareMode,
    /// The action plan awaiting F11 confirmation.
    pub pending_actions: Vec<PlannedAction>,
    /// Shell-script preview of the current F11 plan — shown
    /// on the "Commands" tab and saved with `S`.
    pub confirm_script: String,
    /// Triage (triage v1): a move awaiting a receiver (the source is fixed).
    pub triage: Option<TriagePending>,
    /// Triage move journal for Undo (`u`); newest at the end.
    pub move_log: Vec<MoveRecord>,
    /// Datasets for which a safety snapshot has already been taken this run.
    pub snapshotted: HashSet<String>,
    /// File info lines for the F3 overlay.
    pub info_lines: Vec<String>,
    /// The last left mouse click: (instant, panel index, entry index) —
    /// for recognising a double click.
    pub last_click: Option<(Instant, usize, usize)>,
    /// Triage Board — a separate 3-panel sorting screen. `None`
    /// until it has been opened; preserved between showings (receivers aren't lost).
    pub board: Option<BoardState>,
    /// The Board is shown and intercepts input (drawn instead of the old panels).
    pub board_active: bool,
    /// Number of background move batches in progress — the "moving…" indicator;
    /// the UI does not block, the heavy move/hash/copy runs in a separate thread.
    pub move_pending: usize,
    /// Roots of the scan awaiting confirmation (F2) — while Overlay::ResumeScan is shown
    ///; on "new scan" we scan them without spawning a session.
    pub pending_scan_roots: Vec<PathBuf>,
    /// Data for the F2 overlay: an unfinished session and/or the last
    /// completed scan of these roots — for showing dates/progress and a recommendation.
    pub resume_unfinished: Option<ResumeInfo>,
    pub resume_complete: Option<ResumeInfo>,
    /// A pending "o" jump — for checking the "not found" status
    /// after the async load. See `PendingJump`.
    pub pending_jump: Option<PendingJump>,
}

impl CommanderState {
    /// Creates two panels on the starting directories. The dedup index
    /// starts empty — it is built in the background (`App::spawn_dedup_load`).
    pub fn new(start_dirs: &[PathBuf]) -> Self {
        let first = start_dirs
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/"));
        let second = start_dirs.get(1).cloned().unwrap_or_else(|| first.clone());
        Self {
            panels: vec![Panel::new(first), Panel::new(second)],
            roots: start_dirs.to_vec(),
            active: 0,
            status: String::new(),
            return_to_commander: false,
            dedup: DedupCache::default(),
            dedup_scan_id: None,
            group_summaries: Vec::new(),
            dir_groups: Vec::new(),
            groups_loaded_for: None,
            scan_coverage_cache: HashMap::new(),
            watch_cache: Vec::new(),
            watch_dir_cache: Vec::new(),
            dir_size_cache: HashMap::new(),
            dir_size_pending: HashSet::new(),
            dir_sizer: None,
            panel_loader: None,
            move_worker: None,
            second_layer: false,
            term_width: 80,
            term_height: 24,
            overlay: Overlay::None,
            compare_mode: CompareMode::Off,
            pending_actions: Vec::new(),
            confirm_script: String::new(),
            triage: None,
            move_log: Vec::new(),
            snapshotted: HashSet::new(),
            info_lines: Vec::new(),
            last_click: None,
            board: None,
            board_active: false,
            move_pending: 0,
            pending_scan_roots: Vec::new(),
            resume_unfinished: None,
            resume_complete: None,
            pending_jump: None,
        }
    }

    /// The focused panel.
    pub fn active_panel(&self) -> &Panel {
        &self.panels[self.active]
    }

    /// The focused panel (mutable reference).
    pub fn active_panel_mut(&mut self) -> &mut Panel {
        &mut self.panels[self.active]
    }

    /// Moves focus to the next panel.
    pub fn focus_next(&mut self) {
        self.active = (self.active + 1) % self.panels.len();
    }

    /// Moves focus to the previous panel.
    pub fn focus_prev(&mut self) {
        self.active = (self.active + self.panels.len() - 1) % self.panels.len();
    }

    /// Adds a panel at the active panel's `cwd` — without synchronously reading the directory.
    /// The content is loaded by the background worker; the caller starts it
    /// via `reload_panel(app, new_index)`. Returns the index of the new panel.
    pub fn add_panel(&mut self) -> Result<usize, String> {
        if self.panels.len() >= 4 {
            return Err("Maximum of 4 panels".to_string());
        }
        let fits = max_panels(self.term_width);
        if self.panels.len() >= fits {
            return Err(format!(
                "The window width fits no more than {fits} panels — widen the terminal"
            ));
        }
        let cwd = self.active_panel().cwd.clone();
        self.panels.push(Panel::empty(cwd));
        let index = self.panels.len() - 1;
        self.active = index;
        Ok(index)
    }

    /// Removes the active panel, if there are more than two.
    pub fn remove_panel(&mut self) -> Result<(), String> {
        if self.panels.len() <= 2 {
            return Err("Minimum of 2 panels".to_string());
        }
        self.panels.remove(self.active);
        if self.active >= self.panels.len() {
            self.active = self.panels.len() - 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, kind: EntryKind, size: u64, mtime: i64) -> PanelEntry {
        PanelEntry {
            path: PathBuf::from(name),
            name: name.to_string(),
            kind,
            size,
            mtime,
            device: 0,
            inode: 0,
        }
    }

    #[test]
    fn sort_entries_keeps_parent_then_dirs_then_files() {
        let mut entries = vec![
            entry("file_b.txt", EntryKind::File, 10, 1),
            entry("dir_b", EntryKind::Dir, 0, 0),
            entry("..", EntryKind::Parent, 0, 0),
            entry("file_a.txt", EntryKind::File, 99, 2),
            entry("dir_a", EntryKind::Dir, 0, 0),
        ];
        sort_entries(&mut entries, SortKey::Name);
        let order: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(order, ["..", "dir_a", "dir_b", "file_a.txt", "file_b.txt"]);
    }

    #[test]
    fn sort_entries_by_size_is_descending_within_files() {
        let mut entries = vec![
            entry("..", EntryKind::Parent, 0, 0),
            entry("small.txt", EntryKind::File, 10, 0),
            entry("big.txt", EntryKind::File, 999, 0),
            entry("mid.txt", EntryKind::File, 100, 0),
        ];
        sort_entries(&mut entries, SortKey::Size);
        let order: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(order, ["..", "big.txt", "mid.txt", "small.txt"]);
    }

    #[test]
    fn watch_empty_default_is_no_source() {
        // The default is the most "harmless" case, meaning "the panel is not in
        // DuplicatesOfCursor/GroupFiles mode or not yet resolved". NoSource
        // also covers the real "no neighbouring Files/DirsOnly on the left".
        assert_eq!(WatchEmpty::default(), WatchEmpty::NoSource);
    }

    #[test]
    fn watch_entry_default_has_no_source_empty() {
        // WatchEntry::default() via derive must give empty=NoSource.
        // This is an invariant for resolve_watch_groups before the first sorting.
        let entry = WatchEntry::default();
        assert!(entry.key.is_none());
        assert!(entry.result.is_none());
        assert_eq!(entry.empty, WatchEmpty::NoSource);
    }

    #[test]
    fn commander_state_starts_with_empty_scan_coverage_cache() {
        // Before the first walk the coverage cache is empty. This is an invariant
        // for `maybe_auto_switch_scan` — an empty cache means "not tried yet, need to
        // poke the DB". Also `dedup_scan_id` starts as None — it will be set either
        // via `spawn_dedup_load(None)` (latest_scan_id) at startup, or via
        // `maybe_auto_switch_scan` (latest_scan_covering) on a cwd change.
        let state = CommanderState::new(&[PathBuf::from("/tank")]);
        assert!(state.scan_coverage_cache.is_empty());
        assert!(state.dedup_scan_id.is_none());
    }
}
