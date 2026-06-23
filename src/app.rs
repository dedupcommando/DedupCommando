// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crossbeam_channel::Sender;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, ModifierKeyCode, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::widgets::ListState;
use std::time::{Duration, Instant};

use crate::actions;
use crate::model::action::{ActionKind, BatchResult, PlannedAction, RevalidationMode};
use crate::model::dataset::Dataset;
use crate::model::duplicate::{DirSigAlgo, DuplicateGroup, FileEntry};
use crate::model::preset::Preset;
use crate::model::scan::{
    HashProfile, ResumeInfo, ScanConfig, ScanPhase, ScanProgress, ScanSummary,
};
use crate::pipeline::ScanOutcome;
use crate::scan::worker::{self, ScanHandle};
use crate::state::{GroupSummary, HostProfile, ScanStore};
use crate::tui::commander::dedup::DedupCache;
use crate::tui::commander::state::{CommanderState, LoadTarget};
use crate::tui::event::AppEvent;
use crate::zfs::ZfsEnvironment;

/// Page size for incremental loading of files in the
/// open group — `group_files_page` loads exactly this many at a time. When the
/// cursor scrolls toward the end of the window, `maybe_load_more_files` loads
/// the next page, until `BROWSE_GROUP_FILE_MAX` is reached.
pub(crate) const BROWSE_GROUP_FILE_PAGE: usize = 200;

/// Upper limit for loading a single group into RAM — a
/// safeguard against the 2.19M-file /tank anomaly. 50,000 × ~200 bytes per
/// `FileEntry` ≈ 10 MiB; for the vast majority of groups the limit is never
/// hit and ALL files are visible. When it is hit — the panel header shows
/// `Files 50000/2.19M · view limit reached`.
pub(crate) const BROWSE_GROUP_FILE_MAX: usize = 50_000;

/// TUI screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    ScanConfig,
    FolderPicker,
    Resume,
    Scanning,
    /// Background application of actions: progress bar, Esc cancels.
    Applying,
    Browser,
    ActionReview,
    Summary,
    /// Comparison of two scans.
    ScanDiff,
    /// Trash — deleted sessions: restore or purge.
    Trash,
}

/// Active application interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    /// Multi-panel interface (commander).
    Commander,
    /// Classic step-by-step wizard.
    Wizard,
}

/// An action awaiting confirmation in a modal dialog.
#[derive(Debug, Clone, Copy)]
pub enum ConfirmAction {
    /// Move the session to trash (reversible).
    TrashScan(i64),
    /// Purge the session from trash FOREVER (irreversible).
    PurgeScan(i64),
}

/// A scan root — a ZFS dataset or an arbitrarily chosen folder.
pub struct RootChoice {
    /// Dataset name; empty for an arbitrary folder.
    pub label: String,
    pub path: PathBuf,
    pub selected: bool,
    pub is_dataset: bool,
}

/// State of the scan configuration screen.
pub struct ScanConfigState {
    pub roots: Vec<RootChoice>,
    pub cursor: usize,
    /// Filter presets by type (built-in + user-defined).
    pub presets: Vec<Preset>,
    /// Index of the active preset in `presets`.
    pub preset_index: usize,
    /// Hash cache: reuse hashes of unchanged files from previous scans.
    pub reuse_hashes: bool,
    /// Hashing intensity profile (Resource Governor).
    pub hash_profile: HashProfile,
    /// Dir-signature algorithm. CLI `--merkle-dirs` sets Merkle at
    /// startup; restored from the DB on resume. Default = Old.
    pub dir_sig_algo: DirSigAlgo,
}

/// State of the file-browser screen for choosing an arbitrary folder.
#[derive(Default)]
pub struct FolderPickerState {
    pub current_dir: PathBuf,
    pub entries: Vec<PathBuf>,
    pub cursor: usize,
}

/// State of the scanning screen (updated from progress events).
#[derive(Default)]
pub struct ScanningState {
    pub phase: Option<ScanPhase>,
    /// Total FS entries walked in the walk phase — grows monotonically.
    pub entries_walked: u64,
    pub files_walked: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub chunk_done: u64,
    pub chunk_total: u64,
    /// Current walk/hash path — for the scan screen.
    pub current_path: Option<std::path::PathBuf>,
    /// Read speed, bytes/s (EMA) — for the scan screen.
    pub rate_bytes_per_sec: u64,
    /// Estimated time remaining, seconds (0 — not yet estimated).
    pub eta_secs: u64,
    /// Notice on the scan screen: estimated memory for phase 3/3 vs free RAM.
    pub notice: Option<String>,
    /// Candidates not hashed by this point (error/identity), for the line
    /// "Failed to hash: N" on the scan screen.
    pub hash_failures: u64,
}

/// State of the action-application screen (updated from `ApplyProgress`).
#[derive(Default)]
pub struct ApplyingState {
    pub phase: crate::actions::ApplyPhase,
    /// Index of the current action (0-based).
    pub index: usize,
    /// Total actions in the batch.
    pub total: usize,
    /// Bytes re-verified (filled in the Hybrid/Strict phase; 0 → bar by actions).
    pub bytes_done: u64,
    /// Total bytes to re-verify (0 in the background phase — bar goes by `index`/`total`).
    pub bytes_total: u64,
    /// Active re-validation mode — for the application overlay header.
    pub mode: RevalidationMode,
}

/// State of the scan-comparison screen.
#[derive(Default)]
pub struct ScanDiffState {
    pub report: Option<crate::state::move_track::DiffReport>,
    /// The diff is computed in the background — until it's ready, show "computing…".
    pub loading: bool,
    /// Index of the selected category among the list ones (see scan_diff::CATEGORIES).
    pub category: usize,
    pub list: ListState,
}

/// Path display mode in the "Group files" panel of the Browser screen.
#[derive(Debug, Clone, Copy, Default)]
pub enum PathStyle {
    /// Directory dimmed, file name bright; full path.
    #[default]
    DimDir,
    /// File name at the start of the line, then the dimmed directory.
    NameFirst,
    /// Path segments graded by nesting depth.
    TreeGraded,
}

impl PathStyle {
    /// Next mode, cycling around.
    pub fn next(self) -> Self {
        match self {
            PathStyle::DimDir => PathStyle::NameFirst,
            PathStyle::NameFirst => PathStyle::TreeGraded,
            PathStyle::TreeGraded => PathStyle::DimDir,
        }
    }

    /// Short mode name — for the panel header.
    pub fn label(self) -> &'static str {
        match self {
            PathStyle::DimDir => "name bright",
            PathStyle::NameFirst => "name first",
            PathStyle::TreeGraded => "by tree",
        }
    }
}

/// State of the duplicate-browsing screen. Holds lightweight group
/// summaries, while files — only of the OPEN group (loaded from the DB on entry,
/// discarded on exit). Previously the whole scan (all `FileEntry`) sat in RAM (on
/// /tank — gigabytes).
#[derive(Default)]
pub struct BrowserState {
    /// Lightweight summaries of all groups "by reclaim" (645k×~48 B ≈ 31 MiB).
    pub group_summaries: Vec<GroupSummary>,
    /// Files of the OPEN group ONLY (`id` = summary rank). `None` — group not open.
    pub open_group: Option<DuplicateGroup>,
    /// Cache of the "file name → color" palette of the open group: computed
    /// ONCE when the group is loaded, NOT during render. On a /tank group of 2.2M
    /// files, recomputing the palette every frame caused ~4 s of freeze per cursor move.
    pub open_group_colors: HashMap<String, Color>,
    pub group_state: ListState,
    pub file_state: ListState,
    /// true — focus on the files panel, false — on the groups panel.
    pub focus_files: bool,
    pub summary: ScanSummary,
    /// Path display mode in the "Group files" panel.
    pub path_style: PathStyle,
    /// Cache of the total reclaimable benefit (E2E fix): from group
    /// summaries, independent of marks — computed on load, not every frame.
    pub reclaim_total: u64,
    /// Cache of the count of files marked for action — from the DB (`marked_count`).
    pub marked_count: usize,
    /// TOTAL number of files in the open group (`COUNT(*)` from
    /// the DB). `open_group.files.len()` — how many are loaded into the panel window;
    /// total — the upper bound needed for "Files 234/2.19M · ↓ load more" in the header.
    pub open_group_total: u64,
    /// Whether `BROWSE_GROUP_FILE_MAX` has been reached — beyond
    /// that, loading stops so as not to eat all RAM on pathologically large groups.
    pub open_group_max_reached: bool,
    /// Height of visible rows of the "Groups" panel (without border).
    /// Updated in `tui::screens::browser::render` after layout. 0 — not yet
    /// rendered (fallback in `browser_page` → 20).
    pub group_visible_rows: u16,
    /// The same for the "Group files" panel.
    pub files_visible_rows: u16,
    /// Coordinates of the "Groups" panel after the last layout —
    /// for mapping a mouse click "(col,row) → which panel + row". `None` until
    /// the first frame.
    pub groups_area: Option<Rect>,
    /// Coordinates of the "Group files" panel.
    pub files_area: Option<Rect>,
    /// Time and position of the last mouse click — for
    /// detecting a double-click (Enter-like gesture).
    pub last_click: Option<(Instant, u16, u16)>,
    /// Active browser tab (Files/Dirs).
    pub tab: crate::tui::screens::browser::BrowserTab,
    /// Lightweight summaries of twin-directory groups for
    /// the `[2] Directories` tab. Loaded synchronously in `show_results` (on /tank
    /// ≤ a few thousand rows — not hundreds of thousands like file-groups).
    pub dir_group_summaries: Vec<crate::state::DirGroupSummary>,
    /// Total reclaim of dir-groups — for the tab bar.
    pub dir_groups_reclaim_total: u64,
    /// Cursor over dir-groups (left panel of the Dirs tab).
    pub dir_group_state: ListState,
    /// Cursor over paths of the open dir-group (right).
    pub dir_file_state: ListState,
    /// The full open dir-group with `paths` (loaded by
    /// `store::dir_group_paths` on entry). `None` while none is open.
    pub open_dir_group: Option<crate::model::duplicate::DirGroup>,
    /// Index of the "keeper" in `open_dir_group.paths` (★).
    /// Default 0 (first path); changed with Enter on the right panel.
    pub dir_keeper_index: usize,
    /// Coordinates of the `[1] Files` tab on the tab bar — for mouse clicks.
    /// `None` until the first frame.
    pub tab_files_area: Option<Rect>,
    /// The same for the `[2] Directories` tab.
    pub tab_dirs_area: Option<Rect>,
}

impl BrowserState {
    /// Recomputes the total reclaim from group summaries (independent of marks).
    /// `marked_count` is updated separately from the DB (`App::refresh_marked_count`).
    pub fn recompute_reclaim(&mut self) {
        self.reclaim_total = self.group_summaries.iter().map(|s| s.reclaim_bytes).sum();
    }
}

/// State of the action-review screen.
#[derive(Default)]
pub struct ReviewState {
    pub actions: Vec<PlannedAction>,
    pub confirming: bool,
}

/// State of the startup disclaimer/consent gate.
#[derive(Default)]
pub struct DisclaimerState {
    /// "Read and agree" checkbox — required to enter.
    pub agreed: bool,
    /// "Don't show again at startup" checkbox — optional.
    pub suppress: bool,
    /// Focus: 0 — consent checkbox, 1 — suppress checkbox.
    pub focus: usize,
}

/// Global application state.
pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub zfs: ZfsEnvironment,
    /// Host profile captured at startup — for auto-selecting the
    /// Resource Governor profile, summaries, and the inotify-limit warning.
    pub host: HostProfile,
    pub db_path: PathBuf,
    /// Persistent connection for VIEWING results: open once,
    /// reuse during navigation. Otherwise `ScanStore::open` on every cursor
    /// move (create_dir_all + WAL PRAGMA + migrate + cold page-cache) loaded
    /// the DB from disk → freeze of "groups by reclaim" on /tank (the same class as upstream Bug 4).
    pub(crate) browse_store: Option<ScanStore>,
    pub events: Sender<AppEvent>,
    pub config: ScanConfigState,
    pub folder_picker: FolderPickerState,
    pub sessions: Vec<ResumeInfo>,
    pub session_cursor: usize,
    /// The session list is loaded in the background; until ready — an indicator.
    pub sessions_loading: bool,
    /// The session list is already loaded — don't start loading again.
    pub sessions_loaded: bool,
    pub scanning: ScanningState,
    /// State of the action-application screen (background worker).
    pub applying: ApplyingState,
    pub scan_diff: ScanDiffState,
    pub browser: BrowserState,
    pub review: ReviewState,
    pub summary_result: Option<BatchResult>,
    pub status: String,
    pub scan: Option<ScanHandle>,
    /// Control of background application; `Some` while application is running.
    pub apply: Option<crate::actions::apply_worker::ApplyHandle>,
    /// Targets of the applied batch — for invalidating the commander directory-size
    /// cache after background application.
    pub apply_affected: Vec<PathBuf>,
    pub verify: bool,
    /// Re-validation mode before a destructive op: Hybrid (default) or Strict
    /// (`--strict-verify`). Passed through to the background apply_worker.
    pub reval_mode: RevalidationMode,
    pub show_help: bool,
    /// Whether to show the startup disclaimer/consent gate: true until
    /// the user has checked "don't show" for the current version of the text.
    pub show_disclaimer: bool,
    /// State of the disclaimer gate's checkboxes/focus.
    pub disclaimer: DisclaimerState,
    /// "Read-only" mode: an observer alongside a live operator —
    /// scanning and destructive operations are forbidden, banner in the corner.
    pub read_only: bool,
    /// The held single-instance lock: while it's alive (until App is dropped),
    /// we are the operator. `None` — observer, or operator "by force".
    pub instance_lock: Option<crate::lock::InstanceLock>,
    /// `Some` → show the startup role-selection overlay when an operator is live
    /// (`ask` policy): `[R]` read-only / `[F]` as operator / `Esc` exit.
    pub concurrency_prompt: Option<crate::lock::Holder>,
    /// TUI frame counter — for animating indicators (the "process alive" spinner).
    pub tick: u64,
    /// scan_id of the scan whose groups are open in Browser — for saving marks.
    pub current_scan_id: Option<i64>,
    /// Active interface: multi-panel commander or classic wizard.
    pub mode: AppMode,
    /// State of the multi-panel commander interface.
    pub commander: CommanderState,
    /// Process RAM/CPU monitor — for the indicator in the TUI corner.
    pub resource: crate::sysmon::ResourceMonitor,
    /// Sessions in trash — list for the restore/purge screen.
    pub trashed: Vec<ResumeInfo>,
    pub trash_cursor: usize,
    /// An action awaiting confirmation in a modal dialog.
    pub confirm: Option<ConfirmAction>,
    /// A completed scan's result is being loaded in the background (E2E feedback) — `Some(start)`
    /// enables the "Opening result" animation and holds the time for the marquee.
    pub opening_started: Option<std::time::Instant>,
    /// The result was opened from the session list (F2/F12) — Esc returns to the list, not to
    /// commander (don't jump over the parent, E2E feedback).
    pub results_from_sessions: bool,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        zfs: ZfsEnvironment,
        host: HostProfile,
        db_path: PathBuf,
        events: Sender<AppEvent>,
        sessions: Vec<ResumeInfo>,
        verify: bool,
        reval_mode: RevalidationMode,
        presets: Vec<Preset>,
        start_in_commander: bool,
        lock_startup: crate::lock::Startup,
        merkle_dirs: bool,
    ) -> Self {
        // Roots — all ZFS datasets of the pools; unchecked by default.
        let mut roots = Vec::new();
        for pool in &zfs.pools {
            for dataset in &pool.datasets {
                // Datasets are NOT checked by default — the user explicitly
                // chooses what to scan (Space, or folders via F).
                roots.push(RootChoice {
                    label: dataset.name.clone(),
                    path: dataset.mountpoint.clone(),
                    selected: false,
                    is_dataset: true,
                });
            }
        }

        // Startup directories for the commander panels — dataset mountpoints.
        let mut commander_dirs: Vec<PathBuf> = Vec::new();
        for pool in &zfs.pools {
            for dataset in &pool.datasets {
                commander_dirs.push(dataset.mountpoint.clone());
            }
        }
        let commander = CommanderState::new(&commander_dirs);
        let mode = if start_in_commander {
            AppMode::Commander
        } else {
            AppMode::Wizard
        };

        // There are saved sessions — show their list for selection.
        let screen = if sessions.is_empty() {
            Screen::ScanConfig
        } else {
            Screen::Resume
        };

        // Auto-default of the intensity profile by hardware —
        // computed before `host` is moved into the struct.
        let default_profile = if host.has_fast_storage() {
            HashProfile::Turbo
        } else {
            HashProfile::Balanced
        };

        // Startup disclaimer gate: shown until the user has checked
        // "don't show" for the current version of the text. state_dir is the parent
        // of the checkpoint DB (where board.json/consent.json also live).
        let show_disclaimer = {
            let saved = db_path.parent().and_then(crate::consent::load);
            crate::consent::should_show_disclaimer(
                saved.as_ref(),
                crate::consent::DISCLAIMER_VERSION,
            )
        };

        let app = Self {
            screen,
            should_quit: false,
            zfs,
            host,
            db_path,
            events,
            config: ScanConfigState {
                roots,
                cursor: 0,
                presets,
                preset_index: 0,
                reuse_hashes: true,
                // Auto-default by hardware (above); the user changes it with the g key.
                hash_profile: default_profile,
                dir_sig_algo: if merkle_dirs {
                    DirSigAlgo::Merkle
                } else {
                    DirSigAlgo::Old
                },
            },
            folder_picker: FolderPickerState::default(),
            sessions,
            session_cursor: 0,
            sessions_loading: false,
            sessions_loaded: matches!(mode, AppMode::Wizard),
            scanning: ScanningState::default(),
            applying: ApplyingState::default(),
            scan_diff: ScanDiffState::default(),
            browse_store: None,
            browser: BrowserState::default(),
            review: ReviewState::default(),
            summary_result: None,
            status: String::new(),
            scan: None,
            apply: None,
            apply_affected: Vec::new(),
            verify,
            reval_mode,
            show_help: false,
            show_disclaimer,
            disclaimer: DisclaimerState::default(),
            read_only: lock_startup.read_only,
            instance_lock: lock_startup.lock,
            concurrency_prompt: lock_startup.prompt,
            tick: 0,
            current_scan_id: None,
            mode,
            commander,
            resource: crate::sysmon::ResourceMonitor::new(),
            trashed: Vec::new(),
            trash_cursor: 0,
            confirm: None,
            opening_started: None,
            results_from_sessions: false,
        };
        // The initial auto-switch to a covering scan
        // is done by render via `maybe_auto_switch_scan` on the first frame — we don't
        // pull in `latest_scan_id` (it could be about an unrelated part of the tree; the user
        // saw `overlay: scan #9` and 0% coverage without even pressing F12).
        // We do NOT put the host summary into the status line — it cluttered the footer and distracted.
        // It stays in the log (main.rs) and is available in help.
        app
    }

    pub fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Key(key) => self.on_key(key),
            AppEvent::Resize => {}
            AppEvent::ScanProgress(progress) => self.on_progress(progress),
            AppEvent::ScanFinished(result) => self.on_finished(result),
            AppEvent::ApplyProgress(progress) => self.on_apply_progress(progress),
            AppEvent::ApplyFinished(result) => self.on_apply_finished(result),
            AppEvent::CommanderHash(path, hash) => {
                self.commander.dedup.insert_hash(path.clone(), hash);
                self.commander.status = format!("Hash computed: {}", path.display());
            }
            AppEvent::CommanderHashFailed(path, err) => {
                self.commander.status = format!("Failed to compute hash {}: {err}", path.display());
            }
            AppEvent::CommanderHashCached(path, hash) => {
                // Quietly: into memory + the persistent identity-keyed cache (layout §B).
                self.commander.dedup.insert_hash(path.clone(), hash);
                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(mut store) = ScanStore::open(&self.db_path) {
                        let _ = store.upsert_hash(
                            meta.dev(),
                            meta.ino(),
                            meta.size(),
                            meta.mtime(),
                            &hash,
                        );
                    }
                }
            }
            AppEvent::CommanderDirDedup { cwd, dir } => {
                // Put the directory's dedup data into the cache and prune it down to the
                // current panel directories — memory stays at the level of the panel count.
                let mut keep: std::collections::HashSet<PathBuf> = self
                    .commander
                    .panels
                    .iter()
                    .map(|panel| panel.cwd.clone())
                    .collect();
                if let Some(board) = &self.commander.board {
                    keep.insert(board.source.cwd.clone());
                    for receiver in &board.receivers {
                        keep.insert(receiver.cwd.clone());
                    }
                }
                keep.insert(cwd.clone());
                self.commander.dedup.insert_dir(cwd, dir);
                self.commander.dedup.prune(&keep);
            }
            AppEvent::CommanderDirSize(path, size) => {
                self.commander.dir_size_pending.remove(&path);
                self.commander.dir_size_cache.insert(path, size);
            }
            AppEvent::CommanderPanelLoaded {
                target,
                generation,
                entries,
                previous,
            } => {
                use crate::tui::commander::state::apply_panel_load;
                // Routing of the background-load result by recipient.
                match target {
                    LoadTarget::Commander(i) => {
                        if let Some(p) = self.commander.panels.get_mut(i) {
                            apply_panel_load(p, generation, entries, previous);
                        }
                        // Check that the "o"-jump has landed (see check_jump_landed).
                        crate::tui::commander::check_jump_landed(
                            &mut self.commander,
                            i,
                            generation,
                        );
                    }
                    LoadTarget::BoardSource => {
                        if let Some(board) = self.commander.board.as_mut() {
                            apply_panel_load(&mut board.source, generation, entries, previous);
                        }
                    }
                    LoadTarget::BoardReceiver(i) => {
                        if let Some(p) = self
                            .commander
                            .board
                            .as_mut()
                            .and_then(|board| board.receivers.get_mut(i))
                        {
                            apply_panel_load(p, generation, entries, previous);
                        }
                    }
                }
                // The panel directory was updated — read its dedup attributes from the DB.
                crate::tui::commander::fetch_panel_dedup(self, target);
            }
            AppEvent::CommanderMoveDone(outcome) => {
                crate::tui::commander::apply_move_outcome(self, *outcome);
            }
            AppEvent::SessionsReady(list) => {
                self.sessions = list;
                self.sessions_loading = false;
                self.sessions_loaded = true;
                self.session_cursor = 0;
            }
            AppEvent::SessionDeleted(result) => {
                self.status = match result {
                    Ok(_) => "Session purged from trash".to_string(),
                    Err(err) => format!("Failed to purge scan: {err}"),
                };
            }
            AppEvent::ResultsLoaded(scan_id, summaries, summary) => {
                // Opened a completed scan as a LIST of results. Browser is
                // a wizard screen, so we switch mode (relevant for entry from F2).
                self.mode = AppMode::Wizard;
                self.show_results(scan_id, summaries, summary);
            }
            AppEvent::CommanderResumeProbe {
                roots,
                unfinished,
                complete,
            } => {
                if unfinished.is_none() && complete.is_none() {
                    self.commander_scan_new(roots);
                } else {
                    self.commander.resume_unfinished = unfinished;
                    self.commander.resume_complete = complete;
                    self.commander.pending_scan_roots = roots;
                    self.commander.overlay = crate::tui::commander::state::Overlay::ResumeScan;
                }
            }
            AppEvent::ScanDiffReady(report) => {
                self.scan_diff.report = Some(*report);
                self.scan_diff.loading = false;
                self.scan_diff.category = 0;
                self.scan_diff.list.select(Some(0));
                self.status.clear();
            }
            AppEvent::ScanDiffFailed(err) => {
                self.scan_diff.loading = false;
                self.status = format!("Diff failed: {err}");
            }
            AppEvent::Mouse(mouse) => self.on_mouse(mouse),
        }
    }

    fn on_progress(&mut self, progress: ScanProgress) {
        match progress {
            ScanProgress::Phase(phase) => self.scanning.phase = Some(phase),
            ScanProgress::Walked {
                entries,
                files,
                current_path,
            } => {
                self.scanning.entries_walked = entries;
                self.scanning.files_walked = files;
                self.scanning.current_path = current_path;
            }
            ScanProgress::Hashing {
                files_done,
                files_total,
                bytes_done,
                bytes_total,
                chunk_done,
                chunk_total,
                current_path,
                rate_bytes_per_sec,
                eta_secs,
                hash_failures,
            } => {
                self.scanning.files_done = files_done;
                self.scanning.files_total = files_total;
                self.scanning.bytes_done = bytes_done;
                self.scanning.bytes_total = bytes_total;
                self.scanning.chunk_done = chunk_done;
                self.scanning.chunk_total = chunk_total;
                self.scanning.current_path = current_path;
                self.scanning.rate_bytes_per_sec = rate_bytes_per_sec;
                self.scanning.eta_secs = eta_secs;
                self.scanning.hash_failures = hash_failures;
            }
            ScanProgress::Done(summary) => {
                self.scanning.current_path = None;
                self.browser.summary = summary;
            }
            ScanProgress::Notice(msg) => self.scanning.notice = Some(msg),
        }
    }

    /// Fills the duplicate window with a ready result: default keeper, stats
    /// cache, reset of lists, Browser screen. The single path for scan completion and for
    /// opening an already-completed scan (`spawn_open_completed`).
    fn show_results(&mut self, scan_id: i64, summaries: Vec<GroupSummary>, summary: ScanSummary) {
        self.opening_started = None; // result is ready — remove the opening animation
        self.current_scan_id = Some(scan_id);
        self.browser.group_summaries = summaries;
        self.browser.open_group = None;
        self.browser.summary = summary;
        self.browser.recompute_reclaim();
        self.browser.group_state = ListState::default();
        self.browser.file_state = ListState::default();
        self.browser.focus_files = false;
        // Reset the tab to Files, dir-state to empty,
        // then synchronously pull in the dir-group summaries.
        self.browser.tab = crate::tui::screens::browser::BrowserTab::Files;
        self.browser.dir_group_summaries.clear();
        self.browser.dir_group_state = ListState::default();
        self.browser.dir_file_state = ListState::default();
        self.browser.open_dir_group = None;
        self.browser.dir_keeper_index = 0;
        self.browser.dir_groups_reclaim_total = 0;
        if !self.browser.group_summaries.is_empty() {
            self.browser.group_state.select(Some(0));
            // Files of the first group — loaded from the DB on entry (the default keeper is set here).
            self.open_selected_group();
        }
        // Dir-group summaries — synchronously: they are usually < 10k on /tank, unlike
        // the 645k file-groups. If 0 — the `[2] Directories` tab stays empty, the user
        // sees "0 groups" on the bar and won't go there.
        if let Some(store) = self.browse_conn() {
            if let Ok(dir_sums) = store.dir_group_summaries(scan_id) {
                self.browser.dir_groups_reclaim_total =
                    dir_sums.iter().map(|s| s.reclaim_bytes()).sum();
                self.browser.dir_group_summaries = dir_sums;
                if !self.browser.dir_group_summaries.is_empty() {
                    self.browser.dir_group_state.select(Some(0));
                    // Defer open_dir_group until the tab is actually switched —
                    // lazily, so we don't spend a query on the first
                    // opening of the scan (most users stay on Files).
                }
            }
        }
        self.refresh_marked_count();
        self.status = format!(
            "Duplicate groups found: {} · scan time {} · {}",
            self.browser.group_summaries.len(),
            crate::tui::format_duration(self.browser.summary.elapsed_seconds),
            crate::tui::format_speed(
                self.browser.summary.bytes_hashed,
                self.browser.summary.elapsed_seconds,
            ),
        );
        // Completed with a warning — some files could not be hashed (they did NOT
        // participate in duplicate search). In the session list the same scan shows as "ready ⚠".
        if self.browser.summary.hash_failures > 0 {
            self.status.push_str(&format!(
                " · ⚠ failed to hash: {}",
                self.browser.summary.hash_failures
            ));
        }
        self.screen = Screen::Browser;
    }

    /// Opens the selected dir-group — loads the full
    /// `paths` via `store::dir_group_paths(signature)`. The keeper defaults
    /// to index 0 (by `paths` ASC sort order). If no
    /// group is selected — no-op.
    fn open_selected_dir_group(&mut self) {
        let Some(idx) = self.browser.dir_group_state.selected() else {
            return;
        };
        let Some(summary) = self.browser.dir_group_summaries.get(idx).cloned() else {
            return;
        };
        let Some(scan_id) = self.current_scan_id else {
            return;
        };
        let group = self.browse_conn().and_then(|store| {
            store
                .dir_group_paths(scan_id, &summary.signature)
                .ok()
                .flatten()
        });
        self.browser.open_dir_group = group;
        self.browser.dir_keeper_index = 0;
        self.browser.dir_file_state = ListState::default();
        if self
            .browser
            .open_dir_group
            .as_ref()
            .is_some_and(|g| !g.paths.is_empty())
        {
            self.browser.dir_file_state.select(Some(0));
        }
    }

    /// Persistent connection for viewing: opens once and
    /// caches. Group navigation reuses it — without `ScanStore::open`
    /// (create_dir_all + WAL PRAGMA + migrate, cold cache) on every move.
    fn browse_conn(&mut self) -> Option<&mut ScanStore> {
        if self.browse_store.is_none() {
            self.browse_store = ScanStore::open(&self.db_path).ok();
        }
        self.browse_store.as_mut()
    }

    /// Loads the selected group's files from the DB into `open_group`: on entry
    /// into a group, discarding the previous one. The default keeper (first file) is set in RAM
    /// for display if the group doesn't yet have a marked keeper; it is persisted only on
    /// the first action mark (`browser_mark`) — plain viewing does not write to the DB.
    fn open_selected_group(&mut self) {
        let (Some(scan_id), Some(index)) =
            (self.current_scan_id, self.browser.group_state.selected())
        else {
            self.browser.open_group = None;
            self.browser.file_state.select(None);
            return;
        };
        let Some(summary) = self.browser.group_summaries.get(index) else {
            self.browser.open_group = None;
            self.browser.file_state.select(None);
            return;
        };
        let hash = summary.hash.clone();
        let size_bytes = summary.size_bytes;
        let rank = summary.rank;
        let total_from_summary = summary.file_count;
        // The first page `BROWSE_GROUP_FILE_PAGE`. Beyond that,
        // it loads as the cursor scrolls (`maybe_load_more_files`) up to the
        // upper limit `BROWSE_GROUP_FILE_MAX`. The cap on a single page is no
        // longer "result truncation" — it's a progressive-loading window.
        let (mut files, total) = if let Some(store) = self.browse_conn() {
            let files = store
                .group_files_page(scan_id, &hash, 0, BROWSE_GROUP_FILE_PAGE)
                .unwrap_or_default();
            // Exact counter — for robustness against desync with file_group.
            let total = store
                .group_files_count(scan_id, &hash)
                .unwrap_or(total_from_summary);
            (files, total)
        } else {
            (Vec::new(), total_from_summary)
        };
        // Default keeper for display, if no file is marked as keeper.
        if !files.iter().any(|file| file.is_keeper) {
            if let Some(first) = files.first_mut() {
                first.is_keeper = true;
            }
        }
        let group = DuplicateGroup {
            id: rank as usize,
            size_bytes,
            hash,
            files,
        };
        let has_files = !group.files.is_empty();
        self.browser.open_group_total = total;
        self.browser.open_group_max_reached = group.files.len() >= BROWSE_GROUP_FILE_MAX;
        // We compute the palette ONCE here, not during render: on a 2.2M group,
        // recomputing every frame caused ~4 s of freeze per move. Render reads the ready map in O(1).
        self.browser.open_group_colors = crate::tui::screens::browser::name_palette(&group);
        self.browser.open_group = Some(group);
        self.browser
            .file_state
            .select(if has_files { Some(0) } else { None });
    }

    /// Refreshes the cache of the count of files marked for action from the DB.
    fn refresh_marked_count(&mut self) {
        let count = match self.current_scan_id {
            Some(id) => self
                .browse_conn()
                .and_then(|store| store.marked_count(id).ok())
                .unwrap_or(0),
            None => 0,
        };
        self.browser.marked_count = count as usize;
    }

    fn on_finished(&mut self, result: std::result::Result<ScanOutcome, String>) {
        self.scan = None;
        // Fresh scan/resume: the result is not from viewing the session list — Esc → ScanConfig/commander.
        self.results_from_sessions = false;
        let completed_scan = match &result {
            Ok(ScanOutcome::Completed(results)) => Some(results.scan_id),
            _ => None,
        };
        match result {
            Ok(ScanOutcome::Completed(results)) => {
                // The pipeline returns lightweight group summaries (files — from the DB on entry).
                self.show_results(results.scan_id, results.summaries, results.summary);
            }
            Ok(ScanOutcome::Cancelled) => {
                self.status = "Scan stopped — progress saved, you can continue".to_string();
                self.screen = Screen::ScanConfig;
            }
            Err(message) => {
                self.status = format!("Scan error: {message}");
                self.screen = Screen::ScanConfig;
            }
        }
        // Scan started from the commander — refresh the overlay or return there.
        if self.commander.return_to_commander {
            match completed_scan {
                Some(scan_id) => {
                    self.spawn_dedup_load(Some(scan_id));
                }
                None => {
                    self.mode = AppMode::Commander;
                    self.commander.return_to_commander = false;
                    self.commander.status = std::mem::take(&mut self.status);
                }
            }
        }
        // Scan finished (ready/cancelled/error) — the session list is stale (new scan_id /
        // updated candidate progress). Re-read in the background so that F12 shows
        // the current state without a restart. DB progress is live (per-chunk flush);
        // only the cache was lying. Mirror of restore_selected_trash.
        self.sessions_loaded = false;
        self.sessions_loading = false;
        self.spawn_sessions_load();
        // The coverage cache is stale too. A new Complete scan
        // could become covering for already-visited cwd's for which an older
        // id was previously found (#10 vs #9 on /tank). Without a full clear, `maybe_auto_switch_scan` on
        // returning to `/tank` goes by a cache hit and returns a stale decision. The
        // `latest_scan_covering` queries are dirt cheap — we'll rebuild the cache on subsequent navigations.
        self.commander.scan_coverage_cache.clear();
    }

    /// Updates the application progress bar from a worker progress snapshot. A late
    /// snapshot after `ApplyFinished` is ignored — application has already been cleared.
    fn on_apply_progress(&mut self, progress: crate::actions::ApplyProgress) {
        if self.apply.is_none() {
            return;
        }
        self.applying.phase = progress.phase;
        self.applying.index = progress.index;
        self.applying.bytes_done = progress.bytes_done;
    }

    /// Result of background application: summary + Summary screen. For commander —
    /// re-read the panels (marks cleared, directories changed), as it was synchronously.
    /// On error — return to the original screen with a message.
    fn on_apply_finished(&mut self, result: std::result::Result<BatchResult, String>) {
        self.apply = None;
        self.review.confirming = false;
        let from_commander = self.commander.return_to_commander;
        match result {
            Ok(batch) => {
                self.summary_result = Some(batch);
                self.status.clear();
                self.screen = Screen::Summary;
                if from_commander {
                    let affected = std::mem::take(&mut self.apply_affected);
                    crate::tui::commander::invalidate_dir_sizes(self, &affected);
                    let count = self.commander.panels.len();
                    for index in 0..count {
                        self.commander.panels[index].marks.clear();
                        crate::tui::commander::reload_panel(self, index);
                    }
                }
            }
            Err(err) => {
                self.apply_affected.clear();
                if from_commander {
                    self.mode = AppMode::Commander;
                    self.commander.return_to_commander = false;
                    self.commander.status = format!("Actions failed: {err}");
                } else {
                    self.screen = Screen::ActionReview;
                    self.status = format!("Actions failed: {err}");
                }
            }
        }
    }

    fn on_key(&mut self, key: KeyEvent) {
        // On terminals with keyboard enhancement, holding Shift also arms the
        // second layer of F-keys (the main mechanism is the prefix key `, see §A1).
        // We execute commands only on Press/Repeat.
        if matches!(
            key.code,
            KeyCode::Modifier(ModifierKeyCode::LeftShift)
                | KeyCode::Modifier(ModifierKeyCode::RightShift)
        ) {
            self.commander.second_layer = key.kind != KeyEventKind::Release;
            return;
        }
        if key.kind == KeyEventKind::Release {
            return;
        }
        // The startup disclaimer gate intercepts all input until consent.
        if self.show_disclaimer {
            self.on_key_disclaimer(key);
            return;
        }
        // The role-selection overlay when an operator is live (ask policy) — after consent.
        if self.concurrency_prompt.is_some() {
            self.on_key_concurrency(key);
            return;
        }
        // The help overlay intercepts input and is available from any screen.
        if self.show_help {
            if matches!(
                key.code,
                KeyCode::Esc
                    | KeyCode::Char('?')
                    | KeyCode::Char('q')
                    | KeyCode::Char('Q')
                    | KeyCode::F(1)
            ) {
                self.show_help = false;
            }
            return;
        }
        match self.mode {
            AppMode::Commander => crate::tui::commander::on_key(self, key),
            AppMode::Wizard => self.on_key_wizard(key),
        }
    }

    /// Input for the startup disclaimer gate: Space — toggle the checkbox under
    /// focus, Tab/↑/↓ — switch focus, Enter — enter (only when agreed),
    /// Esc — exit the program.
    fn on_key_disclaimer(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                self.disclaimer.focus = 1 - self.disclaimer.focus;
            }
            KeyCode::Char(' ') => {
                if self.disclaimer.focus == 0 {
                    self.disclaimer.agreed = !self.disclaimer.agreed;
                } else {
                    self.disclaimer.suppress = !self.disclaimer.suppress;
                }
            }
            KeyCode::Enter => {
                if self.disclaimer.agreed {
                    self.dismiss_disclaimer();
                }
            }
            KeyCode::Esc => self.should_quit = true,
            _ => {}
        }
    }

    /// Closes the disclaimer gate. If "don't show" is checked — persists
    /// consent for the current version of the text (`<state_dir>/consent.json`).
    fn dismiss_disclaimer(&mut self) {
        if self.disclaimer.suppress {
            if let Some(dir) = self.db_path.parent() {
                let _ = crate::consent::save(
                    dir,
                    &crate::consent::Consent {
                        suppressed: true,
                        disclaimer_version: crate::consent::DISCLAIMER_VERSION,
                    },
                );
            }
        }
        self.show_disclaimer = false;
    }

    /// Input for the startup role-selection overlay when an operator is live
    /// (`ask` policy): `[R]` — read-only observer; `[F]` — become the
    /// operator (retry the acquire: another instance may have exited,
    /// otherwise — by force, without a lock); `Esc` — exit.
    fn on_key_concurrency(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.read_only = true;
                self.concurrency_prompt = None;
                self.commander.status = "Observer mode: read-only".to_string();
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                if let Some(dir) = self.db_path.parent() {
                    match crate::lock::try_acquire(dir) {
                        Ok(crate::lock::Acquire::Operator(lock)) => {
                            self.instance_lock = Some(lock);
                            self.read_only = false;
                            self.commander.status = "Operator role acquired".to_string();
                        }
                        _ => {
                            self.read_only = false;
                            self.commander.status =
                                "WARNING: operator by force — another instance is active"
                                    .to_string();
                        }
                    }
                } else {
                    self.read_only = false;
                }
                self.concurrency_prompt = None;
            }
            KeyCode::Esc => self.should_quit = true,
            _ => {}
        }
    }

    /// Gate for destructive operations in "read-only" mode. If
    /// an observer is active — sets an explanatory status and returns `true`
    /// (the caller must abort). Otherwise `false` — the operation is allowed.
    pub fn deny_if_read_only(&mut self, what: &str) -> bool {
        if self.read_only {
            let msg = format!("Read-only: {what} unavailable (another instance is active)");
            match self.mode {
                AppMode::Commander => self.commander.status = msg,
                AppMode::Wizard => self.status = msg,
            }
            return true;
        }
        false
    }

    /// Mouse event: in commander mode — click and wheel over panels and the footer;
    /// on the Browser screen — wheel and left-click.
    fn on_mouse(&mut self, mouse: MouseEvent) {
        if matches!(self.mode, AppMode::Commander) {
            crate::tui::commander::on_mouse(self, mouse);
            return;
        }
        if matches!(self.screen, Screen::Browser) {
            self.on_mouse_browser(mouse);
        }
    }

    /// Mouse on the Browser screen:
    /// - Wheel ↑/↓ — scroll the cursor by 3 entries of the focused panel of the active
    ///   tab.
    /// - Left-click on the tab bar — switch the tab.
    /// - Left-click on the body — switch focus to the panel under the cursor +
    ///   select the real row. Double-click = Enter
    ///   (`browser_set_keeper` for Files / `browser_dir_set_keeper` for Dirs).
    fn on_mouse_browser(&mut self, mouse: MouseEvent) {
        use crate::tui::screens::browser::BrowserTab;
        match mouse.kind {
            MouseEventKind::ScrollUp => match self.browser.tab {
                BrowserTab::Files => self.browser_move(-3),
                BrowserTab::Dirs => self.browser_dir_move(-3),
            },
            MouseEventKind::ScrollDown => match self.browser.tab {
                BrowserTab::Files => self.browser_move(3),
                BrowserTab::Dirs => self.browser_dir_move(3),
            },
            MouseEventKind::Down(MouseButton::Left) => {
                self.browser_mouse_click(mouse.column, mouse.row);
            }
            _ => {}
        }
    }

    /// Mapping a left-click in the browser: first the tab-bar check, then
    /// determining the panel + row of the active tab.
    fn browser_mouse_click(&mut self, col: u16, row: u16) {
        use crate::tui::screens::browser::BrowserTab;
        // 1) Click on the tab bar — switch, exit without selection.
        if self
            .browser
            .tab_files_area
            .is_some_and(|a| rect_contains(a, col, row))
        {
            self.browser.tab = BrowserTab::Files;
            self.browser.focus_files = false;
            self.status.clear();
            return;
        }
        if self
            .browser
            .tab_dirs_area
            .is_some_and(|a| rect_contains(a, col, row))
        {
            self.browser.tab = BrowserTab::Dirs;
            self.browser.focus_files = false;
            if self.browser.open_dir_group.is_none() && !self.browser.dir_group_summaries.is_empty()
            {
                if self.browser.dir_group_state.selected().is_none() {
                    self.browser.dir_group_state.select(Some(0));
                }
                self.open_selected_dir_group();
            }
            self.status.clear();
            return;
        }
        // 2) Click on the body — dispatch by active tab.
        match self.browser.tab {
            BrowserTab::Files => self.browser_mouse_click_files(col, row),
            BrowserTab::Dirs => self.browser_mouse_click_dirs(col, row),
        }
    }

    /// Left-click in the body of the `[1] Files` tab (split).
    /// Logic of behavior unchanged.
    fn browser_mouse_click_files(&mut self, col: u16, row: u16) {
        let groups_hit = self
            .browser
            .groups_area
            .is_some_and(|a| rect_contains(a, col, row));
        let files_hit = self
            .browser
            .files_area
            .is_some_and(|a| rect_contains(a, col, row));
        if !groups_hit && !files_hit {
            return; // click missed both panels (header/footer) — ignore
        }

        // Switch focus to under the cursor. If clicked where focus ALREADY is —
        // nothing changes. If groups AND files overlap (not our
        // case — horizontal layout), groups takes priority.
        let want_focus_files = files_hit && !groups_hit;
        self.browser.focus_files = want_focus_files;

        let Some(area) = (if want_focus_files {
            self.browser.files_area
        } else {
            self.browser.groups_area
        }) else {
            return;
        };

        // Inside the panel: top — border (1 row), bottom — border too. visual_row
        // (0-based) = row - area.y - 1. If the click is on the border — ignore.
        let Some(visual_row) = row.checked_sub(area.y + 1) else {
            return;
        };
        if (visual_row + 2) > area.height {
            return; // click on the bottom border
        }

        let (start, total) = if want_focus_files {
            (
                self.browser.file_state.offset(),
                self.browser
                    .open_group
                    .as_ref()
                    .map_or(0, |g| g.files.len()),
            )
        } else {
            (
                self.browser.group_state.offset(),
                self.browser.group_summaries.len(),
            )
        };
        let real_idx = match crate::tui::screens::browser::visual_to_real_index(
            start,
            visual_row as usize,
            total,
        ) {
            Some(idx) => idx,
            None => return, // click on a separator or outside the list — ignore
        };

        if want_focus_files {
            self.browser.file_state.select(Some(real_idx));
            self.maybe_load_more_files();
        } else {
            let prev = self.browser.group_state.selected();
            self.browser.group_state.select(Some(real_idx));
            if self.browser.group_state.selected() != prev {
                self.open_selected_group();
            }
        }

        // Double-click: same (col,row) and recent (< DOUBLE_CLICK_MS).
        let now = Instant::now();
        let is_double = self.browser.last_click.is_some_and(|(t, c, r)| {
            now.duration_since(t) < Duration::from_millis(DOUBLE_CLICK_MS) && c == col && r == row
        });
        self.browser.last_click = Some((now, col, row));
        if is_double {
            self.browser_set_keeper();
        }
    }

    /// Left-click in the body of the `[2] Directories` tab (Stage 1).
    /// Mirror of `browser_mouse_click_files` for the dir-states.
    fn browser_mouse_click_dirs(&mut self, col: u16, row: u16) {
        let groups_hit = self
            .browser
            .groups_area
            .is_some_and(|a| rect_contains(a, col, row));
        let files_hit = self
            .browser
            .files_area
            .is_some_and(|a| rect_contains(a, col, row));
        if !groups_hit && !files_hit {
            return;
        }
        let want_focus_files = files_hit && !groups_hit;
        self.browser.focus_files = want_focus_files;

        let Some(area) = (if want_focus_files {
            self.browser.files_area
        } else {
            self.browser.groups_area
        }) else {
            return;
        };
        let Some(visual_row) = row.checked_sub(area.y + 1) else {
            return;
        };
        if (visual_row + 2) > area.height {
            return;
        }

        let (start, total) = if want_focus_files {
            (
                self.browser.dir_file_state.offset(),
                self.browser
                    .open_dir_group
                    .as_ref()
                    .map_or(0, |g| g.paths.len()),
            )
        } else {
            (
                self.browser.dir_group_state.offset(),
                self.browser.dir_group_summaries.len(),
            )
        };
        // Separators are not drawn in Dirs, but we use the common
        // function for uniformity — with no separators the result is correct there.
        let real_idx = match crate::tui::screens::browser::visual_to_real_index(
            start,
            visual_row as usize,
            total,
        ) {
            Some(idx) => idx,
            None => return,
        };

        if want_focus_files {
            self.browser.dir_file_state.select(Some(real_idx));
        } else {
            let prev = self.browser.dir_group_state.selected();
            self.browser.dir_group_state.select(Some(real_idx));
            if self.browser.dir_group_state.selected() != prev {
                self.open_selected_dir_group();
            }
        }

        let now = Instant::now();
        let is_double = self.browser.last_click.is_some_and(|(t, c, r)| {
            now.duration_since(t) < Duration::from_millis(DOUBLE_CLICK_MS) && c == col && r == row
        });
        self.browser.last_click = Some((now, col, row));
        if is_double {
            self.browser_dir_set_keeper();
        }
    }

    /// Input in the classic wizard — a dispatcher by the current screen.
    fn on_key_wizard(&mut self, key: KeyEvent) {
        // Modal confirmation intercepts all input.
        if self.confirm.is_some() {
            self.on_key_confirm(key);
            return;
        }
        if key.code == KeyCode::Char('?') {
            self.show_help = true;
            return;
        }
        // Esc from results opened from the session list (E2E feedback): return to
        // the list, not to commander — don't jump over the parent. Then Esc from the list → commander.
        if self.results_from_sessions && self.screen == Screen::Browser && key.code == KeyCode::Esc
        {
            self.results_from_sessions = false;
            self.screen = Screen::Resume;
            self.status.clear();
            return;
        }
        // The wizard was opened from the commander — Esc/q on the top screen return there.
        if self.commander.return_to_commander
            && matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q')
            )
            && matches!(
                self.screen,
                Screen::ScanConfig | Screen::Resume | Screen::Browser | Screen::Summary
            )
        {
            self.return_to_commander();
            return;
        }
        match self.screen {
            Screen::ScanConfig => self.on_key_scan_config(key),
            Screen::FolderPicker => self.on_key_folder_picker(key),
            Screen::Resume => self.on_key_resume(key),
            Screen::Scanning => self.on_key_scanning(key),
            Screen::Applying => self.on_key_applying(key),
            Screen::Browser => self.on_key_browser(key),
            Screen::ActionReview => self.on_key_action_review(key),
            Screen::Summary => self.on_key_summary(key),
            Screen::ScanDiff => self.on_key_scan_diff(key),
            Screen::Trash => self.on_key_trash(key),
        }
    }

    fn on_key_scan_config(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.config.cursor > 0 {
                    self.config.cursor -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.config.cursor + 1 < self.config.roots.len() {
                    self.config.cursor += 1;
                }
            }
            KeyCode::Char(' ') => {
                if let Some(root) = self.config.roots.get_mut(self.config.cursor) {
                    root.selected = !root.selected;
                }
            }
            KeyCode::Char('f') | KeyCode::Char('F') => self.open_folder_picker(),
            KeyCode::Char('p') | KeyCode::Char('P') => {
                if !self.config.presets.is_empty() {
                    self.config.preset_index =
                        (self.config.preset_index + 1) % self.config.presets.len();
                }
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.config.reuse_hashes = !self.config.reuse_hashes;
            }
            KeyCode::Char('g') | KeyCode::Char('G') => {
                self.config.hash_profile = self.config.hash_profile.next();
            }
            KeyCode::Delete => self.remove_current_root(),
            KeyCode::Char('s') | KeyCode::Char('S') => self.start_scan(None),
            _ => {}
        }
    }

    fn on_key_folder_picker(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Esc => self.screen = Screen::ScanConfig,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.folder_picker.cursor > 0 {
                    self.folder_picker.cursor -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.folder_picker.cursor + 1 < self.folder_picker.entries.len() {
                    self.folder_picker.cursor += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(dir) = self
                    .folder_picker
                    .entries
                    .get(self.folder_picker.cursor)
                    .cloned()
                {
                    self.folder_picker_enter(dir);
                }
            }
            KeyCode::Backspace | KeyCode::Left => {
                if let Some(parent) = self.folder_picker.current_dir.parent() {
                    self.folder_picker_enter(parent.to_path_buf());
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => self.add_current_folder(),
            _ => {}
        }
    }

    fn on_key_resume(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Char('n') | KeyCode::Char('N') => self.screen = Screen::ScanConfig,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.session_cursor > 0 {
                    self.session_cursor -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.session_cursor + 1 < self.sessions.len() {
                    self.session_cursor += 1;
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => self.resume_selected(),
            KeyCode::Char('d') | KeyCode::Char('D') => self.open_scan_diff(),
            KeyCode::Char('t') | KeyCode::Char('T') => self.open_trash(),
            KeyCode::Delete => self.request_trash_selected(),
            _ => {}
        }
    }

    /// D on the sessions screen: compares the selected session (newer) with the next in
    /// the list (older). The diff is computed in the background.
    fn open_scan_diff(&mut self) {
        let (old_id, new_id, root) = match (
            self.sessions.get(self.session_cursor + 1),
            self.sessions.get(self.session_cursor),
        ) {
            (Some(old), Some(new)) => (
                old.scan_id,
                new.scan_id,
                new.roots
                    .first()
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from("/")),
            ),
            _ => {
                self.status = "No older scan to compare against".to_string();
                return;
            }
        };
        self.scan_diff = ScanDiffState {
            loading: true,
            ..Default::default()
        };
        self.screen = Screen::ScanDiff;
        self.status = format!("Comparing scans #{old_id} ↔ #{new_id}…");
        let db_path = self.db_path.clone();
        let events = self.events.clone();
        std::thread::spawn(move || {
            let report = ScanStore::open(&db_path)
                .and_then(|store| crate::state::move_track::diff(&store, old_id, new_id, &root));
            let _ = match report {
                Ok(report) => events.send(AppEvent::ScanDiffReady(Box::new(report))),
                Err(err) => events.send(AppEvent::ScanDiffFailed(err.to_string())),
            };
        });
    }

    fn on_key_scan_diff(&mut self, key: KeyEvent) {
        let categories = crate::tui::screens::scan_diff::CATEGORIES.len();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::F(10) => {
                self.screen = Screen::Resume;
            }
            KeyCode::Tab => {
                self.scan_diff.category = (self.scan_diff.category + 1) % categories;
                self.scan_diff.list.select(Some(0));
            }
            KeyCode::BackTab => {
                self.scan_diff.category = (self.scan_diff.category + categories - 1) % categories;
                self.scan_diff.list.select(Some(0));
            }
            KeyCode::Up | KeyCode::Char('k') => self.scan_diff_move(-1),
            KeyCode::Down | KeyCode::Char('j') => self.scan_diff_move(1),
            _ => {}
        }
    }

    fn scan_diff_move(&mut self, delta: i32) {
        let len = crate::tui::screens::scan_diff::category_len(&self.scan_diff) as i32;
        if len == 0 {
            self.scan_diff.list.select(None);
            return;
        }
        let cur = self.scan_diff.list.selected().unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, len - 1);
        self.scan_diff.list.select(Some(next as usize));
    }

    /// Opens the selected session: an unfinished one — resumes it, a completed one —
    /// reopens it to the results screen (data from the DB, without rescanning).
    fn resume_selected(&mut self) {
        let Some(session) = self.sessions.get(self.session_cursor) else {
            return;
        };
        let scan_id = session.scan_id;
        let status = session.status;
        // Completed scan — open the RESULT without rescanning; unfinished
        // — continue hashing. Opening from the list → Esc returns to the list (E2E feedback).
        if status.is_completed() {
            self.results_from_sessions = true;
            self.spawn_open_completed(scan_id);
        } else {
            self.results_from_sessions = false;
            self.start_scan(Some(scan_id));
        }
    }

    /// Opens a completed scan as a RESULT in the background: without a worker, phases,
    /// `set_status`, or `add_elapsed` (viewing doesn't spoil the time metric) — read-only of
    /// the materialization. The result arrives via the `ResultsLoaded` event.
    pub fn spawn_open_completed(&mut self, scan_id: i64) {
        self.status = "Opening results…".to_string();
        self.commander.status = "Opening results…".to_string();
        // Enable the "Opening result" animation (E2E feedback): the first opening of an old
        // scan materializes once and can be slow — a live indicator is needed.
        self.opening_started = Some(std::time::Instant::now());
        let db_path = self.db_path.clone();
        let events = self.events.clone();
        std::thread::spawn(move || {
            let (summaries, summary) = match ScanStore::open(&db_path) {
                Ok(mut store) => {
                    // Materialize file_group once, if it doesn't exist yet (scan completed
                    // previously), then read the lightweight summaries — without groups in RAM.
                    let _ = store.ensure_materialized(scan_id);
                    let summaries = store.group_summaries(scan_id).unwrap_or_default();
                    let summary = store.scan_summary(scan_id).unwrap_or_default();
                    (summaries, summary)
                }
                Err(_) => (Vec::new(), ScanSummary::default()),
            };
            let _ = events.send(AppEvent::ResultsLoaded(scan_id, summaries, summary));
        });
    }

    /// Del on the sessions screen: requests confirmation to move to
    /// trash. Deletion is soft and reversible; hard purge — separately, from the trash.
    fn request_trash_selected(&mut self) {
        if self.deny_if_read_only("scan deletion") {
            return;
        }
        // A scan is running — it writes to the same DB; we don't start edits, to avoid a race.
        if self.scan.is_some() {
            self.status = "A scan is running — stop it (Esc), then delete scans".to_string();
            return;
        }
        if let Some(session) = self.sessions.get(self.session_cursor) {
            self.confirm = Some(ConfirmAction::TrashScan(session.scan_id));
        }
    }

    /// Input for modal confirmation: Y/Enter — execute, N/Esc — cancel.
    fn on_key_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                if let Some(action) = self.confirm.take() {
                    match action {
                        ConfirmAction::TrashScan(id) => self.execute_trash(id),
                        ConfirmAction::PurgeScan(id) => self.execute_purge(id),
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.confirm = None,
            _ => {}
        }
    }

    /// Moves the session to trash — instantly (one UPDATE), reversibly.
    fn execute_trash(&mut self, scan_id: i64) {
        match ScanStore::open(&self.db_path).and_then(|store| store.trash_scan(scan_id)) {
            Ok(()) => {
                self.sessions.retain(|s| s.scan_id != scan_id);
                if self.session_cursor >= self.sessions.len() {
                    self.session_cursor = self.sessions.len().saturating_sub(1);
                }
                self.status = "Session in trash · t — open trash".to_string();
                if self.sessions.is_empty() {
                    self.screen = Screen::ScanConfig;
                }
            }
            Err(err) => self.status = format!("Failed to move to trash: {err}"),
        }
    }

    /// `t` on the sessions screen: open the trash.
    fn open_trash(&mut self) {
        self.trashed = ScanStore::open(&self.db_path)
            .and_then(|store| store.list_trashed())
            .unwrap_or_default();
        self.trash_cursor = 0;
        self.screen = Screen::Trash;
        self.status = if self.trashed.is_empty() {
            "Trash is empty · Esc back".to_string()
        } else {
            "Trash · R restore · Del purge forever · Esc back".to_string()
        };
    }

    fn on_key_trash(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => self.screen = Screen::Resume,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.trash_cursor > 0 {
                    self.trash_cursor -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.trash_cursor + 1 < self.trashed.len() {
                    self.trash_cursor += 1;
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => {
                self.restore_selected_trash()
            }
            KeyCode::Delete => {
                if self.deny_if_read_only("purging the trash") {
                    return;
                }
                if let Some(t) = self.trashed.get(self.trash_cursor) {
                    self.confirm = Some(ConfirmAction::PurgeScan(t.scan_id));
                }
            }
            _ => {}
        }
    }

    /// Restores the selected session from trash and refreshes the active-sessions list.
    fn restore_selected_trash(&mut self) {
        if self.deny_if_read_only("scan restoration") {
            return;
        }
        let Some(scan_id) = self.trashed.get(self.trash_cursor).map(|t| t.scan_id) else {
            return;
        };
        match ScanStore::open(&self.db_path).and_then(|store| store.restore_scan(scan_id)) {
            Ok(()) => {
                self.trashed.retain(|t| t.scan_id != scan_id);
                if self.trash_cursor >= self.trashed.len() {
                    self.trash_cursor = self.trashed.len().saturating_sub(1);
                }
                // The active list is stale — re-read in the background.
                self.sessions_loaded = false;
                self.sessions_loading = false;
                self.spawn_sessions_load();
                self.status = "Session restored".to_string();
            }
            Err(err) => self.status = format!("Failed to restore: {err}"),
        }
    }

    /// Purges the session from trash FOREVER. The heavy multi-index DELETE on `file`
    /// (millions of rows on /tank) runs in the BACKGROUND — otherwise it hangs the terminal for minutes (E2E fix r11).
    fn execute_purge(&mut self, scan_id: i64) {
        self.trashed.retain(|t| t.scan_id != scan_id);
        if self.trash_cursor >= self.trashed.len() {
            self.trash_cursor = self.trashed.len().saturating_sub(1);
        }
        self.status = "Purging from trash in the background…".to_string();
        let db_path = self.db_path.clone();
        let events = self.events.clone();
        std::thread::spawn(move || {
            let result = ScanStore::open(&db_path)
                .and_then(|mut store| store.purge_scan(scan_id))
                .map(|()| scan_id)
                .map_err(|err| err.to_string());
            let _ = events.send(AppEvent::SessionDeleted(result));
        });
    }

    fn on_key_scanning(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Esc => {
                if let Some(handle) = &self.scan {
                    handle.cancel();
                    self.status = "Stopping the scan…".to_string();
                }
            }
            _ => {}
        }
    }

    fn on_key_applying(&mut self, key: KeyEvent) {
        // During application, input is blocked except Esc — cancel after the current
        // action (q does not exit: you must not abandon the process mid-destructive).
        // The snapshot is already made, what's applied is in quarantine, the partial result is consistent.
        if matches!(key.code, KeyCode::Esc) {
            if let Some(handle) = &self.apply {
                handle.cancel();
                self.status = "Stopping application after the current action…".to_string();
            }
        }
    }

    fn on_key_browser(&mut self, key: KeyEvent) {
        use crate::tui::screens::browser::BrowserTab;
        // Global browser-screen keys — independent of the tab.
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.should_quit = true;
                return;
            }
            KeyCode::Esc => {
                self.screen = Screen::ScanConfig;
                self.status.clear();
                return;
            }
            KeyCode::Char('1') => {
                self.browser.tab = BrowserTab::Files;
                self.browser.focus_files = false;
                self.status.clear();
                return;
            }
            KeyCode::Char('2') => {
                self.browser.tab = BrowserTab::Dirs;
                self.browser.focus_files = false;
                // Open the selected dir-group lazily — on the first entry into the Dirs tab.
                if self.browser.open_dir_group.is_none()
                    && !self.browser.dir_group_summaries.is_empty()
                {
                    if self.browser.dir_group_state.selected().is_none() {
                        self.browser.dir_group_state.select(Some(0));
                    }
                    self.open_selected_dir_group();
                }
                self.status.clear();
                return;
            }
            _ => {}
        }
        // Tab switches panel focus in both tabs.
        if key.code == KeyCode::Tab {
            self.browser.focus_files = !self.browser.focus_files;
            return;
        }
        // Dispatch navigation/actions by the active tab.
        match self.browser.tab {
            BrowserTab::Files => self.on_key_browser_files(key),
            BrowserTab::Dirs => self.on_key_browser_dirs(key),
        }
    }

    /// Keys for the `[1] Files` tab (split by
    /// tabs). Identical to the behavior of — no regressions.
    fn on_key_browser_files(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.browser_move(-1),
            KeyCode::Down | KeyCode::Char('j') => self.browser_move(1),
            KeyCode::PageUp => self.browser_page(-1),
            KeyCode::PageDown => self.browser_page(1),
            // Home/End + vim-style aliases `g`/`G`.
            KeyCode::Home | KeyCode::Char('g') => self.browser_home(),
            KeyCode::End | KeyCode::Char('G') => self.browser_end(),
            KeyCode::Enter => self.browser_set_keeper(),
            KeyCode::Char('d') | KeyCode::Char('D') => self.browser_mark(Some(ActionKind::Delete)),
            KeyCode::Char('h') | KeyCode::Char('H') => {
                self.browser_mark(Some(ActionKind::Hardlink))
            }
            KeyCode::Char('c') | KeyCode::Char('C') => self.browser_mark(Some(ActionKind::Reflink)),
            KeyCode::Char(' ') => self.browser_mark(None),
            KeyCode::Char('a') | KeyCode::Char('A') => self.browser_auto(),
            KeyCode::Char('r') | KeyCode::Char('R') => self.open_review(),
            KeyCode::Char('v') | KeyCode::Char('V') => {
                self.browser.path_style = self.browser.path_style.next();
            }
            _ => {}
        }
    }

    /// Keys for the `[2] Directories` tab (Stage 1). Only
    /// viewing + assigning the ★ keeper; marks/actions — a separate round
    /// (Stage 2), for now they show a status message.
    fn on_key_browser_dirs(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.browser_dir_move(-1),
            KeyCode::Down | KeyCode::Char('j') => self.browser_dir_move(1),
            KeyCode::PageUp => self.browser_dir_page(-1),
            KeyCode::PageDown => self.browser_dir_page(1),
            KeyCode::Home | KeyCode::Char('g') => self.browser_dir_home(),
            KeyCode::End | KeyCode::Char('G') => self.browser_dir_end(),
            KeyCode::Enter => self.browser_dir_set_keeper(),
            KeyCode::Char('d')
            | KeyCode::Char('D')
            | KeyCode::Char('h')
            | KeyCode::Char('H')
            | KeyCode::Char('c')
            | KeyCode::Char('C')
            | KeyCode::Char(' ')
            | KeyCode::Char('a')
            | KeyCode::Char('A')
            | KeyCode::Char('r')
            | KeyCode::Char('R') => {
                self.status =
                    "Actions on directories — a separate round (Stage 2). For now only viewing is available."
                        .to_string();
            }
            _ => {}
        }
    }

    fn on_key_action_review(&mut self, key: KeyEvent) {
        if self.review.confirming {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.apply_actions(),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.review.confirming = false;
                }
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Char('y') | KeyCode::Char('Y') => self.review.confirming = true,
            KeyCode::Esc => {
                self.screen = Screen::Browser;
                self.status.clear();
            }
            _ => {}
        }
    }

    fn on_key_summary(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Esc => {
                self.screen = Screen::ScanConfig;
                self.status = "Actions applied. Start a new scan for fresh data.".to_string();
            }
            _ => {}
        }
    }

    /// Opens the file browser for choosing an arbitrary folder (starting from the FS root).
    fn open_folder_picker(&mut self) {
        self.folder_picker_enter(PathBuf::from("/"));
        self.screen = Screen::FolderPicker;
    }

    /// Navigates into directory `dir` in the file browser.
    fn folder_picker_enter(&mut self, dir: PathBuf) {
        self.folder_picker.entries = list_subdirs(&dir);
        self.folder_picker.current_dir = dir;
        self.folder_picker.cursor = 0;
    }

    /// Adds the current file-browser directory to the list of scan roots.
    fn add_current_folder(&mut self) {
        let path = self.folder_picker.current_dir.clone();
        if self.config.roots.iter().any(|root| root.path == path) {
            self.status = format!("Folder already in the list: {}", path.display());
        } else {
            self.config.roots.push(RootChoice {
                label: String::new(),
                path: path.clone(),
                selected: true,
                is_dataset: false,
            });
            self.config.cursor = self.config.roots.len() - 1;
            self.status = format!("Folder added: {}", path.display());
        }
        self.screen = Screen::ScanConfig;
    }

    /// Removes the selected root from the list — only if it's an arbitrary folder.
    fn remove_current_root(&mut self) {
        match self.config.roots.get(self.config.cursor) {
            Some(root) if !root.is_dataset => {
                self.config.roots.remove(self.config.cursor);
                if self.config.cursor >= self.config.roots.len() {
                    self.config.cursor = self.config.roots.len().saturating_sub(1);
                }
            }
            _ => {
                self.status = "Cannot delete a dataset — uncheck it (Space)".to_string();
            }
        }
    }

    /// Moves the selection in the active Browser panel. Changing the group loads its
    /// files from the DB, discarding the previously open group.
    /// When moving the cursor in files — if we approach the end of
    /// the window, we load the next page (`maybe_load_more_files`).
    fn browser_move(&mut self, delta: i32) {
        if self.browser.focus_files {
            let len = self
                .browser
                .open_group
                .as_ref()
                .map_or(0, |g| g.files.len());
            step(&mut self.browser.file_state, len, delta);
            self.maybe_load_more_files();
        } else {
            let prev = self.browser.group_state.selected();
            step(
                &mut self.browser.group_state,
                self.browser.group_summaries.len(),
                delta,
            );
            if self.browser.group_state.selected() != prev {
                self.open_selected_group();
            }
        }
    }

    /// PgUp/PgDn in the browser. Step = "a page of what
    /// you see" — `visible_rows - 1` entries of the focused panel (classic
    /// two-panel shells). The height is not yet fixed (`= 0` until the first
    /// frame) — fallback 20.
    fn browser_page(&mut self, delta_pages: i32) {
        let rows = if self.browser.focus_files {
            self.browser.files_visible_rows
        } else {
            self.browser.group_visible_rows
        };
        self.browser_move(page_step(rows, delta_pages));
    }

    /// Home in the browser — cursor of the focused panel to 0.
    /// For groups: changing the group triggers `open_selected_group` (like `browser_move`).
    fn browser_home(&mut self) {
        if self.browser.focus_files {
            if self
                .browser
                .open_group
                .as_ref()
                .is_some_and(|g| !g.files.is_empty())
            {
                self.browser.file_state.select(Some(0));
            }
        } else {
            let prev = self.browser.group_state.selected();
            if !self.browser.group_summaries.is_empty() {
                self.browser.group_state.select(Some(0));
                if self.browser.group_state.selected() != prev {
                    self.open_selected_group();
                }
            }
        }
    }

    /// End in the browser. For groups — the last rank, for
    /// files — load all pages up to `open_group_total` or the
    /// `BROWSE_GROUP_FILE_MAX` limit (synchronously, the user EXPECTS to reach the end), then
    /// the cursor to the last loaded file.
    fn browser_end(&mut self) {
        if self.browser.focus_files {
            // Load pages until we hit total or the limit. The loop
            // is guarded: if a page returned 0 files (error/exhausted) — we exit.
            loop {
                if self.browser.open_group_max_reached {
                    break;
                }
                let loaded = self
                    .browser
                    .open_group
                    .as_ref()
                    .map_or(0, |g| g.files.len());
                let total = self.browser.open_group_total as usize;
                if loaded >= total {
                    break;
                }
                // Emulate "cursor at the end of the window" — `maybe_load_more_files`
                // will load the next page from the DB.
                self.browser
                    .file_state
                    .select(Some(loaded.saturating_sub(1)));
                self.maybe_load_more_files();
                let after = self
                    .browser
                    .open_group
                    .as_ref()
                    .map_or(0, |g| g.files.len());
                if after <= loaded {
                    break; // nothing was loaded — we exit
                }
            }
            let len = self
                .browser
                .open_group
                .as_ref()
                .map_or(0, |g| g.files.len());
            if len > 0 {
                self.browser.file_state.select(Some(len - 1));
            }
        } else {
            let prev = self.browser.group_state.selected();
            let len = self.browser.group_summaries.len();
            if len > 0 {
                self.browser.group_state.select(Some(len - 1));
                if self.browser.group_state.selected() != prev {
                    self.open_selected_group();
                }
            }
        }
    }

    // === Navigation in the `[2] Directories` tab ===
    // Mirror of `browser_move`/`browser_page`/`browser_home`/`browser_end` for
    // the file-tab, but works with `dir_group_state` / `dir_file_state`.

    fn browser_dir_move(&mut self, delta: i32) {
        if self.browser.focus_files {
            let len = self
                .browser
                .open_dir_group
                .as_ref()
                .map_or(0, |g| g.paths.len());
            step(&mut self.browser.dir_file_state, len, delta);
        } else {
            let prev = self.browser.dir_group_state.selected();
            step(
                &mut self.browser.dir_group_state,
                self.browser.dir_group_summaries.len(),
                delta,
            );
            if self.browser.dir_group_state.selected() != prev {
                self.open_selected_dir_group();
            }
        }
    }

    fn browser_dir_page(&mut self, delta_pages: i32) {
        let rows = if self.browser.focus_files {
            self.browser.files_visible_rows
        } else {
            self.browser.group_visible_rows
        };
        self.browser_dir_move(page_step(rows, delta_pages));
    }

    fn browser_dir_home(&mut self) {
        if self.browser.focus_files {
            if self
                .browser
                .open_dir_group
                .as_ref()
                .is_some_and(|g| !g.paths.is_empty())
            {
                self.browser.dir_file_state.select(Some(0));
            }
        } else {
            let prev = self.browser.dir_group_state.selected();
            if !self.browser.dir_group_summaries.is_empty() {
                self.browser.dir_group_state.select(Some(0));
                if self.browser.dir_group_state.selected() != prev {
                    self.open_selected_dir_group();
                }
            }
        }
    }

    fn browser_dir_end(&mut self) {
        if self.browser.focus_files {
            let len = self
                .browser
                .open_dir_group
                .as_ref()
                .map_or(0, |g| g.paths.len());
            if len > 0 {
                self.browser.dir_file_state.select(Some(len - 1));
            }
        } else {
            let prev = self.browser.dir_group_state.selected();
            let len = self.browser.dir_group_summaries.len();
            if len > 0 {
                self.browser.dir_group_state.select(Some(len - 1));
                if self.browser.dir_group_state.selected() != prev {
                    self.open_selected_dir_group();
                }
            }
        }
    }

    /// Enter on the right panel of the Dirs tab — assign the ★ keeper to the cursor's
    /// directory in `open_dir_group.paths`. On the left panel, Enter — opening the group
    /// already happens via `browser_dir_move` (as in the file-tab); here — a no-op
    /// so that an accidental press on the left panel doesn't reset the keeper.
    fn browser_dir_set_keeper(&mut self) {
        if !self.browser.focus_files {
            return;
        }
        let Some(idx) = self.browser.dir_file_state.selected() else {
            return;
        };
        let in_range = self
            .browser
            .open_dir_group
            .as_ref()
            .is_some_and(|g| idx < g.paths.len());
        if in_range {
            self.browser.dir_keeper_index = idx;
        }
    }

    /// When the cursor approaches the end of the `open_group.files`
    /// window — loads the next page from the DB. Previously, the window was a static 200
    /// files, and the header honestly said "(first)"; now the user can scroll
    /// up to `BROWSE_GROUP_FILE_MAX` (a safeguard against /tank's 2.19M anomalies).
    /// We recompute the `open_group_colors` palette after the extend — otherwise new file names
    /// would be left without a color.
    fn maybe_load_more_files(&mut self) {
        if self.browser.open_group_max_reached {
            return;
        }
        let Some(cursor) = self.browser.file_state.selected() else {
            return;
        };
        let (hash, loaded) = match self.browser.open_group.as_ref() {
            Some(g) => (g.hash.clone(), g.files.len()),
            None => return,
        };
        let total = self.browser.open_group_total as usize;
        if loaded >= total {
            return;
        }
        if loaded >= BROWSE_GROUP_FILE_MAX {
            self.browser.open_group_max_reached = true;
            return;
        }
        // We trigger one page before the end of the window — so the user doesn't hit the wall.
        if cursor + BROWSE_GROUP_FILE_PAGE < loaded {
            return;
        }
        let Some(scan_id) = self.current_scan_id else {
            return;
        };
        let next = self
            .browse_conn()
            .and_then(|store| {
                store
                    .group_files_page(scan_id, &hash, loaded, BROWSE_GROUP_FILE_PAGE)
                    .ok()
            })
            .unwrap_or_default();
        if next.is_empty() {
            return;
        }
        if let Some(open_mut) = self.browser.open_group.as_mut() {
            open_mut.files.extend(next);
            if open_mut.files.len() >= BROWSE_GROUP_FILE_MAX
                || open_mut.files.len() as u64 >= self.browser.open_group_total
            {
                self.browser.open_group_max_reached = true;
            }
            // The palette needs recomputing: new file names have arrived, and without
            // an update they would be drawn in the default color.
            self.browser.open_group_colors = crate::tui::screens::browser::name_palette(open_mut);
        }
    }

    /// The (group, file) indices of the current selection, if valid (the file is in the open group).
    fn current_group_file(&self) -> Option<(usize, usize)> {
        let group_index = self.browser.group_state.selected()?;
        let file_index = self.browser.file_state.selected()?;
        let open = self.browser.open_group.as_ref()?;
        if file_index < open.files.len() {
            Some((group_index, file_index))
        } else {
            None
        }
    }

    /// Marks the current file of the open group with an action (or clears it with `None`).
    fn browser_mark(&mut self, action: Option<ActionKind>) {
        if action == Some(ActionKind::Reflink) && !self.zfs.capabilities.reflink_safe {
            self.status =
                "reflink unavailable — requires ZFS 2.3+ with block cloning enabled".to_string();
            return;
        }
        let Some((_, file_index)) = self.current_group_file() else {
            return;
        };
        if self
            .browser
            .open_group
            .as_ref()
            .is_some_and(|group| group.files[file_index].is_keeper)
        {
            self.status = "This is the keeper file — no action is applied to it".to_string();
            return;
        }
        if let Some(open) = self.browser.open_group.as_mut() {
            // Before an action in the group a keeper is needed — so the plan from the DB sees the
            // target→keeper pair. No keeper → assign a default one (any, except the target).
            if action.is_some() && !open.files.iter().any(|file| file.is_keeper) {
                if let Some(k) = (0..open.files.len()).find(|&i| i != file_index) {
                    open.files[k].is_keeper = true;
                }
            }
            open.files[file_index].action = action;
        }
        // Persist the whole group: keeper + marked; default rows are cleared.
        if let Some(open) = self.browser.open_group.as_ref() {
            self.persist_marks(open.files.iter());
        }
        self.refresh_marked_count();
    }

    /// Makes the current file the keeper of the open group.
    fn browser_set_keeper(&mut self) {
        let Some((_, file_index)) = self.current_group_file() else {
            return;
        };
        if let Some(open) = self.browser.open_group.as_mut() {
            for (index, file) in open.files.iter_mut().enumerate() {
                file.is_keeper = index == file_index;
                if index == file_index {
                    file.action = None;
                }
            }
        }
        if let Some(open) = self.browser.open_group.as_ref() {
            self.persist_marks(open.files.iter());
        }
        self.refresh_marked_count();
    }

    /// Auto-select: in each group keep the newest file, the rest — for deletion.
    /// Streams groups from the DB (per group — `group_files`), writes marks
    /// in batches (~500 groups/transaction), without holding the whole scan in RAM.
    fn browser_auto(&mut self) {
        let Some(scan_id) = self.current_scan_id else {
            return;
        };
        let Ok(mut store) = ScanStore::open(&self.db_path) else {
            self.status = "Auto-select: failed to open the DB".to_string();
            return;
        };
        const SAVE_CHUNK_GROUPS: usize = 500;
        let mut batch: Vec<FileEntry> = Vec::new();
        let mut groups_in_batch = 0usize;
        let mut failed = false;
        for summary in &self.browser.group_summaries {
            let mut files = match store.group_files(scan_id, &summary.hash) {
                Ok(files) if !files.is_empty() => files,
                _ => continue,
            };
            let keeper_index = pick_keeper(&files);
            for (index, file) in files.iter_mut().enumerate() {
                file.is_keeper = index == keeper_index;
                file.action = if index == keeper_index {
                    None
                } else {
                    Some(ActionKind::Delete)
                };
            }
            batch.append(&mut files);
            groups_in_batch += 1;
            if groups_in_batch >= SAVE_CHUNK_GROUPS {
                if store.save_marks(scan_id, batch.iter()).is_err() {
                    failed = true;
                    break;
                }
                batch.clear();
                groups_in_batch = 0;
            }
        }
        if !failed && !batch.is_empty() {
            failed = store.save_marks(scan_id, batch.iter()).is_err();
        }
        drop(store);
        self.status = if failed {
            "Auto-select: error writing marks".to_string()
        } else {
            "Auto-select: kept the newest file, the rest marked for deletion".to_string()
        };
        // Re-read the open group with fresh marks and update the counter.
        self.open_selected_group();
        self.refresh_marked_count();
    }

    /// Saves the marks of the specified files of the current scan to the DB (Feature 6B).
    /// Opens the DB in place; the error is not critical — the mark stays in RAM.
    fn persist_marks<'a>(&self, files: impl Iterator<Item = &'a FileEntry>) {
        let Some(scan_id) = self.current_scan_id else {
            return;
        };
        let result =
            ScanStore::open(&self.db_path).and_then(|mut store| store.save_marks(scan_id, files));
        if let Err(err) = result {
            tracing::warn!("failed to save action marks: {err}");
        }
    }

    /// Transition to the action review (if there are marked files). The plan
    /// is built DIRECTLY from the DB (`file` + `file_mark`), without materializing all groups.
    fn open_review(&mut self) {
        let plan = self
            .current_scan_id
            .and_then(|scan_id| {
                ScanStore::open(&self.db_path)
                    .ok()
                    .and_then(|store| actions::plan_actions_from_db(&store, scan_id).ok())
            })
            .unwrap_or_default();
        if plan.is_empty() {
            self.status = "No marked actions — mark files: d delete, h hardlink".to_string();
            return;
        }
        self.review = ReviewState {
            actions: plan,
            confirming: false,
        };
        self.status.clear();
        self.screen = Screen::ActionReview;
    }

    /// Applies the batch of actions (snapshot -> application) and transitions to the summary.
    fn apply_actions(&mut self) {
        if self.deny_if_read_only("performing actions") {
            return;
        }
        let plan = self.review.actions.clone();
        self.start_apply(plan);
    }

    /// Launches applying the batch in a background worker: the UI does not freeze,
    /// progress and summary come as `ApplyProgress`/`ApplyFinished` events. A single path
    /// for the wizard (`apply_actions`) and the commander (`confirm_execution`).
    pub fn start_apply(&mut self, plan: Vec<PlannedAction>) {
        if plan.is_empty() {
            return;
        }
        let datasets: Vec<Dataset> = self
            .zfs
            .pools
            .iter()
            .flat_map(|pool| pool.datasets.iter().cloned())
            .collect();
        self.apply_affected = plan.iter().map(|action| action.target.clone()).collect();
        self.applying = ApplyingState {
            total: plan.len(),
            bytes_total: actions::verify_bytes_total(&plan, self.reval_mode),
            mode: self.reval_mode,
            ..ApplyingState::default()
        };
        self.status.clear();
        self.screen = Screen::Applying;
        self.apply = Some(actions::apply_worker::spawn(
            plan,
            datasets,
            self.zfs.capabilities.reflink_safe,
            self.reval_mode,
            self.events.clone(),
        ));
    }

    /// Launches (or resumes) a scan in a background worker.
    fn start_scan(&mut self, resume: Option<i64>) {
        if self.deny_if_read_only("scanning") {
            return;
        }
        let config = if resume.is_some() {
            // On resume the config is taken from the DB; we pass a stub.
            ScanConfig::new(vec![PathBuf::from("/")])
        } else {
            let roots: Vec<PathBuf> = self
                .config
                .roots
                .iter()
                .filter(|root| root.selected)
                .map(|root| root.path.clone())
                .collect();
            if roots.is_empty() {
                self.status = "Select a dataset (Space) or add a folder (F)".to_string();
                return;
            }
            let mut config = ScanConfig::new(roots);
            if let Some(preset) = self.config.presets.get(self.config.preset_index) {
                config.include_extensions = preset.extensions.clone();
            }
            config.reuse_hashes = self.config.reuse_hashes;
            config.hash_profile = self.config.hash_profile;
            config.dir_sig_algo = self.config.dir_sig_algo;
            config
        };

        self.scanning = ScanningState::default();
        self.status.clear();
        self.screen = Screen::Scanning;
        self.scan = Some(worker::spawn(
            self.db_path.clone(),
            config,
            resume,
            self.verify,
            self.events.clone(),
        ));
    }

    /// Opens the wizard screen `screen`, invoked from the commander.
    pub fn open_wizard(&mut self, screen: Screen) {
        self.screen = screen;
        self.mode = AppMode::Wizard;
        self.commander.return_to_commander = true;
        self.show_help = false;
        // Sessions screen: the list loads lazily in the background.
        if screen == Screen::Resume {
            self.spawn_sessions_load();
        }
    }

    /// Returns control from the wizard to the commander, refreshing the overlay.
    pub fn return_to_commander(&mut self) {
        self.mode = AppMode::Commander;
        self.commander.return_to_commander = false;
        if let Some(scan_id) = self.current_scan_id {
            self.spawn_dedup_load(Some(scan_id));
        }
    }

    /// Sets the scan source of the dedup overlay: if `scan_id` is given —
    /// it is used, otherwise the newest scan in the DB (a lightweight id query). Resets the
    /// directory cache and reads in the background the dedup attributes of all open panels
    /// (`fetch_panel_dedup` → `CommanderDirDedup`). RAM no longer holds the whole scan.
    pub fn spawn_dedup_load(&mut self, scan_id: Option<i64>) {
        let resolved = match scan_id {
            Some(id) => Some(id),
            None => ScanStore::open(&self.db_path)
                .ok()
                .and_then(|store| store.latest_scan_id().ok().flatten()),
        };
        // New scan source → the previous caches are invalid.
        self.commander.dedup = DedupCache::default();
        self.commander.dedup_scan_id = resolved;
        self.commander.group_summaries = Vec::new();
        self.commander.dir_groups = Vec::new();
        self.commander.groups_loaded_for = None;
        self.commander.watch_cache = Vec::new();
        self.commander.watch_dir_cache = Vec::new();
        if resolved.is_some() {
            let count = self.commander.panels.len();
            for index in 0..count {
                crate::tui::commander::fetch_panel_dedup(self, LoadTarget::Commander(index));
            }
        }
    }

    /// Loads the list of saved sessions in a background thread:
    /// the DB statistics query is heavy and must not block the interface.
    /// The result arrives as a `SessionsReady` event.
    fn spawn_sessions_load(&mut self) {
        if self.sessions_loaded || self.sessions_loading {
            return;
        }
        self.sessions_loading = true;
        let db_path = self.db_path.clone();
        let events = self.events.clone();
        std::thread::spawn(move || {
            let list = ScanStore::open(&db_path)
                .and_then(|store| store.list_scans())
                .unwrap_or_default();
            let _ = events.send(AppEvent::SessionsReady(list));
        });
    }

    /// F2: scans `roots`. If for these roots there is an unfinished session and/or
    /// a last completed scan — shows a summary with dates and a recommendation
    /// (`Overlay::ResumeScan`), otherwise launches a new scan.
    pub fn commander_scan(&mut self, roots: Vec<PathBuf>) {
        if self.deny_if_read_only("scanning") {
            return;
        }
        if roots.is_empty() {
            self.commander.status = "No directory selected for scanning".to_string();
            return;
        }
        // Instant response: the heavy sessions probe (`list_scans`) goes to the background, F2
        // does not «stay silent». The decision (resume overlay / new scan) — via the
        // `CommanderResumeProbe` event.
        self.commander.status = "Checking saved scans…".to_string();
        let db_path = self.db_path.clone();
        let events = self.events.clone();
        std::thread::spawn(move || {
            let (unfinished, complete) = ScanStore::open(&db_path)
                .and_then(|store| store.resume_probe_for_roots(&roots))
                .unwrap_or((None, None));
            let _ = events.send(AppEvent::CommanderResumeProbe {
                roots,
                unfinished,
                complete,
            });
        });
    }

    /// Launches a NEW scan of `roots` without a resume check.
    pub(crate) fn commander_scan_new(&mut self, roots: Vec<PathBuf>) {
        if self.deny_if_read_only("scanning") {
            return;
        }
        if roots.is_empty() {
            self.commander.status = "No directory selected for scanning".to_string();
            return;
        }
        let mut config = ScanConfig::new(roots);
        config.reuse_hashes = true;
        config.hash_profile = self.config.hash_profile;
        config.dir_sig_algo = self.config.dir_sig_algo;
        self.scanning = ScanningState::default();
        self.status.clear();
        self.commander.return_to_commander = true;
        self.mode = AppMode::Wizard;
        self.screen = Screen::Scanning;
        self.scan = Some(worker::spawn(
            self.db_path.clone(),
            config,
            None,
            self.verify,
            self.events.clone(),
        ));
    }

    /// Continues the unfinished session `scan_id` from the commander.
    /// The resume config is read from the DB — a stub is passed.
    pub(crate) fn commander_resume(&mut self, scan_id: i64) {
        if self.deny_if_read_only("resuming the scan") {
            return;
        }
        self.scanning = ScanningState::default();
        self.status.clear();
        self.commander.return_to_commander = true;
        self.mode = AppMode::Wizard;
        self.screen = Screen::Scanning;
        self.scan = Some(worker::spawn(
            self.db_path.clone(),
            ScanConfig::new(vec![PathBuf::from("/")]),
            Some(scan_id),
            self.verify,
            self.events.clone(),
        ));
    }

    /// Computes a file's hash in a background thread (F4 in the commander).
    pub fn commander_hash(&mut self, path: PathBuf) {
        let events = self.events.clone();
        std::thread::spawn(move || {
            let progress = std::sync::atomic::AtomicU64::new(0);
            let event = match crate::pipeline::hash::hash_file(&path, &progress) {
                Ok(hash) => AppEvent::CommanderHash(path, hash),
                Err(err) => AppEvent::CommanderHashFailed(path, err.to_string()),
            };
            let _ = events.send(event);
        });
    }

    /// Hashes the relocated layout files in the background and quietly puts the result into
    /// the index + DB cache (triage §B). One thread per batch — sequentially, so as
    /// not to cause an I/O storm on the pool; read errors are silently skipped.
    pub fn commander_hash_cache_batch(&mut self, paths: Vec<PathBuf>) {
        let events = self.events.clone();
        std::thread::spawn(move || {
            for path in paths {
                let progress = std::sync::atomic::AtomicU64::new(0);
                if let Ok(hash) = crate::pipeline::hash::hash_file(&path, &progress) {
                    let _ = events.send(AppEvent::CommanderHashCached(path, hash));
                }
            }
        });
    }
}

/// Shifts the selection in `ListState` within `[0, len)`.
fn step(state: &mut ListState, len: usize, delta: i32) {
    if len == 0 {
        state.select(None);
        return;
    }
    let current = state.selected().unwrap_or(0) as i32;
    let next = (current + delta).clamp(0, len as i32 - 1);
    state.select(Some(next as usize));
}

// `page_step` — in `tui::screens::browser`, tests are there too.
use crate::tui::screens::browser::page_step;

/// Mouse double-click threshold, ms. The desktop standard is 250-500;
/// 250 is responsive and is not confused with an accidental double-press during scrolling clicks.
const DOUBLE_CLICK_MS: u64 = 250;

/// Whether point `(col, row)` is inside `area` (treating the right/bottom edge as «not inside» —
/// the classic half-open Rect semantics).
fn rect_contains(area: Rect, col: u16, row: u16) -> bool {
    col >= area.x && col < area.x + area.width && row >= area.y && row < area.y + area.height
}

/// Index of the default keeper file: newest mtime, on a tie — the shorter path.
fn pick_keeper(files: &[FileEntry]) -> usize {
    files
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            a.mtime
                .cmp(&b.mtime)
                .then_with(|| b.path.as_os_str().len().cmp(&a.path.as_os_str().len()))
        })
        .map(|(index, _)| index)
        .unwrap_or(0)
}

/// Returns a sorted list of subdirectories of `dir`.
fn list_subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                dirs.push(entry.path());
            }
        }
    }
    dirs.sort();
    dirs
}
