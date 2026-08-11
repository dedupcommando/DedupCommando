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
use crate::actions::{ApplyOutcome, ApplyRefusal};
use crate::model::action::{ActionKind, BatchResult, RevalidationMode};
use crate::model::dataset::Dataset;
use crate::model::duplicate::{DirSigAlgo, DuplicateGroup, FileEntry};
use crate::model::plan::{ActionPlan, GroupId, MarkIntent, PlanRefusal, RequestedMark};
use crate::model::preset::Preset;
use crate::model::scan::{
    HashProfile, ResumeInfo, ScanConfig, ScanPhase, ScanProgress, ScanSummary,
};
use crate::pipeline::ScanOutcome;
use crate::scan::worker::{self, ScanHandle};
use crate::state::browse::{
    Activation, ActorId, AutoSelectOutcome, AutoSelectRefusal, BrowseEvent, BrowseOpenFailure,
    BrowseRequest, BrowseRole, BrowseSink, CancelToken, CloseCause, DrainedInflight, MarkOutcome,
    MarkTicket, OpenedBrowse, PanelFailure, Presentation, RefusedAutoSelect, RequestId,
    RetiredActor, StoreMiss,
};
use crate::state::{
    CandidateView, GroupSummary, HostProfile, MembershipMiss, MembershipSummaries, ScanStore,
};
use crate::tui::commander::dedup::DedupCache;
use crate::tui::commander::state::{CommanderState, ConfirmScript, LoadTarget};
use crate::tui::event::AppEvent;
use crate::zfs::ZfsEnvironment;

/// Shown when the batch is over but its marks could not be settled in the DB: the plan on disk
/// still lists what was just applied, and executing it again would act on stale marks.
pub const MARKS_NOT_SETTLED: &str =
    "WARNING: the saved marks were not updated — the plan on disk still lists what was applied";

/// Shown when browsing stopped while a mark write was still unacknowledged. The window goes back
/// to what the database last said; the acknowledgement the operator was told to wait for is never
/// arriving, so the wait has to be ended in words rather than left on screen.
const MARKS_STRANDED: &str = "browsing stopped before the marks were acknowledged";

/// Shown when the batch refused itself before touching anything. Nothing was applied, so the marks
/// are exactly where the operator left them and the plan can simply be run again.
pub const BATCH_REFUSED: &str =
    "The batch was refused before any change — the marks are kept; check the snapshots it created";

/// What the wide surfaces say about a scan whose results were never published. Frozen wording:
/// a candidate view is not a result, and the only way out is a rescan.
pub const RESULTS_UNPUBLISHED: &str = "results not published — rescan required";

/// The same fact where the width does not allow the sentence.
pub const RESULTS_UNPUBLISHED_COMPACT: &str = "unpublished · rescan required";

/// What every surface says once the checkpoint at the configured path stopped being the one the
/// view was opened over. Only a fresh open recovers, so the wording names that.
pub const REOPEN_REQUIRED: &str = "the checkpoint database was replaced — reopen required";

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
    /// Lightweight summaries of all groups "by reclaim" (645k×~48 B ≈ 31 MiB), each with the
    /// identity of the publication it belongs to. Keyed by identity, never by digest: two
    /// verified populations may legitimately share one digest and are two different groups.
    pub group_summaries: Vec<(GroupId, GroupSummary)>,
    /// The identities the authority itself named inconsistent — shown as unavailable rows
    /// rather than quietly dropped.
    pub inconsistent: Vec<GroupId>,
    /// A scan with no published authority: browse-only candidate digests. `Some` excludes
    /// `group_summaries` being meaningful — the two are the two halves of one presentation.
    pub candidates: Option<CandidateView>,
    /// Files of the OPEN group ONLY (`id` = summary rank). `None` — group not open.
    pub open_group: Option<DuplicateGroup>,
    /// Cache of the "file name → color" palette of the open group: computed
    /// ONCE when the group is loaded, NOT during render. On a /tank group of 2.2M
    /// files, recomputing the palette every frame caused ~4 s of freeze per cursor move.
    pub open_group_colors: HashMap<String, Color>,
    /// What the OPEN group's materialized row claims — read from `file_group` plus its link
    /// evidence when the group is opened, never derived from the page of files on screen.
    pub open_group_claim: Option<crate::state::GroupClaim>,
    pub group_state: ListState,
    pub file_state: ListState,
    /// true — focus on the files panel, false — on the groups panel.
    pub focus_files: bool,
    pub summary: ScanSummary,
    /// Path display mode in the "Group files" panel.
    pub path_style: PathStyle,
    /// The count of files marked for action, as the authority last reported it. `None` while
    /// it is being reloaded or after a read that failed — the header then renders `—`, because
    /// a refusal that renders as `0` is indistinguishable from «nothing is marked».
    pub marked_count: Option<usize>,
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
    /// Attributed summaries of twin-directory groups for
    /// the `[2] Directories` tab. Loaded synchronously in `show_results` (on /tank
    /// ≤ a few thousand rows — not hundreds of thousands like file-groups).
    pub dir_group_summaries: Vec<crate::state::AttributedDirGroupSummary>,
    /// Total reclaim of dir-groups — TRUSTED groups only, for the tab bar. An unverified
    /// candidate contributes a count, never bytes.
    pub dir_groups_reclaim_total: u64,
    /// How many of the loaded groups are unverified candidates.
    pub dir_groups_unverified: u32,
    /// The attributed load's failure, when it failed — rendered instead of the list, so a store
    /// error can never read as «no directory groups».
    pub dir_groups_error: Option<String>,
    /// Cursor over dir-groups (left panel of the Dirs tab).
    pub dir_group_state: ListState,
    /// Cursor over paths of the open dir-group (right).
    pub dir_file_state: ListState,
    /// The full open dir-group with `paths` and member trust (loaded by
    /// `store::attributed_dir_group` on entry). `None` while none is open.
    pub open_dir_group: Option<crate::model::duplicate::AttributedDirGroup>,
    /// Index of the "keeper" in `open_dir_group.paths` (★).
    /// Default 0 (first path); changed with Enter on the right panel.
    pub dir_keeper_index: usize,
    /// Coordinates of the `[1] Files` tab on the tab bar — for mouse clicks.
    /// `None` until the first frame.
    pub tab_files_area: Option<Rect>,
    /// The same for the `[2] Directories` tab.
    pub tab_dirs_area: Option<Rect>,
}

/// State of the action-review screen.
///
/// The plan is owned whole. Everything the screen prints — the rows, the count, the guaranteed and
/// potential figures, the warnings — is read out of this one value, so the review, the confirmation
/// and the batch that follows cannot describe different things.
#[derive(Default)]
pub struct ReviewState {
    pub plan: Option<ActionPlan>,
    pub confirming: bool,
    /// Cursor and scroll offset of the action list. The plan can hold every
    /// duplicate of a scan, so without this the rows past the first screen
    /// were unreachable — the operator confirmed a batch they could not read.
    pub list: ListState,
    /// Height of the list window from the last frame — for PageUp/PageDown.
    /// `0` until the first frame; `page_step` falls back to 20.
    pub visible_rows: u16,
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
    /// The serialized browsing-actor fleet: the ONE owner of a browsing connection. Every
    /// completed-scan answer and every mark travels through it, so no two call sites can hold
    /// their own connection and disagree about what the database said.
    pub(crate) browse: crate::state::browse::BrowseFleet,
    /// Which activation the UI currently has installed. Bumped only by a successful `Open`,
    /// on both sides at once; a reply stamped with anything else is dropped whole.
    pub(crate) installed_act: Activation,
    /// What each in-flight request was asked for. A reply carries its `RequestId`, and this is
    /// where that id says which row, panel or overlay it belongs to.
    pub(crate) routes: BrowseRoutes,
    /// Whether the marks the windows show are settled against the database. `BuildPlan` is
    /// refused locally while it is not.
    pub(crate) marks_gate: MarksGate,
    /// Mark mutations the actor has not acknowledged yet, by request id — the optimistic rows
    /// they belong to, so a refusal or a terminal restores exactly what was on screen.
    pub(crate) pending_marks: HashMap<u64, MarkOrigin>,
    /// The live auto-select sweep, if one is running.
    pub(crate) auto_select: Option<(RequestId, CancelToken)>,
    /// The staged shutdown: producers first, then the owed reconcile, then the actor.
    pub(crate) shutdown: ShutdownStage,
    /// The settlement the last batch owes the database. Sent immediately when an actor is
    /// live, and re-sent by the shutdown machine if the exit beats the acknowledgement.
    pub(crate) pending_reconcile: Option<PendingReconcile>,
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
    /// The last batch ended with its marks unsettled in the DB — the plan on disk still lists
    /// what was applied. Explicit state, not a status string: every screen that reports the batch
    /// has to keep saying so, and a status line is overwritten by the next thing that happens.
    pub marks_unsettled: bool,
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
    /// Background `purge_scan` jobs in flight. They have no cancel flag, so a shutdown signal
    /// waits for them rather than abandoning a half-finished multi-index DELETE.
    pub purge_pending: usize,
    /// An action awaiting confirmation in a modal dialog.
    pub confirm: Option<ConfirmAction>,
    /// A completed scan's result is being loaded in the background (E2E feedback) — `Some(start)`
    /// enables the "Opening result" animation and holds the time for the marquee.
    pub opening_started: Option<std::time::Instant>,
    /// The result was opened from the session list (F2/F12) — Esc returns to the list, not to
    /// commander (don't jump over the parent, E2E feedback).
    pub results_from_sessions: bool,
}

/// Where the browsing actor's replies enter the application's event loop.
///
/// The actor names its sink once, at spawn; nothing else can emit into this channel as a
/// browsing answer, so every reply the UI settles from came from the one owner of the store.
pub(crate) struct AppBrowseSink {
    events: Sender<AppEvent>,
}

impl BrowseSink for AppBrowseSink {
    fn emit(&self, event: BrowseEvent) {
        // A closed channel means the application is already gone; the actor's own terminal
        // path does not depend on this send.
        let _ = self.events.send(AppEvent::Browse(Box::new(event)));
    }
}

/// Why a scan is being opened — what the reply should switch to once it installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenIntent {
    /// The classic browser: switch to Wizard/Browser when the payload installs.
    Wizard,
    /// The commander overlay: stay where the operator is.
    Commander,
}

/// The one open in flight: its request, the activation it will install, and what it is for.
pub(crate) struct OpenRoute {
    pub(crate) req: RequestId,
    pub(crate) act: Activation,
    pub(crate) scan_id: i64,
    pub(crate) intent: OpenIntent,
}

/// What an in-flight `GroupOpen` is for.
pub(crate) enum GroupPurpose {
    /// The classic browser opened a group: install it whole.
    BrowserOpen { id: GroupId },
    /// The classic browser scrolled toward the end: append this page.
    BrowserMore { id: GroupId, loaded: usize },
    /// An authoritative reload after marks changed underneath the open group.
    BrowserReload { id: GroupId },
    /// A commander «watching» panel resolved its source.
    Watch { panel: usize, id: GroupId },
}

/// What an in-flight `FileInfo` is for.
pub(crate) enum InfoPurpose {
    /// The F3 overlay, whose header lines were built from the panel entry before the request
    /// went out; the membership half is appended when the answer arrives.
    Overlay { header: Vec<String> },
    /// A commander «duplicates of the cursor» panel: the answer says whether the pathname is in
    /// the scan at all, and the identity it carries chains into one `GroupOpen`.
    WatchDup { panel: usize },
}

/// What an in-flight `OpenDirGroup` is for.
pub(crate) enum DirOpenPurpose {
    /// The classic browser's Directories tab.
    WizardDirs,
    /// A commander panel showing the directories of a selected group.
    Watch { panel: usize },
}

/// Which window asked for a plan, and therefore which one receives it or its refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanWindow {
    Wizard,
    Commander,
}

/// What every in-flight request was asked for, keyed by its request id.
///
/// A reply that finds no route here is a reply for work the UI has already abandoned, and it
/// changes nothing — which is what makes dropping a stale activation whole safe.
#[derive(Default)]
pub(crate) struct BrowseRoutes {
    pub(crate) open: Option<OpenRoute>,
    pub(crate) groups: HashMap<u64, GroupPurpose>,
    pub(crate) counts: HashMap<u64, GroupId>,
    pub(crate) infos: HashMap<u64, InfoPurpose>,
    pub(crate) dirs_at: HashMap<u64, usize>,
    pub(crate) dir_opens: HashMap<u64, DirOpenPurpose>,
    pub(crate) panels: HashMap<u64, (LoadTarget, PathBuf)>,
    pub(crate) marked: Option<RequestId>,
    pub(crate) latest: Option<RequestId>,
    pub(crate) covering: HashMap<u64, PathBuf>,
    pub(crate) plan: Option<(RequestId, PlanWindow)>,
    pub(crate) reconcile: Option<RequestId>,
}

/// What an unacknowledged mark mutation would have to be restored to.
///
/// The actor's ticket carries the DURABLE before-image; this carries the window's own optimistic
/// state, which is what the operator is looking at. Both are needed: one says what the database
/// held, the other says what the screen must go back to.
pub(crate) enum MarkOrigin {
    /// The classic browser writes the whole open group back on every mark.
    WizardGroup { before: Vec<FileEntry> },
    /// The commander marks one pathname at a time, on one panel.
    CommanderMark {
        panel: usize,
        path: PathBuf,
        previous: Option<crate::tui::commander::state::Mark>,
        /// What this keystroke asked for. Kept only to correlate the acknowledgement: the
        /// durable meaning shown to the operator is read back out of the after-image, never
        /// from this field.
        requested: Option<crate::tui::commander::state::Mark>,
    },
}

/// How a durable mark reads to the operator — taken from what the database returned.
fn durable_meaning(intent: Option<&MarkIntent>) -> &'static str {
    match intent {
        Some(MarkIntent::Keeper) => "keeper",
        Some(MarkIntent::Act(ActionKind::Hardlink)) => "hardlink",
        Some(MarkIntent::Act(ActionKind::Reflink)) => "reflink",
        Some(MarkIntent::Act(ActionKind::Delete)) => "delete",
        None => "cleared",
    }
}

/// The durable meaning a keystroke asked for. A triage selection is not durable, so it reads as
/// «cleared»: the database holds no row for it either way.
fn requested_meaning(mark: Option<crate::tui::commander::state::Mark>) -> &'static str {
    use crate::tui::commander::state::Mark;
    match mark {
        Some(Mark::Keeper) => "keeper",
        Some(Mark::Hardlink) => "hardlink",
        Some(Mark::Reflink) => "reflink",
        Some(Mark::Delete) => "delete",
        Some(Mark::Selected) | None => "cleared",
    }
}

/// Whether the marks on screen are settled against the database.
///
/// A plan may only be built from `Settled`: an unacknowledged or failed mark that entered a plan
/// is a window showing DELETE over a database that says something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MarksGate {
    Settled,
    /// Authoritative rows are being re-read after a write the UI did not see in full.
    Reloading {
        act: Activation,
        marked: RequestId,
        group: Option<RequestId>,
        marked_ok: bool,
        group_ok: bool,
    },
    /// A reload failed, a batch could not settle, or an actor died holding marks. Planning stays
    /// refused until a successful open re-establishes the picture.
    Blocked {
        act: Activation,
        reason: String,
    },
}

impl MarksGate {
    /// Why planning is refused right now, if it is.
    pub(crate) fn refusal(&self) -> Option<String> {
        match self {
            MarksGate::Settled => None,
            MarksGate::Reloading { .. } => {
                Some("the marks are being re-read — wait for them to settle".to_string())
            }
            MarksGate::Blocked { reason, .. } => Some(reason.clone()),
        }
    }
}

/// The settlement a finished batch owes the database.
pub(crate) struct PendingReconcile {
    pub(crate) scan_id: i64,
    pub(crate) attempted: Vec<PathBuf>,
    pub(crate) cancelled: bool,
    /// Which window's RAM marks the acknowledgement clears.
    pub(crate) commander: bool,
}

/// The staged exit.
///
/// Producers first — with the browsing actor deliberately still ALIVE, because a finished batch
/// owes it a mark settlement — then that settlement and its acknowledgement, and only then the
/// actor's own close. Every transition is decided from state alone (`terminal_owed`), never from
/// a remembered step, so no stage can wait for a terminal that nobody owes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShutdownStage {
    None,
    Producers,
    Settling { req: RequestId },
    Draining,
    Done,
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
            browse: crate::state::browse::BrowseFleet::new(),
            installed_act: Activation(0),
            routes: BrowseRoutes::default(),
            marks_gate: MarksGate::Settled,
            pending_marks: HashMap::new(),
            auto_select: None,
            shutdown: ShutdownStage::None,
            pending_reconcile: None,
            browser: BrowserState::default(),
            review: ReviewState::default(),
            summary_result: None,
            marks_unsettled: false,
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
            purge_pending: 0,
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
            AppEvent::Browse(event) => self.on_browse(*event),
            AppEvent::ScanProgress(progress) => self.on_progress(progress),
            AppEvent::ScanFinished(result) => self.on_finished(result),
            AppEvent::ApplyProgress(progress) => self.on_apply_progress(progress),
            AppEvent::ApplyFinished(outcome) => self.on_apply_finished(*outcome),
            AppEvent::CommanderHash(path, hash) => {
                self.commander.dedup.insert_hash(path.clone(), hash);
                self.commander.status = format!("Hash computed: {}", path.display());
            }
            AppEvent::CommanderHashFailed(path, err) => {
                self.commander.status = format!("Failed to compute hash {}: {err}", path.display());
            }
            AppEvent::CommanderHashCached(path, hash) => {
                // Quietly: into memory + the persistent identity-keyed cache (layout §B). The
                // cache write goes through the one store owner like every other write.
                self.commander.dedup.insert_hash(path.clone(), hash);
                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    use std::os::unix::fs::MetadataExt;
                    let act = self.installed_act;
                    let (device, inode, size, mtime) =
                        (meta.dev(), meta.ino(), meta.size(), meta.mtime());
                    self.send_browse(|req| BrowseRequest::CacheHash {
                        act,
                        req,
                        device,
                        inode,
                        size,
                        mtime,
                        digest: hash,
                    });
                }
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
                // Records the MoveRecord and the Undo entry, and clears `move_pending`.
                crate::tui::commander::apply_move_outcome(self, *outcome);
                // We were only staying alive to let this land (see `request_shutdown`).
                if shutdown_pending() {
                    self.request_shutdown(false);
                }
            }
            AppEvent::SessionsReady(list) => {
                self.sessions = list;
                self.sessions_loading = false;
                self.sessions_loaded = true;
                self.session_cursor = 0;
            }
            AppEvent::SessionDeleted(result) => {
                self.purge_pending = self.purge_pending.saturating_sub(1);
                self.status = match result {
                    Ok(_) => "Session purged from trash".to_string(),
                    Err(err) => format!("Failed to purge scan: {err}"),
                };
                // We were only staying alive to let this land (see `request_shutdown`).
                if shutdown_pending() {
                    self.request_shutdown(false);
                }
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

    // === The browsing actor: the one owner of a browsing connection ===

    /// The capability this process browses with. Immutable for an actor's whole life, so a
    /// later role flip replaces the actor instead of retro-fitting its connection.
    fn browse_role(&self) -> BrowseRole {
        if self.read_only {
            BrowseRole::Observer
        } else {
            BrowseRole::Operator
        }
    }

    /// Spawns the browsing actor if the fleet is idle. Returns whether one is live afterwards.
    fn ensure_browse_actor(&mut self) -> bool {
        if self.browse.live().is_some() {
            return true;
        }
        // A draining fleet accepts nothing new: its successor is spawned when its terminal
        // settles, never beside it.
        if !matches!(self.browse.phase(), crate::state::browse::FleetPhase::Idle) {
            return false;
        }
        let sink = Box::new(AppBrowseSink {
            events: self.events.clone(),
        });
        self.browse
            .spawn(self.db_path.clone(), self.browse_role(), sink)
            .is_some()
    }

    /// Enqueues one request, allocating its id from the fleet. `None` means the request was
    /// never accepted — no reply will come, so no route is recorded for it.
    fn send_browse(&mut self, build: impl FnOnce(RequestId) -> BrowseRequest) -> Option<RequestId> {
        if !self.ensure_browse_actor() {
            return None;
        }
        let req = self.browse.next_request();
        let request = build(req);
        let handle = self.browse.live()?;
        match handle.send(request) {
            Ok(()) => Some(req),
            Err(reason) => {
                self.note_browse_refusal(&format!("{reason:?}"));
                None
            }
        }
    }

    /// One place says a browsing request never left. Not a data answer — nothing is installed
    /// or cleared here — so a refused enqueue can never look like an empty result.
    fn note_browse_refusal(&mut self, detail: &str) {
        let message = format!("browsing request refused: {detail}");
        match self.mode {
            AppMode::Commander => self.commander.status = message,
            AppMode::Wizard => self.status = message,
        }
    }

    /// Opens a completed scan through the actor. The activation is proposed here and installed
    /// only by a successful reply, so a failed reopen leaves the previously installed scan
    /// exactly as it was.
    ///
    /// ONE open at a time, as an invariant rather than a screen convention. Two overlapping
    /// opens both derive their proposal from the still-installed activation and share the single
    /// `routes.open` slot: the second would overwrite the first, `on_open_finished` would drop
    /// the first reply as unrouted — and the actor may already have installed that first
    /// candidate. A class-A refusal of the second then leaves the UI on its old activation while
    /// the actor serves the one the UI threw away, and every later request is stale until
    /// something opens again. So a request that arrives while one is in flight is either the same
    /// scan — which the pending request already IS — or is refused out loud, and in neither case
    /// does the pending request, intent or activation change.
    pub(crate) fn open_via_actor(&mut self, scan_id: i64, intent: OpenIntent) {
        if let Some(pending) = &self.routes.open {
            let message = if pending.scan_id == scan_id {
                // Leaning on Enter, or an auto-switch that agrees with what is already being
                // opened: idempotent, because the answer on its way is the answer to this.
                "Opening results…".to_string()
            } else {
                format!(
                    "Still opening scan #{} — that has to finish before another scan opens",
                    pending.scan_id
                )
            };
            self.status = message.clone();
            self.commander.status = message;
            return;
        }
        // Checked, because an activation that wrapped would make a stale reply look current.
        let Some(act) = self.installed_act.0.checked_add(1).map(Activation) else {
            let message =
                "the browsing activation counter is exhausted — restart dedcom".to_string();
            self.status = message.clone();
            self.commander.status = message;
            return;
        };
        let Some(req) = self.send_browse(|req| BrowseRequest::Open { act, req, scan_id }) else {
            self.opening_started = None;
            return;
        };
        self.opening_started = Some(std::time::Instant::now());
        self.status = "Opening results…".to_string();
        self.commander.status = "Opening results…".to_string();
        self.routes.open = Some(OpenRoute {
            req,
            act,
            scan_id,
            intent,
        });
    }

    /// Everything a successful `Open` installs, in one step.
    ///
    /// The payload was read from ONE snapshot inside the actor — one SQLite read transaction —
    /// so the scan id, its summary, its marked count, its directory groups and its presentation
    /// all describe the same database state. A writer that republishes or re-marks while the
    /// payload is being built cannot split it, and there is no window in which half of a result
    /// is on screen. «One actor pass» was the weaker R4B-2c claim; R4B-2c1 made it a transaction.
    fn install_opened(&mut self, act: Activation, payload: OpenedBrowse, intent: OpenIntent) {
        let OpenedBrowse {
            scan_id,
            status,
            created_at,
            summary,
            marked_count,
            dir_groups,
            presentation,
        } = payload;
        self.installed_act = act;
        self.current_scan_id = Some(scan_id);
        self.opening_started = None;
        // The payload re-read the count, the summaries and the directory groups atomically, so
        // whatever the previous activation could not settle is answered by this one.
        self.marks_gate = MarksGate::Settled;
        self.invalidate_confirmation("the results were reopened");

        self.browser.open_group = None;
        self.browser.open_group_claim = None;
        self.browser.summary = summary;
        self.browser.marked_count = Some(marked_count as usize);
        self.browser.group_state = ListState::default();
        self.browser.file_state = ListState::default();
        self.browser.focus_files = false;
        self.browser.tab = crate::tui::screens::browser::BrowserTab::Files;
        self.browser.dir_group_state = ListState::default();
        self.browser.dir_file_state = ListState::default();
        self.browser.open_dir_group = None;
        self.browser.dir_keeper_index = 0;
        self.browser.dir_groups_error = None;
        self.browser.dir_groups_reclaim_total = dir_groups.trusted_reclaim_total;
        self.browser.dir_groups_unverified = dir_groups.unverified_groups;
        self.browser.dir_group_summaries = dir_groups.groups.clone();
        if !self.browser.dir_group_summaries.is_empty() {
            self.browser.dir_group_state.select(Some(0));
        }

        // Exactly one presentation: published membership, or the typed candidate view of a scan
        // that has no authority at all. Never both, never a third shape.
        let published = match presentation {
            Presentation::Published(MembershipSummaries {
                groups,
                inconsistent,
                ..
            }) => {
                let count = groups.len();
                self.browser.group_summaries = groups;
                self.browser.inconsistent = inconsistent;
                self.browser.candidates = None;
                Some(count)
            }
            Presentation::Unpublished(view) => {
                self.browser.group_summaries = Vec::new();
                self.browser.inconsistent = Vec::new();
                self.browser.candidates = Some(view);
                None
            }
        };

        // The commander reads the same one answer.
        self.commander.dedup_scan_id = Some(scan_id);
        self.commander.groups_loaded_for = Some(scan_id);
        self.commander.group_summaries = self.browser.group_summaries.clone();
        self.commander.candidates = self.browser.candidates.clone();
        self.commander.dir_group_summaries = self.browser.dir_group_summaries.clone();
        self.commander.dir_groups_error = None;
        self.commander.scan_created_at = created_at;
        self.commander.dedup = DedupCache::default();
        self.commander.watch_cache = Vec::new();
        self.commander.watch_dir_cache = Vec::new();

        self.status = self.completion_status(published, status);
        self.commander.status = self.status.clone();

        if published.is_some() && !self.browser.group_summaries.is_empty() {
            self.browser.group_state.select(Some(0));
            self.open_selected_group();
        }
        // Every visible panel re-reads its dedup evidence from the newly installed scan.
        let panels = self.commander.panels.len();
        for index in 0..panels {
            crate::tui::commander::fetch_panel_dedup(self, LoadTarget::Commander(index));
        }
        if intent == OpenIntent::Wizard {
            self.mode = AppMode::Wizard;
            self.screen = Screen::Browser;
        }
    }

    /// The line that reports what was opened. `None` groups means the scan has no published
    /// authority: it says so in the accepted wording instead of printing a zero.
    fn completion_status(
        &self,
        published: Option<usize>,
        status: crate::model::scan::ScanStatus,
    ) -> String {
        let mut line = match published {
            Some(count) => format!(
                "Duplicate groups found: {count} · scan time {} · {}",
                crate::tui::format_duration(self.browser.summary.elapsed_seconds),
                crate::tui::format_speed(
                    self.browser.summary.bytes_hashed,
                    self.browser.summary.elapsed_seconds,
                ),
            ),
            None => RESULTS_UNPUBLISHED.to_string(),
        };
        if self.browser.summary.hash_failures > 0 {
            line.push_str(&format!(
                " · ⚠ failed to hash: {}",
                self.browser.summary.hash_failures
            ));
        }
        // The omission account beside it: exact ledger or session-observed counters when there
        // are any; for a warned scan whose account was not retainable, say so instead of showing
        // nothing — an absent number must not read as a clean scan.
        match &self.browser.summary.omissions {
            crate::model::scan::OmissionAccounting::Ledger(totals)
            | crate::model::scan::OmissionAccounting::Observed(totals)
                if !totals.is_empty() =>
            {
                if let (Ok(files), Ok(entries)) =
                    (totals.known_omitted_files(), totals.unsupported_entries())
                {
                    let errors = totals.unknown_cardinality_events();
                    line.push_str(&format!(
                        " · ⚠ gaps: {files} files omitted, {errors} walk errors, {entries} unsupported entries"
                    ));
                }
            }
            crate::model::scan::OmissionAccounting::Unavailable
                if status == crate::model::scan::ScanStatus::CompleteWithWarnings =>
            {
                line.push_str(" · ⚠ omission details not retained (no completeness authority)");
            }
            _ => {}
        }
        line
    }

    /// The checkpoint the view was opened over is gone — the file at the configured path is not
    /// the one this connection opened, or the connection itself was lost.
    ///
    /// Everything that describes the scan is uninstalled, because keeping any of it on screen
    /// would let the operator act on a database nobody can reach. Only a fresh open recovers.
    fn uninstall_browsing(&mut self, detail: &str) {
        self.current_scan_id = None;
        self.opening_started = None;
        self.browser.group_summaries = Vec::new();
        self.browser.inconsistent = Vec::new();
        self.browser.candidates = None;
        self.browser.open_group = None;
        self.browser.open_group_claim = None;
        self.browser.open_group_total = 0;
        self.browser.open_group_max_reached = false;
        self.browser.marked_count = None;
        self.browser.dir_group_summaries = Vec::new();
        self.browser.open_dir_group = None;
        self.browser.dir_groups_reclaim_total = 0;
        self.browser.dir_groups_unverified = 0;
        self.browser.dir_groups_error = Some(REOPEN_REQUIRED.to_string());
        self.commander.dedup_scan_id = None;
        self.commander.groups_loaded_for = None;
        self.commander.group_summaries = Vec::new();
        self.commander.candidates = None;
        self.commander.dir_group_summaries = Vec::new();
        self.commander.dir_groups_error = Some(REOPEN_REQUIRED.to_string());
        self.commander.scan_created_at = None;
        self.commander.dedup = DedupCache::default();
        self.commander.watch_cache = Vec::new();
        self.commander.watch_dir_cache = Vec::new();
        self.commander.scan_coverage_cache.clear();
        self.invalidate_confirmation(REOPEN_REQUIRED);
        self.marks_gate = MarksGate::Blocked {
            act: self.installed_act,
            reason: format!("{REOPEN_REQUIRED} ({detail})"),
        };
        let message = format!("{REOPEN_REQUIRED} ({detail})");
        self.status = message.clone();
        self.commander.status = message;
    }

    /// Drops a pending confirmation's script when the plan behind it can no longer be trusted.
    /// The plan itself is kept so the operator sees what was invalidated and why.
    pub(crate) fn invalidate_confirmation(&mut self, reason: &str) {
        if self.commander.pending_plan.is_some() {
            self.commander.confirm_script = ConfirmScript::Invalidated {
                reason: reason.to_string(),
            };
        }
    }

    /// Whether a reply belongs to the activation the UI has installed.
    fn is_current(&self, act: Activation) -> bool {
        act == self.installed_act
    }

    /// Opens the selected dir-group through the actor — the full `paths` and member trust,
    /// revalidated at open time. The keeper defaults to index 0 (by `paths` ASC sort order).
    fn open_selected_dir_group(&mut self) {
        let Some(idx) = self.browser.dir_group_state.selected() else {
            return;
        };
        let Some(signature) = self
            .browser
            .dir_group_summaries
            .get(idx)
            .map(|summary| summary.signature.clone())
        else {
            return;
        };
        let act = self.installed_act;
        if let Some(req) = self.send_browse(|req| BrowseRequest::OpenDirGroup {
            act,
            req,
            signature,
        }) {
            self.routes
                .dir_opens
                .insert(req.0, DirOpenPurpose::WizardDirs);
        }
    }

    /// Asks the actor for the selected group's first page. Nothing is installed here: the reply
    /// carries the members, the summary and the identity together.
    fn open_selected_group(&mut self) {
        let Some(index) = self.browser.group_state.selected() else {
            self.browser.open_group = None;
            self.browser.open_group_claim = None;
            self.browser.file_state.select(None);
            return;
        };
        let id = match self.browser.group_summaries.get(index) {
            Some((id, _)) => *id,
            None => {
                self.browser.open_group = None;
                self.browser.open_group_claim = None;
                self.browser.file_state.select(None);
                return;
            }
        };
        let act = self.installed_act;
        if let Some(req) = self.send_browse(|req| BrowseRequest::GroupOpen {
            act,
            req,
            id,
            offset: 0,
            limit: BROWSE_GROUP_FILE_PAGE,
        }) {
            self.routes
                .groups
                .insert(req.0, GroupPurpose::BrowserOpen { id });
        }
        // The live member count beside the page: the published `file_count` is what the
        // publication recorded, and the panel header states what the membership holds now.
        if let Some(req) = self.send_browse(|req| BrowseRequest::GroupCount { act, req, id }) {
            self.routes.counts.insert(req.0, id);
        }
    }

    /// Every reply the browsing actor gives.
    ///
    /// Two rules run through all of it. A reply whose activation is not the installed one is
    /// dropped WHOLE — it changes no row, no gate and no ticket — except that a mark reply
    /// still settles its own ticket, because a settlement is owed to the actor's ledger rather
    /// than to the screen. And a typed path replacement uninstalls the whole browsing view
    /// wherever it surfaces: no trusted answer survives a checkpoint that was swapped.
    fn on_browse(&mut self, event: BrowseEvent) {
        match event {
            BrowseEvent::OpenFinished { act, req, result } => {
                self.on_open_finished(act, req, result)
            }
            BrowseEvent::PanelData { act, req, result } => self.on_panel_data(act, req, result),
            BrowseEvent::Group { act, req, result } => self.on_group(act, req, result),
            BrowseEvent::GroupCount { act, req, result } => self.on_group_count(act, req, result),
            BrowseEvent::FileInfo { act, req, result } => {
                self.on_file_info(act, req, result.map(|answer| *answer))
            }
            BrowseEvent::DirGroupAt { act, req, result } => self.on_dir_group_at(act, req, result),
            BrowseEvent::DirGroupOpened { act, req, result } => {
                self.on_dir_group_opened(act, req, result)
            }
            BrowseEvent::MarkedCount { act, req, result } => self.on_marked_count(act, req, result),
            BrowseEvent::MarkAck { act, req, outcome } => self.on_mark_ack(act, req, outcome),
            BrowseEvent::AutoSelectDone { act, req, outcome } => {
                self.on_auto_select_done(act, req, outcome)
            }
            BrowseEvent::PlanReady { act, req, plan } => self.on_plan_ready(act, req, *plan),
            BrowseEvent::PlanRefused { act, req, refusal } => {
                self.on_plan_refused(act, req, refusal)
            }
            BrowseEvent::ReconcileAck { act, req, result } => {
                self.on_reconcile_ack(act, req, result)
            }
            BrowseEvent::LatestScan { act, req, result } => self.on_latest_scan(act, req, result),
            BrowseEvent::CoveringScan {
                act,
                req,
                cwd,
                result,
            } => self.on_covering_scan(act, req, cwd, result),
            BrowseEvent::CacheHashAck { result, .. } => {
                if let Err(miss) = result {
                    if !self.fatal_store_miss(&miss) {
                        tracing::warn!("the identity hash cache was not updated: {miss:?}");
                    }
                }
            }
            BrowseEvent::Closed { actor, cause } => self.on_actor_closed(actor, cause),
        }
    }

    /// A path replacement anywhere uninstalls the browsing view. `true` — it was one, and the
    /// caller must not treat the reply as an ordinary refusal on top of it.
    fn fatal_store_miss(&mut self, miss: &StoreMiss) -> bool {
        match miss {
            StoreMiss::PathChanged { detail } => {
                let detail = detail.clone();
                self.uninstall_browsing(&detail);
                true
            }
            _ => false,
        }
    }

    fn fatal_membership_miss(&mut self, miss: &MembershipMiss) -> bool {
        match miss {
            MembershipMiss::ReopenRequired { detail } => {
                let detail = detail.clone();
                self.uninstall_browsing(&detail);
                true
            }
            _ => false,
        }
    }

    fn fatal_panel_failure(&mut self, failure: &PanelFailure) -> bool {
        match failure {
            PanelFailure::PathChanged { detail } => {
                let detail = detail.clone();
                self.uninstall_browsing(&detail);
                true
            }
            PanelFailure::Snapshot(miss) => self.fatal_membership_miss(miss),
            _ => false,
        }
    }

    fn on_open_finished(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<Box<OpenedBrowse>, BrowseOpenFailure>,
    ) {
        // Routed by request id, not by activation: an open proposes an activation that only
        // success installs, so the reply cannot be matched by one.
        let route = match &self.routes.open {
            Some(route) if route.req == req => self.routes.open.take().expect("just matched"),
            _ => return,
        };
        debug_assert_eq!(
            route.act, act,
            "an open reply carries the activation it proposed"
        );
        match result {
            Ok(payload) => self.install_opened(route.act, *payload, route.intent),
            // Class B: the actor uninstalled both its connection and its scan, so the UI must
            // stop describing one too. Every other failure is class A — the previously
            // installed scan is untouched and still served.
            Err(BrowseOpenFailure::PathChanged { detail }) => self.uninstall_browsing(&detail),
            Err(failure) => {
                self.opening_started = None;
                let message = format!(
                    "the results of scan #{} could not be opened: {failure:?}",
                    route.scan_id
                );
                self.status = message.clone();
                self.commander.status = message;
            }
        }
    }

    fn on_panel_data(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<Box<crate::state::browse::PanelData>, PanelFailure>,
    ) {
        let Some((target, cwd)) = self.routes.panels.remove(&req.0) else {
            return;
        };
        let _ = target;
        if !self.is_current(act) {
            return;
        }
        match result {
            Ok(data) => {
                let dir = crate::tui::commander::dedup::DirDedup::from_panel(*data);
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
                self.commander.dedup.insert_dir(cwd, Ok(dir));
                self.commander.dedup.prune(&keep);
            }
            Err(failure) => {
                if self.fatal_panel_failure(&failure) {
                    return;
                }
                let message = format!("{failure:?}");
                self.commander.status = format!("directory status unavailable: {message}");
                self.commander.dedup.insert_dir(cwd, Err(message));
            }
        }
    }

    fn on_group(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<crate::state::ResolvedGroup, MembershipMiss>,
    ) {
        let Some(purpose) = self.routes.groups.remove(&req.0) else {
            return;
        };
        if !self.is_current(act) {
            return;
        }
        let group = match result {
            Ok(group) => group,
            Err(miss) => {
                if self.fatal_membership_miss(&miss) {
                    return;
                }
                match purpose {
                    GroupPurpose::Watch { panel, .. } => {
                        self.set_watch_unavailable(
                            panel,
                            crate::tui::commander::state::WatchSubject::FileGroup,
                            &format!("{miss:?}"),
                        );
                    }
                    GroupPurpose::BrowserReload { .. } => {
                        // A reload that failed blocks planning: the rows on screen are not what
                        // the database holds, and nothing may be built from them.
                        self.settle_gate_group(req, false);
                        self.browser.open_group = None;
                        self.browser.open_group_claim = None;
                        self.browser.file_state.select(None);
                        self.status = format!("file group unavailable: {miss:?}");
                    }
                    _ => {
                        // A group that cannot be read is not an empty group: the window says so
                        // and keeps nothing that pretends otherwise.
                        self.browser.open_group = None;
                        self.browser.open_group_claim = None;
                        self.browser.file_state.select(None);
                        self.status = format!("file group unavailable: {miss:?}");
                    }
                }
                return;
            }
        };
        // The answer must be about the group that was asked for; anything else is a routing
        // defect, not a row to install.
        let expected = match &purpose {
            GroupPurpose::BrowserOpen { id }
            | GroupPurpose::BrowserMore { id, .. }
            | GroupPurpose::BrowserReload { id }
            | GroupPurpose::Watch { id, .. } => *id,
        };
        if group.id != expected {
            tracing::warn!(?expected, actual = ?group.id, "a group reply named another identity");
            return;
        }
        match purpose {
            GroupPurpose::BrowserOpen { .. } => self.install_open_group(group, true),
            GroupPurpose::BrowserMore { loaded, .. } => self.append_open_group(group, loaded),
            GroupPurpose::BrowserReload { .. } => {
                // An authoritative re-read of the group already on screen: the rows change, the
                // operator's cursor does not.
                self.install_open_group(group, false);
                self.settle_gate_group(req, true);
            }
            GroupPurpose::Watch { panel, .. } => self.install_watch_group(panel, group),
        }
    }

    fn on_group_count(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<u64, MembershipMiss>,
    ) {
        let Some(id) = self.routes.counts.remove(&req.0) else {
            return;
        };
        if !self.is_current(act) {
            return;
        }
        match result {
            Ok(total) => {
                // Only for the group that is actually open — a late count of a group the
                // operator has already left changes nothing.
                if self
                    .browser
                    .open_group
                    .as_ref()
                    .is_some_and(|open| open.id == id.rank as usize)
                {
                    self.browser.open_group_total = total;
                }
            }
            Err(miss) => {
                if !self.fatal_membership_miss(&miss) {
                    tracing::warn!("the open group's member count is unavailable: {miss:?}");
                }
            }
        }
    }

    /// Asks the authority how many files carry an action mark. The answer replaces the cached
    /// number; a refusal renders as unavailable, never as zero.
    fn refresh_marked_count(&mut self) -> Option<RequestId> {
        if self.current_scan_id.is_none() {
            self.browser.marked_count = None;
            return None;
        }
        let act = self.installed_act;
        let sent = self.send_browse(|req| BrowseRequest::MarkedCount { act, req });
        self.browser.marked_count = None;
        self.routes.marked = sent;
        sent
    }

    /// Installs a group page as the open group. `reset_cursor` is false for an authoritative
    /// reload of the group already on screen, so re-reading it does not move the operator.
    fn install_open_group(&mut self, group: crate::state::ResolvedGroup, reset_cursor: bool) {
        let mut files = group.members;
        // Default keeper for display, if no file is marked as keeper. It is RAM-only until the
        // first real mark — plain viewing writes nothing.
        if !files.iter().any(|file| file.is_keeper) {
            if let Some(first) = files.first_mut() {
                first.is_keeper = true;
            }
        }
        let duplicate = DuplicateGroup {
            id: group.id.rank as usize,
            size_bytes: group.summary.size_bytes,
            hash: group.summary.hash.clone(),
            files,
        };
        let has_files = !duplicate.files.is_empty();
        self.browser.open_group_total = group.summary.file_count;
        self.browser.open_group_max_reached = duplicate.files.len() >= BROWSE_GROUP_FILE_MAX;
        // The palette is computed ONCE here, not during render: on a 2.2M group, recomputing it
        // every frame cost ~4 s per cursor move.
        self.browser.open_group_colors = crate::tui::screens::browser::name_palette(&duplicate);
        self.browser.open_group = Some(duplicate);
        // What the group claims comes from its own published row, never from the page on
        // screen: a page is a window, and a window cannot say how many allocations a group
        // holds.
        self.browser.open_group_claim = Some(crate::state::GroupClaim {
            reclaim: group.summary.reclaim,
            links: crate::state::GroupLinks {
                observed: group.summary.file_count,
                total: crate::model::reclaim::LinkCount::Unknown,
            },
        });
        if reset_cursor {
            self.browser
                .file_state
                .select(if has_files { Some(0) } else { None });
        }
    }

    /// Appends the next page of the open group. A page that arrived for a group the operator
    /// has already left, or after the window moved on, changes nothing.
    fn append_open_group(&mut self, group: crate::state::ResolvedGroup, loaded: usize) {
        let Some(open) = self.browser.open_group.as_mut() else {
            return;
        };
        if open.id != group.id.rank as usize || open.files.len() != loaded {
            return;
        }
        if group.members.is_empty() {
            self.browser.open_group_max_reached = true;
            return;
        }
        open.files.extend(group.members);
        if open.files.len() >= BROWSE_GROUP_FILE_MAX
            || open.files.len() as u64 >= self.browser.open_group_total
        {
            self.browser.open_group_max_reached = true;
        }
        // New names arrived — without a fresh palette they would render in the default colour.
        let palette = crate::tui::screens::browser::name_palette(open);
        self.browser.open_group_colors = palette;
    }

    /// Fills a commander watch panel with a resolved file group.
    fn install_watch_group(&mut self, panel: usize, group: crate::state::ResolvedGroup) {
        let claim = crate::state::GroupClaim {
            reclaim: group.summary.reclaim,
            links: crate::state::GroupLinks {
                observed: group.summary.file_count,
                total: crate::model::reclaim::LinkCount::Unknown,
            },
        };
        let duplicate = DuplicateGroup {
            id: group.id.rank as usize,
            size_bytes: group.summary.size_bytes,
            hash: group.summary.hash.clone(),
            files: group.members,
        };
        if let Some(entry) = self.commander.watch_cache.get_mut(panel) {
            entry.result = Some(crate::tui::commander::state::WatchResult::FileGroup(
                duplicate, claim,
            ));
            entry.empty = crate::tui::commander::state::WatchEmpty::default();
            entry.unavailable = None;
        }
    }

    /// A watch panel whose source could not be read at all. Never a fallback: an unreadable
    /// checkpoint is not «no duplicates here».
    fn set_watch_unavailable(
        &mut self,
        panel: usize,
        subject: crate::tui::commander::state::WatchSubject,
        detail: &str,
    ) {
        if let Some(entry) = self.commander.watch_cache.get_mut(panel) {
            entry.result = None;
            entry.empty = crate::tui::commander::state::WatchEmpty::default();
            entry.unavailable = Some(crate::tui::commander::state::WatchUnavailable {
                subject,
                detail: crate::textsan::terminal(detail),
            });
        }
    }

    /// A watch panel with a legitimate empty answer — and the reason it is empty.
    fn set_watch_empty(&mut self, panel: usize, reason: crate::tui::commander::state::WatchEmpty) {
        if let Some(entry) = self.commander.watch_cache.get_mut(panel) {
            entry.result = None;
            entry.empty = reason;
            entry.unavailable = None;
        }
    }

    fn on_file_info(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<crate::state::FileInfoAnswer, StoreMiss>,
    ) {
        let Some(purpose) = self.routes.infos.remove(&req.0) else {
            return;
        };
        if !self.is_current(act) {
            return;
        }
        let answer = match result {
            Ok(answer) => answer,
            Err(miss) => {
                if self.fatal_store_miss(&miss) {
                    return;
                }
                match purpose {
                    InfoPurpose::Overlay { mut header } => {
                        header.push(format!("file group unavailable: {miss:?}"));
                        self.commander.info_lines = header;
                        self.commander.overlay = crate::tui::commander::state::Overlay::FileInfo;
                    }
                    InfoPurpose::WatchDup { panel } => self.set_watch_unavailable(
                        panel,
                        crate::tui::commander::state::WatchSubject::FileGroup,
                        &format!("{miss:?}"),
                    ),
                }
                return;
            }
        };
        match purpose {
            InfoPurpose::Overlay { header } => self.show_file_info(header, answer),
            InfoPurpose::WatchDup { panel } => self.watch_from_file_info(panel, answer),
        }
    }

    /// The F3 overlay's membership half, from the one typed answer.
    fn show_file_info(&mut self, mut lines: Vec<String>, answer: crate::state::FileInfoAnswer) {
        use crate::state::{FileInfoAnswer, FileMembership};
        match answer {
            FileInfoAnswer::NotInScan => {
                lines.push("Not part of the loaded scan".to_string());
            }
            FileInfoAnswer::InScan {
                hash_text,
                membership,
            } => {
                match hash_text {
                    Some(hash) => lines.push(format!("Hash:     {hash}")),
                    None => lines.push("Hash:     not computed — F4 to calculate".to_string()),
                }
                match membership {
                    // «No duplicates found» is allowed for exactly one state: the row is in the
                    // manifest and belongs to no current group.
                    Ok(FileMembership::NotGrouped) => lines.push("No duplicates found".to_string()),
                    Ok(FileMembership::InGroup(info)) => {
                        let peers = info.peers.len();
                        lines.push(format!("Duplicates ({}):", info.total.saturating_sub(1)));
                        for peer in info.peers.iter() {
                            lines.push(format!("  · {}", peer.display()));
                        }
                        if info.truncated {
                            lines.push(format!(
                                "  … and {} more",
                                info.total.saturating_sub(1).saturating_sub(peers as u64)
                            ));
                        }
                    }
                    Err(MembershipMiss::Unknown) => lines.push(RESULTS_UNPUBLISHED.to_string()),
                    Err(miss) => lines.push(format!("file group unavailable: {miss:?}")),
                }
            }
        }
        self.commander.info_lines = lines;
        self.commander.overlay = crate::tui::commander::state::Overlay::FileInfo;
    }

    /// A watch panel over a file cursor: the typed answer decides between «outside the scan»,
    /// «in the scan, no duplicates» and a real group, which is then opened by identity.
    fn watch_from_file_info(&mut self, panel: usize, answer: crate::state::FileInfoAnswer) {
        use crate::state::{FileInfoAnswer, FileMembership};
        use crate::tui::commander::state::{WatchEmpty, WatchSubject};
        match answer {
            FileInfoAnswer::NotInScan => self.set_watch_empty(panel, WatchEmpty::NotInScan),
            FileInfoAnswer::InScan { membership, .. } => match membership {
                Ok(FileMembership::NotGrouped) => {
                    self.set_watch_empty(panel, WatchEmpty::NoDuplicates)
                }
                Ok(FileMembership::InGroup(info)) => {
                    let id = info.id;
                    let act = self.installed_act;
                    if let Some(req) = self.send_browse(|req| BrowseRequest::GroupOpen {
                        act,
                        req,
                        id,
                        offset: 0,
                        limit: BROWSE_GROUP_FILE_PAGE,
                    }) {
                        self.routes
                            .groups
                            .insert(req.0, GroupPurpose::Watch { panel, id });
                    }
                }
                Err(MembershipMiss::Unknown) => {
                    self.set_watch_unavailable(panel, WatchSubject::FileGroup, RESULTS_UNPUBLISHED)
                }
                Err(miss) => {
                    if !self.fatal_membership_miss(&miss) {
                        self.set_watch_unavailable(
                            panel,
                            WatchSubject::FileGroup,
                            &format!("{miss:?}"),
                        );
                    }
                }
            },
        }
    }

    fn on_dir_group_at(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<crate::state::DirGroupAnswer, StoreMiss>,
    ) {
        use crate::state::DirGroupAnswer;
        use crate::tui::commander::state::{WatchEmpty, WatchResult, WatchSubject};
        let Some(panel) = self.routes.dirs_at.remove(&req.0) else {
            return;
        };
        if !self.is_current(act) {
            return;
        }
        match result {
            Ok(DirGroupAnswer::Group(group)) => {
                if let Some(entry) = self.commander.watch_cache.get_mut(panel) {
                    entry.result = Some(WatchResult::DirGroup(*group));
                    entry.empty = WatchEmpty::default();
                    entry.unavailable = None;
                }
            }
            Ok(DirGroupAnswer::InnerDupes {
                members,
                total,
                truncated,
            }) => {
                let paths = members.into_iter().map(|inner| inner.path).collect();
                if let Some(entry) = self.commander.watch_cache.get_mut(panel) {
                    entry.result = Some(WatchResult::InnerDupes {
                        paths,
                        total,
                        truncated,
                    });
                    entry.empty = WatchEmpty::default();
                    entry.unavailable = None;
                }
            }
            // No authority: candidates, never duplicates. They carry no identity and are
            // rendered with the unpublished wording.
            Ok(DirGroupAnswer::InnerCandidates {
                paths,
                total,
                truncated,
            }) => {
                if let Some(entry) = self.commander.watch_cache.get_mut(panel) {
                    entry.result = Some(WatchResult::InnerCandidates {
                        paths,
                        total,
                        truncated,
                    });
                    entry.empty = WatchEmpty::default();
                    entry.unavailable = None;
                }
            }
            Ok(DirGroupAnswer::NoDuplicates) => {
                self.set_watch_empty(panel, WatchEmpty::NoDuplicates)
            }
            Ok(DirGroupAnswer::NotInScan) => self.set_watch_empty(panel, WatchEmpty::NotInScan),
            Err(miss) => {
                if !self.fatal_store_miss(&miss) {
                    self.set_watch_unavailable(
                        panel,
                        WatchSubject::DirectoryGroup,
                        &format!("{miss:?}"),
                    );
                }
            }
        }
    }

    fn on_dir_group_opened(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<
            Option<Box<crate::model::duplicate::AttributedDirGroup>>,
            StoreMiss,
        >,
    ) {
        let Some(purpose) = self.routes.dir_opens.remove(&req.0) else {
            return;
        };
        if !self.is_current(act) {
            return;
        }
        match result {
            Ok(group) => match purpose {
                DirOpenPurpose::WizardDirs => {
                    self.browser.open_dir_group = group.map(|boxed| *boxed);
                    self.browser.dir_keeper_index = 0;
                    self.browser.dir_file_state = ListState::default();
                    if self
                        .browser
                        .open_dir_group
                        .as_ref()
                        .is_some_and(|g| !g.group.paths.is_empty())
                    {
                        self.browser.dir_file_state.select(Some(0));
                    }
                }
                DirOpenPurpose::Watch { panel } => {
                    if let Some(slot) = self.commander.watch_dir_cache.get_mut(panel) {
                        *slot = group.map(|boxed| *boxed);
                    }
                }
            },
            Err(miss) => {
                if self.fatal_store_miss(&miss) {
                    return;
                }
                // «No such group» and «could not be read» are different answers, and only one of
                // them is allowed to render as an absent group.
                match purpose {
                    DirOpenPurpose::WizardDirs => {
                        self.browser.open_dir_group = None;
                        self.browser.dir_groups_error =
                            Some(format!("directory group unavailable: {miss:?}"));
                    }
                    DirOpenPurpose::Watch { panel } => self.set_watch_unavailable(
                        panel,
                        crate::tui::commander::state::WatchSubject::DirectoryGroup,
                        &format!("{miss:?}"),
                    ),
                }
            }
        }
    }

    fn on_marked_count(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<u64, StoreMiss>,
    ) {
        let expected = match self.routes.marked {
            Some(expected) if expected == req => {
                self.routes.marked = None;
                expected
            }
            _ => return,
        };
        if !self.is_current(act) {
            return;
        }
        match result {
            Ok(count) => {
                self.browser.marked_count = Some(count as usize);
                self.settle_gate_marked(expected, true);
            }
            Err(miss) => {
                // Unavailable, never zero: the operator must not read a refusal as «nothing is
                // marked» and act on it.
                self.browser.marked_count = None;
                if !self.fatal_store_miss(&miss) {
                    self.settle_gate_marked(expected, false);
                    self.status = format!("the marked count is unavailable: {miss:?}");
                }
            }
        }
    }

    fn on_latest_scan(
        &mut self,
        _act: Activation,
        req: RequestId,
        result: std::result::Result<Option<i64>, StoreMiss>,
    ) {
        match self.routes.latest {
            Some(expected) if expected == req => self.routes.latest = None,
            _ => return,
        }
        match result {
            Ok(Some(scan_id)) => self.open_via_actor(scan_id, OpenIntent::Commander),
            Ok(None) => {
                self.commander.dedup_scan_id = None;
                self.commander.status = "No scans in the checkpoint database".to_string();
            }
            Err(miss) => {
                if !self.fatal_store_miss(&miss) {
                    self.commander.status = format!("the scan list is unavailable: {miss:?}");
                }
            }
        }
    }

    // === The marks gate ===

    /// Starts an authoritative re-read after a write the UI did not see in full.
    ///
    /// Both halves are issued together: the count in the header and the rows of the open group.
    /// Planning stays refused until every issued reload has succeeded, so nothing can be built
    /// from rows that are still catching up.
    fn start_gate_reload(&mut self) {
        let act = self.installed_act;
        let marked = self.refresh_marked_count();
        let group = self
            .browser
            .open_group
            .as_ref()
            .and_then(|open| {
                self.browser
                    .group_summaries
                    .iter()
                    .find(|(id, _)| id.rank as usize == open.id)
                    .map(|(id, _)| *id)
            })
            .and_then(|id| {
                let sent = self.send_browse(|req| BrowseRequest::GroupOpen {
                    act,
                    req,
                    id,
                    offset: 0,
                    limit: BROWSE_GROUP_FILE_PAGE,
                });
                if let Some(req) = sent {
                    self.routes
                        .groups
                        .insert(req.0, GroupPurpose::BrowserReload { id });
                }
                sent
            });
        match marked {
            Some(marked) => {
                self.marks_gate = MarksGate::Reloading {
                    act,
                    marked,
                    group,
                    marked_ok: false,
                    group_ok: group.is_none(),
                };
            }
            // Nothing could even be asked: the marks stay unsettled and planning stays refused
            // rather than quietly proceeding over rows nobody re-read.
            None => {
                self.marks_gate = MarksGate::Blocked {
                    act,
                    reason: "the marks could not be re-read — reopen the results".to_string(),
                };
                self.marks_unsettled = true;
            }
        }
    }

    /// The marked-count half of a reload settled.
    fn settle_gate_marked(&mut self, req: RequestId, ok: bool) {
        let MarksGate::Reloading {
            act,
            marked,
            group,
            marked_ok: _,
            group_ok,
        } = self.marks_gate.clone()
        else {
            return;
        };
        if !self.is_current(act) || marked != req {
            return;
        }
        if !ok {
            self.marks_gate = MarksGate::Blocked {
                act,
                reason: "the marked count could not be re-read".to_string(),
            };
            self.marks_unsettled = true;
            return;
        }
        self.marks_gate = MarksGate::Reloading {
            act,
            marked,
            group,
            marked_ok: true,
            group_ok,
        };
        self.clear_gate_if_settled();
    }

    /// The open-group half of a reload settled.
    fn settle_gate_group(&mut self, req: RequestId, ok: bool) {
        let MarksGate::Reloading {
            act,
            marked,
            group,
            marked_ok,
            group_ok: _,
        } = self.marks_gate.clone()
        else {
            return;
        };
        if !self.is_current(act) || group != Some(req) {
            return;
        }
        if !ok {
            self.marks_gate = MarksGate::Blocked {
                act,
                reason: "the open group could not be re-read".to_string(),
            };
            self.marks_unsettled = true;
            return;
        }
        self.marks_gate = MarksGate::Reloading {
            act,
            marked,
            group,
            marked_ok,
            group_ok: true,
        };
        self.clear_gate_if_settled();
    }

    /// The gate clears only when EVERY issued reload has succeeded.
    fn clear_gate_if_settled(&mut self) {
        if let MarksGate::Reloading {
            marked_ok,
            group_ok,
            ..
        } = self.marks_gate
        {
            if marked_ok && group_ok {
                self.marks_gate = MarksGate::Settled;
            }
        }
    }

    // === Marks, auto-select, planning and settlement ===

    /// Releases the actor-side ticket for `req`, whatever the reply says. A settlement is owed
    /// to the ledger, not to the screen: a stale activation is no reason to leave a path locked.
    fn settle_ticket(&mut self, req: RequestId) {
        if let Some(handle) = self.browse.live() {
            let _ = handle.settle(req);
        }
    }

    /// Writes the durable after-image the store returned into every window that shows those
    /// pathnames. This is the authoritative state — never the optimistic one the UI guessed.
    fn apply_mark_image(&mut self, after: &[(PathBuf, Option<MarkIntent>)]) {
        use crate::tui::commander::state::Mark;
        if let Some(open) = self.browser.open_group.as_mut() {
            for (path, intent) in after {
                if let Some(file) = open.files.iter_mut().find(|file| &file.path == path) {
                    file.is_keeper = matches!(intent, Some(MarkIntent::Keeper));
                    file.action = match intent {
                        Some(MarkIntent::Act(kind)) => Some(*kind),
                        _ => None,
                    };
                }
            }
        }
        for panel in &mut self.commander.panels {
            for (path, intent) in after {
                match intent {
                    // `Selected` is a triage selection, not a durable mark — the database says
                    // nothing about it and must not clear it.
                    None => {
                        if panel
                            .marks
                            .get(path)
                            .is_some_and(|mark| *mark != Mark::Selected)
                        {
                            panel.marks.remove(path);
                        }
                    }
                    Some(MarkIntent::Keeper) => {
                        panel.marks.insert(path.clone(), Mark::Keeper);
                    }
                    Some(MarkIntent::Act(ActionKind::Delete)) => {
                        panel.marks.insert(path.clone(), Mark::Delete);
                    }
                    Some(MarkIntent::Act(ActionKind::Hardlink)) => {
                        panel.marks.insert(path.clone(), Mark::Hardlink);
                    }
                    Some(MarkIntent::Act(ActionKind::Reflink)) => {
                        panel.marks.insert(path.clone(), Mark::Reflink);
                    }
                }
            }
        }
    }

    /// Puts the window back the way it was before an optimistic mark the database never took.
    fn restore_mark_origin(&mut self, origin: MarkOrigin) {
        match origin {
            MarkOrigin::WizardGroup { before } => {
                if let Some(open) = self.browser.open_group.as_mut() {
                    open.files = before;
                }
            }
            MarkOrigin::CommanderMark {
                panel,
                path,
                previous,
                // The rollback restores what the panel showed before the keystroke; what that
                // keystroke asked for is correlation evidence and has no part in it.
                requested: _,
            } => {
                if let Some(panel) = self.commander.panels.get_mut(panel) {
                    match previous {
                        Some(mark) => {
                            panel.marks.insert(path, mark);
                        }
                        None => {
                            panel.marks.remove(&path);
                        }
                    }
                }
            }
        }
    }

    fn on_mark_ack(&mut self, act: Activation, req: RequestId, outcome: MarkOutcome) {
        self.settle_ticket(req);
        let origin = self.pending_marks.remove(&req.0);
        if !self.is_current(act) {
            return;
        }
        // What this keystroke asked for, kept for correlation only. The success line is built from
        // the after-image the database returned, never from this.
        let asked = match &origin {
            Some(MarkOrigin::CommanderMark {
                path, requested, ..
            }) => Some((path.clone(), *requested)),
            _ => None,
        };
        match outcome {
            MarkOutcome::Settled { after } => {
                self.apply_mark_image(&after);
                if let Some((path, requested)) = asked {
                    self.report_commander_mark_settled(&path, requested, &after);
                }
            }
            // The write refused, but the database still told us what it holds for exactly these
            // pathnames: settle from that, not from the guess the window made.
            MarkOutcome::Failed { error, after } => {
                self.apply_mark_image(&after);
                self.report_mark_failure(&error);
            }
            // No authoritative image exists at all — the window goes back to what it showed.
            MarkOutcome::Unreadable { error } => {
                if let Some(origin) = origin {
                    self.restore_mark_origin(origin);
                }
                self.report_mark_failure(&error);
            }
        }
        let _ = self.refresh_marked_count();
        self.invalidate_confirmation("the marks changed");
    }

    /// The one place a Commander mark is allowed to be called saved.
    ///
    /// `Settled` alone is not the proof: the reply must actually carry the pathname this keystroke
    /// wrote, holding the durable meaning that was asked for. A reply that omits the path, or that
    /// returns a different meaning, is reported fail-closed — the operator must never read
    /// «Mark saved» over a database that says something else. The displayed meaning is read out of
    /// the after-image, so it states what the database holds rather than what the window hoped.
    fn report_commander_mark_settled(
        &mut self,
        path: &std::path::Path,
        requested: Option<crate::tui::commander::state::Mark>,
        after: &[(PathBuf, Option<MarkIntent>)],
    ) {
        let shown = crate::textsan::terminal(&path.display().to_string());
        let Some((_, returned)) = after.iter().find(|(candidate, _)| candidate == path) else {
            self.commander.status = format!(
                "The mark was not confirmed: the database did not report {shown} — do not treat it as saved"
            );
            return;
        };
        let returned_meaning = durable_meaning(returned.as_ref());
        let asked_meaning = requested_meaning(requested);
        if returned_meaning != asked_meaning {
            self.commander.status = format!(
                "The mark was not confirmed: the database holds {returned_meaning} for {shown}, not {asked_meaning}"
            );
            return;
        }
        // Prefix first, so a 36-column status line clips the pathname and never the verdict.
        self.commander.status = format!("Mark saved: {shown} = {returned_meaning}");
    }

    /// One place turns a typed mark failure into what the operator sees — and uninstalls the
    /// view when the failure says the checkpoint itself was replaced.
    fn report_mark_failure(&mut self, error: &crate::state::MarkWriteError) {
        if let crate::state::MarkWriteError::PathChanged { detail } = error {
            let detail = detail.clone();
            self.uninstall_browsing(&detail);
            return;
        }
        let message = match error {
            // The one refusal an operator meets by ordinary navigation — marking a file the scan
            // never walked — keeps the sentence it has always had. A `Debug` rendering of the
            // variant would tell them the shape of an enum instead of what is wrong.
            crate::state::MarkWriteError::NotInManifest { path } => format!(
                "The mark was not saved: {} is not part of the loaded scan",
                crate::textsan::terminal(&path.display().to_string())
            ),
            _ => format!("the mark was not saved: {error:?}"),
        };
        match self.mode {
            AppMode::Commander => self.commander.status = message,
            AppMode::Wizard => self.status = message,
        }
    }

    fn on_auto_select_done(&mut self, act: Activation, req: RequestId, outcome: AutoSelectOutcome) {
        self.settle_ticket(req);
        if self
            .auto_select
            .as_ref()
            .is_some_and(|(live, _)| *live == req)
        {
            self.auto_select = None;
        }
        if !self.is_current(act) {
            return;
        }
        match outcome {
            AutoSelectOutcome::Completed { groups, marks } => {
                self.status =
                    format!("Auto-select: kept the newest file in {groups} groups, {marks} marked");
                self.after_bulk_mark_write(false);
            }
            // Partial means SOME chunks are durable: the RAM marks are invalidated exactly as
            // they are after a completed sweep, and the batch is reported unsettled until the
            // authoritative reload lands.
            AutoSelectOutcome::Partial {
                committed_groups,
                last_committed_rank,
                cancelled,
                detail,
            } => {
                self.status = format!(
                    "Auto-select stopped after {committed_groups} groups (last rank \
                     {last_committed_rank}{}): {detail}",
                    if cancelled { ", cancelled" } else { "" }
                );
                self.after_bulk_mark_write(true);
            }
            // Refused means exactly zero chunks committed, so nothing in RAM is stale.
            AutoSelectOutcome::Refused(refusal) => {
                if let AutoSelectRefusal::PathChanged { detail } = &refusal {
                    let detail = detail.clone();
                    self.uninstall_browsing(&detail);
                    return;
                }
                self.status = match refusal {
                    AutoSelectRefusal::Unknown => RESULTS_UNPUBLISHED.to_string(),
                    AutoSelectRefusal::CancelledBeforeFirstCommit => {
                        "Auto-select cancelled — nothing was marked".to_string()
                    }
                    other => format!("Auto-select refused: {other:?}"),
                };
            }
        }
    }

    /// What follows a write the UI did not see row by row: every named RAM representation of a
    /// mark is dropped, and the authoritative rows are re-read behind the gate.
    fn after_bulk_mark_write(&mut self, unsettled: bool) {
        use crate::tui::commander::state::Mark;
        for panel in &mut self.commander.panels {
            // The durable marks are stale; the triage selection is not a durable mark.
            panel.marks.retain(|_, mark| *mark == Mark::Selected);
        }
        if let Some(board) = self.commander.board.as_mut() {
            board.source.marks.retain(|_, mark| *mark == Mark::Selected);
            for receiver in &mut board.receivers {
                receiver.marks.retain(|_, mark| *mark == Mark::Selected);
            }
        }
        self.marks_unsettled = unsettled;
        self.invalidate_confirmation("the marks were rewritten");
        self.start_gate_reload();
    }

    fn on_plan_ready(&mut self, act: Activation, req: RequestId, plan: ActionPlan) {
        let window = match self.routes.plan {
            Some((expected, window)) if expected == req => {
                self.routes.plan = None;
                window
            }
            _ => return,
        };
        // A plan belongs to the activation that asked for it. If the view was reopened in the
        // meantime, that plan describes a publication the operator is no longer looking at.
        if !self.is_current(act) {
            return;
        }
        match window {
            PlanWindow::Wizard => {
                let mut list = ListState::default();
                list.select(Some(0));
                self.review = ReviewState {
                    plan: Some(plan),
                    confirming: false,
                    list,
                    visible_rows: 0,
                };
                self.status.clear();
                self.screen = Screen::ActionReview;
            }
            PlanWindow::Commander => crate::tui::commander::actions::seat_plan(self, plan),
        }
    }

    fn on_plan_refused(&mut self, act: Activation, req: RequestId, refusal: PlanRefusal) {
        let window = match self.routes.plan {
            Some((expected, window)) if expected == req => {
                self.routes.plan = None;
                window
            }
            _ => return,
        };
        if !self.is_current(act) {
            return;
        }
        let message = match &refusal {
            PlanRefusal::NoMarks => match window {
                PlanWindow::Wizard => {
                    "No marked actions — mark files: d delete, h hardlink".to_string()
                }
                PlanWindow::Commander => "No marked files (F5/F6/F7/F8)".to_string(),
            },
            other => other.to_string(),
        };
        match window {
            PlanWindow::Wizard => self.status = message,
            PlanWindow::Commander => {
                crate::tui::commander::actions::clear_pending(self);
                self.commander.status = message;
            }
        }
    }

    fn on_reconcile_ack(
        &mut self,
        act: Activation,
        req: RequestId,
        result: std::result::Result<(), StoreMiss>,
    ) {
        match self.routes.reconcile {
            Some(expected) if expected == req => self.routes.reconcile = None,
            _ => return,
        }
        let owed = self.pending_reconcile.take();
        let settling =
            matches!(self.shutdown, ShutdownStage::Settling { req: waiting } if waiting == req);
        match result {
            Ok(()) => {
                if let Some(owed) = &owed {
                    self.forget_settled_marks(&owed.attempted, owed.cancelled, owed.commander);
                }
                self.marks_unsettled = false;
                // The batch's own report is not authority: the count and the open group are
                // re-read behind the gate.
                //
                // Deliberately NOT `after_bulk_mark_write`. That one drops every RAM mark because
                // it follows a write whose rows the UI never saw — an auto-select. This write is
                // the opposite: the batch named exactly which pathnames it attempted, and
                // `forget_settled_marks` has just applied that delta. Wiping the panels on top of
                // it would throw away the marks of the work a cancelled batch never reached,
                // which is the one thing that must survive it.
                //
                // And not during a shutdown: the reload exists to refresh a screen, the exit is
                // about to close the actor, and a reload that never comes back would end the
                // session claiming the marks were not settled — over the write just acknowledged.
                if self.is_current(act) && matches!(self.shutdown, ShutdownStage::None) {
                    self.invalidate_confirmation("the marks were rewritten");
                    self.start_gate_reload();
                }
            }
            Err(miss) => {
                // Fail-visible: the plan on disk still lists what was applied, so nothing may
                // claim the marks were dealt with.
                self.marks_unsettled = true;
                self.marks_gate = MarksGate::Blocked {
                    act: self.installed_act,
                    reason: MARKS_NOT_SETTLED.to_string(),
                };
                if !self.fatal_store_miss(&miss) {
                    self.status = MARKS_NOT_SETTLED.to_string();
                    self.commander.status = MARKS_NOT_SETTLED.to_string();
                }
            }
        }
        if settling {
            self.shutdown = ShutdownStage::Draining;
            self.advance_shutdown();
        }
    }

    fn on_covering_scan(
        &mut self,
        _act: Activation,
        req: RequestId,
        cwd: PathBuf,
        result: std::result::Result<Option<i64>, StoreMiss>,
    ) {
        let Some(_) = self.routes.covering.remove(&req.0) else {
            return;
        };
        match result {
            Ok(found) => {
                self.commander
                    .scan_coverage_cache
                    .insert(cwd.clone(), found);
                crate::tui::commander::apply_auto_switch(self, &cwd, found);
            }
            Err(miss) => {
                if !self.fatal_store_miss(&miss) {
                    // Nothing is cached: a failed probe must not become a remembered «no scan
                    // covers this directory».
                    self.commander.status = format!("scan coverage unavailable: {miss:?}");
                }
            }
        }
    }

    fn on_finished(&mut self, result: std::result::Result<ScanOutcome, String>) {
        self.scan = None;
        // We were only staying alive to let this finish — but other background work may still
        // be in flight, so re-ask rather than quitting outright.
        if shutdown_pending() {
            self.request_shutdown(false);
        }
        // Fresh scan/resume: the result is not from viewing the session list — Esc → ScanConfig/commander.
        self.results_from_sessions = false;
        let completed_scan = match &result {
            Ok(ScanOutcome::Completed(results)) => Some(results.scan_id),
            _ => None,
        };
        match result {
            Ok(ScanOutcome::Completed(results)) => {
                // The scan published its result; the browsing actor is what reads it back. The
                // summary the pipeline reported is what the header shows until the payload
                // installs the authority's own answer.
                self.browser.summary = results.summary;
                self.open_via_actor(results.scan_id, OpenIntent::Wizard);
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

    /// Sends the settlement the last batch owes the database, through the one store owner.
    ///
    /// `None` — it could not even be enqueued; the caller raises the unsettled state rather than
    /// letting the exit proceed as if the marks had been dealt with.
    fn send_pending_reconcile(&mut self) -> Option<RequestId> {
        let owed = self.pending_reconcile.as_ref()?;
        // The settlement belongs to the scan the batch was planned against. If the view has
        // since been reopened onto another one, this actor cannot settle it — and saying so is
        // the honest outcome, not sending the write to the wrong scan.
        if self.current_scan_id != Some(owed.scan_id) {
            return None;
        }
        let act = self.installed_act;
        let attempted = owed.attempted.clone();
        let cancelled = owed.cancelled;
        let sent = self.send_browse(|req| BrowseRequest::ReconcileAfterBatch {
            act,
            req,
            attempted,
            cancelled,
        });
        self.routes.reconcile = sent;
        sent
    }

    /// The batch is over and its marks are not settled in the database. Explicit state, not a
    /// status string: every screen that reports the batch has to keep saying so.
    fn raise_unsettled(&mut self) {
        self.marks_unsettled = true;
        self.marks_gate = MarksGate::Blocked {
            act: self.installed_act,
            reason: MARKS_NOT_SETTLED.to_string(),
        };
        self.status = MARKS_NOT_SETTLED.to_string();
        self.commander.status = MARKS_NOT_SETTLED.to_string();
    }

    /// Background work that has no cancel flag and must be allowed to land.
    fn producers_busy(&self) -> bool {
        self.scan.is_some()
            || self.apply.is_some()
            || self.commander.move_pending > 0
            || self.purge_pending > 0
    }

    /// The one terminal an actor owes has arrived (or was synthesised). Settles what it was
    /// holding, joins it exactly once, and decides whether a successor may exist.
    fn retire_actor(&mut self, retired: RetiredActor, cause: CloseCause) {
        let RetiredActor {
            actor,
            handle,
            join,
        } = retired;
        tracing::info!(?actor, ?cause, "the browsing actor retired");
        let drained = handle.drain_tickets();
        self.settle_retired(drained, &cause);
        // An `Open` the retired actor owed is never going to be answered. Releasing its route
        // here is what keeps «one open at a time» from becoming «no open ever again» — and the
        // operator is told, rather than left watching an «Opening results…» that has stopped.
        if let Some(route) = self.routes.open.take() {
            self.opening_started = None;
            let message = format!(
                "the results of scan #{} could not be opened: browsing stopped first",
                route.scan_id
            );
            self.status = message.clone();
            self.commander.status = message;
        }
        // Exactly once: `take_terminal` hands the pair over on the first terminal only.
        let _ = join.join();
        match cause {
            // A panicked actor gets no successor — the fleet already cleared the pending spawn,
            // and the process is on its way out through the panic hook anyway.
            CloseCause::Panicked(text) => {
                self.marks_unsettled = true;
                self.marks_gate = MarksGate::Blocked {
                    act: self.installed_act,
                    reason: format!("browsing stopped unexpectedly: {text}"),
                };
                let message = format!("browsing stopped unexpectedly: {text}");
                self.status = message.clone();
                self.commander.status = message;
            }
            CloseCause::Requested => {
                if matches!(self.shutdown, ShutdownStage::None) {
                    if let Some(spawn) = self.browse.pending_spawn().cloned() {
                        self.browse.cancel_pending_spawn();
                        let sink = Box::new(AppBrowseSink {
                            events: self.events.clone(),
                        });
                        // Serialized replacement: the successor is spawned only now, after the
                        // old actor's terminal settled and its thread joined.
                        if self
                            .browse
                            .spawn(self.db_path.clone(), spawn.role, sink)
                            .is_some()
                        {
                            if let Some(scan_id) = spawn.reopen {
                                let intent = match self.mode {
                                    AppMode::Commander => OpenIntent::Commander,
                                    AppMode::Wizard => OpenIntent::Wizard,
                                };
                                self.open_via_actor(scan_id, intent);
                            }
                        }
                    }
                } else {
                    self.browse.cancel_pending_spawn();
                }
            }
        }
    }

    /// What a retired actor was still holding: mark tickets nobody acknowledged, and a sweep
    /// that was mid-flight. Both are reported; neither is quietly forgotten.
    fn settle_retired(&mut self, drained: DrainedInflight, cause: &CloseCause) {
        let DrainedInflight { tickets, long_op } = drained;
        let stranded = !tickets.is_empty();
        for ticket in tickets {
            let MarkTicket { req, .. } = &ticket;
            if let Some(origin) = self.pending_marks.remove(&req.0) {
                self.restore_mark_origin(origin);
            }
        }
        if stranded {
            // The database never acknowledged them, so the windows go back to what it last
            // said — and planning is blocked until a fresh open re-establishes the picture.
            self.marks_unsettled = true;
            self.marks_gate = MarksGate::Blocked {
                act: self.installed_act,
                reason: MARKS_STRANDED.to_string(),
            };
            // The commander may still be showing «Saving mark» over a write that is now never
            // going to be answered. Leaving it there would point the operator at a «Mark saved»
            // that cannot arrive — the one fence they were told to wait at.
            self.commander.status = MARKS_STRANDED.to_string();
        }
        if let Some(operation) = long_op {
            operation.cancel.cancel();
            self.auto_select = None;
            self.marks_unsettled = true;
            self.marks_gate = MarksGate::Blocked {
                act: self.installed_act,
                reason: "auto-select was interrupted — its marks are unsettled".to_string(),
            };
        }
        if matches!(cause, CloseCause::Requested) && (stranded || self.marks_unsettled) {
            self.status = MARKS_NOT_SETTLED.to_string();
        }
    }

    fn on_actor_closed(&mut self, actor: ActorId, cause: CloseCause) {
        // Routed by `ActorId` alone and never dropped as stale: a terminal must be deliverable
        // at any time. A duplicate or late one finds nothing to take and is a no-op.
        let Some(retired) = self.browse.take_terminal(actor, &cause) else {
            self.advance_shutdown();
            return;
        };
        self.retire_actor(retired, cause);
        self.advance_shutdown();
    }

    /// Drops the marks in RAM that the DB has just lost — the panels of the commander, or the
    /// group open in the wizard's browser, which is written back wholesale by the next mark and
    /// would otherwise resurrect what the batch already applied.
    fn forget_settled_marks(&mut self, attempted: &[PathBuf], cancelled: bool, commander: bool) {
        let spent = |path: &Path| !cancelled || attempted.iter().any(|target| target == path);
        if commander {
            for panel in &mut self.commander.panels {
                if cancelled {
                    for target in attempted {
                        panel.marks.remove(target);
                    }
                } else {
                    panel.marks.clear();
                }
            }
        } else if let Some(open) = self.browser.open_group.as_mut() {
            for file in &mut open.files {
                if spent(&file.path) {
                    file.is_keeper = false;
                    file.action = None;
                }
            }
        }
    }

    /// Result of background application: summary + Summary screen. For commander —
    /// re-read the panels (marks cleared, directories changed), as it was synchronously.
    /// On error — return to the original screen with a message.
    fn on_apply_finished(&mut self, outcome: ApplyOutcome) {
        self.apply = None;
        self.review.confirming = false;
        let from_commander = self.commander.return_to_commander;
        match outcome {
            // The guarded boundary refused: no lease, no snapshot, no filesystem work at all.
            // The exact plan comes back to the window that confirmed it, and the marks are
            // untouched, so the operator can rescan or simply try again.
            ApplyOutcome::Refused { refusal, plan } => {
                self.apply_affected.clear();
                self.marks_unsettled = false;
                let message = Self::refusal_message(&refusal);
                if from_commander {
                    self.mode = AppMode::Commander;
                    self.commander.return_to_commander = false;
                    crate::tui::commander::actions::seat_plan(self, *plan);
                    self.commander.status = message;
                } else {
                    let mut list = ListState::default();
                    list.select(Some(0));
                    self.review = ReviewState {
                        plan: Some(*plan),
                        confirming: false,
                        list,
                        visible_rows: 0,
                    };
                    self.screen = Screen::ActionReview;
                    self.status = message;
                }
            }
            // A batch that refused itself after the snapshots ran NOTHING. Reconciling its marks
            // would delete the whole plan from the database over a batch that touched no file, and
            // «unsettled» would be a lie of its own: the database never refused a write, because
            // none should have been attempted. The snapshots it did create are in the result and
            // have to be reported so they can be destroyed.
            ApplyOutcome::Finished(batch) if batch.aborted.is_some() => {
                self.apply_affected.clear();
                self.marks_unsettled = false;
                self.status = String::new();
                self.summary_result = Some(batch);
                self.screen = Screen::Summary;
                if from_commander {
                    self.commander.status = BATCH_REFUSED.to_string();
                }
                let _ = self.refresh_marked_count();
            }
            ApplyOutcome::Finished(batch) => {
                // A cancelled batch is not a finished one: only what was actually attempted loses
                // its mark, so the marking work for the rest of the plan survives.
                let cancelled = batch.cancelled;
                let attempted: Vec<PathBuf> = batch
                    .outcomes
                    .iter()
                    .map(|outcome| outcome.target.clone())
                    .collect();
                // The marks also live in SQLite, and the plan is built straight from there —
                // settling only the copy in RAM would bring the applied actions back on the next
                // restart. The settlement goes through the one store owner and is acknowledged;
                // until that acknowledgement lands, nothing claims the marks were dealt with.
                let scan_id = if from_commander {
                    self.commander.dedup_scan_id
                } else {
                    self.current_scan_id
                };
                self.summary_result = Some(batch);
                self.screen = Screen::Summary;
                match scan_id {
                    Some(scan_id) => {
                        self.pending_reconcile = Some(PendingReconcile {
                            scan_id,
                            attempted,
                            cancelled,
                            commander: from_commander,
                        });
                        self.marks_unsettled = true;
                        self.status = String::new();
                        if self.send_pending_reconcile().is_none() {
                            // It could not even be enqueued — say so rather than implying the
                            // plan on disk has changed.
                            self.raise_unsettled();
                        }
                    }
                    // No scan behind the marks (a commander batch without loaded dedup data) —
                    // nothing was ever persisted, so there is nothing to settle.
                    None => {
                        self.marks_unsettled = false;
                        self.status = String::new();
                    }
                }
                if from_commander {
                    let affected = std::mem::take(&mut self.apply_affected);
                    crate::tui::commander::invalidate_dir_sizes(self, &affected);
                    let count = self.commander.panels.len();
                    for index in 0..count {
                        crate::tui::commander::reload_panel(self, index);
                    }
                }
            }
            ApplyOutcome::Failed(err) => {
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
        // The batch has reported, so its outcome is recorded; other background work may still
        // need to land, so re-ask rather than quitting outright.
        if shutdown_pending() {
            self.request_shutdown(false);
        } else {
            self.advance_shutdown();
        }
    }

    /// What a guarded refusal says to the operator. Every variant means the batch never began.
    fn refusal_message(refusal: &ApplyRefusal) -> String {
        format!("The batch was refused before any change: {refusal:?}")
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
                self.set_read_only(true);
                self.concurrency_prompt = None;
                self.commander.status = "Observer mode: read-only".to_string();
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                if let Some(dir) = self.db_path.parent() {
                    match crate::lock::try_acquire(dir) {
                        Ok(crate::lock::Acquire::Operator(lock)) => {
                            self.instance_lock = Some(lock);
                            self.set_read_only(false);
                            self.commander.status = "Operator role acquired".to_string();
                        }
                        _ => {
                            self.set_read_only(false);
                            self.commander.status =
                                "WARNING: operator by force — another instance is active"
                                    .to_string();
                        }
                    }
                } else {
                    self.set_read_only(false);
                }
                self.concurrency_prompt = None;
            }
            KeyCode::Esc => self.should_quit = true,
            _ => {}
        }
    }

    /// Switches the role.
    ///
    /// A browsing actor's capability is fixed for its whole life, so a role change REPLACES it:
    /// the old actor is closed, its tickets settle, its thread is joined, and only then does a
    /// successor open a connection of the new kind. At most one actor ever exists over the
    /// database. The replacement is refused while a batch is live, because that batch owes the
    /// current actor a mark settlement.
    fn set_read_only(&mut self, read_only: bool) {
        if self.read_only == read_only {
            return;
        }
        if self.apply.is_some() {
            self.commander.status =
                "The role cannot change while actions are being applied — wait for the batch"
                    .to_string();
            return;
        }
        self.read_only = read_only;
        crate::state::set_observer_role(read_only);
        let role = self.browse_role();
        let reopen = self.current_scan_id;
        if matches!(self.browse.phase(), crate::state::browse::FleetPhase::Idle) {
            // No actor to replace: the next request opens one with the new capability.
            self.browse.cancel_pending_spawn();
            if let Some(scan_id) = reopen {
                let intent = match self.mode {
                    AppMode::Commander => OpenIntent::Commander,
                    AppMode::Wizard => OpenIntent::Wizard,
                };
                self.open_via_actor(scan_id, intent);
            }
            return;
        }
        if let Some(retired) = self.browse.replace(role, reopen) {
            // The close could not even be sent — the actor is already gone, so its retirement
            // (and the successor it was waiting for) happens here.
            self.retire_actor(retired, CloseCause::Requested);
        }
    }

    /// A shutdown signal arrived (SIGHUP from a dropped SSH session, SIGTERM, SIGINT).
    ///
    /// Arms the same cancellation Esc uses — finish the current action, then stop — instead of
    /// dying between a quarantine evacuation and its publish. `forced` (a second signal) stops
    /// waiting and leaves the threads detached, exactly as before.
    ///
    /// Called from the event loop on every iteration, so it must stay idempotent.
    pub fn request_shutdown(&mut self, forced: bool) {
        if let Some(handle) = &self.scan {
            handle.cancel();
        }
        if let Some(handle) = &self.apply {
            handle.cancel();
        }
        if forced {
            self.browse.cancel_pending_spawn();
            self.shutdown = ShutdownStage::Done;
            self.should_quit = true;
            return;
        }
        if matches!(self.shutdown, ShutdownStage::None) {
            // A pending role replacement is cancelled here: no successor may be spawned once
            // the exit has begun. The browsing actor itself stays ALIVE — a finished batch owes
            // it a mark settlement, and closing it now would refuse that write.
            self.browse.cancel_pending_spawn();
            self.shutdown = ShutdownStage::Producers;
        }
        self.advance_shutdown();
    }

    /// The staged exit, re-evaluated from state alone.
    ///
    /// Idempotent by construction: every transition is decided from what is true right now —
    /// which producers are still running, whether a settlement is owed, and whether any actor
    /// still owes its one terminal — never from a remembered step. That is what keeps a stage
    /// from waiting for a terminal nobody owes.
    pub(crate) fn advance_shutdown(&mut self) {
        loop {
            match self.shutdown.clone() {
                ShutdownStage::None => return,
                // A background move must reach `CommanderMoveDone` so its MoveRecord and Undo
                // entry are written, and a purge must reach `SessionDeleted`. Neither has a
                // cancel flag to arm — the only safe thing is to let it finish.
                ShutdownStage::Producers => {
                    if self.producers_busy() {
                        let waiting =
                            "Signal received — finishing the current action, then exiting…";
                        if self.status != waiting {
                            self.status = waiting.to_string();
                            self.commander.status = waiting.to_string();
                        }
                        return;
                    }
                    if self.pending_reconcile.is_none() {
                        self.shutdown = ShutdownStage::Draining;
                        continue;
                    }
                    if !self.browse.terminal_owed() {
                        // Nothing is alive to settle it. Say so and leave — a settlement that
                        // cannot happen must not hold the exit open.
                        self.raise_unsettled();
                        self.pending_reconcile = None;
                        self.shutdown = ShutdownStage::Done;
                        continue;
                    }
                    match self.send_pending_reconcile() {
                        Some(req) => {
                            self.shutdown = ShutdownStage::Settling { req };
                            return;
                        }
                        None => {
                            self.raise_unsettled();
                            self.pending_reconcile = None;
                            self.shutdown = ShutdownStage::Draining;
                        }
                    }
                }
                ShutdownStage::Settling { .. } => {
                    // The terminal was consumed while the settlement was in flight: its
                    // acknowledgement is never coming, and no state may wait for a second one.
                    if !self.browse.terminal_owed() {
                        self.raise_unsettled();
                        self.pending_reconcile = None;
                        self.routes.reconcile = None;
                        self.shutdown = ShutdownStage::Done;
                        continue;
                    }
                    return;
                }
                ShutdownStage::Draining => {
                    if !self.browse.terminal_owed() {
                        self.shutdown = ShutdownStage::Done;
                        continue;
                    }
                    // Idempotent: a fleet that is already draining is asked nothing twice. A
                    // send failure means the actor is already gone, and its retirement — the
                    // tickets it held included — happens here rather than being waited for.
                    match self.browse.begin_close() {
                        Some(retired) => {
                            self.retire_actor(retired, CloseCause::Requested);
                            continue;
                        }
                        None => return,
                    }
                }
                ShutdownStage::Done => {
                    self.should_quit = true;
                    return;
                }
            }
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
        let real_idx = if want_focus_files {
            match crate::tui::screens::browser::visual_to_real_index(
                start,
                visual_row as usize,
                total,
            ) {
                Some(idx) => idx,
                None => return, // click on a separator or outside the list — ignore
            }
        } else {
            // The group list draws no separators and gives each group as many rows as this panel
            // width needs, so the click maps by that height. Sharing the separator-aware mapping
            // with the file panel would land the cursor on a different group than the pointer.
            let rows = crate::tui::screens::browser::group_rows(area.width).max(1) as usize;
            let idx = start + visual_row as usize / rows;
            if idx >= total {
                return; // click below the last group — ignore
            }
            idx
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
                    .map_or(0, |g| g.group.paths.len()),
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

    /// Opens a completed scan as a RESULT: the browsing actor prepares it (operator only),
    /// reads it under one validated snapshot and answers with the whole payload.
    ///
    /// Nothing is loaded here and nothing is installed until that answer arrives, so there is no
    /// window in which the screen shows half a result — and a slow first open shows the
    /// «Opening result» animation instead of freezing the interface.
    pub fn spawn_open_completed(&mut self, scan_id: i64) {
        self.open_via_actor(scan_id, OpenIntent::Wizard);
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
        // Counted so a shutdown signal waits for the multi-index DELETE to finish and for its
        // result to be handled, rather than leaving it half-done.
        self.purge_pending += 1;
        spawn_purge_job(events, move || {
            ScanStore::open(&db_path)
                .and_then(|mut store| store.purge_scan(scan_id))
                .map(|()| scan_id)
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
                // Esc cancels a running sweep before it means «leave the screen»: the token is
                // the request-scoped one created before the request was enqueued, so a
                // cancellation pressed at any moment — including before the actor even reached
                // the handler — is seen at the next chunk boundary and cannot be erased.
                if self.cancel_auto_select() {
                    return;
                }
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
        let len = self
            .review
            .plan
            .as_ref()
            .map_or(0, |plan| plan.actions().len());
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Char('y') | KeyCode::Char('Y') => self.review.confirming = true,
            KeyCode::Up => step(&mut self.review.list, len, -1),
            KeyCode::Down => step(&mut self.review.list, len, 1),
            KeyCode::PageUp => step(
                &mut self.review.list,
                len,
                page_step(self.review.visible_rows, -1),
            ),
            KeyCode::PageDown => step(
                &mut self.review.list,
                len,
                page_step(self.review.visible_rows, 1),
            ),
            KeyCode::Home => step(&mut self.review.list, len, i32::MIN / 2),
            KeyCode::End => step(&mut self.review.list, len, i32::MAX / 2),
            KeyCode::Esc => {
                // Leaving the review drops the plan: coming back rebuilds it from the database, so
                // a stale value can never be the thing a later [Y] executes.
                self.review.plan = None;
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
                // «Applied» would be a lie after a cancelled batch — the marks that were never
                // reached are still there, waiting to be executed again.
                let result = self.summary_result.as_ref();
                let cancelled = result.map(|result| result.cancelled).unwrap_or(false);
                let refused = result
                    .map(|result| result.aborted.is_some())
                    .unwrap_or(false);
                // Unsettled marks outrank the rest: the plan on disk still holds what was applied,
                // and this screen is where the operator would start the next one. A refused batch
                // outranks «applied» for the opposite reason — nothing was applied at all.
                self.status = if self.marks_unsettled {
                    MARKS_NOT_SETTLED.to_string()
                } else if refused {
                    BATCH_REFUSED.to_string()
                } else if cancelled {
                    "Application cancelled. The marks that were not reached are kept.".to_string()
                } else {
                    "Actions applied. Start a new scan for fresh data.".to_string()
                };
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
                .map_or(0, |g| g.group.paths.len());
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
                .is_some_and(|g| !g.group.paths.is_empty())
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
                .map_or(0, |g| g.group.paths.len());
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
            .is_some_and(|g| idx < g.group.paths.len());
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
        let (rank, loaded) = match self.browser.open_group.as_ref() {
            Some(open) => (open.id, open.files.len()),
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
        // One page in flight at a time: a second request for the same offset would append the
        // same rows twice.
        if self
            .routes
            .groups
            .values()
            .any(|purpose| matches!(purpose, GroupPurpose::BrowserMore { .. }))
        {
            return;
        }
        let Some(id) = self
            .browser
            .group_summaries
            .iter()
            .find(|(id, _)| id.rank as usize == rank)
            .map(|(id, _)| *id)
        else {
            return;
        };
        let act = self.installed_act;
        if let Some(req) = self.send_browse(|req| BrowseRequest::GroupOpen {
            act,
            req,
            id,
            offset: loaded,
            limit: BROWSE_GROUP_FILE_PAGE,
        }) {
            self.routes
                .groups
                .insert(req.0, GroupPurpose::BrowserMore { id, loaded });
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
        // Marks feed the operator's deletion plan, so an observer must not set them. The store
        // would refuse the write anyway; this is the message that explains why.
        if self.deny_if_read_only("marking files") {
            return;
        }
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
        let before = self.open_group_marks();
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
        self.settle_open_group(before);
    }

    /// The open group's rows as they stand — the state to fall back to when a write is refused.
    fn open_group_marks(&self) -> Vec<FileEntry> {
        self.browser
            .open_group
            .as_ref()
            .map(|open| open.files.clone())
            .unwrap_or_default()
    }

    /// Makes the current file the keeper of the open group.
    fn browser_set_keeper(&mut self) {
        if self.deny_if_read_only("choosing a keeper") {
            return;
        }
        let Some((_, file_index)) = self.current_group_file() else {
            return;
        };
        let before = self.open_group_marks();
        if let Some(open) = self.browser.open_group.as_mut() {
            for (index, file) in open.files.iter_mut().enumerate() {
                file.is_keeper = index == file_index;
                if index == file_index {
                    file.action = None;
                }
            }
        }
        self.settle_open_group(before);
    }

    /// Auto-select: in each group keep the newest file, the rest — for deletion.
    ///
    /// One request for the whole sweep. The actor streams the groups through the membership
    /// authority and commits in chunks, so nothing holds the scan in RAM; Esc cancels it at a
    /// chunk boundary through the request-scoped token created BEFORE the request is enqueued —
    /// there is no window in which a cancellation can be erased.
    fn browser_auto(&mut self) {
        if self.deny_if_read_only("auto-select") {
            return;
        }
        if self.current_scan_id.is_none() {
            return;
        }
        if self.auto_select.is_some() {
            self.status = "Auto-select is already running — Esc cancels it".to_string();
            return;
        }
        let act = self.installed_act;
        let cancel = CancelToken::new();
        let req = self.browse.next_request();
        let Some(handle) = self.browse.live().cloned() else {
            self.status = "Auto-select: browsing is not available".to_string();
            return;
        };
        match handle.send_auto_select(act, req, cancel.clone()) {
            Ok(()) => {
                self.auto_select = Some((req, cancel));
                self.status = "Auto-select: running…".to_string();
            }
            // The complete long operation comes back, so the refusal names exactly what was
            // refused rather than a sentence about it.
            Err(RefusedAutoSelect { reason, long_op }) => {
                debug_assert_eq!(long_op.req, req);
                self.status = format!("Auto-select refused: {reason:?}");
            }
        }
    }

    /// Saves the marks of the specified files of the current scan to the DB (Feature 6B).
    ///
    /// Fail-closed: a write the database refused is reported, and the caller puts the group back
    /// the way the database still has it. A mark that lives only in RAM is a screen that says
    /// DELETE over a database that says nothing — and the plan is built from the database.
    /// Sends the open group's marks to the actor and remembers what the window looked like.
    ///
    /// The rows on screen are optimistic until the acknowledgement arrives: the after-image the
    /// store read inside its own write transaction is what finally settles them, and a refusal
    /// puts `before` back. Nothing here decides that a write succeeded.
    fn settle_open_group(&mut self, before: Vec<FileEntry>) {
        if self.current_scan_id.is_none() {
            return;
        }
        let Some(entries) = self
            .browser
            .open_group
            .as_ref()
            .map(|open| open.files.clone())
        else {
            return;
        };
        // The durable image of exactly these pathnames, as this window last heard it — the
        // ticket's own before-image, which is what a refusal or a terminal restores from.
        let durable: Vec<(PathBuf, Option<MarkIntent>)> = before
            .iter()
            .map(|file| (file.path.clone(), mark_intent_of(file)))
            .collect();
        let act = self.installed_act;
        let req = self.browse.next_request();
        let Some(handle) = self.browse.live().cloned() else {
            if let Some(open) = self.browser.open_group.as_mut() {
                open.files = before;
            }
            self.status = "The mark was not saved — browsing is not available".to_string();
            return;
        };
        match handle.send_set_marks(act, req, entries, durable) {
            Ok(()) => {
                self.pending_marks
                    .insert(req.0, MarkOrigin::WizardGroup { before });
            }
            Err(refused) => {
                // The complete ticket (or the complete raw inputs) comes back, so the window is
                // restored from what it actually supplied — and from the durable image that
                // supply carried, which is what the database still holds.
                if let Some(open) = self.browser.open_group.as_mut() {
                    open.files = before;
                }
                let durable = refused.before().to_vec();
                self.apply_mark_image(&durable);
                self.status = format!("The mark was not saved: {:?}", refused.reason());
            }
        }
    }

    /// The marks this window believes it holds right now — the group open in the browser.
    ///
    /// The store reconciles them against the database rather than trusting them, so a mark whose
    /// write failed cannot be quietly replaced by the older meaning it was supposed to overwrite.
    /// Durable marks made elsewhere stay in the plan; they are the operator's earlier work.
    fn requested_marks(&self) -> Vec<RequestedMark> {
        let Some(open) = self.browser.open_group.as_ref() else {
            return Vec::new();
        };
        open.files
            .iter()
            .filter_map(|file| {
                let intent = match (file.is_keeper, file.action) {
                    (true, _) => MarkIntent::Keeper,
                    (false, Some(kind)) => MarkIntent::Act(kind),
                    (false, None) => return None,
                };
                Some(RequestedMark {
                    path: file.path.clone(),
                    intent,
                })
            })
            .collect()
    }

    /// Transition to the action review. The plan comes from the one store authority, over the
    /// complete persisted evidence of every referenced group — never from the pathnames on screen.
    ///
    /// A refusal is shown, not swallowed. «No marked actions» used to be printed for an unreadable
    /// database too, which told the operator their marks were gone when the truth was that nothing
    /// could be read at all.
    fn open_review(&mut self) {
        if self.current_scan_id.is_none() {
            self.status = "No scan is loaded — run or open a scan first".to_string();
            return;
        }
        // A plan may not overtake a mark the database has not accepted yet, and it may not be
        // built while the rows on screen are being re-read. Refused HERE, locally, on top of the
        // queue's own FIFO order — an unacknowledged mark must never enter a plan.
        if let Some(reason) = self.plan_gate_refusal() {
            self.status = reason;
            return;
        }
        let requested = self.requested_marks();
        let act = self.installed_act;
        if let Some(req) = self.send_browse(|req| BrowseRequest::BuildPlan {
            act,
            req,
            requested,
        }) {
            self.routes.plan = Some((req, PlanWindow::Wizard));
            self.status = "Building the plan…".to_string();
        }
    }

    /// Asks the authority for the commander's plan. `false` — it could not even be enqueued.
    pub(crate) fn request_commander_plan(&mut self, requested: Vec<RequestedMark>) -> bool {
        let act = self.installed_act;
        match self.send_browse(|req| BrowseRequest::BuildPlan {
            act,
            req,
            requested,
        }) {
            Some(req) => {
                self.routes.plan = Some((req, PlanWindow::Commander));
                true
            }
            None => false,
        }
    }

    /// One panel refresh: every file's membership and every subdirectory's size and signature,
    /// in one request answered from one snapshot.
    pub(crate) fn request_panel_data(
        &mut self,
        target: LoadTarget,
        cwd: PathBuf,
        files: Vec<PathBuf>,
        dirs: Vec<PathBuf>,
    ) {
        let act = self.installed_act;
        let asked = cwd.clone();
        match self.send_browse(|req| BrowseRequest::PanelData {
            act,
            req,
            files,
            dirs,
        }) {
            Some(req) => {
                self.routes.panels.insert(req.0, (target, cwd));
            }
            // Nothing was asked, so nothing is pending: the panel keeps whatever it had rather
            // than waiting for an answer that will never come.
            None => {
                self.commander
                    .dedup
                    .insert_dir(asked, Err("browsing is not available".to_string()));
            }
        }
    }

    /// Sends one commander mark and remembers what that panel showed before it.
    ///
    /// The before-image is the durable meaning this window last heard for exactly this pathname,
    /// so a refusal — or an actor that dies holding the ticket — puts the panel back where the
    /// database still is.
    pub(crate) fn send_commander_mark(
        &mut self,
        panel: usize,
        file: FileEntry,
        previous: Option<crate::tui::commander::state::Mark>,
        requested: Option<crate::tui::commander::state::Mark>,
    ) -> crate::error::Result<()> {
        let path = file.path.clone();
        let durable = previous.and_then(|mark| match mark {
            crate::tui::commander::state::Mark::Keeper => Some(MarkIntent::Keeper),
            crate::tui::commander::state::Mark::Delete => Some(MarkIntent::Act(ActionKind::Delete)),
            crate::tui::commander::state::Mark::Hardlink => {
                Some(MarkIntent::Act(ActionKind::Hardlink))
            }
            crate::tui::commander::state::Mark::Reflink => {
                Some(MarkIntent::Act(ActionKind::Reflink))
            }
            // A triage selection is not a durable mark: the database holds nothing for it.
            crate::tui::commander::state::Mark::Selected => None,
        });
        let act = self.installed_act;
        let req = self.browse.next_request();
        let Some(handle) = self.browse.live().cloned() else {
            return Err(crate::error::AppError::msg(
                "browsing is not available — the mark was not saved",
            ));
        };
        match handle.send_set_marks(act, req, vec![file], vec![(path.clone(), durable)]) {
            Ok(()) => {
                // «Submitted», never «saved». The operator learns the write landed only from the
                // acknowledgement, and only after the after-image is checked against the request.
                self.commander.status = format!(
                    "Saving mark: {}",
                    crate::textsan::terminal(&path.display().to_string())
                );
                self.pending_marks.insert(
                    req.0,
                    MarkOrigin::CommanderMark {
                        panel,
                        path,
                        previous,
                        requested,
                    },
                );
                Ok(())
            }
            Err(refused) => {
                let durable = refused.before().to_vec();
                self.apply_mark_image(&durable);
                Err(crate::error::AppError::msg(format!(
                    "{:?}",
                    refused.reason()
                )))
            }
        }
    }

    /// Opens a group for a commander watching panel, by identity.
    pub(crate) fn request_watch_group_open(&mut self, panel: usize, id: GroupId) {
        let act = self.installed_act;
        if let Some(req) = self.send_browse(|req| BrowseRequest::GroupOpen {
            act,
            req,
            id,
            offset: 0,
            limit: BROWSE_GROUP_FILE_PAGE,
        }) {
            self.routes
                .groups
                .insert(req.0, GroupPurpose::Watch { panel, id });
        }
    }

    /// Asks what a file cursor resolves to for a commander watching panel.
    pub(crate) fn request_watch_file_info(&mut self, panel: usize, path: PathBuf) {
        let act = self.installed_act;
        if let Some(req) = self.send_browse(|req| BrowseRequest::FileInfo { act, req, path }) {
            self.routes
                .infos
                .insert(req.0, InfoPurpose::WatchDup { panel });
        }
    }

    /// Opens one directory group by signature for a commander panel.
    pub(crate) fn request_open_dir_group(&mut self, panel: usize, signature: String) {
        let act = self.installed_act;
        if let Some(req) = self.send_browse(|req| BrowseRequest::OpenDirGroup {
            act,
            req,
            signature,
        }) {
            self.routes
                .dir_opens
                .insert(req.0, DirOpenPurpose::Watch { panel });
        }
    }

    /// Asks what a directory cursor resolves to for a commander watching panel.
    pub(crate) fn request_watch_dir_group(&mut self, panel: usize, dir: PathBuf) {
        let act = self.installed_act;
        if let Some(req) = self.send_browse(|req| BrowseRequest::DirGroupAt { act, req, dir }) {
            self.routes.dirs_at.insert(req.0, panel);
        }
    }

    /// The F3 overlay: the header lines are built from the panel entry, the membership half
    /// arrives from the authority.
    pub(crate) fn request_file_info_overlay(&mut self, path: PathBuf, header: Vec<String>) {
        let act = self.installed_act;
        match self.send_browse(|req| BrowseRequest::FileInfo { act, req, path }) {
            Some(req) => {
                self.routes
                    .infos
                    .insert(req.0, InfoPurpose::Overlay { header });
            }
            // Without a scan there is nothing to ask: the overlay shows what the filesystem
            // itself said and says plainly that membership is unknown.
            None => {
                let mut lines = header;
                lines.push("No scan is loaded — F2/F12 to select one".to_string());
                self.commander.info_lines = lines;
                self.commander.overlay = crate::tui::commander::state::Overlay::FileInfo;
            }
        }
    }

    /// Asks which scan covers `cwd`, once. The answer fills the coverage cache and applies the
    /// switch; a directory with a probe in flight is simply not decided yet.
    pub(crate) fn request_covering_scan(&mut self, cwd: PathBuf) {
        if self.routes.covering.values().any(|pending| *pending == cwd) {
            return;
        }
        let act = self.installed_act;
        let asked = cwd.clone();
        if let Some(req) = self.send_browse(|req| BrowseRequest::CoveringScan {
            act,
            req,
            cwd: asked,
        }) {
            self.routes.covering.insert(req.0, cwd);
        }
    }

    /// Cancels a running auto-select sweep. `true` — one was running, so the keystroke belonged
    /// to it and means nothing else.
    ///
    /// The sweep stops at its next chunk boundary; whatever it had already committed stays
    /// durable and is reported as `Partial`, so the operator is never told nothing happened when
    /// something did.
    pub(crate) fn cancel_auto_select(&mut self) -> bool {
        let Some((_, cancel)) = self.auto_select.as_ref() else {
            return false;
        };
        cancel.cancel();
        // The handle's own ledger holds the same request-scoped token, and cancelling through it
        // is what covers the window between «registered» and «the handler started».
        if let Some(handle) = self.browse.live() {
            handle.cancel_long_operation();
        }
        let message = "Auto-select: cancelling…".to_string();
        self.status = message.clone();
        self.commander.status = message;
        true
    }

    /// Why a plan may not be built right now, if it may not be.
    pub(crate) fn plan_gate_refusal(&self) -> Option<String> {
        if !self.pending_marks.is_empty() {
            return Some(
                "a mark is still being written — the plan waits for the database to accept it"
                    .to_string(),
            );
        }
        if self.auto_select.is_some() {
            return Some("auto-select is still running — wait for it to finish".to_string());
        }
        self.marks_gate.refusal()
    }

    /// Applies the reviewed plan (snapshot -> application) and transitions to the summary.
    ///
    /// The plan is MOVED into the worker: what was confirmed is exactly what runs, and the screen
    /// is left without a plan it could confirm a second time.
    fn apply_actions(&mut self) {
        if self.deny_if_read_only("performing actions") {
            return;
        }
        let Some(plan) = self.review.plan.take() else {
            return;
        };
        self.start_apply(plan);
    }

    /// Launches applying the batch in a background worker: the UI does not freeze,
    /// progress and summary come as `ApplyProgress`/`ApplyFinished` events. A single path
    /// for the wizard (`apply_actions`) and the commander (`confirm_execution`).
    pub fn start_apply(&mut self, plan: ActionPlan) {
        if plan.actions().is_empty() {
            return;
        }
        let datasets: Vec<Dataset> = self
            .zfs
            .pools
            .iter()
            .flat_map(|pool| pool.datasets.iter().cloned())
            .collect();
        self.apply_affected = plan
            .actions()
            .iter()
            .map(|action| action.target().to_path_buf())
            .collect();
        // The warning belongs to the batch that raised it, not to the session.
        self.marks_unsettled = false;
        self.applying = ApplyingState {
            total: plan.actions().len(),
            bytes_total: actions::verify_bytes_total(&plan, self.reval_mode),
            mode: self.reval_mode,
            ..ApplyingState::default()
        };
        self.status.clear();
        self.screen = Screen::Applying;
        // Through the guarded boundary: the worker opens its own apply lease, revalidates the
        // witness the plan owns and holds the lease for the whole batch.
        self.apply = Some(actions::apply_worker::spawn(
            self.db_path.clone(),
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

    /// Sets the scan source of the dedup overlay: if `scan_id` is given it is opened, otherwise
    /// the actor is asked for the newest scan and the answer opens it.
    ///
    /// Nothing is cleared here for the `None` case: the caches belong to the scan that is
    /// installed, and they are replaced atomically by the open that follows.
    pub fn spawn_dedup_load(&mut self, scan_id: Option<i64>) {
        match scan_id {
            Some(id) => self.open_via_actor(id, OpenIntent::Commander),
            None => {
                let act = self.installed_act;
                self.routes.latest = self.send_browse(|req| BrowseRequest::LatestScan { act, req });
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

/// What a row's marks mean, in the vocabulary the store persists. The two states are exclusive,
/// so «keeper and delete» is not representable here either.
fn mark_intent_of(file: &FileEntry) -> Option<MarkIntent> {
    match (file.is_keeper, file.action) {
        (true, _) => Some(MarkIntent::Keeper),
        (false, Some(kind)) => Some(MarkIntent::Act(kind)),
        (false, None) => None,
    }
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

/// A shutdown is already under way when a signal arrived or a panic took the screen away. The
/// completion handlers ask again, so the last piece of background work releases the wait.
fn shutdown_pending() -> bool {
    crate::signals::requested() || crate::panics::tui_dead()
}

/// Runs the purge in the background so a multi-index DELETE does not hang the UI. Split out so a
/// test can hand it a job that panics: `purge_pending` is released only by `SessionDeleted`, so
/// that event has to arrive even then.
fn spawn_purge_job<F>(events: crossbeam_channel::Sender<AppEvent>, job: F)
where
    F: FnOnce() -> crate::error::Result<i64> + Send + 'static,
{
    std::thread::spawn(move || {
        let result = crate::panics::guard("the purge worker", job);
        let _ = events.send(AppEvent::SessionDeleted(result));
    });
}

/// `Settled` is not by itself permission to say «saved».
///
/// These read the verdict straight out of the one function allowed to render the success prefix,
/// with the after-image supplied by hand — the two shapes a real store could hand back that must
/// never become a success line.
#[cfg(test)]
mod mark_settlement_is_checked_tests {
    use super::*;
    use crate::tui::commander::state::Mark;

    #[test]
    fn an_after_image_that_omits_the_path_is_not_saved() {
        let (mut app, _rx) = test_app();
        let path = PathBuf::from("/tank/a.bin");

        // The reply settled — but it says nothing about the pathname this keystroke wrote.
        app.report_commander_mark_settled(&path, Some(Mark::Keeper), &[]);

        assert!(
            !app.commander.status.starts_with("Mark saved"),
            "a silent after-image is not an acknowledgement: {}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains("did not report"),
            "and it says exactly what was missing: {}",
            app.commander.status
        );
    }

    #[test]
    fn an_after_image_holding_a_different_meaning_is_not_saved() {
        let (mut app, _rx) = test_app();
        let path = PathBuf::from("/tank/a.bin");
        let after = vec![(
            path.clone(),
            Some(MarkIntent::Act(crate::model::action::ActionKind::Delete)),
        )];

        // Keeper was asked for; the database says delete. Success here would print a lie.
        app.report_commander_mark_settled(&path, Some(Mark::Keeper), &after);

        assert!(
            !app.commander.status.starts_with("Mark saved"),
            "a disagreeing after-image must never read as success: {}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains("delete") && app.commander.status.contains("keeper"),
            "and it names both meanings so the operator can see the disagreement: {}",
            app.commander.status
        );
    }

    #[test]
    fn an_agreeing_after_image_is_the_only_thing_that_is_saved() {
        let (mut app, _rx) = test_app();
        let path = PathBuf::from("/tank/a.bin");
        let after = vec![(path.clone(), Some(MarkIntent::Keeper))];

        app.report_commander_mark_settled(&path, Some(Mark::Keeper), &after);

        assert!(
            app.commander.status.starts_with("Mark saved"),
            "the agreeing case is the one that earns the prefix: {}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains("keeper"),
            "stating the meaning the database returned: {}",
            app.commander.status
        );
    }
}

/// A shutdown signal must not abandon background work that has no cancel flag: a move batch
/// still has to reach `CommanderMoveDone` so its MoveRecord and Undo entry are written, and a
/// purge still has to reach `SessionDeleted`.
/// An `App` in commander mode over a database that is not there. Lives outside the test modules
/// because the commander's own tests need the same one.
#[cfg(test)]
pub(crate) fn test_app() -> (App, crossbeam_channel::Receiver<AppEvent>) {
    test_app_with_db(PathBuf::from("/nonexistent/dedcom.db"))
}

#[cfg(test)]
pub(crate) fn test_app_with_db(db_path: PathBuf) -> (App, crossbeam_channel::Receiver<AppEvent>) {
    let (tx, rx) = crate::tui::event::channel();
    let zfs = ZfsEnvironment {
        pools: Vec::new(),
        capabilities: crate::model::dataset::ZfsCapabilities::default(),
        warnings: Vec::new(),
    };
    let app = App::new(
        zfs,
        HostProfile::default(),
        db_path,
        tx,
        Vec::new(),
        false,
        RevalidationMode::default(),
        Vec::new(),
        true,
        crate::lock::Startup {
            lock: None,
            read_only: false,
            prompt: None,
        },
        false,
    );
    (app, rx)
}

/// How many events one interaction may deliver before a test gives up on it. Generous: an `Open`
/// installs a payload that fetches a group, a count and one dedup batch per panel, and each of
/// those is an event of its own. It is a runaway guard, not a timing assumption.
#[cfg(test)]
const PUMP_LIMIT: usize = 256;

/// Feeds the browsing actor's replies into the application until `done` holds.
///
/// This is how every test that used to call a synchronous store reader drives the real thing:
/// the request goes out through the production route, the actor answers on its own thread, and
/// `handle_event` installs the answer exactly as the main loop does.
///
/// Not a sleep, a retry or a poll. Every accepted request owes exactly one reply, so `recv` is a
/// wait for something that is coming; the timeout exists only so a lost reply fails the test
/// instead of hanging it, and the iteration cap only so a mis-written predicate does.
#[cfg(test)]
pub(crate) fn pump_until(
    app: &mut App,
    rx: &crossbeam_channel::Receiver<AppEvent>,
    what: &str,
    mut done: impl FnMut(&App) -> bool,
) {
    for _ in 0..PUMP_LIMIT {
        if done(app) {
            return;
        }
        let event = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .unwrap_or_else(|err| panic!("waiting for {what}: {err}"));
        app.handle_event(event);
    }
    panic!("{what} never settled within {PUMP_LIMIT} events");
}

/// Dispatches every reply already in the channel, without waiting for another.
///
/// For the tail of an interaction — the panel refreshes an `Open` fans out — where the test cares
/// that they were consumed, not that any particular one arrives.
#[cfg(test)]
pub(crate) fn drain(app: &mut App, rx: &crossbeam_channel::Receiver<AppEvent>) {
    for _ in 0..PUMP_LIMIT {
        match rx.try_recv() {
            Ok(event) => app.handle_event(event),
            Err(_) => return,
        }
    }
}

/// Opens `scan_id` the way production does — through the actor — and settles the reply.
///
/// Returns once the open is no longer in flight; whether it installed is the caller's assertion,
/// because a refused open is exactly what several tests are about.
#[cfg(test)]
pub(crate) fn open_and_settle(
    app: &mut App,
    rx: &crossbeam_channel::Receiver<AppEvent>,
    scan_id: i64,
    intent: OpenIntent,
) {
    app.open_via_actor(scan_id, intent);
    pump_until(app, rx, "the Open reply", |app| app.routes.open.is_none());
}

/// A plan of `count` deletions of independent twins, distinguishable by path. Module level because
/// the ActionReview screen's own render test plans the same batch. `None` for `count == 0`: a plan
/// with nothing in it is a shape `ActionPlan` refuses to hold.
#[cfg(test)]
pub(crate) fn test_plan(count: usize) -> Option<ActionPlan> {
    use crate::model::plan::{PlanGroupInput, PlanMemberEvidence, PlanObjectKey};
    use crate::model::reclaim::LinkCount;

    let key = |inode: u64| PlanObjectKey {
        device: 1,
        inode,
        size: 1024,
        mtime: 1_700_000_000,
        mtime_nsec: 0,
        ctime_sec: 1_700_000_001,
        ctime_nsec: 0,
        identity_version: 1,
    };
    let member = |path: PathBuf, inode: u64, intent| {
        PlanMemberEvidence::new(path, key(inode), LinkCount::Known(1), Some(intent))
            .expect("a well-formed fixture member")
    };
    let mut members = vec![member(
        PathBuf::from("/x/keeper.bin"),
        10,
        MarkIntent::Keeper,
    )];
    for index in 0..count {
        members.push(member(
            PathBuf::from(format!("/x/dup{index:02}.bin")),
            100 + index as u64,
            MarkIntent::Act(ActionKind::Delete),
        ));
    }
    ActionPlan::try_new(
        1,
        vec![PlanGroupInput {
            id: crate::model::plan::GroupId {
                scan_id: 1,
                rank: 0,
                generation: 1,
            },
            hash: "ab".repeat(32),
            members,
        }],
    )
    .ok()
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;

    #[test]
    fn the_first_signal_waits_for_a_background_move() {
        let (mut app, _rx) = test_app();
        app.commander.move_pending = 1;
        app.request_shutdown(false);
        assert!(
            !app.should_quit,
            "must wait for CommanderMoveDone so the Undo entry is written"
        );
        // The move landed and `apply_move_outcome` cleared the counter.
        app.commander.move_pending = 0;
        app.request_shutdown(false);
        assert!(app.should_quit, "nothing left in flight — leave");
    }

    #[test]
    fn the_first_signal_waits_for_a_background_purge() {
        let (mut app, _rx) = test_app();
        app.purge_pending = 1;
        app.request_shutdown(false);
        assert!(
            !app.should_quit,
            "must wait for the purge and its SessionDeleted"
        );
        app.purge_pending = 0;
        app.request_shutdown(false);
        assert!(app.should_quit);
    }

    #[test]
    fn handling_session_deleted_releases_the_wait() {
        // The real path: the event clears the counter, so the pending shutdown can proceed.
        let (mut app, _rx) = test_app();
        app.purge_pending = 1;
        app.request_shutdown(false);
        assert!(!app.should_quit);
        app.handle_event(AppEvent::SessionDeleted(Ok(1)));
        assert_eq!(app.purge_pending, 0, "the counter is released by the event");
    }

    /// A panicking purge must still report. `purge_pending` is released only by `SessionDeleted`,
    /// so without the event a shutdown waits for work that is already over.
    #[test]
    fn a_panicking_purge_still_reports_and_releases_the_wait() {
        let _lock = crate::panics::test_lock();
        let (mut app, rx) = test_app();
        app.purge_pending = 1;
        spawn_purge_job(app.events.clone(), || panic!("boom in the purge"));

        let event = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("SessionDeleted must arrive even when the purge panics");
        match &event {
            AppEvent::SessionDeleted(Err(err)) => assert!(
                err.contains("boom in the purge"),
                "the status must show what happened: {err}"
            ),
            _ => panic!("a panicking purge must report an error, not a success"),
        }
        app.handle_event(event);
        assert_eq!(app.purge_pending, 0, "the counter is released by the event");
        assert!(app.status.contains("boom in the purge"), "{}", app.status);
    }

    /// The shutdown that a panic starts has to finish by itself. The operator has already lost the
    /// screen; making them send a second signal because a worker died is the bug A-4 is about.
    #[test]
    fn a_panic_shutdown_ends_without_a_second_signal() {
        let _lock = crate::panics::test_lock();
        crate::panics::clear_tui_dead();
        let (mut app, _rx) = test_app();
        app.commander.move_pending = 1;
        // The hook fired while the move was still running; this is what the main loop then does.
        crate::panics::mark_tui_dead();
        app.request_shutdown(false);
        assert!(!app.should_quit, "the move still has to land");

        let outcome = crate::tui::commander::move_batch::MoveBatchOutcome {
            error: Some("the move worker panicked: boom".to_string()),
            ..Default::default()
        };
        app.handle_event(AppEvent::CommanderMoveDone(Box::new(outcome)));
        assert_eq!(app.commander.move_pending, 0, "the event released the wait");
        assert!(app.should_quit, "no second signal should be needed");
        crate::panics::clear_tui_dead();
    }

    #[test]
    fn a_second_signal_stops_waiting_for_either_kind_of_work() {
        let (mut app, _rx) = test_app();
        app.commander.move_pending = 1;
        app.request_shutdown(true);
        assert!(
            app.should_quit,
            "a forced shutdown does not wait for a move"
        );

        let (mut app, _rx) = test_app();
        app.purge_pending = 1;
        app.request_shutdown(true);
        assert!(
            app.should_quit,
            "a forced shutdown does not wait for a purge"
        );
    }

    #[test]
    fn with_nothing_in_flight_the_first_signal_leaves_at_once() {
        let (mut app, _rx) = test_app();
        app.request_shutdown(false);
        assert!(app.should_quit);
    }
}

/// Esc during a batch stops it at an action boundary, so most of the plan may never be attempted.
/// Treating that as a completed run threw the marks for the rest of the work away.
#[cfg(test)]
mod cancel_tests {
    use super::*;
    use crate::model::action::ActionOutcome;
    use crate::tui::commander::state::Mark;
    use crossbeam_channel::Receiver;

    /// An app over a real DB seeded with keeper `/x/a` and targets `/x/b`, `/x/c`. `commander`
    /// picks which origin owns the marks — the two UIs keep their scan id in different fields,
    /// and both persist through the same `file_mark` table.
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("dedcom_marks_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn app_over_seeded_db(tag: &str, commander: bool) -> (PathBuf, App, Receiver<AppEvent>, i64) {
        let dir = temp_dir(tag);
        let db_path = dir.join("dedcom.db");
        let scan_id = crate::state::store::seed_marked_group(&db_path);

        let (mut app, rx) = test_app_with_db(db_path);
        // Opened the way the operator opened it: one actor payload installs the scan both
        // windows then plan and settle against. Setting the id by hand would leave the app in a
        // state no production route can reach — and the settlement below travels through the
        // actor, which only exists once something opened it.
        let intent = if commander {
            OpenIntent::Commander
        } else {
            OpenIntent::Wizard
        };
        open_and_settle(&mut app, &rx, scan_id, intent);
        assert_eq!(
            app.current_scan_id,
            Some(scan_id),
            "the fixture's scan must open: {}",
            app.status
        );
        if commander {
            app.commander.return_to_commander = true;
        }
        // The open fans out panel and group reads; none of them is what these tests observe.
        drain(&mut app, &rx);
        (dir, app, rx, scan_id)
    }

    /// The batch reports, and the settlement it owes travels to its acknowledgement.
    ///
    /// This is the production route in full: `ApplyFinished` records what is owed and sends
    /// `ReconcileAfterBatch` through the one store owner; the actor writes and answers
    /// `ReconcileAck`; `handle_event` settles the durable and the RAM halves together. Nothing
    /// here waits for a write to have "probably" happened — it waits for the acknowledgement.
    fn finish_and_settle(app: &mut App, rx: &Receiver<AppEvent>, event: AppEvent) {
        app.handle_event(event);
        pump_until(app, rx, "the reconcile acknowledgement", |app| {
            app.routes.reconcile.is_none()
        });
    }

    fn plan_targets(db_path: &Path, scan_id: i64) -> Vec<PathBuf> {
        crate::state::store::marked_action_paths(db_path, scan_id)
    }

    fn finished(outcomes: Vec<ActionOutcome>, planned: usize, cancelled: bool) -> AppEvent {
        AppEvent::ApplyFinished(Box::new(ApplyOutcome::Finished(BatchResult {
            outcomes,
            planned,
            cancelled,
            ..Default::default()
        })))
    }

    /// The marks are in SQLite too, and the wizard rebuilds its plan straight from there. A
    /// cancelled batch must leave exactly the untouched remainder behind — not the whole plan
    /// (the applied action would run again) and not an empty one (the work would be lost).
    #[test]
    fn a_cancelled_batch_settles_the_persisted_marks_of_the_wizard() {
        let _role = crate::state::store::role_guard();
        let (dir, mut app, rx, scan_id) = app_over_seeded_db("wizard_cancel", false);
        let db_path = app.db_path.clone();

        finish_and_settle(
            &mut app,
            &rx,
            finished(vec![applied(Path::new("/x/b"))], 2, true),
        );

        assert!(
            !app.marks_unsettled,
            "the acknowledgement arrived: {}",
            app.status
        );
        assert_eq!(
            plan_targets(&db_path, scan_id),
            vec![PathBuf::from("/x/c")],
            "the plan on disk holds only what the batch never reached"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Same table, other origin: the commander keeps its scan id in `dedup_scan_id`, and its
    /// batches were leaving the persisted marks untouched just as the wizard's did.
    #[test]
    fn a_cancelled_batch_settles_the_persisted_marks_of_the_commander() {
        let _role = crate::state::store::role_guard();
        let (dir, mut app, rx, scan_id) = app_over_seeded_db("commander_cancel", true);
        let db_path = app.db_path.clone();
        app.commander.panels[0]
            .marks
            .insert(PathBuf::from("/x/b"), Mark::Delete);
        app.commander.panels[0]
            .marks
            .insert(PathBuf::from("/x/c"), Mark::Delete);

        finish_and_settle(
            &mut app,
            &rx,
            finished(vec![applied(Path::new("/x/b"))], 2, true),
        );

        assert!(!app.marks_unsettled, "the acknowledgement arrived");
        assert_eq!(
            plan_targets(&db_path, scan_id),
            vec![PathBuf::from("/x/c")],
            "the plan on disk holds only what the batch never reached"
        );
        let marks = &app.commander.panels[0].marks;
        assert!(!marks.contains_key(&PathBuf::from("/x/b")));
        assert!(marks.contains_key(&PathBuf::from("/x/c")), "RAM agrees");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A batch that ran to the end spends the whole plan: nothing may be rebuilt from the marks
    /// it left behind, or a restart would apply the same actions again.
    #[test]
    fn a_finished_batch_leaves_no_persisted_plan_behind() {
        let _role = crate::state::store::role_guard();
        let (dir, mut app, rx, scan_id) = app_over_seeded_db("wizard_finished", false);
        let db_path = app.db_path.clone();

        finish_and_settle(
            &mut app,
            &rx,
            finished(
                vec![applied(Path::new("/x/b")), applied(Path::new("/x/c"))],
                2,
                false,
            ),
        );

        assert!(
            plan_targets(&db_path, scan_id).is_empty(),
            "an applied plan must not survive in the DB"
        );
        assert!(app.status.is_empty(), "no warning when the DB was settled");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An aborted result: the second preflight refused after the safety snapshots existed, so the
    /// batch reached no action at all.
    fn refused(snapshots: Vec<String>, planned: usize) -> AppEvent {
        AppEvent::ApplyFinished(Box::new(ApplyOutcome::Finished(BatchResult {
            outcomes: Vec::new(),
            snapshots,
            planned,
            cancelled: false,
            aborted: Some("a covered pathname moved after the snapshots".to_string()),
            ..Default::default()
        })))
    }

    /// R2D-C5-2a, blocker B: nothing ran, so nothing may be settled. Reconciling here deleted the
    /// whole plan from the database over a batch that had not touched a single file.
    #[test]
    fn an_aborted_batch_keeps_every_durable_mark() {
        let _role = crate::state::store::role_guard();
        let (dir, mut app, _rx, scan_id) = app_over_seeded_db("wizard_aborted", false);
        let db_path = app.db_path.clone();

        app.handle_event(refused(vec!["tank/ds_a@dedcom-ts".to_string()], 2));

        assert_eq!(
            plan_targets(&db_path, scan_id),
            vec![PathBuf::from("/x/b"), PathBuf::from("/x/c")],
            "no action ran, so the plan on disk is untouched"
        );
        assert!(
            !app.marks_unsettled,
            "the database refused nothing — no write should have been attempted"
        );
        assert!(matches!(app.screen, Screen::Summary));
        let summary = app.summary_result.as_ref().expect("a result is shown");
        assert_eq!(summary.snapshots.len(), 1, "the snapshot is still reported");
        assert!(summary.aborted.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A snapshot that fails after an earlier one succeeded aborts the same way, and must be
    /// treated the same way.
    #[test]
    fn a_partial_snapshot_abort_keeps_the_commanders_marks() {
        let _role = crate::state::store::role_guard();
        let (dir, mut app, _rx, scan_id) = app_over_seeded_db("commander_aborted", true);
        let db_path = app.db_path.clone();
        for path in ["/x/b", "/x/c"] {
            app.commander.panels[0]
                .marks
                .insert(PathBuf::from(path), Mark::Delete);
        }

        app.handle_event(refused(vec!["tank/ds_a@dedcom-ts".to_string()], 2));

        assert_eq!(
            plan_targets(&db_path, scan_id),
            vec![PathBuf::from("/x/b"), PathBuf::from("/x/c")],
            "the durable plan survives"
        );
        let marks = &app.commander.panels[0].marks;
        assert!(
            marks.contains_key(&PathBuf::from("/x/b"))
                && marks.contains_key(&PathBuf::from("/x/c")),
            "and so do the panel's own marks"
        );
        assert!(
            app.commander.status.contains("refused"),
            "the commander is told why: {}",
            app.commander.status
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Leaving that summary must never read as a completed run.
    #[test]
    fn leaving_the_summary_of_a_refused_batch_says_the_marks_are_kept() {
        let (mut app, _rx) = test_app();
        app.show_disclaimer = false;
        app.mode = AppMode::Wizard;
        app.handle_event(refused(vec!["tank/ds_a@dedcom-ts".to_string()], 2));
        assert!(matches!(app.screen, Screen::Summary));

        app.handle_event(AppEvent::Key(KeyEvent::from(KeyCode::Esc)));

        assert!(
            app.status.contains("refused") && app.status.contains("marks are kept"),
            "the operator must read what happened: {}",
            app.status
        );
        assert!(
            !app.status.contains("Actions applied"),
            "nothing was applied: {}",
            app.status
        );
    }

    /// The DB is the durable half. If it cannot be updated we must not imply it was: the marks in
    /// RAM stay as they are and the operator is told the plan on disk is still the old one.
    #[test]
    fn an_unsettled_db_warns_and_keeps_the_marks() {
        let _role = crate::state::store::role_guard();
        let dir = temp_dir("unsettled");
        // The DB cannot be opened: its parent is a regular file, which is ENOTDIR for anyone,
        // root included — the same effect on the marks as a refused write.
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"x").unwrap();
        let target = PathBuf::from("/x/b");
        let (mut app, _rx) = test_app_with_db(blocker.join("dedcom.db"));
        app.commander.dedup_scan_id = Some(1);
        app.commander.return_to_commander = true;
        app.commander.panels[0]
            .marks
            .insert(target.clone(), Mark::Delete);

        app.handle_event(finished(vec![applied(&target)], 1, false));

        assert!(
            app.commander.panels[0].marks.contains_key(&target),
            "the marks stay while the DB still holds them"
        );
        assert!(
            app.status.contains("WARNING"),
            "the operator must be told: {}",
            app.status
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The wizard leaves the Summary through `Esc`, and that handler used to overwrite the
    /// warning with "Actions applied…" — a false success over a plan that still lists what was
    /// just applied. The screen the operator lands on is where the next batch starts.
    #[test]
    fn the_wizard_carries_the_unsettled_warning_out_of_the_summary() {
        let _role = crate::state::store::role_guard();
        let dir = temp_dir("unsettled_wizard");
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"x").unwrap();
        let (mut app, _rx) = test_app_with_db(blocker.join("dedcom.db"));
        app.show_disclaimer = false;
        app.mode = AppMode::Wizard;
        app.current_scan_id = Some(1);

        app.handle_event(finished(vec![applied(Path::new("/x/b"))], 1, false));
        assert!(app.marks_unsettled, "the DB refused, so nothing is settled");
        assert!(matches!(app.screen, Screen::Summary));

        app.handle_event(AppEvent::Key(KeyEvent::from(KeyCode::Esc)));
        assert!(matches!(app.screen, Screen::ScanConfig));
        assert!(
            app.marks_unsettled,
            "leaving the screen does not settle anything"
        );
        assert!(
            app.status.contains("WARNING"),
            "the warning must survive the exit: {}",
            app.status
        );
        assert!(
            !app.status.contains("Actions applied"),
            "and must not be replaced by a success line: {}",
            app.status
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn applied(target: &Path) -> ActionOutcome {
        ActionOutcome {
            kind: ActionKind::Delete,
            target: target.to_path_buf(),
            quarantine: None,
            result: Ok(()),
        }
    }

    /// A commander over the seeded scan whose panel holds the RAM half of the same marks the
    /// fixture persisted: the keeper and both targets.
    fn marked_commander(tag: &str) -> (PathBuf, App, Receiver<AppEvent>, i64) {
        let (dir, mut app, rx, scan_id) = app_over_seeded_db(tag, true);
        let marks = &mut app.commander.panels[0].marks;
        marks.insert(PathBuf::from("/x/a"), Mark::Keeper);
        marks.insert(PathBuf::from("/x/b"), Mark::Delete);
        marks.insert(PathBuf::from("/x/c"), Mark::Delete);
        (dir, app, rx, scan_id)
    }

    #[test]
    fn a_cancelled_batch_keeps_the_marks_it_never_reached() {
        let _role = crate::state::store::role_guard();
        let (dir, mut app, rx, scan_id) = marked_commander("commander_cancel_ram");
        let db_path = app.db_path.clone();
        let done = PathBuf::from("/x/b");
        let never_reached = PathBuf::from("/x/c");

        finish_and_settle(&mut app, &rx, finished(vec![applied(&done)], 2, true));

        let marks = &app.commander.panels[0].marks;
        assert!(
            !marks.contains_key(&done),
            "the action that ran must lose its mark"
        );
        assert!(
            marks.contains_key(&never_reached),
            "the action that was never attempted must keep its mark"
        );
        assert_eq!(
            plan_targets(&db_path, scan_id),
            vec![never_reached],
            "and the durable half agrees with the screen"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_batch_that_ran_to_the_end_still_clears_the_marks() {
        let _role = crate::state::store::role_guard();
        let (dir, mut app, rx, scan_id) = marked_commander("commander_finished_ram");
        let db_path = app.db_path.clone();
        let first = PathBuf::from("/x/b");
        let second = PathBuf::from("/x/c");

        finish_and_settle(
            &mut app,
            &rx,
            finished(vec![applied(&first), applied(&second)], 2, false),
        );

        assert!(
            app.commander.panels[0].marks.is_empty(),
            "a finished batch clears everything, keepers included"
        );
        assert!(
            plan_targets(&db_path, scan_id).is_empty(),
            "and the durable plan is spent with it"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leaving_the_summary_of_a_cancelled_batch_does_not_say_applied() {
        let (mut app, _rx) = test_app();
        app.show_disclaimer = false;
        app.mode = AppMode::Wizard;
        app.screen = Screen::Summary;
        app.summary_result = Some(BatchResult {
            planned: 2,
            cancelled: true,
            ..Default::default()
        });

        app.handle_event(AppEvent::Key(KeyEvent::from(KeyCode::Esc)));
        assert!(
            app.status.contains("cancelled"),
            "the operator must not read a stopped batch as a finished one: {}",
            app.status
        );
    }
}

/// R2D-C5-2: the classic window's half of the switch — the review is built by the one authority
/// and refuses out loud, and a mark the database would not take does not stay on screen.
#[cfg(test)]
mod classic_switch_tests {
    use super::*;
    use crate::testfixtures::PlanScenario;

    /// The classic browser sitting on a real scenario's group, marks and all — reached the way
    /// the operator reaches it. One actor payload installs the summaries and opens the first
    /// group, so every row on screen came from the authority rather than from a literal built
    /// beside it.
    fn browsing(tag: &str) -> (PlanScenario, App, crossbeam_channel::Receiver<AppEvent>) {
        let scenario = PlanScenario::new(tag);
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), twin.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &twin, false, Some(ActionKind::Delete));
        drop(store);

        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        app.show_disclaimer = false;
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Wizard);
        pump_until(&mut app, &rx, "the first group to open", |app| {
            app.browser.open_group.is_some()
        });
        assert_eq!(app.mode, AppMode::Wizard);
        assert_eq!(app.screen, Screen::Browser);
        let files = &app.browser.open_group.as_ref().unwrap().files;
        assert_eq!(files.len(), 2, "the scenario's one group, both members");
        assert_eq!(files[1].path, twin, "the cursor lands on the marked twin");
        app.browser.file_state.select(Some(1));
        drain(&mut app, &rx);
        (scenario, app, rx)
    }

    fn press(app: &mut App, code: KeyCode) {
        app.handle_event(AppEvent::Key(KeyEvent::from(code)));
    }

    /// `open_review` used to swallow a store failure and print «No marked actions», which tells
    /// the operator their marking work is gone when the truth is that nothing could be read.
    ///
    /// Since R4B-2c the plan is built by the actor, so the refusal arrives as an event — and the
    /// checkpoint under a live view is not merely unreadable, it has been REPLACED. The door
    /// notices, the browsing is uninstalled, and the operator is told to reopen. What may never
    /// happen is any of the quiet outcomes: a review over an empty plan, «No marked actions», or
    /// a screen that simply does nothing.
    #[test]
    fn an_unreadable_store_refuses_the_review_out_loud() {
        let _role = crate::state::store::role_guard();
        let (scenario, mut app, rx) = browsing("classic_store_error");
        // The file the view was opened over is replaced by one nothing can open.
        std::fs::remove_file(&scenario.db_path).unwrap();
        std::fs::create_dir(&scenario.db_path).unwrap();

        press(&mut app, KeyCode::Char('r'));
        pump_until(&mut app, &rx, "the plan request to be answered", |app| {
            app.routes.plan.is_none()
        });

        assert_eq!(app.screen, Screen::Browser, "no review may open");
        assert!(app.review.plan.is_none(), "and nothing is left pending");
        assert!(app.apply.is_none());
        assert!(
            app.status.contains("could not be read") && app.status.contains("dedcom.db"),
            "the operator is told what happened: {}",
            app.status
        );
        assert!(
            !app.status.contains("No marked actions"),
            "a store failure is not an absence of marks: {}",
            app.status
        );
        assert!(
            !app.status.contains("Building the plan"),
            "and the in-flight line does not survive as the answer: {}",
            app.status
        );
    }

    /// Makes the next durable mark on `path` refuse for a named, typed reason: the pathname
    /// leaves the manifest under the open view. `NotInManifest` is precisely that case, and it
    /// travels back through the actor's `MarkAck` like any other refusal.
    fn drop_from_manifest(scenario: &PlanScenario, path: &Path) {
        let conn = rusqlite::Connection::open(&scenario.db_path).expect("the scenario database");
        let removed = conn
            .execute(
                "DELETE FROM file WHERE path = ?1",
                rusqlite::params![path.to_string_lossy()],
            )
            .expect("the manifest row leaves");
        assert_eq!(removed, 1, "the fixture must remove exactly one row");
    }

    fn actions_on_screen(app: &App) -> Vec<Option<ActionKind>> {
        app.browser
            .open_group
            .as_ref()
            .expect("a group is open")
            .files
            .iter()
            .map(|file| file.action)
            .collect()
    }

    /// A mark the database refuses must not stay on screen: the window and the DB have to keep
    /// saying the same thing, because the plan is built from the DB.
    ///
    /// The write goes to the actor and the refusal comes back as `MarkAck`, so the optimistic
    /// row on screen lives exactly as long as the round trip — and is then put back the way the
    /// database still holds it.
    #[test]
    fn a_refused_mark_does_not_stay_in_the_window() {
        let _role = crate::state::store::role_guard();
        let (scenario, mut app, rx) = browsing("classic_mark_refused");
        let before = actions_on_screen(&app);
        let cursor = app.browser.open_group.as_ref().unwrap().files[1]
            .path
            .clone();
        drop_from_manifest(&scenario, &cursor);

        press(&mut app, KeyCode::Char('h'));
        pump_until(&mut app, &rx, "the mark acknowledgement", |app| {
            app.pending_marks.is_empty()
        });

        assert_eq!(
            actions_on_screen(&app),
            before,
            "the window shows what the database still holds"
        );
        assert!(
            app.status.contains("not saved"),
            "and says the write was refused: {}",
            app.status
        );
        assert!(
            !app.status.contains("browsing is not available"),
            "a refused write is not a missing browsing surface: {}",
            app.status
        );
    }

    /// Clearing a mark is the same durable write, and it fails closed the same way.
    #[test]
    fn a_refused_unmark_does_not_stay_in_the_window_either() {
        let _role = crate::state::store::role_guard();
        let (scenario, mut app, rx) = browsing("classic_unmark_refused");
        let cursor = app.browser.open_group.as_ref().unwrap().files[1]
            .path
            .clone();
        drop_from_manifest(&scenario, &cursor);

        press(&mut app, KeyCode::Char(' '));
        pump_until(&mut app, &rx, "the mark acknowledgement", |app| {
            app.pending_marks.is_empty()
        });

        let still_marked = actions_on_screen(&app).contains(&Some(ActionKind::Delete));
        assert!(
            still_marked,
            "the DELETE the database still holds must stay on screen"
        );
        assert!(app.status.contains("not saved"), "{}", app.status);
        assert!(
            !app.status.contains("browsing is not available"),
            "{}",
            app.status
        );
    }
}

/// R4B-2c: the application's half of the one browsing route. The store and the actor have their
/// own suites; what only exists here is the wiring the cutover added — one activation per
/// installed open, the class A/B rules, the marks gate, and the staged shutdown.
#[cfg(test)]
mod actor_route_tests {
    use super::*;
    use crate::testfixtures::PlanScenario;
    use crossbeam_channel::Receiver;

    /// A published scenario of one group over three real files, and an app over its database.
    fn opened(tag: &str) -> (PlanScenario, App, Receiver<AppEvent>, i64) {
        let scenario = PlanScenario::new(tag);
        let keeper = scenario.file("keeper.bin");
        let first = scenario.file("dup1.bin");
        let second = scenario.file("dup2.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper, first, second]);
        drop(store);

        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        app.show_disclaimer = false;
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Wizard);
        assert_eq!(app.current_scan_id, Some(scan_id), "{}", app.status);
        pump_until(&mut app, &rx, "the first group", |app| {
            app.browser.open_group.is_some()
        });
        drain(&mut app, &rx);
        (scenario, app, rx, scan_id)
    }

    /// Every route settled: nothing is in flight, so what the assertions read is final.
    fn quiet(app: &App) -> bool {
        app.routes.open.is_none()
            && app.routes.groups.is_empty()
            && app.routes.counts.is_empty()
            && app.routes.infos.is_empty()
            && app.routes.dirs_at.is_empty()
            && app.routes.dir_opens.is_empty()
            && app.routes.panels.is_empty()
            && app.routes.marked.is_none()
            && app.routes.latest.is_none()
            && app.routes.covering.is_empty()
            && app.routes.plan.is_none()
            && app.routes.reconcile.is_none()
    }

    /// Matrix 6 — the scripted interaction, from the application's side: ONE activation is
    /// installed and ONE actor serves the whole thing. Twenty cursor moves cost nothing at all,
    /// and re-opening the same group does not re-open the scan.
    ///
    /// The store's half of the same claim — one browsing store, one full validation for twenty
    /// legacy reads — is `state::browse::tests::one_browsing_interaction_validates_once`; the
    /// probe table beside it prices every door operation. This is the half that only exists
    /// after the cutover: that the UI asks once and rides one connection.
    #[test]
    fn one_scripted_interaction_installs_one_activation_and_keeps_one_actor() {
        let _role = crate::state::store::role_guard();
        let (_scenario, mut app, rx, _scan_id) = opened("scripted");
        let actor = app.browse.live_actor().expect("the open spawned one actor");
        assert_eq!(
            app.installed_act,
            Activation(1),
            "the first successful open is the first activation"
        );

        // Twenty cursor moves over the group list: pure UI, not one request.
        let before_moves = app.browse.requests_issued();
        for _ in 0..20 {
            app.handle_event(AppEvent::Key(KeyEvent::from(KeyCode::Down)));
            app.handle_event(AppEvent::Key(KeyEvent::from(KeyCode::Up)));
        }
        assert_eq!(
            app.browse.requests_issued(),
            before_moves,
            "a cursor move is not a question for the database"
        );

        // Three group opens over the same identity.
        for _ in 0..3 {
            app.open_selected_group();
            pump_until(&mut app, &rx, "the group page", quiet);
        }

        // Three acknowledged marks through the production route.
        for action in [Some(ActionKind::Delete), None, Some(ActionKind::Hardlink)] {
            app.browser.file_state.select(Some(1));
            app.browser_mark(action);
            pump_until(&mut app, &rx, "the mark acknowledgement", |app| {
                app.pending_marks.is_empty()
            });
            drain(&mut app, &rx);
        }

        // And the plan, built by the one authority.
        app.browser.file_state.select(Some(0));
        app.browser_set_keeper();
        pump_until(&mut app, &rx, "the keeper acknowledgement", |app| {
            app.pending_marks.is_empty()
        });
        drain(&mut app, &rx);
        app.open_review();
        pump_until(&mut app, &rx, "the plan", |app| app.routes.plan.is_none());
        drain(&mut app, &rx);

        assert_eq!(
            app.installed_act,
            Activation(1),
            "nothing in the interaction re-opened the scan"
        );
        assert_eq!(
            app.browse.live_actor(),
            Some(actor),
            "and one actor served all of it"
        );
        assert!(
            quiet(&app),
            "every request the interaction sent was answered"
        );
    }

    /// R4B-2c1 blocker A: two opens cannot overlap.
    ///
    /// Both would propose an activation derived from the same installed one and share the single
    /// `routes.open` slot. The second would overwrite the first, its reply would be dropped as
    /// unrouted — and the actor may already have installed that first candidate. A class-A
    /// refusal of the second then leaves the UI on its old activation while the actor serves the
    /// one the UI threw away, and every later request is stale.
    #[test]
    fn a_second_open_cannot_overtake_the_one_in_flight() {
        let _role = crate::state::store::role_guard();
        let (_scenario, mut app, rx, scan_id) = opened("overlapping_opens");
        let installed = app.installed_act;

        let before = app.browse.requests_issued();
        app.open_via_actor(scan_id, OpenIntent::Wizard);
        let pending = app
            .routes
            .open
            .as_ref()
            .map(|route| (route.req, route.act, route.scan_id))
            .expect("one open in flight");
        assert_eq!(pending.1, Activation(installed.0 + 1));

        // Leaning on Enter: the same scan, already being opened. Idempotent.
        app.open_via_actor(scan_id, OpenIntent::Wizard);
        app.open_via_actor(scan_id, OpenIntent::Commander);
        // And a different scan — refused out loud, and one the actor would refuse class A.
        app.open_via_actor(999_999, OpenIntent::Wizard);
        assert!(
            app.status.contains("Still opening"),
            "the operator is told why nothing happened: {}",
            app.status
        );

        assert_eq!(
            app.browse.requests_issued(),
            before + 1,
            "exactly one Open was enqueued"
        );
        assert_eq!(
            app.routes
                .open
                .as_ref()
                .map(|route| (route.req, route.act, route.scan_id)),
            Some(pending),
            "the pending request, its activation and its scan are the only ones"
        );

        pump_until(&mut app, &rx, "the open reply", |app| {
            app.routes.open.is_none()
        });
        drain(&mut app, &rx);
        assert_eq!(
            (app.installed_act, app.current_scan_id),
            (pending.1, Some(scan_id)),
            "the UI installed the activation it asked for, over the scan it asked for"
        );

        // And the actor agrees: a later request is answered, not refused as stale.
        app.browser.marked_count = None;
        app.refresh_marked_count();
        pump_until(&mut app, &rx, "the marked count", |app| {
            app.routes.marked.is_none()
        });
        assert!(
            app.browser.marked_count.is_some(),
            "a request after the open must not be stale: {}",
            app.status
        );
    }

    /// The other half of the same invariant: an open whose actor dies before answering must
    /// release its route, or «one open at a time» becomes «no open ever again».
    #[test]
    fn an_open_whose_actor_retires_releases_its_route() {
        let _role = crate::state::store::role_guard();
        let (_scenario, mut app, rx, scan_id) = opened("open_route_released");

        app.open_via_actor(scan_id, OpenIntent::Wizard);
        assert!(app.routes.open.is_some(), "one open in flight");
        app.request_shutdown(false);
        pump_until(&mut app, &rx, "the shutdown to finish", |app| {
            app.should_quit
        });

        assert!(
            app.routes.open.is_none(),
            "the retired actor's open must not hold the slot forever"
        );
        assert!(
            app.opening_started.is_none(),
            "and the «Opening results…» animation stops with it"
        );
    }

    /// A durable Commander mark the actor never acknowledged, because browsing stopped first.
    ///
    /// The retirement here is the production one: the ticket is taken out of the real registry
    /// exactly as `retire_actor` takes it, and handed to the production settlement. What an
    /// actor's death itself looks like belongs to the browsing suite; what only exists here is
    /// what the window does with a write that is never going to be answered — it goes back to
    /// what the database last said, it stops pointing at an acknowledgement that cannot arrive,
    /// and neither the retirement nor the actor's late reply may render the success prefix.
    #[test]
    fn a_retired_mark_ticket_restores_the_row_and_never_says_saved() {
        use crate::tui::commander::state::{EntryKind, Mark, PanelEntry};

        let _role = crate::state::store::role_guard();
        let scenario = PlanScenario::new("commander_mark_retired");
        let keeper = scenario.file("keeper.bin");
        let twin = scenario.file("twin.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper, twin.clone()]);
        drop(store);

        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        app.show_disclaimer = false;
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        assert_eq!(
            app.commander.dedup_scan_id,
            Some(scan_id),
            "the fixture's scan must open: {}",
            app.commander.status
        );
        drain(&mut app, &rx);

        let panel = app.commander.active_panel_mut();
        panel.entries = vec![PanelEntry {
            path: twin.clone(),
            name: "twin.bin".to_string(),
            kind: EntryKind::File,
            size: 0,
            mtime: 0,
            device: 0,
            inode: 0,
        }];
        panel.list.select(Some(0));

        // F7 is the keeper key, pressed through the production dispatcher.
        app.handle_event(AppEvent::Key(KeyEvent::from(KeyCode::F(7))));
        assert_eq!(app.pending_marks.len(), 1, "one durable write is in flight");
        assert!(
            app.commander.status.starts_with("Saving mark"),
            "and the operator was told to wait for it: {}",
            app.commander.status
        );
        assert_eq!(
            app.commander.panels[app.commander.active].marks.get(&twin),
            Some(&Mark::Keeper),
            "with an optimistic row on screen"
        );

        // Browsing stops while that write is still unacknowledged.
        let drained = app
            .browse
            .live()
            .expect("the actor is live")
            .drain_tickets();
        assert_eq!(
            drained.tickets.len(),
            1,
            "the unacknowledged ticket is exactly what retirement has to settle"
        );
        app.settle_retired(drained, &CloseCause::Requested);

        assert!(app.pending_marks.is_empty(), "nothing is left in flight");
        assert!(
            !app.commander.panels[app.commander.active]
                .marks
                .contains_key(&twin),
            "the optimistic row is gone — nothing ever said the database holds it"
        );
        assert!(
            !app.commander.status.starts_with("Mark saved"),
            "a write nobody answered is not a saved mark: {}",
            app.commander.status
        );
        assert_eq!(
            app.commander.status, MARKS_STRANDED,
            "and the wait ends in words instead of resting on «Saving mark»"
        );
        assert!(
            matches!(app.marks_gate, MarksGate::Blocked { .. }),
            "with planning blocked until a fresh open"
        );

        // The reply lands after its ticket was retired. It may settle the picture from the
        // after-image, but it has no origin left to correlate and cannot borrow the success line.
        drain(&mut app, &rx);
        assert!(
            !app.commander.status.starts_with("Mark saved"),
            "a late reply may not resurrect the acknowledgement: {}",
            app.commander.status
        );
    }

    /// Matrix 5 and 11 — class A preserves, class B uninstalls, and only a fresh open recovers.
    #[test]
    fn a_repeat_open_preserves_and_a_replaced_checkpoint_uninstalls_until_a_fresh_open() {
        let _role = crate::state::store::role_guard();
        let (scenario, mut app, rx, scan_id) = opened("class_ab");
        // Identity and digest are what a repeat open must reproduce; `GroupSummary` itself is a
        // display record with no equality of its own.
        let groups: Vec<(GroupId, String)> = app
            .browser
            .group_summaries
            .iter()
            .map(|(id, summary)| (*id, summary.hash.clone()))
            .collect();
        assert!(!groups.is_empty(), "the fixture published a group");

        // Class A: opening the same scan again installs a NEW activation over the same data,
        // and the previous one is superseded rather than mixed with.
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Wizard);
        drain(&mut app, &rx);
        assert_eq!(app.installed_act, Activation(2));
        assert_eq!(app.current_scan_id, Some(scan_id));
        let reopened: Vec<(GroupId, String)> = app
            .browser
            .group_summaries
            .iter()
            .map(|(id, summary)| (*id, summary.hash.clone()))
            .collect();
        assert_eq!(
            reopened, groups,
            "the same authority answers the same identities"
        );

        // Class B: the file the view was opened over is replaced. The next touch is refused
        // typed, and everything that describes the scan is uninstalled.
        std::fs::remove_file(&scenario.db_path).unwrap();
        std::fs::create_dir(&scenario.db_path).unwrap();
        app.refresh_marked_count();
        pump_until(&mut app, &rx, "the typed refusal", |app| {
            app.current_scan_id.is_none()
        });

        assert!(app.browser.group_summaries.is_empty());
        assert!(
            app.browser.marked_count.is_none(),
            "no trusted answer stays"
        );
        assert!(app.commander.dedup_scan_id.is_none());
        assert!(
            app.status.contains(REOPEN_REQUIRED),
            "the operator is told to reopen: {}",
            app.status
        );
        assert!(
            matches!(app.marks_gate, MarksGate::Blocked { .. }),
            "and nothing may be marked or planned meanwhile"
        );
        assert!(
            app.plan_gate_refusal().is_some(),
            "the plan gate is closed too"
        );

        // Only a fresh Open recovers — and over a checkpoint nobody can open, it does not.
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Wizard);
        assert!(
            app.current_scan_id.is_none(),
            "a replaced checkpoint does not come back by itself"
        );
    }

    /// Matrix 8 — a plan may not overtake a mark the database has not acknowledged.
    #[test]
    fn a_plan_cannot_overtake_a_pending_mark() {
        let _role = crate::state::store::role_guard();
        let (_scenario, mut app, rx, _scan_id) = opened("gate_overtake");

        app.browser.file_state.select(Some(1));
        app.browser_mark(Some(ActionKind::Delete));
        assert!(
            !app.pending_marks.is_empty(),
            "the mark is in flight, not settled"
        );

        let before = app.browse.requests_issued();
        app.open_review();
        assert_eq!(
            app.browse.requests_issued(),
            before,
            "no plan request may be enqueued behind an unacknowledged mark"
        );
        assert!(app.routes.plan.is_none());
        assert!(
            app.status.contains("the plan waits"),
            "and the operator is told why: {}",
            app.status
        );

        // Once the acknowledgement lands, the same keystroke works.
        pump_until(&mut app, &rx, "the mark acknowledgement", |app| {
            app.pending_marks.is_empty()
        });
        drain(&mut app, &rx);
        app.open_review();
        pump_until(&mut app, &rx, "the plan", |app| app.routes.plan.is_none());
        assert!(
            app.review.plan.is_some() || !app.status.is_empty(),
            "the plan request was made and answered"
        );
    }

    /// Matrix 13 — the staged shutdown, in order: the batch's settlement is sent and
    /// acknowledged BEFORE the actor is asked to close, and the actor is joined exactly once.
    #[test]
    fn the_shutdown_settles_the_owed_batch_before_it_closes_the_actor() {
        let _role = crate::state::store::role_guard();
        let dir = std::env::temp_dir().join(format!(
            "dedcom_shutdown_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("dedcom.db");
        let scan_id = crate::state::store::seed_marked_group(&db_path);
        let (mut app, rx) = test_app_with_db(db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Wizard);
        assert_eq!(app.current_scan_id, Some(scan_id));
        drain(&mut app, &rx);

        // A batch reports; its settlement is owed and in flight.
        app.handle_event(AppEvent::ApplyFinished(Box::new(ApplyOutcome::Finished(
            BatchResult {
                outcomes: vec![crate::model::action::ActionOutcome {
                    kind: ActionKind::Delete,
                    target: PathBuf::from("/x/b"),
                    quarantine: None,
                    result: Ok(()),
                }],
                planned: 2,
                cancelled: true,
                ..Default::default()
            },
        ))));
        assert!(
            app.routes.reconcile.is_some(),
            "the settlement is in flight"
        );

        app.request_shutdown(false);
        assert!(
            matches!(app.shutdown, ShutdownStage::Settling { .. }),
            "the exit waits for the settlement it owes: {:?}",
            app.shutdown
        );
        assert!(!app.should_quit, "and does not leave meanwhile");

        // Order: the settlement is acknowledged first, and only then is the actor closed.
        pump_until(&mut app, &rx, "the settlement acknowledgement", |app| {
            app.routes.reconcile.is_none()
        });
        assert!(
            !app.marks_unsettled,
            "the acknowledgement settles the marks: {}",
            app.status
        );
        assert!(
            matches!(app.shutdown, ShutdownStage::Draining | ShutdownStage::Done),
            "and only then does the exit move on: {:?}",
            app.shutdown
        );

        pump_until(&mut app, &rx, "the shutdown to finish", |app| {
            app.should_quit
        });
        assert!(matches!(app.shutdown, ShutdownStage::Done));
        assert_eq!(
            crate::state::store::marked_action_paths(&db_path, scan_id),
            vec![PathBuf::from("/x/c")],
            "the settlement was the real write, not a claim about one"
        );
        assert!(
            !app.marks_unsettled,
            "and it was acknowledged before the close: {}",
            app.status
        );
        assert!(
            app.browse.live_actor().is_none(),
            "the actor was closed and joined"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// U-3: the action review lists the whole plan, so it has to scroll. The keys go in through
/// `handle_event` — the screen used to swallow them one level below, in `on_key_action_review`.
#[cfg(test)]
mod action_review_scroll_tests {
    use super::*;

    /// An app sitting on ActionReview over a plan of `count` actions, as
    /// `open_action_review` leaves it. `rows` is what the last frame measured.
    fn review_app(count: usize, rows: u16) -> (App, crossbeam_channel::Receiver<AppEvent>) {
        let (mut app, rx) = test_app();
        app.show_disclaimer = false;
        app.mode = AppMode::Wizard;
        app.screen = Screen::ActionReview;
        let mut list = ListState::default();
        list.select(Some(0));
        app.review = ReviewState {
            plan: test_plan(count),
            confirming: false,
            list,
            visible_rows: rows,
        };
        (app, rx)
    }

    fn press(app: &mut App, code: KeyCode) {
        app.handle_event(AppEvent::Key(KeyEvent::from(code)));
    }

    #[test]
    fn arrows_move_the_cursor() {
        let (mut app, _rx) = review_app(50, 12);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.review.list.selected(), Some(2));
        press(&mut app, KeyCode::Up);
        assert_eq!(app.review.list.selected(), Some(1));
    }

    #[test]
    fn end_reaches_an_action_below_the_first_screen() {
        let (mut app, _rx) = review_app(50, 12);
        press(&mut app, KeyCode::End);
        assert_eq!(
            app.review.list.selected(),
            Some(49),
            "the last action of the plan must be reachable — 12 rows fit on screen, 50 are planned"
        );
        press(&mut app, KeyCode::Home);
        assert_eq!(app.review.list.selected(), Some(0));
    }

    #[test]
    fn page_keys_step_by_the_rendered_window() {
        let (mut app, _rx) = review_app(50, 12);
        press(&mut app, KeyCode::PageDown);
        assert_eq!(
            app.review.list.selected(),
            Some(11),
            "a page is the window minus one row of overlap"
        );
        press(&mut app, KeyCode::PageUp);
        assert_eq!(app.review.list.selected(), Some(0));
    }

    #[test]
    fn the_cursor_stays_inside_the_plan() {
        let (mut app, _rx) = review_app(3, 12);
        for _ in 0..10 {
            press(&mut app, KeyCode::Down);
        }
        assert_eq!(app.review.list.selected(), Some(2));
        for _ in 0..10 {
            press(&mut app, KeyCode::Up);
        }
        assert_eq!(app.review.list.selected(), Some(0));
    }

    /// Scrolling must not become another way to start the batch: the confirmation modal
    /// still owns the keys while it is open.
    #[test]
    fn the_confirmation_modal_ignores_scrolling() {
        let (mut app, _rx) = review_app(50, 12);
        press(&mut app, KeyCode::Char('y'));
        assert!(app.review.confirming);
        press(&mut app, KeyCode::End);
        assert_eq!(app.review.list.selected(), Some(0));
        assert!(app.review.confirming, "only Y/N/Esc answer the modal");
    }

    /// The plan is confirmed from wherever the operator scrolled to — Y is not tied to the
    /// first row, and asking the question is not yet starting the batch.
    #[test]
    fn confirmation_opens_from_a_scrolled_cursor() {
        let (mut app, _rx) = review_app(50, 12);
        press(&mut app, KeyCode::End);
        assert_eq!(app.review.list.selected(), Some(49));

        press(&mut app, KeyCode::Char('y'));

        assert!(app.review.confirming, "Y must open the modal from any row");
        assert_eq!(
            app.review.list.selected(),
            Some(49),
            "opening the modal does not move the cursor"
        );
        assert_eq!(app.screen, Screen::ActionReview);
        assert!(app.apply.is_none(), "the question alone starts nothing");
    }

    /// Answering "no" leaves everything as it was, scroll position included, so the operator
    /// resumes reading the plan where they stopped.
    #[test]
    fn declining_the_confirmation_starts_nothing_and_keeps_the_position() {
        for answer in [KeyCode::Char('n'), KeyCode::Esc] {
            let (mut app, _rx) = review_app(50, 12);
            press(&mut app, KeyCode::PageDown);
            let position = app.review.list.selected();
            press(&mut app, KeyCode::Char('y'));
            assert!(app.review.confirming);

            press(&mut app, answer);

            assert!(!app.review.confirming, "{answer:?} closes the modal");
            assert_eq!(
                app.review.list.selected(),
                position,
                "{answer:?} leaves the cursor where it was"
            );
            assert_eq!(
                app.screen,
                Screen::ActionReview,
                "{answer:?} must not start the batch"
            );
            assert!(app.apply.is_none(), "{answer:?} spawned an apply worker");
        }
    }
}

#[cfg(test)]
mod group_list_navigation_tests {
    //! The file-group list is taller than one row per entry, so the two places that turn terminal
    //! rows back into entries — the click mapping and the page step — have to agree with the
    //! renderer. These are the guards for that agreement.

    use super::*;
    use crate::model::reclaim::ReclaimEstimate;
    use crate::state::GroupSummary;
    use crate::tui::screens::browser::{group_rows, groups_that_fit, BrowserTab};

    /// The classic browser's group panel: a fixed 52 columns, 20 rows tall.
    const PANEL: Rect = Rect {
        x: 0,
        y: 4,
        width: 52,
        height: 20,
    };

    fn browser_with_groups(count: usize) -> (App, crossbeam_channel::Receiver<AppEvent>) {
        let (mut app, events) = test_app();
        app.browser.group_summaries = (0..count)
            .map(|rank| GroupSummary {
                rank: rank as i64,
                hash: format!("h{rank}"),
                file_count: 3,
                size_bytes: 4096,
                object_count: 2,
                reclaim: ReclaimEstimate::exact(4096),
            })
            .map(|summary| {
                (
                    crate::model::plan::GroupId {
                        scan_id: 1,
                        rank: summary.rank,
                        generation: 1,
                    },
                    summary,
                )
            })
            .collect();
        app.browser.tab = BrowserTab::Files;
        app.browser.focus_files = false;
        app.browser.groups_area = Some(PANEL);
        app.browser.files_area = Some(Rect::new(52, 4, 40, 20));
        app.browser.group_state.select(Some(0));
        (app, events)
    }

    /// Whichever line of an entry the pointer lands on, the click selects that entry. A mapping
    /// that still counted one row per group would select a different one for every second line.
    #[test]
    fn every_line_of_a_group_entry_selects_that_entry() {
        let (mut app, _events) = browser_with_groups(6);
        let rows = group_rows(PANEL.width);
        assert_eq!(
            rows, 3,
            "the widest figure the columns accept wraps onto a second claim line even here"
        );
        for entry in 0..6u16 {
            for line in 0..rows {
                let y = PANEL.y + 1 + entry * rows + line;
                app.browser_mouse_click(PANEL.x + 3, y);
                assert_eq!(
                    app.browser.group_state.selected(),
                    Some(entry as usize),
                    "line {line} of entry {entry} must select entry {entry}"
                );
            }
        }
    }

    /// A click below the last entry changes nothing — it is not a click on the last one.
    #[test]
    fn a_click_below_the_last_group_is_ignored() {
        let (mut app, _events) = browser_with_groups(2);
        let rows = group_rows(PANEL.width);
        app.browser.group_state.select(Some(1));
        app.browser_mouse_click(PANEL.x + 3, PANEL.y + 1 + 2 * rows);
        assert_eq!(
            app.browser.group_state.selected(),
            Some(1),
            "the cursor must not move for a click past the list"
        );
    }

    /// PageUp/PageDown step by entries. `group_visible_rows` is what the renderer wrote, so the
    /// step is a screenful of groups whatever height each one has.
    #[test]
    fn paging_steps_by_entries_not_by_terminal_lines() {
        let (mut app, _events) = browser_with_groups(40);
        // What `render` writes for the Files tab.
        app.browser.group_visible_rows = groups_that_fit(PANEL) as u16;
        assert_eq!(
            app.browser.group_visible_rows, 6,
            "18 rows inside the borders, three rows a group"
        );
        app.browser_page(1);
        assert_eq!(
            app.browser.group_state.selected(),
            Some(5),
            "a page is visible groups minus one, not visible terminal rows"
        );
    }

    /// The folder tab is untouched: one row per group, and its own page step.
    #[test]
    fn the_folder_tab_still_counts_one_row_per_group() {
        let (mut app, _events) = browser_with_groups(0);
        app.browser.tab = BrowserTab::Dirs;
        app.browser.dir_group_summaries = (0..40)
            .map(|rank| crate::state::AttributedDirGroupSummary {
                rank,
                signature: format!("s{rank}"),
                dir_count: 2,
                file_count: 2,
                size_per_dir: 100,
                trust: crate::model::duplicate::DirTrust::Trusted,
            })
            .collect();
        app.browser.dir_group_state.select(Some(0));
        // What `render` writes for the Folders tab: terminal rows, unchanged.
        app.browser.group_visible_rows = PANEL.height.saturating_sub(2);
        app.browser_dir_page(1);
        assert_eq!(
            app.browser.dir_group_state.selected(),
            Some(17),
            "18 rows inside the borders, one row a group"
        );
    }
}
