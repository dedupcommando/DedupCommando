// SPDX-License-Identifier: Apache-2.0
use std::thread;

use crossbeam_channel::{Receiver, Sender};
use ratatui::crossterm::event::{self, Event, KeyEvent, MouseEvent};

use crate::model::scan::{ResumeInfo, ScanProgress, ScanSummary};
use crate::pipeline::ScanOutcome;
use crate::state::GroupSummary;

/// Main-loop event: from the keyboard, from the scanning worker, or a tick.
pub enum AppEvent {
    Key(KeyEvent),
    Resize,
    ScanProgress(ScanProgress),
    ScanFinished(std::result::Result<ScanOutcome, String>),
    /// Progress of background action application: phase/index/bytes ~6/s.
    ApplyProgress(crate::actions::ApplyProgress),
    /// Background application finished: `BatchResult` (or an error text).
    ApplyFinished(std::result::Result<crate::model::action::BatchResult, String>),
    /// File hash computed on request (F4) in the commander interface.
    CommanderHash(std::path::PathBuf, [u8; 32]),
    /// Failed to compute the file hash on request.
    CommanderHashFailed(std::path::PathBuf, String),
    /// Background hash of a moved file (sorting) — quietly into the index + DB cache,
    /// so the destinations index grows without a manual rehash (triage §B).
    CommanderHashCached(std::path::PathBuf, [u8; 32]),
    /// Dedup attributes of ONE panel directory, read in the background from the DB:
    /// file status/hash + sizes/signatures of subdirectories. Placed in the cache by `cwd`.
    /// Replaces the former `CommanderDedupLoaded` (the whole scan in RAM).
    CommanderDirDedup {
        cwd: std::path::PathBuf,
        dir: crate::tui::commander::dedup::DirDedup,
    },
    /// A directory's computed size, calculated in a background thread.
    CommanderDirSize(std::path::PathBuf, u64),
    /// Panel directory contents, read in the background. `target` routes the
    /// result: the commander panel, the Board source or destination.
    CommanderPanelLoaded {
        target: crate::tui::commander::state::LoadTarget,
        generation: u64,
        entries: Vec<crate::tui::commander::state::PanelEntry>,
        previous: Option<std::path::PathBuf>,
    },
    /// A background move batch is ready — apply to the UI: the Undo journal,
    /// the hash index, re-read the panels. The UI was not blocked during the move.
    CommanderMoveDone(Box<crate::tui::commander::move_batch::MoveBatchOutcome>),
    /// List of saved sessions, loaded in the background.
    SessionsReady(Vec<ResumeInfo>),
    /// Background purge of a session from the trash finished: a heavy
    /// multi-index DELETE by `file` ran in the background so as not to hang the UI.
    SessionDeleted(std::result::Result<i64, String>),
    /// A finished scan's ready result, loaded in the background: opening
    /// without rescanning. `(scan_id, group summaries, scan summary)`. Carries
    /// lightweight `GroupSummary`, not all `DuplicateGroup` (RAM paging).
    ResultsLoaded(i64, Vec<GroupSummary>, ScanSummary),
    /// Background session probe for F2: unfinished + the last Complete of the same
    /// roots — F2 gives an instant response, while the heavy `list_scans` runs in the background.
    CommanderResumeProbe {
        roots: Vec<std::path::PathBuf>,
        unfinished: Option<ResumeInfo>,
        complete: Option<ResumeInfo>,
    },
    /// Diff of two scans, computed in the background.
    ScanDiffReady(Box<crate::state::move_track::DiffReport>),
    /// Diff not performed (the DB didn't open / the query crashed) — clear the loading and show
    /// the error, otherwise the screen would hang in "computing" forever.
    ScanDiffFailed(String),
    /// Mouse event — a click or a wheel scroll.
    Mouse(MouseEvent),
}

/// Creates the application's single event channel.
pub fn channel() -> (Sender<AppEvent>, Receiver<AppEvent>) {
    crossbeam_channel::unbounded()
}

/// Starts a background keyboard-reading thread; events go into `tx`.
/// The thread terminates when the receiver is closed (the application has exited).
pub fn spawn_input_thread(tx: Sender<AppEvent>) {
    thread::spawn(move || loop {
        match event::read() {
            Ok(Event::Key(key)) => {
                if tx.send(AppEvent::Key(key)).is_err() {
                    break;
                }
            }
            Ok(Event::Resize(_, _)) => {
                if tx.send(AppEvent::Resize).is_err() {
                    break;
                }
            }
            Ok(Event::Mouse(mouse)) => {
                if tx.send(AppEvent::Mouse(mouse)).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    });
}
