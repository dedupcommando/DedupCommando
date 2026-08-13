// SPDX-License-Identifier: Apache-2.0
use std::thread;

use crossbeam_channel::{Receiver, Sender};
use ratatui::crossterm::event::{self, Event, KeyEvent, MouseEvent};

use crate::model::scan::{ResumeInfo, ScanProgress};
use crate::pipeline::ScanOutcome;

/// Main-loop event: from the keyboard, from the scanning worker, or a tick.
pub enum AppEvent {
    Key(KeyEvent),
    Resize,
    ScanProgress(ScanProgress),
    ScanFinished(std::result::Result<ScanOutcome, String>),
    /// Progress of background action application: phase/index/bytes ~6/s.
    ApplyProgress(crate::actions::ApplyProgress),
    /// The guarded batch's outcome: refused whole (the plan comes back to its window),
    /// finished with a `BatchResult`, or failed with an error text.
    ApplyFinished(Box<crate::actions::ApplyOutcome>),
    /// File hash computed on request (F4) in the commander interface.
    CommanderHash(std::path::PathBuf, [u8; 32]),
    /// Failed to compute the file hash on request.
    CommanderHashFailed(std::path::PathBuf, String),
    /// Background hash of a moved file (sorting) — quietly into the index + DB cache,
    /// so the destinations index grows without a manual rehash (triage §B).
    CommanderHashCached(std::path::PathBuf, [u8; 32]),
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
    /// List of saved sessions, loaded in the background — or the store error that stopped it.
    /// Result-bearing on purpose: an unopenable checkpoint must not be representable as the same
    /// value as one that genuinely holds no sessions.
    ///
    /// `generation` is the request this reply answers. Several loads can be in flight at once —
    /// a finished scan and a restored session both abandon the list and ask again — and without
    /// the tag their replies are indistinguishable, so a superseded answer could overwrite the
    /// current one in either direction.
    SessionsReady {
        generation: u64,
        result: std::result::Result<Vec<ResumeInfo>, String>,
    },
    /// Background purge of a session from the trash finished: a heavy
    /// multi-index DELETE by `file` ran in the background so as not to hang the UI.
    SessionDeleted(std::result::Result<i64, String>),
    /// A browsing-actor reply. The one carrier for every completed-scan answer: opening a
    /// result installs a complete `OpenedBrowse` atomically through it, so a half-loaded
    /// result is unrepresentable and a stale reply is dropped whole by its activation.
    Browse(Box<crate::state::browse::BrowseEvent>),
    /// Background session probe for F2: unfinished + the last Complete of the same
    /// roots — F2 gives an instant response, while the heavy `list_scans` runs in the background.
    ///
    /// `probe` is a Result because this is the destructive member of the cluster: only a real
    /// `Ok((None, None))` — the checkpoint opened and holds no history for these roots — may be
    /// read as permission to start a new scan. A store error must never reach that branch.
    CommanderResumeProbe {
        roots: Vec<std::path::PathBuf>,
        probe: std::result::Result<(Option<ResumeInfo>, Option<ResumeInfo>), String>,
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
