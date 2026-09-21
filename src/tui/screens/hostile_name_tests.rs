// SPDX-License-Identifier: Apache-2.0
//! Every wizard screen that prints a pathname, fed names that try to drive the terminal.
//!
//! One test per screen and not one for all of them: a screen that stops escaping has to be named
//! by the test that fails. Each draws the real `render` over real state and then looks at the
//! cells, because that is what the terminal is given.

use std::path::PathBuf;

use crate::app::{test_app, test_plan_over, App, RootChoice};
use crate::model::action::{ActionKind, ActionOutcome, BatchResult};
use crate::model::plan::{ObjectRealization, PlanObjectKey};
use crate::model::reclaim::ReclaimEstimate;
use crate::model::scan::{ResumeInfo, ScanStatus};
use crate::state::move_track::{DiffReport, FileChange};
use crate::tui::commander::panel::ellipsize_left;
use crate::tui::event::AppEvent;
use crate::tui::hostile::{self, NAMES, ORDINARY, RETITLE, RETITLE_SHOWN};

use super::{
    action_review, folder_picker, resume, scan_config, scan_diff, scanning, summary, trash,
};

/// Every fixture name as a path under a directory that is hostile as well.
fn hostile_paths() -> Vec<PathBuf> {
    NAMES
        .iter()
        .map(|name| PathBuf::from(format!("/tank/{}/{name}", hostile::CLEAR)))
        .collect()
}

/// The receiver is handed back so the channel stays open for as long as the app is drawn.
fn new_app() -> (App, crossbeam_channel::Receiver<AppEvent>) {
    let (mut app, events) = test_app();
    app.show_disclaimer = false;
    (app, events)
}

fn session(roots: Vec<PathBuf>) -> ResumeInfo {
    ResumeInfo {
        scan_id: 7,
        created_at: "2026-07-31 10:00:00".to_string(),
        status: ScanStatus::Complete,
        roots,
        files_total: 10,
        files_hashed: 10,
        cand_bytes_total: 1000,
        cand_bytes_hashed: 1000,
        files_scanned: 100,
        reclaim: ReclaimEstimate::exact(4096),
        already_linked_sets: None,
    }
}

#[test]
fn the_action_review_lists_a_hostile_target_escaped() {
    let (mut app, _events) = new_app();
    app.review.plan = test_plan_over(&hostile_paths());
    app.review.list.select(Some(0));
    let shown = hostile::inert_text(200, 16, "action review", |frame| {
        action_review::render(frame, &mut app)
    });
    assert!(shown.contains(RETITLE_SHOWN), "{shown}");
}

#[test]
fn the_action_review_lists_an_ordinary_target_as_it_is() {
    let (mut app, _events) = new_app();
    app.review.plan = test_plan_over(&[PathBuf::from(format!("/tank/{ORDINARY}"))]);
    app.review.list.select(Some(0));
    let shown = hostile::inert_text(120, 16, "action review", |frame| {
        action_review::render(frame, &mut app)
    });
    assert!(shown.contains(ORDINARY), "{shown}");
}

/// Every category of the comparison, and the two places that never went through the cut at all:
/// the peer of a new duplicate and the root in the header.
#[test]
fn the_scan_comparison_shows_hostile_paths_escaped_in_every_category() {
    let paths = hostile_paths();
    let one = |index: usize| paths[index % paths.len()].clone();
    // The root is an ordinary one here, so that what each category is seen to escape is its own
    // rows and not the header above them.
    let report = DiffReport {
        old_scan_id: 1,
        new_scan_id: 2,
        root: PathBuf::from("/tank"),
        new_dup_candidates: vec![FileChange::NewDupCandidate {
            path: one(1),
            peers_in_old: vec![one(0)],
        }],
        moved_inode: vec![FileChange::MovedByInode {
            from: one(0),
            to: one(1),
        }],
        moved_hash: vec![FileChange::MovedByHash {
            from: one(2),
            to: one(3),
        }],
        modified: vec![FileChange::Modified {
            old_path: one(0),
            new_path: one(0),
        }],
        deleted: vec![FileChange::Deleted { path: one(0) }],
        new: vec![FileChange::New { path: one(0) }],
        ..Default::default()
    };
    for category in 0..scan_diff::CATEGORIES.len() {
        let (mut app, _events) = new_app();
        app.scan_diff.report = Some(report.clone());
        app.scan_diff.category = category;
        app.scan_diff.list.select(Some(0));
        let surface = format!("scan comparison · {}", scan_diff::CATEGORIES[category]);
        let shown = hostile::inert_text(240, 16, &surface, |frame| scan_diff::render(frame, &app));
        // Every path of the fixture sits in the same hostile directory.
        assert!(
            shown.contains("/tank/wipe\\u{1b}[2Jme.txt/"),
            "{surface}:\n{shown}"
        );
    }

    // The peer of a new duplicate never went through the cut, so it is looked for by name.
    let (mut app, _events) = new_app();
    app.scan_diff.report = Some(report.clone());
    app.scan_diff.category = 0;
    let shown = hostile::inert_text(240, 16, "new duplicates", |frame| {
        scan_diff::render(frame, &app)
    });
    assert!(
        shown.contains(&format!(
            "← duplicate of: {}",
            crate::textsan::path(&one(0))
        )),
        "{shown}"
    );

    // And the root in the header, on its own.
    let mut rooted = report;
    rooted.root = PathBuf::from("/mnt").join(RETITLE);
    let (mut app, _events) = new_app();
    app.scan_diff.report = Some(rooted);
    let shown = hostile::inert_text(240, 16, "scan comparison header", |frame| {
        scan_diff::render(frame, &app)
    });
    assert!(
        shown.contains(&format!("root /mnt/{RETITLE_SHOWN}")),
        "{shown}"
    );
}

/// The list cuts its paths on the left. Whatever width the cut lands on, what is left of a
/// sequence must not be one.
#[test]
fn the_scan_comparison_cuts_a_path_only_after_escaping_it() {
    let report = DiffReport {
        root: PathBuf::from("/tank"),
        deleted: hostile_paths()
            .into_iter()
            .map(|path| FileChange::Deleted { path })
            .collect(),
        ..Default::default()
    };
    let first = crate::textsan::path(&hostile_paths()[0]);
    for width in 12..=70 {
        let (mut app, _events) = new_app();
        app.scan_diff.report = Some(report.clone());
        app.scan_diff.category = 4;
        let buffer = hostile::frame_of(width, 16, |frame| scan_diff::render(frame, &app));
        hostile::assert_inert(&buffer, &format!("scan comparison at {width} columns"));

        // Escaping after the cut would be inert too, and too wide: the row is cut to the list's
        // own width, and it is the escaped text that has to fit it.
        let row = ellipsize_left(&first, width as usize - 4);
        let shown = hostile::text(&buffer);
        assert!(shown.contains(&row), "at {width} columns {row:?}:\n{shown}");
    }
}

/// The live feed: every path the walker and the hasher touch passes through this one line.
#[test]
fn the_scan_progress_shows_the_current_path_escaped() {
    for path in hostile_paths() {
        for width in [16, 40, 200] {
            let (mut app, _events) = new_app();
            app.scanning.current_path = Some(path.clone());
            let buffer = hostile::frame_of(width, 12, |frame| scanning::render(frame, &app));
            hostile::assert_inert(&buffer, &format!("scan progress at {width} columns"));

            // The line has the frame's width less its borders and its indent, and what fits it
            // is the escaped path cut on the left — not a cut path escaped afterwards.
            let line = ellipsize_left(&crate::textsan::path(&path), width as usize - 4);
            let shown = hostile::text(&buffer);
            assert!(
                shown.contains(&line),
                "at {width} columns {line:?}:\n{shown}"
            );
        }
    }
}

#[test]
fn the_scan_setup_lists_hostile_roots_escaped() {
    let (mut app, _events) = new_app();
    app.config.roots = hostile_paths()
        .into_iter()
        .enumerate()
        .map(|(index, path)| RootChoice {
            label: format!("tank/ds{index}"),
            path,
            selected: true,
            // Both shapes of the row: a dataset with its mountpoint, and a picked folder.
            is_dataset: index % 2 == 0,
        })
        .collect();
    let shown = hostile::inert_text(200, 24, "scan setup", |frame| {
        scan_config::render(frame, &app)
    });
    assert!(shown.contains(RETITLE_SHOWN), "{shown}");
}

#[test]
fn the_folder_picker_shows_a_hostile_directory_escaped() {
    let (mut app, _events) = new_app();
    app.folder_picker.current_dir = PathBuf::from("/tank").join(RETITLE);
    app.folder_picker.entries = hostile_paths();
    // A path with no final component falls back to the whole path.
    app.folder_picker
        .entries
        .push(PathBuf::from("/mnt").join(RETITLE).join(".."));
    let shown = hostile::inert_text(200, 16, "folder picker", |frame| {
        folder_picker::render(frame, &app)
    });
    assert_eq!(
        shown.matches(RETITLE_SHOWN).count(),
        3,
        "in the header, as a name in the list, and inside the path that has no name:\n{shown}"
    );
    assert!(
        shown.contains(&format!("/mnt/{RETITLE_SHOWN}/../")),
        "{shown}"
    );
}

#[test]
fn the_saved_scans_list_shows_hostile_roots_escaped() {
    let (mut app, _events) = new_app();
    app.sessions_loading = false;
    app.sessions = vec![session(hostile_paths())];
    let shown = hostile::inert_text(400, 12, "saved scans", |frame| resume::render(frame, &app));
    assert!(shown.contains(RETITLE_SHOWN), "{shown}");
}

#[test]
fn the_trash_shows_hostile_roots_escaped() {
    let (mut app, _events) = new_app();
    app.trashed = vec![session(hostile_paths())];
    let shown = hostile::inert_text(400, 12, "trash", |frame| trash::render(frame, &app));
    assert!(shown.contains(RETITLE_SHOWN), "{shown}");
}

/// The summary prints a pathname in five places, and one of them inside text it did not write:
/// an action's error message quotes the paths and the xattr names the lower layers saw.
#[test]
fn the_batch_summary_shows_every_pathname_and_error_text_escaped() {
    let paths = hostile_paths();
    let key = PlanObjectKey {
        device: 1,
        inode: 7,
        size: 1024,
        mtime: 1_700_000_000,
        mtime_nsec: 0,
        ctime_sec: 1_700_000_001,
        ctime_nsec: 0,
        identity_version: 1,
    };
    let (mut app, _events) = new_app();
    app.summary_result = Some(BatchResult {
        outcomes: paths
            .iter()
            .map(|path| ActionOutcome {
                kind: ActionKind::Hardlink,
                target: path.clone(),
                quarantine: Some(PathBuf::from("/tank/.dedcom-quarantine/ts").join(RETITLE)),
                result: Err(format!("cannot copy xattr user.{RETITLE}: denied")),
            })
            .collect(),
        quarantine_dirs: vec![PathBuf::from("/tank/.dedcom-quarantine").join(RETITLE)],
        planned: paths.len(),
        aborted: Some(format!("the plan no longer matches {RETITLE}")),
        realized: vec![(
            key,
            ObjectRealization::Unknown {
                reason: format!("rename failed for {RETITLE}"),
                quarantine: Some(PathBuf::from("/tank/q").join(RETITLE)),
            },
        )],
        ..Default::default()
    });
    let shown = hostile::inert_text(240, 60, "batch summary", |frame| {
        summary::render(frame, &app)
    });
    for (line, what) in [
        ("BATCH REFUSED", "the refusal"),
        ("✗ HARDLINK", "the failed target and its error"),
        (
            "/tank/.dedcom-quarantine/\\u{1b}",
            "the quarantine directory",
        ),
        (
            "/tank/.dedcom-quarantine/ts/\\u{1b}",
            "the quarantined original",
        ),
        (
            "unknown — check /tank/q/\\u{1b}",
            "the unsettled allocation",
        ),
    ] {
        let row = shown
            .lines()
            .find(|row| row.contains(line))
            .unwrap_or_else(|| panic!("{what} is not on screen:\n{shown}"));
        assert!(row.contains("\\u{1b}]0;PWNED\\u{7}"), "{what}: {row}");
    }
    let failed = shown
        .lines()
        .find(|row| row.contains("✗ HARDLINK"))
        .unwrap();
    assert_eq!(
        failed.matches("\\u{1b}]0;PWNED\\u{7}").count(),
        2,
        "the target and the message are two different strings: {failed}"
    );
}

#[test]
fn the_batch_summary_shows_an_ordinary_pathname_as_it_is() {
    let (mut app, _events) = new_app();
    app.summary_result = Some(BatchResult {
        outcomes: vec![ActionOutcome {
            kind: ActionKind::Delete,
            target: PathBuf::from("/tank").join(ORDINARY),
            quarantine: Some(PathBuf::from("/tank/q").join(ORDINARY)),
            result: Err(format!("no such file: {ORDINARY}")),
        }],
        planned: 1,
        ..Default::default()
    });
    let shown = hostile::inert_text(200, 40, "batch summary", |frame| {
        summary::render(frame, &app)
    });
    assert_eq!(shown.matches(ORDINARY).count(), 3, "{shown}");
}
