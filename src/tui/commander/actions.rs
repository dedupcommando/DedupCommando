// SPDX-License-Identifier: Apache-2.0
//! F11 — building and executing deduplication actions from panel marks.

use std::collections::HashMap;

use crate::app::{App, AppMode};
use crate::model::dataset::Dataset;
use crate::model::duplicate::{hex_encode, DuplicateGroup, FileEntry};
use crate::state::ScanStore;

use super::state::{ConfirmTab, Mark, Overlay};

/// F11: collects marks from all panels, builds a plan, opens the confirmation.
pub fn prepare_execution(app: &mut App) {
    if app.deny_if_read_only("executing actions") {
        return;
    }
    let files = collect_marked(app);
    if files.is_empty() {
        app.commander.status = "No marked files (F5/F6/F7/F8)".to_string();
        return;
    }
    let (groups, no_hash) = build_groups(app, files);
    let plan = crate::actions::plan_actions(&groups);
    if plan.is_empty() {
        app.commander.status = if no_hash > 0 {
            format!("No actions: {no_hash} files without a hash — run a scan (F2)")
        } else {
            "No actions: a group needs one keeper (F7) and at least one action".to_string()
        };
        return;
    }
    let count = plan.len();
    let reclaim: u64 = plan.iter().map(|action| action.size).sum();
    // Shell-script preview — datasets are needed for quarantine
    // and snapshot paths, as in apply_batch.
    let datasets: Vec<Dataset> = app
        .zfs
        .pools
        .iter()
        .flat_map(|pool| pool.datasets.iter().cloned())
        .collect();
    app.commander.confirm_script = crate::actions::script_preview::render_script(
        &plan,
        &datasets,
        crate::zfs::trusted_zfs_bin(),
    );
    app.commander.pending_actions = plan;
    app.commander.overlay = Overlay::Confirm {
        files: count,
        reclaim,
        tab: ConfirmTab::Summary,
    };
}

/// F11 confirmation: applies the actions and moves to the summary screen.
pub fn confirm_execution(app: &mut App) {
    if app.deny_if_read_only("executing actions") {
        app.commander.overlay = Overlay::None;
        return;
    }
    let plan = std::mem::take(&mut app.commander.pending_actions);
    app.commander.overlay = Overlay::None;
    if plan.is_empty() {
        return;
    }
    // Application runs in the BACKGROUND — the UI does not freeze. The
    // Applying/Summary screens belong to the wizard, so we switch to Wizard and flag
    // the return to commander; re-reading the panels after success happens in
    // `App::on_apply_finished`.
    app.mode = AppMode::Wizard;
    app.commander.return_to_commander = true;
    app.start_apply(plan);
}

/// Cancels the F11 confirmation.
pub fn cancel_execution(app: &mut App) {
    app.commander.pending_actions.clear();
    app.commander.overlay = Overlay::None;
}

/// Collects marked files from all panels with fresh metadata.
fn collect_marked(app: &App) -> Vec<FileEntry> {
    use std::os::unix::fs::MetadataExt;
    let mut files = Vec::new();
    for panel in &app.commander.panels {
        for (path, mark) in &panel.marks {
            let meta = match std::fs::symlink_metadata(path) {
                Ok(meta) if meta.is_file() => meta,
                _ => continue,
            };
            files.push(FileEntry {
                path: path.clone(),
                size: meta.size(),
                mtime: meta.mtime(),
                device: meta.dev(),
                inode: meta.ino(),
                is_keeper: matches!(mark, Mark::Keeper),
                action: mark.action(),
            });
        }
    }
    files
}

/// Groups marked files by hash; returns the groups and the count of files without a hash.
/// Each file's hash is read from the DB via a pointed lookup (there is no RAM index).
fn build_groups(app: &App, files: Vec<FileEntry>) -> (Vec<DuplicateGroup>, usize) {
    let mut by_hash: HashMap<String, Vec<FileEntry>> = HashMap::new();
    let mut no_hash = 0usize;
    let scan_id = app.commander.dedup_scan_id;
    let store = scan_id.and_then(|_| ScanStore::open(&app.db_path).ok());
    for file in files {
        let hash = match (scan_id, &store) {
            (Some(scan_id), Some(store)) => store
                .hash_for_path(scan_id, &file.path)
                .ok()
                .flatten()
                .map(|bytes| hex_encode(&bytes)),
            _ => None,
        };
        match hash {
            Some(hash) => by_hash.entry(hash).or_default().push(file),
            None => no_hash += 1,
        }
    }
    let groups = by_hash
        .into_iter()
        .enumerate()
        .map(|(id, (hash, files))| DuplicateGroup {
            id,
            size_bytes: files.first().map(|file| file.size).unwrap_or(0),
            hash,
            files,
        })
        .collect();
    (groups, no_hash)
}
