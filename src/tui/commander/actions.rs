// SPDX-License-Identifier: Apache-2.0
//! F11 — building and executing deduplication actions from panel marks.

use std::collections::HashMap;

use crate::app::{App, AppMode};
use crate::model::dataset::Dataset;
use crate::model::duplicate::{hex_encode, DuplicateGroup, FileEntry};
use crate::state::ScanStore;

use super::state::{ConfirmTab, Mark, Overlay, PlanDigest};

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
    app.commander.confirm_digest = PlanDigest::of(&plan);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_app_with_db;
    use crate::model::action::ActionKind;
    use crate::state::store::{role_guard, ManifestRow};
    use std::path::{Path, PathBuf};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("dedcom_u4a_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Real files on disk (`collect_marked` stats them) whose paths carry one shared hash in
    /// the DB (`build_groups` looks each one up) — the minimum for F11 to build a plan.
    fn seed(dir: &Path, names: &[&str]) -> (PathBuf, i64) {
        let db_path = dir.join("dedcom.db");
        let mut store = ScanStore::open_writable(&db_path).unwrap();
        let scan_id = store
            .begin_scan(&crate::model::scan::ScanConfig::new(
                vec![dir.to_path_buf()],
            ))
            .unwrap();
        let mut rows = Vec::new();
        let mut hashes = Vec::new();
        for name in names {
            let path = dir.join(name);
            std::fs::write(&path, b"identical content").unwrap();
            rows.push(ManifestRow {
                path: path.clone(),
                size: 17,
                ..Default::default()
            });
            hashes.push((path, [7u8; 32]));
        }
        store.record_files(scan_id, &rows).unwrap();
        store.record_hashes(scan_id, &hashes).unwrap();
        (db_path, scan_id)
    }

    /// The review's failure scenario: F8 landed where F7 was meant, so the batch deletes the
    /// two files the operator wanted to keep. «Actions: 2» reads as expected — the digest is
    /// what makes the mistake visible before Y.
    #[test]
    fn the_confirmation_digest_names_a_mis_marked_batch() {
        let _role = role_guard();
        let dir = temp_dir("mismarked");
        let (db_path, scan_id) = seed(&dir, &["keeper.bin", "dup1.bin", "dup2.bin"]);

        let (mut app, _rx) = test_app_with_db(db_path);
        app.commander.dedup_scan_id = Some(scan_id);
        let marks = &mut app.commander.panels[0].marks;
        marks.insert(dir.join("keeper.bin"), Mark::Keeper);
        marks.insert(dir.join("dup1.bin"), Mark::Delete);
        marks.insert(dir.join("dup2.bin"), Mark::Delete);

        prepare_execution(&mut app);

        assert!(
            matches!(app.commander.overlay, Overlay::Confirm { files: 2, .. }),
            "the plan is two deletions: {:?}",
            app.commander.overlay
        );
        let digest = &app.commander.confirm_digest;
        assert_eq!(
            digest.counts,
            vec![(ActionKind::Delete, 2)],
            "the confirmation must be able to say «delete 2»"
        );
        let named: Vec<&PathBuf> = digest.samples.iter().map(|(_, path)| path).collect();
        assert!(
            named.contains(&&dir.join("dup1.bin")) && named.contains(&&dir.join("dup2.bin")),
            "both targets are named: {named:?}"
        );
        assert_eq!(digest.hidden, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A stale digest is worse than none: the overlay would describe the previous plan.
    #[test]
    fn a_second_plan_replaces_the_first_digest() {
        let _role = role_guard();
        let dir = temp_dir("replace");
        let (db_path, scan_id) = seed(&dir, &["keeper.bin", "dup1.bin", "dup2.bin"]);

        let (mut app, _rx) = test_app_with_db(db_path);
        app.commander.dedup_scan_id = Some(scan_id);
        {
            let marks = &mut app.commander.panels[0].marks;
            marks.insert(dir.join("keeper.bin"), Mark::Keeper);
            marks.insert(dir.join("dup1.bin"), Mark::Delete);
            marks.insert(dir.join("dup2.bin"), Mark::Delete);
        }
        prepare_execution(&mut app);
        assert_eq!(app.commander.confirm_digest.counts.len(), 1);

        // The operator backs out and re-marks one file as a hardlink instead.
        cancel_execution(&mut app);
        {
            let marks = &mut app.commander.panels[0].marks;
            marks.remove(&dir.join("dup2.bin"));
            marks.insert(dir.join("dup1.bin"), Mark::Hardlink);
        }
        prepare_execution(&mut app);

        assert_eq!(
            app.commander.confirm_digest.counts,
            vec![(ActionKind::Hardlink, 1)],
            "the digest describes the plan on screen now, not the one that was cancelled"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
