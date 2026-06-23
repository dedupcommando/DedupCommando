// SPDX-License-Identifier: Apache-2.0
//! Maintenance of the checkpoint DB: trash cleanup + VACUUM and a deferred
//! auto-VACUUM on an interval. VACUUM rewrites the whole file — on a production 5+ GB DB
//! this is noticeable, so it runs only by the operator, when idle, in the background, or via the
//! explicit command `--compact-db`. Settings and the timestamp live in `<state_dir>/config.json`
//! (alongside `concurrency`); we write additively, without clobbering other fields.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Result;
use crate::state::ScanStore;

/// Default auto-VACUUM interval, hours (0 — disabled).
pub const DEFAULT_VACUUM_INTERVAL_HOURS: u64 = 120;

fn config_path(state_dir: &Path) -> PathBuf {
    state_dir.join("config.json")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Reads the interval and the last-VACUUM timestamp from config.json.
fn read_config(state_dir: &Path) -> (u64, Option<i64>) {
    #[derive(serde::Deserialize)]
    struct Cfg {
        vacuum_interval_hours: Option<u64>,
        last_vacuum: Option<i64>,
    }
    let cfg = std::fs::read_to_string(config_path(state_dir))
        .ok()
        .and_then(|j| serde_json::from_str::<Cfg>(&j).ok());
    match cfg {
        Some(c) => (
            c.vacuum_interval_hours
                .unwrap_or(DEFAULT_VACUUM_INTERVAL_HOURS),
            c.last_vacuum,
        ),
        None => (DEFAULT_VACUUM_INTERVAL_HOURS, None),
    }
}

/// Whether auto-VACUUM is due: interval>0 and enough time has passed since last time. A pure
/// function of its inputs — testable without a filesystem.
pub fn vacuum_due(interval_hours: u64, last_vacuum: Option<i64>, now: i64) -> bool {
    if interval_hours == 0 {
        return false;
    }
    match last_vacuum {
        None => true,
        Some(last) => now.saturating_sub(last) >= interval_hours as i64 * 3600,
    }
}

/// Decides from config.json whether auto-VACUUM is due now.
pub fn should_auto_vacuum(state_dir: &Path) -> bool {
    let (interval, last) = read_config(state_dir);
    vacuum_due(interval, last, now_unix())
}

/// Default retention: how many of the newest completed scans of the same roots to keep active.
pub const DEFAULT_HISTORY_KEEP: usize = 2;

/// History limit for the same roots from config.json: the newest `keep`
/// completed ones stay, the rest go to the trash on a fresh Complete.
pub fn history_keep(state_dir: &Path) -> usize {
    #[derive(serde::Deserialize)]
    struct Cfg {
        history_keep: Option<usize>,
    }
    std::fs::read_to_string(config_path(state_dir))
        .ok()
        .and_then(|j| serde_json::from_str::<Cfg>(&j).ok())
        .and_then(|c| c.history_keep)
        .unwrap_or(DEFAULT_HISTORY_KEEP)
}

/// Writes the last-VACUUM timestamp to config.json, PRESERVING the other
/// fields (e.g. `concurrency`) — we read it as an object and edit one key.
fn record_vacuum(state_dir: &Path) -> Result<()> {
    let path = config_path(state_dir);
    let mut value: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !value.is_object() {
        value = serde_json::json!({});
    }
    if let Some(obj) = value.as_object_mut() {
        obj.insert("last_vacuum".to_string(), serde_json::json!(now_unix()));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&value)?)?;
    Ok(())
}

/// `--compact-db`: clears the trash (purge of all trashed) and compacts the DB (VACUUM).
/// Returns (number of purged sessions, size before, size after) in bytes.
pub fn compact(db_path: &Path, state_dir: &Path) -> Result<(usize, u64, u64)> {
    let before = file_size(db_path);
    let purged = {
        let mut store = ScanStore::open(db_path)?;
        let trashed = store.list_trashed()?;
        for info in &trashed {
            store.purge_scan(info.scan_id)?;
        }
        store.vacuum()?;
        trashed.len()
    };
    record_vacuum(state_dir)?;
    Ok((purged, before, file_size(db_path)))
}

/// VACUUM only (deferred auto-mode) + timestamp. Does not touch the trash.
pub fn vacuum_only(db_path: &Path, state_dir: &Path) -> Result<()> {
    {
        let store = ScanStore::open(db_path)?;
        store.vacuum()?;
    }
    record_vacuum(state_dir)
}

/// DB size on disk: main file + WAL — the single source for
/// `--stats` and the F12 header.
pub fn db_size_bytes(db_path: &Path) -> u64 {
    let wal = PathBuf::from(format!("{}-wal", db_path.display()));
    file_size(db_path) + file_size(&wal)
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_when_interval_zero() {
        assert!(!vacuum_due(0, None, 1_000_000));
        assert!(!vacuum_due(0, Some(0), 1_000_000));
    }

    #[test]
    fn due_when_never_run() {
        assert!(vacuum_due(120, None, 1_000_000));
    }

    #[test]
    fn due_only_after_full_interval() {
        let last = 1_000_000i64;
        let hour = 3600;
        assert!(!vacuum_due(120, Some(last), last + 119 * hour));
        assert!(vacuum_due(120, Some(last), last + 120 * hour));
    }
}
