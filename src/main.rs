// SPDX-License-Identifier: Apache-2.0
// Stylistic clippy lints the project deliberately diverges from (clippy gate):
// - collapsible_match: an explicit `match { Pat => if cond {…} }` (which key — separate from
//   the condition) reads better than a guard and doesn't run into 100 columns in our manual
//   formatting;
// - items_after_test_module: a test module next to the code it tests (e.g. `version_tests`
//   by `version()`) — deliberate locality, not "at the very end of the file".
#![allow(clippy::collapsible_match)]
#![allow(clippy::items_after_test_module)]

mod actions;
mod app;
mod bench;
mod cli;
mod consent;
mod error;
mod lock;
mod logging;
mod maint;
mod model;
mod paths;
mod pipeline;
mod scan;
mod state;
mod sysmon;
mod textsan;
mod tui;
mod zfs;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use ratatui::crossterm::event::KeyCode;

use crate::app::App;
use crate::error::{AppError, Result};
use crate::model::scan::{ScanConfig, ScanProgress};
use crate::pipeline::ScanOutcome;
use crate::state::{HostProfile, ScanStore};
use crate::tui::event::AppEvent;

/// The application version — the single source of truth in the `VERSION` file (embedded in
/// the binary and echoed by the build script). The public scheme is SemVer
/// `MAJOR.MINOR.PATCH[-pre]` (e.g. `0.9.0-beta.1`).
pub fn version() -> &'static str {
    include_str!("../VERSION").trim()
}

#[cfg(test)]
mod version_tests {
    #[test]
    fn version_is_nonempty_and_well_formed() {
        // The single source of the version (VERSION). A broken file breaks the build rather
        // than silently diverging from `--version`.
        let v = super::version();
        assert!(!v.is_empty(), "VERSION is empty");
        // The public scheme is SemVer: core = MAJOR.MINOR.PATCH (up to the pre-release `-…`).
        let core = v.split('-').next().unwrap_or("");
        let parts: Vec<&str> = core.split('.').collect();
        assert!(
            parts.len() == 3,
            "the version core is MAJOR.MINOR.PATCH: {v}"
        );
        assert!(
            parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
            "MAJOR/MINOR/PATCH — digits only: {v}"
        );
    }
}

fn main() {
    let cli = match cli::Cli::parse() {
        Ok(cli) => cli,
        Err(msg) => {
            eprintln!("dedcom: {msg}");
            eprintln!("Run with --help for usage.");
            std::process::exit(2);
        }
    };

    let _log_guards = logging::init(&paths::log_file(&cli), &paths::bench_file(&cli));
    tracing::info!("dedcom v{} starting", version());

    // Headless modes that write to the DB/FS hold the single-instance lock for the duration:
    // otherwise a write race with a second process or with a running TUI operator.
    // Read-only modes (--stats/--export-csv) do not take the lock. The guard (_lock) lives
    // until the end of the closure → released after the operation completes.
    let result = if cli.stats {
        run_stats(&cli)
    } else if cli.compact_db {
        acquire_write_lock(&cli).and_then(|_lock| run_compact(&cli))
    } else if let Some(out) = &cli.export_csv {
        run_export_csv(&cli, out)
    } else if cli.purge_quarantine {
        acquire_write_lock(&cli).and_then(|_lock| run_purge_quarantine(&cli))
    } else if !cli.scan_roots.is_empty() {
        acquire_write_lock(&cli).and_then(|_lock| run_headless_scan(&cli))
    } else {
        run_tui(&cli)
    };

    if let Err(err) = result {
        tracing::error!("exiting with error: {err}");
        eprintln!("dedcom: error: {err}");
        std::process::exit(1);
    }
}

/// Interactive mode: the TUI with a background scan worker.
fn run_tui(cli: &cli::Cli) -> Result<()> {
    let db_path = paths::checkpoint_db(cli);
    let state_dir = paths::state_dir(cli);
    // The state directory may not exist on the first run — we create it ahead at 0700
    // (for the lock file and consent.json) with a check of the whole parent chain.
    // Fail-closed: on an untrusted chain (foreign/group-writable ancestor) we refuse to
    // operate.
    paths::establish_state_dir(&state_dir)?;

    // Single-instance lock: acquiring the advisory flock = the OPERATOR role;
    // held by another live instance → the role is decided by the policy + CLI flags.
    let (busy, holder, mut lock_to_hold) = match lock::try_acquire(&state_dir) {
        Ok(lock::Acquire::Operator(guard)) => (false, None, Some(guard)),
        Ok(lock::Acquire::Busy(h)) => (true, h, None),
        Err(err) => {
            tracing::warn!("single-instance lock unavailable ({err}); continuing as operator");
            (false, None, None)
        }
    };
    let policy = lock::load_policy(&state_dir);
    let decision = lock::decide(busy, policy, cli.read_only, cli.force);
    if matches!(decision, lock::Decision::Blocked) {
        let who = holder
            .map(|h| format!(" (PID {}, since {})", h.pid, h.since))
            .unwrap_or_default();
        eprintln!(
            "dedcom: another instance is already running{who}.\n\
             Run with --read-only to observe, or terminate that process."
        );
        return Ok(());
    }
    let (read_only, prompt) = match decision {
        lock::Decision::Operator => (false, None),
        lock::Decision::ReadOnly => {
            lock_to_hold = None; // an observer does not hold the operator lock
            (true, None)
        }
        // The role will be chosen in the overlay; until then — read-only mode (safe default).
        lock::Decision::Ask => (true, holder),
        lock::Decision::Blocked => unreachable!("handled above"),
    };

    // Deferred auto-VACUUM: operator only, at startup (no scan running yet),
    // if config.json says it's time (default every 120 h, 0=off). In the background — a
    // VACUUM of a 5+ GB DB is noticeable; busy_timeout keeps it clear of the background
    // session load.
    if !read_only && maint::should_auto_vacuum(&state_dir) {
        let db_path = db_path.clone();
        let state_dir = state_dir.clone();
        std::thread::spawn(move || match maint::vacuum_only(&db_path, &state_dir) {
            Ok(()) => tracing::info!("auto-VACUUM completed"),
            Err(err) => tracing::warn!("auto-VACUUM not completed: {err}"),
        });
    }

    let commander = wants_commander(cli);

    let (tx, rx) = tui::event::channel();
    let presets = model::preset::load_all(&paths::presets_file(cli));

    tui::install_panic_hook();
    let mut guard = tui::TerminalGuard::enter()?;
    // Splash on screen immediately — even before the keyboard-support request.
    let mut tick: u64 = 0;
    guard
        .terminal()
        .draw(|frame| tui::render_splash(frame, tick))?;
    // The keyboard-enhancement request reads the terminal's reply from stdin — it must
    // run BEFORE the input-reading thread is started.
    guard.enable_keyboard_enhancement();
    tui::event::spawn_input_thread(tx.clone());

    // Heavy initialization (ZFS detection, and the session list for the wizard) is moved
    // to a background thread; the splash with a spinner is on screen immediately, so the
    // start doesn't look like a hang and doesn't scale with the volume of data.
    let (boot_tx, boot_rx) = crossbeam_channel::bounded(1);
    {
        let db_path = db_path.clone();
        let no_resume = cli.no_resume;
        std::thread::spawn(move || {
            let zfs = zfs::ZfsEnvironment::detect();
            // The host profile (CPU/RAM/disks/ZFS/inotify) — also here, in the background.
            let host = HostProfile::detect();
            // Commander loads sessions lazily (F12); the classic wizard — immediately.
            let sessions = if commander || no_resume {
                Vec::new()
            } else {
                ScanStore::open(&db_path)
                    .and_then(|store| store.list_scans())
                    .unwrap_or_default()
            };
            let _ = boot_tx.send((zfs, host, sessions));
        });
    }

    let (zfs, host, sessions) = loop {
        tick = tick.wrapping_add(1);
        guard
            .terminal()
            .draw(|frame| tui::render_splash(frame, tick))?;
        match boot_rx.recv_timeout(Duration::from_millis(120)) {
            Ok(boot) => break boot,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                return Err(AppError::msg("initialization interrupted"));
            }
        }
        // Allow exiting via q/Esc while initialization is in progress.
        while let Ok(event) = rx.try_recv() {
            if let AppEvent::Key(key) = event {
                if matches!(
                    key.code,
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc
                ) {
                    return Ok(());
                }
            }
        }
    };

    tracing::info!(
        "ZFS: version={:?}, datasets={}",
        zfs.capabilities.zfs_version,
        zfs.dataset_count()
    );
    for warning in &zfs.warnings {
        tracing::warn!("{warning}");
    }

    tracing::info!("{}", host.summary_line());
    // Intensity-profile recommendation based on the hardware (the default Resource Governor
    // is wired up elsewhere; for now — a log hint).
    let profile_hint = if host.has_fast_storage() {
        "Turbo (SSD/NVMe present)"
    } else if host.all_rotational() {
        "Balanced (all disks HDD)"
    } else {
        "Balanced (disk class undetermined)"
    };
    tracing::info!("recommended intensity profile: {profile_hint}");
    if host.low_inotify_for_watch() {
        tracing::warn!(
            "inotify watch limit is low ({}) — watching large trees will require raising fs.inotify.max_user_watches",
            host.inotify_max_watches
        );
    }
    // Re-validation mode before a destructive action: Strict via `--strict-verify`,
    // otherwise Hybrid (default). Fast is deferred research, unreachable in main.
    let reval_mode = if cli.strict_verify {
        crate::model::action::RevalidationMode::Strict
    } else {
        crate::model::action::RevalidationMode::Hybrid
    };
    let mut app = App::new(
        zfs,
        host,
        db_path,
        tx,
        sessions,
        cli.verify,
        reval_mode,
        presets,
        commander,
        lock::Startup {
            lock: lock_to_hold,
            read_only,
            prompt,
        },
        cli.merkle_dirs,
    );

    while !app.should_quit {
        app.tick = app.tick.wrapping_add(1);
        // Resource sampling before the frame — self-throttles by interval.
        app.resource.sample();
        guard
            .terminal()
            .draw(|frame| tui::render(frame, &mut app))?;

        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => app.handle_event(event),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    tracing::info!("normal shutdown");
    Ok(())
}

/// DedupCommando IS the multi-pane commando, so it is open by default. `--classic` takes you
/// to the classic step-by-step wizard; `--commando` is an explicit synonym for the default
/// (takes priority over `--classic` if both are passed).
fn wants_commander(cli: &cli::Cli) -> bool {
    !cli.force_classic || cli.force_commando
}

/// Acquires the single-instance lock for headless modes that WRITE to the DB/FS
/// (`--scan`/`--compact-db`/`--purge-quarantine`), so there is no concurrent write
/// (including with a running TUI operator). `Ok(Some(guard))` — hold until the end of the
/// operation; `Ok(None)` — `--force`/the `allow` policy / flock unavailable. Held and without
/// `--force` (or `--read-only` given) → `Err` (exit 1). No UI — the `ask` policy collapses to
/// `block`. Read-only modes (`--stats`, `--export-csv`) do not write and do not take the lock.
fn acquire_write_lock(cli: &cli::Cli) -> Result<Option<lock::InstanceLock>> {
    let state_dir = paths::state_dir(cli);
    // Write mode: state-dir 0700 + a check of the whole chain, fail-closed.
    paths::establish_state_dir(&state_dir)?;
    let (busy, holder, guard) = match lock::try_acquire(&state_dir) {
        Ok(lock::Acquire::Operator(g)) => (false, None, Some(g)),
        Ok(lock::Acquire::Busy(h)) => (true, h, None),
        Err(err) => {
            tracing::warn!("single-instance lock unavailable ({err}); continuing without it");
            return Ok(None);
        }
    };
    let policy = lock::load_policy(&state_dir);
    match lock::decide_headless(busy, policy, cli.read_only, cli.force) {
        lock::Decision::Operator => Ok(guard),
        _ => {
            let who = holder
                .map(|h| format!(" (PID {}, since {})", h.pid, h.since))
                .unwrap_or_default();
            Err(AppError::msg(format!(
                "write cancelled{who}: held by another instance or --read-only given — \
                 terminate that process or retry with --force"
            )))
        }
    }
}

/// Headless mode (`--scan`): scanning without the TUI — for testing the pipeline and
/// resumability (kill -9 mid-way, restart -> continuation).
fn run_headless_scan(cli: &cli::Cli) -> Result<()> {
    let mut store = ScanStore::open(&paths::checkpoint_db(cli))?;
    let mut config = ScanConfig::new(cli.scan_roots.clone());
    config.include_extensions = cli.include_extensions.clone();
    config.storage_type_override = cli.storage_type.clone();
    config.reuse_hashes = !cli.no_hash_reuse;
    if cli.merkle_dirs {
        config.dir_sig_algo = crate::model::duplicate::DirSigAlgo::Merkle;
    }

    let resume = if cli.no_resume {
        None
    } else {
        // Resume ONLY an unfinished scan of the SAME roots: find_resumable took the
        // newest ANY scan without checking the roots or the trash filter — `--scan /b` could
        // continue an unfinished `/a` (or one moved to trash). resume_probe_for_roots checks
        // the roots and skips trashed (via list_scans).
        let (unfinished, _complete) = store.resume_probe_for_roots(&config.roots)?;
        match unfinished {
            Some(info) if info.status.is_resumable() => {
                println!(
                    "Resuming unfinished scan #{} from {} ({} / {} files already hashed)",
                    info.scan_id, info.created_at, info.files_hashed, info.files_total
                );
                Some(info.scan_id)
            }
            _ => None,
        }
    };

    let cancel = Arc::new(AtomicBool::new(false));
    // Hashing progress now arrives frequently (by bytes); we print a line only when the file
    // count changes — otherwise the output is overwhelmed.
    let mut last_hashed_files = u64::MAX;
    let print_progress = |progress: ScanProgress| match progress {
        ScanProgress::Phase(phase) => println!("[phase] {phase:?}"),
        ScanProgress::Walked { entries, files, .. } => {
            println!("[walk] entries: {entries}, files: {files}")
        }
        ScanProgress::Hashing {
            files_done,
            files_total,
            bytes_done,
            bytes_total,
            ..
        } => {
            if files_done != last_hashed_files {
                last_hashed_files = files_done;
                println!(
                    "[hash] {files_done}/{files_total} files, {bytes_done}/{bytes_total} bytes"
                );
            }
        }
        ScanProgress::Notice(msg) => println!("{msg}"),
        ScanProgress::Done(_) => {}
    };
    let outcome = pipeline::run_scan(
        &mut store,
        &config,
        resume,
        cli.verify,
        &cancel,
        print_progress,
    )?;

    match outcome {
        ScanOutcome::Completed(results) => {
            println!();
            println!("=== Done ===");
            println!("Files scanned:        {}", results.summary.files_scanned);
            // Candidates without a pinned hash (error/identity) — did NOT take part in
            // duplicate detection. >0 → scan status `complete_with_warnings`.
            println!("Failed to hash:       {}", results.summary.hash_failures);
            println!("Duplicate groups:     {}", results.summary.groups_found);
            println!(
                "Potentially reclaimable: {} bytes",
                results.summary.total_reclaimable_bytes
            );
            println!(
                "Scan time:            {} (speed {})",
                tui::format_duration(results.summary.elapsed_seconds),
                tui::format_speed(
                    results.summary.bytes_hashed,
                    results.summary.elapsed_seconds
                ),
            );
            for summary in results.summaries.iter().take(50) {
                println!(
                    "  #{:<4} {} files x {} bytes",
                    summary.rank, summary.file_count, summary.size_bytes
                );
                // Group members — from the DB on demand (we don't keep them all in RAM).
                if let Ok(files) = store.group_files(results.scan_id, &summary.hash) {
                    for file in &files {
                        println!(
                            "        {}",
                            textsan::terminal(&file.path.display().to_string())
                        );
                    }
                }
            }
            if results.summaries.len() > 50 {
                println!("  ... and {} more groups", results.summaries.len() - 50);
            }
        }
        ScanOutcome::Cancelled => println!("Scan cancelled."),
    }
    Ok(())
}

/// The `--stats` mode: prints statistics for all scans (exportable data).
fn run_stats(cli: &cli::Cli) -> Result<()> {
    let db_path = paths::checkpoint_db(cli);
    let store = ScanStore::open(&db_path)?;

    // DB state: file size + contents — shows where the space went and how
    // much --compact-db will return (trash purge + VACUUM).
    let counts = store.db_counts()?;
    println!("=== DB state ===");
    println!(
        "  file (scan.db + WAL): {}",
        tui::human_bytes(maint::db_size_bytes(&db_path)),
    );
    println!(
        "  sessions: {} (in trash {}) · manifest rows: {}",
        counts.scans, counts.trashed, counts.file_rows,
    );

    let stats = store.list_stats()?;
    if stats.is_empty() {
        println!("\nScan statistics are empty — there hasn't been a single scan yet.");
        return Ok(());
    }

    println!("\n=== Scan statistics ===");
    for row in &stats {
        let roots = row
            .roots
            .iter()
            .map(|root| textsan::terminal(&root.display().to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        println!();
        println!("#{}  {}  [{}]", row.scan_id, row.created_at, row.status);
        println!("  roots:       {roots}");
        println!(
            "  environment: storage={} layout={} ZFS={}",
            row.storage_type, row.pool_layout, row.zfs_version,
        );
        println!(
            "  workload:    files={} volume(hash)={} groups={} reclaimable={} failures(hash)={}",
            row.files_scanned,
            tui::human_bytes(row.bytes_hashed),
            row.groups_found,
            tui::human_bytes(row.reclaimable_bytes),
            row.hash_failures,
        );
        println!(
            "  time:        {} (speed {})",
            tui::format_duration(row.elapsed_seconds),
            tui::format_speed(row.bytes_hashed, row.elapsed_seconds),
        );
    }
    Ok(())
}

/// The `--compact-db` mode: empties the session trash (purges all trashed)
/// and compacts the DB (VACUUM), then exits. Frees space after history has accumulated.
fn run_compact(cli: &cli::Cli) -> Result<()> {
    let db_path = paths::checkpoint_db(cli);
    let state_dir = paths::state_dir(cli);
    println!("Emptying the trash and compacting the DB (VACUUM)…");
    let (purged, before, after) = maint::compact(&db_path, &state_dir)?;
    println!(
        "Done: sessions purged from the trash — {purged}; DB size {} → {}.",
        tui::human_bytes(before),
        tui::human_bytes(after),
    );
    Ok(())
}

/// The `--purge-quarantine` mode: shows the quarantine size across all datasets and deletes
/// it ONLY with `--yes`.
///
/// The size is computed and printed BEFORE deletion; the deletion
/// itself is gated by the `--yes` flag (not stdin — headless must work in a pipe). Without
/// `--yes`, the size is printed and the program exits without deleting (exit 0). ZFS
/// snapshots are an independent safety net; purge does not touch them.
fn run_purge_quarantine(cli: &cli::Cli) -> Result<()> {
    let zfs = zfs::ZfsEnvironment::detect();

    // Estimate across all trash dirs — without deleting anything.
    let mut targets: Vec<(PathBuf, u64, u64)> = Vec::new();
    let mut total_bytes = 0u64;
    let mut total_files = 0u64;
    for pool in &zfs.pools {
        for dataset in &pool.datasets {
            let root = actions::quarantine::quarantine_root(&dataset.mountpoint);
            if !root.is_dir() {
                continue;
            }
            let (bytes, files) = dir_stats(&root);
            total_bytes += bytes;
            total_files += files;
            targets.push((root, bytes, files));
        }
    }

    if targets.is_empty() {
        println!("The quarantine is empty — nothing to purge.");
        return Ok(());
    }

    println!("=== Quarantine to purge ===");
    for (root, bytes, files) in &targets {
        println!(
            "  {} ({} files, {} bytes)",
            textsan::terminal(&root.display().to_string()),
            files,
            bytes
        );
    }
    println!("Total: {total_files} files, {total_bytes} bytes");

    // Gate: apply_purge performs the deletion only with assume_yes (single source).
    let report = apply_purge(&targets, cli.assume_yes);

    if !cli.assume_yes {
        println!();
        println!("Nothing deleted. To confirm, re-run the command with the --yes flag.");
        return Ok(());
    }

    println!(
        "Reclaimed: {} files, {} bytes",
        report.deleted_files, report.deleted_bytes
    );
    if !report.errors.is_empty() {
        for (root, err) in &report.errors {
            eprintln!(
                "ERROR: trash not deleted: {}: {}",
                textsan::terminal(&root.display().to_string()),
                textsan::terminal(err)
            );
        }
        return Err(AppError::msg(format!(
            "failed to purge {} of {} trash dirs (see the messages above)",
            report.errors.len(),
            targets.len()
        )));
    }
    Ok(())
}

/// The outcome of deleting the quarantine trash dirs. Per-root errors are
/// collected, not silently lost.
#[derive(Default)]
struct PurgeReport {
    deleted_files: u64,
    deleted_bytes: u64,
    errors: Vec<(PathBuf, String)>,
}

/// Deletes the quarantine roots `targets` ONLY with `assume_yes` (gate: without confirmation
/// the destructive action is not performed). `remove_dir_all` does NOT follow a symlink — it
/// deletes the link as a link, without traversing its target. An error on any root does not
/// abort the rest and is collected into a report to show to the user.
fn apply_purge(targets: &[(PathBuf, u64, u64)], assume_yes: bool) -> PurgeReport {
    let mut report = PurgeReport::default();
    if !assume_yes {
        return report;
    }
    for (root, bytes, files) in targets {
        match std::fs::remove_dir_all(root) {
            Ok(()) => {
                report.deleted_files += files;
                report.deleted_bytes += bytes;
            }
            Err(err) => report.errors.push((root.clone(), err.to_string())),
        }
    }
    report
}

/// Recursively computes the total size and file count in a directory.
fn dir_stats(dir: &Path) -> (u64, u64) {
    let mut bytes = 0u64;
    let mut files = 0u64;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(file_type) if file_type.is_dir() => {
                    let (sub_bytes, sub_files) = dir_stats(&entry.path());
                    bytes += sub_bytes;
                    files += sub_files;
                }
                Ok(file_type) if file_type.is_file() => {
                    if let Ok(meta) = entry.metadata() {
                        bytes += meta.len();
                        files += 1;
                    }
                }
                _ => {}
            }
        }
    }
    (bytes, files)
}

#[cfg(test)]
mod purge_tests {
    use super::{apply_purge, dir_stats};
    use std::io::Write as _;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_purge_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn dir_stats_sums_bytes_and_files_recursively() {
        let root = temp_dir("stats");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::File::create(root.join("a.bin"))
            .unwrap()
            .write_all(&[0u8; 10])
            .unwrap();
        std::fs::File::create(sub.join("b.bin"))
            .unwrap()
            .write_all(&[0u8; 25])
            .unwrap();
        let (bytes, files) = dir_stats(&root);
        assert_eq!(files, 2);
        assert_eq!(bytes, 35);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn dir_stats_empty_dir_is_zero() {
        let root = temp_dir("empty");
        assert_eq!(dir_stats(&root), (0, 0));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn purge_without_yes_deletes_nothing() {
        // (a) Without --yes the gate deletes nothing; the directory stays in place.
        let base = temp_dir("noyes");
        let q = base.join("quar");
        std::fs::create_dir_all(q.join("sub")).unwrap();
        std::fs::write(q.join("sub/f.bin"), b"x").unwrap();
        let (bytes, files) = dir_stats(&q);
        let report = apply_purge(&[(q.clone(), bytes, files)], false);
        assert!(
            q.is_dir(),
            "without --yes the quarantine must not be deleted"
        );
        assert_eq!((report.deleted_files, report.deleted_bytes), (0, 0));
        assert!(report.errors.is_empty());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn purge_with_yes_removes_only_target_roots() {
        // (b) With --yes ONLY the passed roots are deleted; an unrelated directory is intact.
        let base = temp_dir("yes");
        let q = base.join("quar");
        std::fs::create_dir_all(&q).unwrap();
        std::fs::write(q.join("a.bin"), b"abc").unwrap();
        let sibling = base.join("keep");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("keep.bin"), b"keep").unwrap();
        let (bytes, files) = dir_stats(&q);
        let report = apply_purge(&[(q.clone(), bytes, files)], true);
        assert!(!q.exists(), "the trash dir is deleted");
        assert!(
            sibling.is_dir() && sibling.join("keep.bin").is_file(),
            "the unrelated directory is untouched"
        );
        assert_eq!(report.deleted_files, files);
        assert!(report.errors.is_empty());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn purge_surfaces_partial_errors() {
        // (c) An error on one root is not lost and does not abort the rest.
        let base = temp_dir("partial");
        let good = base.join("good");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::write(good.join("g.bin"), b"g").unwrap();
        // A "root" that is a file (not a directory): remove_dir_all returns an error even as root.
        let bad = base.join("bad_is_a_file");
        std::fs::write(&bad, b"not a dir").unwrap();
        let report = apply_purge(&[(good.clone(), 1, 1), (bad.clone(), 0, 0)], true);
        assert!(
            !good.exists(),
            "the healthy root is deleted despite the error on the other"
        );
        assert_eq!(
            report.errors.len(),
            1,
            "the error on the problematic root is collected"
        );
        assert_eq!(report.errors[0].0, bad);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn purge_does_not_follow_symlinks_out_of_root() {
        // (d) remove_dir_all does not take the deletion outside the root via a symlink.
        let base = temp_dir("symlink");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious.bin"), b"precious").unwrap();
        let q = base.join("quar");
        std::fs::create_dir_all(&q).unwrap();
        std::os::unix::fs::symlink(&outside, q.join("link_to_outside")).unwrap();
        let report = apply_purge(&[(q.clone(), 0, 0)], true);
        assert!(!q.exists(), "the quarantine is deleted");
        assert!(
            outside.is_dir(),
            "the symlink must not take the deletion outside"
        );
        assert!(
            outside.join("precious.bin").is_file(),
            "the external file survived"
        );
        assert!(report.errors.is_empty());
        std::fs::remove_dir_all(&base).ok();
    }
}

/// The `--export-csv` mode: exports the duplicate groups of the last scan to CSV.
/// Works for an unfinished scan too — the already-hashed files are taken.
fn run_export_csv(cli: &cli::Cli, out_path: &Path) -> Result<()> {
    let store = ScanStore::open(&paths::checkpoint_db(cli))?;
    let info = store
        .find_resumable()?
        .ok_or_else(|| AppError::msg("no saved scan"))?;
    let groups = store.duplicate_groups(info.scan_id)?;

    let mut csv = String::from("group,keep,size_bytes,hash,path\n");
    let mut file_rows = 0u64;
    for group in &groups {
        // The default keeper is the file with the freshest mtime.
        let keeper = group
            .files
            .iter()
            .enumerate()
            .max_by_key(|(_, file)| file.mtime)
            .map(|(index, _)| index)
            .unwrap_or(0);
        for (index, file) in group.files.iter().enumerate() {
            let keep = if index == keeper { 1 } else { 0 };
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                group.id,
                keep,
                file.size,
                group.hash,
                csv_field(&file.path.to_string_lossy()),
            ));
            file_rows += 1;
        }
    }

    std::fs::write(out_path, csv)?;
    println!(
        "Exported {} groups ({} files), scan status: {} -> {}",
        groups.len(),
        file_rows,
        info.status.as_str(),
        textsan::terminal(&out_path.display().to_string())
    );
    Ok(())
}

/// CSV field escaping per RFC 4180 (quotes, commas, line breaks) with formula-injection
/// neutralization (CWE-1236).
///
/// Excel/LibreOffice execute a cell as a formula if it starts with `= + - @` or the control
/// characters `\t`/`\r`. A file name on /tank can set such a first character; opening the
/// export, the operator would run the formula. Before RFC quoting we prefix an apostrophe
/// (OWASP) — the cell is treated as text. Defense-in-depth: exported paths are usually
/// absolute (leading `/`), but we harden the helper in the general case.
fn csv_field(value: &str) -> String {
    let guarded = if value
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'))
    {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[cfg(test)]
mod csv_tests {
    use super::csv_field;

    #[test]
    fn formula_lead_chars_are_prefixed_with_apostrophe() {
        assert_eq!(csv_field("=cmd"), "'=cmd");
        assert_eq!(csv_field("+1"), "'+1");
        assert_eq!(csv_field("-2+3"), "'-2+3");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_field("\tx"), "'\tx");
    }

    #[test]
    fn normal_path_is_unchanged() {
        assert_eq!(csv_field("/tank/ordinary.bin"), "/tank/ordinary.bin");
    }

    #[test]
    fn comma_still_rfc_quoted() {
        assert_eq!(csv_field("/tank/a,b.bin"), "\"/tank/a,b.bin\"");
    }

    #[test]
    fn formula_and_comma_compose() {
        // The apostrophe is placed BEFORE RFC quoting; both protections work together.
        assert_eq!(csv_field("=a,b"), "\"'=a,b\"");
    }
}
