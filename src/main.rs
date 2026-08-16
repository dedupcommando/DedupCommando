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
mod panics;
mod paths;
mod pipeline;
mod scan;
mod signals;
mod state;
mod sysmon;
/// Shared test fixtures (hardlink forest, content-read counting). Test builds only.
#[cfg(test)]
mod testfixtures;
mod textsan;
mod tui;
mod zfs;

use std::path::{Path, PathBuf};
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

    // Signal handlers are installed per mode, NOT here: a mode that catches a signal without
    // checking the cancel flag would simply swallow it and become unkillable by SIGTERM.
    // `--compact-db` and `--purge-quarantine` have no cancellation of their own, so they keep
    // the default disposition and die promptly, as before.

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

/// The classic wizard's eager session load, run on the boot thread.
///
/// Fail-closed by construction: the only empty list it can produce is the deliberate skip for the
/// commander and for `--no-resume`, which load lazily or not at all. A checkpoint that refuses to
/// open returns its own error, which travels the boot channel and becomes `run_tui`'s error — an
/// unreadable database must never reach the operator as a wizard with no saved scans.
fn boot_session_load(
    db_path: &std::path::Path,
    commander: bool,
    no_resume: bool,
) -> Result<Vec<model::scan::ResumeInfo>> {
    if commander || no_resume {
        return Ok(Vec::new());
    }
    ScanStore::open(db_path).and_then(|store| store.list_scans())
}

/// Interactive mode: the TUI with a background scan worker.
fn run_tui(cli: &cli::Cli) -> Result<()> {
    // The event loop checks for an arrived signal every iteration and turns it into the same
    // cancellation Esc uses, so catching them here does not swallow them.
    signals::install();
    // Before the first background thread is started, so none of them can panic outside the hook's
    // reach and leave the splash drawing over the message.
    tui::install_panic_hook();
    let db_path = paths::checkpoint_db(cli);
    let state_dir = paths::state_dir(cli);
    // The state directory may not exist on the first run — we create it ahead at 0700
    // (for the lock file and consent.json) with a check of the whole parent chain.
    // Fail-closed: on an untrusted chain (foreign/group-writable ancestor) we refuse to
    // operate.
    paths::establish_state_dir(&state_dir)?;

    // Single-instance lock: acquiring the advisory flock = the OPERATOR role;
    // held by another live instance → the role is decided by the policy + CLI flags.
    let (lock_state, holder, mut lock_to_hold) = match lock::try_acquire(&state_dir) {
        Ok(lock::Acquire::Operator(guard)) => (lock::LockState::Held, None, Some(guard)),
        Ok(lock::Acquire::Busy(h)) => (lock::LockState::Busy, h, None),
        Err(err) => {
            // NOT «continue as operator»: we have no idea whether one is already running.
            tracing::warn!("single-instance lock could not be evaluated: {err}");
            (lock::LockState::Unknown, None, None)
        }
    };
    let policy = lock::load_policy(&state_dir);
    let decision = lock::decide(lock_state, policy, cli.read_only, cli.force);
    if matches!(decision, lock::Decision::Blocked) {
        if lock_state == lock::LockState::Unknown {
            eprintln!(
                "dedcom: cannot verify the single-instance lock in {}.\n\
                 Refusing to start as the operator: two operators on one state can apply\n\
                 destructive plans at the same time. A network filesystem without lockd cannot\n\
                 provide the lock — put the state directory on local storage (--state-dir),\n\
                 run with --read-only to observe, or with --force to proceed anyway.",
                textsan::terminal(&state_dir.display().to_string())
            );
            return Ok(());
        }
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

    // The role decided above is what makes read-only real: from here on every ScanStore::open in
    // this process hands back a query_only connection, so an observer cannot write marks — or
    // anything else — even through a path that forgot to ask.
    state::set_observer_role(read_only);

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

    // Results are prepared by the WRITER: the operator brings every completed scan that predates
    // the marker up to date at startup, so an observer only ever reads. In the background —
    // aggregating an old multi-million-row manifest is not instant.
    if !read_only {
        let db_path = db_path.clone();
        std::thread::spawn(move || {
            match ScanStore::open(&db_path).and_then(|mut store| store.prepare_completed_scans()) {
                Ok(0) => {}
                Ok(n) => tracing::info!("prepared results of {n} completed scan(s)"),
                Err(err) => tracing::warn!("preparing completed scans failed: {err}"),
            }
        });
    }

    let commander = wants_commander(cli);

    let (tx, rx) = tui::event::channel();
    let presets = model::preset::load_all(&paths::presets_file(cli));

    let mut guard = tui::TerminalGuard::enter()?;
    // Splash on screen immediately — even before the keyboard-support request.
    let mut tick: u64 = 0;
    // A startup thread (auto-VACUUM, preparing results) may already have panicked: the hook has
    // restored the terminal, so the splash must not paint over the message either.
    if panics::tui_dead() {
        return Err(panic_shutdown_error());
    }
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
            let sessions = boot_session_load(&db_path, commander, no_resume);
            let _ = boot_tx.send((zfs, host, sessions));
        });
    }

    let (zfs, host, sessions) = loop {
        if panics::tui_dead() {
            return Err(panic_shutdown_error());
        }
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

    // The boot session load is fail-closed: its error is the run's error. `main` prefixes it with
    // `dedcom: error: ` and exits non-zero, so an unreadable checkpoint can never present itself
    // as a wizard with no saved scans.
    let sessions = sessions?;

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

    let mut panicked = false;
    while !app.should_quit {
        // A signal arrived: arm the same cancellation Esc uses and leave once the current action
        // is done. A second signal means the operator has stopped waiting.
        if signals::requested() {
            app.request_shutdown(signals::count() > 1);
        }
        // A thread panicked. The hook has already given the terminal back to the shell and printed
        // the message, so another frame would only scribble over it. We leave the same way a signal
        // does — the batch in flight still has its snapshot and quarantine to finish into, and
        // keys still work if the operator would rather quit now.
        if panics::tui_dead() {
            if !panicked {
                panicked = true;
                eprintln!("dedcom: a background thread panicked — finishing the current action, then exiting");
            }
            app.request_shutdown(false);
        }
        app.tick = app.tick.wrapping_add(1);
        // Resource sampling before the frame — self-throttles by interval.
        app.resource.sample();
        if !panicked {
            guard
                .terminal()
                .draw(|frame| tui::render(frame, &mut app))?;
        }

        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => app.handle_event(event),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    if panicked {
        return Err(panic_shutdown_error());
    }
    tracing::info!("normal shutdown");
    Ok(())
}

/// A panic in a background thread has already restored the terminal and printed its message, so
/// nothing may be drawn afterwards — and the process must not pretend it exited cleanly.
fn panic_shutdown_error() -> AppError {
    AppError::msg("a background thread panicked — see the message above")
}

#[cfg(test)]
mod startup_order_tests {
    /// The hook is what tells the loop the screen is gone, so a thread started before it is
    /// installed can panic outside its reach — auto-VACUUM and the results preparation both start
    /// long before the terminal is entered. Only source order can hold this, hence the guard.
    #[test]
    fn the_panic_hook_is_installed_before_the_first_background_thread() {
        let after_run_tui = include_str!("main.rs")
            .split_once("fn run_tui")
            .expect("run_tui must exist")
            .1;
        let hook = after_run_tui
            .find("install_panic_hook()")
            .expect("run_tui must install the panic hook");
        let spawn = after_run_tui
            .find("thread::spawn")
            .expect("run_tui must start background threads");
        assert!(
            hook < spawn,
            "the panic hook must be installed before the first background thread"
        );
    }
}

/// DedupCommando IS the multi-pane commando, so it is open by default. `--classic` takes you
/// to the classic step-by-step wizard; `--commando` is an explicit synonym for the default
/// (takes priority over `--classic` if both are passed).
fn wants_commander(cli: &cli::Cli) -> bool {
    !cli.force_classic || cli.force_commando
}

/// Acquires the single-instance lock for headless modes that WRITE to the DB/FS
/// (`--scan`/`--compact-db`/`--purge-quarantine`), so there is no concurrent write
/// (including with a running TUI operator). `Ok(Some(guard))` — the lock is ours, hold it until
/// the end of the operation; `Ok(None)` — proceeding deliberately without one, which now means
/// only `--force`, or the `allow` policy against a *known* holder. Everything else is an `Err`
/// (exit 1): a holder without `--force`, `--read-only`, and a lock that could not be evaluated
/// at all. No UI — the `ask` policy collapses to `block`. Read-only modes (`--stats`,
/// `--export-csv`) do not write and do not take the lock.
fn acquire_write_lock(cli: &cli::Cli) -> Result<Option<lock::InstanceLock>> {
    let state_dir = paths::state_dir(cli);
    // Write mode: state-dir 0700 + a check of the whole chain, fail-closed.
    paths::establish_state_dir(&state_dir)?;
    let (lock_state, holder, guard) = match lock::try_acquire(&state_dir) {
        Ok(lock::Acquire::Operator(g)) => (lock::LockState::Held, None, Some(g)),
        Ok(lock::Acquire::Busy(h)) => (lock::LockState::Busy, h, None),
        Err(err) => {
            // Used to return Ok(None) — the write then proceeded with no lock whatsoever.
            tracing::warn!("single-instance lock could not be evaluated: {err}");
            (lock::LockState::Unknown, None, None)
        }
    };
    let policy = lock::load_policy(&state_dir);
    match lock::decide_headless(lock_state, policy, cli.read_only, cli.force) {
        lock::Decision::Operator => Ok(guard),
        _ if lock_state == lock::LockState::Unknown => Err(AppError::msg(format!(
            "write cancelled: cannot verify the single-instance lock in {} — \
             put the state directory on local storage (a network filesystem without lockd \
             cannot provide the lock), or retry with --force",
            textsan::terminal(&state_dir.display().to_string())
        ))),
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

    // The scan checks the flag at phase and chunk boundaries, so it is safe to catch signals
    // here. Watch the signal flag itself: this used to be a freshly created flag that nothing
    // ever armed, so Ctrl+C could not stop a headless scan.
    signals::install();
    let cancel = signals::shutdown_flag();
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
        cancel,
        print_progress,
    )?;

    match outcome {
        ScanOutcome::Completed(results) => {
            println!();
            println!("=== Done ===");
            for line in completion_lines(&results.summary) {
                println!("{line}");
            }
            list_published_groups(&store, results.scan_id)?;
        }
        ScanOutcome::Cancelled => println!("Scan cancelled."),
    }
    Ok(())
}

/// How many groups the headless listing prints in full.
const HEADLESS_GROUP_LIMIT: usize = 50;

/// Prints the scan's published groups and their members, through the membership authority.
///
/// Identity, not digest: each group is opened by its own `GroupId`, so two verified
/// populations that happen to share a digest stay two groups and a pathname verification
/// rejected has no member row to be printed from. A refusal is printed and returned as an
/// error — the caller exits non-zero — because an empty listing and an unreadable checkpoint
/// must never look the same. A scan with no published authority is not a failure: it says so
/// in the accepted wording and prints nothing it cannot vouch for.
fn list_published_groups(store: &ScanStore, scan_id: i64) -> Result<()> {
    let miss = |miss: state::MembershipMiss| {
        AppError::msg(format!(
            "scan {scan_id}: the published results could not be read ({miss:?})"
        ))
    };
    let snapshot = store.membership_snapshot(scan_id).map_err(miss)?;
    if snapshot.mode() == state::MembershipMode::Unknown {
        println!("  results not published — rescan required");
        if let Some(view) = snapshot.unknown_candidates().map_err(miss)? {
            println!(
                "  ({} candidate digests, unverified)",
                view.candidates.len()
            );
        }
        return Ok(());
    }
    let summaries = snapshot.summaries().map_err(miss)?;
    for (id, summary) in summaries.groups.iter().take(HEADLESS_GROUP_LIMIT) {
        println!(
            "  #{:<4} {} files x {} bytes",
            id.rank, summary.file_count, summary.size_bytes
        );
        // Members on demand, by identity — never every group's rows at once.
        let group = snapshot
            .group_page(id, 0, summary.file_count as usize)
            .map_err(miss)?;
        for file in &group.members {
            println!(
                "        {}",
                textsan::terminal(&file.path.display().to_string())
            );
        }
    }
    if summaries.groups.len() > HEADLESS_GROUP_LIMIT {
        println!(
            "  ... and {} more groups",
            summaries.groups.len() - HEADLESS_GROUP_LIMIT
        );
    }
    // Named, never repaired: a group whose summary and membership disagree is reported by
    // identity instead of being listed as if it were answerable.
    for id in &summaries.inconsistent {
        println!(
            "  #{:<4} unavailable — its summary and membership disagree",
            id.rank
        );
    }
    Ok(())
}

/// The `--stats` mode: prints statistics for all scans (exportable data).
fn run_stats(cli: &cli::Cli) -> Result<()> {
    let db_path = paths::checkpoint_db(cli);
    // Reporting only: never create a missing DB, flip WAL, migrate, or touch permissions —
    // `--stats` may well run beside a live operator.
    let store = ScanStore::open_read_only(&db_path)?;

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
        for line in stats_lines(row) {
            println!("{line}");
        }
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

/// The headless write path itself, not just the pure decision: this is where an unevaluable
/// lock used to turn into `Ok(None)` and let the write proceed unlocked.
#[cfg(test)]
mod acquire_write_lock_tests {
    use super::{acquire_write_lock, cli};
    use std::path::{Path, PathBuf};

    fn temp_state_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_awl_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cli_for(dir: &Path, force: bool) -> cli::Cli {
        cli::Cli {
            state_dir: Some(dir.to_path_buf()),
            force,
            ..Default::default()
        }
    }

    #[test]
    fn unevaluable_lock_refuses_the_write_even_with_allow_policy() {
        let dir = temp_state_dir("unevaluable");
        // A directory where the lock file belongs: opening it read-write fails with EISDIR, so
        // try_acquire returns Err — the same shape as ENOLCK on a filesystem without lockd.
        std::fs::create_dir_all(dir.join("dedcom.lock")).unwrap();
        // The most permissive policy there is must not buy a way past it.
        std::fs::write(dir.join("config.json"), br#"{"concurrency":"allow"}"#).unwrap();

        // `match` rather than expect_err: the Ok side holds a lock guard, which is not Debug.
        let err = match acquire_write_lock(&cli_for(&dir, false)) {
            Ok(_) => panic!("an unevaluable lock must refuse the write"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains(&dir.display().to_string()),
            "the message must name the state directory, got: {err}"
        );
        assert!(
            err.contains("--force"),
            "the message must offer --force, got: {err}"
        );

        // --force is the one documented way through, and it holds no guard.
        let forced = match acquire_write_lock(&cli_for(&dir, true)) {
            Ok(guard) => guard,
            Err(err) => panic!("--force must proceed, got: {err}"),
        };
        assert!(
            forced.is_none(),
            "there is no lock to hold when flock cannot be evaluated"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_free_lock_is_acquired_and_held() {
        let dir = temp_state_dir("free");
        let guard = match acquire_write_lock(&cli_for(&dir, false)) {
            Ok(guard) => guard,
            Err(err) => panic!("a free lock must be acquired, got: {err}"),
        };
        assert!(guard.is_some(), "the guard must be held for the write");
        drop(guard);
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// `--stats` and `--export-csv` report on the checkpoint; they must never change it.
#[cfg(test)]
mod headless_readonly_tests {
    use super::{cli, paths, run_export_csv, run_stats};
    use crate::state::{schema, ScanStore};
    use std::path::{Path, PathBuf};

    fn temp_state_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_hro_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cli_for(dir: &Path) -> cli::Cli {
        cli::Cli {
            state_dir: Some(dir.to_path_buf()),
            ..Default::default()
        }
    }

    #[test]
    fn reporting_modes_do_not_create_a_missing_db() {
        let dir = temp_state_dir("missing");
        let cli = cli_for(&dir);
        let db = paths::checkpoint_db(&cli);
        assert!(!db.exists());

        assert!(run_stats(&cli).is_err(), "--stats needs an existing DB");
        assert!(!db.exists(), "--stats must not create dedcom.db");

        let out = dir.join("export.csv");
        assert!(run_export_csv(&cli, &out).is_err());
        assert!(!db.exists(), "--export-csv must not create dedcom.db");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reporting_modes_refuse_an_old_schema_without_migrating_it() {
        let dir = temp_state_dir("oldschema");
        let cli = cli_for(&dir);
        let db = paths::checkpoint_db(&cli);
        drop(ScanStore::open_writable(&db).unwrap());
        let old = schema::SCHEMA_VERSION - 1;
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.pragma_update(None, "user_version", old).unwrap();
        }

        let err = run_stats(&cli).unwrap_err().to_string();
        assert!(
            err.contains("older schema"),
            "the reason must be plain, got: {err}"
        );
        assert!(run_export_csv(&cli, &dir.join("export.csv")).is_err());

        let after: i64 = rusqlite::Connection::open(&db)
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, old, "a reporting mode must not migrate the DB");

        std::fs::remove_dir_all(&dir).ok();
    }
}

/// What the headless run prints when a scan completes.
///
/// A function rather than a run of `println!` so the wording can be asserted: the whole point of
/// this reporting is that every surface says the same thing about the same result, and a claim
/// nothing tests is a claim waiting to drift.
fn completion_lines(summary: &model::scan::ScanSummary) -> Vec<String> {
    let mut lines = vec![
        format!("Files scanned:        {}", summary.files_scanned),
        // Candidates without a pinned hash (error/identity) — did NOT take part in
        // duplicate detection. >0 → scan status `complete_with_warnings`.
        format!("Failed to hash:       {}", summary.hash_failures),
        format!("Duplicate groups:     {}", summary.groups_found),
        format!("Already linked sets:  {}", summary.already_linked_sets),
        format!(
            "Reclaim:              {}",
            tui::reclaim_phrase(summary.reclaim)
        ),
        format!(
            "Scan time:            {} (speed {})",
            tui::format_duration(summary.elapsed_seconds),
            tui::format_speed(summary.bytes_hashed, summary.elapsed_seconds),
        ),
    ];
    // The omission account, with its provenance: exact from the ledger, session-only when the
    // roots carry no authority, or honestly not retained.
    let counted = |totals: &model::omission::OmissionSummary, suffix: &str| match (
        totals.known_omitted_files(),
        totals.unsupported_entries(),
    ) {
        (Ok(files), Ok(entries)) => format!(
            "Omissions:            {} files, {} walk errors, {} unsupported entries{}",
            files,
            totals.unknown_cardinality_events(),
            entries,
            suffix,
        ),
        _ => "Omissions:            totals overflow what can be printed".to_string(),
    };
    match &summary.omissions {
        model::scan::OmissionAccounting::Ledger(totals) => lines.push(counted(totals, "")),
        model::scan::OmissionAccounting::Observed(totals) => {
            lines.push(counted(totals, " (session only — not persisted)"))
        }
        model::scan::OmissionAccounting::Unavailable => {
            lines.push("Omissions:            details not retained".to_string())
        }
    }
    lines
}

/// The per-scan block of the `--stats` report, for the same reason.
fn stats_lines(row: &model::scan::ScanStatsRow) -> Vec<String> {
    vec![
        format!(
            "  workload:    files={} volume(hash)={} groups={} already-linked-sets={} failures(hash)={}",
            row.files_scanned,
            tui::human_bytes(row.bytes_hashed),
            row.groups_found,
            row.already_linked_sets,
            row.hash_failures,
        ),
        format!("  reclaim:     {}", tui::reclaim_phrase(row.reclaim)),
        format!(
            "  time:        {} (speed {})",
            tui::format_duration(row.elapsed_seconds),
            tui::format_speed(row.bytes_hashed, row.elapsed_seconds),
        ),
    ]
}

#[cfg(test)]
mod reporting_tests {
    use super::*;
    use model::reclaim::ReclaimEstimate;
    use model::scan::{ScanStatsRow, ScanSummary};

    fn summary(reclaim: ReclaimEstimate) -> ScanSummary {
        ScanSummary {
            files_scanned: 6,
            groups_found: 1,
            reclaim,
            already_linked_sets: 2,
            bytes_hashed: 4096,
            elapsed_seconds: 1.0,
            hash_failures: 0,
            ..Default::default()
        }
    }

    fn stats_row(reclaim: ReclaimEstimate) -> ScanStatsRow {
        ScanStatsRow {
            scan_id: 1,
            created_at: "2026-07-31 00:00:00".to_string(),
            status: "complete".to_string(),
            roots: vec![PathBuf::from("/x")],
            elapsed_seconds: 1.0,
            storage_type: "ssd".to_string(),
            pool_layout: "mirror".to_string(),
            zfs_version: "2.3.1".to_string(),
            files_scanned: 6,
            bytes_hashed: 4096,
            groups_found: 1,
            reclaim,
            already_linked_sets: 2,
            hash_failures: 0,
        }
    }

    /// Headless says what the browser says: the state-aware phrase and the already-linked count,
    /// through the same formatter.
    #[test]
    fn headless_completion_states_the_reclaim_and_never_calls_a_bound_free() {
        let exact = completion_lines(&summary(ReclaimEstimate::exact(4096))).join("\n");
        assert!(
            exact.contains("Reclaim:              guaranteed after quarantine purge: 4.0 KiB"),
            "{exact}"
        );
        assert!(exact.contains("Already linked sets:  2"), "{exact}");

        let bounded = completion_lines(&summary(ReclaimEstimate::upper_bound(4096))).join("\n");
        assert!(
            bounded.contains("guaranteed after quarantine purge: 0 B")
                && bounded.contains("up to 4.0 KiB after quarantine purge"),
            "an upper bound must state both halves: {bounded}"
        );
        assert!(
            !bounded.contains("free"),
            "an upper bound is never labelled freed: {bounded}"
        );

        let unknown = completion_lines(&summary(ReclaimEstimate::unknown())).join("\n");
        assert!(
            unknown.contains("Reclaim:              rescan required"),
            "{unknown}"
        );
        assert!(
            !unknown.contains("KiB") && !unknown.contains(" B"),
            "an unestablished result offers no number: {unknown}"
        );
    }

    /// `--stats` reports the same three shapes in the same words.
    #[test]
    fn stats_report_states_the_reclaim_in_the_same_words() {
        let exact = stats_lines(&stats_row(ReclaimEstimate::exact(4096))).join("\n");
        assert!(
            exact.contains("reclaim:     guaranteed after quarantine purge: 4.0 KiB"),
            "{exact}"
        );
        assert!(exact.contains("already-linked-sets=2"), "{exact}");

        let bounded = stats_lines(&stats_row(ReclaimEstimate::upper_bound(4096))).join("\n");
        assert!(
            bounded.contains("up to 4.0 KiB after quarantine purge") && !bounded.contains("free"),
            "{bounded}"
        );
        let unknown = stats_lines(&stats_row(ReclaimEstimate::unknown())).join("\n");
        assert!(
            unknown.contains("reclaim:     rescan required"),
            "{unknown}"
        );
    }
}

/// The header of the trusted export. The first five columns are the original ones, in their
/// original order and meaning, so a consumer reading them positionally keeps working; everything
/// the physical model needs is appended after them.
const EXPORT_HEADER: &str =
    "group,keep,size_bytes,hash,path,scan_id,generation,device,inode,links,mark,keep_source\n";

/// The export's write buffer. One named constant rather than a default nobody can point at: the
/// only unbounded thing in the export would be the writer, and this is its bound.
const EXPORT_WRITER_CAPACITY: usize = 256 * 1024;

/// The `--export-csv` mode: exports one finished scan's published groups to CSV.
///
/// Trusted, or nothing. The rows come from the membership authority — the same one the browser
/// and the destructive plan obey — so a pathname byte verification rejected can no longer appear,
/// two Explicit ranks of one digest stay two groups, and the operator's durable marks are what
/// the `keep` column says. A scan without that authority, or one that has not finished, is a
/// refusal that leaves the operator's destination exactly as it was.
///
/// Read-only, and still without the instance lock: it opens the checkpoint read-only, writes only
/// its own artifact, and takes one consistent snapshot rather than a lock.
fn run_export_csv(cli: &cli::Cli, out_path: &Path) -> Result<()> {
    // The destination directory is opened ONCE, here, and every step below acts on that handle.
    // Both halves matter. The protected-state check has to compare directory OBJECTS, because a
    // bind mount gives one directory two canonical paths and comparing spellings let an alias of
    // the state directory through — the checkpoint was replaced that way. And the publication has
    // to rename inside the same opened directory, so the parent cannot be re-pointed between the
    // check and the rename.
    let (dir_path, artifact_name) = destination_parts(out_path)?;
    let parent = paths::DirHandle::open(&dir_path).map_err(|err| {
        AppError::msg(format!(
            "the directory for the export does not exist or cannot be opened: {} ({err})",
            textsan::terminal(&dir_path.display().to_string())
        ))
    })?;
    refuse_dedcoms_own_state(cli, &parent, &artifact_name, out_path)?;
    // Test seam: anything that could re-point the destination pathname lands exactly here, after
    // the check and before the publication. The handle above is what publishes, so a swap must
    // not move the artifact.
    #[cfg(test)]
    take_export_parent_swap();

    // Export reads the checkpoint and writes only the CSV — same read-only contract as --stats.
    let store = ScanStore::open_read_only(&paths::checkpoint_db(cli))?;
    // Every eligibility refusal happens here, BEFORE any file exists: a destination that already
    // holds yesterday's export must survive today's refusal byte for byte.
    let session = store.open_trusted_export()?;

    let mut artifact = TempArtifact::create(parent, &artifact_name)?;
    let totals = {
        let mut writer =
            std::io::BufWriter::with_capacity(EXPORT_WRITER_CAPACITY, artifact.file_mut());
        write_export(&mut writer, &session.snapshot)?
    };
    artifact.publish()?;

    println!(
        "Exported {} groups ({} files) from scan {}, status: {} -> {}",
        totals.groups,
        totals.rows,
        session.scan_id,
        session.status.as_str(),
        textsan::terminal(&out_path.display().to_string())
    );
    Ok(())
}

/// Writes the header and every group, one group at a time, and flushes what it wrote.
fn write_export(
    writer: &mut std::io::BufWriter<&mut std::fs::File>,
    snapshot: &state::store::MembershipSnapshot<'_>,
) -> Result<state::store::ExportTotals> {
    use std::io::Write as _;
    writer.write_all(EXPORT_HEADER.as_bytes())?;
    let totals = snapshot.for_each_export_group(|group| {
        write_export_group(writer, group)?;
        // Test seam: fires only after a whole group has reached the temporary file, which is what
        // makes «the failure happened mid-write» a fact rather than a hope.
        #[cfg(test)]
        {
            let fault = take_export_write_fault();
            if fault != ExportFault::None {
                writer.flush()?;
                let len = writer
                    .get_ref()
                    .metadata()
                    .map(|meta| meta.len())
                    .unwrap_or(0);
                record_export_fault_len(len);
                if fault == ExportFault::Panic {
                    panic!("injected export panic");
                }
                return Err(AppError::msg("injected export write fault"));
            }
        }
        Ok(())
    })?;
    writer.flush()?;
    Ok(totals)
}

/// One group's rows, with the keeper rule applied to the group as a whole.
///
/// The rule, in the order it is applied: durable keeper marks win and there may be several of
/// them; action marks are never turned into keepers; only when no keeper mark exists at all is a
/// keeper computed, and then only among the members the operator left unmarked. A group with no
/// keeper mark and no unmarked member has no survivor to name — and a CSV whose every row of a
/// group says `keep=0` reads, to any consumer of the original five columns, as permission to
/// delete every copy. That file is not written.
fn write_export_group(
    writer: &mut impl std::io::Write,
    group: &state::store::ExportGroup,
) -> Result<()> {
    let marked_keeper = |member: &state::store::ExportMember| {
        matches!(member.mark, Some(crate::model::plan::MarkIntent::Keeper))
    };
    let has_keeper_mark = group.members.iter().any(marked_keeper);
    // Deterministic and total: mtime, then its nanoseconds, then the pathname. `max_by_key`
    // alone returns the LAST maximum, which would make the answer depend on row arrival.
    let fallback = if has_keeper_mark {
        None
    } else {
        group
            .members
            .iter()
            .enumerate()
            .filter(|(_, member)| member.mark.is_none())
            .max_by(|(_, left), (_, right)| {
                left.mtime
                    .cmp(&right.mtime)
                    .then(left.mtime_nsec.cmp(&right.mtime_nsec))
                    .then(left.path.cmp(&right.path))
            })
            .map(|(index, _)| index)
    };
    if !has_keeper_mark && fallback.is_none() {
        return Err(AppError::msg(format!(
            "group {} of scan {} has every pathname marked for an action and no keeper — a CSV \
             of that group would read as «delete every copy». Mark a keeper (F7) or clear one \
             action, then export again. Nothing was written.",
            group.id.rank, group.id.scan_id
        )));
    }
    for (index, member) in group.members.iter().enumerate() {
        let keep = marked_keeper(member) || fallback == Some(index);
        let mark = match member.mark {
            Some(crate::model::plan::MarkIntent::Keeper) => "keeper",
            Some(crate::model::plan::MarkIntent::Act(kind)) => kind.as_str(),
            None => "",
        };
        // Where THIS row's `keep` came from: its own durable mark, or the operator's keeper
        // elsewhere in the group — both `mark`; the computed fallback — `default`.
        let keep_source = if has_keeper_mark || member.mark.is_some() {
            "mark"
        } else {
            "default"
        };
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            group.id.rank,
            u8::from(keep),
            member.size,
            csv_field(&group.hash),
            csv_field(&member.path.to_string_lossy()),
            group.id.scan_id,
            group.id.generation,
            member.device,
            member.inode,
            member.links,
            mark,
            keep_source,
        )?;
    }
    Ok(())
}

/// The uncommitted export artifact: a temporary file in the destination's own directory, owned by
/// a guard that removes it unless the publication succeeded.
///
/// Cleanup is a mechanism here, not an intention. Every early return — a refusal from the reader,
/// a write error, a corrupt mark discovered halfway through — and every unwind runs `Drop`, so
/// there is no path on which a half-written file survives under a name that looks finished. What
/// `Drop` cannot cover is stated rather than implied: `process::abort`, a panic while panicking
/// and `SIGKILL` leave the temporary behind. It is inert — it never carries the destination's
/// name, it is mode 0600, nothing in this product reads it, and the next export claims a fresh
/// name.
struct TempArtifact {
    dir: paths::DirHandle,
    temp: std::ffi::OsString,
    dest: std::ffi::OsString,
    file: std::fs::File,
    armed: bool,
}

/// Splits a destination into the directory that will hold it and the name it will carry.
fn destination_parts(dest: &Path) -> Result<(PathBuf, std::ffi::OsString)> {
    let Some(name) = dest.file_name() else {
        return Err(AppError::msg(format!(
            "{} does not name a file to write",
            textsan::terminal(&dest.display().to_string())
        )));
    };
    let dir = match dest.parent() {
        Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    };
    Ok((dir, name.to_os_string()))
}

/// Refuses a destination that IS one of dedcom's own live state entries.
///
/// Two questions, and both have to be about objects rather than spellings. Is the name one of the
/// five (compared without ASCII case, because a case-insensitive dataset resolves `DEDCOM.DB` to
/// the checkpoint)? And is the already-opened parent the same directory OBJECT as the state
/// directory — which a bind mount, a second mount of the same filesystem, a symlink or a `..`
/// spelling all are, while their canonical paths differ.
///
/// If the name is protected and the comparison cannot be made — the state directory will not open,
/// or the two handles will not answer about their identity — it refuses. This is the one question
/// where «could not tell» must not mean «go ahead»: the error can be transient, the state path can
/// change between this check and the database open, and the thing at stake is every scan the
/// operator has ever run. An ordinary destination name is unaffected either way; reporting a
/// missing checkpoint stays the database open's job.
fn refuse_dedcoms_own_state(
    cli: &cli::Cli,
    parent: &paths::DirHandle,
    name: &std::ffi::OsStr,
    dest: &Path,
) -> Result<()> {
    let Some(entry) = name.to_str().and_then(paths::protected_state_entry_name) else {
        return Ok(());
    };
    let state_dir = paths::state_dir(cli);
    let state = paths::DirHandle::open(&state_dir).map_err(|err| {
        AppError::msg(format!(
            "{} is named {entry}, and whether {} is dedcom's state directory could not be \
             established ({err}). Refusing rather than risking the checkpoint; nothing was \
             written.",
            textsan::terminal(&dest.display().to_string()),
            textsan::terminal(&state_dir.display().to_string()),
        ))
    })?;
    if parent.is_same_object(&state).unwrap_or(true) {
        return Err(AppError::msg(format!(
            "{} is dedcom's own {entry} — that directory IS the state directory, whatever the \
             path says. Exporting over it would destroy the checkpoint or the lock a running \
             instance holds. Choose another destination; nothing was written.",
            textsan::terminal(&dest.display().to_string())
        )));
    }
    Ok(())
}

/// Upper bound on create-and-retry repetitions for the temporary name; a backstop against an
/// infinite loop, never reached in practice (the base carries the pid and nanoseconds).
const MAX_TEMP_CLAIM_RETRIES: u32 = 1_000;

impl TempArtifact {
    /// Claims a temporary name IN the already-opened directory and opens it exclusively.
    ///
    /// The same directory, because the publication is a `rename` and a rename is only atomic
    /// within one filesystem — and the same DIRECTORY HANDLE, because re-resolving the parent
    /// pathname between the check and the rename is what a bind-mounted alias exploited.
    /// `O_EXCL` is the cross-process guarantee (the pid/nanos base only keeps the retry count
    /// down), `O_NOFOLLOW` refuses a symlink planted at the temporary name, and 0600 is what the
    /// content deserves: a complete pathname inventory of the pool.
    fn create(dir: paths::DirHandle, dest: &std::ffi::OsStr) -> Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        let base = format!(
            ".{}.dedcom-export-{}-{nanos}",
            dest.to_string_lossy(),
            std::process::id()
        );
        let mut attempt = 0u32;
        loop {
            let candidate = std::ffi::OsString::from(if attempt == 0 {
                format!("{base}.tmp")
            } else {
                format!("{base}-r{attempt}.tmp")
            });
            match dir.create_new_file(&candidate) {
                Ok(file) => {
                    return Ok(Self {
                        dir,
                        temp: candidate,
                        dest: dest.to_os_string(),
                        file,
                        armed: true,
                    })
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if attempt >= MAX_TEMP_CLAIM_RETRIES {
                        return Err(AppError::msg(format!(
                            "could not claim a temporary name for the export in {} after \
                             {MAX_TEMP_CLAIM_RETRIES} attempts",
                            dir.shown()
                        )));
                    }
                    attempt += 1;
                }
                Err(err) => {
                    return Err(AppError::msg(format!(
                        "cannot create the temporary export file in {}: {err}",
                        dir.shown()
                    )))
                }
            }
        }
    }

    fn file_mut(&mut self) -> &mut std::fs::File {
        &mut self.file
    }

    /// Durability first, then the atomic replacement of the final name — inside the directory
    /// this artifact has held open all along.
    ///
    /// The rename replaces the NAME the operator gave, deliberately: if the destination is a
    /// symlink, its target is never written through. Re-exporting over an existing file is the
    /// ordinary case, so this is a plain replace rather than `RENAME_NOREPLACE` — that rule
    /// belongs to the destructive action path, where the target is a file nobody asked to lose.
    fn publish(mut self) -> Result<()> {
        self.file.sync_data()?;
        self.dir.rename(&self.temp, &self.dest).map_err(|err| {
            AppError::msg(format!(
                "cannot publish the export in {}: {err}",
                self.dir.shown()
            ))
        })?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TempArtifact {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.dir.remove_file(&self.temp);
        }
    }
}

// Test-only one-shot seam at the instant between validating the destination directory and
// publishing into it. It exists so a test can re-point a symlinked parent right there and prove
// that publication still lands in the directory that was opened and checked — the property a
// re-resolved pathname would silently lose.
#[cfg(test)]
thread_local! {
    static EXPORT_PARENT_SWAP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arms the one-shot parent-swap hook for this thread and disarms it on drop.
#[cfg(test)]
struct ExportParentSwap;

#[cfg(test)]
impl ExportParentSwap {
    fn armed(action: impl FnOnce() + 'static) -> Self {
        EXPORT_PARENT_SWAP.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
        ExportParentSwap
    }

    /// Whether the armed shot was consumed. A test whose seam was never reached proved nothing.
    fn fired(&self) -> bool {
        EXPORT_PARENT_SWAP.with(|slot| slot.borrow().is_none())
    }
}

#[cfg(test)]
impl Drop for ExportParentSwap {
    fn drop(&mut self) {
        EXPORT_PARENT_SWAP.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
fn take_export_parent_swap() {
    let action = EXPORT_PARENT_SWAP.with(|slot| slot.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
}

// Test-only one-shot fault in the export's write path, so «the export failed after bytes reached
// the temporary file» can be produced deterministically — the real thing is a full disk or an I/O
// error, which no test can schedule. The length observed when it fired is recorded, so a test can
// prove the failure really was mid-write rather than before the first byte.
/// What the armed one-shot does when the export reaches the seam.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportFault {
    None,
    /// An ordinary `Err` return, as a full disk would produce.
    Error,
    /// An unwind, so the guard's `Drop` is what has to clean up.
    Panic,
}

#[cfg(test)]
thread_local! {
    static EXPORT_WRITE_FAULT: std::cell::Cell<ExportFault> =
        const { std::cell::Cell::new(ExportFault::None) };
    static EXPORT_FAULT_LEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Arms the one-shot export write fault for this thread and disarms it on drop.
#[cfg(test)]
struct ExportWriteFault;

#[cfg(test)]
impl ExportWriteFault {
    fn armed(kind: ExportFault) -> Self {
        EXPORT_WRITE_FAULT.with(|slot| slot.set(kind));
        EXPORT_FAULT_LEN.with(|slot| slot.set(0));
        ExportWriteFault
    }

    /// Whether the armed shot was consumed. A test whose seam was never reached proved nothing.
    fn fired(&self) -> bool {
        EXPORT_WRITE_FAULT.with(|slot| slot.get() == ExportFault::None)
    }

    /// How many bytes were already in the temporary file when it fired.
    fn bytes_written(&self) -> u64 {
        EXPORT_FAULT_LEN.with(|slot| slot.get())
    }
}

#[cfg(test)]
impl Drop for ExportWriteFault {
    fn drop(&mut self) {
        EXPORT_WRITE_FAULT.with(|slot| slot.set(ExportFault::None));
    }
}

#[cfg(test)]
fn take_export_write_fault() -> ExportFault {
    EXPORT_WRITE_FAULT.with(|slot| slot.replace(ExportFault::None))
}

#[cfg(test)]
fn record_export_fault_len(len: u64) {
    EXPORT_FAULT_LEN.with(|slot| slot.set(len));
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

/// The trusted `--export-csv` contract: what the artifact says, and what it refuses to say.
#[cfg(test)]
mod export_csv_tests {
    use std::path::{Path, PathBuf};

    use super::{
        cli, paths, refuse_dedcoms_own_state, run_export_csv, ExportFault, ExportParentSwap,
        ExportWriteFault, EXPORT_HEADER,
    };
    use crate::model::action::ActionKind;
    use crate::model::scan::{ScanConfig, ScanStatus};
    use crate::state::store::ExportRace;
    use crate::state::{ManifestRow, PublishMode, ScanStore};

    /// A state directory that cleans itself up even when a test panics.
    struct Rig {
        dir: PathBuf,
    }

    impl Rig {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or(0);
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "dedcom_export_{tag}_{}_{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Rig { dir }
        }

        fn cli(&self) -> cli::Cli {
            cli::Cli {
                state_dir: Some(self.dir.clone()),
                ..Default::default()
            }
        }

        fn db(&self) -> PathBuf {
            paths::checkpoint_db(&self.cli())
        }

        fn store(&self) -> ScanStore {
            ScanStore::open_writable(&self.db()).unwrap()
        }

        fn dest(&self) -> PathBuf {
            self.dir.join("export.csv")
        }

        fn run(&self) -> super::Result<()> {
            run_export_csv(&self.cli(), &self.dest())
        }

        fn export(&self) -> String {
            self.run().expect("the export must succeed");
            std::fs::read_to_string(self.dest()).unwrap()
        }

        /// Temporary artifacts still lying around the destination directory.
        fn residue(&self) -> Vec<String> {
            std::fs::read_dir(&self.dir)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.contains(".dedcom-export-"))
                .collect()
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn row(path: &str, inode: u64, mtime: i64) -> ManifestRow {
        ManifestRow {
            path: PathBuf::from(path),
            size: 8192,
            mtime,
            mtime_nsec: 0,
            ctime_sec: mtime,
            ctime_nsec: 0,
            device: 7,
            inode,
            nlink: 1,
        }
    }

    /// Manifest rows plus one digest for all of them.
    fn seed(store: &mut ScanStore, rows: &[ManifestRow], digest: u8) -> i64 {
        let id = store
            .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
            .unwrap();
        store.record_files(id, rows).unwrap();
        let hashes: Vec<(PathBuf, [u8; 32])> = rows
            .iter()
            .map(|row| (row.path.clone(), [digest; 32]))
            .collect();
        store.record_hashes(id, &hashes).unwrap();
        id
    }

    /// The ordinary case: one digest, published Derived, scan finished.
    fn complete_derived(store: &mut ScanStore, rows: &[ManifestRow], digest: u8) -> i64 {
        let id = seed(store, rows, digest);
        store.publish_results(id, PublishMode::Derived).unwrap();
        store.set_status(id, ScanStatus::Complete).unwrap();
        id
    }

    /// One exported row, split so a quoted pathname cannot confuse the fields around it: the
    /// first four and the last seven columns never contain a comma.
    struct Row {
        group: String,
        keep: String,
        size: String,
        hash: String,
        path: String,
        scan_id: String,
        generation: String,
        device: String,
        inode: String,
        links: String,
        mark: String,
        keep_source: String,
    }

    fn unquote(field: &str) -> String {
        if field.len() >= 2 && field.starts_with('"') && field.ends_with('"') {
            field[1..field.len() - 1].replace("\"\"", "\"")
        } else {
            field.to_string()
        }
    }

    fn parse(line: &str) -> Row {
        let mut head = line.splitn(5, ',');
        let group = head.next().unwrap().to_string();
        let keep = head.next().unwrap().to_string();
        let size = head.next().unwrap().to_string();
        let hash = head.next().unwrap().to_string();
        let rest = head.next().unwrap();
        let mut tail: Vec<&str> = rest.rsplitn(8, ',').collect();
        tail.reverse();
        Row {
            group,
            keep,
            size,
            hash,
            path: unquote(tail[0]),
            scan_id: tail[1].to_string(),
            generation: tail[2].to_string(),
            device: tail[3].to_string(),
            inode: tail[4].to_string(),
            links: tail[5].to_string(),
            mark: tail[6].to_string(),
            keep_source: tail[7].to_string(),
        }
    }

    fn rows_of(csv: &str) -> Vec<Row> {
        csv.lines()
            .skip(1)
            .filter(|line| !line.is_empty())
            .map(parse)
            .collect()
    }

    /// The destination's mtime, pinned so a refusal can be shown not to have touched it.
    fn modified(path: &Path) -> std::time::SystemTime {
        std::fs::metadata(path).unwrap().modified().unwrap()
    }

    fn find<'a>(rows: &'a [Row], path: &str) -> &'a Row {
        rows.iter()
            .find(|row| row.path == path)
            .unwrap_or_else(|| panic!("no row for {path}"))
    }

    /// G1 — an ordinary Derived export: published identity, physical columns, one computed keeper.
    #[test]
    fn an_ordinary_derived_export_carries_the_published_identity() {
        let rig = Rig::new("derived");
        let rows = [
            row("/tank/a", 1, 1000),
            row("/tank/b", 2, 2000),
            row("/tank/c", 3, 3000),
        ];
        let id = complete_derived(&mut rig.store(), &rows, 0xA1);

        let csv = rig.export();
        assert_eq!(
            csv.lines().next().unwrap(),
            EXPORT_HEADER.trim_end(),
            "the header is the accepted append-only schema"
        );
        let parsed = rows_of(&csv);
        assert_eq!(parsed.len(), 3);
        for row in &parsed {
            assert_eq!(row.group, "0");
            assert_eq!(row.scan_id, id.to_string());
            assert_eq!(row.generation, "1");
            assert_eq!(row.device, "7");
            assert_eq!(row.links, "1");
            assert_eq!(row.size, "8192");
            assert_eq!(row.hash.len(), 64);
            assert_eq!(row.mark, "");
            assert_eq!(row.keep_source, "default");
        }
        assert_eq!(parsed.iter().filter(|row| row.keep == "1").count(), 1);
        assert_eq!(find(&parsed, "/tank/c").keep, "1", "freshest mtime keeps");
        assert!(rig.residue().is_empty());
    }

    /// G2 — the pathname byte verification rejected is absent from the artifact.
    #[test]
    fn a_verification_rejected_pathname_is_not_exported() {
        let rig = Rig::new("rejected");
        let rows = [
            row("/tank/a", 1, 1000),
            row("/tank/b", 2, 1000),
            row("/tank/c", 3, 1000),
        ];
        {
            let mut store = rig.store();
            let id = seed(&mut store, &rows, 0xA2);
            let mut groups = store.duplicate_groups(id).unwrap();
            groups[0]
                .files
                .retain(|file| file.path.as_path() != Path::new("/tank/c"));
            store
                .publish_results(id, PublishMode::Explicit(&groups))
                .unwrap();
            store.set_status(id, ScanStatus::Complete).unwrap();
        }

        let csv = rig.export();
        assert!(
            !csv.contains("/tank/c"),
            "the rejected pathname must not come back:\n{csv}"
        );
        assert_eq!(rows_of(&csv).len(), 2);
    }

    /// G3 — two Explicit ranks that share one digest stay two groups.
    #[test]
    fn two_explicit_ranks_of_one_digest_stay_two_groups() {
        let rig = Rig::new("split");
        let rows = [
            row("/tank/a", 1, 1000),
            row("/tank/b", 2, 1000),
            row("/tank/c", 3, 1000),
            row("/tank/d", 4, 1000),
        ];
        {
            let mut store = rig.store();
            let id = seed(&mut store, &rows, 0xA3);
            let raw = store.duplicate_groups(id).unwrap();
            let mut left = raw[0].clone();
            let mut right = raw[0].clone();
            left.files.retain(|file| file.inode <= 2);
            right.files.retain(|file| file.inode >= 3);
            store
                .publish_results(id, PublishMode::Explicit(&[left, right]))
                .unwrap();
            store.set_status(id, ScanStatus::Complete).unwrap();
        }

        let csv = rig.export();
        let parsed = rows_of(&csv);
        assert_eq!(parsed.len(), 4);
        let groups: std::collections::BTreeSet<&str> =
            parsed.iter().map(|row| row.group.as_str()).collect();
        assert_eq!(
            groups.len(),
            2,
            "two published ranks, two CSV groups:\n{csv}"
        );
        assert_eq!(parsed.iter().filter(|row| row.keep == "1").count(), 2);
        let hashes: std::collections::BTreeSet<&str> =
            parsed.iter().map(|row| row.hash.as_str()).collect();
        assert_eq!(hashes.len(), 1, "and they legitimately share one digest");
    }

    /// G4 — with no marks the keeper is a total order, not «whichever the rows arrived in».
    #[test]
    fn without_marks_the_keeper_is_the_deterministic_maximum() {
        let rig = Rig::new("fallback");
        // Same mtime AND same nanoseconds: only the pathname can break the tie.
        let rows = [row("/tank/a", 1, 5000), row("/tank/b", 2, 5000)];
        complete_derived(&mut rig.store(), &rows, 0xA4);

        let csv = rig.export();
        let parsed = rows_of(&csv);
        assert_eq!(find(&parsed, "/tank/b").keep, "1", "the greater path wins");
        assert_eq!(find(&parsed, "/tank/a").keep, "0");
        assert_eq!(find(&parsed, "/tank/b").keep_source, "default");
    }

    /// G5 — a durable keeper mark on the OLDER file wins over the freshest mtime.
    #[test]
    fn a_durable_keeper_mark_wins_over_a_fresher_mtime() {
        let rig = Rig::new("keeper");
        let rows = [row("/tank/old", 1, 1000), row("/tank/new", 2, 9000)];
        {
            let mut store = rig.store();
            let id = complete_derived(&mut store, &rows, 0xA5);
            let mut groups = store.duplicate_groups(id).unwrap();
            for file in &mut groups[0].files {
                file.is_keeper = file.path.as_path() == Path::new("/tank/old");
            }
            let marked = groups[0].files.clone();
            store.save_marks(id, marked.iter()).unwrap();
        }

        let csv = rig.export();
        let parsed = rows_of(&csv);
        let old = find(&parsed, "/tank/old");
        assert_eq!(old.keep, "1");
        assert_eq!(old.mark, "keeper");
        assert_eq!(old.keep_source, "mark");
        let new = find(&parsed, "/tank/new");
        assert_eq!(new.keep, "0");
        assert_eq!(
            new.keep_source, "mark",
            "its 0 follows from the operator's keeper, not from a default"
        );
    }

    /// G6 — keeper and action marks in one group are both honoured, and an unmarked sibling
    /// stays a candidate.
    #[test]
    fn keeper_and_action_marks_are_both_honoured() {
        let rig = Rig::new("combo");
        let rows = [
            row("/tank/keep", 1, 1000),
            row("/tank/link", 2, 2000),
            row("/tank/plain", 3, 3000),
        ];
        {
            let mut store = rig.store();
            let id = complete_derived(&mut store, &rows, 0xA6);
            let mut groups = store.duplicate_groups(id).unwrap();
            for file in &mut groups[0].files {
                if file.path.as_path() == Path::new("/tank/keep") {
                    file.is_keeper = true;
                } else if file.path.as_path() == Path::new("/tank/link") {
                    file.action = Some(ActionKind::Hardlink);
                }
            }
            let marked = groups[0].files.clone();
            store.save_marks(id, marked.iter()).unwrap();
        }

        let csv = rig.export();
        let parsed = rows_of(&csv);
        assert_eq!(find(&parsed, "/tank/keep").keep, "1");
        assert_eq!(find(&parsed, "/tank/keep").mark, "keeper");
        assert_eq!(find(&parsed, "/tank/link").keep, "0");
        assert_eq!(find(&parsed, "/tank/link").mark, "hardlink");
        let plain = find(&parsed, "/tank/plain");
        assert_eq!(
            plain.keep, "0",
            "the freshest mtime does not override a keeper mark"
        );
        assert_eq!(plain.mark, "");
    }

    /// G7 — two keeper marks stay two keepers; the export invents no single survivor.
    #[test]
    fn two_keeper_marks_stay_two_keepers() {
        let rig = Rig::new("twokeepers");
        let rows = [
            row("/tank/a", 1, 1000),
            row("/tank/b", 2, 2000),
            row("/tank/c", 3, 3000),
        ];
        {
            let mut store = rig.store();
            let id = complete_derived(&mut store, &rows, 0xA7);
            let mut groups = store.duplicate_groups(id).unwrap();
            for file in &mut groups[0].files {
                file.is_keeper = file.path.as_path() != Path::new("/tank/c");
            }
            let marked = groups[0].files.clone();
            store.save_marks(id, marked.iter()).unwrap();
        }

        let csv = rig.export();
        let parsed = rows_of(&csv);
        assert_eq!(parsed.iter().filter(|row| row.keep == "1").count(), 2);
        assert_eq!(find(&parsed, "/tank/c").keep, "0");
    }

    /// G8' — a group whose every pathname is action-marked has no survivor, and a CSV that says
    /// so would read as «delete every copy». The whole export refuses.
    #[test]
    fn a_group_with_no_survivor_refuses_the_whole_export() {
        let rig = Rig::new("nosurvivor");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        {
            let mut store = rig.store();
            let id = complete_derived(&mut store, &rows, 0xA8);
            let mut groups = store.duplicate_groups(id).unwrap();
            for file in &mut groups[0].files {
                file.action = Some(ActionKind::Delete);
            }
            let marked = groups[0].files.clone();
            store.save_marks(id, marked.iter()).unwrap();
        }
        std::fs::write(rig.dest(), b"previous export\n").unwrap();
        let before = modified(&rig.dest());

        let err = rig.run().unwrap_err().to_string();
        assert!(
            err.contains("no keeper"),
            "the refusal explains itself: {err}"
        );
        assert!(err.contains("group 0"), "and names the group: {err}");
        assert_eq!(
            std::fs::read(rig.dest()).unwrap(),
            b"previous export\n",
            "the operator's existing file is untouched"
        );
        assert_eq!(modified(&rig.dest()), before, "its mtime included");
        assert!(rig.residue().is_empty(), "and no temporary is left behind");
    }

    /// G9 — a mark that states two fates, and an action identifier this build does not know,
    /// both refuse instead of being normalised into guidance.
    #[test]
    fn a_damaged_mark_refuses_the_export() {
        for (tag, sql) in [
            (
                "contradictory",
                "INSERT INTO file_mark(scan_id, path, is_keeper, action)
                 VALUES (?1, '/tank/a', 1, 'delete')",
            ),
            (
                "unknown",
                "INSERT INTO file_mark(scan_id, path, is_keeper, action)
                 VALUES (?1, '/tank/a', 0, 'obliterate')",
            ),
        ] {
            let rig = Rig::new(tag);
            let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
            {
                let mut store = rig.store();
                let id = complete_derived(&mut store, &rows, 0xA9);
                assert_eq!(store.corrupt_directly(sql, rusqlite::params![id]), 1);
            }
            let err = rig.run().unwrap_err().to_string();
            assert!(
                err.contains("/tank/a"),
                "the refusal names the pathname ({tag}): {err}"
            );
            assert!(!rig.dest().exists(), "no artifact was published ({tag})");
            assert!(rig.residue().is_empty(), "no temporary is left ({tag})");
        }
    }

    /// G10 — aliases of one allocation are visible as such, and an unrecorded link count is
    /// reported as unknown rather than refused.
    #[test]
    fn aliases_of_one_allocation_are_visible() {
        let rig = Rig::new("aliases");
        let mut rows = [
            row("/tank/one", 1, 1000),
            row("/tank/one-alias", 1, 1000),
            row("/tank/other", 2, 2000),
        ];
        rows[0].nlink = 2;
        rows[1].nlink = 2;
        rows[2].nlink = 0; // a pre-v3 row: the link count was never recorded
        complete_derived(&mut rig.store(), &rows, 0xAA);

        let csv = rig.export();
        let parsed = rows_of(&csv);
        assert_eq!(parsed.len(), 3);
        assert_eq!(find(&parsed, "/tank/one").inode, "1");
        assert_eq!(find(&parsed, "/tank/one-alias").inode, "1");
        assert_eq!(
            find(&parsed, "/tank/one").links,
            "2",
            "the link count the walk observed"
        );
        assert_eq!(
            find(&parsed, "/tank/other").links,
            "0",
            "0 is «never recorded», not «no links»"
        );
    }

    /// G11 — a trusted publication with no duplicate groups is a finished answer.
    #[test]
    fn an_empty_publication_is_a_header_only_file() {
        let rig = Rig::new("empty");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        {
            let mut store = rig.store();
            let id = store
                .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
                .unwrap();
            store.record_files(id, &rows).unwrap();
            // Two different digests: nothing is a duplicate of anything.
            store
                .record_hashes(
                    id,
                    &[
                        (rows[0].path.clone(), [0xB1; 32]),
                        (rows[1].path.clone(), [0xB2; 32]),
                    ],
                )
                .unwrap();
            store.publish_results(id, PublishMode::Derived).unwrap();
            store.set_status(id, ScanStatus::Complete).unwrap();
        }

        let csv = rig.export();
        assert_eq!(csv, EXPORT_HEADER, "header only, and it succeeded");
    }

    /// G12 — a summary whose member count its membership does not hold refuses the whole export.
    #[test]
    fn an_inconsistent_rank_refuses_the_export() {
        let rig = Rig::new("inconsistent");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        {
            let mut store = rig.store();
            let id = complete_derived(&mut store, &rows, 0xAB);
            assert_eq!(
                store.corrupt_directly(
                    "UPDATE file_group SET file_count = file_count + 5 WHERE scan_id = ?1",
                    rusqlite::params![id],
                ),
                1
            );
        }
        std::fs::write(rig.dest(), b"previous export\n").unwrap();
        let before = modified(&rig.dest());

        let err = rig.run().unwrap_err().to_string();
        assert!(err.contains("member count"), "{err}");
        assert_eq!(std::fs::read(rig.dest()).unwrap(), b"previous export\n");
        assert_eq!(modified(&rig.dest()), before);
        assert!(rig.residue().is_empty());
    }

    /// G13 — no authority is a refusal that tells the operator the only real remedy.
    #[test]
    fn an_unknown_authority_refuses_and_says_rescan() {
        let rig = Rig::new("unknown");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        {
            let mut store = rig.store();
            let id = seed(&mut store, &rows, 0xAC);
            store.set_status(id, ScanStatus::Complete).unwrap();
        }

        let err = rig.run().unwrap_err().to_string();
        assert!(err.contains("no verified membership"), "{err}");
        assert!(err.contains("Re-run the scan"), "{err}");
        assert!(
            err.contains("opening the checkpoint does not republish it"),
            "the message must not send the operator down a path that cannot work: {err}"
        );
        assert!(!rig.dest().exists(), "and nothing was written");
    }

    /// G26/G27 — the authority is published before the final status, so the status is checked on
    /// its own.
    #[test]
    fn a_published_but_unfinished_scan_refuses() {
        for status in [
            ScanStatus::Hashing,
            ScanStatus::Walking,
            ScanStatus::Aborted,
        ] {
            let rig = Rig::new("unfinished");
            let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
            {
                let mut store = rig.store();
                let id = seed(&mut store, &rows, 0xAD);
                store.publish_results(id, PublishMode::Derived).unwrap();
                store.set_status(id, status).unwrap();
            }
            let err = rig.run().unwrap_err().to_string();
            assert!(
                err.contains("has not finished"),
                "{status:?} must refuse: {err}"
            );
            assert!(err.contains(status.as_str()), "and name the status: {err}");
            assert!(!rig.dest().exists());
        }
    }

    /// A status this build cannot read on the NEWEST session refuses — it must never quietly
    /// hand back an older session under the newest one's name.
    ///
    /// The earlier version of this test had a single scan, so `no saved scan` hid the fall-back
    /// branch entirely.
    #[test]
    fn an_unknown_newest_status_refuses_instead_of_exporting_an_older_scan() {
        let rig = Rig::new("badstatus2");
        let older = complete_derived(
            &mut rig.store(),
            &[row("/tank/one/a", 1, 1000), row("/tank/one/b", 2, 2000)],
            0xC1,
        );
        let newest = {
            let mut store = rig.store();
            let newest = complete_derived(
                &mut store,
                &[row("/tank/two/a", 11, 1000), row("/tank/two/b", 12, 2000)],
                0xC2,
            );
            assert!(newest > older);
            assert_eq!(
                store.corrupt_directly(
                    "UPDATE scan SET status = 'quantum' WHERE id = ?1",
                    rusqlite::params![newest],
                ),
                1
            );
            newest
        };
        std::fs::write(rig.dest(), b"previous export\n").unwrap();
        let before = modified(&rig.dest());

        let err = rig.run().unwrap_err().to_string();
        assert!(err.contains(&format!("scan {newest}")), "{err}");
        assert!(err.contains("quantum"), "the status is quoted: {err}");
        assert!(
            !err.contains(&format!("scan {older}")),
            "the older session is not offered as a substitute: {err}"
        );
        assert_eq!(std::fs::read(rig.dest()).unwrap(), b"previous export\n");
        assert_eq!(modified(&rig.dest()), before);
        assert!(rig.residue().is_empty());
    }

    /// The same rule with only one session: it names that session instead of pretending there is
    /// nothing saved.
    #[test]
    fn a_single_unknown_status_names_that_scan() {
        let rig = Rig::new("badstatus1");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        let id = {
            let mut store = rig.store();
            let id = complete_derived(&mut store, &rows, 0xAE);
            assert_eq!(
                store.corrupt_directly(
                    "UPDATE scan SET status = 'quantum' WHERE id = ?1",
                    rusqlite::params![id],
                ),
                1
            );
            id
        };
        let err = rig.run().unwrap_err().to_string();
        assert!(err.contains(&format!("scan {id}")), "{err}");
        assert!(
            !err.contains("no saved scan"),
            "«no saved scan» is false here and used to hide the fall-back branch: {err}"
        );
        assert!(!rig.dest().exists());
    }

    /// A trashed session is not eligible, and with nothing else active the export refuses.
    #[test]
    fn a_trashed_session_is_not_exported() {
        let rig = Rig::new("trashed");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        {
            let mut store = rig.store();
            let id = complete_derived(&mut store, &rows, 0xAF);
            store.trash_scan(id).unwrap();
        }
        let err = rig.run().unwrap_err().to_string();
        assert!(err.contains("no saved scan"), "{err}");
        assert!(!rig.dest().exists());
    }

    /// G15 — a pathname the walk could not read as UTF-8 is exported in the manifest's own
    /// spelling; the export adds no second lossy conversion of its own.
    #[test]
    fn a_non_utf8_pathname_keeps_the_manifest_spelling() {
        use std::os::unix::ffi::OsStrExt;
        let rig = Rig::new("nonutf8");
        let raw = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tank/bad\xffname.bin"));
        let mut rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        rows[1].path = raw;
        complete_derived(&mut rig.store(), &rows, 0xB0);

        let csv = rig.export();
        assert!(
            csv.contains("/tank/bad\u{FFFD}name.bin"),
            "the manifest's lossy spelling is what every surface uses:\n{csv}"
        );
    }

    /// G16 — RFC-4180 quoting and formula neutralisation survive the new columns.
    #[test]
    fn commas_quotes_and_formula_prefixes_stay_escaped() {
        let rig = Rig::new("escaping");
        let rows = [
            row("=cmd|calc,evil\"quote", 1, 1000),
            row("/tank/plain", 2, 2000),
        ];
        complete_derived(&mut rig.store(), &rows, 0xB3);

        let csv = rig.export();
        assert!(
            csv.contains("\"'=cmd|calc,evil\"\"quote\""),
            "apostrophe first, then RFC quoting, then doubled quotes:\n{csv}"
        );
        // The row still has its twelve fields: the quoted pathname did not shift them.
        let parsed = rows_of(&csv);
        assert_eq!(parsed.len(), 2);
        assert_eq!(find(&parsed, "/tank/plain").keep_source, "default");
    }

    /// G17 — a refusal after the temporary exists still leaves the destination alone, byte for
    /// byte and mtime for mtime.
    #[test]
    fn a_mid_write_failure_leaves_the_destination_untouched() {
        let rig = Rig::new("midwrite");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xB4);
        std::fs::write(rig.dest(), b"previous export\n").unwrap();
        let before = std::fs::metadata(rig.dest()).unwrap().modified().unwrap();

        let fault = ExportWriteFault::armed(ExportFault::Error);
        let err = rig.run().unwrap_err().to_string();
        assert!(fault.fired(), "the seam must have been reached");
        assert!(
            fault.bytes_written() > 0,
            "and it must have fired AFTER bytes reached the temporary"
        );
        assert!(err.contains("injected export write fault"), "{err}");
        assert_eq!(std::fs::read(rig.dest()).unwrap(), b"previous export\n");
        assert_eq!(
            std::fs::metadata(rig.dest()).unwrap().modified().unwrap(),
            before
        );
        assert!(rig.residue().is_empty(), "the guard removed the temporary");
    }

    /// G24 — the same guarantee under an unwind, where only `Drop` can deliver it.
    #[test]
    fn a_panic_mid_write_leaves_no_artifact() {
        let rig = Rig::new("panic");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xB5);
        std::fs::write(rig.dest(), b"previous export\n").unwrap();

        let before = modified(&rig.dest());

        let fault = ExportWriteFault::armed(ExportFault::Panic);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rig.run()));
        std::panic::set_hook(previous);

        assert!(outcome.is_err(), "the export must have unwound");
        assert!(fault.fired());
        assert!(fault.bytes_written() > 0);
        assert_eq!(std::fs::read(rig.dest()).unwrap(), b"previous export\n");
        assert_eq!(
            modified(&rig.dest()),
            before,
            "the destination was not even opened"
        );
        assert!(rig.residue().is_empty(), "Drop ran during the unwind");
    }

    /// G18 — the destination NAME is replaced; a symlink's target is never written through.
    #[test]
    fn a_symlinked_destination_is_replaced_not_followed() {
        let rig = Rig::new("symlink");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xB6);
        let target = rig.dir.join("elsewhere.csv");
        std::fs::write(&target, b"not to be overwritten\n").unwrap();
        std::os::unix::fs::symlink(&target, rig.dest()).unwrap();

        let csv = rig.export();
        assert!(csv.starts_with("group,keep"), "the export succeeded");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"not to be overwritten\n",
            "the link's target is untouched"
        );
        assert!(
            !std::fs::symlink_metadata(rig.dest())
                .unwrap()
                .file_type()
                .is_symlink(),
            "the name now holds the artifact itself"
        );
    }

    /// The published artifact is not world-readable: it is the pool's complete pathname
    /// inventory, exactly what the checkpoint's own 0600 protects.
    #[test]
    fn the_published_artifact_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let rig = Rig::new("mode");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xB7);

        rig.export();
        let mode = std::fs::metadata(rig.dest()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    /// G21 — the session is trashed in the gap between selection and snapshot.
    #[test]
    fn a_trash_at_the_selection_seam_refuses() {
        let rig = Rig::new("raceTrash");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        let id = complete_derived(&mut rig.store(), &rows, 0xB8);
        let db = rig.db();

        let race = ExportRace::armed(move || {
            ScanStore::open_writable(&db)
                .unwrap()
                .trash_scan(id)
                .unwrap();
        });
        let err = rig.run().unwrap_err().to_string();
        assert!(race.fired(), "the seam must have been reached");
        assert!(err.contains("moved to the trash"), "{err}");
        assert!(!rig.dest().exists());
        assert!(rig.residue().is_empty());
    }

    /// G21 — a newer session finishes in that same gap: the export refuses rather than quietly
    /// exporting a session nobody asked for.
    #[test]
    fn a_newer_scan_at_the_selection_seam_refuses() {
        let rig = Rig::new("raceNewer");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xB9);
        let db = rig.db();

        let race = ExportRace::armed(move || {
            let mut store = ScanStore::open_writable(&db).unwrap();
            let rows = [row("/tank/x", 11, 1000), row("/tank/y", 12, 2000)];
            complete_derived(&mut store, &rows, 0xBA);
        });
        let err = rig.run().unwrap_err().to_string();
        assert!(race.fired());
        assert!(err.contains("newest active session changed"), "{err}");
        assert!(!rig.dest().exists());
    }

    /// G20 — a republication and a mark land in that same gap: the artifact describes ONE state.
    #[test]
    fn a_republication_at_the_seam_yields_one_whole_state() {
        let rig = Rig::new("raceRepublish");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        let id = complete_derived(&mut rig.store(), &rows, 0xBB);
        let db = rig.db();

        let race = ExportRace::armed(move || {
            let mut store = ScanStore::open_writable(&db).unwrap();
            store.publish_results(id, PublishMode::Derived).unwrap();
            let mut groups = store.duplicate_groups(id).unwrap();
            for file in &mut groups[0].files {
                file.is_keeper = file.path.as_path() == Path::new("/tank/a");
            }
            let marked = groups[0].files.clone();
            store.save_marks(id, marked.iter()).unwrap();
        });
        let csv = rig.export();
        assert!(race.fired());
        let parsed = rows_of(&csv);
        let generations: std::collections::BTreeSet<&str> =
            parsed.iter().map(|row| row.generation.as_str()).collect();
        assert_eq!(
            generations.len(),
            1,
            "one publication per artifact, never two:\n{csv}"
        );
        assert_eq!(
            generations.into_iter().next().unwrap(),
            "2",
            "and it is the state the snapshot opened on"
        );
        let keeper = parsed.iter().find(|row| row.keep == "1").unwrap();
        assert_eq!(
            keeper.path, "/tank/a",
            "the marks come from that same state:\n{csv}"
        );
    }

    /// The reporting contract the mode has always had: no lock, no writes to the checkpoint.
    #[test]
    fn the_export_does_not_modify_the_checkpoint() {
        let rig = Rig::new("readonly");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xBC);
        let before = std::fs::read(rig.db()).unwrap();

        rig.export();
        assert_eq!(
            std::fs::read(rig.db()).unwrap(),
            before,
            "the checkpoint is a report source, not a workspace"
        );
    }

    /// Re-exporting over yesterday's artifact is the ordinary case and must keep working.
    #[test]
    fn an_existing_destination_is_replaced_on_success() {
        let rig = Rig::new("replace");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xBD);
        std::fs::write(rig.dest(), b"previous export\n").unwrap();

        let csv = rig.export();
        assert!(csv.starts_with("group,keep"));
        assert_eq!(rows_of(&csv).len(), 2);
        assert!(rig.residue().is_empty());
    }

    /// A destination whose directory does not exist is refused before anything is created.
    #[test]
    fn a_missing_destination_directory_is_refused() {
        let rig = Rig::new("nodir");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xBE);

        let missing = rig.dir.join("no-such-dir").join("export.csv");
        let err = run_export_csv(&rig.cli(), &missing)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not exist"), "{err}");
        assert!(rig.residue().is_empty());
    }

    /// dedcom's own live state is never a destination — not the checkpoint, not the files SQLite
    /// keeps beside it, not the lock.
    #[test]
    fn the_export_refuses_to_replace_its_own_state_files() {
        for entry in crate::paths::PROTECTED_STATE_ENTRIES {
            let rig = Rig::new("protected");
            let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
            complete_derived(&mut rig.store(), &rows, 0xC5);

            let dest = rig.dir.join(entry);
            if entry != "dedcom.db" {
                std::fs::write(&dest, format!("{entry} content\n")).unwrap();
            }
            let before = std::fs::read(&dest).unwrap();
            let stamp = modified(&dest);

            let err = run_export_csv(&rig.cli(), &dest).unwrap_err().to_string();
            assert!(err.contains(entry), "the refusal names the entry: {err}");
            assert_eq!(
                std::fs::read(&dest).unwrap(),
                before,
                "{entry} must be byte-identical"
            );
            assert_eq!(modified(&dest), stamp, "{entry} mtime must not move");
            assert!(rig.residue().is_empty(), "no temporary for {entry}");
            if entry == "dedcom.db" {
                assert!(before.starts_with(b"SQLite format 3"));
                // Still a checkpoint this build accepts, i.e. still schema v5.
                drop(ScanStore::open_read_only(&rig.db()).expect("the checkpoint still opens"));
            }
        }
    }

    /// An ordinary destination directory, opened for the helper under test.
    fn state_check_rig(tag: &str) -> (Rig, PathBuf, paths::DirHandle) {
        let rig = Rig::new(tag);
        let out = rig.dir.join("out");
        std::fs::create_dir(&out).unwrap();
        let parent = paths::DirHandle::open(&out).unwrap();
        (rig, out, parent)
    }

    /// A protected basename may not slip through because the state directory could not be
    /// opened. «I could not establish whether this is live state» is not permission to publish
    /// over it — the next DB open usually fails too, but usually is not a safety property: the
    /// error can be transient and the state path can change between the two operations.
    #[test]
    fn an_unavailable_state_directory_still_refuses_a_protected_name() {
        let (rig, out, parent) = state_check_rig("stategone");
        let missing = rig.dir.join("no-such-state");
        let cli = cli::Cli {
            state_dir: Some(missing.clone()),
            ..Default::default()
        };
        let dest = out.join("dedcom.db");

        let err = refuse_dedcoms_own_state(&cli, &parent, std::ffi::OsStr::new("dedcom.db"), &dest)
            .unwrap_err()
            .to_string();
        assert!(err.contains("dedcom.db"), "the entry is named: {err}");
        assert!(
            err.contains("could not"),
            "and so is the reason it refused: {err}"
        );
        assert!(!dest.exists(), "nothing was created at the destination");
        assert!(!missing.exists(), "and no state directory was conjured");
        assert!(
            std::fs::read_dir(&out).unwrap().next().is_none(),
            "the destination directory is untouched"
        );
    }

    /// The same unavailable state directory must NOT make an ordinary name fail here: reporting
    /// a missing checkpoint is the database open's job, not this helper's.
    #[test]
    fn an_unavailable_state_directory_does_not_refuse_an_ordinary_name() {
        let (rig, out, parent) = state_check_rig("stategone_ok");
        let cli = cli::Cli {
            state_dir: Some(rig.dir.join("no-such-state")),
            ..Default::default()
        };
        let dest = out.join("groups.csv");

        assert!(
            refuse_dedcoms_own_state(&cli, &parent, std::ffi::OsStr::new("groups.csv"), &dest)
                .is_ok(),
            "an ordinary destination is not this helper's business"
        );
        assert!(std::fs::read_dir(&out).unwrap().next().is_none());
    }

    /// The protected names are matched without ASCII case, because a case-insensitive dataset
    /// resolves `DEDCOM.DB` to the checkpoint itself.
    #[test]
    fn a_cased_spelling_of_a_protected_entry_is_refused() {
        for spelling in ["DEDCOM.DB", "Dedcom.Db", "DEDCOM.LOCK"] {
            let rig = Rig::new("cased");
            let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
            complete_derived(&mut rig.store(), &rows, 0xCD);

            let dest = rig.dir.join(spelling);
            std::fs::write(&dest, b"not the artifact\n").unwrap();
            let stamp = modified(&dest);

            let err = run_export_csv(&rig.cli(), &dest).unwrap_err().to_string();
            assert!(err.contains("state directory"), "{spelling}: {err}");
            assert_eq!(std::fs::read(&dest).unwrap(), b"not the artifact\n");
            assert_eq!(modified(&dest), stamp);
            assert!(rig.residue().is_empty());
        }
    }

    /// The destination directory is opened once and pinned: re-pointing the path afterwards must
    /// not move the artifact — least of all into the state directory.
    #[test]
    fn a_parent_swapped_after_the_check_cannot_redirect_the_publication() {
        let rig = Rig::new("parentswap");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xCE);

        let real = rig.dir.join("out");
        std::fs::create_dir(&real).unwrap();
        let link = rig.dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let dest = link.join("export.csv");

        let swapped_link = link.clone();
        let state_dir = rig.dir.clone();
        let swap = ExportParentSwap::armed(move || {
            std::fs::remove_file(&swapped_link).unwrap();
            std::os::unix::fs::symlink(&state_dir, &swapped_link).unwrap();
        });

        run_export_csv(&rig.cli(), &dest).unwrap();
        assert!(swap.fired(), "the seam must have been reached");
        assert!(
            real.join("export.csv").exists(),
            "published into the directory that was opened and checked"
        );
        assert!(
            !rig.dir.join("export.csv").exists(),
            "and never into the directory the path came to mean"
        );
        assert!(rig.residue().is_empty());
    }

    /// The comparison is on directory OBJECTS, so a `..` spelling and a symlinked alias of the
    /// state directory are caught too.
    #[test]
    fn a_dotdot_or_aliased_parent_cannot_smuggle_the_checkpoint_in() {
        let rig = Rig::new("aliasparent");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xC6);
        std::fs::create_dir(rig.dir.join("sub")).unwrap();
        std::os::unix::fs::symlink(&rig.dir, rig.dir.join("alias")).unwrap();
        let before = std::fs::read(rig.db()).unwrap();

        for dest in [
            rig.dir.join("sub").join("..").join("dedcom.db"),
            rig.dir.join("alias").join("dedcom.db"),
        ] {
            let err = run_export_csv(&rig.cli(), &dest).unwrap_err().to_string();
            assert!(err.contains("dedcom.db"), "{dest:?}: {err}");
            assert_eq!(std::fs::read(rig.db()).unwrap(), before, "{dest:?}");
            assert!(rig.residue().is_empty(), "{dest:?}");
        }
    }

    /// Only those five entries are protected: an ordinary CSV inside the state directory is a
    /// perfectly good destination and stays one.
    #[test]
    fn an_ordinary_name_in_the_state_directory_is_still_writable() {
        let rig = Rig::new("ordinary");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xC7);

        assert_eq!(rig.dest().parent().unwrap(), rig.dir);
        let csv = rig.export();
        assert!(csv.starts_with("group,keep"));
    }

    /// The lock is not replaced underneath the instance that holds it.
    #[test]
    fn the_lock_file_is_not_replaced_under_a_held_guard() {
        use std::os::unix::fs::MetadataExt;
        let rig = Rig::new("lockheld");
        let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
        complete_derived(&mut rig.store(), &rows, 0xC8);

        let guard = match crate::lock::try_acquire(&rig.dir).unwrap() {
            crate::lock::Acquire::Operator(guard) => guard,
            crate::lock::Acquire::Busy(_) => panic!("the fixture must hold the lock itself"),
        };
        let lock_path = rig.dir.join("dedcom.lock");
        let before = std::fs::metadata(&lock_path).unwrap();

        let err = run_export_csv(&rig.cli(), &lock_path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("dedcom.lock"), "{err}");
        let after = std::fs::metadata(&lock_path).unwrap();
        assert_eq!(
            after.ino(),
            before.ino(),
            "the path still names the file the guard holds"
        );
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert!(rig.residue().is_empty());
        drop(guard);
    }

    /// One cell, read back from the database as text — a corruption fixture proves what it wrote
    /// before the export is asked about it.
    fn read_cell(db: &Path, sql: &str) -> String {
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.query_row(sql, [], |row| row.get::<_, rusqlite::types::Value>(0))
            .map(|value| format!("{value:?}"))
            .unwrap()
    }

    /// A damaged physical cell refuses the export; it is never cast into a plausible huge number.
    #[test]
    fn a_damaged_physical_cell_refuses_the_export() {
        let cases: [(&str, &str, &str, &str, &str); 8] = [
            (
                "size",
                "UPDATE file SET size = -1 WHERE scan_id = ?1 AND path = '/tank/a'",
                "SELECT size FROM file WHERE path = '/tank/a'",
                "-1",
                "file.size",
            ),
            (
                "device",
                "UPDATE file SET device = -2 WHERE scan_id = ?1 AND path = '/tank/a'",
                "SELECT device FROM file WHERE path = '/tank/a'",
                "-2",
                "file.device",
            ),
            (
                "inode",
                "UPDATE file SET inode = -3 WHERE scan_id = ?1 AND path = '/tank/a'",
                "SELECT inode FROM file WHERE path = '/tank/a'",
                "-3",
                "file.inode",
            ),
            (
                "nsec_negative",
                "UPDATE file SET mtime_nsec = -1 WHERE scan_id = ?1 AND path = '/tank/a'",
                "SELECT mtime_nsec FROM file WHERE path = '/tank/a'",
                "-1",
                "mtime_nsec",
            ),
            (
                "nsec_overflow",
                "UPDATE file SET mtime_nsec = 1000000000 WHERE scan_id = ?1 AND path = '/tank/a'",
                "SELECT mtime_nsec FROM file WHERE path = '/tank/a'",
                "1000000000",
                "mtime_nsec",
            ),
            (
                "size_storage_class",
                "UPDATE file SET size = 'huge' WHERE scan_id = ?1 AND path = '/tank/a'",
                "SELECT size FROM file WHERE path = '/tank/a'",
                "huge",
                "file.size",
            ),
            (
                "size_disagrees_with_summary",
                "UPDATE file SET size = 4096 WHERE scan_id = ?1 AND path = '/tank/a'",
                "SELECT size FROM file WHERE path = '/tank/a'",
                "4096",
                "declares",
            ),
            (
                "empty_path",
                "UPDATE file SET path = '' WHERE scan_id = ?1 AND path = '/tank/a'",
                "SELECT COUNT(*) FROM file WHERE path = ''",
                "1",
                "empty pathname",
            ),
        ];
        for (tag, corrupt, probe, expected_cell, needle) in cases {
            let rig = Rig::new(tag);
            let rows = [row("/tank/a", 1, 1000), row("/tank/b", 2, 2000)];
            {
                let mut store = rig.store();
                let id = complete_derived(&mut store, &rows, 0xCA);
                assert_eq!(store.corrupt_directly(corrupt, rusqlite::params![id]), 1);
            }
            let cell = read_cell(&rig.db(), probe);
            assert!(
                cell.contains(expected_cell),
                "{tag}: the fixture must hold the corrupt cell, got {cell}"
            );
            std::fs::write(rig.dest(), b"previous export\n").unwrap();
            let stamp = modified(&rig.dest());

            let err = rig.run().unwrap_err().to_string();
            assert!(err.contains(needle), "{tag}: {err} (cell was {cell})");
            assert_eq!(
                std::fs::read(rig.dest()).unwrap(),
                b"previous export\n",
                "{tag}"
            );
            assert_eq!(modified(&rig.dest()), stamp, "{tag}");
            assert!(rig.residue().is_empty(), "{tag}");
        }
    }

    /// The healthy edges of those same domains export without complaint.
    #[test]
    fn healthy_boundary_values_still_export() {
        let rig = Rig::new("boundary");
        let mut rows = [row("/tank/a", 0, 1000), row("/tank/b", 2, 2000)];
        rows[0].device = 0;
        rows[0].mtime_nsec = 999_999_999;
        rows[1].mtime_nsec = 0;
        complete_derived(&mut rig.store(), &rows, 0xCB);

        let csv = rig.export();
        let parsed = rows_of(&csv);
        assert_eq!(parsed.len(), 2);
        let zeroed = find(&parsed, "/tank/a");
        assert_eq!(
            zeroed.device, "0",
            "a device id of 0 is a value, not corruption"
        );
        assert_eq!(zeroed.inode, "0");
    }
}

/// The classic wizard's boot session load is fail-closed: its error becomes the run's error, so
/// an unreadable checkpoint exits non-zero instead of presenting a wizard with no saved scans.
#[cfg(test)]
mod boot_session_load_is_fail_closed_tests {
    use super::*;

    const NEWER: &str = "dedcom.db was created by a newer version (schema v6; this build supports v5). Upgrade dedcom, or move the old dedcom.db aside.";

    /// A scratch directory that removes itself when the test returns: a green test may not leave
    /// a persistent fixture behind merely because the cargo process eventually exits.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("dedcom-bootload-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        Scratch::new(name)
    }

    fn v5_db(dir: &std::path::Path) -> std::path::PathBuf {
        let db = dir.join("dedcom.db");
        let store = ScanStore::open(&db).expect("the product creates its own v5 checkpoint");
        drop(store);
        db
    }

    fn v6_db(dir: &std::path::Path) -> std::path::PathBuf {
        let db = v5_db(dir);
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.pragma_update(None, "user_version", 6i64).unwrap();
        drop(conn);
        db
    }

    /// Exact bytes, mtime, `user_version` and the sibling census of one checkpoint.
    type Census = (Vec<u8>, std::time::SystemTime, i64, Vec<String>);

    /// Exact bytes, mtime at the platform's full precision, `user_version` and the sibling
    /// census. Metadata is taken before the inspection connection and re-verified after it, so a
    /// census that disturbed the file cannot pass.
    fn census(db: &std::path::Path) -> Census {
        let bytes = std::fs::read(db).unwrap();
        let before = std::fs::metadata(db).unwrap().modified().unwrap();

        let conn = rusqlite::Connection::open(db).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        drop(conn);

        let after = std::fs::metadata(db).unwrap().modified().unwrap();
        assert_eq!(
            before, after,
            "the census helper itself must not modify the checkpoint"
        );

        let mut siblings: Vec<String> = std::fs::read_dir(db.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n != "dedcom.db")
            .collect();
        siblings.sort();
        (bytes, after, version, siblings)
    }

    #[test]
    fn a_readable_checkpoint_returns_its_real_list() {
        let dir = scratch("ok");
        let list =
            boot_session_load(&v5_db(dir.path()), false, false).expect("a v5 checkpoint opens");
        assert!(list.is_empty(), "a fresh checkpoint holds no sessions yet");
    }

    #[test]
    fn a_newer_checkpoint_returns_the_exact_error_instead_of_an_empty_list() {
        let dir = scratch("v6");
        let db = v6_db(dir.path());
        let before = census(&db);

        let err = boot_session_load(&db, false, false)
            .expect_err("a v6 checkpoint must refuse, not report zero sessions");

        assert_eq!(
            err.to_string(),
            NEWER,
            "the diagnostic body is the store's own, byte for byte"
        );
        assert_eq!(
            census(&db),
            before,
            "bytes, mtime, user_version and the sidecar census are untouched"
        );
    }

    const NOT_A_CHECKPOINT: &str = "dedcom.db is not a checkpoint this build can upgrade";

    /// A checkpoint the product itself wrote, carrying one completed scan, rewound to the shape a
    /// build of `version` would have left behind. Rewinding the real schema is how the migration
    /// tests in `state::schema` build their legacy databases as well — hand-transcribed DDL in
    /// this role is precisely what the G2 masters got wrong.
    ///
    /// The rollback journal is restored at the end: WAL is something an opener flips, not
    /// something a resting checkpoint carries, and a fixture in WAL mode would blur the
    /// no-sidecar assertions below.
    fn genuine_checkpoint(dir: &std::path::Path, version: i64) -> std::path::PathBuf {
        let db = dir.join("dedcom.db");
        {
            let mut store = ScanStore::open(&db).expect("the product creates its own checkpoint");
            let scan = store
                .begin_scan(&crate::model::scan::ScanConfig::new(vec![dir.to_path_buf()]))
                .unwrap();
            store
                .set_status(scan, crate::model::scan::ScanStatus::Complete)
                .unwrap();
        }
        let conn = rusqlite::Connection::open(&db).unwrap();
        if version < 5 {
            conn.execute_batch("DROP TABLE file_group_member; DROP TABLE scan_membership;")
                .unwrap();
        }
        if version < 4 {
            conn.execute_batch("DROP TABLE dir_omission; DROP TABLE scan_root;")
                .unwrap();
        }
        if version < 3 {
            // The two v3 indexes go as well. They depend on no column dropped here, so they would
            // survive the rewind — and a checkpoint declaring v0 while carrying a name that only
            // arrived at v3 is exactly what the guard refuses. Dropping the v4/v5 TABLES above
            // takes their indexes with them; these two have to be named.
            conn.execute_batch(
                "DROP INDEX file_scan_identity;
                 DROP INDEX file_hash_identity;
                 ALTER TABLE file       DROP COLUMN nlink;
                 ALTER TABLE file_group DROP COLUMN object_count;
                 ALTER TABLE file_group DROP COLUMN reclaim_state;
                 ALTER TABLE scan_stats DROP COLUMN reclaim_state;",
            )
            .unwrap();
        }
        if version < 2 {
            conn.execute_batch("ALTER TABLE scan_stats DROP COLUMN results_materialized;")
                .unwrap();
        }
        conn.pragma_update(None, "user_version", version).unwrap();
        let _: String = conn
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
            .unwrap();
        drop(conn);
        db
    }

    /// A database built by hand into a shape no release of this product ever wrote: `scan` with
    /// `started_at` instead of the timestamps, and a table called `file_entry` where ours is
    /// `file`. It exists here only as the foreign input that has to be refused.
    fn foreign_shape(dir: &std::path::Path) -> std::path::PathBuf {
        raw_db(
            dir,
            "CREATE TABLE scan (id INTEGER PRIMARY KEY, status TEXT NOT NULL,
                                config_json TEXT NOT NULL, started_at INTEGER NOT NULL,
                                trashed INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE file_entry (id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL,
                                      path TEXT NOT NULL, size INTEGER NOT NULL,
                                      hash TEXT NOT NULL);
             CREATE TABLE scan_membership (scan_id INTEGER NOT NULL, file_id INTEGER NOT NULL,
                                           mode, generation);
             CREATE TABLE scan_stats (scan_id INTEGER PRIMARY KEY, files_scanned INTEGER NOT NULL,
                                      bytes_hashed INTEGER NOT NULL, groups_found INTEGER NOT NULL,
                                      results_materialized INTEGER NOT NULL DEFAULT 0);
             INSERT INTO scan (id, status, config_json, started_at, trashed)
                  VALUES (1, 'complete', '{}', 1700000000, 0);",
        )
    }

    fn raw_db(dir: &std::path::Path, ddl: &str) -> std::path::PathBuf {
        let db = dir.join("dedcom.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(ddl).unwrap();
        drop(conn);
        db
    }

    /// Every refusal of a database we do not own says which object failed, never SQLite's own
    /// «no such column», and leaves the file exactly as it found it.
    fn assert_refused_untouched(db: &std::path::Path, before: &Census, names: &[&str]) {
        let err = boot_session_load(db, false, false)
            .expect_err("a database that is not our checkpoint must be refused");
        let text = err.to_string();
        assert!(
            text.starts_with(NOT_A_CHECKPOINT),
            "the refusal must be the shape guard's own: {text}"
        );
        assert!(
            !text.contains("no such column"),
            "a raw SQLite sentence must never reach the operator: {text}"
        );
        for name in names {
            assert!(
                text.contains(name),
                "the refusal must name {name}, not just complain: {text}"
            );
        }
        assert_eq!(
            &census(db),
            before,
            "bytes, mtime, user_version and the sidecar census are untouched"
        );
    }

    #[test]
    fn a_genuine_unstamped_checkpoint_migrates() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("floor-v0");
        let db = genuine_checkpoint(dir.path(), 0);

        let list = boot_session_load(&db, false, false)
            .expect("a checkpoint of our own first shape upgrades");

        assert_eq!(list.len(), 1, "its one completed session is listed");
        let (_, _, version, _) = census(&db);
        assert_eq!(version, 5, "and the upgrade is stamped");
    }

    #[test]
    fn a_fresh_state_dir_still_creates_a_checkpoint() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("fresh");
        let db = dir.path().join("dedcom.db");

        let list = boot_session_load(&db, false, false)
            .expect("the first run creates the checkpoint it then reads");

        assert!(list.is_empty(), "a brand new checkpoint holds no sessions");
        let (_, _, version, _) = census(&db);
        assert_eq!(version, 5);
    }

    #[test]
    fn a_genuine_v3_checkpoint_migrates_to_v5() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("floor-v3");
        let db = genuine_checkpoint(dir.path(), 3);

        let list = boot_session_load(&db, false, false).expect("an intermediate version upgrades");

        assert_eq!(list.len(), 1);
        let (_, _, version, _) = census(&db);
        assert_eq!(version, 5);
    }

    #[test]
    fn an_unrelated_table_and_its_rows_survive_the_migration() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("extra-table");
        let db = genuine_checkpoint(dir.path(), 3);
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
                 INSERT INTO notes (id, body) VALUES (1, 'kept'), (2, 'also kept');",
            )
            .unwrap();
        }

        boot_session_load(&db, false, false)
            .expect("a table that is not ours is no reason to refuse a checkpoint that is");

        let conn = rusqlite::Connection::open(&db).unwrap();
        let mut stmt = conn.prepare("SELECT id, body FROM notes ORDER BY id").unwrap();
        let rows: Vec<(i64, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![(1, "kept".to_string()), (2, "also kept".to_string())],
            "the foreign table keeps every row, unchanged"
        );
    }

    #[test]
    fn a_foreign_shape_is_refused_without_touching_the_checkpoint() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("foreign");
        let db = foreign_shape(dir.path());
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["scan", "created_at"]);
    }

    #[test]
    fn a_lone_foreign_table_is_not_mistaken_for_a_fresh_database() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("users-only");
        let db = raw_db(
            dir.path(),
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);",
        );
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["scan"]);
    }

    #[test]
    fn a_v5_stamp_missing_a_v5_table_is_refused() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("half-v5");
        let db = genuine_checkpoint(dir.path(), 5);
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch("DROP TABLE scan_membership;").unwrap();
        }
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["scan_membership"]);
    }

    #[test]
    fn a_required_name_held_by_another_object_is_refused() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("file-as-view");
        let db = genuine_checkpoint(dir.path(), 5);
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "DROP TABLE file;
                 CREATE VIEW file AS SELECT 1 AS scan_id, 'x' AS path;",
            )
            .unwrap();
        }
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["file", "view"]);
    }

    /// A genuine v5 checkpoint with one statement run over it. Every product-owned name is at or
    /// below v5 here, so the version rule cannot fire first and each test below is left facing
    /// exactly the axis it means to exercise.
    fn v5_then(tag: &str, ddl: &str) -> (Scratch, std::path::PathBuf) {
        let dir = scratch(tag);
        let db = genuine_checkpoint(dir.path(), 5);
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(ddl).unwrap();
        }
        (dir, db)
    }

    fn assert_v5_refused(tag: &str, ddl: &str, names: &[&str]) {
        let _role = crate::state::store::role_guard();
        let (_dir, db) = v5_then(tag, ddl);
        let before = census(&db);
        assert_refused_untouched(&db, &before, names);
    }

    /// `LIKE` treats `_` as a wildcard, so `NOT LIKE 'sqlite_%'` also hides a foreign table called
    /// `sqlitex` — and a database that reads as holding nothing is one the migration adopts.
    #[test]
    fn a_table_named_like_an_internal_one_is_not_mistaken_for_a_fresh_database() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("sqlitex");
        let db = raw_db(dir.path(), "CREATE TABLE sqlitex (id INTEGER PRIMARY KEY);");
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["scan"]);
    }

    /// The version rule, on a table name: the object is exactly the shape v5 declares, and it is
    /// still refused, because a checkpoint that says v0 cannot hold a name that arrived at v5.
    #[test]
    fn a_future_table_name_is_refused_whatever_its_shape() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("future-table");
        let db = genuine_checkpoint(dir.path(), 0);
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE scan_membership (
                     scan_id    INTEGER PRIMARY KEY,
                     mode       INTEGER NOT NULL,
                     generation INTEGER NOT NULL);",
            )
            .unwrap();
        }
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["scan_membership", "v5", "v0"]);
    }

    /// The same rule on an index name. `file_scan_identity` is chosen because it can be built in
    /// its exact v3 form on a v0 checkpoint — `file` is there from the start — so the refusal can
    /// only be about the version the name belongs to.
    #[test]
    fn a_future_index_name_is_refused_whatever_its_shape() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("future-index");
        let db = genuine_checkpoint(dir.path(), 0);
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE INDEX file_scan_identity ON file(scan_id, device, inode);",
            )
            .unwrap();
        }
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["file_scan_identity", "v3", "v0"]);
    }

    /// The consequential one: our UNIQUE index name taken by an index over someone else's table.
    /// The fixture first shows what that costs — membership loses its uniqueness entirely.
    #[test]
    fn a_product_index_on_a_foreign_table_is_refused() {
        let _role = crate::state::store::role_guard();
        let (_dir, db) = v5_then(
            "index-foreign-owner",
            "DROP INDEX file_group_member_by_path;
             CREATE TABLE notes (scan_id INTEGER, path TEXT);
             CREATE UNIQUE INDEX file_group_member_by_path ON notes(scan_id, path);",
        );
        {
            // The primary key is (scan_id, group_rank, path), so it already forbids the same row
            // twice. What `file_group_member_by_path` alone forbids is one path in TWO groups of
            // one scan — the membership invariant — and with the index gone that goes straight in.
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "INSERT INTO file_group
                        (scan_id, rank, hash, file_count, size, reclaim,
                         object_count, reclaim_state)
                      VALUES (1, 0, lower(hex(zeroblob(32))), 2, 10, 10, 0, 0),
                             (1, 1, replace(lower(hex(zeroblob(32))), '0', '1'), 2, 10, 10, 0, 0);
                 INSERT INTO file_group_member (scan_id, group_rank, path, generation)
                      VALUES (1, 0, '/x/a', 1), (1, 1, '/x/a', 1);",
            )
            .expect("with the real index gone, one path lands in two groups — that is the damage");
        }
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["file_group_member_by_path", "notes"]);
    }

    #[test]
    fn a_product_index_without_its_uniqueness_is_refused() {
        assert_v5_refused(
            "index-not-unique",
            "DROP INDEX file_group_member_by_path;
             CREATE INDEX file_group_member_by_path ON file_group_member(scan_id, path);",
            &["file_group_member_by_path", "not unique"],
        );
    }

    #[test]
    fn a_partial_product_index_is_refused() {
        assert_v5_refused(
            "index-partial",
            "DROP INDEX file_group_member_by_path;
             CREATE UNIQUE INDEX file_group_member_by_path
                 ON file_group_member(scan_id, path) WHERE scan_id > 0;",
            &["file_group_member_by_path", "partial"],
        );
    }

    #[test]
    fn a_product_index_with_a_foreign_collation_is_refused() {
        assert_v5_refused(
            "index-nocase",
            "DROP INDEX file_group_member_by_path;
             CREATE UNIQUE INDEX file_group_member_by_path
                 ON file_group_member(scan_id, path COLLATE NOCASE);",
            &["file_group_member_by_path", "NOCASE"],
        );
    }

    #[test]
    fn a_product_index_sorted_descending_is_refused() {
        assert_v5_refused(
            "index-desc",
            "DROP INDEX file_group_member_by_path;
             CREATE UNIQUE INDEX file_group_member_by_path
                 ON file_group_member(scan_id, path DESC);",
            &["file_group_member_by_path", "descending"],
        );
    }

    #[test]
    fn a_product_index_over_the_wrong_columns_is_refused() {
        assert_v5_refused(
            "index-columns",
            "DROP INDEX file_group_hash;
             CREATE INDEX file_group_hash ON file_group(scan_id);",
            &["file_group_hash", "covers"],
        );
    }

    #[test]
    fn a_product_index_over_an_expression_is_refused() {
        assert_v5_refused(
            "index-expression",
            "DROP INDEX file_group_hash;
             CREATE INDEX file_group_hash ON file_group(lower(hash));",
            &["file_group_hash", "expression"],
        );
    }

    #[test]
    fn a_product_index_name_held_by_a_table_is_refused() {
        assert_v5_refused(
            "index-name-is-a-table",
            "DROP INDEX file_group_hash;
             CREATE TABLE file_group_hash (id INTEGER PRIMARY KEY);",
            &["file_group_hash", "table"],
        );
    }

    /// Today's shape declaring v0 is not a legacy checkpoint, it is an incoherent one: no build
    /// ever wrote `scan_root` at v0, so the stamp and the contents contradict each other. A
    /// `.dump` and reload produces exactly this, and the answer is a refusal that says so rather
    /// than a silent re-stamp — the opener cannot tell a lost stamp from a forged one, and
    /// adopting the file is the branch that has no way back.
    #[test]
    fn a_current_shape_with_a_zeroed_stamp_is_refused() {
        let _role = crate::state::store::role_guard();
        let dir = scratch("stamp-zeroed");
        let db = genuine_checkpoint(dir.path(), 5);
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.pragma_update(None, "user_version", 0i64).unwrap();
        }
        let before = census(&db);

        assert_refused_untouched(&db, &before, &["scan_root", "v4", "v0"]);
    }

    /// The other side of the policy: a name that is not ours is not our business. An unrelated
    /// index on an unrelated table passes, and both are still there afterwards.
    #[test]
    fn an_unrelated_index_and_its_table_survive_the_migration() {
        let _role = crate::state::store::role_guard();
        let (_dir, db) = v5_then(
            "index-unrelated",
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
             CREATE INDEX notes_by_body ON notes(body);
             INSERT INTO notes (id, body) VALUES (1, 'kept');",
        );

        boot_session_load(&db, false, false)
            .expect("an index that is not ours is no reason to refuse a checkpoint that is");

        let conn = rusqlite::Connection::open(&db).unwrap();
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'notes_by_body'",
                [],
                |row| row.get(0),
            )
            .expect("the foreign index is still there");
        assert!(sql.contains("notes(body)"), "and unchanged: {sql}");
        let body: String = conn
            .query_row("SELECT body FROM notes WHERE id = 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(body, "kept", "with its row intact");
    }

    #[test]
    fn commander_and_no_resume_skip_only_this_eager_load() {
        let dir = scratch("skip");
        let db = v6_db(dir.path());

        // Both deliberately load lazily or not at all, so neither touches the store here — and
        // that skip is the ONLY way this function can yield an empty list.
        assert!(
            boot_session_load(&db, true, false)
                .expect("commander skips")
                .is_empty(),
            "commander loads sessions lazily at F12"
        );
        assert!(
            boot_session_load(&db, false, true)
                .expect("--no-resume skips")
                .is_empty(),
            "--no-resume asks for no session list"
        );
        // Their later operations are governed by the F12 route, which fails closed on the same DB.
        assert!(
            boot_session_load(&db, false, false).is_err(),
            "and the classic route still refuses the same checkpoint"
        );
    }
}
