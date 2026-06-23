// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use crate::error::{AppError, Result};
use crate::model::scan::{
    HashProfile, ScanConfig, ScanPhase, ScanProgress, ScanResults, ScanStatus, ScanSummary,
    WalkStage,
};
use crate::state::{ManifestRow, ScanStore};

pub mod governor;
pub mod hash;
mod safe_open;
pub mod verify;
pub mod walk;

/// Result of running the pipeline.
pub enum ScanOutcome {
    Completed(ScanResults),
    Cancelled,
}

/// Batch size for writing the manifest to the DB.
const WALK_BATCH: usize = 2048;
/// Hashing batch size (= the interval between checkpoints and progress updates).
const HASH_CHUNK: usize = 64;

/// Empirical estimate of the grouping-phase peak memory per ONE hashed file:
/// `file_hash_status` (~290 B) + `build_dir_groups` (~2.2 KiB, a replica of the record under each
/// parent directory). /tank measurement 2026-05-25: 2.12M files → ~5.0 GiB. Depends on
/// tree depth. Used only for the WARNING (we don't touch the algorithm).
const GROUPING_BYTES_PER_FILE: u64 = 2560;

/// Starts or resumes a scan.
///
/// `resume` — the id of an unfinished scan (otherwise a new one is created).
/// The pipeline checkpoints hashes to the DB in batches, so it survives a power loss.
/// Each run measures its own segment of active time and accumulates it into `scan_stats`.
pub fn run_scan(
    store: &mut ScanStore,
    config: &ScanConfig,
    resume: Option<i64>,
    verify: bool,
    cancel: &Arc<AtomicBool>,
    mut on_progress: impl FnMut(ScanProgress),
) -> Result<ScanOutcome> {
    let segment_start = Instant::now();

    // `scan_id` is fixed before the phases — so the statistics can be written
    // on any exit path, including cancellation.
    let scan_id = match resume {
        Some(id) => id,
        None => store.begin_scan(config)?,
    };
    store.ensure_scan_stats(scan_id)?;

    // Guard: opening an already-finished scan does NOT rescan and does NOT touch
    // the time metric (`add_elapsed` below). We normally don't get here — `resume_selected`
    // routes Complete to `spawn_open_completed`; this is a safeguard against direct calls.
    if resume.is_some() && store.scan_status(scan_id)?.is_completed() {
        store.ensure_materialized(scan_id)?;
        let summaries = store.group_summaries(scan_id)?;
        let summary = store.scan_summary(scan_id)?;
        on_progress(ScanProgress::Done(summary.clone()));
        return Ok(ScanOutcome::Completed(ScanResults {
            scan_id,
            summaries,
            summary,
        }));
    }

    let environment = crate::zfs::pool::scan_environment(config.storage_type_override.as_deref());
    tracing::info!(
        "scan environment: storage={}, layout={}, ZFS={}",
        environment.storage_type,
        environment.pool_layout,
        environment.zfs_version,
    );
    store.record_scan_environment(scan_id, &environment)?;

    let outcome = run_phases(
        store,
        scan_id,
        config,
        resume.is_some(),
        verify,
        cancel,
        &mut on_progress,
    );

    // The active time of this segment accumulates even on cancellation or error.
    store.add_elapsed(scan_id, segment_start.elapsed().as_secs_f64())?;

    let mut outcome = outcome?;
    if let ScanOutcome::Completed(results) = &mut outcome {
        results.summary.elapsed_seconds = store.elapsed_seconds(scan_id)?;
        store.record_scan_result(scan_id, &results.summary)?;
        on_progress(ScanProgress::Done(results.summary.clone()));
    }
    Ok(outcome)
}

/// Running the phases: walk → hashing → grouping. `Cancelled` — cancellation on any phase.
fn run_phases(
    store: &mut ScanStore,
    scan_id: i64,
    config: &ScanConfig,
    is_resume: bool,
    verify: bool,
    cancel: &Arc<AtomicBool>,
    on_progress: &mut impl FnMut(ScanProgress),
) -> Result<ScanOutcome> {
    // Effective config: on resume we read it from the DB (we need not only
    // `hash_profile`, but also `reuse_hashes` for inheritance before hashing), for
    // a new scan — the one passed in.
    let effective = if is_resume {
        store.load_config(scan_id)?
    } else {
        config.clone()
    };
    let hash_profile = effective.hash_profile;
    // The walk is needed for a new scan and for resuming an unfinished walk (it's cheap).
    let need_walk = !is_resume || store.scan_status(scan_id)? == ScanStatus::Walking;
    if need_walk {
        if is_resume {
            store.clear_files(scan_id)?;
        }
        if !walk_phase(store, scan_id, &effective, cancel, on_progress)? {
            return Ok(ScanOutcome::Cancelled);
        }
        store.set_status(scan_id, ScanStatus::Hashing)?;
    }

    // Inheriting hashes from past scans — EXPLICITLY and idempotently BEFORE
    // hashing: both for a new scan (after walk) and for a resume in the Hashing status
    // (walk skipped). `inherit_hashes` only hits `hash IS NULL`, a repeated call is
    // safe. Without this a resume would re-read the disk if a finished scan with the
    // same (path,size,mtime) appeared LATER than this session's walk.
    if effective.reuse_hashes {
        let inherited = store.inherit_hashes(scan_id)?;
        tracing::info!("hash cache: inherited {inherited} hashes from past scans");
    }

    if !hash_phase(store, scan_id, hash_profile, cancel, on_progress)? {
        return Ok(ScanOutcome::Cancelled);
    }

    on_progress(ScanProgress::Phase(ScanPhase::Grouping));

    // RSS instrumentation of the grouping phase: RSS probes before/after the large
    // structures → dedcom.log (grep `RSS probe`). They measure the profile BEFORE the rework (C1).
    let rss = || crate::tui::human_bytes(crate::sysmon::current_rss_bytes());
    tracing::info!("RSS probe: grouping phase start: {}", rss());

    // Opening an already-finished scan (Complete resume): the directory groups and status
    // were computed earlier — we don't recompute (E2E fix: on /tank this wasted
    // minutes of file_hash_status + build_dir_groups and was uncancellable by Esc).
    let was_complete = store.scan_status(scan_id)?.is_completed();

    if cancel.load(Ordering::Relaxed) {
        return Ok(ScanOutcome::Cancelled);
    }

    // ONE candidate_stats at the finish (after hashing) — reconciliation of hash failures.
    // A candidate without a committed hash (read error / identity-mismatch) stays
    // hash IS NULL → goes into hash_failures. NOT in the per-batch loop (on /tank that would be
    // ~34k heavy GROUP BYs) — exactly once here. Reused for the memory estimate,
    // the final status, and the summary.
    let recon = store.candidate_stats(scan_id)?;
    let hash_failures = recon.total_files - recon.hashed_files;

    if !was_complete {
        // Grouping-phase memory warning — only for the Old path:
        // build_dir_groups holds transiently ~2.5 KiB per hashed file. The Merkle path
        // (`--merkle-dirs`) has O(depth) memory — needs no warning.
        if matches!(
            effective.dir_sig_algo,
            crate::model::duplicate::DirSigAlgo::Old
        ) {
            let hashed_files = recon.hashed_files;
            let est_peak = hashed_files.saturating_mul(GROUPING_BYTES_PER_FILE);
            let free_ram = crate::state::host_profile::available_ram_bytes();
            let notice = format!(
                "Phase 3/3: estimated peak memory ~{} ({} files × ~2.5 KiB); free RAM ~{}{}",
                crate::tui::human_bytes(est_peak),
                hashed_files,
                crate::tui::human_bytes(free_ram),
                if est_peak > free_ram {
                    " — ⚠ LOW, OOM risk: free memory or abort (Esc)"
                } else {
                    ""
                },
            );
            if est_peak > free_ram {
                tracing::warn!("{notice}");
            } else {
                tracing::info!("{notice}");
            }
            on_progress(ScanProgress::Notice(notice));
        }

        // Groups of duplicate directories — for the DirGroupList mode.
        tracing::info!("RSS probe: before file_hash_status: {}", rss());
        // The dir-signature builders receive ALL regular manifest files (with
        // an optional hash), not just `hash IS NOT NULL`. Otherwise an unhashed file
        // (unique-size / failure) is invisible to the signature, and a directory with such an "extra"
        // file gave a false "twin". The completeness rule (suppressing incomplete ones) is inside
        // the builders.
        let mut all_files: Vec<(PathBuf, u64, Option<String>)> = store
            .file_hash_status(scan_id)?
            .into_iter()
            .map(|(path, size, hash)| (path, size, hash.map(|h| hex32(&h))))
            .collect();
        tracing::info!(
            "RSS probe: after file_hash_status ({} manifest files, algo={:?}): {}",
            all_files.len(),
            effective.dir_sig_algo,
            rss()
        );
        match effective.dir_sig_algo {
            crate::model::duplicate::DirSigAlgo::Old => {
                let dir_groups = crate::model::duplicate::build_dir_groups(&all_files);
                tracing::info!(
                    "RSS probe: after build_dir_groups ({} dir groups, Old): {}",
                    dir_groups.len(),
                    rss()
                );
                store.record_dir_groups(scan_id, &dir_groups)?;
            }
            crate::model::duplicate::DirSigAlgo::Merkle => {
                // Path sorting before streaming Merkle (file_hash_status does not
                // guarantee ORDER BY). Then materialization via a temporary table.
                all_files.sort_by(|a, b| a.0.cmp(&b.0));
                store.materialize_dir_groups(scan_id, |emit| {
                    crate::model::duplicate::build_dir_signatures_streaming(all_files, emit)
                })?;
                tracing::info!(
                    "RSS probe: after materialize_dir_groups (Merkle): {}",
                    rss()
                );
            }
        }

        if cancel.load(Ordering::Relaxed) {
            return Ok(ScanOutcome::Cancelled);
        }

        // file_group summaries. On the default path — by SQL aggregation, WITHOUT
        // loading Vec<DuplicateGroup> into RAM (cuts the transient peak on 2.2M /tank).
        // With --verify a byte-for-byte comparison is needed, which can SPLIT groups → we load
        // the groups and write the verified ones the old way (result-identical to the previous behavior).
        if verify {
            tracing::info!("RSS probe: before duplicate_groups (--verify): {}", rss());
            let mut groups = store.duplicate_groups(scan_id)?;
            // Byte-for-byte comparison — protection against a hash collision; may split groups.
            groups = verify::verify_groups(groups);
            crate::model::duplicate::sort_groups_by_benefit(&mut groups);
            tracing::info!(
                "RSS probe: after verify ({} groups): {}",
                groups.len(),
                rss()
            );
            store.record_file_results(scan_id, &groups)?;
        } else {
            store.materialize_file_groups(scan_id)?;
            tracing::info!("RSS probe: after materialize_file_groups (SQL): {}", rss());
        }
        // With a warning if some candidates stayed without a hash (otherwise Complete).
        store.set_status(scan_id, ScanStatus::on_completion(hash_failures))?;
        // Retention: we trim the history of the same roots into the TRASH (softly,
        // recoverably) — finished ones beyond keep + stale unfinished ones.
        let db = store.db_path();
        if let Some(state_dir) = db.as_deref().and_then(|p| p.parent()) {
            let keep = crate::maint::history_keep(state_dir);
            match store.apply_retention(&effective.roots, keep, scan_id) {
                Ok(n) if n > 0 => {
                    tracing::info!("retention: {n} old sessions of the same roots → trash")
                }
                Ok(_) => {}
                Err(err) => tracing::warn!("retention skipped: {err}"),
            }
        }
    }

    // ensure_materialized — a safeguard for the rare was_complete branch without materialization
    // (the normal path already wrote file_group above). The summaries are light.
    store.ensure_materialized(scan_id)?;
    let summaries = store.group_summaries(scan_id)?;
    tracing::info!("RSS probe: grouping phase end: {}", rss());

    // The summary statistics — from the light summaries: groups_found/reclaim no longer
    // require the full Vec<DuplicateGroup> in RAM. Equivalent in value to before.
    let summary = ScanSummary {
        files_scanned: store.manifest_count(scan_id)?,
        groups_found: summaries.len(),
        total_reclaimable_bytes: summaries.iter().map(|s| s.reclaim_bytes).sum(),
        bytes_hashed: recon.hashed_bytes,
        elapsed_seconds: 0.0,
        // Candidates that stayed without a hash at completion time (reconciliation above).
        hash_failures,
    };
    Ok(ScanOutcome::Completed(ScanResults {
        scan_id,
        summaries,
        summary,
    }))
}

/// Walk phase: builds the file manifest. Returns `false` if cancelled.
fn walk_phase(
    store: &mut ScanStore,
    scan_id: i64,
    config: &ScanConfig,
    cancel: &AtomicBool,
    on_progress: &mut impl FnMut(ScanProgress),
) -> Result<bool> {
    on_progress(ScanProgress::Phase(ScanPhase::Walking(WalkStage::Scanning)));
    tracing::info!("scan roots: {:?}", config.roots);
    let mut bench = crate::bench::start("walk_phase");

    let mut total_entries = 0u64;
    let (walked, skipped_non_utf8) = walk::walk(config, cancel, |entries, files, path| {
        total_entries = entries;
        on_progress(ScanProgress::Walked {
            entries,
            files,
            current_path: path.map(std::path::Path::to_path_buf),
        });
    })?;
    if cancel.load(Ordering::Relaxed) {
        return Ok(false);
    }

    // Non-UTF8 guard: we report how many files were skipped
    // because of an undisplayable name — to the scan screen and the log (for transparency).
    if skipped_non_utf8 > 0 {
        let notice = format!(
            "Files skipped due to non-UTF8 names: {skipped_non_utf8} \
             (not scanned for data safety)"
        );
        tracing::warn!("{notice}");
        on_progress(ScanProgress::Notice(notice));
    }

    let rows: Vec<ManifestRow> = walked
        .into_iter()
        .map(|file| ManifestRow {
            path: file.path,
            size: file.size,
            mtime: file.mtime,
            mtime_nsec: file.mtime_nsec,
            ctime_sec: file.ctime_sec,
            ctime_nsec: file.ctime_nsec,
            device: file.device,
            inode: file.inode,
        })
        .collect();

    // Persisting sub-stage: the walk iterator has already handed everything to RAM, now we write
    // the manifest to SQLite in batches. The disk here is only for WAL commits — without a second
    // FS traversal. The screen header names this explicitly.
    on_progress(ScanProgress::Phase(ScanPhase::Walking(
        WalkStage::Persisting,
    )));

    let mut written: u64 = 0;
    for chunk in rows.chunks(WALK_BATCH) {
        store.record_files(scan_id, chunk)?;
        written += chunk.len() as u64;
        on_progress(ScanProgress::Walked {
            entries: total_entries,
            files: written,
            current_path: chunk.last().map(|row| row.path.clone()),
        });
        if cancel.load(Ordering::Relaxed) {
            return Ok(false);
        }
    }
    on_progress(ScanProgress::Walked {
        entries: total_entries,
        files: written,
        current_path: rows.last().map(|row| row.path.clone()),
    });

    bench.set_entries(written);
    Ok(true)
}

/// The open descriptor carries the same temporal identity that was recorded in the manifest
/// during the walk (size + full time + dev/inode). Otherwise the file was changed/swapped between
/// the walk and hashing — we don't commit the hash. dev/inode here is descriptor
/// validation, NOT a reuse key across scans.
fn manifest_matches(opened: &crate::model::action::FileIdentity, row: &ManifestRow) -> bool {
    opened.size == row.size
        && opened.mtime_sec == row.mtime
        && opened.mtime_nsec == row.mtime_nsec
        && opened.ctime_sec == row.ctime_sec
        && opened.ctime_nsec == row.ctime_nsec
        && opened.dev == row.device
        && opened.ino == row.inode
}

/// Hashing phase: hashes candidates in batches, checkpointing the result.
/// Returns `false` if cancelled (the status stays `hashing` — resumable).
fn hash_phase(
    store: &mut ScanStore,
    scan_id: i64,
    profile: HashProfile,
    cancel: &AtomicBool,
    on_progress: &mut impl FnMut(ScanProgress),
) -> Result<bool> {
    on_progress(ScanProgress::Phase(ScanPhase::Hashing));
    let mut bench = crate::bench::start("hash_phase");

    let stats = store.candidate_stats(scan_id)?;
    let mut candidates = store.candidate_files(scan_id)?;
    // Inode order: we read candidates by (device, inode), not in directory-walk
    // order — this clusters disk accesses and cuts the seek storm on HDD (the
    // bottleneck per upstream's measurement on 2×HDD: −21% on a cold scan). On SSD/NVMe harmless
    // (no seeks). The hashing result does not depend on the order — the same files, hashes,
    // groups. Sorting in RAM (~1M rows <1 s) is cheaper than SQL ORDER BY.
    candidates.sort_by_key(|row| (row.device, row.inode));

    let files_total = stats.total_files;
    let bytes_total = stats.total_bytes;
    // On resume some are already hashed — we start the progress from there.
    let mut files_done = stats.hashed_files;
    let mut bytes_done = stats.hashed_bytes;

    // Fix the candidate total/progress in the DB immediately: even if the session
    // is interrupted, the session list shows honest progress without an expensive recompute.
    let _ =
        store.update_candidate_progress(scan_id, files_total, bytes_total, files_done, bytes_done);

    // We compute ETA from the bytes read in THIS session (we don't count those inherited on
    // resume — they were not read from disk). EMA smooths the spikes.
    let phase_start = Instant::now();
    let session_start_bytes = bytes_done;
    let mut ema_rate = 0.0f64;
    // A live accumulator of hash failures over the session (uncommitted candidates: read
    // error / identity-mismatch) — for the "Failed to hash: N" line on the scan screen.
    // The authoritative total is computed at the finish by reconciling candidate_stats.
    let mut hash_failures_seen: u64 = 0;

    on_progress(ScanProgress::Hashing {
        files_done,
        files_total,
        bytes_done,
        bytes_total,
        chunk_done: 0,
        chunk_total: 0,
        current_path: None,
        rate_bytes_per_sec: 0,
        eta_secs: 0,
        hash_failures: hash_failures_seen,
    });

    // The number of reader threads and the CPU/IO priority — by the Resource Governor profile.
    let jobs = governor::jobs_for(
        profile,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2),
    );
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .start_handler(move |_| governor::apply_priority(profile))
        .build()
        .map_err(|err| AppError::msg(format!("hashing pool: {err}")))?;
    tracing::info!(
        "hashing phase: files={files_total}, profile={}, reader threads={jobs}",
        profile.label()
    );

    for chunk in candidates.chunks(HASH_CHUNK) {
        if cancel.load(Ordering::Relaxed) {
            return Ok(false);
        }

        let chunk_total = chunk.len() as u64;
        // Live counters for the current batch: bytes read and files processed.
        let live = AtomicU64::new(0);
        let live_files = AtomicU64::new(0);

        // The batch is hashed in a background thread on the bounded pool; this thread
        // meanwhile ticks the progress — so the counter moves even on a
        // single huge file, instead of freezing until the end of the batch.
        let hashed: Vec<(ManifestRow, [u8; 32])> = thread::scope(|s| {
            let handle = s.spawn(|| {
                pool.install(|| {
                    chunk
                        .par_iter()
                        .filter_map(|row| {
                            tracing::debug!(
                                "hashing {}",
                                crate::textsan::terminal(&row.path.display().to_string())
                            );
                            let result = match hash::hash_file_verified(&row.path, &live) {
                                // The open object matched the walk manifest → commit.
                                Ok((digest, opened)) if manifest_matches(&opened, row) => {
                                    Some((row.clone(), digest))
                                }
                                // The hash was computed, but the identity diverged from the walk — the file
                                // was changed/swapped between walk and hashing: skip.
                                Ok(_) => {
                                    tracing::warn!(
                                        "skip {}: identity changed after the walk",
                                        crate::textsan::terminal(&row.path.display().to_string())
                                    );
                                    None
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        "skip {}: {err}",
                                        crate::textsan::terminal(&row.path.display().to_string())
                                    );
                                    None
                                }
                            };
                            live_files.fetch_add(1, Ordering::Relaxed);
                            result
                        })
                        .collect::<Vec<(ManifestRow, [u8; 32])>>()
                })
            });

            // While the batch is being computed — we send progress every 200 ms.
            while !handle.is_finished() {
                thread::sleep(Duration::from_millis(200));
                // Live bytes read (incl. the current batch's files, not yet committed) —
                // ONLY for rate/ETA (this is read throughput). They do NOT go into the
                // `bytes_done` field: the progress must reflect only committed
                // hashes, otherwise the bar "finished reading" a failed file and would roll back after the checkpoint.
                let read_bytes = bytes_done + live.load(Ordering::Relaxed);
                let (rate, eta, ema) = governor::rate_eta(
                    phase_start.elapsed().as_secs_f64(),
                    read_bytes.saturating_sub(session_start_bytes),
                    bytes_total.saturating_sub(read_bytes),
                    ema_rate,
                );
                ema_rate = ema;
                on_progress(ScanProgress::Hashing {
                    files_done,
                    files_total,
                    // Persisted delta only (see above): monotonic, no roll-back on failures.
                    bytes_done,
                    bytes_total,
                    chunk_done: live_files.load(Ordering::Relaxed),
                    chunk_total,
                    current_path: chunk.first().map(|row| row.path.clone()),
                    rate_bytes_per_sec: rate,
                    eta_secs: eta,
                    hash_failures: hash_failures_seen,
                });
            }
            handle.join().expect("the batch hashing thread panicked")
        });

        // Checkpoint: the batch of fd-verified hashes is committed by a conditional
        // UPDATE by identity. The uncommitted ones (identity race) — to the log, not to success.
        let persisted = store.record_hashes_verified(scan_id, &hashed)?;
        if (persisted.files as usize) < hashed.len() {
            tracing::warn!(
                "checkpoint: {} of {} hashes not committed (identity changed)",
                hashed.len() as u64 - persisted.files,
                hashed.len()
            );
        }

        // Honest DB progress — we advance by the ACTUALLY committed persisted delta,
        // not by the batch size (otherwise %/bytes/ETA are inflated on hash failures). The uncommitted
        // batch candidates (error/identity) we accumulate into the failure counter for the scan screen.
        files_done += persisted.files;
        bytes_done += persisted.bytes;
        hash_failures_seen += chunk_total - persisted.files;
        // Candidate progress in the DB — DB-accurate (persisted delta), for an honest
        // % in the session list.
        let _ = store.update_candidate_progress(
            scan_id,
            files_total,
            bytes_total,
            files_done,
            bytes_done,
        );
        let (rate, eta, ema) = governor::rate_eta(
            phase_start.elapsed().as_secs_f64(),
            bytes_done.saturating_sub(session_start_bytes),
            bytes_total.saturating_sub(bytes_done),
            ema_rate,
        );
        ema_rate = ema;
        on_progress(ScanProgress::Hashing {
            files_done,
            files_total,
            bytes_done,
            bytes_total,
            chunk_done: chunk_total,
            chunk_total,
            current_path: chunk.first().map(|row| row.path.clone()),
            rate_bytes_per_sec: rate,
            eta_secs: eta,
            hash_failures: hash_failures_seen,
        });
        tracing::info!("hash progress: {files_done}/{files_total} files");
    }

    bench.set_entries(files_total);
    Ok(true)
}

/// hex-encoding of a blake3 hash (lowercase) — for directory signatures.
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod hash_failures_tests {
    use super::*;

    /// A unique temporary directory (as in pipeline::hash::tests) — without the tempfile crate.
    fn unique_temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_pipe_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn run_scan_clean_dir_completes_without_warnings() {
        // positive control: a normal scan of readable files → Complete, 0 failures,
        // the files really hashed and grouped (the persisted delta doesn't understate).
        let dir = unique_temp_dir("clean");
        std::fs::write(dir.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(dir.join("b.bin"), b"identical duplicate content").unwrap();

        let mut cfg = ScanConfig::new(vec![dir.clone()]);
        cfg.min_size = 0; // the test files are tiny
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let outcome = run_scan(&mut store, &cfg, None, false, &cancel, |_| {}).unwrap();

        let results = match outcome {
            ScanOutcome::Completed(r) => r,
            ScanOutcome::Cancelled => panic!("expected Completed, not Cancelled"),
        };
        assert_eq!(
            results.summary.hash_failures, 0,
            "a clean scan — no failures"
        );
        assert_eq!(
            results.summary.groups_found, 1,
            "two identical files → one group"
        );
        assert_eq!(
            store.scan_status(results.scan_id).unwrap(),
            ScanStatus::Complete,
            "status Complete without warnings"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_scan_unhashable_candidates_complete_with_warnings() {
        // negative control: candidates that cannot be hashed (the files don't exist),
        // → completion with a warning, hash_failures=2, progress NOT inflated. The resume path
        // (Hashing status) skips the walk and hashes the directly written manifest.
        let mut store = ScanStore::open_in_memory().unwrap();
        let cfg = ScanConfig::new(vec![PathBuf::from("/dedcom-nonexistent-root")]);
        let id = store.begin_scan(&cfg).unwrap();
        // Two candidates of the same size whose paths don't exist → open/hash will fail.
        let missing = |p: &str, ino: u64| ManifestRow {
            path: PathBuf::from(p),
            size: 4096,
            inode: ino,
            device: 1,
            ..Default::default()
        };
        store
            .record_files(
                id,
                &[
                    missing("/dedcom-nonexistent-root/a", 1),
                    missing("/dedcom-nonexistent-root/b", 2),
                ],
            )
            .unwrap();
        store.set_status(id, ScanStatus::Hashing).unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let outcome = run_scan(&mut store, &cfg, Some(id), false, &cancel, |_| {}).unwrap();

        let results = match outcome {
            ScanOutcome::Completed(r) => r,
            ScanOutcome::Cancelled => panic!("expected Completed, not Cancelled"),
        };
        assert_eq!(
            results.summary.hash_failures, 2,
            "both candidates not hashed"
        );
        assert_eq!(
            store.scan_status(id).unwrap(),
            ScanStatus::CompleteWithWarnings,
            "status with a warning"
        );
        // Progress NOT inflated: persisted delta = 0, so cand_files_hashed=0 (with the old
        // `+= chunk_total` it would be 2 here). Visible through the session list.
        let info = store
            .list_scans()
            .unwrap()
            .into_iter()
            .find(|s| s.scan_id == id)
            .expect("scan in the session list");
        assert_eq!(
            info.files_hashed, 0,
            "no file committed — the progress is honest"
        );
    }

    #[test]
    fn resume_completes_pending_candidates_without_residual_warning() {
        // end-to-end resume: run 1 interrupted EXACTLY on entry into the hashing phase (walk
        // wrote the manifest, no candidate hashed → Hashing status, resumable);
        // run 2 (resume, walk skipped) finishes hashing the candidates → Complete, hash_failures=0,
        // WITHOUT a residual warning. Proves that files uncommitted-at-the-moment-of-interruption
        // do not turn into a permanent warning, but are reconciled by fact.
        let dir = unique_temp_dir("resume");
        std::fs::write(dir.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(dir.join("b.bin"), b"identical duplicate content").unwrap();

        let mut cfg = ScanConfig::new(vec![dir.clone()]);
        cfg.min_size = 0;
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store.begin_scan(&cfg).unwrap();

        // Run 1: we trigger cancellation as soon as the pipeline enters the hashing phase —
        // by this moment the walk has already committed the manifest, no candidate is committed.
        let cancel1 = Arc::new(AtomicBool::new(false));
        let trip = Arc::clone(&cancel1);
        let outcome1 = run_scan(&mut store, &cfg, Some(id), false, &cancel1, move |p| {
            if matches!(p, ScanProgress::Phase(ScanPhase::Hashing)) {
                trip.store(true, Ordering::Relaxed);
            }
        })
        .unwrap();
        assert!(
            matches!(outcome1, ScanOutcome::Cancelled),
            "run 1 interrupted"
        );
        assert_eq!(
            store.scan_status(id).unwrap(),
            ScanStatus::Hashing,
            "the interrupted scan is resumable"
        );
        let mid = store.candidate_stats(id).unwrap();
        assert_eq!(
            (mid.total_files, mid.hashed_files),
            (2, 0),
            "2 candidates await hashing (none committed)"
        );

        // Run 2: resume (walk skipped) finishes hashing both → Complete, without a warning.
        let cancel2 = Arc::new(AtomicBool::new(false));
        let outcome2 = run_scan(&mut store, &cfg, Some(id), false, &cancel2, |_| {}).unwrap();
        let results = match outcome2 {
            ScanOutcome::Completed(r) => r,
            ScanOutcome::Cancelled => panic!("run 2 should complete"),
        };
        assert_eq!(
            results.summary.hash_failures, 0,
            "after the resume there are no failures"
        );
        assert_eq!(
            results.summary.groups_found, 1,
            "the identical files are grouped"
        );
        assert_eq!(
            store.scan_status(id).unwrap(),
            ScanStatus::Complete,
            "Complete, not CompleteWithWarnings — no residual warning"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
