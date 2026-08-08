// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use crate::error::{AppError, Result};
use crate::model::omission::{
    LegacyContext, OmissionSummary, ScanAccounting, SignatureContext, SnapshotOutcome,
};
use crate::model::scan::{
    HashProfile, OmissionAccounting, ScanConfig, ScanPhase, ScanProgress, ScanResults, ScanStatus,
    ScanSummary, WalkStage,
};
use crate::state::{ManifestRow, MembershipMode, PublishMode, ScanStore};
use walk::{OmissionSnapshot, SnapshotUnavailable, WalkOutcome};

pub mod governor;
pub mod hash;
pub mod roots;
mod safe_open;
pub mod verify;
pub mod walk;

/// Result of running the pipeline.
pub enum ScanOutcome {
    Completed(ScanResults),
    Cancelled,
}

/// What the walk phase left behind for the completion accounting.
enum WalkPublication {
    /// The walk or the manifest persist was cancelled; nothing was published.
    Cancelled,
    /// The omission ledger was committed atomically; the grouping-phase snapshot reads it back.
    Committed,
    /// The expected no-authority fallback: the configuration cannot carry a root authority, so
    /// nothing was published — and these are the events the walk observed without attribution.
    NoAuthority { observed: OmissionSummary },
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
    // `&AtomicBool`, not `&Arc<…>`: the flag is only ever read here, and the process-wide signal
    // flag is a plain static. An `Arc<AtomicBool>` caller still passes `&cancel` unchanged.
    cancel: &AtomicBool,
    mut on_progress: impl FnMut(ScanProgress),
) -> Result<ScanOutcome> {
    let segment_start = Instant::now();

    // Fail-closed root set, on every invocation and before anything is written. A root set where one
    // tree is reachable twice has no honest result to report, so it never becomes a scan at all.
    // Resume is not an exemption: an unfinished scan from a build without this check can carry
    // overlapping roots, and an alias can appear after the scan was created. The walk's alias guard
    // is not a substitute — it accepts the same pathname twice by design, and nested roots collapse
    // to identical manifest pathnames.
    roots::ensure_disjoint(&config.roots)?;

    // `scan_id` is fixed before the phases — so the statistics can be written
    // on any exit path, including cancellation.
    let scan_id = match resume {
        Some(id) => {
            // A resume walks and hashes the roots stored with the scan, whatever the caller happened
            // to pass, so those are the ones that have to be disjoint. Checked before the first
            // resume-side write.
            roots::ensure_disjoint(&store.load_config(id)?.roots)?;
            id
        }
        None => store.begin_scan(config)?,
    };
    store.ensure_scan_stats(scan_id)?;

    // Guard: opening an already-finished scan does NOT rescan and does NOT touch
    // the time metric (`add_elapsed` below). We normally don't get here — `resume_selected`
    // routes Complete to the browsing actor; this is a safeguard against direct calls.
    //
    // Preparation is browse-only: a legacy checkpoint gets viewable summaries and keeps its
    // Unknown authority, an authoritative one is validated and left byte-identical. Neither
    // mints membership, and no group list travels back — whoever shows the result reads it
    // through the authority itself.
    if resume.is_some() && store.scan_status(scan_id)?.is_completed() {
        store.prepare_legacy_for_viewing(scan_id)?;
        let summary = store.scan_summary(scan_id)?;
        on_progress(ScanProgress::Done(summary.clone()));
        return Ok(ScanOutcome::Completed(ScanResults { scan_id, summary }));
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
    cancel: &AtomicBool,
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
    // The walk is needed for a new scan, for resuming an unfinished walk, and — since R3D — for
    // any Hashing resume whose persisted completeness ledger is not fully authoritative. A
    // Roots-unavailable walk holds its observed warnings only in RAM, so a process exit between
    // `set_status(Hashing)` and completion would otherwise resume into a clean `Complete` with
    // every counter lost; a pre-ledger, generation-zero or drifted scan re-walks for the same
    // price and earns a fresh authority through `clear_files`. A fully authoritative ledger keeps
    // the cheap walk-less resume. Hard snapshot corruption propagates as `Err` — it is never
    // "solved" by re-walking over it.
    let status = store.scan_status(scan_id)?;
    let need_walk = !is_resume
        || status == ScanStatus::Walking
        || (status == ScanStatus::Hashing && !store.ledger_authoritative(scan_id)?);
    let mut walk_publication: Option<WalkPublication> = None;
    if need_walk {
        if is_resume {
            store.clear_files(scan_id)?;
        }
        let publication = walk_phase(store, scan_id, &effective, cancel, on_progress)?;
        if matches!(publication, WalkPublication::Cancelled) {
            return Ok(ScanOutcome::Cancelled);
        }
        walk_publication = Some(publication);
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

    // The omission account this run established; the rare was_complete path reads it back from
    // the store instead, exactly as a reopen would.
    let mut run_accounting: Option<OmissionAccounting> = None;

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

        // The one completeness authority for this scan's builders and its final accounting: the
        // persisted snapshot, loaded once. `Bounded` supplies the context; only the typed expected
        // `Unavailable` selects `LegacyContext` — a hard error propagates and never falls back.
        let snapshot_outcome = store.completeness_snapshot(scan_id)?;
        let legacy = LegacyContext;
        let ctx: &dyn SignatureContext = match &snapshot_outcome {
            SnapshotOutcome::Bounded(snapshot) => snapshot,
            SnapshotOutcome::Unavailable(_) => &legacy,
        };

        // Groups of duplicate directories — for the DirGroupList mode.
        tracing::info!("RSS probe: before file_hash_status: {}", rss());
        // The dir-signature builders receive ALL regular manifest files (with
        // an optional hash), not just `hash IS NOT NULL`. Otherwise an unhashed file
        // (unique-size / failure) is invisible to the signature, and a directory with such an "extra"
        // file gave a false "twin". The completeness rules (the unhashed-file rule and the ledger
        // suppression) are inside the builders.
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
                let attributed =
                    crate::model::duplicate::build_dir_groups_in_context(&all_files, ctx)?;
                tracing::info!(
                    "RSS probe: after build_dir_groups_in_context ({} dir groups, Old): {}",
                    attributed.len(),
                    rss()
                );
                // Trust is transient by contract: `dir_dedup` has no column for it, and every
                // reader recomputes against the then-current snapshot.
                let dir_groups: Vec<crate::model::duplicate::DirGroup> =
                    attributed.into_iter().map(|group| group.group).collect();
                store.record_dir_groups(scan_id, &dir_groups)?;
            }
            crate::model::duplicate::DirSigAlgo::Merkle => {
                // Path sorting before streaming Merkle (file_hash_status does not
                // guarantee ORDER BY). Then materialization via a temporary table.
                all_files.sort_by(|a, b| a.0.cmp(&b.0));
                store.materialize_dir_groups(scan_id, |emit| {
                    crate::model::duplicate::build_dir_signatures_streaming_in_context(
                        all_files,
                        ctx,
                        |signature| {
                            emit(
                                signature.path,
                                signature.signature,
                                signature.size,
                                signature.file_count,
                            )
                        },
                    )
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

        // The publication. An ordinary hash-only completion publishes `Derived` — one SQL
        // aggregation, no `Vec<DuplicateGroup>` in RAM (that is what keeps the transient peak
        // down on 2.2M /tank) — and membership is the manifest by each summary's digest.
        // `--verify` compares bytes, which can SPLIT one digest into two populations, so it
        // publishes `Explicit` from exactly the populations verification returned: two ranks
        // may then share a digest legitimately, each answering only for its own members.
        if verify {
            verify_and_publish(store, scan_id)?;
        } else {
            store.publish_results(scan_id, PublishMode::Derived)?;
            tracing::info!("RSS probe: after publish_results (Derived SQL): {}", rss());
        }
        // The scan-wide account, from the same snapshot the builders used. A live completion is
        // structurally either freshly committed, an authoritative walk-less resume, or the typed
        // Roots fallback carrying its observed events — anything else is a violated invariant of
        // the resume rule above, and it errors loudly rather than degrading quietly.
        let (accounting, warning_events) = match &snapshot_outcome {
            SnapshotOutcome::Bounded(snapshot) => match snapshot.scan_accounting()? {
                ScanAccounting::Exact(totals) => {
                    let events = warning_events_of(&totals)?;
                    (OmissionAccounting::Ledger(totals), events)
                }
                ScanAccounting::Unavailable => {
                    return Err(AppError::msg(format!(
                        "scan {scan_id} reached completion without an authoritative completeness \
                         ledger; this is a wiring defect — the resume rule re-walks exactly this \
                         state"
                    )))
                }
            },
            SnapshotOutcome::Unavailable(_) => match walk_publication.take() {
                Some(WalkPublication::NoAuthority { observed }) => {
                    let events = warning_events_of(&observed)?;
                    (OmissionAccounting::Observed(observed), events)
                }
                _ => {
                    return Err(AppError::msg(format!(
                        "scan {scan_id} has no completeness authority and no observed account; \
                         this is a wiring defect — a no-authority completion always walked in \
                         this run"
                    )))
                }
            },
        };
        // With a warning if some candidates stayed without a hash, or if the walk left anything
        // out for a reason the operator did not choose (otherwise Complete).
        store.set_status(
            scan_id,
            ScanStatus::on_completion(hash_failures, warning_events),
        )?;
        // ONE aggregate omission notice, emitted once the publication result is known. It subsumes
        // the old standalone non-UTF8 notice: same fact, one owner, all reasons together.
        if let Some(notice) = omission_notice(&accounting)? {
            tracing::warn!("{notice}");
            on_progress(ScanProgress::Notice(notice));
        }
        run_accounting = Some(accounting);
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

    // A safeguard for the rare was_complete branch, which published nothing in this run: it
    // gets browse-only summaries and keeps whatever authority it had. The normal path just
    // published, so preparation validates that publication and changes nothing.
    store.prepare_legacy_for_viewing(scan_id)?;
    // How many groups this scan now holds, read through the authority that owns them. A scan
    // with no authority (the legacy branch) reports its candidate digests instead of a zero
    // that would read as «no duplicates».
    let groups_found = published_group_count(store, scan_id)?;
    tracing::info!("RSS probe: grouping phase end: {}", rss());

    // The summary statistics — from the light summaries: groups_found no longer requires the full
    // Vec<DuplicateGroup> in RAM. The reclaim total is READ from where it was published rather
    // than re-summed here: publishing wrote the rows and the total together, and a second sum in
    // a different place is a second answer waiting to disagree.
    let summary = ScanSummary {
        files_scanned: store.manifest_count(scan_id)?,
        groups_found,
        reclaim: store.scan_reclaim(scan_id)?,
        already_linked_sets: store.already_linked_sets(scan_id)?,
        bytes_hashed: recon.hashed_bytes,
        elapsed_seconds: 0.0,
        // Candidates that stayed without a hash at completion time (reconciliation above).
        hash_failures,
        omissions: match run_accounting {
            Some(accounting) => accounting,
            None => store.scan_omission_accounting(scan_id)?,
        },
    };
    Ok(ScanOutcome::Completed(ScanResults { scan_id, summary }))
}

/// How many groups the scan's CURRENT publication holds.
///
/// Read through the membership snapshot, so the number and the groups the operator will browse
/// come from one authority. A scan with no authority at all — the legacy checkpoint the
/// was-complete branch reopens — has no published groups; it reports how many raw-digest
/// candidates it carries, which is what its browse-only view will show, rather than a zero that
/// would read as «this scan found no duplicates».
fn published_group_count(store: &ScanStore, scan_id: i64) -> Result<usize> {
    let snapshot = store
        .membership_snapshot(scan_id)
        .map_err(|miss| AppError::msg(format!("scan {scan_id}: {miss:?}")))?;
    if snapshot.mode() == MembershipMode::Unknown {
        let candidates = snapshot
            .unknown_candidates()
            .map_err(|miss| AppError::msg(format!("scan {scan_id}: {miss:?}")))?;
        return Ok(candidates.map_or(0, |view| view.candidates.len()));
    }
    let summaries = snapshot
        .summaries()
        .map_err(|miss| AppError::msg(format!("scan {scan_id}: {miss:?}")))?;
    Ok(summaries.groups.len())
}

/// Walk phase: builds the file manifest and publishes what the walk left out.
///
/// Publication is the last act of the phase — after the complete manifest persist and a final
/// cancellation check, before the caller advances the status to `Hashing` — so the ledger always
/// describes exactly the manifest beside it, and a cancelled or failed walk can never publish.
fn walk_phase(
    store: &mut ScanStore,
    scan_id: i64,
    config: &ScanConfig,
    cancel: &AtomicBool,
    on_progress: &mut impl FnMut(ScanProgress),
) -> Result<WalkPublication> {
    on_progress(ScanProgress::Phase(ScanPhase::Walking(WalkStage::Scanning)));
    tracing::info!("scan roots: {:?}", config.roots);
    let mut bench = crate::bench::start("walk_phase");

    let mut total_entries = 0u64;
    let outcome = walk::walk_collecting(config, cancel, |entries, files, path| {
        total_entries = entries;
        on_progress(ScanProgress::Walked {
            entries,
            files,
            current_path: path.map(std::path::Path::to_path_buf),
        });
    })?;
    let (walked, omissions) = match outcome {
        WalkOutcome::Cancelled { files } => {
            tracing::info!(
                "walk cancelled after {} files; nothing persisted, nothing published",
                files.len()
            );
            return Ok(WalkPublication::Cancelled);
        }
        WalkOutcome::Finished { files, omissions } => (files, omissions),
    };
    if cancel.load(Ordering::Relaxed) {
        return Ok(WalkPublication::Cancelled);
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
            nlink: file.nlink,
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
            return Ok(WalkPublication::Cancelled);
        }
    }
    on_progress(ScanProgress::Walked {
        entries: total_entries,
        files: written,
        current_path: rows.last().map(|row| row.path.clone()),
    });

    // Final cancellation check, then publication. Every cancel/error exit above happens before
    // this line, which is what makes «a cancelled walk never publishes» structural.
    if cancel.load(Ordering::Relaxed) {
        return Ok(WalkPublication::Cancelled);
    }
    let publication = publish_walk_omissions(store, scan_id, omissions)?;

    bench.set_entries(written);
    Ok(publication)
}

/// The exhaustive publication decision — one place, so a variant added later cannot be routed
/// quietly. `Roots` is the only expected fallback; the three collector failures and the observed
/// overflow mean the walk cannot truthfully account what it saw, and they fail the scan exactly
/// as a refused `commit_omissions` does.
fn publish_walk_omissions(
    store: &mut ScanStore,
    scan_id: i64,
    omissions: OmissionSnapshot,
) -> Result<WalkPublication> {
    match omissions {
        OmissionSnapshot::Publishable(map) => {
            store.commit_omissions(scan_id, &map)?;
            Ok(WalkPublication::Committed)
        }
        OmissionSnapshot::Unavailable(SnapshotUnavailable::Roots { why, observed }) => {
            tracing::warn!(
                "scan {scan_id}: directory completeness will be reported as unknown — {}",
                why.explain()
            );
            Ok(WalkPublication::NoAuthority { observed })
        }
        OmissionSnapshot::Unavailable(
            why @ (SnapshotUnavailable::CountOverflow { .. }
            | SnapshotUnavailable::CountNotStorable { .. }
            | SnapshotUnavailable::UnregisteredRoot { .. }
            | SnapshotUnavailable::ObservedOverflow { .. }),
        ) => Err(collector_failure(scan_id, &why)),
    }
}

/// Names the exact cell the collector could not represent. Loud on purpose: completing the scan
/// would publish a result whose omission account is silently short.
fn collector_failure(scan_id: i64, why: &SnapshotUnavailable) -> AppError {
    let cell = |root: &crate::model::omission::PathKey,
                directory: &crate::model::omission::PathKey,
                reason: &crate::model::omission::OmissionReason| {
        format!(
            "{} at {} under root {}",
            reason.as_str(),
            crate::textsan::terminal(directory.as_str()),
            crate::textsan::terminal(root.as_str())
        )
    };
    match why {
        SnapshotUnavailable::CountOverflow {
            root,
            directory,
            reason,
        } => AppError::msg(format!(
            "scan {scan_id} aborted: the omission count overflowed while aggregating {} — the \
             walk cannot truthfully account what it left out. Rescan into a fresh session.",
            cell(root, directory, reason)
        )),
        SnapshotUnavailable::CountNotStorable {
            root,
            directory,
            reason,
        } => AppError::msg(format!(
            "scan {scan_id} aborted: the omission count for {} exceeds what the checkpoint can \
             store, so the ledger cannot be published truthfully. Rescan into a fresh session.",
            cell(root, directory, reason)
        )),
        SnapshotUnavailable::UnregisteredRoot {
            root,
            directory,
            reason,
        } => AppError::msg(format!(
            "scan {scan_id} aborted: an omission event ({}) arrived for a root the collector was \
             never seeded with — a wiring defect, not an operator problem. Please report it.",
            cell(root, directory, reason)
        )),
        SnapshotUnavailable::ObservedOverflow { reason } => AppError::msg(format!(
            "scan {scan_id} aborted: the global omission tally overflowed while counting {} \
             events — the walk cannot truthfully account what it left out. Rescan into a fresh \
             session.",
            reason.as_str()
        )),
        SnapshotUnavailable::Roots { .. } => {
            unreachable!("Roots is the expected fallback and is routed before failure construction")
        }
    }
}

/// Events of the reasons an operator did not choose: everything that is not an intentional
/// min/max/extension filter, including `unsupported_entry`. Checked — a total that cannot be
/// represented is an error, never a smaller number than the truth.
fn warning_events_of(totals: &OmissionSummary) -> Result<u64> {
    let mut total: u64 = 0;
    for (reason, count) in totals.per_reason() {
        if !reason.is_intentional_filter() {
            total = total
                .checked_add(count.get())
                .ok_or_else(|| AppError::msg("omission counts overflowed while aggregating"))?;
        }
    }
    Ok(total)
}

/// The one aggregate omission notice, or `None` when there is nothing to say. Zero clauses are
/// omitted; the observed account carries the honest suffix about its own persistence.
fn omission_notice(accounting: &OmissionAccounting) -> Result<Option<String>> {
    let (totals, suffix) = match accounting {
        OmissionAccounting::Ledger(totals) => (totals, ""),
        OmissionAccounting::Observed(totals) => (
            totals,
            " (details not persisted: no completeness authority)",
        ),
        OmissionAccounting::Unavailable => return Ok(None),
    };
    if totals.is_empty() {
        return Ok(None);
    }
    let mut clauses: Vec<String> = Vec::new();
    let files = totals.known_omitted_files()?;
    if files > 0 {
        clauses.push(format!("{files} files omitted"));
    }
    let errors = totals.unknown_cardinality_events();
    if errors > 0 {
        clauses.push(format!("{errors} walk errors (unknown files hidden)"));
    }
    let entries = totals.unsupported_entries()?;
    if entries > 0 {
        clauses.push(format!("{entries} unsupported entries"));
    }
    Ok(Some(format!(
        "Scan left gaps: {} — affected directories are not exact twins{suffix}",
        clauses.join(", ")
    )))
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

    // Immediately after inheritance and before any candidate is chosen: give every alias of an
    // object the digest one of its pathnames inherited. An object whose aliases are all filled in
    // this way is no longer a candidate and costs zero reads. Refuses if two aliases inherited
    // different digests — see `propagate_inherited_hashes`.
    let propagated = store.propagate_inherited_hashes(scan_id)?;
    if propagated > 0 {
        tracing::info!("hash reuse: {propagated} aliases filled from an inherited digest");
    }

    let stats = store.candidate_stats(scan_id)?;
    let mut candidates = store.candidate_objects(scan_id)?;
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
    // Content reads this phase performs: one attempt per candidate object. The bench entry count
    // must mean reads, so it cannot be the path-row total — propagated aliases are exactly the
    // reads that did NOT happen.
    let mut objects_read: u64 = 0;

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
        if (persisted.representatives as usize) < hashed.len() {
            tracing::warn!(
                "checkpoint: {} of {} hashes not committed (identity changed)",
                hashed.len() as u64 - persisted.representatives,
                hashed.len()
            );
        }

        // Honest DB progress — we advance by the ACTUALLY committed persisted delta,
        // not by the batch size (otherwise %/bytes/ETA are inflated on hash failures). The uncommitted
        // batch candidates (error/identity) we accumulate into the failure counter for the scan screen.
        files_done += persisted.files;
        bytes_done += persisted.bytes;
        objects_read += chunk_total;
        // Against the REPRESENTATIVES, never against `files`: one representative can complete
        // several pathnames, so `files` may exceed the batch size and the subtraction would
        // underflow. A failure is a candidate object whose representative did not commit.
        hash_failures_seen += chunk_total - persisted.representatives;
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

    bench.set_entries(objects_read);
    Ok(true)
}

/// The `--verify` publication boundary: loads the candidate groups, byte-verifies ALL of them
/// and only then publishes the surviving populations — the publication is never reached when
/// any group failed to verify, so a read failure surfaces as the scan's error instead of an
/// empty or shrunken published result. Returns the verified group count.
fn verify_and_publish(store: &mut ScanStore, scan_id: i64) -> Result<usize> {
    let rss = || crate::tui::human_bytes(crate::sysmon::current_rss_bytes());
    tracing::info!("RSS probe: before duplicate_groups (--verify): {}", rss());
    let groups = store.duplicate_groups(scan_id)?;
    // Byte-for-byte comparison — protection against a hash collision; may split groups.
    // A split changes which allocations a group holds, so its worth is recomputed from
    // the surviving membership inside the publication — never carried over.
    let groups = verify::verify_groups(groups)?;
    tracing::info!(
        "RSS probe: after verify ({} groups): {}",
        groups.len(),
        rss()
    );
    // Explicit membership: every surviving pathname gets a member row against the rank the
    // authoritative reclaim order assigned it, so a rejected pathname has no row at all and
    // cannot be handed back by any reader.
    store.publish_results(scan_id, PublishMode::Explicit(&groups))?;
    Ok(groups.len())
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
    use std::sync::Arc;

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

    /// A root set where one tree is reachable twice is refused before anything is written: no scan
    /// row, no manifest, no result. The same tree scanned by one root still completes normally.
    #[test]
    fn conflicting_roots_are_refused_before_a_scan_row_exists() {
        let dir = unique_temp_dir("nested_roots");
        let inner = dir.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(dir.join("b.bin"), b"identical duplicate content").unwrap();

        let mut cfg = ScanConfig::new(vec![dir.clone(), inner.clone()]);
        cfg.min_size = 0;
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        // Not `expect_err`: `ScanOutcome` has no `Debug`, and adding one is not this commit's job.
        let text = match run_scan(&mut store, &cfg, None, false, &cancel, |_| {}) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("nested roots must not start a scan"),
        };
        assert!(
            text.contains("nested roots"),
            "the class must be named: {text}"
        );
        assert!(
            text.contains(&inner.display().to_string()),
            "both roots must be named: {text}"
        );

        let counts = store.db_counts().unwrap();
        assert_eq!(counts.scans, 0, "begin_scan was never reached");
        assert_eq!(counts.file_rows, 0, "and no manifest row was written");
        assert!(
            store.list_scans().unwrap().is_empty(),
            "no session to resume"
        );

        // Control: one root over the same tree scans to completion.
        let mut ok = ScanConfig::new(vec![dir.clone()]);
        ok.min_size = 0;
        ok.exclude_globs = Vec::new();
        let outcome = run_scan(&mut store, &ok, None, false, &cancel, |_| {})
            .expect("a disjoint root set still scans");
        match outcome {
            ScanOutcome::Completed(results) => assert_eq!(
                results.summary.groups_found, 1,
                "the two identical files are still found"
            ),
            ScanOutcome::Cancelled => panic!("expected Completed"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Resume is not an exemption. An unfinished scan whose stored roots overlap — what a build
    /// without the preflight could leave behind — must be refused before any resume-side write, and
    /// nothing about it may be published.
    #[test]
    fn a_resumed_scan_with_conflicting_roots_is_refused() {
        let dir = unique_temp_dir("resume_roots");
        let inner = dir.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(dir.join("b.bin"), b"identical duplicate content").unwrap();

        // Seeded through the store, exactly as an older build would have: `begin_scan` directly, so
        // the fresh-scan preflight never ran, then a resumable status.
        let mut cfg = ScanConfig::new(vec![dir.clone(), inner.clone()]);
        cfg.min_size = 0;
        cfg.exclude_globs = Vec::new();
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store.begin_scan(&cfg).unwrap();
        store.set_status(id, ScanStatus::Hashing).unwrap();
        assert!(
            store.scan_status(id).unwrap().is_resumable(),
            "the seeded scan must look resumable"
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let text = match run_scan(&mut store, &cfg, Some(id), false, &cancel, |_| {}) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("a resume must not bypass the root preflight"),
        };
        assert!(
            text.contains("nested roots"),
            "the class must be named: {text}"
        );
        assert!(
            text.contains(&inner.display().to_string()),
            "both roots must be named: {text}"
        );

        let counts = store.db_counts().unwrap();
        assert_eq!(counts.scans, 1, "no new scan was created");
        assert_eq!(counts.file_rows, 0, "no manifest row was written");
        assert_eq!(
            store.scan_status(id).unwrap(),
            ScanStatus::Hashing,
            "the status is untouched — certainly not completed"
        );
        assert!(
            !store.results_materialized(id).unwrap(),
            "no result was published"
        );
        assert!(
            store.browse_summaries(id).unwrap().is_empty(),
            "and no group summary"
        );
        // `add_elapsed` is the last resume-side write of `run_scan`; 0 proves it never ran (and an
        // absent stats row is the same answer).
        assert_eq!(
            store.elapsed_seconds(id).unwrap_or(0.0),
            0.0,
            "no time was accumulated for the refused resume"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The stored roots are the ones a resume actually walks, so they are the ones that must be
    /// disjoint — even when the caller hands in a perfectly clean set. Without this, a TUI resume that
    /// passes its own config would slip past the check that the supplied set happens to satisfy.
    #[test]
    fn a_resume_is_validated_against_the_roots_stored_with_the_scan() {
        let dir = unique_temp_dir("resume_stored_roots");
        let inner = dir.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("a.bin"), b"identical duplicate content").unwrap();

        let mut stored = ScanConfig::new(vec![dir.clone(), inner.clone()]);
        stored.min_size = 0;
        stored.exclude_globs = Vec::new();
        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store.begin_scan(&stored).unwrap();
        store.set_status(id, ScanStatus::Hashing).unwrap();

        // What the caller passes is disjoint on its own — only the stored set conflicts.
        let mut supplied = ScanConfig::new(vec![dir.clone()]);
        supplied.min_size = 0;
        supplied.exclude_globs = Vec::new();
        assert!(
            roots::ensure_disjoint(&supplied.roots).is_ok(),
            "the supplied set must be innocent, or the test proves nothing"
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let text = match run_scan(&mut store, &supplied, Some(id), false, &cancel, |_| {}) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("the stored roots must be validated on resume"),
        };
        assert!(
            text.contains("nested roots"),
            "the class must be named: {text}"
        );
        assert_eq!(
            store.db_counts().unwrap().file_rows,
            0,
            "no manifest row was written"
        );
        assert_eq!(
            store.scan_status(id).unwrap(),
            ScanStatus::Hashing,
            "the status is untouched"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_scan_unhashable_candidates_complete_with_warnings() {
        // negative control: candidates that cannot be hashed (the files don't exist),
        // → completion with a warning, hash_failures=2, progress NOT inflated. The resume path
        // (Hashing status, fully authoritative ledger) skips the walk and hashes the directly
        // written manifest — without the committed ledger the resume rule would re-walk the
        // nonexistent root and replace this seeded manifest.
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
        let empty_ledger = std::collections::BTreeMap::from([(
            crate::model::omission::PathKey::new(std::path::Path::new("/dedcom-nonexistent-root"))
                .unwrap(),
            crate::model::omission::OmissionCounts::new(),
        )]);
        store.commit_omissions(id, &empty_ledger).unwrap();
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

    /// One walk fires exactly one `Walking(Scanning)` phase event, so counting those pins how
    /// many walks a resume performed — the clean witness the accounting matrix asks for.
    fn counting_progress(
        walks: std::sync::Arc<AtomicU64>,
        notices: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> impl FnMut(ScanProgress) {
        move |progress| match progress {
            ScanProgress::Phase(ScanPhase::Walking(WalkStage::Scanning)) => {
                walks.fetch_add(1, Ordering::Relaxed);
            }
            ScanProgress::Notice(text) => notices.lock().unwrap().push(text),
            _ => {}
        }
    }

    fn make_fifo(path: &std::path::Path) {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(name.as_ptr(), 0o644) };
        assert_eq!(rc, 0, "mkfifo failed for {}", path.display());
    }

    /// Interrupts a scan at the entry into the hashing phase and returns the walk count of that
    /// first run. The walk has committed by then; no candidate has.
    fn interrupt_at_hashing(store: &mut ScanStore, cfg: &ScanConfig, resume: Option<i64>) -> u64 {
        let cancel = Arc::new(AtomicBool::new(false));
        let trip = Arc::clone(&cancel);
        let walks = std::sync::Arc::new(AtomicU64::new(0));
        let walked = std::sync::Arc::clone(&walks);
        let outcome = run_scan(store, cfg, resume, false, &cancel, move |p| {
            if matches!(
                p,
                ScanProgress::Phase(ScanPhase::Walking(WalkStage::Scanning))
            ) {
                walked.fetch_add(1, Ordering::Relaxed);
            }
            if matches!(p, ScanProgress::Phase(ScanPhase::Hashing)) {
                trip.store(true, Ordering::Relaxed);
            }
        })
        .unwrap();
        assert!(matches!(outcome, ScanOutcome::Cancelled), "run 1 cancelled");
        walks.load(Ordering::Relaxed)
    }

    /// A5/A8 of the accounting matrix, plus initial-vs-reopen parity: a Hashing resume whose
    /// ledger is fully authoritative performs ZERO walks, keeps the committed generation, and
    /// completes with the exact `Ledger` account a reopen then reproduces.
    #[test]
    fn an_authoritative_hashing_resume_performs_zero_walks() {
        let dir = unique_temp_dir("auth_resume");
        std::fs::write(dir.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(dir.join("b.bin"), b"identical duplicate content").unwrap();
        let mut cfg = ScanConfig::new(vec![dir.clone()]);
        cfg.min_size = 0;
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store.begin_scan(&cfg).unwrap();
        assert_eq!(interrupt_at_hashing(&mut store, &cfg, Some(id)), 1);
        assert_eq!(store.scan_status(id).unwrap(), ScanStatus::Hashing);
        assert!(
            store.ledger_authoritative(id).unwrap(),
            "the interrupted walk left a committed, fully authoritative ledger"
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let walks = std::sync::Arc::new(AtomicU64::new(0));
        let notices = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let outcome = run_scan(
            &mut store,
            &cfg,
            Some(id),
            false,
            &cancel,
            counting_progress(
                std::sync::Arc::clone(&walks),
                std::sync::Arc::clone(&notices),
            ),
        )
        .unwrap();
        let results = match outcome {
            ScanOutcome::Completed(results) => results,
            ScanOutcome::Cancelled => panic!("run 2 completes"),
        };
        assert_eq!(
            walks.load(Ordering::Relaxed),
            0,
            "an authoritative Hashing resume must not re-walk"
        );
        assert_eq!(store.scan_status(id).unwrap(), ScanStatus::Complete);
        assert_eq!(
            results.summary.omissions,
            crate::model::scan::OmissionAccounting::Ledger(
                crate::model::omission::OmissionSummary::default()
            ),
            "a clean walk's account is the exact zero"
        );
        // Initial-vs-reopen parity: the persisted ledger folds to the same account.
        assert_eq!(
            store.scan_summary(id).unwrap().omissions,
            results.summary.omissions
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A7: a bounded generation-zero ledger forces the re-walk and earns fresh authority.
    #[test]
    fn a_generation_zero_hashing_resume_re_walks() {
        let dir = unique_temp_dir("genzero_resume");
        std::fs::write(dir.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(dir.join("b.bin"), b"identical duplicate content").unwrap();
        let mut cfg = ScanConfig::new(vec![dir.clone()]);
        cfg.min_size = 0;
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store.begin_scan(&cfg).unwrap();
        assert_eq!(interrupt_at_hashing(&mut store, &cfg, Some(id)), 1);
        store.clear_scan_omissions(id).unwrap();
        assert!(!store.ledger_authoritative(id).unwrap());

        let cancel = Arc::new(AtomicBool::new(false));
        let walks = std::sync::Arc::new(AtomicU64::new(0));
        let notices = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let outcome = run_scan(
            &mut store,
            &cfg,
            Some(id),
            false,
            &cancel,
            counting_progress(
                std::sync::Arc::clone(&walks),
                std::sync::Arc::clone(&notices),
            ),
        )
        .unwrap();
        assert!(matches!(outcome, ScanOutcome::Completed(_)));
        assert_eq!(walks.load(Ordering::Relaxed), 1, "the resume re-walked");
        assert_eq!(store.scan_status(id).unwrap(), ScanStatus::Complete);
        assert!(
            store.ledger_authoritative(id).unwrap(),
            "the re-walk earned a fresh authority"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A6, the blocker-1 window closed: a `Roots`-unavailable walk (a `..`-spelled root) is
    /// interrupted after the status became `Hashing`; the resume re-walks, reconstructs the
    /// session-only `Observed` account — the fifo is back on the books — and completes with the
    /// warning status. Reopen then honestly reports the details as not retained.
    #[test]
    fn an_unavailable_authority_hashing_resume_re_walks_and_recovers_observed() {
        let holder = unique_temp_dir("observed_resume");
        let real = holder.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(real.join("b.bin"), b"identical duplicate content").unwrap();
        make_fifo(&real.join("pipe"));
        // `real/../real`: resolvable on disk (so the disjoint preflight passes) and unkeyable
        // for the ledger (so no authority can exist).
        let spelled = real.join("..").join("real");
        let mut cfg = ScanConfig::new(vec![spelled]);
        cfg.min_size = 0;
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let id = store.begin_scan(&cfg).unwrap();
        assert_eq!(interrupt_at_hashing(&mut store, &cfg, Some(id)), 1);
        assert_eq!(store.scan_status(id).unwrap(), ScanStatus::Hashing);
        assert!(
            !store.ledger_authoritative(id).unwrap(),
            "an unkeyable configuration never has authority"
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let walks = std::sync::Arc::new(AtomicU64::new(0));
        let notices = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let outcome = run_scan(
            &mut store,
            &cfg,
            Some(id),
            false,
            &cancel,
            counting_progress(
                std::sync::Arc::clone(&walks),
                std::sync::Arc::clone(&notices),
            ),
        )
        .unwrap();
        let results = match outcome {
            ScanOutcome::Completed(results) => results,
            ScanOutcome::Cancelled => panic!("run 2 completes"),
        };
        assert_eq!(
            walks.load(Ordering::Relaxed),
            1,
            "without authority the Hashing resume MUST re-walk — this is the lost-Observed window"
        );
        assert_eq!(
            store.scan_status(id).unwrap(),
            ScanStatus::CompleteWithWarnings,
            "the unsupported entry is warning-worthy"
        );
        match &results.summary.omissions {
            crate::model::scan::OmissionAccounting::Observed(totals) => {
                assert_eq!(totals.unsupported_entries().unwrap(), 1, "the fifo is back");
            }
            other => panic!("expected the reconstructed Observed account, got {other:?}"),
        }
        let collected = notices.lock().unwrap().join("\n");
        assert!(
            collected.contains("Scan left gaps: 1 unsupported entries")
                && collected.contains("(details not persisted: no completeness authority)"),
            "the aggregate notice names the observed account and its persistence: {collected}"
        );
        // Reopen: the session-only account is gone, and the summary says so rather than showing
        // an exact zero.
        assert_eq!(
            store.scan_summary(id).unwrap().omissions,
            crate::model::scan::OmissionAccounting::Unavailable
        );

        std::fs::remove_dir_all(&holder).ok();
    }

    /// The publication seam, all five variants with constructed snapshots: `Publishable` commits,
    /// `Roots` degrades carrying its observed account, and every collector failure — including
    /// the no-attribution overflow — is a loud error that publishes nothing.
    #[test]
    fn walk_publication_is_exhaustive_and_loud() {
        use crate::model::omission::{
            AuthorityUnavailable, EventCount, OmissionCounts, OmissionReason, OmissionSummary,
            PathKey,
        };
        let key = |p: &str| PathKey::new(std::path::Path::new(p)).unwrap();

        let fresh = || {
            let mut store = ScanStore::open_in_memory().unwrap();
            let id = store
                .begin_scan(&ScanConfig::new(vec![PathBuf::from("/tank")]))
                .unwrap();
            (store, id)
        };

        // Publishable → committed, and the account is readable back as the exact ledger.
        let (mut store, id) = fresh();
        let mut cells = OmissionCounts::new();
        cells.bump(key("/tank/a"), OmissionReason::MinSize).unwrap();
        let map = std::collections::BTreeMap::from([(key("/tank"), cells)]);
        let publication =
            publish_walk_omissions(&mut store, id, OmissionSnapshot::Publishable(map)).unwrap();
        assert!(matches!(publication, WalkPublication::Committed));
        assert!(store.ledger_authoritative(id).unwrap());

        // Roots → the expected fallback, observed account carried through.
        let (mut store, id) = fresh();
        let mut observed = OmissionSummary::default();
        observed
            .add(OmissionReason::UnsupportedEntry, EventCount::ONE)
            .unwrap();
        let publication = publish_walk_omissions(
            &mut store,
            id,
            OmissionSnapshot::Unavailable(SnapshotUnavailable::Roots {
                why: AuthorityUnavailable::NoRoots,
                observed,
            }),
        )
        .unwrap();
        match publication {
            WalkPublication::NoAuthority { observed } => {
                assert_eq!(observed.unsupported_entries().unwrap(), 1)
            }
            _ => panic!("Roots is the expected no-authority fallback"),
        }
        assert!(!store.ledger_authoritative(id).unwrap());

        // The four failures: loud, named, and nothing published.
        let failures: Vec<(SnapshotUnavailable, &str)> = vec![
            (
                SnapshotUnavailable::CountOverflow {
                    root: key("/tank"),
                    directory: key("/tank/a"),
                    reason: OmissionReason::MinSize,
                },
                "overflowed",
            ),
            (
                SnapshotUnavailable::CountNotStorable {
                    root: key("/tank"),
                    directory: key("/tank/a"),
                    reason: OmissionReason::MinSize,
                },
                "exceeds what the checkpoint can store",
            ),
            (
                SnapshotUnavailable::UnregisteredRoot {
                    root: key("/tank"),
                    directory: key("/tank/a"),
                    reason: OmissionReason::MinSize,
                },
                "wiring defect",
            ),
            (
                SnapshotUnavailable::ObservedOverflow {
                    reason: OmissionReason::NonUtf8,
                },
                "global omission tally overflowed",
            ),
        ];
        for (why, fragment) in failures {
            let (mut store, id) = fresh();
            // Not `expect_err`: that needs `Debug` on the success type, and `WalkPublication`
            // deliberately has none.
            let err =
                match publish_walk_omissions(&mut store, id, OmissionSnapshot::Unavailable(why)) {
                    Err(err) => err.to_string(),
                    Ok(_) => panic!("a collector failure must fail the scan"),
                };
            assert!(err.contains(fragment), "{err}");
            assert!(
                !store.ledger_authoritative(id).unwrap(),
                "nothing may be published on the failure path"
            );
        }
    }

    /// G6's re-walk crash truth: `clear_files` has already destroyed the previous ledger in its
    /// own transaction, so a commit failure later in the re-walk leaves `Unknown` — the actual
    /// state, not the older authority P0 wrongly promised.
    #[test]
    fn a_failed_commit_after_clear_files_leaves_unknown_not_the_old_ledger() {
        let dir = unique_temp_dir("rewalk_crash");
        std::fs::write(dir.join("keep.bin"), vec![b'k'; 64]).unwrap();
        std::fs::write(dir.join("tiny.bin"), b"x").unwrap();
        let mut cfg = ScanConfig::new(vec![dir.clone()]);
        cfg.min_size = 16; // tiny.bin is filtered → exactly one ledger row to fail on
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let outcome = run_scan(&mut store, &cfg, None, false, &cancel, |_| {}).unwrap();
        let id = match outcome {
            ScanOutcome::Completed(results) => results.scan_id,
            ScanOutcome::Cancelled => panic!("run 1 completes"),
        };
        assert!(store.ledger_authoritative(id).unwrap(), "run 1 committed");

        // Force the re-walk path and fail the very first ledger insert inside the commit.
        store.set_status(id, ScanStatus::Walking).unwrap();
        let fault = crate::state::store::LedgerInsertFault::after(0);
        let err = match run_scan(&mut store, &cfg, Some(id), false, &cancel, |_| {}) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("the injected commit failure must fail the scan"),
        };
        assert!(err.contains("injected ledger insert fault"), "{err}");
        assert!(!fault.pending(), "the fault fired inside the commit");

        assert_eq!(
            store.scan_status(id).unwrap(),
            ScanStatus::Walking,
            "no completion status was written"
        );
        assert!(
            !store.ledger_authoritative(id).unwrap(),
            "the previous authority is honestly gone — clear_files destroyed it with the manifest"
        );
        assert_eq!(
            store.scan_omission_accounting(id).unwrap(),
            crate::model::scan::OmissionAccounting::Unavailable,
            "Unknown, not the older ledger"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// R4-C1's production route: a resume that re-walks clears the manifest first, and a
    /// cancellation right after leaves the scan with no manifest at all. Nothing the previous run
    /// published may still be readable then — a summary whose members cannot be found, or a
    /// prepared marker that makes an opening scan return those summaries as current, is a result
    /// that outlived its evidence.
    #[test]
    fn a_cancelled_rewalk_leaves_no_result_behind() {
        let dir = unique_temp_dir("rewalk_cancel");
        std::fs::write(dir.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(dir.join("b.bin"), b"identical duplicate content").unwrap();
        let mut cfg = ScanConfig::new(vec![dir.clone()]);
        cfg.min_size = 0;
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let id = match run_scan(&mut store, &cfg, None, false, &cancel, |_| {}).unwrap() {
            ScanOutcome::Completed(results) => results.scan_id,
            ScanOutcome::Cancelled => panic!("the first run completes"),
        };
        assert_eq!(
            store.browse_summaries(id).unwrap().len(),
            1,
            "the first run published one group"
        );
        assert!(store.results_materialized(id).unwrap());
        assert!(store.scan_reclaim(id).unwrap().guaranteed_bytes() > 0);
        assert!(
            !store.attributed_dir_groups(id).unwrap().is_empty()
                || store.manifest_count(id).unwrap() > 0,
            "the first run left something to invalidate"
        );

        // Force the re-walk route and cancel before it can publish anything.
        store.set_status(id, ScanStatus::Walking).unwrap();
        cancel.store(true, Ordering::Relaxed);
        let outcome = run_scan(&mut store, &cfg, Some(id), false, &cancel, |_| {}).unwrap();
        assert!(
            matches!(outcome, ScanOutcome::Cancelled),
            "the re-walk must cancel before publication"
        );

        assert_eq!(store.manifest_count(id).unwrap(), 0, "the manifest is gone");
        assert!(
            store.browse_summaries(id).unwrap().is_empty(),
            "no file group may outlive the manifest its members came from"
        );
        assert!(
            store.attributed_dir_groups(id).unwrap().is_empty(),
            "no directory group either"
        );
        assert!(
            !store.results_materialized(id).unwrap(),
            "the prepared marker must not survive: opening returns through it"
        );
        let reclaim = store.scan_reclaim(id).unwrap();
        assert_eq!(reclaim.guaranteed_bytes(), 0);
        assert_eq!(
            reclaim.state(),
            crate::model::reclaim::ReclaimState::Unknown,
            "an exact total over a deleted manifest is a claim nothing supports"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// G12: `unsupported_entry` escalates to `CompleteWithWarnings`; an intentional min-size
    /// filter never does. Both leave their exact `Ledger` account and one aggregate notice; the
    /// old standalone non-UTF8 notice is gone from the stream.
    #[test]
    fn warning_events_escalate_and_intentional_filters_do_not() {
        // A fifo beside two duplicates: nothing failed, nothing was filtered, and the scan must
        // still warn — the directory result is incomplete.
        let dir = unique_temp_dir("warn_fifo");
        std::fs::write(dir.join("a.bin"), b"identical duplicate content").unwrap();
        std::fs::write(dir.join("b.bin"), b"identical duplicate content").unwrap();
        make_fifo(&dir.join("pipe"));
        let mut cfg = ScanConfig::new(vec![dir.clone()]);
        cfg.min_size = 0;
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let walks = std::sync::Arc::new(AtomicU64::new(0));
        let notices = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let outcome = run_scan(
            &mut store,
            &cfg,
            None,
            false,
            &cancel,
            counting_progress(
                std::sync::Arc::clone(&walks),
                std::sync::Arc::clone(&notices),
            ),
        )
        .unwrap();
        let results = match outcome {
            ScanOutcome::Completed(results) => results,
            ScanOutcome::Cancelled => panic!("completes"),
        };
        assert_eq!(results.summary.hash_failures, 0);
        assert_eq!(
            store.scan_status(results.scan_id).unwrap(),
            ScanStatus::CompleteWithWarnings,
            "an unsupported entry is warning-worthy"
        );
        match &results.summary.omissions {
            crate::model::scan::OmissionAccounting::Ledger(totals) => {
                assert_eq!(totals.unsupported_entries().unwrap(), 1)
            }
            other => panic!("expected the exact ledger account, got {other:?}"),
        }
        let collected = notices.lock().unwrap().join("\n");
        assert!(
            collected.contains("Scan left gaps: 1 unsupported entries"),
            "{collected}"
        );
        std::fs::remove_dir_all(&dir).ok();

        // The same shape with an intentional filter instead: incomplete twins, no warning status.
        let dir = unique_temp_dir("warn_filter");
        std::fs::write(dir.join("a.bin"), vec![b'a'; 64]).unwrap();
        std::fs::write(dir.join("b.bin"), vec![b'a'; 64]).unwrap();
        std::fs::write(dir.join("tiny.bin"), b"x").unwrap();
        let mut cfg = ScanConfig::new(vec![dir.clone()]);
        cfg.min_size = 16;
        cfg.exclude_globs = Vec::new();

        let mut store = ScanStore::open_in_memory().unwrap();
        let notices = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let walks = std::sync::Arc::new(AtomicU64::new(0));
        let outcome = run_scan(
            &mut store,
            &cfg,
            None,
            false,
            &cancel,
            counting_progress(
                std::sync::Arc::clone(&walks),
                std::sync::Arc::clone(&notices),
            ),
        )
        .unwrap();
        let results = match outcome {
            ScanOutcome::Completed(results) => results,
            ScanOutcome::Cancelled => panic!("completes"),
        };
        assert_eq!(
            store.scan_status(results.scan_id).unwrap(),
            ScanStatus::Complete,
            "an operator-chosen narrowing is not a warning about the scan"
        );
        match &results.summary.omissions {
            crate::model::scan::OmissionAccounting::Ledger(totals) => {
                assert_eq!(
                    totals.known_omitted_files().unwrap(),
                    1,
                    "the filtered file"
                )
            }
            other => panic!("expected the exact ledger account, got {other:?}"),
        }
        let collected = notices.lock().unwrap().join("\n");
        assert!(
            collected.contains("Scan left gaps: 1 files omitted"),
            "the filter is still accounted and announced: {collected}"
        );
        assert!(
            !collected.contains("non-UTF8 names"),
            "the old standalone notice is gone: {collected}"
        );

        std::fs::remove_dir_all(&dir).ok();
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

#[cfg(test)]
mod verify_boundary_tests {
    use super::safe_open::open_regular_nofollow;
    use super::*;

    /// A unique temporary directory (as in hash_failures_tests) — without the tempfile crate.
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

    /// The real manifest identity of an existing regular file.
    fn manifest_row(path: &std::path::Path) -> ManifestRow {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).unwrap();
        ManifestRow {
            path: path.to_path_buf(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            device: meta.dev(),
            inode: meta.ino(),
            nlink: meta.nlink(),
        }
    }

    /// A verification read failure crosses the publication boundary as an error and publishes
    /// NOTHING — no `file_group` row, no results-materialized marker — while the collected
    /// manifest/hash evidence survives untouched. The store and the files are real; the fault
    /// is a symlink replacing a member after hashing, which `open_regular_nofollow` provably
    /// rejects (chmod would be inert under the root of the Docker gate).
    #[test]
    fn a_verify_read_failure_publishes_nothing_and_keeps_the_evidence() {
        let dir = unique_temp_dir("verify_boundary");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let payload = b"identical bytes for the verify boundary";
        std::fs::write(&a, payload).unwrap();
        std::fs::write(&b, payload).unwrap();

        let mut store = ScanStore::open_in_memory().unwrap();
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![dir.clone()]))
            .unwrap();
        store
            .record_files(scan_id, &[manifest_row(&a), manifest_row(&b)])
            .unwrap();
        let digest = [7u8; 32];
        store
            .record_hashes(scan_id, &[(a.clone(), digest), (b.clone(), digest)])
            .unwrap();
        // The candidate exists BEFORE the fault: one group over two allocations.
        assert_eq!(
            store.duplicate_groups(scan_id).unwrap().len(),
            1,
            "the fixture must produce a real candidate group"
        );

        // The replacement fault is real, not inert: the member is now a symlink and the safe
        // open rejects it.
        std::fs::remove_file(&b).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        assert!(open_regular_nofollow(&b).is_err());

        assert!(
            verify_and_publish(&mut store, scan_id).is_err(),
            "the failed byte verification must reach the caller"
        );

        assert!(
            store.browse_summaries(scan_id).unwrap().is_empty(),
            "no verified file_group result may be published"
        );
        assert!(
            !store.results_materialized(scan_id).unwrap(),
            "the results-materialized marker must stay unset"
        );
        let manifest = store.file_hash_status(scan_id).unwrap();
        assert_eq!(manifest.len(), 2, "the manifest evidence is intact");
        assert!(
            manifest.iter().all(|(_, _, hash)| hash.is_some()),
            "the collected hash evidence is not rewritten by the failure"
        );

        // The intact evidence is directly usable: repairing the member and running the same
        // boundary again publishes from this store, without a rescan.
        std::fs::remove_file(&b).unwrap();
        std::fs::write(&b, payload).unwrap();
        assert_eq!(
            verify_and_publish(&mut store, scan_id).unwrap(),
            1,
            "the repaired member verifies and one group is published"
        );
        assert!(store.results_materialized(scan_id).unwrap());
        assert_eq!(store.browse_summaries(scan_id).unwrap().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
