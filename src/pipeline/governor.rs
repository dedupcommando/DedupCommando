// SPDX-License-Identifier: Apache-2.0
//! Resource Governor: the hashing-intensity profile
//! controls the number of reader threads and the CPU/IO priority of the worker threads.

use crate::model::scan::HashProfile;

/// Number of reader threads for the hashing pool, by profile and core count.
pub fn jobs_for(profile: HashProfile, nproc: usize) -> usize {
    let nproc = nproc.max(1);
    match profile {
        HashProfile::Turbo => nproc,
        HashProfile::Balanced => 2.min(nproc),
        HashProfile::Idle => 1,
    }
}

/// Applies CPU/IO priority to the CURRENT thread by profile. For `Idle` —
/// nice 19 (CPU) + ionice idle class (IO), so the dedup yields to VMs and
/// backups. Called from the pool's `start_handler` — once per worker
/// thread. Best-effort: errors are ignored.
#[cfg(target_os = "linux")]
pub fn apply_priority(profile: HashProfile) {
    if !matches!(profile, HashProfile::Idle) {
        return;
    }
    // CPU: lowest scheduler priority. On Linux setpriority with
    // PRIO_PROCESS and who=0 acts on the calling thread (task).
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }
    // IO: idle class — the thread gets the disk only when it is idle.
    const IOPRIO_WHO_PROCESS: libc::c_int = 1;
    const IOPRIO_CLASS_IDLE: libc::c_long = 3;
    const IOPRIO_CLASS_SHIFT: libc::c_long = 13;
    let ioprio = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
    unsafe {
        // who=0 → calling thread.
        let _ = libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, ioprio);
    }
}

/// Stub for non-Linux (the binary is Linux-only, but clippy/tests may run elsewhere).
#[cfg(not(target_os = "linux"))]
pub fn apply_priority(_profile: HashProfile) {}

/// Instantaneous rate and time estimate with EMA smoothing. Returns
/// `(rate_bytes_per_sec, eta_secs, new_ema)`. `prev_ema <= 0` — the first sample.
pub fn rate_eta(
    elapsed_secs: f64,
    session_bytes: u64,
    remaining_bytes: u64,
    prev_ema: f64,
) -> (u64, u64, f64) {
    // Below 0.5 s the sample is noisy — we don't estimate.
    let inst = if elapsed_secs > 0.5 {
        session_bytes as f64 / elapsed_secs
    } else {
        0.0
    };
    let ema = if prev_ema <= 0.0 {
        inst
    } else {
        0.7 * prev_ema + 0.3 * inst
    };
    let rate = ema as u64;
    let eta = if ema > 1.0 {
        (remaining_bytes as f64 / ema) as u64
    } else {
        0
    };
    (rate, eta, ema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_scale_with_profile() {
        assert_eq!(jobs_for(HashProfile::Turbo, 16), 16);
        assert_eq!(jobs_for(HashProfile::Balanced, 16), 2);
        assert_eq!(jobs_for(HashProfile::Idle, 16), 1);
        // We don't exceed the core count.
        assert_eq!(jobs_for(HashProfile::Turbo, 1), 1);
        assert_eq!(jobs_for(HashProfile::Balanced, 1), 1);
        // Guard against nproc=0.
        assert_eq!(jobs_for(HashProfile::Turbo, 0), 1);
    }

    #[test]
    fn rate_eta_first_sample_seeds_ema() {
        // 100 MB in 1 s → 100 MB/s; 200 MB remaining → ~2 s.
        let (rate, eta, ema) = rate_eta(1.0, 100_000_000, 200_000_000, 0.0);
        assert_eq!(rate, 100_000_000);
        assert_eq!(eta, 2);
        assert!((ema - 100_000_000.0).abs() < 1.0);
    }

    #[test]
    fn rate_eta_too_early_is_zero() {
        let (rate, eta, ema) = rate_eta(0.2, 10_000_000, 100_000_000, 0.0);
        assert_eq!(rate, 0);
        assert_eq!(eta, 0);
        assert_eq!(ema, 0.0);
    }

    #[test]
    fn rate_eta_smooths_with_prev() {
        // prev 100 MB/s, instantaneous 200 MB/s → 0.7*100+0.3*200 = 130 MB/s.
        let (rate, _eta, ema) = rate_eta(1.0, 200_000_000, 0, 100_000_000.0);
        assert_eq!(rate, 130_000_000);
        assert!((ema - 130_000_000.0).abs() < 1.0);
    }
}
