// SPDX-License-Identifier: Apache-2.0
//! Lightweight resource monitor for the process itself — for the
//! RAM/CPU indicator in the corner of the TUI. The project is Linux-only, we read `/proc/self`
//! directly (like `host_profile`), without third-party crates.
//!
//! RSS — resident pages from `/proc/self/statm` × `_SC_PAGESIZE`. CPU% — the delta of
//! `utime+stime` (ticks) from `/proc/self/stat` over real time, divided by
//! `_SC_CLK_TCK`. We compute it not on every frame but over a window (`interval`): the read is cheap,
//! but the percentage jumps around over too short a window.

use std::time::{Duration, Instant};

/// Snapshot of process resources for the badge.
#[derive(Debug, Clone, Copy)]
pub struct ResourceSample {
    pub rss_bytes: u64,
    pub cpu_percent: f32,
}

/// Reader with memory of the previous sample (needed for the CPU delta).
pub struct ResourceMonitor {
    page_size: u64,
    clk_tck: u64,
    last_cpu_ticks: u64,
    last_at: Instant,
    interval: Duration,
    latest: ResourceSample,
}

impl ResourceMonitor {
    pub fn new() -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        ResourceMonitor {
            page_size,
            clk_tck,
            last_cpu_ticks: read_cpu_ticks(),
            last_at: Instant::now(),
            interval: Duration::from_millis(700),
            latest: ResourceSample {
                rss_bytes: read_rss_bytes(page_size),
                cpu_percent: 0.0,
            },
        }
    }

    /// Recomputes no more often than `interval`; between recomputes returns the cache.
    pub fn sample(&mut self) -> ResourceSample {
        let now = Instant::now();
        let dt = now.duration_since(self.last_at);
        if dt < self.interval {
            return self.latest;
        }
        let ticks = read_cpu_ticks();
        let secs = dt.as_secs_f64();
        let cpu_percent = if secs > 0.0 {
            (ticks.saturating_sub(self.last_cpu_ticks) as f64 / self.clk_tck as f64 / secs * 100.0)
                as f32
        } else {
            self.latest.cpu_percent
        };
        self.last_cpu_ticks = ticks;
        self.last_at = now;
        self.latest = ResourceSample {
            rss_bytes: read_rss_bytes(self.page_size),
            cpu_percent,
        };
        self.latest
    }

    pub fn latest(&self) -> ResourceSample {
        self.latest
    }
}

impl Default for ResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Current process RSS (one-shot, without `ResourceMonitor`) — for spot probes
/// (RSS instrumentation of the grouping phase).
pub fn current_rss_bytes() -> u64 {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    read_rss_bytes(page_size)
}

fn read_rss_bytes(page_size: u64) -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| parse_rss_pages(&s))
        .map(|pages| pages.saturating_mul(page_size))
        .unwrap_or(0)
}

fn read_cpu_ticks() -> u64 {
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| parse_cpu_ticks(&s))
        .unwrap_or(0)
}

/// `statm`: «size resident shared …» in pages — we take the resident field (2nd).
fn parse_rss_pages(statm: &str) -> Option<u64> {
    statm.split_whitespace().nth(1)?.parse().ok()
}

/// `stat`: field 2 (comm) is in parentheses and may contain spaces/parens, so
/// we parse the tail after the LAST `)`. Then tokens[0] = state (field 3), and
/// utime (field 14) and stime (field 15) are tokens[11] and tokens[12].
fn parse_cpu_ticks(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    let tokens: Vec<&str> = after.split_whitespace().collect();
    let utime: u64 = tokens.get(11)?.parse().ok()?;
    let stime: u64 = tokens.get(12)?.parse().ok()?;
    Some(utime.saturating_add(stime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_pages_reads_resident_field() {
        assert_eq!(parse_rss_pages("1234 567 89 1 0 100 0"), Some(567));
        assert_eq!(parse_rss_pages(""), None);
    }

    #[test]
    fn cpu_ticks_sum_survives_comm_with_spaces_and_parens() {
        // pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt
        //   cmajflt utime stime …  → after ')' utime=tokens[11], stime=tokens[12].
        let stat = "42 (weird (name) ) S 1 42 42 0 -1 0 0 0 0 0 100 23 0 0 20";
        assert_eq!(parse_cpu_ticks(stat), Some(123));
    }

    #[test]
    fn cpu_ticks_handles_garbage() {
        assert_eq!(parse_cpu_ticks("nonsense without paren"), None);
    }

    #[test]
    fn current_rss_is_positive() {
        // Linux build environment (Docker) → /proc/self/statm is available.
        assert!(current_rss_bytes() > 0);
    }
}
