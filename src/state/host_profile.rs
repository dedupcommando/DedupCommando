// SPDX-License-Identifier: Apache-2.0
//! Host profile, taken once at startup: CPU, RAM, disk classes,
//! ZFS pools, inotify limit. Used for auto-selecting the Resource
//! Governor profile, showing a summary, and warning about the inotify
//! limit ahead of a future watch mode.
//!
//! Collection is via native reads of `/proc` and `/sys` (no `fork` and no dependency on
//! `lscpu`/`free`/`lsblk`); only ZFS pools are read through `zpool` (no native
//! way). On a non-Linux/non-ZFS system the fields simply stay empty/zero —
//! detection does not fail.

use std::process::Command;
use std::time::Instant;

/// A single block disk and its media class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskInfo {
    pub name: String,
    /// `true` — rotational (HDD); `false` — SSD/NVMe.
    pub rotational: bool,
}

/// A single ZFS pool and its layout.
#[derive(Debug, Clone, PartialEq)]
pub struct PoolInfo {
    pub name: String,
    /// raidz1/raidz2/raidz3/mirror/stripe/unknown.
    pub layout: String,
    /// Measured read speed, MB/s. Filled in not here, but during
    /// calibration of the hashing phase; here always `None`.
    pub approx_read_mbps: Option<f64>,
}

/// Snapshot of the host hardware and environment.
#[derive(Debug, Clone, Default)]
pub struct HostProfile {
    pub cpu_model: String,
    pub logical_cpus: usize,
    pub cpu_mhz: Option<u32>,
    pub ram_total_kb: u64,
    pub ram_free_kb: u64,
    pub inotify_max_watches: u64,
    pub disks: Vec<DiskInfo>,
    pub pools: Vec<PoolInfo>,
}

impl HostProfile {
    /// Takes the host profile. Never fails: unavailable sources yield
    /// default values. There are no heavy blocking calls (pool speed
    /// is not measured — that is done by the hashing phase), so it is suitable for
    /// the boot thread during the splash screen.
    pub fn detect() -> Self {
        let start = Instant::now();

        let logical_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let (cpu_model, cpu_mhz) = parse_cpuinfo(&cpuinfo);

        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let (ram_total_kb, ram_free_kb) = parse_meminfo(&meminfo);

        let inotify_max_watches = std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        let disks = detect_disks();
        let pools = detect_pools();

        let profile = Self {
            cpu_model,
            logical_cpus,
            cpu_mhz,
            ram_total_kb,
            ram_free_kb,
            inotify_max_watches,
            disks,
            pools,
        };

        tracing::info!(
            "host profile: {} ×{} · RAM {} MB · disks {} · pools {} · inotify {} · in {} ms",
            profile.cpu_model,
            profile.logical_cpus,
            profile.ram_total_kb / 1024,
            profile.disks.len(),
            profile.pools.len(),
            profile.inotify_max_watches,
            start.elapsed().as_millis(),
        );
        profile
    }

    /// All detected disks are rotational (HDD host). If there are no disks —
    /// we treat it as NOT HDD-only (do not impose Balanced blindly).
    pub fn all_rotational(&self) -> bool {
        !self.disks.is_empty() && self.disks.iter().all(|d| d.rotational)
    }

    /// There is at least one SSD/NVMe — the Turbo profile is justified by default.
    pub fn has_fast_storage(&self) -> bool {
        self.disks.iter().any(|d| !d.rotational)
    }

    /// The inotify limit is small for a recursive watch of a large tree.
    pub fn low_inotify_for_watch(&self) -> bool {
        self.inotify_max_watches < 100_000
    }

    /// One-line summary for the status line/log.
    pub fn summary_line(&self) -> String {
        let base = if self.cpu_model.is_empty() {
            format!("CPU ×{}", self.logical_cpus)
        } else {
            format!("{} ×{}", self.cpu_model, self.logical_cpus)
        };
        let cpu = match self.cpu_mhz {
            Some(mhz) => format!("{base} @ {mhz} MHz"),
            None => base,
        };
        let ram = format!(
            "{} GiB (free {} GiB)",
            self.ram_total_kb / 1024 / 1024,
            self.ram_free_kb / 1024 / 1024,
        );
        let hdd = self.disks.iter().filter(|d| d.rotational).count();
        let fast = self.disks.len() - hdd;
        let disks = format!("disks: {hdd} HDD, {fast} SSD/NVMe");
        let pools = if self.pools.is_empty() {
            "pools: —".to_string()
        } else {
            let list: Vec<String> = self
                .pools
                .iter()
                .map(|p| format!("{}({})", p.name, p.layout))
                .collect();
            format!("pools: {}", list.join(", "))
        };
        format!(
            "{cpu} · {ram} · {disks} · {pools} · inotify: {}",
            self.inotify_max_watches
        )
    }
}

/// Extracts «model name» and «cpu MHz» from `/proc/cpuinfo` (takes the first core).
fn parse_cpuinfo(text: &str) -> (String, Option<u32>) {
    let mut model = String::new();
    let mut mhz: Option<u32> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if model.is_empty() && key == "model name" {
            model = value.to_string();
        }
        if mhz.is_none() && key == "cpu MHz" {
            mhz = value.split('.').next().and_then(|n| n.parse::<u32>().ok());
        }
        if !model.is_empty() && mhz.is_some() {
            break;
        }
    }
    (model, mhz)
}

/// Extracts MemTotal and MemAvailable (fallback MemFree) from `/proc/meminfo`, in KiB.
fn parse_meminfo(text: &str) -> (u64, u64) {
    let mut total = 0u64;
    let mut available = 0u64;
    let mut free = 0u64;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let kb = value
            .trim()
            .trim_end_matches(" kB")
            .trim()
            .parse::<u64>()
            .unwrap_or(0);
        match key.trim() {
            "MemTotal" => total = kb,
            "MemAvailable" => available = kb,
            "MemFree" => free = kb,
            _ => {}
        }
    }
    let usable = if available > 0 { available } else { free };
    (total, usable)
}

/// Available RAM (`MemAvailable`, fallback `MemFree`) in BYTES — a lightweight read of
/// `/proc/meminfo` without the full host profile (memory warning for phase 3/3).
pub fn available_ram_bytes() -> u64 {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let (_total, usable_kb) = parse_meminfo(&text);
    usable_kb.saturating_mul(1024)
}

/// Enumerates real top-level block devices in `/sys/block`,
/// filtering out virtual ones (loop, ram, zram, dm-*, sr). Class — from `rotational`.
fn detect_disks() -> Vec<DiskInfo> {
    let mut disks = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return disks;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_virtual_block(&name) {
            continue;
        }
        let rot_path = format!("/sys/block/{name}/queue/rotational");
        let rotational = match std::fs::read_to_string(&rot_path) {
            Ok(s) => s.trim() == "1",
            Err(_) => continue,
        };
        disks.push(DiskInfo { name, rotational });
    }
    disks.sort_by(|a, b| a.name.cmp(&b.name));
    disks
}

/// A virtual block device — not of interest for media classification.
fn is_virtual_block(name: &str) -> bool {
    name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("zram")
        || name.starts_with("dm-")
        || name.starts_with("sr")
        || name.starts_with("md")
}

/// List of ZFS pools with layout. `zpool` via `Command`; if the binary is
/// missing/on error — an empty list (non-ZFS host).
fn detect_pools() -> Vec<PoolInfo> {
    let names = match zpool_output(&["list", "-H", "-o", "name"]) {
        Some(text) => text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>(),
        None => return Vec::new(),
    };
    let layouts = zpool_output(&["status", "-L", "-P"])
        .map(|status| parse_pool_layouts(&status))
        .unwrap_or_default();

    names
        .into_iter()
        .map(|name| {
            let layout = layouts
                .iter()
                .find(|(pool, _)| pool == &name)
                .map(|(_, layout)| layout.clone())
                .unwrap_or_else(|| "unknown".to_string());
            PoolInfo {
                name,
                layout,
                approx_read_mbps: None,
            }
        })
        .collect()
}

/// Parses `zpool status` into `(pool_name, layout)` pairs.
fn parse_pool_layouts(status: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut current: Option<String> = None;
    let mut block = String::new();

    let flush = |out: &mut Vec<(String, String)>, name: &Option<String>, block: &str| {
        if let Some(name) = name {
            out.push((name.clone(), classify_layout(block)));
        }
    };

    for line in status.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("pool:") {
            flush(&mut out, &current, &block);
            current = Some(rest.trim().to_string());
            block.clear();
        } else {
            block.push_str(line);
            block.push('\n');
        }
    }
    flush(&mut out, &current, &block);
    out
}

/// Pool layout by the first vdev keyword (as in `zfs::pool`).
fn classify_layout(block: &str) -> String {
    for line in block.lines() {
        let token = line.split_whitespace().next().unwrap_or("");
        if token.starts_with("raidz3") {
            return "raidz3".to_string();
        }
        if token.starts_with("raidz2") {
            return "raidz2".to_string();
        }
        if token.starts_with("raidz") {
            return "raidz1".to_string();
        }
        if token.starts_with("mirror") {
            return "mirror".to_string();
        }
    }
    "stripe".to_string()
}

/// Runs `zpool <args>`, returns stdout or `None` on any error.
fn zpool_output(args: &[&str]) -> Option<String> {
    let output = Command::new(crate::zfs::zpool_bin())
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuinfo_extracts_model_and_mhz() {
        let text = "\
processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu MHz\t\t: 2399.998
processor\t: 1
model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
";
        let (model, mhz) = parse_cpuinfo(text);
        assert_eq!(model, "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz");
        assert_eq!(mhz, Some(2399));
    }

    #[test]
    fn cpuinfo_empty_is_safe() {
        let (model, mhz) = parse_cpuinfo("");
        assert!(model.is_empty());
        assert_eq!(mhz, None);
    }

    #[test]
    fn meminfo_prefers_available() {
        let text = "\
MemTotal:       65802340 kB
MemFree:         1234567 kB
MemAvailable:   60000000 kB
Buffers:          100000 kB
";
        let (total, usable) = parse_meminfo(text);
        assert_eq!(total, 65_802_340);
        assert_eq!(usable, 60_000_000);
    }

    #[test]
    fn meminfo_falls_back_to_free() {
        let text = "MemTotal: 1000 kB\nMemFree: 400 kB\n";
        let (total, usable) = parse_meminfo(text);
        assert_eq!(total, 1000);
        assert_eq!(usable, 400);
    }

    #[test]
    fn pool_layouts_parsed() {
        let status = "\
  pool: tank
 state: ONLINE
config:
\tNAME        STATE
\ttank        ONLINE
\t  raidz2-0  ONLINE
\t    /dev/sda  ONLINE
\t    /dev/sdb  ONLINE

  pool: rpool
 state: ONLINE
config:
\tNAME        STATE
\trpool       ONLINE
\t  mirror-0  ONLINE
\t    /dev/nvme0n1  ONLINE
";
        let layouts = parse_pool_layouts(status);
        assert_eq!(
            layouts,
            vec![
                ("tank".to_string(), "raidz2".to_string()),
                ("rpool".to_string(), "mirror".to_string()),
            ]
        );
    }

    #[test]
    fn virtual_block_devices_skipped() {
        assert!(is_virtual_block("loop0"));
        assert!(is_virtual_block("zram0"));
        assert!(is_virtual_block("dm-3"));
        assert!(!is_virtual_block("sda"));
        assert!(!is_virtual_block("nvme0n1"));
    }

    #[test]
    fn profile_recommendation_helpers() {
        let hdd = HostProfile {
            disks: vec![
                DiskInfo {
                    name: "sda".into(),
                    rotational: true,
                },
                DiskInfo {
                    name: "sdb".into(),
                    rotational: true,
                },
            ],
            ..Default::default()
        };
        assert!(hdd.all_rotational());
        assert!(!hdd.has_fast_storage());

        let mixed = HostProfile {
            disks: vec![
                DiskInfo {
                    name: "sda".into(),
                    rotational: true,
                },
                DiskInfo {
                    name: "nvme0n1".into(),
                    rotational: false,
                },
            ],
            ..Default::default()
        };
        assert!(!mixed.all_rotational());
        assert!(mixed.has_fast_storage());
    }
}
