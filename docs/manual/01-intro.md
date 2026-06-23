# 01. Introduction

## What DedupCommando does

It finds **byte-for-byte identical** files in the directories you point it at and helps
you reclaim space safely — delete the extras, replace them with a hardlink, or make a
reflink (ZFS block cloning). By default it opens the multi-panel "commander" interface
(a two-to-four-pane, classic file-manager-style view); a classic stepwise wizard is also
available (`--classic`).

The process has three phases:

1. **Walk** — traverse the tree and store the file list in SQLite (`dedcom.db`).
2. **Hash** — BLAKE3 of every file, reading in `(device, inode)` order (inode-order on
   HDD gives −21% cold-scan time on 2×HDD). Hashes are cached by
   `(path, size, mtime)` — re-scanning the same directory is almost instant.
3. **Group** — merge files with the same hash into groups; optionally, build directory
   signatures for "twin folders".

The result is groups of duplicate files and (if enabled) groups of directories with
identical contents, sorted "by payoff" — how much space deduplicating each group would
free.

Every destructive action (`delete`, `hardlink`, `reflink`) runs under a ZFS snapshot of
the dataset (`@dedcom-<timestamp>`), with the target and keeper re-validated (re-hashed)
beforehand. See [Safety](03-safety.md) for details.

## What DedupCommando does NOT do

- **It does not compress files.** Compression is ZFS's job (`zfs set compression=zstd`).
- **It does not do block-level deduplication.** That is `zfs set dedup=on` (see the
  OpenZFS documentation; it is usually unnecessary — it eats RAM and CPU). DedupCommando
  works at the level of filesystem operations (`unlink`, `link`, `clone`), not pool
  blocks.
- **It does not look for "similar" files.** Only byte-for-byte identical ones (the same
  BLAKE3). No fuzzy matching or perceptual hashing.
- **It does not provide snapshot safety on non-ZFS filesystems.** On ext4/xfs/btrfs the
  walk and hash run fine, but the snapshot insurance before a destructive action is
  unavailable. Applying actions in that mode is NOT recommended.
- **It is not meant for several operators at once.** A single-instance lock keeps one
  active session; a second one can only be opened as an observer (`--read-only`) or with
  an explicit risk (`--force`) — which is always a bad idea.
- **It does not index "everything" automatically.** There is no background daemon, no
  watch mode, no inotify mode. You start a scan by hand or from the `--scan` headless
  mode (for example, from cron — see [Headless mode](11-headless.md)).
- **It does not run on non-Linux systems.** The binary is Linux-only
  (`x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu`). Windows and macOS are for
  development only; cross-compilation is not supported.

## Requirements

| Requirement                 | Level                  | Note                                                                                                     |
|-----------------------------|------------------------|----------------------------------------------------------------------------------------------------------|
| Linux                       | Required               | Binary is Linux-only (`x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu`).                          |
| Linux kernel ≥ 3.15         | Required               | Needed for `renameat2(RENAME_NOREPLACE)` for atomic publishing. On Proxmox it is certainly present.      |
| ZFS                         | Strongly recommended   | Without ZFS, walk/hash work, but snapshot insurance is disabled. On Proxmox it is available out of the box. |
| `zfs` in `PATH`             | Strongly recommended   | Needed for snapshots and dataset detection. See [Troubleshooting](13-troubleshooting.md) if it is not found. |
| Reflink (block_cloning)     | Optional               | `zpool feature@block_cloning=active`. Without it, `delete` and `hardlink` are available, but not `reflink`. |
| RAM                         | Depends on volume      | Walk/hash — tens of MB. Phase 3/3 — ~2.5 KiB/file; the `--merkle-dirs` alternative. Details in [Scanning](07-scanning.md). |
| Terminal                    | UTF-8, 256 colors      | Unicode box-drawing (`┌┐└┘├┤─│`); ratatui works in most emulators. The Proxmox web shell has quirks ([Troubleshooting](13-troubleshooting.md)). |

## Safety guarantees (the minimum to keep in mind)

The full chapter is [Safety](03-safety.md). Reading it before your first "real" apply is
MANDATORY. The minimum:

- A **ZFS snapshot** of the dataset is created once per batch of actions before applying
  begins. Name: `<dataset>@dedcom-<timestamp>`. Manual rollback:
  `zfs rollback tank@dedcom-<ts>`. Delete it once you are sure it is no longer needed:
  `zfs destroy tank@dedcom-<ts>`.
- A **quarantine** (`.dedcom-quarantine/<timestamp>/` at the dataset root) — every
  deleted file goes here instead of being `unlink`ed. They are restored by hand like
  ordinary files, from the subdirectory stamped with the apply time.
- **Revalidate** before each destructive action: the target and the keeper are re-hashed;
  if anything changed since the scan, the action is aborted. The default mode is Hybrid
  (faster, safe for typical use); the strict mode is `--strict-verify`
  ([Actions](08-actions.md)).
- **Single-instance** — only one writing `dedcom` per state directory
  (`~/.local/state/dedcom/`). A second window can only be `--read-only`.
- **Cross-device — refused.** If a move would cross a dataset boundary (i.e. a device),
  we raise an error with an `rsync` hint (rather than a silent copy + delete).

## Who wrote it and for whom

DedupCommando is an open-source tool released under Apache-2.0. It targets the Linux+ZFS
operator — a sysadmin on Proxmox VE or any other Linux system backed by ZFS — who needs
to reclaim years of accumulated duplicate media and backups without turning on pool-level
block deduplication.

→ Next: [Installation](02-install.md).
