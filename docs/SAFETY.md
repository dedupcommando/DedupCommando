# Safety, Recovery, and Limitations

DedupCommando removes and relinks real files. This document explains the guardrails that protect your data,
how to recover if something goes wrong, and the tool's limitations. **Read it before applying actions, and
keep backups.**

## Safety model

Every destructive batch (delete / hardlink / reflink) runs behind layered guardrails:

### 1. ZFS snapshot before the batch
Before the first action, `dedcom` snapshots **every dataset** the batch will touch, named
`<dataset>@dedcom-<YYYYMMDD-HHMMSS>-<seq>`. **If any snapshot fails, the entire batch is aborted** — no action
runs. Snapshots are never auto-removed; they remain as insurance until you delete them with `zfs destroy`.

### 2. Quarantine instead of unlink
"Delete" does not call `unlink`. The file is moved into a per-dataset quarantine directory,
`.dedcom-quarantine/<YYYYMMDD-HHMMSS>-<seq>/<path-relative-to-dataset>`, preserving permissions, owner, and
extended attributes. Space is reclaimed only when you purge the quarantine. The same quarantine is used to
publish hardlinks/reflinks atomically (the original is evacuated first, the link is published into the freed
slot, and on failure the original is restored).

### 3. Content revalidation before each action
Immediately before each destructive action, `dedcom` re-checks the target and the keeper against the last
scan:
- always: a symlink-swap check and a size check;
- **Hybrid** (default): each distinct file is hashed once per batch; between actions it re-stats file
  identity (device, inode, size, mtime, ctime, mode);
- **Strict** (`--strict-verify`): full re-hash of target and keeper before every action.

A mismatch aborts that action; the rest of the batch continues.

### 4. Atomic publish — `renameat2(RENAME_NOREPLACE)`
File moves use `renameat2` with `RENAME_NOREPLACE`, so "does the destination exist?" and the move itself are a
single kernel operation — there is no check-then-rename window on the destination.

### 5. Single-instance lock
A writing instance holds an advisory `flock` on `~/.local/state/dedcom/dedcom.lock`. A second instance can
only run read-only (or force-seize, which is dangerous). Headless writers never prompt — they exit non-zero
if the lock is held.

### 6. Consent gating and resource governor
A one-time disclaimer must be accepted before first use. On busy hosts the scan's resource profile
(Turbo / Balanced / **Idle**) caps threads and I/O priority so a scan does not starve VMs or backups.

### 7. Cross-dataset moves are refused
A move that would cross a dataset boundary is rejected (with an `rsync` hint) rather than performed as a
silent copy-and-delete, which would lose ownership/permissions/ACLs/xattrs, inflate sparse files, and break
hardlinks.

### Honest caveat: TOCTOU
Operations act by path, not by an open file descriptor, so a theoretical check-to-act window exists. It is
mitigated by the snapshot, the atomic publish, repeated symlink checks, and quarantine-based restore. A full
`fd + O_NOFOLLOW` closure is deliberately deferred for the single-administrator model this tool targets.

## Recovery

- **Restore one file:** move it back from `/<pool>/.dedcom-quarantine/<timestamp>/…` to its original path. If
  a hardlink now occupies that path, remove the link first, then move the original back.
- **Roll back a whole batch:** run `zfs rollback <dataset>@dedcom-<timestamp>` for each affected dataset.
  ⚠️ Rollback reverts the **entire** dataset to snapshot time — anything written since is also lost. Prefer
  restore-from-quarantine when other writes happened concurrently.
- **Purge quarantine:** `dedcom --purge-quarantine` reports the size; it deletes only with `--yes`
  (irreversible). Purge does not touch snapshots — remove those separately with `zfs destroy`. Waiting a week
  or two before purging/destroying is recommended.

## Limitations

- **Linux only** (x86_64 / aarch64), kernel ≥ 3.15 (for `renameat2`). No Windows/macOS, no cross-compile.
- **No headless apply.** `--scan` only scans; applying actions is interactive (`F11`) or via a saved
  shell-script plan. This is deliberate — applying needs visual keeper/mark confirmation.
- **ZFS-dependent safety.** Snapshots, dataset detection, reflink, and quarantine resolution rely on ZFS. On
  non-ZFS filesystems, scanning works but there is no snapshot safety, so applying actions is not recommended.
- **Root** is typically required (to take snapshots and to scan outside your home directory).
- **Hardlink** works within a single dataset and shares one inode/metadata; **reflink** needs ZFS ≥ 2.3 with
  `block_cloning` and the same pool.
- **Grouping memory** can be large on big pools (≈ hashed files × 2.5 KiB, transient); `--merkle-dirs` reduces
  it to O(depth). `dedcom` estimates and warns before the grouping phase.
- **One operator at a time** (the lock). The commander's group-files panel displays at most the first 200
  files; the apply plan still uses the full group from the database.
- No background daemon or watch mode; scans are run manually or scheduled with cron (`--scan`).
