# 04. Quickstart — a typical scenario in 5 minutes

Scenario: "I have a 6 TB ZFS pool mounted at `/tank`; over the years I've
accumulated a lot of duplicate media; I want to turn the copies into hardlinks
without starving my VMs of I/O."

All key presses below are for **commando** (the default mode). The equivalent
for the stepwise `--classic` wizard is in [§06 Classic wizard](06-classic.md).

> Before your first real run, read [§03 Safety](03-safety.md). What saves you if
> you make a mistake is the per-batch snapshot, the file quarantine, and
> revalidation. All of these guardrails are active right now — there will be a
> reminder at every step below.

## Step 1. Launch and the notice

```text
$ dedcom
```

```text
┌─ Notice ───────────────────────────────────────────────────────────────┐
│  DedupCommando 0.9.0-beta.1                                             │
│                                                                         │
│  Notice and consent                                                    │
│  ...                                                                    │
│  ▸ [ ] I have read and agree (required)                                │
│    [ ] Don't show this at startup again                                │
│  [Space] check   [Tab] switch focus   [Esc] exit                       │
└────────────────────────────────────────────────────────────────────────┘
```

- **Space** — tick the "I have read and agree" checkbox.
- (optional) **Tab → Space** — "Don't show this at startup again".
- **Enter** — continue.

The full text and the meaning of each line are in
[§02 Installation](02-install.md#1-startup-notice-one-time).

## Step 2. The Commando main screen

```text
┌─ DedupCommando v0.9.0-beta.1 ────────────────────────  RAM 13.1M · CPU  0% ┐
│ Multi-panel mode                                                            │
│ ZFS: datasets 8 · warnings 0                                                │
├──────────────────────────────┬──────────────────────────────────────────────┤
│ Panel 1 · /                  │ Panel 2 · /                                   │
│ ▸ bin/                       │   bin/                                        │
│   etc/                       │   etc/                                        │
│   home/                      │   home/                                       │
│   tank/                      │   tank/                                       │
│   usr/                       │   usr/                                        │
│   var/                       │   var/                                        │
│                              │                                               │
├──────────────────────────────┴──────────────────────────────────────────────┤
│ Panel 1 · / · files: 6                                                      │
│ 1Help 2Scan 3File 4Hash 5Hard 6Ref 7Keep 8Del 9Menu 10Exit 11Exec 12Sessions│
└─────────────────────────────────────────────────────────────────────────────┘
```

The footer is the numbered F-key bar (`1` = F1, `2` = F2, and so on). The full
description of panels and views is in [§05 Commando](05-commando.md). For now we
need just one thing: to start a configured scan.

## Step 3. The F9 menu → start the scan wizard

Press **F9**:

```text
┌─ Menu — F9 ────────────────────────────────────────────────────────────┐
│  1. Scan the active panel's directory                                  │
│  2. Configure and start a scan…                     ◀ select          │
│  3. Sessions and scan results…                                        │
│  4. Clear all marks of the active panel                               │
│  5. Reload scan data                                                  │
│  6. Change panel mode (v)                                             │
│  7. Synchronize panels (Shift+F1)                                     │
│  8. Compare panels (Shift+F2)                                         │
│  9. Add a panel (Shift+F3)                                            │
│  10. Remove a panel (Shift+F4)                                        │
│  11. Change panel root (Shift+F5)                                     │
│  12. Recompute directory size (Shift+F6)                              │
│  13. Keyboard help                                                    │
│                                                                         │
│  ↑↓ select  Enter apply  Esc cancel                                   │
└────────────────────────────────────────────────────────────────────────┘
```

**↓ Enter** on "Configure and start a scan…" → the scan configuration wizard
opens (Screen::ScanConfig).

> Alternative: **Shift+F9** (or `` ` `` then `F9` for xterm.js, see
> [§05](05-commando.md)) — the same thing in a single press.

## Step 4. Scan configuration — choose roots and a profile

```text
┌─ DedupCommando — scan configuration ───────────────────────────────────┐
│ ZFS: 2.2.4 · block_cloning: tank, rpool · reflink: available           │
│                                                                         │
│ Filter by type: All files — all files                                  │
│ Hash cache: on — repeat scans skip unchanged files                     │
│ Intensity: Balanced — 2 threads, no seek-thrash                        │
│                                                                         │
│ Datasets and folders — Space select, F add folder                       │
│   [ ] rpool        →  /rpool                                            │
│ ▸ [x] tank         →  /tank                                             │
│   [ ] tank/media   →  /tank/media                                       │
│   [ ] tank/backup  →  /tank/backup                                      │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ ↑↓ · Space · F folder · P preset · C cache · G intensity · Del remove · S start · Q quit │
└─────────────────────────────────────────────────────────────────────────┘
```

| Key       | Action                                                                |
|-----------|-----------------------------------------------------------------------|
| **↑↓**    | Move the cursor over roots                                            |
| **Space** | Mark / unmark a root                                                  |
| **F**     | Add an arbitrary folder (FolderPicker)                                |
| **P**     | Cycle the extension-filter preset                                    |
| **C**     | Turn the hash cache on / off (`hash_cache`)                          |
| **G**     | Cycle the intensity profile (Turbo → Balanced → Idle → Turbo)        |
| **Delete**| Remove an added folder from the list                                 |
| **S**     | Start the scan                                                       |
| **q**     | Quit                                                                 |

**What to press:**

1. **Space** on `tank` (mark the whole pool).
2. **G** — switch the profile to **Idle** (from the default Balanced — once;
   from Turbo — twice; the cycle is `Turbo → Balanced → Idle → Turbo`).
3. **S** — start.

> ⚠️ **Idle on production data is mandatory.** There are three profiles:
> **Turbo** (all cores, disk at full — "it's my pool, I'm in a hurry"),
> **Balanced** (the default: 2 threads, no seek-thrash), and **Idle** (1 thread
> + nice 19 + ionice idle — does not starve VMs or backups of I/O). More in
> [§07 Scanning](07-scanning.md).

## Step 5. Scanning

```text
┌─ DedupCommando — scanning ─────────────────────────────────────────────┐
│ Phase 2/3: hashing content                                             │
│                                                                         │
│ Walked:  1,234,567 entries · 1,201,034 files                           │
│ Hashed:  412,765 / 1,201,034 files                                     │
│ Read:  423 GiB / 1234 GiB                                              │
│ Speed:  92 MiB/s · remaining ~02:14:30                                 │
│ Chunk:  8765 / 50000 files  (Esc stops after the chunk)                │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ [Esc] stop — progress is saved, you can resume later                   │
└─────────────────────────────────────────────────────────────────────────┘
```

The phases:

1. **Walk** (1/3) — tree traversal, ~minutes per million files.
2. **Hash** (2/3) — the longest phase. On 2×HDD ≈ 50–100 MiB/s in Idle (faster
   on SSD).
3. **Group** (3/3) — seconds to minutes; **peak memory ~2.5 KiB/file**. If RAM
   is short, use `--merkle-dirs` (§07).

> RAM and CPU use are shown in the top-right badge of the header, not as fields
> on this screen.

**Esc** — a clean cancel. Progress is saved to `dedcom.db` in chunks — on the
next launch the wizard will offer to resume. Exactly what is saved at each phase
is in [§03 Safety](03-safety.md#what-happens-if-you).

When the scan finishes it returns to commando automatically; the header will
show a "scan loaded" indicator — meaning the panels are ready to display groups.

## Step 6. Switch a panel to "duplicate groups"

The active panel currently shows the directory's files. To see the groups that
were found, cycle the view with **v** in the active panel:

```text
v once  → directories
v twice → groups               ◀ this is where we want to be
v three → group files (watch)
v ...   → cursor duplicates / twin folders / ...
```

When the panel shows groups:

```text
┌─ groups · /tank (12,437 groups total, frees 145 GiB) ──────────────────┐
│ #1 ●●●●●●●  72.4 MiB × 23  /tank/media/photo/2022-08/IMG_4421.HEIC    │
│ #2 ●●●●●●   45.0 MiB × 18  /tank/backup/2023/proxmox.tar              │
│ #3 ●●●●     32.1 MiB × 12  /tank/media/video/test.mp4                 │
│ #4 ●●●●     28.3 MiB × 11  /tank/old/iso/ubuntu.iso                   │
│ ▸ #5 ●●●●   25.7 MiB × 10  /tank/media/photo/2021-11/IMG_3120.HEIC    │
│ #6 ●●●     18.9 MiB × 8   /tank/media/photo/2024-03/IMG_7891.HEIC    │
│ ...                                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

Sorting is by reclaim payoff (how much deduplicating the group would free) by
default.

## Step 7. Switch the adjacent panel to "group files"

In commando the adjacent panel on the right automatically shows the files of the
group under the cursor — if its view is set to **"group files"** (watch mode).
Switch focus to the adjacent panel (**Tab**) and cycle **v** to that view:

```text
┌─ groups ────────────────────────┬─ group files #5 (10 of 10) ───────────┐
│ #1 ●●●●●●●  72.4 MiB × 23      │   /tank/media/photo/2021-11/IMG_3120.HEIC│
│ #2 ●●●●●●   45.0 MiB × 18      │   /tank/media/photo/2022-03/IMG_9876.HEIC│
│ #3 ●●●●     32.1 MiB × 12      │ ▸ /tank/backup/photo/IMG_3120.HEIC      │
│ #4 ●●●●     28.3 MiB × 11      │   /tank/old-copy/IMG_3120.HEIC          │
│ ▸ #5 ●●●●   25.7 MiB × 10      │   /tank/media/photo/2021-11/dup.HEIC    │
│ #6 ●●●     18.9 MiB × 8       │   /tank/old-copy-2/IMG_3120.HEIC        │
│ ...                              │   ...                                  │
└─────────────────────────────────┴────────────────────────────────────────┘
```

The adjacent panel on the right switches automatically as the cursor moves in
the left panel ("watch" modes). More in [§05 Commando](05-commando.md).

> On very large groups (millions of files) the files panel shows the **first
> 200** — a visual cap to keep navigation from freezing. The cap does **not**
> affect mass actions (F11): the plan is built from the database over the full
> group. See [§13](13-troubleshooting.md).

## Step 8. Mark a keeper and hardlinks

The cursor is in the right panel (focus on "group files"). On the file that
**stays** (typically the most "canonical" path, e.g. the first alphabetically):

- **F7** — mark as **keeper** (`K` at the start of the line).

On the rest of the files in the group:

- **F5** — mark as **hardlink to the keeper** (`H` at the start of the line).

```text
┌─ group files #5 ───────────────────────────────────────────────────────┐
│ K /tank/media/photo/2021-11/IMG_3120.HEIC                              │
│ H /tank/media/photo/2022-03/IMG_9876.HEIC                              │
│ H /tank/backup/photo/IMG_3120.HEIC                                      │
│ H /tank/old-copy/IMG_3120.HEIC                                          │
│ H /tank/media/photo/2021-11/dup.HEIC                                    │
│ H /tank/old-copy-2/IMG_3120.HEIC                                        │
│ ...                                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

Alternatives:

- **F8** on non-keepers → delete to quarantine (not a hardlink); marked `D`.
- **F6** → reflink (only if `block_cloning: active` for the dataset — see the
  scan-configuration header); marked `C`.
- **Space** on a marked file — clear the mark.

How `delete` differs from `hardlink` and which to pick when are in
[§08 Actions](08-actions.md).

## Step 9. F11 — confirmation

Once there is a keeper plus marked actions, **F11** opens the confirmation
overlay with two tabs — **Summary** and **Commands**:

```text
┌─ Confirmation — F11 ───────────────────────────────────────────────────┐
│   Summary     Commands                                                 │
│                                                                         │
│   Actions to be executed: 9                                            │
│   Approximately freed: 232.0 MiB                                       │
│                                                                         │
│   A ZFS snapshot for rollback is created before changes.               │
│                                                                         │
│   [Tab] tab  [S] save .sh  [Y] execute  [N]/[Esc] cancel               │
└─────────────────────────────────────────────────────────────────────────┘
```

| Key             | Action                                                        |
|-----------------|---------------------------------------------------------------|
| **Tab**         | Switch tab: "Summary" ↔ "Commands" (the full shell-script plan) |
| **S**           | Save the plan as a `.sh` file (dry-run — review / run by hand) |
| **Y**           | Execute — start applying                                      |
| **N** / **Esc** | Cancel                                                        |

The **Commands** tab is the generated shell script. Saving the `.sh` with **S**
is useful if you want to review the plan by eye or run it without the TUI (an
audit trail).

**Y** — go.

## Step 10. Applying

```text
┌─ DedupCommando — applying actions · mode: hybrid ──────────────────────┐
│ Verifying content and moving/linking…                                  │
│                                                                         │
│ Action:  5 / 9                                                         │
│ Re-verified:  127 MiB / 232 MiB                                        │
│                                                                         │
│ Now: hardlink /tank/media/photo/2021-11/dup.HEIC → ../IMG_3120.HEIC    │
│                                                                         │
│ Snapshots: tank@dedcom-20260527-143215-512874000-4821-0               │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ [Esc] stop after the current action — the snapshot is done, applied items are in quarantine │
└─────────────────────────────────────────────────────────────────────────┘
```

What happens:

1. **Snapshots** — a ZFS snapshot of every affected dataset. A failure of any
   one aborts the batch; no action is performed.
2. **Applying** — per action: revalidate (re-hash the target + keeper; in Hybrid
   mode the keeper is read once per batch) → evacuate the original to quarantine
   → publish the hardlink/reflink via `renameat2(RENAME_NOREPLACE)`.
3. **Done** — the summary.

**Esc** — cancel on an action boundary. What has been done by that point is in
quarantine and reversible. Details in
[§03 Safety](03-safety.md#pull-the-cable-during-apply-between-actions).

## Step 11. Summary

```text
┌─ DedupCommando — summary ──────────────────────────────────────────────┐
│ Completed successfully: 9 operations      Errors: 0                    │
│                                                                         │
│ Safety snapshots created:                                              │
│   zfs rollback tank@dedcom-20260527-143215-512874000-4821-0           │
│                                                                         │
│ Files moved to quarantine:                                             │
│   /tank/.dedcom-quarantine/20260527-143215-512874000-4821-0/          │
│                                                                         │
│ Volume of successfully processed files: 232.0 MiB                      │
│ Space is freed AFTER verifying and purging with the commands:          │
│   zfs destroy tank@dedcom-20260527-143215-512874000-4821-0            │
│   dedcom --purge-quarantine                                            │
├─────────────────────────────────────────────────────────────────────────┤
│ [Esc] to configuration · [Q] quit                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

Done. What to do next:

- **Use the system normally for a few days** — make sure nothing broke (images
  open, backup scripts didn't fail, and so on).
- **When you're confident** — delete the snapshot and the quarantine:
  ```text
  zfs destroy tank@dedcom-20260527-143215-512874000-4821-0
  dedcom --purge-quarantine
  ```
- **If something is wrong** — roll back:
  ```text
  zfs rollback tank@dedcom-20260527-143215-512874000-4821-0
  ```
  This rollback returns the **whole** dataset to its state before the batch
  (including everything other processes wrote in the meantime).

## What's next

- [§05 Commando](05-commando.md) — all the capabilities of the multi-panel mode.
- [§06 Classic wizard](06-classic.md) — the linear, stepwise equivalent.
- [§07 Scanning](07-scanning.md) — details on profiles, filters, `--merkle-dirs`.
- [§08 Actions](08-actions.md) — when to choose delete vs hardlink vs reflink.
- [§09 Triage Board](09-triage-board.md) — for manual layout (not dedup).
