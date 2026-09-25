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
│  4. Execute marked actions (F11 or x)                                 │
│  5. Clear all marks                                                   │
│  6. Reload scan data                                                  │
│  7. Change panel mode (v)                                             │
│  8. Synchronize panels (Shift+F1)                                     │
│  9. Compare panels (Shift+F2)                                         │
│  10. Add a panel (Shift+F3)                                           │
│  11. Remove a panel (Shift+F4)                                        │
│  12. Change panel root (Shift+F5)                                     │
│  13. Recompute directory size (Shift+F6)                              │
│  14. Keyboard help                                                    │
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
│   [ ] tank/vm      →  /tank/vm                                          │
│   [ ] tank/iso     →  /tank/iso                                         │
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

> ⚠️ **A backup program's store or a virtual machine's disks on this pool?** Then do not
> mark the whole pool: mark the datasets, or add the folders with **F**, that do not reach
> them ([§8.9](08-actions.md#89-backups-and-other-programs-stores)).

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
┌ 1 · groups (by savings) ─────────────────────────────────────────────┐
│▶ #0    2 files · 2 objects · 4.0 GiB                                 │
│    guaranteed after quarantine purge: 4.0 GiB                        │
│  #1    2 files · 2 objects · 700.0 MiB                               │
│    guaranteed after quarantine purge: 700.0 MiB                      │
│  #2    3 files · 3 objects · 24.0 MiB                                │
│    guaranteed after quarantine purge: 48.0 MiB                       │
└──────────────────────────────────────────────────────────────────────┘
```

Each group takes two lines. The first gives its rank (counting from `#0`), how many
files it has, how many separate copies of the data those files are (`objects`: files
that are already hardlinks of one another count once) and the size of one file. The
second is the space you are guaranteed to get back once the copies are dealt with and
the quarantine is purged ([§08](08-actions.md)). The largest figure comes first.

## Step 7. Switch the adjacent panel to "group files"

In commando the adjacent panel on the right shows the files of the group under the
cursor — if its view is set to **"group files"** (a watch mode). Put the cursor on a
group, switch focus to the adjacent panel (**Tab**) and cycle **v** to that view.
With the cursor on `#2`:

```text
┌ 2 · group files ─────────────────────────────────────────────────────┐
│guaranteed after quarantine purge: 48.0 MiB · links seen 3/unrecorded │
│▶   IMG_3120.HEIC  ·  /tank/backup/photo                              │
│    IMG_3120.HEIC  ·  /tank/media/photo/2021-11                       │
│    IMG_3120.HEIC  ·  /tank/old-copy                                  │
└──────────────────────────────────────────────────────────────────────┘
```

The first line repeats the group's figure. Each file is shown by its name, then its
directory. The panel follows the cursor
in the groups panel ("watch" modes). More in [§05 Commando](05-commando.md).

> On very large groups the files panel shows the **first 200** files — a visual cap
> to keep navigation from freezing. The cap does **not** affect mass actions (F11):
> the plan is built from the database over the full group. See
> [§13](13-troubleshooting.md).

## Step 8. Mark a keeper and hardlinks

Marks are set in a files panel. In "group files" the marking keys are refused with
`Row commands need «files» or «directories» view (press v)`; the **o** key takes you
from a file of the group to the file itself:

1. In "group files", put the cursor on the file that **stays** (typically the most
   "canonical" path) and press **o**. Its directory opens in a third panel on the
   right, with the cursor on that file and the focus in that panel. Three panels need
   a window at least 108 columns wide.
2. Once the file is under the cursor there, press **F7** — mark it as the **keeper**
   (`K` in the files panel).
3. Go back with **←**, put the cursor on a copy and press **o** again. The third panel
   now shows that copy's directory while the focus stays in "group files"; move there
   with **→** and, once the copy is under the cursor, press **F5** — **hardlink to the
   keeper** (`H`).
4. Repeat step 3 for each remaining copy.

A hardlink or a reflink stays inside one dataset: here all three copies are in
`tank`. A copy on another dataset than the keeper can only be deleted (**F8**); a
hardlink or reflink mark on it makes **F11** refuse the plan
([§13](13-troubleshooting.md)).

"group files" shows the marks as they are saved:

```text
┌ 2 · group files ─────────────────────────────────────────────────────┐
│guaranteed after quarantine purge: 48.0 MiB · links seen 3/unrecorded │
│▶ h IMG_3120.HEIC  ·  /tank/backup/photo  -> HARDLINK                 │
│  ★ IMG_3120.HEIC  ·  /tank/media/photo/2021-11  (keeper)             │
│  h IMG_3120.HEIC  ·  /tank/old-copy  -> HARDLINK                     │
└──────────────────────────────────────────────────────────────────────┘
```

Here `★` is the keeper and `h` a hardlink; a reflink shows as `c`, a delete as `x`, and
`=` marks a file that is already the same file on disk as the keeper.

Alternatives, in the files panel:

- **F8** on a copy → delete to quarantine (not a hardlink); marked `D`, shown as `x`
  in "group files".
- **F6** → reflink (only if `block_cloning: active` for the dataset — see the
  scan-configuration header); marked `C`, shown as `c`. Like a hardlink, only for a
  copy on the keeper's dataset.
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
│   By type: delete 2 · hardlink 7                                       │
│   guaranteed after quarantine purge: 232.0 MiB                         │
│                                                                         │
│   DELETE    /tank/junk/duplicate.bin                                   │
│   DELETE    /tank/junk/duplicate-2.bin                                 │
│   HARDLINK  /tank/dup/IMG_4421.HEIC                                    │
│   HARDLINK  …/old-copy/IMG_4421.HEIC                                   │
│   HARDLINK  /tank/dup/IMG_4422.HEIC                                    │
│   … and 4 more                                                          │
│                                                                         │
│   A ZFS snapshot for rollback is created before changes.               │
│                                                                         │
│   [Tab] tab  [S] save .sh  [Y] execute  [N]/[Esc] cancel               │
└─────────────────────────────────────────────────────────────────────────┘
```

The composition matters more than the total: "Actions: 3" looks exactly the same
whether you marked the three copies or the three originals. The **By type** line
and the first few paths are there so a batch that marked the wrong side of a
group is recognisable before **Y**. Deep paths lose their head, not their name.
On a short terminal the box gives up the quoted paths first, then the spacing
and the explanatory lines — the count, the composition, the `… and N more` and
the `[Y]/[N]` hint stay visible down to a 10-row window.

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
│ Space is released AFTER verifying and purging with the commands:       │
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
  dedcom --purge-quarantine --yes
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
