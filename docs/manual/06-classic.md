# 06. Classic wizard (`--classic`)

The classic step-by-step wizard. Opened with the `--classic` flag:

```text
$ dedcom --classic
```

Unlike Commando (see [§05](05-commando.md)), this is a linear flow: one
screen at a time, explicit "forward / back" buttons. Useful for:

- a first acquaintance — each step suggests the next;
- stream-scripting — plain ASCII output without the multi-panel mosaic;
- terminals without extended-keyboard support (no F-keys, no Shift+F).

Screen flow:

```text
ScanConfig ──► Scanning ──► Browser ──► ActionReview ──► Applying ──► Summary
    │             │                                                         │
    ▼ F           ▼ Esc                                                     ▼ Esc
FolderPicker                                                            ScanConfig
                  │
                  ▼
              Resume ──► ScanDiff   (D — compare scans)
                 │
                 └─────► Trash      (t — session trash)
```

All wizard screens are also reachable from commando (via `F12` for Resume,
`Shift+F9` for ScanConfig, and so on) — it is the **same code**, the only
difference is the start-up view.

## 6.1. ScanConfig — scan configuration

Goal of this screen: choose what to scan, with which filter and which
intensity profile.

```text
┌ DedupCommando — scan configuration ────────────────────────────────────┐
│┌ Scan parameters — P preset · C cache · G intensity ───────────────────┐│
││ Filter by type: All files — all files                                 ││
││ Hash cache: on — repeat scans skip unchanged files                    ││
││ Intensity: Balanced — 2 threads, no seek-thrash                       ││
│└───────────────────────────────────────────────────────────────────────┘│
│┌ Datasets and folders — Space select, F add folder ────────────────────┐│
││   [ ] rpool        →  /rpool                                          ││
││ ▸ [x] tank         →  /tank                                           ││
││   [ ] tank/media   →  /tank/media                                     ││
││   [ ] tank/backup  →  /tank/backup                                    ││
│└───────────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────┤
│ ↑↓ · Space · F folder · P preset · C cache · G intensity · Del remove · S start · Q quit │
└─────────────────────────────────────────────────────────────────────────┘
```

With no roots yet the list shows `No roots set — press F to add a folder`.
The type-filter line reads `Filter by type: {preset} — all files` for the
all-files preset, or `Filter by type: {preset} ({ext,ext})` for an
extension preset. The hash-cache line toggles between
`Hash cache: on — repeat scans skip unchanged files` and
`Hash cache: off — all files will be re-hashed`. The intensity line is
`Intensity: {label} — {hint}` (see profiles below).

| Key         | Action                                                              |
|-------------|---------------------------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Move the cursor through the roots                |
| **Space**   | Mark / unmark a root                                                |
| **F**       | Add an arbitrary folder → FolderPicker                              |
| **P**       | Switch the extension-filter preset (for example, "media only")     |
| **C**       | Turn the hash cache on / off (see [§07](07-scanning.md))           |
| **G**       | Switch the intensity profile (cycle: Turbo → Balanced → Idle → Turbo) |
| **Del**     | Remove an arbitrarily added folder from the list                    |
| **S**       | Start the scan (needs ≥1 selected root)                             |
| **q** / **Q** | Quit                                                              |

Profiles cycle Turbo → Balanced → Idle and carry a hint each: `Turbo`
(all cores, disk at full), `Balanced` (2 threads, no seek-thrash), `Idle`
(1 thread, nice+ionice idle). More on profiles and filters —
[§07 Scanning](07-scanning.md).

## 6.2. FolderPicker — adding an arbitrary folder

If the directory you need is not a ZFS dataset (for example, a subdirectory
inside a pool), add it through the FolderPicker:

```text
┌ DedupCommando — pick a folder to scan ─────────────────────────────────┐
│ Current directory:  /tank/media                                        │
│┌ Subdirectories — Enter to enter ──────────────────────────────────────┐│
││ ▸ photo/                                                               ││
││   video/                                                               ││
││   audio/                                                               ││
││   raw/                                                                 ││
│└───────────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────┤
│ ↑↓ select · Enter enter · Backspace up · A select this directory · Esc cancel │
└─────────────────────────────────────────────────────────────────────────┘
```

When a directory has no subdirectories the list shows `(no subdirectories)`.

| Key                    | Action                                            |
|------------------------|---------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Move the cursor                           |
| **Enter**              | Open the subdirectory under the cursor            |
| **Backspace**          | Go up to the parent directory                     |
| **A**                  | Select the CURRENT directory as a root → back to ScanConfig |
| **Esc**                | Return to ScanConfig without adding               |

## 6.3. Resume — scan list

After the first run, on the next start the wizard opens **Resume** — a list
of previously performed scans:

```text
┌ DedupCommando v0.9.0-beta.1 ─── Scans ─────────────────────────────────┐
│ Saved scans · DB on disk: 184.2 MiB                                    │
│┌ Scans — R/Enter open · Del to trash · t trash · N new ────────────────┐│
││ ▸ #142  /tank             hashing 47%   2026-05-20 14:15             ││
││   #141  /tank             ready         2026-04-12 09:23             ││
││   #140  /tank/media       ready ⚠       2026-03-30 11:08             ││
││   #135  /rpool            aborted       2026-02-14 22:50             ││
││   ...                                                                  ││
│└───────────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────┤
│ ↑↓ · R/Enter open · Del to trash · t trash · N new · Q quit            │
└─────────────────────────────────────────────────────────────────────────┘
```

Entries are sorted newest to oldest. The status column shows `walking`,
`hashing {pct}%`, `ready`, `ready ⚠` (finished with read warnings), or
`aborted`.

| Key                    | Action                                                |
|------------------------|-------------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Move the cursor through the scans            |
| **R** / **Enter**      | Resume an unfinished scan OR open a finished one's result |
| **N**                  | New scan → ScanConfig                                 |
| **D**                  | Compare the selected scan with the next one in the list (an older one) → ScanDiff |
| **t**                  | Open the session trash → Trash                        |
| **Del**                | Move the selected scan to trash (soft, reversible)    |
| **q** / **Q**          | Quit                                                  |

> **Opened result vs new scan.** Pressing R on a finished scan opens the
> stored materialization (without re-scanning) — instant for fresh ones, up
> to tens of seconds for old ones (materialized once into `file_group`).
> For fresh data, start a new scan (N).

## 6.4. Scanning — scan progress

```text
┌ DedupCommando — scanning ──────────────────────────────────────────────┐
│ Phase 2/3: hashing content                                             │
│                                                                         │
│ Walked:  1,234,567 entries · 1,200,400 files                           │
│ Hashed:  423,180 / 1,234,567 files                                     │
│ Read:  198.4 GiB / 412.0 GiB                                           │
│ Speed:  92 MiB/s · remaining ~02:14:30                                 │
│                                                                         │
│ Now: /tank/media/photo/2024-08/IMG_0815.HEIC                           │
│ Failed to hash:  3 files                                               │
├─────────────────────────────────────────────────────────────────────────┤
│ [Esc] stop — progress is saved, you can resume later                   │
└─────────────────────────────────────────────────────────────────────────┘
```

The phase line changes through the run: `Phase 1/3 · walking files`,
`Phase 1/3 · writing manifest`, `Phase 2/3: hashing content`,
`Phase 3/3: grouping`, and `Preparing…`. While hashing a chunked resume
also shows `Chunk:  {} / {} files  (Esc stops after the chunk)`.

| Key         | Action                                                              |
|-------------|---------------------------------------------------------------------|
| **Esc**     | Stop the scan cleanly (progress is saved to the database for resume) |

The three phases and what they save — [§03 Data Safety](03-safety.md#what-happens-if-you).

For very large trees you can rerun with `--merkle-dirs` to lower the
phase-3 memory footprint (see [§07](07-scanning.md)).

## 6.5. Browser — viewing groups and marking actions

After a scan finishes (or after opening a finished session) — the Browser
(shared with commander):

```text
┌ DedupCommando v0.9.0-beta.1 ─── Duplicates ────────────────────────────┐
│ Groups: 12,437 · Scanned: 234.5 GiB · Will free: 41.2 GiB · Marked: 18 │
│┌ [1] Folders  [2] Files ──────────────┬ Group files · view: name bright ┐│
││ ▸ #5  72.4M × 23 IMG_4421            │ ★ /tank/backup/IMG_4421.HEIC    ││
││   #6  45.0M × 18 disk.img            │ x /tank/dup/IMG_4421.HEIC -> DELETE││
││   #7  32.1M × 12 test.mp4            │ h /tank/old-copy/IMG_4421.HEIC -> HARDLINK││
││   ...                                 │ = /tank/media/IMG_4421.dup      ││
│└───────────────────────────────────────┴─────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────┤
│ 1=Folders 2=Files · Tab · ↑↓/PgUp·PgDn/g·G · LMB·wheel · Enter=keeper · d/h/c=mark · Space=unmark · a=auto · v=view · r=review · ?=help │
└─────────────────────────────────────────────────────────────────────────┘
```

The two tabs are `[1] Folders` and `[2] Files`. The right panel title is
`Group files · view: {name bright|name first|by tree}` on the Files tab and
`Group folders` on the Folders tab. Marks are shown by glyph: `★ ` keeper,
`= ` already linked, `x ` delete, `h ` hardlink, `c ` reflink; a marked row
also carries the suffix `-> DELETE`, `-> HARDLINK`, or `-> REFLINK`.

| Key                    | Action                                              |
|------------------------|-----------------------------------------------------|
| **1** / **2**          | Switch to the Folders / Files tab                   |
| **Tab**                | Switch focus between the panels                     |
| **↑** / **↓** or **k** / **j**, **PgUp** / **PgDn**, **g** / **G** | Move the cursor / jump |
| **Enter**              | (on a file) Assign keeper for the group             |
| **d**                  | Mark as Delete (to quarantine)                      |
| **h**                  | Mark as Hardlink                                    |
| **c**                  | Mark as Reflink (ZFS clone)                         |
| **Space**              | Clear the mark                                       |
| **a**                  | Auto-select across ALL groups (keeper by rule + the rest = default action) |
| **v**                  | Switch the file-view style (name bright / name first / by tree) |
| **r**                  | Go to the action review (ActionReview)              |
| **?**                  | Keyboard help                                       |

### How the Browser differs from the commando views

In commando, the same data is shown by the **GroupList + GroupFiles** pair
(see [§05](05-commando.md)). The Browser is a "fixed" combination on a single
screen with an explicit header and footer. In commando the panels are more
flexible (you can hold GroupList + DupOf + DirGroupList + Files at once), but
also more complex.

For deduplicating **large** scans (millions of files) the Browser is simpler:
a single layout, nothing drifts apart.

## 6.6. ActionReview — action review

From the Browser, the **r** key opens the list of **planned** actions — what
exactly will happen on apply:

```text
┌ Action review — dry-run, nothing executed yet ─────────────────────────┐
│ HARDLINK   /tank/dup/IMG_4421.HEIC                       (3.6 MiB)      │
│ HARDLINK   /tank/old-copy/IMG_4421.HEIC                  (3.6 MiB)      │
│ DELETE     /tank/junk/duplicate.bin                      (1.8 MiB)      │
│ REFLINK    /tank/vm/disk.img                             (80.0 MiB)     │
│ ...                                                                      │
├─────────────────────────────────────────────────────────────────────────┤
│ Operations: 9 · potential to free: 232.0 MiB                           │
│ Before applying, ZFS snapshots of the affected datasets will be created. │
│ [Y] execute · [Esc] back to review                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

Each row is `{KIND:9}  {path}   ({bytes})`.

| Key         | Action                                                              |
|-------------|---------------------------------------------------------------------|
| **↑** / **↓**| Scroll the list                                                    |
| **Y**       | Go to the final confirmation (modal "are you sure?")               |
| **Esc**     | Return to the Browser                                               |

After **Y** — a modal confirmation on top:

```text
┌ Confirmation ──────────────────────────────────────────────────────────┐
│  Execute 9 operations?                                                  │
│  A snapshot + quarantine are created — actions are reversible until     │
│  purge.  (frees ~232.0 MiB)                                            │
│                                                                         │
│  [Y] yes        [N] no                                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

| Key         | Action                                                              |
|-------------|---------------------------------------------------------------------|
| **Y**       | Start applying                                                     |
| **N**       | Close the modal, stay in ActionReview                              |

## 6.7. Applying — applying

The same screen as in commando (see [§04 Quickstart, step 10](04-quickstart.md#step-10-applying)):

```text
┌ DedupCommando — applying actions · mode: hybrid ───────────────────────┐
│ Verifying content and moving/linking…                                  │
│                                                                         │
│ Action:  5 / 9                                                         │
│ Re-verified:  5 / 9                                                    │
│                                                                         │
│ Now: hardlink /tank/dup/IMG_3120.HEIC → /tank/backup/IMG_canon.HEIC    │
│                                                                         │
│ Snapshots: tank@dedcom-20260527-143215-…                               │
├─────────────────────────────────────────────────────────────────────────┤
│ [Esc] stop after the current action — the snapshot is done, applied items are in quarantine │
└─────────────────────────────────────────────────────────────────────────┘
```

The mode in the title is `strict`, `hybrid`, or `fast`. The phase line
moves through `Creating safety ZFS snapshots…`,
`Verifying content and moving/linking…`, and `Finishing…`.

| Key         | Action                                                              |
|-------------|---------------------------------------------------------------------|
| **Esc**     | Stop after the current action. The snapshot is done; applied items are in quarantine. |

> **`q` does not work** during applying — you must not abandon the process in
> the middle of a destructive operation. Esc is the only way to stop cleanly.

The cancel semantics — [§03 Data Safety](03-safety.md#press-esc-during-apply).

## 6.8. Summary — result

```text
┌ DedupCommando — summary ───────────────────────────────────────────────┐
│ Completed successfully: 9 operations      Errors: 0                     │
│                                                                         │
│ Safety snapshots created:                                              │
│   tank@dedcom-20260527-143215-0                                        │
│                                                                         │
│ Files moved to quarantine:                                             │
│   /tank/.dedcom-quarantine/20260527-143215-0/                          │
│                                                                         │
│ Planned to be freed: 232.0 MiB                                         │
│ Volume of successfully processed files: 232.0 MiB                      │
│                                                                         │
│ Space is freed AFTER verifying and purging with the commands:          │
│   zfs destroy tank@dedcom-20260527-143215-0                            │
│   dedcom --purge-quarantine                                            │
├─────────────────────────────────────────────────────────────────────────┤
│ [Esc] to configuration · [Q] quit                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

On a run with errors, each failed operation is listed as
`✗ {DELETE|HARDLINK|REFLINK} {path} — {message}`.

| Key         | Action                                                              |
|-------------|---------------------------------------------------------------------|
| **Esc**     | Return to ScanConfig (for a new scan)                              |
| **Q**       | Quit                                                              |

Further actions with the snapshot and quarantine — [§03 Data Safety](03-safety.md#1-zfs-snapshot-of-the-action-batch).

## 6.9. ScanDiff — comparing two scans

Opened from Resume with the **D** key — compares the selected scan (the
newer one) with the next in the list (the older one):

```text
┌ Scan comparison ───────────────────────────────────────────────────────┐
│ Scans #141 ↔ #142 · root /tank                                         │
│ Unchanged: 1,204,300 · Moved: inode 412 / hash 38                      │
│ Modified: 17 · Deleted: 9 · New: 124                                   │
│ New duplicates (a duplicate arrived): 6                                 │
│┌ Moved (inode) (412) — Tab next category ──────────────────────────────┐│
││ ▸ /tank/old/A.bin   →   /tank/archive/A.bin                          ││
││   /tank/old/B.bin   →   /tank/archive/B.bin                          ││
││   ...                                                                  ││
│└───────────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────┤
│ ↑↓ select · Tab/Shift+Tab category · Esc/F10 back                      │
└─────────────────────────────────────────────────────────────────────────┘
```

The categories cycled by **Tab** are `New duplicates`, `Moved (inode)`,
`Moved (hash)`, `Modified`, `Deleted`, and `New`. The list title shows the
active one: `{category} ({count}) — Tab next category`.

| Key              | Action                                                         |
|------------------|----------------------------------------------------------------|
| **Tab**          | Next category                                                 |
| **Shift+Tab**    | Previous category                                             |
| **↑** / **↓** or **k** / **j** | Move the cursor in the current category's list   |
| **Esc** or **F10** | Return to Resume                                            |

Categories and the algorithm — [§10 ScanDiff + Trash](10-diff-trash.md).

## 6.10. Trash — session trash

Opened from Resume with the **t** key — softly deleted scans:

```text
┌ DedupCommando — trash ─────────────────────────────────────────────────┐
│ Trash — deleted scans                                                  │
│┌ R/Enter restore · Del purge permanently · Esc back ───────────────────┐│
││ ▸ #138  /tank/media      2026-02-01 (deleted 2026-04-10)             ││
││   #135  /rpool           2026-01-15 (deleted 2026-03-22)             ││
││   ...                                                                  ││
│└───────────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────┤
│ ↑↓ select · R restore · Del purge permanently · Esc back               │
└─────────────────────────────────────────────────────────────────────────┘
```

| Key                    | Action                                                |
|------------------------|-------------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Move the cursor                              |
| **R** / **Enter**      | Restore the session (returns to the active list)      |
| **Del**                | Purge PERMANENTLY (modal confirmation)                |
| **Esc**                | Return to Resume                                       |

Moving to trash and purging both go through a confirmation modal —
` Move to trash? ` with body
`The session will be moved to the trash — it can be restored (t).`, or
` Purge from trash? ` with body
`The session will be deleted PERMANENTLY — this is irreversible.`; both
offer `[Y] yes    ·    [N] no`.

Purging is heavy (millions of rows are removed from `file`) — it runs in the
background, with status shown in the status line.

More detail — [§10 ScanDiff + Trash](10-diff-trash.md).

## What's next

- [§05 Commando](05-commando.md) — the multi-panel equivalent.
- [§07 Scanning](07-scanning.md) — what "Idle/Balanced/Turbo" and the like mean.
- [§08 Actions](08-actions.md) — Delete vs Hardlink vs Reflink.
- [§14 Hotkeys](14-hotkeys.md) — a printable table of all keys.
