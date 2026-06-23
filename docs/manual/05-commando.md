# 05. Commando — Multi-panel mode

Commando is the default mode. It opens when you launch `dedcom` without flags
(or explicitly with `dedcom --commando`). The alternative is the step-by-step
wizard `dedcom --classic` ([§06](06-classic.md)).

This is a **multi-panel navigator** in the spirit of classic two-panel file managers: 2–4
independent panels, each showing something of its own (the files of a directory,
duplicate groups, the files of a selected group, and so on). The main difference
from those is that panels can be "watch" modes and switch automatically as the
cursor moves in a neighbouring panel.

## Screen anatomy

```text
┌─ DedupCommando v0.9.0-beta.1 ────────────────────────  RAM 47.2M · CPU  3% ┐ ← header
│ Multi-panel mode                                                            │ ← mode line
│ ZFS: datasets 8 · block_cloning: tank, rpool · dedup: loaded                │ ← info line
├──────────────────────────┬──────────────────────────┬──────────────────────┤
│ /tank · files · name     │ /tank · groups           │ Group files #5       │
│ ▸ media/                 │ #1 ●●●●  72.4M × 23      │   /tank/IMG_3120.HEIC│ ← 2–4 panels
│   backup/                │ #2 ●●●●  45.0M × 18      │ K /tank/IMG_canon.HEIC│
│   old/                   │ ▸ #5 ●●●  25.7M × 10     │ H /tank/dup.HEIC     │
│   iso/                   │ #6 ●●●   18.9M × 8       │ H /tank/copy.HEIC    │
│   .dedcom-quarantine/    │ ...                       │ ...                  │
├──────────────────────────┴──────────────────────────┴──────────────────────┤
│ Panel 1 · /tank · files: 5 · sort: name · v view · s sort · m layout       │ ← status
│ 1Help 2Scan 3File 4Hash 5Hard 6Ref 7Keep 8Del 9Menu 10Exit 11Exec 12Sessions│ ← F-keys
└─────────────────────────────────────────────────────────────────────────────┘
```

- **Header** — the brand title, the version, and the process RAM/CPU badge.
- **Info line** — an overview of ZFS (pools, datasets, capabilities) plus the
  status of the dedup overlay (whether a scan result is loaded into the cache).
- **Panels** — from 2 to 4; the ones that fit the window width are visible. If the
  window is narrow, the extra panels are "hidden", with a count in the status line.
- **Status line** — a short hint for the active panel plus the relevant
  single-character keys.
- **F-key footer** — the numbering (`1` = F1, …, `12` = F12). The background color
  changes when the second layer is armed (see below).

## Basic panel control

| Key              | Action                                                    |
|------------------|-----------------------------------------------------------|
| **Tab**          | Focus the next panel (cyclic)                            |
| **Shift+Tab**    | Focus the previous panel                                  |
| **←** / **→**    | Focus the previous / next panel                           |
| **↑** / **↓** or **k** / **j** | Cursor up / down                            |
| **PgUp** / **PgDn** | Cursor by ±15 rows                                    |
| **Home** / **End** | Cursor to the start / end of the list                   |
| **Enter**        | Enter a directory / open an entry (depends on the view)  |
| **Backspace**    | Go up to the parent directory                            |

Each panel's cursor is independent. Tab does not "reset" the cursors — they
remember their positions.

### Add and remove a panel

| Key                                         | Action                  |
|---------------------------------------------|-------------------------|
| **Shift+F3** or `` ` `` `F3`                | Add a panel (≤ 4)       |
| **Shift+F4** or `` ` `` `F4`                | Remove a panel (≥ 2)    |

If the window is too narrow for all panels, the hidden ones are shown as a
"hidden panels: N — widen the window" note in the status line.

### Change the panel root

| Key                                         | Action                                  |
|---------------------------------------------|-----------------------------------------|
| **Shift+F5** or `` ` `` `F5`                | Change the active panel's root (to the next ZFS dataset, cyclic) |

Useful for hopping between datasets quickly without `cd` by hand.

### Synchronize and compare panels

| Key                                         | Action                                            |
|---------------------------------------------|---------------------------------------------------|
| **Shift+F1** or `` ` `` `F1`                | All panels → the active panel's directory         |
| **Shift+F2** or `` ` `` `F2`                | Compare the files and folders in the open panels  |
| **,** (comma)                               | Side-by-side comparison (on/off, see below)       |

## Panel views (cycled with the `v` key)

Each panel chooses for itself **what** it shows. The views cycle with the
`v` / `V` key:

```
Files → DirsOnly → GroupList → GroupFiles → DuplicatesOfCursor → DirGroupList → DirGroupFiles → (Files)
```

| View                 | Header label        | What it shows                                                        | Data source     |
|----------------------|---------------------|----------------------------------------------------------------------|-----------------|
| **Files**            | `files`             | The ordinary navigator: files and subdirectories of the current dir | Real FS         |
| **DirsOnly**         | `directories`       | Subdirectories only (no files)                                       | Real FS         |
| **GroupList**        | `groups`            | The duplicate groups of the whole loaded scan, sorted "by benefit"  | Scan DB         |
| **GroupFiles**       | `group files`       | The files of the group selected in the neighbouring GroupList (watch)| Scan DB         |
| **DuplicatesOfCursor** | `duplicates`      | Duplicates of the file under the cursor of the neighbouring Files panel (watch) | Scan DB |
| **DirGroupList**     | `directory groups`  | The list of groups of twin directories (see below)                  | Scan DB         |
| **DirGroupFiles**    | `group directories` | The directories of the group selected in the neighbouring DirGroupList (watch) | Scan DB |

**When to use which view:**

- **Files + DuplicatesOfCursor** (two neighbouring panels): "I walk through my
  directory and immediately see whether a file has duplicates anywhere else." One
  of the main working scenarios.
- **GroupList + GroupFiles** (two neighbouring): "I scroll groups by descending
  benefit and work through the large ones."
- **Files + Files** (two neighbouring): just a file browser for comparing two places.
- **DirGroupList + DirGroupFiles**: "I found folders with identical content and
  look at their full paths."

### File and directory views: Files / DirsOnly

The ordinary navigator. `Enter` enters a subdirectory; `Backspace` goes up.

The panel header is the path, the view label (`files` / `directories`), and the
sort key.

```text
┌─ /tank · files · name ───────────────────────────────────────────────┐
│ ..                                                                    │
│ media/                                                                │
│ backup/                                                               │
│ old-photos/                                                           │
│ ▸ vm-disks/                                                           │
│ readme.txt                                                            │
│ .dedcom-quarantine/                                                   │
└──────────────────────────────────────────────────────────────────────┘
```

### File-duplicate views: GroupList / GroupFiles

After a scan, a panel can be switched to **GroupList** — showing all the
duplicate groups of the loaded scan:

```text
┌─ /tank · groups (12,437 groups, frees 145 GiB) ───────────────────┐
│ #1 ●●●●●●●  72.4 MiB × 23  /tank/media/photo/2022-08/IMG_4421.HEIC │
│ #2 ●●●●●●   45.0 MiB × 18  /tank/backup/2023/proxmox.tar           │
│ ▸ #5 ●●●●    25.7 MiB × 10  /tank/media/photo/2021-11/IMG_3120.HEIC │
│ #6 ●●●     18.9 MiB × 8   /tank/media/photo/2024-03/IMG_7891.HEIC │
│ ...                                                                  │
└──────────────────────────────────────────────────────────────────────┘
```

- The left column is the benefit (visual dots), then size × file count.
- The name is the path of the most "representative" file of the group.

The neighbouring panel on the right, switched to **GroupFiles**, automatically
shows the files of the selected group:

```text
┌─ Group files #5 (10 of 10) ─────────────────────────────────────────┐
│   /tank/media/photo/2021-11/IMG_3120.HEIC                           │
│ K /tank/media/photo/2021-11/IMG_canon.HEIC                          │
│ H /tank/backup/photo/IMG_3120.HEIC                                   │
│ H /tank/old-copy/IMG_3120.HEIC                                       │
│ ▸ /tank/media/photo/2021-11/dup.HEIC                                 │
│ ...                                                                  │
└──────────────────────────────────────────────────────────────────────┘
```

The glyphs in the first column are marks (K/H/C/D/*), see "Marks" below.

> On very large groups, GroupFiles shows the first **200** files (a visual cap
> against freezes). The header reads `(200 of X)`. This does not affect the bulk
> F11 actions. See [§13](13-troubleshooting.md).

### The "duplicates of the cursor" view: DuplicatesOfCursor

The neighbouring panel on the right, switched to **DuplicatesOfCursor**,
automatically shows the duplicates of the file under the cursor of the left
Files panel:

```text
┌─ /tank/photos · files ──┐  ┌─ Duplicates /tank/photos/IMG_3120.HEIC ────┐
│ ..                       │  │ /tank/backup/IMG_3120.HEIC                  │
│ IMG_3119.HEIC           │  │ /tank/old-copy/IMG_3120.HEIC                │
│ ▸ IMG_3120.HEIC         │→ │ /tank/media/dup.HEIC                        │
│ IMG_3121.HEIC           │  │ (4 copies in total, including the current)  │
└─────────────────────────┘  └──────────────────────────────────────────────┘
```

The cursor moved in the left panel → the right one updated instantly (in the
background, no freeze).

### Directory-twin views: DirGroupList / DirGroupFiles

While scanning, DedupCommando builds **directory signatures** — two directories
with identical signatures have identical content (recursively). Groups of such
"twin directories" are available through the **DirGroupList** view:

```text
┌─ Directory-twin groups (47 groups) ─────────────────────────────────┐
│ #1   45.2 GiB × 3 directories  /tank/backup/2023-archive/           │
│ #2   12.7 GiB × 2 directories  /tank/media/photo/canon-raw/         │
│ ▸ #3  8.9 GiB × 4 directories  /tank/old/projects/                  │
│ ...                                                                  │
└──────────────────────────────────────────────────────────────────────┘
```

The neighbouring **DirGroupFiles** shows the full paths of all the directories
in the selected group:

```text
┌─ Group directories #3 (4) ──────────────────────────────────────────┐
│ /tank/old/projects/                                                  │
│ /tank/archive/2022-projects/                                         │
│ /tank/backup/projects-bak/                                           │
│ /tank/restore-test/projects/                                         │
└──────────────────────────────────────────────────────────────────────┘
```

Which algorithm builds the signatures (default vs `--merkle-dirs`) — see
[§07 Scanning](07-scanning.md).

### The `o` key — a file's directory into the adjacent panel

In the **GroupFiles** and **DuplicatesOfCursor** views, the **`o`** / **`O`**
key opens the directory of the file under the cursor in the adjacent panel on the
right, and the cursor there lands on that file immediately:

```text
cursor on /tank/old-copy/IMG_3120.HEIC in GroupFiles
        │ o ↓
┌─ Group files #5 ──────────┐  ┌─ /tank/old-copy · files ────────────┐
│   /tank/media/IMG_3120.HEIC│  │ ..                                   │
│ K /tank/media/IMG_canon... │  │ ▸ IMG_3120.HEIC                      │
│ H /tank/backup/IMG_3120... │→ │ IMG_3119.HEIC                        │
│ ▸ /tank/old-copy/IMG_3120 │  │ IMG_3121.HEIC                        │
│ ...                        │  │ ...                                  │
└────────────────────────────┘  └──────────────────────────────────────┘
```

If there is no right panel, `o` tries to add one; a narrow terminal or the panel
limit puts the error text into the status line. In other views, `o` is a silent
no-op with the status message "The «o» key works in the «group files» and
«duplicates» modes".

## Watch modes: how panels "follow" one another

The **GroupFiles**, **DuplicatesOfCursor**, and **DirGroupFiles** views are
"watch" modes. Each such panel looks at the cursor of the neighbouring panel on
its left and updates automatically.

| Watch view            | Source in the neighbour on the left      |
|-----------------------|------------------------------------------|
| **GroupFiles**        | GroupList — the selected group           |
| **DuplicatesOfCursor**| Files / DirsOnly — the file under the cursor |
| **DirGroupFiles**     | DirGroupList — the selected group        |

If the neighbour has no suitable source (for example, it is in Files mode on a
directory without duplicates), the watch panel shows "no data".

Watch updates in the background — navigating in the source does not "hang" on a
DB query from the right.

## Sorting entries (`s` / `S`)

The sort keys cycle with the **s** / **S** key in the active panel:

```
name → size → type → date → (name)
```

The panel header shows the current key.

## File marks

A mark lives on the absolute path — moving to another directory does not lose it.

| Mark    | Glyph| Key               | Meaning                                               |
|---------|------|-------------------|-------------------------------------------------------|
| Keeper  | `K`  | **F7**            | The group's keeper file (one per group)               |
| Hardlink| `H`  | **F5**            | Replace with a hardlink to the keeper                 |
| Reflink | `C`  | **F6**            | Replace with a reflink to the keeper (ZFS block_cloning)|
| Delete  | `D`  | **F8**            | Delete (to quarantine)                                |
| Selected| `*`  | **Space** / **Insert** | An ephemeral batch (for the `m` layout)          |

**Space** on an already-marked file removes the mark (by default it sets
`Selected`, but if there was a K/H/C/D it removes it).

**Insert** is the same as Space, for batch marking in the style of classic
two-panel file managers.

The semantics of the actions (what exactly hardlink/reflink/delete do, and why
a hardlink is better than a delete) — see [§08 Actions](08-actions.md).

## F-keys — first layer

This is what is drawn on the footer. With no modifiers:

| F-key     | Action                                                                |
|-----------|-----------------------------------------------------------------------|
| **F1** or **?** | Keyboard help (overlay)                                         |
| **F2**    | Scan the active panel's directory                                     |
| **F3**    | Info about the file under the cursor (the FileInfo overlay)          |
| **F4**    | Compute the hash of the file under the cursor (in the background)    |
| **F5**    | Mark as Hardlink                                                       |
| **F6**    | Mark as Reflink                                                        |
| **F7**    | Mark as Keeper                                                         |
| **F8**    | Mark as Delete                                                         |
| **F9**    | Menu (overlay)                                                         |
| **F10**   | Exit                                                                   |
| **F11**   | Apply the marked actions (the confirmation overlay)                   |
| **F12**   | Sessions and scan results (the ResumeScan overlay + the session list) |

## F-keys — second layer

This is enabled by holding **Shift** when pressing an F-key **OR** by the prefix
key `` ` `` (grave accent) for the one next F press. The footer is highlighted in
yellow when the prefix is armed.

Why two mechanisms: the Proxmox web shell terminal (xterm.js) **does not pass**
Shift+F — the `` ` `` prefix is intended for it.

| Key (Shift+F / `` ` `` `F`) | Footer label | Action                       |
|-----------------------------|--------------|------------------------------|
| **F1**                      | Sync         | Synchronize all panels to the active panel's directory |
| **F2**                      | Compare      | Compare the files and folders between panels           |
| **F3**                      | +Panel       | Add a panel (≤ 4)                                       |
| **F4**                      | -Panel       | Remove a panel (≥ 2)                                    |
| **F5**                      | Root         | Change the active panel's root (across datasets)       |
| **F6**                      | Size         | Recompute the directory size (in the background)       |
| **F7**, **F8**              | —            | Unassigned                                              |
| **F9**                      | Wizard       | Open the scan configuration wizard (ScanConfig)        |
| **F10**, **F11**            | —            | Unassigned                                              |
| **F12**                     | Board        | Triage Board — the screen for laying out across 4 receivers ([§09](09-triage-board.md)) |

The prefix is cleared:
- automatically after any key press;
- by pressing `` ` `` again (toggle);
- by an F-key (the second layer handles it and clears).

## The F9 menu (13 items)

```text
┌─ Menu — F9 ────────────────────────────────────────────────────────────┐
│  1. Scan the active panel's directory                                  │
│  2. Configure and start a scan…                                        │
│  3. Sessions and scan results…                                         │
│  4. Clear all marks of the active panel                                │
│  5. Reload scan data                                                   │
│  6. Change panel mode (v)                                              │
│  7. Synchronize panels (Shift+F1)                                      │
│  8. Compare panels (Shift+F2)                                          │
│  9. Add a panel (Shift+F3)                                             │
│  10. Remove a panel (Shift+F4)                                         │
│  11. Change panel root (Shift+F5)                                      │
│  12. Recompute directory size (Shift+F6)                              │
│  13. Keyboard help                                                     │
│                                                                         │
│  ↑↓ select  Enter apply  Esc cancel                                    │
└────────────────────────────────────────────────────────────────────────┘
```

| Key         | Action                                    |
|-------------|-------------------------------------------|
| **↑** / **↓**| Cursor over the items                    |
| **Enter**   | Apply the selected item                   |
| **Esc** or **F9** | Close the menu without an action    |

Items 6–12 duplicate the hotkeys (for those who do not yet remember them). Item
2 = `Shift+F9`, item 3 = `F12`, item 4 = clear all marks in bulk.

## Overlays

Besides the menu there are three more modal overlays:

### F11 confirmation (Overlay::Confirm)

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

| Key     | Action                                                               |
|---------|----------------------------------------------------------------------|
| **Tab** | Switch the tab: `Summary` ↔ `Commands` (the full shell script)       |
| **S**   | Save the plan as a `.sh` (audit trail; manual execution is possible) |
| **Y** or **Enter** | Execute — start applying                                  |
| **N** / **Esc** | Cancel                                                       |

### F3 file info (Overlay::FileInfo)

```text
┌─ File — F3 · Esc to close ─────────────────────────────────────────────┐
│  Path:    /tank/media/photo/IMG_3120.HEIC                             │
│  Size:    3.6 MiB                                                     │
│  Mtime:   2024-08-15 14:23:11                                         │
│  Device:  0x42 (zfs:tank)                                             │
│  Inode:   12345678                                                    │
│  Hash:    a3f5...  (from the last scan)                               │
│  Duplicates: 4 (including this one)                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

| Key | Action |
|-----|--------|
| **Enter** / **Esc** / **F3** | Close |

### Resume — F2 (Overlay::ResumeScan)

On F2 (scan the active panel), if this root already has an unfinished or
finished session, it asks what to do with it:

```text
┌─ Scan roots — F2 ──────────────────────────────────────────────────────┐
│   Root: /tank                                                          │
│                                                                         │
│   Unfinished scan: 2026-05-20 14:15  (47% by volume, 1.2 TiB)         │
│   Last completed: 2026-04-12 09:23  (12,437 groups)                   │
│                                                                         │
│   [R]/[Enter] resume                                                   │
│   [O] open completed                                                   │
│   [N] new scan                                                         │
│   [Esc] cancel                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

| Key     | Action                                                                |
|---------|-----------------------------------------------------------------------|
| **R**   | Resume the unfinished session (if any)                                |
| **O**   | Open the result of the last completed scan                            |
| **Enter** | Equivalent to R, or O if there is no unfinished session             |
| **N**   | Ignore everything, start a new scan                                   |
| **Esc** | Cancel (return to the commander without a scan)                       |

## Side-by-side comparison (`,`)

The **`,`** (comma) key turns the **CompareMode::SideBySide** mode on/off for
neighbouring panels in the Files/DirsOnly views:

```text
┌─ /tank/photos · files ──┐  ┌─ /tank/photos-bak · files ──┐
│ = IMG_3119.HEIC          │  │ = IMG_3119.HEIC               │
│ ≈ IMG_3120.HEIC          │  │ ≈ IMG_3120.HEIC               │
│ ~ IMG_3121.HEIC          │  │ ~ IMG_3121.HEIC               │
│ + IMG_3122.HEIC          │  │                                │
│                          │  │ + IMG_extra.HEIC               │
└──────────────────────────┘  └────────────────────────────────┘
```

Match glyphs:
- **`=`** — identical (the same hash)
- **`≈`** — similar (close size/date)
- **`~`** — differs
- **`+`** — present only in this panel

Useful for an eyeball comparison of two "versions" of a directory — backup vs
original.

## Triage Board — laying out across 4 receivers

A separate screen for manually distributing files. It opens with **Shift+F12**
(or "start the layout" — the **`m`** key + a digit 1–4). This is **not
deduplication** — it is a "I brought a file here and sorted it into bins" tool.
Details — [§09 Triage Board](09-triage-board.md).

## Other actions

| Key     | Action                                                                 |
|---------|------------------------------------------------------------------------|
| **m** / **M** | Start the layout: select files → a digit 1–4 = the receiver       |
| **u** / **U** | Undo the last layout move (Undo)                                   |
| **q** / **Q** | Exit                                                               |

## What's next

- [§06 Classic wizard](06-classic.md) — the step-by-step equivalent for those who
  find the multi-panel mode unwieldy.
- [§07 Scanning](07-scanning.md) — how to configure a scan that will later fill
  the GroupList/GroupFiles/etc. views.
- [§09 Triage Board](09-triage-board.md) — laying out across 4 receivers.
- [§14 Hotkeys reference](14-hotkeys.md) — a printable table of all keys on a
  single page.
