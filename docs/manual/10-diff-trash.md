# 10. ScanDiff and the session trash

Two helper features, both reached from the Resume screen (see
[§06 Resume](06-classic.md)).

## 10.1. ScanDiff — comparing two scans

Analyzes what changed between two scans of the same root. Open it with **D**
from Resume: it compares the **selected** session (the newer one) against the
**next** entry in the list (the older one).

```text
┌─ Scan comparison ──────────────────────────────────────────────────────┐
│ Scans #142 ↔ #141 · root /tank                                          │
│                                                                         │
│ Unchanged: 1234567 · Moved: inode 87 / hash 12                          │
│ Modified: 145 · Deleted: 67 · New: 312                                  │
│ New duplicates (a duplicate arrived): 234                               │
├─────────────────────────────────────────────────────────────────────────┤
│ ▸ New duplicates (234) — Tab next category                              │
│                                                                         │
│ ▶ /tank/photos/2024/IMG_0010.HEIC  ← dup: /tank/backup/IMG_0010.HEIC   │
│   /tank/photos/2024/IMG_0011.HEIC  ← dup: /tank/backup/IMG_0011.HEIC   │
│   ...                                                                   │
├─────────────────────────────────────────────────────────────────────────┤
│ ↑↓ select · Tab/Shift+Tab category · Esc/F10 back                       │
└─────────────────────────────────────────────────────────────────────────┘
```

### The six categories (cycled with Tab)

| Category              | What it means                                                        |
|-----------------------|----------------------------------------------------------------------|
| **New duplicates**    | Files that became duplicates in the new scan (they gained a match)   |
| **Moved (inode)**     | A file relocated — detected by a matching inode (within one dataset) |
| **Moved (hash)**      | A file relocated — detected by a matching hash (across datasets)     |
| **Modified**          | Same path, different hash (the content changed)                      |
| **Deleted**           | The path was present in the old scan, absent in the new one          |
| **New**               | The path appeared in the new scan, was not in the old one            |

"Unchanged" is only a counter in the header; it is never listed (it could be
millions of lines).

### ScanDiff keys

| Key                    | Action                                                                |
|------------------------|-----------------------------------------------------------------------|
| **Tab**                | Next category                                                          |
| **Shift+Tab**          | Previous category                                                     |
| **↑** / **↓** or **k** / **j** | Move the cursor through the category's entries               |
| **Esc** or **q** or **F10**    | Return to Resume                                             |

### Where this is useful

- **Watching a regular scan.** Run `dedcom --scan /tank` once a week and look at
  the diff: what is new, what moved. If **Modified** is unexpectedly large,
  something is changing files — possibly unintentionally.
- **A verify safety net after apply.** After applying deduplication you can run
  a fresh scan and diff it: **Deleted** = everything you removed or turned into a
  hardlink; **Unchanged** = the rest; if anything shows up under **Modified**,
  that is a red flag.
- **Moves as cleanup information.** If files were relocated en masse (the 2024
  photos moved from `/tank/inbox` into `/tank/photos/2024`), the **Moved (inode)**
  category shows it — you can confirm that hardlink groups were not broken.

Detection:
- **Moved (inode)** — an exact match (`device`+`inode` preserved) = an `mv`
  within the dataset. Independent of the hash.
- **Moved (hash)** — a different `inode` (for example, `cp -a`) but a matching
  `blake3` = the same content in another place. Less reliable than the inode
  match, but it catches copies.
- **New duplicates** — the file was already in the old scan as a single copy
  (not a "duplicate"), and in the new scan it gained at least one peer with the
  same hash (now a "duplicate"). A hint that more duplicate content was added.

## 10.2. Session trash — `Trash`

This is **not** the file quarantine (`.dedcom-quarantine` is about physical
files — see [§03 Data Safety](03-safety.md)). The **session trash** is a soft
delete of **scan records** in `dedcom.db`.

Open it with **T** from Resume. On large pools, deleting a session means
deleting millions of rows from `file` — it takes minutes, so it is implemented
as a two-step flow:

```text
Resume — list of active sessions
   │
   │ Del on a session → ConfirmAction::TrashScan(id)
   │
   ▼ modal dialog: "Y confirm · N/Esc cancel"
   │
   ▼ Y → fast UPDATE: trashed=1 (instant)
   │
   │ T from Resume → open the trash
   │
   ▼ Trash — list of "deleted" sessions
       │
       ▼ R/Enter — restore (instant: trashed=0)
       │
       ▼ Del + Y → ConfirmAction::PurgeScan(id)
                    heavy DELETE in the background; final removal
```

### The Trash screen

```text
┌─ Trash — deleted scans ────────────────────────────────────────────────┐
│ ▸ #138  /tank/media      2026-02-01  (deleted 2026-04-10 13:42)        │
│   #135  /rpool           2026-01-15  (deleted 2026-03-22 09:15)        │
│   #130  /tank            2025-12-08  (deleted 2026-02-14 11:00)        │
├─────────────────────────────────────────────────────────────────────────┤
│ R/Enter restore · Del purge permanently · Esc back                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Trash keys

| Key                    | Action                                                                |
|------------------------|-----------------------------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Move the cursor through the sessions                         |
| **R** / **Enter**      | Restore the selected session (it returns to the active list)          |
| **Del**                | Purge permanently (modal Y/N)                                         |
| **Esc** or **q** / **Q** | Return to Resume                                                    |

### The purge confirmation

```text
┌─ Purge from trash? ─────────────────────────────────────────────────────┐
│  The session will be deleted PERMANENTLY — this is irreversible.        │
│                                                                          │
│  The related rows in the DB (file, file_mark, file_group) number in the │
│  millions. The deletion runs in the background; the UI is not blocked.  │
│                                                                          │
│  [Y] yes    ·    [N] no                                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

The matching modal when you first send a session to the trash from Resume is
titled ` Move to trash? ` with the body
`The session will be moved to the trash — it can be restored (t).`

After **Y**, the status reads "Purging from trash in the background…" and work
continues.

### What "purge permanently" does NOT do

- **It does not touch real files.** This deletes the scan's **records**: the
  file manifest, the marks, the groups. ZFS snapshots (`@dedcom-<ts>`) and the
  file quarantine (`.dedcom-quarantine/<ts>/`) stay in place — clearing them is
  separate (`zfs destroy`, `dedcom --purge-quarantine`; see
  [§03 Data Safety](03-safety.md)).
- **It does not free space immediately.** SQLite does not return space to the
  `dedcom.db` file after a `DELETE`; that requires a `VACUUM`
  (`dedcom --compact-db`; see [§12 Maintenance](12-maintenance.md)).

### When to use the session trash

- Dozens of old scans have piled up and the DB has bloated. Delete the old ones,
  keep the recent ones, then run `--compact-db`.
- You ran a test scan against the wrong root — delete it so it does not clutter
  Resume.
- You compared two scans (ScanDiff) and confirmed the older session is no longer
  needed — delete it.

### Retention (automatic cleanup)

If retention is configured in `config.json`, `dedcom` may offer at startup to
move old sessions to the trash. Retention is off by default; it is configured in
code/config and is not yet surfaced in the UI.

## What's next

- [§11 Headless](11-headless.md) — `--stats` for per-session statistics,
  `--compact-db` for VACUUM.
- [§12 Maintenance](12-maintenance.md) — the structure of `dedcom.db`, its size,
  and cleanup.
