# 09. Triage Board — sorting into 4 receivers

The Triage Board is a separate screen for **manually sorting** files: "clear
the inbox into 4 bins." This is **not deduplication**: files are moved (`mv`),
not merged. The idea is like sorting mail or a photo archive: you page through
a source directory and, with each press of 1–4, drop a file into one of four
"bins" (these might be "delete", "archive", "process", "keep").

Opened with **Shift+F12**, or `` ` `` `F12` from commando.

## Anatomy of the screen

```text
╔═ SOURCE ═══════════════════════════╗  ╔═ 1 ═══════════════╗  ╔═ 3 ═══════════════╗
║ /tank/inbox                         ║  ║ /tank/photos/2024 ║  ║ /tank/junk-bin    ║
║ ..                                  ║  ║ ..                ║  ║ ..                ║
║ ▸ IMG_3120.HEIC                     ║  ║ IMG_0001.HEIC     ║  ║ old-test.log      ║
║   IMG_3121.HEIC                     ║  ║ IMG_0002.HEIC     ║  ║                   ║
║   notes-draft.txt                   ║  ║ ...               ║  ║                   ║
║   video.mp4                         ║  ╚═══════════════════╝  ╚═══════════════════╝
║ * trash-me.bin                      ║  ╔═ 2 ═══════════════╗  ╔═ 4 ═══════════════╗
║ ...                                 ║  ║ /tank/archive     ║  ║ /tank/processing  ║
║                                     ║  ║ ..                ║  ║ ..                ║
║                                     ║  ║ ...               ║  ║ batch-001/        ║
║                                     ║  ║                   ║  ║                   ║
╚═════════════════════════════════════╝  ╚═══════════════════╝  ╚═══════════════════╝
 Triage Board
 Tab/←→ panel · ↑↓ file · Enter enter · Insert batch · 1-4 send · a+N receiver · S save · u undo · Esc exit
```

Five panels:

- **SOURCE** (center) — the directory being sorted.
- **1, 2, 3, 4** (corners) — the four receivers. Each has its own path.

Focus (the highlighted frame) moves between all five panels with Tab or
←/→. The number keys 1–4 **send the focused file/batch to receiver N**.

The Board's state (which directories are assigned to the receivers, where the
cursor is) is preserved between sessions (see "Saving the layout" below).

## Full Board key table

| Key                    | Action                                                                |
|------------------------|-----------------------------------------------------------------------|
| **Tab** or **→**       | Focus the next panel (Source → 1 → 2 → 3 → 4 → Source)                |
| **Shift+Tab** or **←** | Focus the previous panel                                              |
| **↑** / **↓** or **k** / **j** | Move the cursor in the active panel                          |
| **PgUp** / **PgDn**    | Move the cursor by ±15                                                 |
| **Home** / **End**     | Cursor to the start / end of the list                                 |
| **Enter**              | Enter the subdirectory under the cursor                               |
| **Backspace**          | Go up to the parent directory                                         |
| **Insert**             | Mark the file under the cursor into a batch (`*`); the next 1–4 sends the batch |
| **1** / **2** / **3** / **4** | Send the file (or the Insert batch) from focus to receiver N  |
| **a** / **A** + digit  | Make the current directory of the focused panel the directory of receiver N |
| **S**                  | Save the Board layout (receiver directories) to `board.json`         |
| **u** / **U**          | Undo the last move                                                    |
| **Esc**                | Exit the Board, return to commando                                   |
| **Shift+F12** or `` ` `` `F12` | The same exit (the combination that opens the Board)         |
| **q** / **Q**          | Save the layout and quit the application                              |

## A typical scenario

### 1. Assign the desired directories to the receivers

You open the Board; by default all four receivers are empty. To assign a
receiver:

1. **Tab** — focus receiver 1.
2. **Backspace** / **Enter** — navigate to the directory you want (for example, `/tank/archive`).
3. **a** + **1** — "the focused panel's current directory = receiver 1".
4. Repeat for 2, 3, 4 (or fewer, if you don't need all of them).

### 2. Switch to the source and start sorting

1. **Tab** until focus is on "Source".
2. **Backspace** / **Enter** — open the source directory you want (for example, `/tank/inbox`).
3. With the cursor on a file → press **1**, **2**, **3**, or **4** — the file
   moves to the corresponding receiver.

The file is moved **in the background** (a separate thread). The status line
shows the number of moves queued. You can keep sorting the next files without
waiting for the current one to finish.

### 3. Batch move (Insert batch)

If you need to send several files to one receiver:

1. On each file — press **Insert** (a `*` appears at the start of the line).
2. When the batch is assembled — press **1**, **2**, **3**, or **4** once.
3. The whole batch moves to the receiver.

### 4. Saving the layout

**S**, or exiting via **q/Esc**, writes the layout to
`~/.local/state/dedcom/board.json`: the paths of the four receivers and the
source cursor. The next time you open the Board, the same receivers are in the
same places.

## Undo (`u`)

**u** / **U** in the Board reverses the last move (and the Insert batch): the
files are returned to their original paths. The `move_log` journal records each
operation separately — you can press `u` several times in a row to undo
several of the most recent steps.

## Cross-device — does not work

Moving between different ZFS datasets is impossible (refused; see [§08 Cross-device](08-actions.md#87-cross-device--refusal)).

This means: **the receivers must be in the same dataset as the source**. To
move a file from `/tank` to `/rpool`, use `rsync` by hand, as the `dedcom`
error advises.

## Inline triage in commando — without opening the Board

In ordinary commando mode there is a **shorthand** triage operation that does
not require opening the Board:

```text
In commando (any Files panel):
  1. Cursor on a file → press m (or M)
  2. Cursor on a receiver directory in ANOTHER panel → press 1, 2, 3, or 4
     (this simply marks which panel to use as the receiver)

  The file is moved in the background.
```

Use this when you need to quickly move one or two files from the current panel
to another panel — without the full-screen Board. Under the hood it is the
same `move_to`/`evacuate_then_publish`, the same `move_log`, the same `u`
(Undo).

Inline triage and the Board are compatible: both write to a single `move_log`,
and Undo works for both.

## When to use the Board, when inline triage?

| Scenario                                                             | What to use              |
|----------------------------------------------------------------------|--------------------------|
| Sort a large inbox (tens to hundreds of files)                       | **Board** — all four bins in view |
| Move one or two files "in passing" within commando                   | **Inline triage (m + 1-4)** — no screen switch |
| Regular sorting (the same distribution every time)                   | **Board** — the receivers are remembered      |

## Why this exists at all

The Triage Board is a separate module, **not part of the deduplication
pipeline**. It is in DedupCommando for two reasons:

1. **"Dedup is not enough."** Often, alongside identical files, there is simply
   junk / archive / "sort later" — which is a move, not a merge. Without
   triage you would have to leave dedcom and run `mv` by hand.

2. **Preparation for dedup.** If you sort files into the right directories
   *before* a scan, the future duplicate groups will be more compact (for
   example, move all 2024 photos into `/tank/photos/2024` in a single step →
   the next scan finds the copies in one folder).

## What's next

- [§05 Commando](05-commando.md) — managing panels in the ordinary mode.
- [§08 Actions](08-actions.md) — what distinguishes dedup from a move.
- [§13 Troubleshooting](13-troubleshooting.md) — if a move does not work.
