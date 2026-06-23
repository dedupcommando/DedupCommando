# 14. Hotkeys reference

Every key on a single page — for printing and keeping next to your keyboard.
Grouped by screen. Details for each group are in the corresponding chapter of
the manual.

## Global (any TUI screen)

| Key               | Action                                                  |
|-------------------|---------------------------------------------------------|
| **q** / **Q**     | Quit the application                                    |
| **F10**           | Exit (Commando, Summary, etc.)                          |
| **F1** or **?**   | Help (overlay) — wherever help exists                   |
| **Esc**           | Close the current overlay / cancel / back to the previous screen |

## Startup overlays

### Notice (first launch)

The overlay title is ` Notice `; it holds two checkboxes — `I have read and
agree (required)` and `Don't show this at startup again`.

| Key         | Action                                                      |
|-------------|-------------------------------------------------------------|
| **Space**   | Check / uncheck the focused checkbox                        |
| **Tab**     | Switch focus between the two checkboxes                     |
| **Enter**   | Continue (only when the "agree" box is checked)             |
| **Esc**     | Exit without saving consent                                 |

### Concurrent launch (when another `dedcom` holds the lock)

Overlay title ` Concurrent launch `.

| Key         | Action                                                      |
|-------------|-------------------------------------------------------------|
| **R**       | Open read-only (observer)                                   |
| **F**       | Become operator (take the lock — **dangerous**)            |
| **Esc**     | Exit                                                        |

## Commando — the default mode

### First F-key layer (as drawn in the footer)

| Key     | Label   | Action                                            |
|---------|---------|---------------------------------------------------|
| **F1**  | Help    | Help (or **?**)                                   |
| **F2**  | Scan    | Scan the active panel's directory                 |
| **F3**  | File    | Information about the file under the cursor (FileInfo) |
| **F4**  | Hash    | Compute the hash of the file under the cursor (in the background) |
| **F5**  | Hard    | Mark Hardlink                                     |
| **F6**  | Ref     | Mark Reflink                                      |
| **F7**  | Keep    | Mark Keeper                                       |
| **F8**  | Del     | Mark Delete                                       |
| **F9**  | Menu    | Menu (overlay with 13 items)                      |
| **F10** | Exit    | Exit                                              |
| **F11** | Exec    | Apply the marked actions (Confirm overlay)        |
| **F12** | Sessions| Sessions list and scan results (wizard Resume)    |

### Second F-key layer (`Shift+F<N>` or `` ` `` then `F<N>`)

| Key      | Label    | Action                                                    |
|----------|----------|-----------------------------------------------------------|
| **F1**   | Sync     | All panels to the active panel's directory                |
| **F2**   | Compare  | Compare files and folders across the open panels          |
| **F3**   | +Panel   | Add a panel (≤ 4)                                         |
| **F4**   | -Panel   | Remove a panel (≥ 2)                                      |
| **F5**   | Root     | Change the active panel's root (to the next dataset)      |
| **F6**   | Size     | Recompute directory size (in the background)              |
| **F9**   | Wizard   | Open the ScanConfig wizard                                 |
| **F12**  | Board    | Triage Board (layout across 4 receivers)                  |
| F7, F8, F10, F11 | — | Unassigned                                          |

Activating the second layer:
- `Shift+F<N>` directly (if the terminal transmits it).
- `` ` `` (backtick) — arms layer 2 for the single next F key press
  (for Proxmox's xterm.js).

### Letters and symbols in Commando

| Key          | Action                                                          |
|--------------|-----------------------------------------------------------------|
| **s** / **S**| Cycle the sort (name → size → type → date → name)              |
| **v** / **V**| Cycle the panel view (files → directories → groups → group files → duplicates → directory groups → group directories → files) |
| **,**        | Side-by-side compare (on / off)                                 |
| **m** / **M**| Inline triage: begin the layout — the next digit 1–4 = receiver |
| **u** / **U**| Undo the last move (Undo)                                       |
| **Insert**   | Add the file to the Select batch                                |
| **Space**    | Set / clear Selected (or clear K/H/C/D)                         |
| **o** / **O**| Directory of the file under the cursor → into the adjacent right panel (in the group-files and duplicates views) |
| **q** / **Q**| Exit                                                            |
| **?**        | Help (synonym for F1)                                            |

### Navigation in Commando

| Key                      | Action                                  |
|--------------------------|-----------------------------------------|
| **Tab**                  | Focus the next panel                    |
| **Shift+Tab**            | Focus the previous panel                |
| **←** / **→**            | Focus the previous / next panel         |
| **↑** / **↓** or **k** / **j** | Cursor up / down                  |
| **PgUp** / **PgDn**      | Cursor by ±15                           |
| **Home** / **End**       | Cursor to the start / end of the list   |
| **Enter**                | Enter the directory / open the entry    |
| **Backspace**            | Go up to the parent directory           |

### Overlays in Commando

#### Menu (F9)

Overlay title ` Menu — F9 `. The 13 items: 1 `Scan the active panel's
directory` · 2 `Configure and start a scan…` · 3 `Sessions and scan results…` ·
4 `Clear all marks of the active panel` · 5 `Reload scan data` · 6 `Change
panel mode (v)` · 7 `Synchronize panels (Shift+F1)` · 8 `Compare panels
(Shift+F2)` · 9 `Add a panel (Shift+F3)` · 10 `Remove a panel (Shift+F4)` ·
11 `Change panel root (Shift+F5)` · 12 `Recompute directory size (Shift+F6)` ·
13 `Keyboard help`.

| Key          | Action                            |
|--------------|-----------------------------------|
| **↑** / **↓**| Move the cursor through the items |
| **Enter**    | Apply the selected item           |
| **Esc** or **F9** | Close                        |

#### Confirm (F11)

Overlay title ` Confirmation — F11 `; tabs `Summary` / `Commands`. Footer hint:
`[Tab] tab  [S] save .sh  [Y] execute  [N]/[Esc] cancel`.

| Key          | Action                                                    |
|--------------|-----------------------------------------------------------|
| **Tab**      | Switch the tab (Summary ↔ Commands)                      |
| **S**        | Save the plan as `.sh`                                    |
| **Y** or **Enter** | Execute                                            |
| **N** / **Esc** | Cancel                                                |

#### FileInfo (F3)

Overlay title ` File — F3 · Esc to close `.

| Key          | Action                            |
|--------------|-----------------------------------|
| **Enter** / **Esc** / **F3** | Close                |

#### ResumeScan (F2 when a session exists)

Overlay title ` Scan roots — F2 `. Options: `[R]/[Enter] resume` ·
`[O] open completed` · `[N] new scan` · `[Esc] cancel`.

| Key          | Action                                                |
|--------------|-------------------------------------------------------|
| **R**        | Resume the unfinished session                         |
| **O**        | Open the result of a completed session                |
| **Enter**    | R, otherwise O                                       |
| **N**        | New scan (ignore the sessions)                        |
| **Esc**      | Cancel                                                |

## Triage Board (Shift+F12 from Commando)

The bottom legend uses the labels SOURCE (center) and 1–4 (the four receivers).

| Key                    | Action                                                      |
|------------------------|-------------------------------------------------------------|
| **Tab** or **→**       | Focus the next panel (5 panels)                            |
| **Shift+Tab** or **←** | Focus the previous panel                                    |
| **↑** / **↓** or **k** / **j** | Cursor in the active panel                         |
| **PgUp** / **PgDn**    | Cursor by ±15                                               |
| **Home** / **End**     | Cursor to the start / end                                   |
| **Enter**              | Enter the subdirectory                                      |
| **Backspace**          | Go up to the parent                                         |
| **Insert**             | Mark the file into the batch                                |
| **1** / **2** / **3** / **4** | Send the file (or the batch) to receiver N          |
| **a** / **A** + **N**  | Assign the current directory to receiver N                  |
| **S**                  | Save the Board layout (`board.json`)                        |
| **u** / **U**          | Undo the last move                                          |
| **Esc** or **Shift+F12** or `` ` `` then `F12` | Exit back to Commando           |
| **q** / **Q**          | Save the layout and quit the application                    |

## Classic wizard

### ScanConfig

Footer: `↑↓ · Space · F folder · P preset · C cache · G intensity · Del remove
· S start · Q quit`.

| Key          | Action                                                         |
|--------------|----------------------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Move the cursor through the roots             |
| **Space**    | Select / deselect a root                                       |
| **F**        | Add an arbitrary folder → FolderPicker                        |
| **P**        | Cycle the extension-filter preset                              |
| **C**        | Enable / disable the hash cache                                |
| **G**        | Intensity profile (Turbo → Balanced → Idle → Turbo)            |
| **Delete**   | Remove an arbitrarily added folder                             |
| **S**        | Start the scan                                                 |
| **q** / **Q**| Exit                                                           |

### FolderPicker

Footer: `↑↓ select · Enter enter · Backspace up · A select this directory ·
Esc cancel`.

| Key                    | Action                                                  |
|------------------------|---------------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Cursor                                          |
| **Enter**              | Enter the subdirectory                                  |
| **Backspace** or **←** | Parent directory                                        |
| **A**                  | Add the CURRENT directory as a root → ScanConfig        |
| **Esc**                | Back to ScanConfig without adding                       |
| **q** / **Q**          | Exit                                                    |

### Resume

Footer: `↑↓ · R/Enter open · Del to trash · t trash · N new · Q quit`.

| Key                    | Action                                                  |
|------------------------|---------------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Move the cursor through the sessions            |
| **R** / **Enter**      | Resume the unfinished / open the completed session      |
| **N**                  | New scan → ScanConfig                                   |
| **D**                  | Compare the session with the next older one → ScanDiff  |
| **T**                  | Open the session trash → Trash                          |
| **Delete**             | Move the session to the trash (soft)                    |
| **q** / **Q**          | Exit                                                    |

### Scanning

Cancel hint: `[Esc] stop — progress is saved, you can resume later`.

| Key          | Action                                                     |
|--------------|------------------------------------------------------------|
| **Esc**      | Cancel the scan (progress is saved to the DB for resume)   |
| **q** / **Q**| Quit the application                                       |

### Browser (viewing groups and marking)

Tabs `[1] Folders` / `[2] Files`. Footer: `1=Folders 2=Files · Tab ·
↑↓/PgUp·PgDn/g·G · LMB·wheel · Enter=keeper · d/h/c=mark · Space=unmark ·
a=auto · v=view · r=review · ?=help`.

| Key                    | Action                                                  |
|------------------------|---------------------------------------------------------|
| **1** / **2**          | Switch the tab (Folders / Files)                        |
| **Tab**                | Switch focus (groups ↔ files)                          |
| **↑** / **↓** or **k** / **j** | Cursor                                          |
| **PgUp** / **PgDn**    | Cursor by a page                                        |
| **g** / **G**          | Cursor to the start / end                               |
| **Enter**              | (on a file) Assign keeper                               |
| **d** / **D**          | Mark Delete                                             |
| **h** / **H**          | Mark Hardlink                                           |
| **c** / **C**          | Mark Reflink                                            |
| **Space**              | Unmark                                                  |
| **a** / **A**          | Auto-select across all groups                           |
| **r** / **R**          | Action review → ActionReview                            |
| **v** / **V**          | Path display style                                      |
| **Esc**                | Back to ScanConfig                                      |
| **q** / **Q**          | Exit                                                    |

The Browser row glyphs (left of each file): `★ ` keeper · `= ` already
linked · `x ` delete · `h ` hardlink · `c ` reflink; a marked row gets the
suffix `-> DELETE` / `-> HARDLINK` / `-> REFLINK`.

### ActionReview

Footer: ` [Y] execute · [Esc] back to review `.

| Key          | Action                                                     |
|--------------|------------------------------------------------------------|
| **↑** / **↓**| Scroll                                                     |
| **Y**        | Go to the final confirmation (modal)                       |
| **Esc**      | Back to Browser                                            |
| **q** / **Q**| Exit                                                       |

Final confirmation (modal, title ` Confirmation `, body `Execute {count}
operations?`):

| Key          | Action                                                     |
|--------------|------------------------------------------------------------|
| **Y**        | Start apply                                                |
| **N** / **Esc** | Stay in ActionReview                                    |

### Applying

Cancel hint: `[Esc] stop after the current action — the snapshot is done,
applied items are in quarantine`.

| Key          | Action                                                     |
|--------------|------------------------------------------------------------|
| **Esc**      | Cancel after the current action (what is done is in quarantine) |

(`q` does not work — you must not abandon the process in the middle of a
destructive operation.)

### Summary

Footer: `[Esc] to configuration · [Q] quit`.

| Key          | Action                                                     |
|--------------|------------------------------------------------------------|
| **Esc** or **Enter** | Back to ScanConfig                                 |
| **q** / **Q**| Exit                                                       |

### ScanDiff

Footer: `↑↓ select · Tab/Shift+Tab category · Esc/F10 back`. Categories
(cycled with Tab): `New duplicates` · `Moved (inode)` · `Moved (hash)` ·
`Modified` · `Deleted` · `New`.

| Key                    | Action                                                  |
|------------------------|---------------------------------------------------------|
| **Tab**                | Next category                                           |
| **Shift+Tab**          | Previous category                                       |
| **↑** / **↓** or **k** / **j** | Cursor within the category                      |
| **Esc** or **q** / **Q** or **F10** | Back to Resume                            |

### Trash

Footer: `↑↓ select · R restore · Del purge permanently · Esc back`.

| Key                    | Action                                                  |
|------------------------|---------------------------------------------------------|
| **↑** / **↓** or **k** / **j** | Cursor                                          |
| **R** / **Enter**      | Restore the session                                     |
| **Delete**             | Purge permanently (modal Y/N)                           |
| **Esc** or **q** / **Q** | Back to Resume                                        |

"Purge permanently" modal (title ` Purge from trash? `):

| Key          | Action          |
|--------------|------------------|
| **Y** / **Enter** | Run the purge |
| **N** / **Esc**   | Cancel          |

## Mark glyphs (in the files panel)

| Glyph | Meaning                              |
|-------|--------------------------------------|
| `K`   | Keeper (the file to keep)            |
| `H`   | Hardlink to the keeper               |
| `C`   | Reflink to the keeper                |
| `D`   | Delete (move to quarantine)          |
| `*`   | Selected (batch for the layout)      |

## Side-by-side comparison glyphs

These appear in front of each file when side-by-side compare is on (the `,`
key in Commando).

| Glyph | Meaning                              |
|-------|--------------------------------------|
| `=`   | Identical file (same hash)           |
| `≈`   | Similar (close in size / date)       |
| `~`   | Differs                              |
| `+`   | Present only in this panel           |

## "5 keys a day" cheat sheet

| Key     | What it does                                                    |
|---------|-----------------------------------------------------------------|
| **F9**  | Menu — the entry point to everything                            |
| **F11** | Apply the marked actions (with confirmation)                    |
| **F12** | Sessions and scan results                                       |
| **F1** or **?** | Help                                                    |
| **Esc** | Back / cancel / leave the overlay                               |

## Printable card (one command)

To print just this chapter:

```text
# from the host that holds the manual source
cat docs/manual/14-hotkeys.md | pandoc -o hotkeys.pdf
```

Or open it in a browser and press `Ctrl+P` → "Save as PDF".

## What's next

- [§01 Introduction](01-intro.md) — if you haven't read it yet.
- [§13 Troubleshooting](13-troubleshooting.md) — if a key doesn't work the way
  you expect.
- [Full manual README](README.md) — table of contents for all chapters.
