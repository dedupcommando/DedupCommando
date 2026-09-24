# 11. Headless — CLI for scripts and cron

Five flags run `dedcom` without the TUI:

| Flag                          | What it does                                            |
|-------------------------------|---------------------------------------------------------|
| `--scan <PATH>`               | Scans a root and prints the result                      |
| `--stats`                     | Prints statistics for all scans and DB state            |
| `--compact-db`                | Empties the session trash and compacts the DB (VACUUM)  |
| `--export-csv <PATH>`         | Exports the newest active session's published groups to CSV (refuses if it has not finished) |
| `--purge-quarantine`          | Deletes the `.dedcom-quarantine` directories in all datasets |

All of them **exit immediately** once done (there is no interactive UI). If
another `dedcom` is already working on this state directory, the headless mode
**does not prompt** — it exits with an error right away (there is no way to
answer interactively).

A run does **one** of them: two different modes in one run are refused before
anything starts (exit code 2) — run them one after another. `--scan` may still
be given several times, one root each. Without any of the five `dedcom` opens
the interface.

## Common: state directory, lock, exit codes

All headless modes:

- Read/write `~/.local/state/dedcom/` (or the directory from `--state-dir`).
- Take the single-instance lock (for the writing modes: `--scan`,
  `--compact-db`, `--purge-quarantine`). If it is held, they **do not ask for
  permission** — they print an error and exit non-zero.
- Return **0** on success, **non-zero** on error (typical: held lock,
  unavailable DB, ZFS that dropped out).

`--stats` and `--export-csv` are read-only — no lock needed.

Exit codes:

- **0** — success, or `--help` / `--version`, or `--purge-quarantine` without
  `--yes` (size reported, nothing deleted).
- **1** — runtime error, including a `--scan` root that does not exist or cannot
  be read. Printed as `dedcom: error: {message}` on stderr.
- **2** — argument-parsing error: an unknown flag, a missing or wrong value, two
  different modes in one run, `--export-csv` given twice, two flags that undo
  each other (`--classic` with `--commando`, `--read-only` with `--force`), or a
  flag the run would ignore — for example `--include-ext` without `--scan`,
  `--yes` without `--purge-quarantine`, `--strict-verify` with a headless mode,
  `--verify` beside `--read-only` in an interface (the table at the end of this
  chapter says which run reads which flag).
  Printed as `dedcom: {message}` followed by `Run with --help for usage.` on
  stderr.

## 11.1. `--scan <PATH>` — scanning without the UI

```text
dedcom --scan /tank
dedcom --scan /tank --scan /home              # several roots
dedcom --scan /tank --include-ext jpg,heic    # extension filter
dedcom --scan /tank --merkle-dirs             # memory-friendly directory signatures
dedcom --scan /tank --no-hash-reuse           # ignore the hash cache
dedcom --scan /tank --no-resume               # start fresh, no resume
dedcom --scan /tank --verify                  # byte-by-byte comparison after hashing
```

A root whose path is not valid UTF-8 is refused before the scan starts (exit
code 2). dedcom leaves out every file whose path is not UTF-8, so nothing under
such a path could be scanned: rename what is not UTF-8 in it, or scan a
directory above that part — its files are then counted under `Omissions:`
(below).

A root that does not exist or cannot be read — a typo, a mount point that is
gone — is refused with exit code 1 before the lock or the database is touched.
It never becomes an empty "finished" scan that retention would count against the
good scans of that root ([§10](10-diff-trash.md)).

An empty directory is still a root like any other — and that includes the mount
point a dataset that is not mounted usually leaves behind. Such a scan finds
nothing and finishes, but it does not send away the scans that still hold the
files: when a root turns up empty where an earlier scan of the same roots found
files, every scan holding files under it stays out of the trash, and the output
says so:

```text
History kept: no files found under /tank, where an earlier scan of the same roots found some — the scans that hold them stay out of the trash. Check that its dataset is mounted (zfs get mounted); if it is empty on purpose, move those scans to the trash yourself.
```

With an extension filter the line names the filter first: a filter that matches
nothing under a root looks the same. The rest of the history is trimmed as usual,
so a root that stays empty for good holds on to those scans only — nothing
retires them but files under that root again, or you (the trash, [§10](10-diff-trash.md)).
The empty scan itself holds nothing and takes no place in `history_keep`
([§12](12-maintenance.md)): the next trim moves it to the trash. The interface
shows the same beside the result, first on the status line:
`⚠ no files under /tank: the older scans that hold some were kept`.

In cron, still guard the line with `mountpoint -q` on the mount point of the
dataset the root lives on — the night is then skipped instead of leaving an
empty scan in the list. That is `/tank` for `/tank` itself and for a plain
directory under it (the last example below does). A plain directory is never a
mount point: guarded by its own path, the line never runs. The guard checks that
one dataset. A dataset below the root that failed to mount is not noticed at
all: the scan found files in the rest of the root, so it trims the history as
usual.

The output is line-by-line text for logging:

```text
[phase] Walking
[walk] entries: 8421, files: 5230
[walk] entries: 16842, files: 10460
...
[phase] Hashing
[hash] 1/5230 files, 2097152/53687091200 bytes
[hash] 2/5230 files, ...
...
[phase] Grouping
RSS probe: build_dir_groups before=…  free=… peak estimate=…

=== Done ===
Files scanned:        5230
Failed to hash:       0
Duplicate groups:     24
Already linked sets:  3
Reclaim:              guaranteed after quarantine purge: 1.1 GiB
Scan time:            23m45s (speed 87.0 MiB/s)
Omissions:            3919 files, 0 walk errors, 0 unsupported entries
  #0    5 files x 104857600 bytes
        /tank/media/photo/IMG_canonical.HEIC
        /tank/backup/IMG_canonical.HEIC
        ...
  #1    3 files x 52428800 bytes
        ...
```

> The first 50 groups are printed with their members; the rest are a count
> only (`... and N more groups`). For a full dump, use `--export-csv`.
>
> `Omissions:` is what the walk left out: files outside the size limits or the
> extension filter, names that are not UTF-8, and files whose metadata could not
> be read; then walk errors (one may stand for a whole unreadable subtree) and
> entries that are neither files nor directories (symbolic links, FIFOs, sockets,
> devices).

### Resume in headless

On a repeated run of `--scan <the same roots>` without the `--no-resume` flag:

```text
$ dedcom --scan /tank
Resuming unfinished scan #142 from 2026-05-20 14:15:00 (12345 / 23456 files already hashed)
Settings kept from its start: extensions all; hash cache on; directory signatures default; profile Idle
[phase] Hashing
...
```

- Only a scan with **exactly the same roots** as in `--scan` is resumed (the
  record in the DB).
- Completed scans are not resumed (no need).
- `--no-resume` → start a new scan, ignoring the checkpoint.
- A resume keeps the settings its scan was started with — the extension
  filter, the hash cache, the directory signatures, the profile — and prints
  them. A flag that asks for something else (`--include-ext` with another list,
  `--no-hash-reuse`, `--merkle-dirs`) is refused rather than ignored: run
  without it to resume, or add `--no-resume` to start a new scan with it.
  `--verify` applies to a resume as well.

### Applying actions from headless? — no

`--scan` **does not apply** actions (delete/hardlink/reflink) — it only scans.
Applying is possible only from the TUI (`F11`) or from a ScanScript saved via
the `S` button in the `F11` overlay (see [§05](05-commando.md#f11-confirmation-overlayconfirm)).

This is deliberate: applying requires visual confirmation of keepers and marks,
which cannot be done safely in headless mode. See the limitations in
[Safety, Recovery, and Limitations](../SAFETY.md).

### Cron example: a nightly scan of /tank

The simplest form:

```cron
# /etc/cron.d/dedcom — every night at 02:00
0 2 * * * root /usr/local/bin/dedcom --scan /tank >> /var/log/dedcom-scan.log 2>&1
```

Better with protection against overlapping a previous run (the single-instance
lock already does this, but `flock` gives an explicit exit code 1 without noise
in the DB):

```cron
0 2 * * * root flock -n /var/lock/dedcom.scan /usr/local/bin/dedcom --scan /tank >> /var/log/dedcom-scan.log 2>&1
```

> ⚠️ **A new headless scan runs on the Balanced profile.** There is no flag for
> the profile yet, and `--scan` does not take it over from an earlier scan: every
> new scan starts on Balanced — two reading threads at normal priority. Only a
> resume keeps the profile its scan was started with. On a production /tank,
> give the cron line Idle's priorities from outside — and skip the night, with a
> line in the log, when the pool is not mounted:
>
> ```cron
> 0 2 * * * root if mountpoint -q /tank; then flock -n /var/lock/dedcom.scan nice -n 19 ionice -c 3 /usr/local/bin/dedcom --scan /tank; else echo "$(date) /tank is not mounted, no scan"; fi >> /var/log/dedcom-scan.log 2>&1
> ```
>
> Every thread of the run inherits them, the walk and the database writes as well
> as the two reading threads: they yield the CPU to VMs and backups, and ask the
> disk to do the same, as Idle does. Unlike Idle, there are two reading threads.

## 11.2. `--stats` — statistics for scans and the DB

```text
$ dedcom --stats
=== DB state ===
  file (scan.db + WAL): 245.7 MiB
  sessions: 23 (in trash 4) · manifest rows: 8 432 119

=== Scan statistics ===

#142  2026-05-20 14:15:00  [hashing]
  roots:       /tank
  environment: media=hdd layout=raidz2 ZFS=2.2.4
  workload:    files=2354678 volume(hash)=8.4 TiB groups=12437 freeable=145 GiB
  time:        2:14:30 (speed 1.2 GiB/s)

#141  2026-04-12 09:23:00  [complete]
  roots:       /tank
  ...
```

| Field            | What it means                                               |
|------------------|-------------------------------------------------------------|
| File             | Size of `dedcom.db` + the WAL journal                       |
| Sessions         | Active + in-trash counted separately                        |
| Manifest rows    | Sum of `file` rows across all scans (to gauge DB weight)    |
| Session status   | `walking` / `hashing` / `complete` / `aborted`              |
| Environment      | Media type, ZFS layout, version — for analytics             |
| Speed            | Accumulated hashed volume / accumulated active time         |

Read-only — it does not block other sessions and can be run alongside a running
TUI.

## 11.3. `--compact-db` — trash cleanup and VACUUM

```text
$ dedcom --compact-db
Emptying the trash and compacting the DB (VACUUM)…
Done: sessions purged from trash — 4; DB size 245.7 MiB → 178.3 MiB.
```

What it does:

1. **Empties the session trash** — every session with `trashed=1` is removed
   from the DB (including its `file` manifests, `file_mark` marks, and
   `file_group` summaries).
2. **`VACUUM`** — compacts the SQLite file (without it, `dedcom.db` does not
   shrink after a `DELETE`).

The before/after size is printed explicitly.

> Requires that no interactive `dedcom` is running (it takes the write lock). In
> cron — run it in a window when the TUI is definitely not in use.

When to run it: periodically, after deleting old sessions via the UI Trash. Or
from cron once a week/month.

## 11.4. `--export-csv <PATH>` — exporting duplicates to CSV

```text
$ dedcom --export-csv /tmp/duplicates.csv
Exported 12437 groups (87234 files) from scan 42, status: complete -> /tmp/duplicates.csv
```

File format:

```csv
group,keep,size_bytes,hash,path,scan_id,generation,device,inode,links,mark,keep_source
0,1,104857600,a3f5...e1,/tank/media/photo/IMG_3120.HEIC,42,3,64768,1180,1,keeper,mark
0,0,104857600,a3f5...e1,/tank/backup/IMG_3120.HEIC,42,3,64768,9912,1,,mark
1,1,52428800,b8d2...c4,/tank/video/v1.mp4,42,3,64768,3311,2,,default
1,0,52428800,b8d2...c4,/tank/video/v1-copy.mp4,42,3,64768,3311,2,,default
...
```

| Column        | Meaning                                                             |
|---------------|---------------------------------------------------------------------|
| `group`       | The group's published rank (0, 1, 2…) — all its rows share a `hash` |
| `keep`        | 1 = the file stays, 0 = dedup candidate                             |
| `size_bytes`  | File size in bytes                                                  |
| `hash`        | BLAKE3 hex (64 characters)                                          |
| `path`        | Full path to the file (CSV-escaped, see below)                      |
| `scan_id`     | Which session was exported                                          |
| `generation`  | Which publication of that session the ranks belong to               |
| `device`, `inode` | Physical identity: equal pairs are **aliases of one allocation** |
| `links`       | Link count the scan observed (`0` = never recorded, a pre-v3 row)   |
| `mark`        | Durable mark: `keeper`, `delete`, `hardlink`, `reflink`, or empty   |
| `keep_source` | `mark` — `keep` follows the operator's durable state; `default` — it was computed |

`scan_id` + `generation` + `group` is the stable identity of a group. Rank is
reassigned by payoff on every publication, so two exports are only comparable
group-by-group when they carry the same `generation`.

Two rows with the same `device`+`inode` are the same physical file under two
names: deleting one of them frees nothing.

### Which session is exported

The **newest active** (non-trashed) session. If that session has not finished,
the export refuses — it does **not** fall back to an older finished one, because
quietly exporting a different session is how a CSV ends up describing something
you never looked at. A session in the trash is never exported.

The export refuses, exits non-zero and leaves the destination file **exactly as
it was** when:

- the newest active session has not finished (still walking/hashing, or aborted);
- its status was written by a **newer dedcom** and this build cannot read it —
  the export names that session and stops. It never quietly exports an older
  session instead;
- it has no verified membership — an older checkpoint, or a scan that never
  published. Re-run the scan: opening the checkpoint does not republish it;
- a group has no keeper mark and no unmarked file, so the CSV would say "delete
  every copy" for it;
- a durable mark is damaged, or says both "keeper" and an action for one path;
- a group summary disagrees with the membership it declares;
- a physical cell is outside what a filesystem can report — a negative size,
  device or inode, or sub-second time outside `0..999999999`, or a size that
  disagrees with the group's own. Such a row is never printed as a number.

### The destination

Any path you like, **except dedcom's own live state**: `dedcom.db`, its
`-wal`/`-shm`/`-journal` companions and `dedcom.lock` in the state directory are
refused. Exporting over the checkpoint would destroy every scan you have run,
and over the lock would pull it out from under a running instance.

The refusal is about the **directory itself**, not about how you spell its path:
`..`, a symlinked directory and a bind mount of the state directory are all the
same directory and all refused. The five names are matched ignoring ASCII case
(`DEDCOM.DB` too), because a `casesensitivity=insensitive` dataset resolves
those spellings to the same file. An ordinary CSV name inside the state
directory is fine.

### How `keep` is decided

1. Files you durably marked as keeper (`F7`) keep. **There may be several**, and
   all of them get `keep=1`.
2. Files you marked for an action get `keep=0` and their action in `mark`.
3. Only when a group has no keeper mark at all is a keeper computed — the newest
   `mtime` among the **unmarked** files (ties broken by nanoseconds, then by
   path, so the answer is always the same). Those rows say `keep_source=default`.

An action mark is never turned into a keeper.

### The file itself

Read-only with respect to the checkpoint, and it does not take the instance
lock — it can run beside a working operator, and everything in one CSV comes
from a single consistent read of the database.

The artifact is written to a temporary file in the destination's own directory
and then renamed into place, so a failure never leaves a half-written CSV and
never damages a previous one. If the destination is a symbolic link, the export
refuses: renaming over it would destroy the link, writing through it would
overwrite whatever it points at, and as root with a typo (`--export-csv
/dev/stdout`) that link can be a system one. Give a regular pathname. The file is
created mode `0600`: it is a complete list of pathnames in your pool.

CSV escaping: paths with commas or quotes are wrapped in double quotes,
and quotes inside are doubled (RFC 4180). A path that begins with `=`, `+`, `-`,
`@`, tab or CR is prefixed with an apostrophe so a spreadsheet treats it as text
rather than a formula.

A pathname that holds control characters — a newline, a tab, a terminal escape
sequence — is exported with them spelled out: `\n`, `\t`, `\u{1b}`. The export is
a file that gets printed, and a terminal would act on the raw bytes; spelled out,
every record is also exactly one line. Such a row is not byte-faithful, so do not
feed it back to `rm` expecting it to name the same file.

A pathname that is not valid UTF-8 never reaches the export: the scan leaves it
out of the manifest. That holds for every file under a directory whose name is
not UTF-8, too. Such a file is counted in the `Omissions:` total `--scan` prints
when it finishes (§11.1), and in the `⚠ gaps` note on the TUI status line when
the scan is opened — together with files skipped by size or extension, so the
count does not name it. To see why one particular file is missing, put the
commander cursor on it and press F3. A name that really contains `U+FFFD` (the
`?`-like replacement character) is an ordinary name and is exported as it is.

### What to do with this CSV

- **Analytics in a spreadsheet** — open it in Excel/LibreOffice, compute the
  potential savings by file type.
- **Your own dedup script** — process the `keep=0` rows, do `ln` / `cp
  --reflink=always` / `rm` manually. **This loses dedcom's revalidation and
  snapshot insurance** — at your own risk.
- **Backup report** — a list of "what was duplicated at scan time".

## 11.5. `--purge-quarantine` — clearing the quarantine

Without `--yes` it only counts. It lists the `.dedcom-quarantine/` directory of every
detected dataset with the regular files inside and their total size, and deletes
nothing:

```text
$ dedcom --purge-quarantine
=== Quarantine to purge ===
  /tank/.dedcom-quarantine (87 files, 145678 bytes)
  /rpool/.dedcom-quarantine (12 files, 4567 bytes)
Total: 99 files, 150245 bytes

Nothing deleted. To confirm, re-run the command with the --yes flag.
```

With `--yes` it deletes those directories and reports what went:

```text
$ dedcom --purge-quarantine --yes
=== Quarantine to purge ===
  /tank/.dedcom-quarantine (87 files, 145678 bytes)
  /rpool/.dedcom-quarantine (12 files, 4567 bytes)
Total: 99 files, 150245 bytes
Reclaimed: 99 files, 150245 bytes
```

A directory that cannot be deleted is named on stderr (`ERROR: trash not deleted: …`),
is not counted in `Reclaimed`, and makes the command exit with an error. With no quarantine
anywhere it prints `The quarantine is empty — nothing to purge.` and exits 0.

> ⚠️ **Irreversible.** With `--yes`, every file in every timestamp subdirectory
> is gone. This is a final `rm -rf`. Before running it, make sure the result of
> the previous `dedcom` runs is stable (1–2 weeks of normal operation — see the
> [Safety, Recovery, and Limitations](../SAFETY.md) document and [§08](08-actions.md)).

> It does not touch the ZFS snapshots `@dedcom-<ts>` — clear those with `zfs
> destroy` manually (or with a script, see [Safety, Recovery, and Limitations](../SAFETY.md)).

## 11.6. `--read-only` — observer mode in the TUI

This is **not** headless: it opens the TUI, but in read-only mode. No
operations, no scans, no edits. Handy as a "second window" — to watch what the
operator is doing:

```text
$ dedcom --read-only        # second window
```

In the top-right corner the ` ● READ-ONLY ` badge stays lit. All action keys
(F5–F8 / F11 / Delete / `S`) are either ignored or answered in the status line,
F11 for example:

```text
Read-only: executing actions unavailable (started with --read-only)
```

A window that became an observer because another `dedcom` holds the lock
([§02](02-install.md)) says `(another instance is active)` instead. An observer
scans and applies nothing, so `--no-resume`, `--verify`, `--merkle-dirs` and
`--strict-verify` are refused beside `--read-only` (exit code 2).

## Other flags (not headless, but important for scripts)

| Flag                       | Action                                                    | Applies to |
|----------------------------|-----------------------------------------------------------|------------|
| `--state-dir /path`        | A different state directory (not `~/.local/state/dedcom`) | every run |
| `--no-resume`              | Ignore the saved checkpoint                               | `--scan`, the classic wizard |
| `--no-hash-reuse`          | Disable the hash cache (re-hash everything)               | `--scan` |
| `--verify`                 | Byte-by-byte comparison after hashing                     | `--scan`, both interfaces |
| `--strict-verify`          | Strict revalidation before an action (see [§08](08-actions.md)) | both interfaces |
| `--merkle-dirs`            | Directory signatures via streaming Merkle (memory-friendly, opt-in) | `--scan`, both interfaces |
| `--include-ext jpg,heic`   | Extension filter                                          | `--scan` |
| `--storage-type hdd`       | Override media auto-detection                             | `--scan` |
| `--yes`                    | Confirm the deletion (§11.5)                              | `--purge-quarantine` |
| `--classic`, `--commando`  | Open the step-by-step wizard, or the Commando interface   | either interface, not both |
| `--read-only`              | Observer (§11.6)                                          | every run, not with `--force` |
| `--force`                  | Seize the lock (dangerous)                                | every run, not with `--read-only` |
| `-V` / `--version`         | Version → stdout, exit 0                                  | — |
| `-h` / `--help`            | Help → stdout, exit 0                                     | — |

"Both interfaces" are the Commando interface (the default) and the classic
wizard (`--classic`). A flag given to a run it does not apply to is refused
(exit code 2) rather than ignored. `--no-resume` belongs to the wizard, which
offers the saved scans at start; the Commando interface offers them when asked
(F2, F12), so there the flag is refused. `--read-only` and `--force` are taken
by every run, but not together: an observer never takes the operator's lock.
Nor does an observer scan or apply, so in either interface `--read-only` refuses
`--no-resume`, `--verify`, `--merkle-dirs` and `--strict-verify` beside it
(§11.6).

## What's next

- [§12 Maintenance](12-maintenance.md) — where `dedcom.db` lives, how to rotate
  logs, retention.
- [§13 Troubleshooting](13-troubleshooting.md) — what to do when headless
  errors occur.
