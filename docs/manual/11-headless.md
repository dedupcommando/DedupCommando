# 11. Headless — CLI for scripts and cron

Five flags run `dedcom` without the TUI:

| Flag                          | What it does                                            |
|-------------------------------|---------------------------------------------------------|
| `--scan <PATH>`               | Scans a root and prints the result                      |
| `--stats`                     | Prints statistics for all scans and DB state            |
| `--compact-db`                | Empties the session trash and compacts the DB (VACUUM)  |
| `--export-csv <PATH>`         | Exports the groups of the last scan to CSV              |
| `--purge-quarantine`          | Deletes the `.dedcom-quarantine` directories in all datasets |

All of them **exit immediately** once done (there is no interactive UI). If
another `dedcom` is already working on this state directory, the headless mode
**does not prompt** — it exits with an error right away (there is no way to
answer interactively).

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
- **1** — runtime error. Printed as `dedcom: error: {message}` on stderr.
- **2** — argument-parsing error. Printed as `dedcom: {message}` followed by
  `Run with --help for usage.` on stderr.

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
Potentially reclaimable: 1234567890 bytes
Scan time:            0:23:45 (speed 87 MiB/s)
  #1     5 files x 104857600 bytes
        /tank/media/photo/IMG_canonical.HEIC
        /tank/backup/IMG_canonical.HEIC
        ...
  #2     3 files x 52428800 bytes
        ...
  ... and 22 more groups
```

> The first 50 groups are printed with their members; the rest are a count
> only. For a full dump, use `--export-csv`.

### Resume in headless

On a repeated run of `--scan <the same roots>` without the `--no-resume` flag:

```text
$ dedcom --scan /tank
Resuming unfinished scan #142 from 2026-05-20 14:15 (12345 / 23456 files already hashed)
[phase] Hashing
...
```

- Only a scan with **exactly the same roots** as in `--scan` is resumed (the
  record in the DB).
- Completed scans are not resumed (no need).
- `--no-resume` → start a new scan, ignoring the checkpoint.

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

> ⚠️ **On a production /tank in cron — always use the Idle profile.** Headless
> `--scan` does not switch the profile automatically; it takes it from the last
> scan configuration in the DB (or Balanced by default). Set Idle once via the
> TUI: F9 → scan configuration wizard → `G` until Idle → `S` (run at least an
> empty scan). After that the profile is remembered and cron will run on Idle.

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
Exported 12437 groups (87234 files), scan status: complete -> /tmp/duplicates.csv
```

File format:

```csv
group,keep,size_bytes,hash,path
1,1,104857600,a3f5...e1,/tank/media/photo/canonical/IMG_3120.HEIC
1,0,104857600,a3f5...e1,/tank/backup/IMG_3120.HEIC
1,0,104857600,a3f5...e1,/tank/old-copy/IMG_3120.HEIC
2,1,52428800,b8d2...c4,/tank/video/v1.mp4
2,0,52428800,b8d2...c4,/tank/video/v1-copy.mp4
...
```

| Column        | Meaning                                                        |
|---------------|----------------------------------------------------------------|
| `group`       | Group number (1, 2, 3…) — all rows of one group share a `hash` |
| `keep`        | 1 = keeper (one per group), 0 = dedup candidate                |
| `size_bytes`  | File size in bytes                                             |
| `hash`        | BLAKE3 hex (64 characters)                                     |
| `path`        | Full path to the file (CSV-escaped, see below)                |

The keeper is chosen **by the most recent mtime** (other criteria — only via the
TUI).

Read-only. It takes the **last** saved scan (including an unfinished one — it
exports what has already been hashed).

CSV escaping: paths with commas/quotes/newlines are wrapped in double quotes,
and quotes inside are doubled (RFC 4180).

### What to do with this CSV

- **Analytics in a spreadsheet** — open it in Excel/LibreOffice, compute the
  potential savings by file type.
- **Your own dedup script** — process the `keep=0` rows, do `ln` / `cp
  --reflink=always` / `rm` manually. **This loses dedcom's revalidation and
  snapshot insurance** — at your own risk.
- **Backup report** — a list of "what was duplicated at scan time".

## 11.5. `--purge-quarantine` — clearing the quarantine

```text
$ dedcom --purge-quarantine
Quarantine cleared: /tank/.dedcom-quarantine (87 files, 145678 bytes)
Quarantine cleared: /rpool/.dedcom-quarantine (12 files, 4567 bytes)
Total freed: 99 files, 150245 bytes
```

Deletes the `.dedcom-quarantine/` directories in ALL detected datasets. Before
deleting, it does a recursive count.

By default it **only reports the size** and deletes nothing. Deletion happens
only when `--yes` is also given.

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
(F5–F8 / F11 / Delete / `S`) are either ignored or report "read-only mode".

## Other flags (not headless, but important for scripts)

| Flag                       | Action                                                    |
|----------------------------|-----------------------------------------------------------|
| `--state-dir /path`        | A different state directory (not `~/.local/state/dedcom`) |
| `--no-resume`              | Ignore the saved checkpoint                               |
| `--no-hash-reuse`          | Disable the hash cache (re-hash everything)               |
| `--verify`                 | Byte-by-byte comparison after hashing                     |
| `--strict-verify`          | Strict revalidation for the TUI (at launch; see [§08](08-actions.md)) |
| `--merkle-dirs`            | Directory signatures via streaming Merkle (memory-friendly, opt-in) |
| `--include-ext jpg,heic`   | Extension filter                                          |
| `--storage-type hdd`       | Override media auto-detection                             |
| `--force`                  | Seize the lock (dangerous)                                |
| `-V` / `--version`         | Version → stdout, exit 0                                  |
| `-h` / `--help`            | Help → stdout, exit 0                                     |

## What's next

- [§12 Maintenance](12-maintenance.md) — where `dedcom.db` lives, how to rotate
  logs, retention.
- [§13 Troubleshooting](13-troubleshooting.md) — what to do when headless
  errors occur.
