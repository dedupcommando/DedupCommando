# 12. Maintenance — database, retention, logs

## State directory

All of `dedcom`'s runtime state lives in a single directory:

```text
~/.local/state/dedcom/             ← default (the XDG state dir on Linux)
├── dedcom.db                       ← SQLite checkpoint of all scans
├── dedcom.db-wal                   ← SQLite WAL journal (grows during apply, shrinks at checkpoint)
├── dedcom.log                      ← Log (tracing → file; grows without auto-rotation)
├── benchmarks.log                  ← Separate timing log (`bench::start`) — for spotting degradation
├── consent.json                    ← The user's acceptance of the notice
├── config.json                     ← User settings (concurrency, vacuum, retention)
├── presets.json                    ← Custom extension-filter presets
├── board.json                      ← Triage Board layout
└── dedcom.lock                     ← Lock file of the active operator (PID + timestamp)
```

Overridden with the `--state-dir` flag:

```text
dedcom --state-dir /var/lib/dedcom
```

Useful when `~` sits on a thin root (a Linux/ZFS root filesystem may be only 16–32 GiB),
while the database can grow to hundreds of MB — move it somewhere roomier.

## `dedcom.db` — structure and size

This is SQLite in WAL mode. The main tables:

| Table         | Contents                                                       | Dominant size |
|---------------|-----------------------------------------------------------------|----------------|
| `scan`        | Metadata of each scan (id, status, config, trashed)            | hundreds of bytes/scan |
| **`file`**    | File manifest of each scan (path, size, mtime, device, inode, hash) | **dominant** — tens of MB per million files |
| `scan_stats`  | Metrics and progress per scan                                  | hundreds of bytes/scan |
| `file_mark`   | Action marks (keeper/delete/hardlink/reflink) — `(scan_id, path)` | bytes × marks |
| `file_group`  | Materialized duplicate-group summaries (for fast loading)       | hundreds of bytes/group |
| `dir_dedup`   | Directory signatures (for twin folders)                        | hundreds of bytes/directory |
| `hash_cache`  | Hash cache: `(device, inode, size, mtime)` → BLAKE3            | bytes × files |
| `move_event`  | Move journal (Triage Board); pathnames stored as raw bytes since schema v6 | bytes × moves |

### Size estimate

On an illustrative `/tank` of 2.2M files:

- `dedcom.db` ≈ 200–400 MiB for a single session
- With 5–10 completed sessions accumulated, it can grow to 1–2 GiB

The exact figures come from `dedcom --stats`:

```text
=== DB state ===
  file (scan.db + WAL): 245.7 MiB
  sessions: 23 (in trash 4) · manifest rows: 8 432 119
```

If `dedcom.db` grows much faster than the number of active sessions, the WAL is not
being checkpointed. Restarting `dedcom` (closing the DB) triggers a checkpoint; as a last
resort `--compact-db` compacts the database forcibly.

## VACUUM — compacting the database

After a `DELETE`, SQLite **does not return space to the file**. Delete a large scan,
clear the trash — and `dedcom.db` stays the same size. `VACUUM` rewrites the file
entirely, dropping the "holes".

### Manual run

```text
dedcom --compact-db
```

(It performs: purge of the session trash + VACUUM. See [§11 Headless](11-headless.md).)

### Automatic VACUUM

At TUI startup the auto-VACUUM flag in `config.json` is checked:

```json
{
  "vacuum_interval_hours": 120,
  "last_vacuum": 1716800000
}
```

| Field                   | Value               | What it is                                                       |
|-------------------------|---------------------|------------------------------------------------------------------|
| `vacuum_interval_hours` | default **120** (5 days) | If ≥ N hours have passed since `last_vacuum`, auto-VACUUM runs. **0 = off** |
| `last_vacuum`           | unix timestamp      | When VACUUM last ran. Updated automatically                      |

Auto-VACUUM runs **in the background** after TUI startup — it does not block work.
It does not touch the trash (it only compacts); clearing the trash is manual only.

### When to change the interval

| Scenario                                              | `vacuum_interval_hours` |
|-------------------------------------------------------|-------------------------|
| Default (5 days) — most cases                         | 120                     |
| Used rarely, the file is heavily fragmented           | 24 (one day)            |
| Very large DB (>5 GB) — VACUUM is slow                | 720 (30 days) or 0      |
| Fully under manual control                            | 0                       |

```text
# Change the interval to 30 days (via jq):
jq '. + {vacuum_interval_hours: 720}' ~/.local/state/dedcom/config.json | \
  sponge ~/.local/state/dedcom/config.json
```

(This is not yet configurable in the TUI.)

## Retention — the session-history limit

On every scan **completion**, `dedcom` checks how many previously completed scans
**of the same roots** are active. If there are more than the limit, the oldest ones are
softly moved to the trash (not purged — reversible).

The parameter in `config.json`:

```json
{
  "history_keep": 2
}
```

| Value      | What it means                                                       |
|------------|---------------------------------------------------------------------|
| 2 (default) | Keep the 2 most recent completed scans for each set of roots       |
| 5          | Keep more history                                                   |
| 1          | Only the current one + one previous                                 |
| 0          | Every new scan moves all previous ones to the trash                 |

This is **not deletion** but a move to the session trash (see [§10 Diff & trash](10-diff-trash.md)).
Final cleanup happens only via the UI Trash → Delete or `--compact-db`.

## Logs — `dedcom.log` and `benchmarks.log`

`dedcom.log`:

- `tracing` → file, plain-text format.
- Levels: info / warn / error (debug is compiled in only in dev builds).
- **No auto-rotation.** Under active work it grows at ~1–10 MB/day.

`benchmarks.log`:

- Targeted timings via `bench::start("op")` → `op=… ms`.
- Enabled in code where tracking degradation matters (a typical example —
  `planned_action_rows`, opening the DB, materialization).
- Grows much more slowly than `dedcom.log`.

### Rotation from outside (logrotate)

`dedcom` does not rotate logs itself — use `logrotate`:

```text
# /etc/logrotate.d/dedcom
/home/*/.local/state/dedcom/dedcom.log
/root/.local/state/dedcom/dedcom.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate` matters: `dedcom` keeps the file open, and a plain `rotate` would detach
it. `copytruncate` copies and truncates in place.

### Alternative — just wipe it periodically

If the logs are expendable:

```cron
# /etc/cron.d/dedcom-cleanup
0 3 * * 0 root :> /root/.local/state/dedcom/dedcom.log
0 3 * * 0 root :> /root/.local/state/dedcom/benchmarks.log
```

(Truncates to zero once a week.) `dedcom` keeps writing to the truncated file correctly.

## `config.json` — format and fields

In full (all fields optional, absence = default):

```json
{
  "concurrency": "ask",
  "vacuum_interval_hours": 120,
  "last_vacuum": 1716800000,
  "history_keep": 2
}
```

| Field                   | Values                                | Default  | What it controls                         |
|-------------------------|---------------------------------------|----------|------------------------------------------|
| `concurrency`           | `ask` / `allow` / `readonly` / `block` | `ask`    | Behavior when the lock is held (see below) |
| `vacuum_interval_hours` | integer ≥ 0                            | 120      | Auto-VACUUM (see above)                  |
| `last_vacuum`           | unix timestamp                         | (none)   | Timestamp; updated automatically         |
| `history_keep`          | integer ≥ 0                            | 2        | Session-history limit (see above)        |

### Concurrency policy

When trying to start while the lock is held:

| Value      | Behavior                                                               |
|------------|------------------------------------------------------------------------|
| `ask` (default) | TUI: the `R/F/Esc` choice overlay. Headless: always **block**.    |
| `allow`    | Straight in as the **operator** (even if held) — equivalent to always `--force`. **Dangerous** |
| `readonly` | Straight into observer mode (if held)                                  |
| `block`    | Just exit with an error (do not start at all if held)                  |

Headless (`--scan`, `--compact-db`, etc.) with `ask` behaves like `block`
(there is no UI to ask questions).

## Migrating state between hosts

`dedcom` stores absolute paths in `dedcom.db`. You can move the state directory to
another host (with the same mountpoints):

```text
ssh old-host 'tar czf - .local/state/dedcom' | ssh new-host 'tar xzf - -C ~'
```

But if the paths differ, the DB will not fit; run a fresh scan.

## Backing up and restoring `dedcom.db`

`dedcom.db` is an "index", not the data itself. Losing it means losing scan history and
marks (but not files!). A backup makes sense if:

- You did a lot of manual keeper marking before an apply.
- You keep many completed sessions for analytics (ScanDiff).
- You are about to upgrade `dedcom` across a schema change and want the option to go
  back. Schema v6 (the move journal stores pathnames as raw bytes) has no downgrade
  migration: an older build refuses a newer database and leaves it untouched, so the only
  way back to the older build is a copy taken before the upgrade.

A plain `cp dedcom.db` is not enough. `dedcom` runs the database in WAL mode: committed
transactions can sit in `dedcom.db-wal` until a checkpoint, and a copy of the main file
alone silently loses them. Take the copy with SQLite's own `.backup`, and only while no
`dedcom` process is running — the two scripts below check that first, and refuse when
they cannot tell. Both set `umask 077`: the copy and the set-aside directory hold every
pathname of the pool and stay readable by the owner alone (`0600` for files, `0700` for
the directory).

### Backup (before the upgrade)

The version check pins the copy to the schema before the v6 upgrade; a copy of a v6
database is not a way back, because the older build cannot open it.

```bash
#!/usr/bin/env bash
# backup-dedcom-db.sh — consistent copy of dedcom.db while dedcom is NOT running.
set -euo pipefail
# Nothing this script creates may be readable by anyone else: the copy holds every pathname of the pool.
umask 077
S="${DEDCOM_STATE_DIR:-$HOME/.local/state/dedcom}"      # or the directory given to --state-dir
cd "$S"

# pgrep exit codes: 0 = a dedcom process exists, 1 = none, anything else (2, 3, 127 when pgrep
# itself is missing) = we could not tell. Only "none" may continue. `|| rc=$?` keeps set -e quiet
# for the check itself; an `if pgrep` would have read every failure as "no process".
rc=0; pgrep -a dedcom || rc=$?
case "$rc" in
  0) echo "dedcom is running — exit it first (do not use --force to bypass its lock)" >&2; exit 1 ;;
  1) ;;
  *) echo "pgrep failed (exit $rc; procps installed?) — cannot prove dedcom is stopped" >&2; exit 1 ;;
esac
command -v sqlite3 >/dev/null || {
  echo "sqlite3 CLI is missing (Debian/Proxmox: apt install sqlite3)." >&2
  echo "Without it: start the OLD dedcom build once and exit cleanly (it folds the WAL and" >&2
  echo "removes -wal/-shm), verify that only dedcom.db remains, then: cp -p dedcom.db <new name>" >&2
  exit 1
}

BAK="dedcom.db.v5-$(date +%Y%m%d-%H%M%S).bak"
if [ -e "$BAK" ] || [ -L "$BAK" ]; then echo "$BAK already exists" >&2; exit 1; fi

# -wal/-shm present with dedcom stopped = unclean exit; .backup reads through the WAL correctly.
ls -l dedcom.db*
sqlite3 dedcom.db ".backup '$BAK'"

# The copy is a regular file of our own, mode 0600 — never a symlink somebody planted under the name.
[ -f "$BAK" ] && [ ! -L "$BAK" ] || { echo "$BAK is not a regular file" >&2; exit 1; }
chmod 600 "$BAK"

# The copy must be sound and must be the OLD schema (5) — verify before trusting it.
sqlite3 "$BAK" "PRAGMA integrity_check;" | grep -qx ok || { echo "$BAK fails integrity_check" >&2; exit 1; }
V="$(sqlite3 "$BAK" "PRAGMA user_version;")"
[ "$V" = 5 ] || { echo "$BAK is schema v$V, not v5 — not a pre-upgrade copy" >&2; exit 1; }
echo "verified backup: $S/$BAK (schema v5)"
```

### Restore (going back to the older build)

The v6 files are set aside into a new directory, never overwritten; the copy is verified
before anything is moved and nothing is copied onto a name that is still taken.

```bash
#!/usr/bin/env bash
# restore-dedcom-db.sh <verified .bak> — put a v5 copy back; sets the v6 files aside, never over them.
set -euo pipefail
# The set-aside directory and everything in it stay private to the owner.
umask 077
S="${DEDCOM_STATE_DIR:-$HOME/.local/state/dedcom}"
BAK="${1:?usage: restore-dedcom-db.sh <verified .bak>}"
cd "$S"

# Same three-way pgrep check as in the backup script: only exit code 1 ("no process") continues.
rc=0; pgrep -a dedcom || rc=$?
case "$rc" in
  0) echo "dedcom is running — exit it first" >&2; exit 1 ;;
  1) ;;
  *) echo "pgrep failed (exit $rc; procps installed?) — cannot prove dedcom is stopped" >&2; exit 1 ;;
esac

# 1. The backup is verified BEFORE anything is moved.
[ -f "$BAK" ] || { echo "backup not found: $BAK" >&2; exit 1; }
sqlite3 "$BAK" "PRAGMA integrity_check;" | grep -qx ok || { echo "$BAK fails integrity_check" >&2; exit 1; }
[ "$(sqlite3 "$BAK" "PRAGMA user_version;")" = 5 ] || { echo "$BAK is not a v5 checkpoint" >&2; exit 1; }

# 2. A NEW directory, mode 0700. No -p: an existing one is an error, and the script stops here.
ASIDE="aside-v6-$(date +%Y%m%d-%H%M%S)"
mkdir -m 700 "$ASIDE"

# 3. The main file must exist and must move; the sidecars move only if present.
#    "Absent sidecar" is normal after a clean exit; "cannot move" is an error (set -e stops).
if [ -e dedcom.db ] || [ -L dedcom.db ]; then
  mv dedcom.db "$ASIDE/"
else
  echo "dedcom.db is not here — nothing to set aside; look before restoring" >&2; exit 1
fi
for f in dedcom.db-wal dedcom.db-shm; do
  if [ -e "$f" ] || [ -L "$f" ]; then mv "$f" "$ASIDE/"; fi
done

# 4. Prove the names are free. Only then copy.
for f in dedcom.db dedcom.db-wal dedcom.db-shm; do
  if [ -e "$f" ] || [ -L "$f" ]; then echo "still present: $f — restore aborted" >&2; exit 1; fi
done
cp -p "$BAK" dedcom.db
[ -f dedcom.db ] && [ ! -L dedcom.db ] || { echo "dedcom.db is not a regular file" >&2; exit 1; }
chmod 600 dedcom.db
sqlite3 dedcom.db "PRAGMA integrity_check;" | grep -qx ok
echo "restored $BAK as dedcom.db (schema $(sqlite3 dedcom.db 'PRAGMA user_version;')); v6 files kept in $S/$ASIDE"
```

### What restoring does not do

Moves made after the copy was taken are not undone: the files stay where the Triage
Board put them. Their journal stays in the set-aside v6 file and can be read with any
`sqlite3`:

```text
sqlite3 aside-v6-<stamp>/dedcom.db \
  "SELECT id, created_at, hex(source_path), hex(target_path), duplicate, path_fidelity
     FROM move_event ORDER BY id;"
```

To roll the files themselves back, use the ZFS snapshot the Triage Board takes before
each batch (`zfs list -t snapshot | grep dedcom`, see §03). Undo inside the TUI lives in
the session's memory only and does not survive a restart.

## What's next

- [§11 Headless](11-headless.md) — `--stats`, `--compact-db`, `--purge-quarantine`
  for automation.
- [§13 Troubleshooting](13-troubleshooting.md) — common problems (DB locked,
  a stale lock, and so on).
