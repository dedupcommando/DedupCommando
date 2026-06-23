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
| `move_event`  | Move journal (Triage Board)                                     | bytes × moves |

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

## Backing up the database

`dedcom.db` is an "index", not the data itself. Losing it means losing scan history and
marks (but not files!). A backup makes sense if:

- You did a lot of manual keeper marking before an apply.
- You keep many completed sessions for analytics (ScanDiff).

Before backing up, close all `dedcom` instances (the lock is released, the WAL is
checkpointed):

```text
# check that nobody is working
ls ~/.local/state/dedcom/dedcom.lock 2>/dev/null && echo "Close dedcom first"

# a simple backup
cp -a ~/.local/state/dedcom ~/dedcom-state-backup-$(date +%F)
```

SQLite supports a "hot backup" via the `.backup` command, but for `dedcom` that is
overkill.

## What's next

- [§11 Headless](11-headless.md) — `--stats`, `--compact-db`, `--purge-quarantine`
  for automation.
- [§13 Troubleshooting](13-troubleshooting.md) — common problems (DB locked,
  a stale lock, and so on).
