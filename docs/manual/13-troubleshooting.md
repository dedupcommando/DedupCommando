# 13. Troubleshooting

A digest of common problems in **symptom → cause → fix** form. If nothing here
matches, `dedcom.log` (`~/.local/state/dedcom/dedcom.log`) usually contains the
exact error message.

## Scanning and memory

### The scan was killed by the OOM killer during the "Grouping" (3/3) phase

**Cause:** the default directory-signature algorithm keeps roughly 2.5 KiB in
memory per hashed file. On a pool with 2 M files that is a peak of about 5 GiB
(see [§07 Estimating the 3/3 memory peak](07-scanning.md#estimating-the-33-memory-peak-for-the-default-algorithm)).

**Fix:**

```text
dedcom --scan /tank --merkle-dirs    # headless, with the memory-friendly algorithm
# or in the TUI:
dedcom --merkle-dirs                  # the flag applies to a NEW scan from this session
```

The Merkle algorithm uses O(tree depth) RAM — tens to hundreds of MB regardless
of the number of files.

> Resuming an old scan continues with **the same algorithm** it was started with.
> If it died on an old scan, start over with `--no-resume --merkle-dirs`.

### The scan hammers the disk and my VMs/backups slowed down

**Cause:** the `Turbo` intensity profile (or `Balanced` on a loaded pool) reads
the disk in parallel and competes with your other workloads.

**Fix:** switch to **Idle** (1 thread + nice 19 + ionice idle):

- In the TUI: F9 → scan configuration wizard → `G` until `Idle` → start.
- Headless: the profile comes from the last scan configuration in the database
  (set it **once** through the TUI, then cron picks it up automatically — the
  profile is persisted in the checkpoint).

See [§07 Intensity profiles](07-scanning.md#intensity-profiles-resource-governor).

### The hash cache is not used (a repeat scan is slow)

**Cause:** `dedcom` looks up rows in `hash_cache` by `(device, inode, size,
mtime)` that match the current file exactly. Any change is a cache miss:

1. **File renamed/moved** — the `inode` is usually preserved (it is just an `mv`
   within the same filesystem) and `mtime` is unchanged → **cache hit**.
2. **File copied** — new `inode` → **cache miss**, re-hash.
3. **External software touched `mtime`** (`touch`, a rebuild from source, etc.) →
   **cache miss**, re-hash.
4. **File moved to another dataset** — different `device` → **cache miss**.

**Fix:**

- Make sure `mtime` is stable between scans on your typical files:
  ```text
  stat -c '%n %Y' /tank/some-file
  ```
- If something touches `mtime`, disable that process or accept the cache miss as
  unavoidable.

### `--no-hash-reuse` is off right now — but I want it on

In the TUI: scan configuration wizard → key **C** (cache toggle). Headless:
`dedcom --scan /tank --no-hash-reuse`.

### The scan reports "0 files scanned" on a ZFS pool

**Cause:** `min_size = 4096` by default — files smaller than one filesystem block
are skipped. If all your files are tiny (config files, for example), none of them
enter the scan. Headless output simply prints `Files scanned:        0`.

**Fix:** the scan configuration wizard does not expose `min_size` — it is fixed
in code. If you need to deduplicate tiny files you have to change
`ScanConfig::new` in the source (`src/model/scan.rs`) and rebuild. For a typical
backup/media workload `min_size=4096` is the right default.

## Applying actions

### F11 → Esc, nothing happened

**Cause:** no keeper is assigned in any group. With no keeper there is nothing to
keep, so the actions are ignored.

**Fix:** in a GroupFiles view, mark one entry of each group with **F7** (or Enter
in the classic browser). You can also mark keepers automatically with **A** in
the browser — the keeper is chosen by the most recent `mtime`.

### "cross-dataset hardlink is impossible — files are in different datasets"

**Cause:** the target and the keeper are in different ZFS datasets; a hardlink
between filesystems is impossible by definition (a hardlink is a directory entry
on the same filesystem).

**Fix:**

- Choose Reflink (`F6`) if both are in the **same pool** and `block_cloning` is
  supported.
- Or Delete (`F8`) — the target goes to quarantine, freeing space without any
  link to the keeper.

### "reflink is impossible — files are in different ZFS pools"

**Cause:** ZFS reflink (`block_cloning`) only works within a single pool.

**Fix:** Hardlink (if both are in the same dataset) or Delete.

### "reflink is unavailable on this host — needs ZFS 2.3+ with block cloning enabled"

**Cause:** a ZFS pool without `block_cloning=active`. Check it:

```text
zpool get all | grep block_cloning
```

**Fix:**

```text
zpool set feature@block_cloning=enabled <pool>   # enable it
# a restart or reboot is needed for it to take effect
```

If your ZFS version is older than 2.3, upgrade ZFS; otherwise only Hardlink/Delete
are available.

### Apply cancelled half the actions (revalidation failed)

**Cause:** the files changed between the scan and the apply. Each cancelled action
is logged with a specific reason in `dedcom.log`:

- `(size)` — the size changed
- `(content)` — the size matched but the BLAKE3 hash did not
- `symlink` — the file was replaced by a symlink

**Fix:** run a **new scan** of the same root (or resume the same one), re-check
your marks, and press F11 again. If apply fails en masse, some process is
overwriting files in parallel — find and stop it, or accept it as a fact (data
under active writes cannot be deduplicated).

### "target file's dataset could not be determined"

**Cause:** the automatic ZFS-dataset lookup by `device` found no match. The file
may be on a non-ZFS filesystem (an external mount point inside the root), or ZFS
was not detected at startup.

**Fix:** only deduplicate roots that lie entirely on ZFS. Check the `mountpoint`
of each target filesystem:

```text
df -T <path>     # should report zfs
```

### "moving by copying would lose the owner/permissions/ACL/xattr…" (cross-device move)

**Cause:** the source and destination are on different filesystems (different ZFS
datasets). `dedcom` refuses to "move" by copying, because that would silently lose
metadata. The full message is:

```text
source and destination are on different filesystems (ZFS datasets): <src> -> <dest>;
moving by copying would lose the owner/permissions/ACL/xattr, would inflate sparse
images and would break hardlinks. Move within a single dataset or do it manually:
rsync -aHAX --sparse <src> <dest> && rm -f <src>
```

**Fix:** keep the move within a single dataset, or run the suggested `rsync`
command by hand (it preserves hardlinks, ACLs, xattrs, and sparseness).

## Concurrency and locking

### "another instance is already running" — but I'm sure it isn't

**Cause:** the lock file `dedcom.lock` was left behind after an unclean exit (an
OOM kill, a yanked cable, `kill -9`). The interactive message is:

```text
dedcom: another instance is already running (PID 12345, since 2026-06-20 14:32:15).
Run with --read-only to observe, or terminate that process.
```

**Fix:**

```text
# confirm no process with the recorded PID exists:
cat ~/.local/state/dedcom/dedcom.lock          # shows the PID
ps -p <PID>                                     # no match = the lock is orphaned

# remove the lock file by hand
rm ~/.local/state/dedcom/dedcom.lock
dedcom                                          # start again
```

If a process with that PID exists but is **not** `dedcom` (the PID was reused by
the system), the lock is also safe to remove by hand.

To only observe the running instance without touching the lock, start with
`dedcom --read-only`. An alternative is the `--force` flag, but it does not remove
an orphaned lock — it **seizes** the state on top (which is less clean).

### Headless from cron does not run, it says "cancelled"

**Cause:** an interactive `dedcom` was running when the cron job started. Under
the `ask` concurrency policy, headless behaves like `block` (there is no UI to
ask the question), so it simply refuses to start. The headless message is:

```text
write cancelled (PID 12345, since 2026-06-20 14:32:15): held by another instance
or --read-only given — terminate that process or retry with --force
```

**Fix:**

- Run cron at a different time.
- Or set `"concurrency": "block"` in `config.json` explicitly — the behavior is
  unchanged, but explicit.
- As a last resort, retry with `--force` to seize the state — only do this when
  you are certain no other instance is actually writing.
- Do NOT set `"concurrency": "allow"` for cron — that would write to the database
  in parallel with the TUI and **corrupt your data**.

## TUI

### Shift+F works in a local terminal but not in the Proxmox web shell

**Cause:** xterm.js (the Proxmox web console) does not pass the Shift modifier with
F-keys. This is a known limitation, not a `dedcom` bug.

**Fix:** use the prefix key `` ` `` (backtick, under Esc) — it arms the "second
layer" for the next single F-key press:

```text
` then F12     # equivalent to Shift+F12 — Triage Board
` then F9      # equivalent to Shift+F9 — scan configuration wizard
```

The F-key footer is highlighted **yellow** while the second layer is armed.

See [§05 F-keys — second layer](05-commando.md#f-keys--second-layer).

### I want to see more than 200 files in a group

**Cause:** the GroupFiles view in commando mode shows the **first 200** files of a
group — a visual cap that prevents navigation from freezing on enormous groups
(millions of files).

**Fix:** **the cap does not affect bulk actions (F11)** — the plan is built from
the full group in the database. The visible subset is for eyeball inspection only.

If you need to see a specific file that is not in the first 200, that is not yet
supported; workarounds:

- `dedcom --export-csv` → grep for the file of interest.
- `dedcom --stats` shows a summary, but not group members.
- Sorting GroupFiles (the `s` key) changes which 200 are visible (by size, by name,
  by date).

Scrolling the full group is on the roadmap.

### The cursor jumps around oddly when I `Tab` between panels

**Cause:** Tab switches focus, but each panel's cursor is **independent** and
remembers its own position. This is by design, not a bug.

**If you want** the same position everywhere, use Shift+F1 (synchronize panels):
everything jumps to the active panel's directory.

### I pressed `o` in the Files view and nothing happened

**Cause:** the **`o`** key (jump to the file's directory) only works in the
**GroupFiles** and **DuplicatesOfCursor** views — those have a meaningful path for
the file under the cursor.

**Fix:** in the Files view no jump is needed — that view **already shows** the
directory's contents; `Enter` descends and `Backspace` ascends. See
[§05 The `o` key](05-commando.md#the-o-key--a-files-directory-into-the-adjacent-panel).

### Directory size is not recomputed automatically

**Cause:** `dedcom` does not recompute every directory's size automatically (it is
expensive on large trees). A size is shown only when it has been computed
explicitly.

**Fix:** Shift+F6 on the focused directory recomputes its size in the background.
Or use the F9 menu → item 12.

## Performance

### dedcom.db has grown to several GB

**Cause:** many completed sessions have accumulated (each scan stores hundreds of
MB of `file` rows). `VACUUM` has not yet had a chance to compact after deletions.

**Fix:**

```text
dedcom --stats               # see the number of sessions
# Delete old ones via the TUI: F12 → Resume → Delete on the unneeded ones
dedcom --compact-db          # empty the session trash + VACUUM
```

Or configure `history_keep` in `config.json` so old sessions move to the trash
automatically (see [§12 Retention](12-maintenance.md)).

### Opening an old scan from Resume takes tens of seconds

**Cause:** an old scan (from an earlier version) has no materialized `file_group`
summaries. The first time it is opened there is a one-off materialization (an SQL
aggregation over millions of files).

**Fix:** nothing — it is a one-off process; subsequent opens are fast. The
"Opening result" animation in the TUI is exactly this work.

### VACUUM (`--compact-db`) takes a long time

**Cause:** on large databases (>3 GB) VACUUM rewrites the whole file — this can
take minutes.

**Fix:**

- Run it in an idle window (at night).
- Reduce the auto-VACUUM interval in `config.json` — frequent small ones beat rare
  large ones.
- Delete unneeded sessions — VACUUM on a smaller database is faster.

### The `dedcom.log` file has swollen to hundreds of MB

**Cause:** `dedcom` does not rotate its own logs.

**Fix:** use `logrotate` or trim it periodically; see
[§12 Logs](12-maintenance.md).

## ZFS

### `dedcom` does not see my pools

**Cause:** the `zfs` utility is not found in `PATH`, or it is being called by an
unprivileged user.

```text
which zfs                    # should show /usr/sbin/zfs or /sbin/zfs
sudo dedcom                  # or run as root (typical on Proxmox)
```

Related: if `zfs` is missing entirely at action time, `dedcom` refuses to act
rather than skipping its safety snapshot:

```text
`zfs` not found in the system directories (/usr/sbin, /sbin, /usr/local/sbin);
the insurance snapshot was not created, the action was cancelled
```

### `dedcom-*` snapshots have accumulated and are eating space

**Cause:** `dedcom` does NOT delete snapshots automatically — this is deliberate
(they are insurance). Over time the delta from old snapshots grows.

**Fix:**

```text
zfs list -t snapshot | grep dedcom-              # look at them
zfs destroy tank@dedcom-20260520-143215-12345-0  # delete a specific one
```

A snapshot name looks like
`<dataset>@dedcom-<YYYYMMDD-HHMMSS>-<nanos>-<pid>-<seq>`. A script for batch
cleanup older than N days is in [§03 Viewing dedcom snapshots](03-safety.md#viewing-dedcom-snapshots).

### The quarantine `.dedcom-quarantine/` is taking space on the pool

**Cause:** all the files evacuated by past applies live there, in
`<timestamp>/...` subdirectories. It is cleared **only manually**.

**Fix:**

```text
du -sh /tank/.dedcom-quarantine/*                # see what is taking how much
dedcom --purge-quarantine                        # clear EVERYTHING in all datasets
```

Or a specific timestamp:

```text
rm -rf /tank/.dedcom-quarantine/20260520-143215-0/
```

(`dedcom --purge-quarantine` clears all of it at once — there is no selective
mode.)

## When nothing helped

1. **Read `dedcom.log`** — the specific cause is usually there.
2. **`dedcom -V`** — record the version (e.g. `dedcom 0.9.0-beta.1`).
3. **`dedcom --stats`** — the state of the database and sessions; it helps you see
   what has accumulated.
4. **A test pool:** `make-test-pool.sh` (from the bundle) creates a pool on an
   image file. Reproduce the problem there so you do not risk production data.

## What's next

- [§14 Hotkeys reference](14-hotkeys.md) — the complete key reference in one
  document.
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — building from source and contributing.
