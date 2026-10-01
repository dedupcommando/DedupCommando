# 03. Data Safety

This chapter answers one question: **what will save you if something goes wrong.**
Read it BEFORE you first apply actions to anything other than a test pool.

Every other chapter (Quickstart, Commando, Actions) relies on the guarantees
described here — without this picture in your head, the `F8`/`F11` keys are
dangerous.

The canonical reference for the safety model, recovery, and limitations is
[../SAFETY.md](../SAFETY.md); this chapter is the operator-facing walkthrough of
the same guardrails.

## Three classes of threat — three sets of insurance

| Threat class                                          | What parries it                                            |
|-------------------------------------------------------|-------------------------------------------------------------|
| Loss of **data** (deleted the wrong thing)            | ZFS snapshot of the batch + file quarantine + revalidation  |
| Loss of **scan result** (reboot, OOM, Esc)            | SQLite checkpoint + resume + hash reuse by `mtime`+`ctime`  |
| Corruption of **state** (two operators at once)       | Single-instance lock + `consent.json` / `dedcom.lock`       |

Each guardrail is described separately below.

## Inventory of guardrails (short summary)

### 1. ZFS snapshot of the action batch

Before the apply phase begins, `dedcom` checks every action for what would stop it
where its files are ([§8.6](08-actions.md#before-the-snapshots--can-the-action-be-carried-out-at-all))
and takes a ZFS snapshot of **every** dataset on which an action will run. An action
that cannot run is refused untouched, and a dataset where none can run gets no
snapshot; if no action of the batch can run, none is taken at all. The snapshots are
created TOGETHER (before the first action). If creating any one of the snapshots
fails — **the entire batch is aborted, no action runs.**

The snapshot name is
`<dataset>@dedcom-<YYYYMMDD-HHMMSS>-<nanos>-<pid>-<seq>`. For example:

```text
tank@dedcom-20260527-143215-512874000-4821-0
tank/media@dedcom-20260527-143215-512874000-4821-0
```

The nanosecond, PID, and sequence suffix guarantees a unique name even when two
batches land in the same second (an earlier scheme could collide with an "already
exists" error).

**What to do with these snapshots:**

- **Roll the dataset back to the moment before the batch:**

  ```text
  zfs rollback tank@dedcom-20260527-143215-512874000-4821-0
  ```

  This rolls back the ENTIRE dataset (a fundamental property of ZFS). If anything
  else wrote to the dataset after the snapshot was created, that data is lost too.

- **Destroy the snapshot once you are sure you no longer need it:**

  ```text
  zfs destroy tank@dedcom-20260527-143215-512874000-4821-0
  ```

  `dedcom` does NOT remove snapshots automatically. This is deliberate — the
  insurance stays in place until you make an explicit decision. Tidy up regularly
  (`zfs list -t snapshot | grep dedcom-`) so they do not accumulate.

### 2. Quarantine instead of unlink

When `dedcom` "deletes" a file, it does not call `unlink` — it **moves** the file
into a quarantine directory at the root of the file's own dataset (each dataset has
its own):

```text
<mountpoint>/.dedcom-quarantine/<timestamp>/<path-relative-to-dataset>
```

The `<timestamp>` matches the timestamp of the batch's snapshot. Example, with
`tank/media` a dataset of its own:

```text
/tank/media/.dedcom-quarantine/20260527-143215-512874000-4821-0/photo/IMG_0001.JPG
/tank/.dedcom-quarantine/20260527-143215-512874000-4821-0/backup/old/notes.txt
```

These are **ordinary files** on the ZFS dataset — permissions, owner, and extended
attributes are preserved. Restore is a plain `mv`:

```text
mv /tank/media/.dedcom-quarantine/20260527-143215-512874000-4821-0/photo/IMG_0001.JPG \
   /tank/media/photo/IMG_0001.JPG
```

The quarantine is also used for **atomic publication** of hardlinks/reflinks: the
original is first evacuated into quarantine, then the link is published into the
freed slot via `renameat2(RENAME_NOREPLACE)` — if anything fails midway, the
original goes back to its place, unless putting it back fails too (for example,
another file took that place in the meantime): then the original stays in
quarantine, and the Summary prints its exact path
([§8.5](08-actions.md#85-what-hardlink-and-reflink-share--atomic-publication)).

Space is reclaimed only when you purge the quarantine.

**Cleanup:** `dedcom --purge-quarantine` (reports the size; deletes only with
`--yes`, irreversible) or manually (`rm -rf` of the timestamped subdirectory). See
[§11 Headless](11-headless.md).

### 3. Revalidation before each destructive action

Immediately before each `unlink`/`link`/`clone`, every file is re-checked against
the hash from the last scan. The check always includes a symlink-swap check and a
size check. If the content changed — the action is aborted with an error ("target
changed since the scan"), and the rest of the batch continues.

Modes:

- **Hybrid** (default). Each DISTINCT file is hashed once per batch. Between
  actions within the batch, only `stat` is re-checked (a re-stat guard on
  `FileIdentity`: device, inode, size, mtime, ctime, mode). If `stat` matches, the
  file is assumed unchanged and is not re-hashed. This is ~N times faster on large
  groups (the keeper of an N-member group is not read N times).

- **Strict** (`--strict-verify`). Every destructive action triggers a full re-hash
  of both target and keeper. This was the behavior of earlier versions; use it for
  paranoid verification or when storage corruption is suspected.

Hybrid safety ≈ Strict for typical use (only milliseconds usually pass between
actions in a batch; an external change in that window is extremely unlikely). If
something else is writing to the dataset, that violates the single-operator model
in general — it is not specific to Hybrid.

> ⚠️ **Fast is not implemented.** The code contains a third variant,
> `RevalidationMode::Fast` (trust the stat fingerprint without reading), but it is
> not reachable from `main.rs` — it is a research stub. In practice only Hybrid and
> Strict are available.

### 4. Atomic publish — `renameat2(RENAME_NOREPLACE)`

File moves use `renameat2` with `RENAME_NOREPLACE`, so "does the destination
exist?" and the move itself are a single kernel operation — there is no
check-then-rename window on the destination.

### 5. Single-instance lock

The state directory (`~/.local/state/dedcom/`) holds a lock file, `dedcom.lock`,
held by the active operator via an advisory `flock`. A second operator cannot start
in parallel: on the attempt, an overlay is shown (see
[§02 Install](02-install.md)) offering a choice — `R`
read-only / `F` force-seize / `Esc` exit. The interactive message is:

```text
dedcom: another instance is already running. Run with --read-only to observe, or terminate that process.
```

Headless modes (`--scan`, `--stats`, `--compact-db`, `--export-csv`,
`--purge-quarantine`) ALWAYS block without asking when the lock is held — there is
nothing to answer interactively:

```text
write cancelled: held by another instance — terminate that process or retry with --force
```

> ⚠️ **`--force` is dangerous.** It seizes the lock, but the previous instance keeps
> running. Two processes then write to the same SQLite database and may call
> `apply_batch` simultaneously — the consequences are unpredictable. A lock is never
> left behind: the kernel releases it when its process exits, even after `kill -9`
> or an OOM kill. If the lock is held, that process is alive — find it
> (`pgrep -a dedcom`) and stop it instead of using `--force`.

### 6. Cross-device — refusal (not "work around it by copying")

If a move (a layout in the Triage Board, [§09](09-triage-board.md)) would cross a
dataset boundary, `dedcom` refuses with an error and a ready-to-run `rsync` hint:

```text
source and destination are on different filesystems (ZFS datasets):
/tank/foo.bin -> /tank/archive/foo.bin;
moving by copying would lose the owner/permissions/ACL/xattr, inflate
sparse images, and break hardlinks. Move within a single dataset or do
it manually:
  rsync -aHAX --sparse '/tank/foo.bin' '/tank/archive/foo.bin' && rm -f '/tank/foo.bin'
```

Why refusal and not a silent copy: `cp`/`fs::rename` across an FS boundary loses
owner, permissions, ACLs, and xattrs, can "inflate" a sparse image (multiplying the
space it occupies), and can break a hardlink (when a single file is moved out of a
group of links).

### Honest caveat: TOCTOU

Operations act by path, not by an open file descriptor, so a theoretical
check-to-act window exists. It is mitigated by the snapshot, the atomic publish,
the repeated symlink checks, and quarantine-based restore. A full
`fd + O_NOFOLLOW` closure is deliberately deferred for the single-administrator
model this tool targets.

## What happens if you…

### …pull the cable during **walk** (phase 1/3)

The list of walked files is saved to `dedcom.db` in chunks. Resume picks the scan
back up where it stopped (to within a `WALK_BATCH` batch of files). No actions are
taken on files in this phase — no file content is changed (access times can change
on a dataset with `atime=on`).

### …pull the cable during **hash** (phase 2/3)

Hashes are computed in chunks of 64 files; after each chunk they are written to the
database (`record_hashes` + `update_candidate_progress`). Resume continues from the
next chunk. No file content is changed (hashing only reads; access times can change
on a dataset with `atime=on`).

### …pull the cable during **group** (phase 3/3)

Grouping is done by SQL aggregation (`materialize_file_groups`) and writes no
intermediate results — on reboot this phase simply starts from scratch. The hashes
from phase 2 are intact; phase 3 on 2 million files takes on the order of seconds to
minutes, not hours. No file content is changed.

> ⚠️ **Memory peak in 3/3.** This is the most RAM-intensive phase (~2.5 KiB/file;
> on 2 million files, ~5 GiB). If RAM runs out, the OOM killer kills the process.
> Resume after an OOM picks the scan back up, but phase 3 will hit the same problem
> again: a resume keeps the algorithm the scan was started with. The fix: start it
> over with `--merkle-dirs` — `dedcom --scan /tank --merkle-dirs --no-resume`, or a
> new scan rather than a resume in the interface (memory is O(depth), not
> O(files); the hashes already read come back from the cache) — see
> [§07](07-scanning.md).

### …press **Esc** during a scan

Equivalent to the cable, but gentler: during hashing `dedcom` stops reading within
about a second, even in the middle of a large file, writes the hashes of the files
it read to the end and returns to the scan settings (or to commando, if the scan
was started there). Resume works the same way; the files it was reading get no
hash and are read again from the start.

### …pull the cable during **apply** (between actions)

This is the most interesting case — there ARE changes on the filesystem:

1. The ZFS snapshots of the affected datasets **are already created** (this is the
   first thing `apply_batch` does after planning).
2. Some actions **are already done**: the originals are in `.dedcom-quarantine/<ts>/`,
   and in their place is an `unlink` (gone) or a replacement hardlink/reflink.
3. The remaining actions are NOT done — the file_mark in the database is still
   present.

After restart:
- If you want to **roll everything back** (including the actions that were
  performed) — run `zfs rollback` on each snapshot with that timestamp:
  ```text
  zfs rollback tank@dedcom-<ts>
  zfs rollback tank/media@dedcom-<ts>
  ```
- If you want to **finish the remaining actions** — run a **new scan** of the same
  roots, mark the remaining files again and press F11. The old scan's marks are all
  still there (the file_mark is alive), but a plan built from them is refused as a
  whole: a file the batch already moved or relinked stops it with
  `… is gone since the scan — rescan required` or
  `… changed since the scan (…) — rescan required`.
- Either way, the actions already performed are NOT lost: the originals are in
  quarantine and can be restored by hand (`mv`).

### …lose the SSH connection during **apply**

A dropped SSH session hangs up the terminal: `dedcom` gets `SIGHUP` (usually twice —
from the shell and from the kernel) and every write to the screen fails from then on.
It treats that like Esc: the current action is carried through to completion, the
batch stops after it, and the program exits by itself. Nothing is drawn and no key is
read any more — there is no screen left. `dedcom.log` gets the lines

```text
the terminal is gone — finishing the current action, then exiting
exiting with error: the terminal was lost — what was running was finished before exiting
```

Reconnect, start `dedcom` again and open the scan to see where the batch stopped. If
you are back while the old process is still finishing its action, the new one stops
with `another instance is already running` — wait for that PID to exit
(`pgrep -a dedcom`).

`SIGHUP` never cuts that wait short, however often it arrives. Two `SIGTERM`s from
another session (`kill <PID>` twice) do: the process exits at once, and the action it
was running may be left halfway — the original in `.dedcom-quarantine/<ts>/`, its
replacement next to the target as `.dedcom-tmp-…`. Put the original back by hand
(`mv`). Inside the interface `Ctrl+C` is an ordinary key, not a signal. To keep the
screen across a drop, run `dedcom` over SSH inside `tmux` or `screen`.

### …`dedcom` itself fails during **apply**

An internal error (a panic) hands the terminal back to the shell and prints its message
there and in `dedcom.log`. Apply is then stopped the way Esc stops it: the current
action is carried through to completion, the batch stops after it, and the program exits
by itself with an error. Keys typed meanwhile are ignored. `Ctrl+C` is a signal again
from here on: the first one only prints a reminder, a second one exits at once and can
leave the running action half done — the original in `.dedcom-quarantine/<ts>/`, its
replacement next to the target as `.dedcom-tmp-…`. Wait for the prompt. If the panic is
in the batch itself, the action it was running stops where it was: the original is
either still in place or in `.dedcom-quarantine/<ts>/`, and a half-built replacement may
be left next to the target as `.dedcom-tmp-…` — delete it. The last line in
`dedcom.log` is one of

```text
exiting with error: the interface panicked — see the message above
exiting with error: a background thread panicked — see the message above
```

Please report the message as a bug.

### …press **Esc** during apply

The worker checks the cancellation flag **at action boundaries** (between files,
not inside one). After Esc:

- The snapshot is already taken (`ApplyPhase::Snapshots` has run).
- The actions already performed are in quarantine (as with the cable).
- The current action **is carried through to completion** — nothing kills it
  halfway, otherwise a file could be left half-evacuated. Only after the current
  action finishes is the cancellation flag checked.
- The UI shows the Summary marked "cancelled"; the partial result is correct.
- The marks of the actions that were never reached **stay** — in the panels and in
  the saved plan on disk alike, so the remaining work survives even a restart. Press
  F11 again to execute what is left. What the batch did reach loses its mark in both
  places, so a re-run never repeats it.

### …apply the wrong thing (the whole batch)

Roll the entire dataset back to the moment before the batch:

```text
zfs rollback tank@dedcom-<ts>
```

After rollback the dataset returns to its state **at the moment the snapshot was
created**. That means: everything written to the dataset AFTER the snapshot is also
lost — not just the result of `dedcom`. If the dataset has newer snapshots,
`zfs rollback` refuses unless given `-r`, which destroys those newer snapshots —
list them first with `zfs list -t snapshot <dataset>`.

If something was writing to the dataset in parallel (which violates the
single-operator model), use targeted restore instead of rollback: pull only the
files you need out of quarantine:

```text
ls /tank/.dedcom-quarantine/<ts>/    # see the structure of what was evacuated
mv  /tank/.dedcom-quarantine/<ts>/path/to/file  /tank/path/to/file
```

### …want to bring back one specific file from quarantine

Look in the quarantine of the file's own dataset — here `tank/media`, mounted at
`/tank/media`:

```text
find /tank/media/.dedcom-quarantine -type f -name 'photo.jpg'
# showed /tank/media/.dedcom-quarantine/20260527-143215-512874000-4821-0/photo.jpg
mv /tank/media/.dedcom-quarantine/20260527-143215-512874000-4821-0/photo.jpg /tank/media/photo.jpg
```

If a hardlink already occupies the path (quarantine = deletion as part of a
hardlink batch) — remove the link first, then restore the original:

```text
rm /tank/media/photo.jpg               # removes the hardlink, not the original in the group
mv /tank/media/.dedcom-quarantine/.../photo.jpg /tank/media/photo.jpg
```

### …corrupted the state with two operators

If two people ran `--force` or otherwise bypassed the lock and the database then
behaves strangely, the options are few:

1. Close both processes.
2. Back up the database just in case — not with a plain `cp`: in WAL mode the `-wal`
   file can hold committed data the main file does not. Use the procedure in
   [§12 Backing up and restoring](12-maintenance.md#backing-up-and-restoring-dedcomdb).
3. Run `dedcom --stats` to see which scans exist at all and in what status.
4. If the data in the datasets is intact and the snapshots are present (`zfs list
   -t snapshot | grep dedcom`) — only the index was hurt, not the data. You can
   delete the database (`rm dedcom.db`) and start over — the old snapshots remain as
   insurance.

This is the last line. Better not to reach it — do not run a second operator,
period.

## Working cushions (typical situations)

### A dry run on a test pool before the real one

The source repository has `scripts/make-test-pool.sh` (the release tarball and the
`.deb` do not). Run as root, with `DEDCOM_E2E_ROOT` set to an existing directory
that will hold everything it creates and `DEDCOM_E2E_OWNER_UID` to the numeric uid
that may own that directory besides root, it creates the pool `testpool` on a file
image (it does not touch real disks), mounted at
`$DEDCOM_E2E_ROOT/pools/testpool/mount`; `teardown-test-pool.sh`, with the same two
variables, removes it. It is worth running every destructive scenario on it first.

### The Idle profile on production data

When scanning a production pool with active VMs/backups — the **Idle** profile is
mandatory (F9 → "Configure and start a scan…" → the `G` key cycles through to
Idle). It hashes with one thread at the lowest CPU and disk priority (`nice 19`,
`ionice idle`); see [§07 Scanning](07-scanning.md).

### The file-panel cap in a giant group

In the commander, the file panel for a single group shows the first **200** files
(a visual cap to prevent a freeze when navigating groups of millions of files). It
does NOT affect **batch actions (F11)** — the plan is built from the database on the
full group, not from the visible panel. See [§13 Troubleshooting](13-troubleshooting.md).

### Viewing dedcom snapshots

```text
zfs list -t snapshot | grep dedcom-
```

To delete ALL `dedcom` snapshots older than N days you will need a script (`dedcom`
does not clean them up itself), for example:

```text
zfs list -H -t snapshot -o name,creation -p | grep 'dedcom-' | \
  awk -v cutoff=$(date -d '7 days ago' +%s) '$2 < cutoff {print $1}' | \
  xargs -r -n1 zfs destroy
```

## What the guardrails do NOT cover

- **Non-ZFS filesystems.** On ext4/xfs/btrfs, `dedcom` will run walk and hash, but
  it cannot take a snapshot insurance there (there is no ZFS), so it refuses delete,
  hardlink and reflink on such files: results there are for review and CSV export only.
- **You deleted a snapshot by hand and then made a mistake.** `zfs destroy` of a
  snapshot is a separate, irreversible operation. Do not destroy snapshots right
  after `apply` — wait a week or two until you are sure the result is stable.
- **You deleted the quarantine by hand and then made a mistake.** `rm -rf
  .dedcom-quarantine/<ts>` is also an irreversible operation. Same recommendations.
- **The content changed between the scan and apply.** Revalidation will abort the
  action for that specific file, but it will not warn you before you reach F11. On
  large datasets it is sensible to run apply in a maintenance window, when writing
  workloads are stopped.
- **Files that belong to another program.** Revalidation proves a file did not change since
  the scan; it cannot tell that a backup program or a virtual machine needs that file as it
  is, at its path ([§8.9](08-actions.md#89-backups-and-other-programs-stores)).
- **A disk error on the dataset.** That is a level below `dedcom`; check `zpool
  status` and run a ZFS scrub. On a damaged pool no guarantees from the tool hold.
- **Concurrent ZFS operations (send/receive/destroy).** Do not run `apply` at the
  same time as a `zfs send` of the same dataset — the snapshot is taken between them,
  but send/receive logic can conflict.

## What's next

→ [§04 Quickstart](04-quickstart.md) — try a typical scenario with all the
guardrails in action. Or [§08 Actions](08-actions.md) — a detailed description of
each action (delete / hardlink / reflink) and its side effects.
