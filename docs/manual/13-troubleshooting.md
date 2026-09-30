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
dedcom --scan /tank --merkle-dirs --no-resume   # headless, with the memory-friendly algorithm
# or in the TUI:
dedcom --merkle-dirs                             # the flag applies to a NEW scan from this session
```

The Merkle algorithm uses O(tree depth) RAM — tens to hundreds of MB regardless
of the number of files.

> The killed scan is still unfinished, and a resume continues with **the same
> algorithm** it was started with — so start a new one: `--no-resume` with
> `--scan` (without it the flag is refused), "new" rather than "resume" in the
> interface. The hashes the killed scan already read come back from the cache.

### The scan hammers the disk and my VMs/backups slowed down

**Cause:** the `Turbo` intensity profile (or `Balanced` on a loaded pool) reads
the disk in parallel and competes with your other workloads.

**Fix:** switch to **Idle** (1 thread + nice 19 + ionice idle):

- In the TUI: F9 → scan configuration wizard → `G` until `Idle` → start.
- Headless: there is no flag for the profile, and every new `--scan` runs on
  Balanced. Run it under `nice -n 19 ionice -c 3` — see
  [§11](11-headless.md#cron-example-a-nightly-scan-of-tank).

See [§07 Intensity profiles](07-scanning.md#intensity-profiles-resource-governor).

### The hash cache is not used (a repeat scan is slow)

**Cause:** `dedcom` takes a hash from an earlier scan only for the same path with
the same size, `mtime` and `ctime`, both to the nanosecond. `device` and `inode` are
not part of the key, so a reboot or a pool import does not matter. Any other change
is a cache miss:

1. **File renamed/moved** — a new path, and `ctime` changes → **cache miss**,
   re-hash.
2. **File copied** — a new file → **cache miss**, re-hash.
3. **External software touched `mtime` or `ctime`** (`touch`, `chmod`, `chown`, a
   new hardlink, a rebuild from source, etc.) → **cache miss**, re-hash.
4. **File moved to another dataset** — a new path → **cache miss**.

**Fix:**

- Make sure `mtime` and `ctime` are stable between scans on your typical files:
  ```text
  stat -c '%n %y %z' /tank/some-file
  ```
- If something touches them, disable that process or accept the cache miss as
  unavoidable.

### `--no-hash-reuse` is off right now — but I want it on

In the TUI: scan configuration wizard → key **C** (cache toggle). Headless:
`dedcom --scan /tank --no-hash-reuse` — and `--no-resume` with it if an
unfinished scan of `/tank` is waiting: a resume keeps the cache setting it was
started with, so the flag alone is refused.

### The scan reports "0 files scanned" on a ZFS pool

**Cause:** `min_size = 4096` by default — files smaller than one filesystem block
are skipped. If all your files are tiny (config files, for example), none of them
enter the scan. Headless output simply prints `Files scanned:        0`.

**Fix:** the scan configuration wizard does not expose `min_size` — it is fixed
in code. If you need to deduplicate tiny files you have to change
`ScanConfig::new` in the source (`src/model/scan.rs`) and rebuild. For a typical
backup/media workload `min_size=4096` is the right default.

**Another cause:** the root is the mount point of a dataset that is not mounted —
an empty directory, so the scan finds nothing and finishes. When an earlier scan
of the same roots found files there, the output says `History kept: …`, and the
scans that hold those files stay out of the trash; the empty scan leaves the list
at the next trim ([§10](10-diff-trash.md)). If the root is empty on purpose, move
the kept scans to the trash yourself — nothing else retires them. Versions before
0.9.2 did trim the history against such a scan: if good scans of that root went to
the trash back then, restore them from there. Check with `zfs get mounted <dataset>`, and in cron
guard the line with `mountpoint -q` on the mount point of the dataset the root
lives on — never on a plain directory, which is never a mount point
([§11](11-headless.md)). A root that does not exist at all is refused instead
(exit code 1).

## Applying actions

### "the group <hash> has files marked for an action and no keeper — choose the file to keep"

**Cause:** a group has files marked Delete, Hardlink or Reflink, and none of its files
is the keeper. The plan is refused as a whole: nothing runs, no snapshot is taken, and
the marks stay.

**Fix:** in a GroupFiles view, mark the file to keep with **F7** (or Enter in the
classic browser), or unmark the group's files. **a** in the classic browser picks the
keepers itself — the newest file of each group — but it also marks every other file of
every group Delete, replacing the marks already set ([§8.9](08-actions.md#89-backups-and-other-programs-stores)).

### "cannot hardlink or reflink across datasets (N marks) — mark DELETE, unmark, or pick a keeper on the same dataset; first: … (HARDLINK), keeper …"

**Cause:** a file marked Hardlink or Reflink and the keeper of its group are in
different ZFS datasets. Every dataset is a filesystem of its own, and neither a
hardlink (a directory entry on the same filesystem) nor a reflink as `dedcom` makes
it (`FICLONE`, which the kernel refuses between two filesystems) can span two — not
even two datasets of one pool. The plan is refused as soon as it is built (`F11` in
the commander, the review in the classic browser): nothing is snapshotted, read or
changed, and the marks stay. `N marks` counts every mark of the plan that would
link across datasets; the first of them is named, with `REFLINK` in place of
`HARDLINK` for a reflink.

**Fix,** for each such mark, one of:

- if the group has another copy on the marked file's dataset, make that copy the
  keeper (`F7` in the commander, Enter in the classic browser) — the link then stays
  inside one dataset;
- mark the file Delete (`F8` in the commander, `d` in the classic browser) — it goes
  to quarantine, freeing space without any link to the keeper;
- unmark it (Space in either window).

### "cannot reflink on this host (N marks) — needs OpenZFS 2.2.1 or newer with zfs_bclone_enabled=1; mark HARDLINK or DELETE, or unmark; first: …"

**Cause:** this host cannot clone blocks safely: the OpenZFS version `zfs version` reports
is older than 2.2.1, or the module parameter `zfs_bclone_enabled` is 0. The scan
configuration header shows what `dedcom` found: `block cloning: supported=… enabled=…` and
`reflink: …`. The plan is refused before its confirmation opens: nothing is snapshotted,
read or changed, and the marks stay.

**Check:**

```text
zfs version
cat /sys/module/zfs/parameters/zfs_bclone_enabled
```

**Fix:** mark those files Hardlink (**F5** in the commander, **h** in the classic browser)
or Delete, or unmark them. If the version is older than 2.2.1, the parameter does not help
— upgrade OpenZFS. On 2.2.1 or newer, if you decide that block cloning is safe there, set
the parameter to 1: `echo 1 > /sys/module/zfs/parameters/zfs_bclone_enabled` until the
next boot; for good, `options zfs zfs_bclone_enabled=1` in `/etc/modprobe.d/zfs.conf` —
and where the root filesystem is on ZFS, `update-initramfs -u -k all` as well, or the old
value comes back at boot. Then restart `dedcom`: it reads the host's state once, at
startup.

### "cannot reflink on pool <pool> (N marks) — its block_cloning feature is disabled; mark HARDLINK or DELETE, or unmark; first: …"

**Cause:** the host can clone, but the pool that holds the marked file has its
`feature@block_cloning` disabled. The plan is refused before its confirmation opens, as
above.

**Check:**

```text
zpool get feature@block_cloning <pool>
```

**Fix:** mark those files Hardlink or Delete, or unmark them — or enable the feature and
restart `dedcom`:

```text
zpool set feature@block_cloning=enabled <pool>
```

Enabling a pool feature cannot be undone. Once a block is cloned, an OpenZFS older than 2.2
opens the pool read-only.

### "nothing done — N actions cannot run: …; no snapshot taken, marks kept; first: …"

**Cause:** every action of the batch was refused by the checks made before the snapshots
([§8.6](08-actions.md#before-the-snapshots--can-the-action-be-carried-out-at-all)); the reason
printed is the first action's. Nothing was snapshotted, read or changed; the plan went
back to its confirmation, and the marks stay. When only some actions cannot run, the
others run as usual and the Summary lists each refused one with its reason.

**Fix,** by the reason — then confirm again:

- `read-only filesystem (<dataset>)` — `zfs get readonly <dataset>`; turn it off
  (`zfs set readonly=off <dataset>`) or unmark the files there.
- `no space left on <dataset> (full pool or quota)` — less than one record is free:
  `zfs get quota,refquota,available,recordsize <dataset>`. Free some space or raise the
  quota. A Delete does not help here — the file only moves to a quarantine on the same
  dataset.
- `the quarantine cannot be made in …: it is immutable (chattr +i)`,
  `the directory is immutable (chattr +i)`, `the directory is append-only (chattr +a)`,
  `the file is immutable (chattr +i)`, `the file is append-only (chattr +a)` —
  `lsattr -d <path>`; clear the flag (`chattr -i`, `chattr -a`) or unmark the file.
- `the keeper is immutable (chattr +i)`, `the keeper is append-only (chattr +a)` — the
  kernel refuses a hardlink to such a file: clear the flag on the keeper, or mark the file
  Reflink or Delete instead.
- `reached through another mount of <dataset> (a bind mount?)`,
  `the keeper is reached through another mount (a bind mount?)` — the scan went through a
  second mount of the dataset: scan the dataset at its own mountpoint and mark the files
  there. For the keeper, a Reflink does not mind.
- `outside the mountpoint of <dataset> (…)` — the path does not begin with the dataset's
  mountpoint: the scan went through a bind mount, a symbolic link or a relative root
  (`--scan ./data`, `/data → /tank/data`). Scan the dataset at its own mountpoint.
- `target file's dataset could not be determined` — the file is not on a ZFS dataset the
  host reported when `dedcom` started: a non-ZFS filesystem, or a dataset mounted later
  (restart `dedcom`).

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

### "dedcom: N of M actions not carried out — each is named above" (a saved script)

**Cause:** a script saved with `S` in the `F11` overlay went on past the actions it could
not carry out and ended with exit status 1. Each of them has its own line above this one,
after the line that gives the reason: the line of the tool that failed (`cmp`, `mv`, `ln`,
`cp`, `findmnt`) or, for a quarantine on another mount, the script's own. None of these lines
means a file was lost:

| Line | What happened |
|---|---|
| `skip …: it or its keeper is a symbolic link` | One of the two was replaced by a symbolic link after the script checked the plan; both were left alone. |
| `skip …: its content is no longer the keeper's` | The file was rewritten after the scan and was left alone. |
| `skip …: it could not be compared with its keeper` | `cmp` could not read one of the two; the file was left alone. |
| `skip …: its dataset was not determined` | As in ["target file's dataset could not be determined"](#target-files-dataset-could-not-be-determined); nothing was done. |
| `…: the quarantine is on another mount than the file (a bind mount?)` | The file is reached through a second mount of its dataset — a bind mount — or the quarantine directory is a link to another filesystem, and a move there would copy the file and delete it. Nothing was moved; scan the dataset at its own mountpoint. The next line names the action. |
| `not moved to the quarantine: …` | A Delete could not move the file: a read-only dataset, `chattr +i` or `+a`, no space or quota, a file already at its place in the quarantine, or a quarantine on another mount (the line above). The file is where it was. |
| `not replaced: … — the link could not be made beside it` | `ln` failed: too many links, an immutable keeper, a second mount of the dataset. The file is where it was. |
| `not replaced: … — the clone could not be made beside it` | The host or the pool cannot clone ([§8.3](08-actions.md#83-reflink--an-independent-inode-with-shared-blocks)), or the copy came out short. The file is where it was. |
| `not replaced: … — its owner, mode, times or extended attributes could not be carried over` | The script ran as a user who may not give the copy the file's owner. The file is where it was; run the script as root. |
| `not replaced: … — it could not be moved to the quarantine` | As for a Delete, before anything took the file's place. |
| `not replaced: … — the replacement could not be published; the original is back in its place` | The last rename failed, and the file was put back. |
| `not replaced: … — the replacement could not be published; the original stays in the quarantine: …` | The file could not be put back either; it is at the path the line ends with. |
| `…: the temporary file .dedcom-….tmp beside it is left behind — delete it by hand` | The script removes only a replacement it made itself, and this file was no longer that one. |

**Fix:** remove the cause the tool's own line names, scan again and apply the new plan. A
script that carried out any action refuses to run a second time: its structural check sees
the files it changed. A file left in the quarantine goes back with
`mv -n -- '<path in the quarantine>' '<its place>'` while its place is free; look at a
left-behind `.dedcom-….tmp` before you delete it.

## Concurrency and locking

### "another instance is already running" — but I'm sure it isn't

**Cause:** another `dedcom` process is still running and holds the lock — a
`--scan` from cron, a session left open in `tmux`, `screen` or another SSH
window, or a session whose SSH connection has just dropped and that is finishing
the action it was running ([§03](03-safety.md#lose-the-ssh-connection-during-apply)).
The lock is an advisory `flock` on `dedcom.lock`, and the kernel releases
it the moment its process exits, even after an OOM kill or `kill -9`: it is never
left behind. The interactive message is:

```text
dedcom: another instance is already running (PID 12345, since 2026-06-20 14:32:15).
Run with --read-only to observe, or terminate that process.
```

**Fix:**

```text
# find the process that holds the lock (the message names its PID too):
pgrep -a dedcom
fuser -v ~/.local/state/dedcom/dedcom.lock

# let it finish, or stop it (an apply finishes its current action first):
kill <PID>
dedcom                                          # start again
```

Never delete `dedcom.lock` to get past the message: the running process keeps its
lock on the deleted file, the next `dedcom` locks a new one, and two writers then
work on the same state.

To only observe the running instance without touching the lock, start with
`dedcom --read-only`. An alternative is the `--force` flag, but it does not stop
the other process — it **seizes** the state on top of it, and two operators then
write at once.

### Headless from cron does not run, it says "cancelled"

**Cause:** an interactive `dedcom` was running when the cron job started. Under
the `ask` concurrency policy, headless behaves like `block` (there is no UI to
ask the question), so it simply refuses to start. The headless message is:

```text
write cancelled (PID 12345, since 2026-06-20 14:32:15): held by another instance
— terminate that process or retry with --force
```

(If the cron line itself carries `--read-only`, the message says so instead:
`write cancelled: --read-only given, and this mode runs as the operator — run it
without --read-only`.)

**Fix:**

- Run cron at a different time.
- Or set `"concurrency": "block"` in `config.json` explicitly — the behavior is
  unchanged, but explicit.
- As a last resort, retry with `--force` to seize the state — only do this when
  you are certain no other instance is actually writing.
- Do NOT set `"concurrency": "allow"` for cron — that would write to the database
  in parallel with the TUI and **corrupt your data**.

## TUI

### F11 does nothing — the terminal window just goes fullscreen

**Cause:** F11 is the fullscreen shortcut in GNOME Terminal, Konsole, Windows
Terminal and xfce4-terminal, and F10 opens their menu. The terminal consumes the
key; `dedcom` never receives it. Nothing is wrong with the marks.

**Fix:** any of these does the same thing as F11:

```text
x              # execute the marked actions
` then -       # the prefix key, then the digit-row key of F11
F9 → "Execute marked actions (F11 or x)"
```

The prefix works for the whole first layer: `` ` `` then `1`…`9` = F1…F9,
`` ` `` `0` = F10, `` ` `` `-` = F11, `` ` `` `=` = F12. A click on the footer cell
also runs the command, but that needs mouse reporting (in tmux: `set -g mouse on`).
A click does nothing while the startup notice, the role-selection overlay, help, an
F-key window or a yes/no question is open: close it first.

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

The `s` key does not change which 200 are shown: it sorts a files panel, and GroupFiles
always takes a group's first 200 files in path order.

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
automatically (see [§12 Retention](12-maintenance.md)). Scans kept for a root that
turned up empty (`History kept: …`) are not trimmed by it — move them yourself.

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
dedcom --purge-quarantine                        # list what would be removed
dedcom --purge-quarantine --yes                  # clear EVERYTHING in all datasets
```

Or a specific timestamp:

```text
rm -rf /tank/.dedcom-quarantine/20260520-143215-0/
```

(`dedcom --purge-quarantine --yes` clears all of it at once — there is no
selective mode.)

## When nothing helped

1. **Read `dedcom.log`** — the specific cause is usually there.
2. **`dedcom -V`** — record the version (e.g. `dedcom 0.9.0-beta.1`).
3. **`dedcom --stats`** — the state of the database and sessions; it helps you see
   what has accumulated.
4. **A test pool:** `scripts/make-test-pool.sh` from the source repository (not in
   the release tarball or the `.deb`) creates a pool on an image file
   ([§03](03-safety.md#a-dry-run-on-a-test-pool-before-the-real-one)). Reproduce the
   problem there so you do not risk production data.

## What's next

- [§14 Hotkeys reference](14-hotkeys.md) — the complete key reference in one
  document.
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — building from source and contributing.
