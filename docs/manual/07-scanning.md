# 07. Scanning

A scan runs as three sequential phases. When it finishes, the result is stored
in `dedcom.db` and becomes available for review in the Browser / Commando.

```text
walk (1/3) ──► hash (2/3) ──► group (3/3)
tree walk      BLAKE3          group assembly
               + cache         + directory
                               signatures
```

| Phase | What it does                                              | Time on 2 M files | Memory |
|-------|-----------------------------------------------------------|-------------------|--------|
| 1/3 Walking | Walk the tree; `lstat` each entry; write to the DB  | minutes           | tens of MB |
| 2/3 Hashing | BLAKE3 of each candidate; read by `(dev,inode)`     | hours (on HDD)    | tens of MB |
| 3/3 Grouping| SQL aggregation into groups + directory signatures  | seconds–minutes   | ~2.5 KiB/file = GiB |

Phases 1 and 2 stream and checkpoint progress in chunks — you can interrupt and
resume. Phase 3 is a single transient memory peak; if RAM is tight, see
`--merkle-dirs` below.

## Intensity profiles (Resource Governor)

In the scan configuration wizard the **G** key cycles the profile:

```
Turbo → Balanced → Idle → Turbo
```

| Profile   | Hint                                              | Read threads    | Priority                  |
|-----------|---------------------------------------------------|-----------------|----------------------------|
| **Turbo**     | all cores, disk at full                       | `nproc`         | default                    |
| **Balanced** ◀ default | 2 threads, no seek-thrash            | `min(2, nproc)` | default                    |
| **Idle**      | 1 thread, nice+ionice idle                    | 1               | `nice 19` + `ionice idle`  |

> ⚠️ **Idle is mandatory on live data.** A concurrent VM or backup will only see
> the dedup run when the disk is idle (the `ionice idle` class on Linux). Turbo
> on `/tank` with running VMs means they slow down for the whole duration of the
> scan.

The profile is persisted in the scan's checkpoint DB — resume uses the same
profile (a CLI flag change is not applied to an already-running session).

## Filters

### By size

`ScanConfig.min_size` (default **4096 bytes**) — smaller files are skipped.
There is little point in deduplicating files smaller than one filesystem block
(the gain is smaller than the hardlink/reflink overhead).

`ScanConfig.max_size` (no default) — if set, larger files are skipped. Not yet
configurable in the UI; change it in the code/checkpoint.

### By extension

The CLI flag **`--include-ext`** (repeatable, comma-separated):

> `--include-ext <LIST>` — Scan only files with these extensions
> (comma-separated: jpg,png,gif; flag repeatable)

Case is ignored and the leading dot is stripped:

```text
dedcom --scan /tank/media --include-ext jpg,heic,raw
dedcom --scan /tank/media --include-ext jpg --include-ext heic
```

In the TUI a preset is chosen with **P** in the scan configuration wizard.
Presets are defined in the code — typical groups (media, documents, and so on).

An empty filter (the default) means all files are scanned.

### Permanent exclusions

Always skipped:

- `**/.zfs/**` — ZFS snapshots (reading them is suboptimal, and they are
  read-only).
- `**/.dedcom-quarantine/**` — our own quarantine (we don't deduplicate
  ourselves).

Additional `exclude_globs` can be set in the code/checkpoint; not yet
configurable in the UI.

## Hash cache (`hash_cache`)

The DB holds a `hash_cache` table keyed by `(device, inode, size, mtime)` — on a
repeat scan of the same file, if those four attributes are unchanged, BLAKE3 is
not recomputed but taken from the cache.

| Enabled | Repeat-scan speed | When to disable                                |
|---------|-------------------|------------------------------------------------|
| ON (default) | Tens of seconds per million files (all from cache) | Never in normal use |
| OFF | Full re-hashing of all files | Suspicion that external software changes content without updating `mtime` |

| How to disable | Where |
|---|---|
| Persistently (for one scan) | TUI: **C** in the scan configuration wizard |
| For headless | `dedcom --scan /tank --no-hash-reuse` |

The flag's help string:

> `--no-hash-reuse` — Disable the hash cache — re-hash all files

> The cache survives a reboot (the `stat` fields are stable). It does not
> survive: a rename by external software (`mv` keeps the inode, but `ctime`
> changes — irrelevant to us, we look only at `mtime`), a copy (a new inode = a
> cache miss), a filesystem change.

## Directory-signature algorithm

After files are hashed, phase 3/3 builds **directory signatures** — a hash of a
directory's entire contents. Two directories with the same signature are
"twin folders" (see [§05 Commando](05-commando.md)).

There are two algorithms:

### Default — `build_dir_groups`

Top-down recursion: each directory keeps its signature together with the list of
its child nodes in memory.

| Property            | Value                                                      |
|---------------------|------------------------------------------------------------|
| Memory              | ~2.5 KiB per hashed file (on `/tank`, gigabytes)           |
| Speed               | Faster on typical trees                                    |
| Group hex value     | Stable, readable                                           |

On large pools (millions of files) **this is a transient memory peak for the
whole program.** On a 2.12 M-file pool the peak was +4.35 GiB.

### Merkle — `--merkle-dirs` (opt-in)

A streaming Merkle hash bottom-up: each directory is hashed once and frees its
child nodes' memory immediately.

| Property            | Value                                                      |
|---------------------|------------------------------------------------------------|
| Memory              | O(tree depth) — tens to hundreds of MB                     |
| Speed               | Comparable to the default (the streaming overhead is minimal) |
| Group hex value     | Different (a Merkle hash), but the **group membership is identical** to the default |

The flag's help string:

> `--merkle-dirs` — (opt-in) streaming-Merkle directory signature: O(depth)
> memory instead of ~2.5 KiB/file. Group membership is identical to the default;
> per-row hex differs. Persisted in the checkpoint — resume uses the same
> algorithm.

```text
dedcom --merkle-dirs                    # TUI with Merkle for the next scan
dedcom --scan /tank --merkle-dirs       # headless
```

> **When you need `--merkle-dirs`:** on a host where `~2.5 KiB × file_count` is
> close to free RAM or exceeds it. Before phase 3/3 dedcom prints a forecast and
> compares it with free RAM — if you get a red warning, or a previous scan was
> killed by OOM on 3/3, turn it on.

The algorithm is persisted in the checkpoint — resume uses the same one.

### Estimating the 3/3 memory peak (for the default algorithm)

`phase_3/3_peak ≈ files × 2.5 KiB`

| Files hashed | Phase-3/3 peak (default) | Decision        |
|-------------:|--------------------------|-----------------|
|      250,000 | ~0.6 GiB                 | fine             |
|    1,000,000 | ~2.4 GiB                 | check free RAM   |
|    2,000,000 | ~4.8 GiB                 | compare with RAM; `--merkle-dirs` likely needed |
|    5,000,000 | ~12 GiB                  | `--merkle-dirs` **required** |

After phase 3/3 the memory is returned to the OS — it is a transient peak. After
showing the result the UI holds hundreds of MB.

## Byte-by-byte comparison (`--verify`)

After hashing, each duplicate group can additionally be compared byte by byte (a
guard against a theoretical BLAKE3 collision):

The flag's help string:

> `--verify` — Byte-by-byte comparison after hashing

```text
dedcom --scan /tank --verify
```

It doubles the scan time (each file is read twice: hash + comparison). In
practice a BLAKE3 collision has never been observed on real data and this check
is redundant — but if you are paranoid, the flag enables it.

## Re-validation before actions (`--strict-verify`)

This is a **different** check — not during the scan, but **before every apply
action**. By default the mode is **Hybrid**: the keeper is hashed once per
batch, the remaining checks go through a re-stat on `FileIdentity`. With the flag
the mode is **Strict**: full re-hashing of target and keeper before every
destructive operation.

The flag's help string:

> `--strict-verify` — Re-validate before an action: re-hash target and keeper
> every time (default Hybrid — keeper once per batch)

```text
dedcom --strict-verify      # for all applies in this session
```

Details — [§08 Actions](08-actions.md).

## Resume — continue an unfinished scan

A scan is saved into `dedcom.db` in chunks:

- **Walking** — after every batch of `WALK_BATCH` files.
- **Hashing** — after every chunk of 64 files (`HASH_CHUNK`).
- **Grouping** — NOT saved (the phase is atomic; a crash = re-running phase 3
  from scratch, but the hashes are intact).

`ScanStatus` in the DB:

| Status       | Meaning                                             | Resume? |
|--------------|-----------------------------------------------------|---------|
| **Walking**  | Interrupted in phase 1                               | ✅       |
| **Hashing**  | Interrupted in phase 2                               | ✅       |
| **Complete** | Scan finished (including phase 3)                   | —       |
| **Aborted**  | Interrupted after phase 3 or an invariant was broken | ❌ — new scan |

On the next start of the wizard for the same roots, a Resume overlay appears (see
[§05 Commando](05-commando.md)) offering "resume / open the last completed / start
a new one".

> **What does NOT survive a resume:**
> - A change of the root set (`resume_probe_for_roots` compares exactly).
> - A change of `min_size` or the extension filter (new files could enter the
>   scan).
> - Deleting `dedcom.db` or the state directory.
> - All CLI flags that affect the config (`--merkle-dirs`, `--no-hash-reuse`,
>   `--include-ext`, the profile): they apply ONLY at the start of a new scan; on
>   resume the values are read from the checkpoint and the command-line flags are
>   ignored.

## Storage-type override (`--storage-type`)

DedupCommando auto-detects a dataset's storage type (HDD / SSD / NVMe) for:

- the read order in phase 2 (for HDD: sorting candidates by `(device, inode)` —
  −21% off the cold-scan time on 2×HDD, by reducing seeks; not needed for
  SSD/NVMe);
- statistics (`--stats` shows the type on the scan line).

If auto-detection is wrong (for example, the host is in a VM and the disks are
reported as SSD but are in reality HDD-backed) — override it:

The flag's help string:

> `--storage-type <TYPE>` — Storage type for statistics: hdd | ssd | nvme
> (overrides auto-detection)

```text
dedcom --scan /tank --storage-type hdd       # force the HDD strategy
dedcom --scan /tank --storage-type ssd
dedcom --scan /tank --storage-type nvme
```

Not configurable in the TUI — CLI only.

## Messages and warnings during a scan

`ScanProgress::Notice(String)` — the Scanning screen and `dedcom.log` print
additional messages, the most important being:

- **"Phase 3/3 peak estimate: X GiB, free: Y GiB"** — the `files × 2.5 KiB`
  calculation from the phase-2 results vs `available_ram_bytes`. If X > Y it is
  printed in yellow: a risk of OOM, and you are advised to interrupt (Esc) and
  restart with `--merkle-dirs`.

## Summary — typical flag combinations

| Scenario                                          | Command                                                           |
|---------------------------------------------------|-------------------------------------------------------------------|
| Scan `/tank`, gently (live VMs)                   | TUI: F9 → scan configuration wizard → Space tank → G to Idle → S  |
| Scan `/tank`, headless from cron                  | `dedcom --scan /tank` (profile defaults to Balanced; for cron, set Idle once via the TUI — it persists in the checkpoint) |
| Large pool, little RAM                            | + `--merkle-dirs`                                                  |
| Doubts about hash integrity                       | + `--verify` (2× slower)                                           |
| Suspicion that external software changes content  | + `--no-hash-reuse`                                                |
| Media only                                        | + `--include-ext jpg,heic,mp4,mov`                                 |
| Paranoid apply                                    | `dedcom --strict-verify` (at TUI launch)                           |
| VM with wrong storage auto-detection              | + `--storage-type hdd`                                             |

## What's next

- [§08 Actions](08-actions.md) — what happens after `apply`.
- [§11 Headless](11-headless.md) — `--scan` in cron, exit codes, output format.
- [§13 Troubleshooting](13-troubleshooting.md) — what to do on an OOM in phase
  3/3, and so on.
