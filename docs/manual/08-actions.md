# 08. Actions — Delete / Hardlink / Reflink

Three things you can do with a duplicate. All three re-check, before acting, that
the content has not changed since the scan (revalidation); all three run under a
per-batch ZFS snapshot and route the original through quarantine for atomic
publication.

> What the snapshot and the quarantine guarantee — [§03 Data Safety](03-safety.md).
> This chapter is about the actions themselves and about revalidation. The canonical
> safety model lives in [../SAFETY.md](../SAFETY.md).

## Summary table

| Action       | Mark  | Key     | What it does                                                    | Frees space |
|--------------|-------|---------|-----------------------------------------------------------------|-------------|
| **Delete**   | `D`   | **F8**  | Moves the target into quarantine; nothing left in place         | Yes         |
| **Hardlink** | `H`   | **F5**  | In place of the target — a hardlink (same inode) to the keeper  | Yes         |
| **Reflink**  | `C`   | **F6**  | In place of the target — a separate file sharing blocks with the keeper | Yes |
| **Keeper**   | `K`   | **F7**  | The group's keeper file (one per group; not an action by itself) | —          |

For `D`/`H`/`C` to take effect, the group must have a **Keeper** assigned. Without a
keeper the actions are ignored (there is nothing for the target to be "linked" to).

## 8.1. Delete — move to quarantine

```text
A group of 3 files:
  /tank/a.bin   ← Keeper
  /tank/b.bin   ← Delete
  /tank/c.bin   ← Delete

After apply:
  /tank/a.bin                                        (unchanged)
  /tank/.dedcom-quarantine/<ts>/tank/b.bin           (was /tank/b.bin)
  /tank/.dedcom-quarantine/<ts>/tank/c.bin           (was /tank/c.bin)
```

- The target is not destroyed — it is moved into `.dedcom-quarantine/<timestamp>/...`
  (the directory structure is preserved).
- Nothing remains at the original location (as if `unlink`).
- Recovery is an `mv` of the file back out of quarantine (see [§03 Data Safety](03-safety.md#2-quarantine-instead-of-unlink)).

**When to choose Delete:**

- The files are known junk: old builds, repeated downloads, temporary copies.
- You do NOT need to preserve the file's path for other programs (that read from or
  write to that path).
- After you have verified the result, `dedcom --purge-quarantine` reclaims the space.

**What Delete does NOT do:**

- It does NOT reclaim space immediately: the file sits in a quarantine on the same
  dataset. Until `--purge-quarantine`, the space is still occupied.
- It does NOT work on a non-ZFS dataset without an explicit quarantine: if the
  automatic dataset detection by device fails (for example, a virtual filesystem
  nested inside another), the action is cancelled with the error
  `target file's dataset could not be determined`.

## 8.2. Hardlink — a shared inode to the keeper

```text
A group of 3 files:
  /tank/a.bin   ← Keeper (inode 12345)
  /tank/b.bin   ← Hardlink
  /tank/c.bin   ← Hardlink

After apply:
  /tank/a.bin   (inode 12345, link count 3)
  /tank/b.bin   (inode 12345, the same one)
  /tank/c.bin   (inode 12345, the same one)

  /tank/.dedcom-quarantine/<ts>/tank/b.bin   (was the original /tank/b.bin)
  /tank/.dedcom-quarantine/<ts>/tank/c.bin   (was the original /tank/c.bin)
```

- The target AND the keeper share **ONE inode entry** in the filesystem. Metadata
  (owner, permissions, xattr) is shared; a change made through any link is seen by
  all.
- Atomic publication: the original target is evacuated to quarantine FIRST, then the
  hardlink is published into the freed slot (see [§8.5](#85-what-hardlink-and-reflink-share--atomic-publication)).

**When to choose Hardlink:**

- The file must stay in place — other programs walk to it by path.
- The content is identical, different names/paths is fine.
- Space reclaimed = size × (N−1) for a group of N files.

**⚠️ Hardlink limitations:**

| Limitation | Details |
|---|---|
| Only within a **single dataset** | If the target and keeper are in different datasets — the error `cross-dataset hardlink is impossible — files are in different datasets`. A ZFS dataset is a separate filesystem, and a hardlink between filesystems is impossible in principle. |
| Metadata is merged | A change of permissions/owner through any path is seen by all — it is **one** inode entry. |
| A write through one path = a write for all | That is exactly what a hardlink means, but if different copies are expected to diverge, choose reflink or do NOT deduplicate them. |
| Backup software may count N paths of one inode as one file | Depends on the software (`rsync` understands this, as does GNU `cp -a`; some count each name separately). |

## 8.3. Reflink — an independent inode with shared blocks

```text
A group of 3 files:
  /tank/a.bin   ← Keeper (inode 12345, blocks B1-B100)
  /tank/b.bin   ← Reflink
  /tank/c.bin   ← Reflink

After apply:
  /tank/a.bin   (inode 12345, blocks B1-B100, owner=root, mode=0644)
  /tank/b.bin   (inode 99999, blocks B1-B100 [shared], owner=user, mode=0600 — DIFFERENT metadata is possible!)
  /tank/c.bin   (inode 99998, blocks B1-B100 [shared], ...)

  /tank/.dedcom-quarantine/<ts>/tank/b.bin
  /tank/.dedcom-quarantine/<ts>/tank/c.bin
```

- The target AND the keeper share **BLOCKS** at the pool level (ZFS `block_cloning`),
  but have **different inodes**.
- Metadata is independent (owner/permissions/xattr may differ).
- Changing the content through any path = copy-on-write of a new block; the other
  files stay as they were.

**⚠️ Reflink limitations:**

| Limitation | Details |
|---|---|
| ZFS ≥ 2.3 with `block_cloning` enabled | `zpool get all <pool> \| grep block_cloning`; the scan configuration header shows on which pools it is active. If the host does not qualify, the action is cancelled with `reflink is unavailable on this host — needs ZFS 2.3+ with block cloning enabled`. |
| The target and keeper in the **same pool** | Between datasets of the SAME pool it is fine; between different pools — the error `reflink is impossible — files are in different ZFS pools`. |
| `reflink_safe` is determined at startup | If `dedcom` did not establish at startup that `block_cloning` is safe for the pool, the action is cancelled (this is the same `reflink is unavailable …` refusal above). |

**When to choose Reflink (over Hardlink):**

- You need different metadata on the copies (owner, permissions).
- You want to freely edit one copy without affecting the others.
- The files are large images / big data, and the ability to modify them
  independently matters.

**When to choose Hardlink (over Reflink):**

- You do not need different metadata (typical for one user's personal archive).
- You want to work on a non-`block_cloning` pool.
- Your backup software can find hardlinks (`rsync --hard-links`, `tar`, and so on) —
  this saves space in the backup too.

## 8.4. Decision matrix

```text
                                 ┌─ same pool? ─ yes ─┬─ same dataset? ─ yes ─► HARDLINK or REFLINK
                                 │                    │
                                 │                    └─ no ─────────────────► REFLINK (if block_cloning)
                                 │                                              or DELETE / nothing
                                 │
target and keeper in same pool? ─┴─ no ───────────────────────────────────────► DELETE or nothing
                                                                                 (hardlink/reflink impossible)

Need different metadata on the copies?
   yes ──► REFLINK (if possible) or do NOT deduplicate
   no  ──► HARDLINK or DELETE

Must the content stay in place "forever" (external references)?
   yes ──► HARDLINK or REFLINK
   no  ──► DELETE
```

## 8.5. What Hardlink and Reflink share — atomic publication

Hardlink and Reflink use the same safe `evacuate_then_publish` pattern:

```text
step 1: build the replacement under a temporary name next to the target
        → /tank/dup.bin    (intact)
        → /tank/.dedcom-tmp-<pid>-<nanos>-<seq>-dup.bin   (new hardlink/reflink)

step 2: evacuate the original target to quarantine atomically
        → /tank/dup.bin                                     (gone)
        → /tank/.dedcom-quarantine/<ts>/tank/dup.bin       (was /tank/dup.bin)
        → /tank/.dedcom-tmp-...-dup.bin                    (intact)

step 3: publish the replacement into the freed target slot
        → /tank/dup.bin                                     (new hardlink/reflink)
        → /tank/.dedcom-quarantine/<ts>/tank/dup.bin       (original, intact)
```

All three steps are atomic at the kernel level (`renameat2(RENAME_NOREPLACE)`). If
step 3 fails (someone claimed the slot between steps 2 and 3), the original is
**automatically restored from quarantine**, with the error
`<path> changed at the moment of applying — action cancelled, original restored`.

This means: **even mid-apply** the target is never in a "lost" state — it is either
the original in place, or the original in quarantine + the replacement published.

## 8.6. Revalidation — the final check before each action

Before each destructive action, the target and the keeper are re-checked against the
hash from the last scan. If something is off, the action is cancelled with an error
and the rest of the batch continues.

### Always checked (cheap)

- **Symlink check.** If the target or the keeper has become a symbolic link — cancel.
  (This guards against a swap: someone replaced the file with a link pointing
  elsewhere.)
- **Size check.** If the size of `target`/`keeper` differs from what was recorded in
  the scan — cancel.

### Content hash — the difference between Hybrid and Strict

| Mode                           | When the content is hashed                                                    |
|--------------------------------|-------------------------------------------------------------------------------|
| **Hybrid** ◀ default           | Each distinct file — once per batch. Between actions within the batch — only a re-stat (FileIdentity = device + inode + size + mtime + ctime + mode). If `stat` matches, the content is not re-read. |
| **Strict** (`--strict-verify`) | Each file — every action. The keeper of an N-member group is read N times.     |

Hybrid behavior is safe for the "one administrator on their own pool" model: usually
only milliseconds pass between actions, so an external change in that window is
extremely unlikely (and contradicts the single-user model). Hybrid avoids the large
keeper read for big groups.

Strict is for paranoid verification: when you suspect something outside might be
editing the files concurrently.

```text
dedcom                  # Hybrid (default)
dedcom --strict-verify  # Strict
```

> A third variant, `RevalidationMode::Fast` (trust the `stat` fingerprint without
> reading), exists in the code but is **not reachable** from `main.rs` — it is a
> research stub. In practice only Hybrid and Strict are available (consistent with
> [§03 Data Safety](03-safety.md#3-revalidation-before-each-destructive-action)).

### Revalidation errors (what you will see in the Summary)

`<role>` is `target` or `keeper`.

| Message | What happened |
|---|---|
| `<role> <path> — symbolic link; action cancelled` | The file was swapped for a symlink |
| `<role> <path> changed after the scan (size) — action cancelled` | The size did not match what was recorded |
| `<role> <path> changed after the scan (content) — action cancelled` | The size matched, the hash did not |
| `<role> <path>: <io_error>` | The file is gone / no permission / the disk dropped out |

Each error affects a single action; it does not affect the rest of the batch. Every
item that was "cancelled" comes back in the file with its mark and can be reviewed
after a fresh scan.

> TOCTOU note: operations act by PATH, not by an open file descriptor, so the
> theoretical "check → act" window exists. Mitigations: the ZFS snapshot, the atomic
> publication via `renameat2(RENAME_NOREPLACE)`, a repeated symlink check at the
> moment of the action, and evacuation of the original to quarantine (recoverable). A
> full closure (`fd` + `O_NOFOLLOW`) is deliberately deferred as a disproportionate
> rework for the "one administrator on their own pool" model.

## 8.7. Cross-device — refusal

If you try to move a file (a layout, not deduplication) across a dataset boundary,
the error carries a ready-to-run hint:

```text
source and destination are on different filesystems (ZFS datasets):
/tank/foo.bin -> /tank/backup/foo.bin;
moving by copying would lose the owner/permissions/ACL/xattr, would inflate
sparse images and would break hardlinks. Move within a single
dataset or do it manually:  rsync -aHAX --sparse '/tank/foo.bin' '/tank/backup/foo.bin' && rm -f '/tank/foo.bin'
```

Why a refusal and not a silent copy: see
[§03 Cross-device](03-safety.md#6-cross-device--refusal-not-work-around-it-by-copying).

This applies to the **Triage Board** (a move, [§09](09-triage-board.md)), not to
deduplication (Hardlink requires a single dataset, Reflink a single pool, Delete acts
in place; by their own logic they never cross boundaries).

## 8.8. After apply

Right after the Summary:

1. **The ZFS snapshot remains** — `zfs list -t snapshot | grep dedcom-`. Until an
   explicit `zfs destroy`, it occupies space (only the delta from the snapshot to the
   current state).
2. **The quarantine occupies space** — every evacuated original sits on the same
   dataset in `.dedcom-quarantine/<ts>/`. Until an explicit
   `dedcom --purge-quarantine`, the space is still occupied.

A typical post-apply ritual (after a few days of calm operation):

```text
zfs list -t snapshot | grep dedcom-                # see what to remove
zfs destroy tank@dedcom-20260527-143215-512874000-4821-0   # one at a time; for each dataset
zfs destroy tank/media@dedcom-20260527-143215-512874000-4821-0
dedcom --purge-quarantine                          # reclaims all quarantines
```

The Summary lists the exact commands to run, under
`Space is freed AFTER verifying and purging with the commands:` →
`zfs destroy <snap>` / `dedcom --purge-quarantine`.

After `--purge-quarantine`, restoring the files is no longer possible (it is a final
`rm -rf`). Snapshots after `destroy` are also unrecoverable. **Wait 1–2 weeks**
before cleaning up, to be sure the result is stable.

## What's next

- [§09 Triage Board](09-triage-board.md) — moving files by hand (not deduplication).
- [§11 Headless](11-headless.md) — `--purge-quarantine` and others for cron.
- [§13 Troubleshooting](13-troubleshooting.md) — what to do if revalidation cancelled
  many actions.
