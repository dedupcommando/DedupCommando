# DedupCommando — user manual

DedupCommando is a TUI (ratatui) for finding **byte-for-byte identical** files in
Linux ZFS pools and deduplicating them safely (delete / hardlink / reflink) under the
protection of a ZFS snapshot. The binary is `dedcom`. It was developed and tested
against ZFS pools including Proxmox VE; it runs on any Linux with ZFS.

This manual is for an operator who already deploys and maintains Linux+ZFS systems.
Internals (the database schema, how `apply_one` works) are documented in the source's
module-level comments.

## Where to start

| Goal                                            | Go to                         |
|-------------------------------------------------|-------------------------------|
| Never ran it — installing and trying it out     | 01 → 02 → 03 → 04             |
| Already installed, want to scan /tank           | §04. Quickstart               |
| Preparing a destructive run (delete/hardlink)   | §03. Safety                   |
| Script / cron — no TUI                          | §11. Headless                 |
| Something isn't working                         | §13. Troubleshooting          |
| Forgot a key                                    | §14. Hotkeys reference        |

## Table of contents

01. [Introduction](01-intro.md) — what it does, what it does NOT do, requirements
02. [Installation](02-install.md) — install, first run
03. [Safety](03-safety.md) — what will save you, what won't
04. [Quickstart](04-quickstart.md) — a typical /tank scenario in 5 minutes
05. [Commando mode](05-commando.md) — the default multi-panel interface
06. [Classic wizard](06-classic.md) — the stepwise `--classic` mode
07. [Scanning](07-scanning.md) — profiles, filters, `--merkle-dirs`, resume
08. [Actions](08-actions.md) — Delete / Hardlink / Reflink, revalidate
09. [Triage Board](09-triage-board.md) — laying duplicates out across 4 receivers
10. [Scan diff and session trash](10-diff-trash.md)
11. [Headless](11-headless.md) — CLI for scripts and cron
12. [Maintenance](12-maintenance.md) — database, retention, logs
13. [Troubleshooting](13-troubleshooting.md) — symptom → cause → fix
14. [Hotkeys reference](14-hotkeys.md) — full key reference

## One-page quickstart

The detailed version with screens is in [§04 Quickstart](04-quickstart.md). The short
form:

```text
1. Install (pick one):
     # a) Download the release binary from GitHub Releases (amd64/arm64),
     #    verify it (see ../VERIFYING-RELEASES.md), then install:
     tar xzf dedcom-<version>-<triple>.tar.gz
     sudo install -m 755 dedcom /usr/local/bin/dedcom
     # b) Or build and install from crates.io (gives the `dedcom` command):
     cargo install dedupcommando

2. First run:
     dedcom               → notice (Space → Enter) → main screen

3. Scanning:
     F9 → "Configure and start a scan…"
     Space on the roots you want; G → "Idle" (REQUIRED for production data)
     S → wait for it to finish

4. Triage (in the Browser that opens):
     F7  mark the keeper (the one that stays)
     F5  mark the rest as "hardlink to the keeper" (Hard)
     (or F8 to delete (Del), or F6 for reflink (Ref) — see §08)

5. Apply:
     F11 → confirmation → Enter → wait for the Summary

6. Rollback, if something is wrong:
     zfs rollback tank@dedcom-<ts>    # the snapshot is taken automatically
```

**Before you run your first "real" apply** — read [§03 Safety](03-safety.md) first. At a
minimum: know exactly what the ZFS snapshot does, what the quarantine is, and how to
roll back anything you didn't mean to touch.
