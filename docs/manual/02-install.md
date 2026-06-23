# 02. Installation and first run

DedupCommando is distributed as a single Linux binary. The recommended path is to
download a verified release from GitHub; `cargo install` and a Docker-based build from
source are also supported. The runtime platform is Linux; `zfs` should be available in
`PATH`, and you typically run as **root** (to take snapshots and scan outside `$HOME`).

## Install from a GitHub Release (recommended)

Pre-built binaries are attached to each GitHub Release for **amd64** and **arm64**. Download
the tarball for your architecture, **verify it**, then install it into `PATH`:

```sh
tar xzf dedcom-<version>-<triple>.tar.gz
sudo install -m 755 dedcom /usr/local/bin/dedcom
dedcom -V                                  # check: should print the version
```

Each release also ships a SHA-256 checksum, a CycloneDX SBOM, a minisign signature (when a
public key has been published), and a SLSA build-provenance attestation. Verifying your
download before installing is strongly recommended — see
[Verifying Releases](../VERIFYING-RELEASES.md).

## Install with cargo

If you have a Rust toolchain, you can install from the crate. This builds and installs the
`dedcom` command:

```sh
cargo install dedupcommando
dedcom -V
```

The crate is named `dedupcommando`; the installed binary is `dedcom`. DedupCommando is
**Linux-only** (it uses `libc`/`renameat2` and ZFS), so `cargo install` is supported on
Linux only.

## Build from source (contributors)

To build from source without a local Rust toolchain, use the Docker-based wrapper. It runs
the `rust:1.95.0` image, but the actual toolchain follows `rust-toolchain.toml`
(`channel = "stable"`), so it tracks current stable. Full details — including the gates your
change must pass — are in [CONTRIBUTING.md](../../CONTRIBUTING.md).

```text
pwsh scripts/build.ps1 check       # fast compile
pwsh scripts/build.ps1 clippy      # lints as a gate (-D warnings)
pwsh scripts/build.ps1 test        # unit tests
pwsh scripts/build.ps1 docs-check  # brand guard + keymap/version tests
pwsh scripts/build.ps1 release     # release binary
```

With a Rust toolchain already on Linux (MSRV **1.82**, declared in `Cargo.toml` as
`rust-version`), the
standard `cargo build` / `cargo test` / `cargo clippy` / `cargo fmt` commands work directly —
again, see [CONTRIBUTING.md](../../CONTRIBUTING.md).

> ⚠️ **Running as `root`.** Scanning directories outside `~` requires the corresponding
> permissions, so `dedcom` is typically run as `root`. If you run it as an unprivileged
> user, ZFS snapshots will be unavailable (you need `zfs allow` or sudo), and without
> snapshot safety, applying actions is **not recommended**.

### State directory

All runtime state lives in `~/.local/state/dedcom/`:

```text
~/.local/state/dedcom/
├── dedcom.db        ← SQLite checkpoint of all scans
├── dedcom.log       ← log (tracing → file; grows without rotation — see §12)
├── consent.json     ← your acceptance of the disclaimer
├── config.json      ← user preferences (concurrency policy, etc.)
├── presets.json     ← saved scan-configuration presets
├── board.json       ← Triage Board state
├── benchmarks.log   ← optional performance measurements
└── dedcom.lock      ← single-instance lock (PID + timestamp)
```

To move it elsewhere: `dedcom --state-dir /var/lib/dedcom`. This is useful when `~` is on a
thin root and the database can grow to hundreds of MB on large pools.

## First run

### 1. Startup notice (one time)

On the first run, a notice overlay opens on top of the main screen:

```text
┌─ Notice ───────────────────────────────────────────────────────────────┐
│  DedupCommando 0.9.0-beta.1                                            │
│                                                                         │
│  Notice and consent                                                    │
│                                                                         │
│  The tool works with real data of a ZFS pool.                         │
│  Moving, deletion and deduplication are irreversible —                 │
│  responsibility for the outcome lies with the user.                    │
│  Make backups and test on a test pool first.                          │
│                                                                         │
│  The version is designed for a single user: simultaneous               │
│  launch on the same state is not supported.                            │
│                                                                         │
│  ▸ [ ] I have read and agree (required)                                │
│    [ ] Don't show this at startup again                                │
│                                                                         │
│  [Enter] unavailable — check the consent box                          │
│  [Space] check   [Tab] switch focus   [Esc] exit                      │
└────────────────────────────────────────────────────────────────────────┘
```

Controls:

| Key       | Action                                                              |
|-----------|---------------------------------------------------------------------|
| **Space** | Check / uncheck the focused checkbox                                |
| **Tab**   | Switch focus between the two checkboxes                             |
| **Enter** | Continue (available only once "I have read and agree" is checked)   |
| **Esc**   | Exit `dedcom` without saving consent                                |

Minimal path: **Space** (agree) → **Enter** (continue).

The decision is written to `~/.local/state/dedcom/consent.json`, bound to the version of the
notice text (`DISCLAIMER_VERSION`). When the text changes in a new binary version, consent is
requested again — this is expected, not a bug.

### 2. Single-instance lock (if another `dedcom` is already running)

If the state directory (`~/.local/state/dedcom/`) is already held by another running
instance, a role-selection overlay appears at startup:

```text
┌─ Concurrent launch ────────────────────────────────────────────────────┐
│  Another running instance was detected                                 │
│                                                                         │
│  Operator: PID 12345, since 2026-05-27 14:23                           │
│                                                                         │
│  Working with the same state from two operators can                    │
│  corrupt data. Choose a launch mode:                                   │
│                                                                         │
│  [R] Read-only — observe the map and progress (safe)                  │
│  [F] Become operator — DANGEROUS if that process is still alive       │
│  [Esc] Exit                                                            │
└────────────────────────────────────────────────────────────────────────┘
```

| Key     | Action                                                                                  |
|---------|-----------------------------------------------------------------------------------------|
| **R**   | Open as an observer (equivalent to the `--read-only` flag). Safe.                       |
| **F**   | Seize the lock and become operator (equivalent to `--force`). See the warning below.    |
| **Esc** | Exit `dedcom`.                                                                          |

> ⚠️ **`F` / `--force` is dangerous.** The previous operator keeps running, but two processes
> must not write to the same database at once — you would overwrite each other's progress or
> results. Use it only when you are sure the previous process is dead and the lock file was
> left behind by mistake (this can happen after `kill -9` or an OOM crash).

In read-only mode, a badge stays lit in the top-right corner:

```text
                                                       ● READ-ONLY
```

Headless modes (`--scan`, `--stats`, `--compact-db`, `--export-csv`, `--purge-quarantine`)
are ALWAYS blocked when the lock is held, with no interactive prompt (there is nothing to
answer). For that reason, scripts launched from cron should not compete with an interactive
session — see [§11 Headless](11-headless.md).

### 3. Main screen

After the notice and the concurrency gate, the multi-panel Commando interface opens (the
default):

```text
┌─ DedupCommando v0.9.0-beta.1 ────────────────────────────  RAM 12.3M · CPU  0% ┐
│ Multi-panel mode                                                                │
│ ZFS: datasets 8                                                                 │
├──────────────────────────┬──────────────────────────────────────────────────────┤
│ Panel 1 · /              │ Panel 2 · /                                           │
│ ▸ bin/                   │   bin/                                                │
│   etc/                   │   etc/                                                │
│   home/                  │   home/                                               │
│   tank/                  │   tank/                                               │
│   usr/                   │   usr/                                                │
│   var/                   │   var/                                                │
│                          │                                                       │
├──────────────────────────┴──────────────────────────────────────────────────────┤
│ files: 6 · F1 Help  F9 Menu  F11 Exec  F12 Sessions                            │
└─────────────────────────────────────────────────────────────────────────────────┘
```

In the top-right corner is the RAM/CPU badge (sysmon refreshes it about once a second). In
read-only mode, the `● READ-ONLY` badge also appears, to the left of the RAM/CPU badge.

A full walkthrough of Commando is in [§05](05-commando.md); the stepwise wizard is in
[§06](06-classic.md).

## Flag summary for the first run

| Flag                       | When to use                                                                  |
|----------------------------|------------------------------------------------------------------------------|
| `dedcom`                   | Normal start. Notice + lock + Commando.                                      |
| `dedcom --classic`         | Open the stepwise wizard. Useful for getting to know the tool.               |
| `dedcom --read-only`       | A second window — "watch what the operator is doing".                        |
| `dedcom --state-dir /path` | State directory outside `~` (for example, `/var/lib/dedcom`).                |
| `dedcom --no-resume`       | Ignore the saved checkpoint and start a new scan.                            |
| `dedcom -V`                | Version.                                                                      |
| `dedcom -h`                | Full help for all flags.                                                      |

Options for scripting and automation (`--scan`, `--stats`, `--compact-db`, `--export-csv`,
`--purge-quarantine`, `--include-ext`, `--strict-verify`, `--no-hash-reuse`, `--merkle-dirs`)
have their own chapter — [§11 Headless](11-headless.md).

## What's next

→ **Before your first scan that applies actions, [§03 Safety](03-safety.md) is
required reading.** Without the safety model in mind, do not run an apply on anything other
than a test pool.

If you want to try it on a test pool right away — [§04 Quickstart](04-quickstart.md).
