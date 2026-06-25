# DedupCommando

> **⚠️ Beta (v0.9.0-beta.1).** DedupCommando performs destructive operations (delete, hardlink, reflink)
> on real files. Read **[docs/SAFETY.md](docs/SAFETY.md)** before applying any action, and keep backups.

**DedupCommando** is a Linux terminal UI for finding and safely deduplicating byte-for-byte identical
files, built for ZFS pools and tested on Proxmox VE 9.1 (OpenZFS 2.3). The command is **`dedcom`**.

Data safety comes first: every destructive batch runs under a ZFS snapshot, "deleted" files are moved to a
quarantine instead of being unlinked, and file content is re-validated immediately before each action.

## Features

- **Three reclaim actions:** delete-to-quarantine, **hardlink** (same dataset), and **reflink** / CoW
  block-clone (ZFS `block_cloning`).
- **Exact matching** via BLAKE3 hashing, with an optional byte-for-byte re-compare (`--verify`).
- **Directory dedup ("twin folders")** — find directory trees whose scanned contents are recursively identical.
- **Two interfaces:** a multi-panel "commander" (default) or a classic stepwise wizard (`--classic`).
- **Resumable scans** with on-disk checkpoints and a hash cache for near-instant re-scans.
- **Headless scan mode** for cron, plus CSV export and stats.
- **Resource governor** (Turbo / Balanced / Idle) so a scan won't starve VMs or backups on a busy host.

It intentionally does **not** do: compression, ZFS block-level dedup (`zfs set dedup`), fuzzy/perceptual
matching, or background daemon/watch indexing. Linux only.

## Requirements

- **Linux**, kernel ≥ 3.15 (requires `renameat2`). x86_64 or aarch64.
- **Pre-built packages need glibc ≥ 2.39** — Debian 13 (trixie), Ubuntu 24.04, or Proxmox VE 9 or newer.
  On older systems (e.g. Proxmox VE 8 / Debian 12), build from source.
- **ZFS strongly recommended** — snapshot safety, dataset detection and reflink depend on it. On non-ZFS
  filesystems scanning works, but applying actions has **no snapshot safety and is not recommended**.
- `zfs` available in `PATH`; typically run as **root** (to take snapshots and scan outside `$HOME`).
- A UTF-8, 256-color terminal.

## Install

> The commands below assume you are **root** — the default on Proxmox VE, which ships without `sudo`. On a non-root Debian login, run `sudo -i` first (or prefix each command with `sudo`).

**Debian / Proxmox VE — APT repository** (recommended; updates via `apt upgrade`):

```sh
curl -fsSL https://dedupcommando.github.io/apt/dedcom-archive-keyring.gpg \
  -o /usr/share/keyrings/dedcom-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/dedcom-archive-keyring.gpg] https://dedupcommando.github.io/apt stable main" \
  | tee /etc/apt/sources.list.d/dedcom.list
apt update && apt install dedcom
```

**Any Linux — GitHub Release tarball** (**verify it** first, see [docs/VERIFYING-RELEASES.md](docs/VERIFYING-RELEASES.md)):

```sh
tar xzf dedcom-<version>-<triple>.tar.gz
install -m 755 dedcom /usr/local/bin/dedcom
```

Both pre-built channels need glibc ≥ 2.39 (Debian 13 / Ubuntu 24.04 / Proxmox VE 9+). To build from source
(Docker-based, no local Rust toolchain needed — works on older systems too), see [CONTRIBUTING.md](CONTRIBUTING.md).
A `cargo install dedcom` is planned once the crate is published.

## Quickstart

```sh
dedcom              # multi-panel commander (default)
dedcom --classic    # classic stepwise wizard
dedcom --read-only  # read-only observer (e.g. a second window)
dedcom -V           # print version
dedcom -h           # all options
```

On first run, `dedcom` shows a one-time safety disclaimer. A typical session: **F9 → "Configure & run a
scan"**, select roots (`Space`), choose an intensity profile (`G` cycles Turbo / Balanced / **Idle**), and
start (`S`). After the scan, review duplicate groups, mark a **keeper** (`F7`) and actions (`F5` hardlink /
`F6` reflink / `F8` delete), then **`F11`** to review and apply — or save the plan as a shell script.

Headless mode scans only (applying actions is interactive by design — see [Limitations](docs/SAFETY.md#limitations)):

```sh
dedcom --scan /tank                 # scan and write checkpoints
dedcom --stats                      # print scan + database stats
dedcom --export-csv groups.csv      # export the last scan's groups to CSV
dedcom --purge-quarantine [--yes]   # report quarantine size; deletes only with --yes
```

State (the `dedcom.db` checkpoint database, logs, config) lives in `~/.local/state/dedcom`
(override with `--state-dir`).

## Safety — read before applying

DedupCommando is designed to be safe on production data, but it relinks and removes real files. The core
guardrails (full detail in **[docs/SAFETY.md](docs/SAFETY.md)**):

- A **ZFS snapshot** is taken of every dataset the batch touches *before* the first action; if any snapshot
  fails, the **entire batch is aborted**.
- **"Delete" moves files to a per-dataset quarantine**, not `unlink` — reversible until you explicitly purge.
- Content is **re-validated** (re-hash / re-stat) before each destructive action; a mismatch aborts that action.
- Files are published atomically with **`renameat2(RENAME_NOREPLACE)`** — no check-then-rename race.
- A **single-instance lock** prevents concurrent writers; cross-dataset moves are **refused**, never a silent
  copy-and-delete.

Recovery (restore from quarantine, snapshot rollback) is documented in [docs/SAFETY.md](docs/SAFETY.md).

## Memory use on large pools

Scan phases 1–2 (walk, hash) stream with low memory. Phase 3 (grouping) transiently holds in-RAM structures,
roughly **(hashed files) × ~2.5 KiB** at peak (freed when the phase ends):

| Hashed files | Approx. phase-3 peak |
|-------------:|----------------------|
|      250,000 | ~0.6 GiB             |
|    1,000,000 | ~2.4 GiB             |
|    2,000,000 | ~4.8 GiB             |

`dedcom` estimates this against free RAM before phase 3 and warns when there's a risk of OOM. The
`--merkle-dirs` option computes directory signatures in O(depth) memory instead.

## Documentation

- **[docs/SAFETY.md](docs/SAFETY.md)** — safety model, recovery, and limitations (read this).
- **[docs/VERIFYING-RELEASES.md](docs/VERIFYING-RELEASES.md)** — checksums, signatures, SBOM, attestation.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — building from source and contributing (DCO).
- **[docs/manual/](docs/manual/)** — full user manual: install, data safety, scanning, actions, the Commando and Classic interfaces, headless/cron, maintenance, troubleshooting, and a hotkeys reference.

## Contributing

Contributions are welcome under Apache-2.0, with a **Developer Certificate of Origin** sign-off on every
commit (`git commit -s`). There is no CLA. See **[CONTRIBUTING.md](CONTRIBUTING.md)**. Please report security
vulnerabilities **privately** — see **[SECURITY.md](SECURITY.md)**.

## License

**Apache-2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Denis "DeQuzzy" Kuznetsov.
Bundled third-party components and their licenses are listed in [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).

## Trademarks

"Proxmox" is a trademark of Proxmox Server Solutions GmbH; this project is independent and not affiliated with
or endorsed by them. "ZFS" / "OpenZFS" belong to their respective owners. DedupCommando is an independent
project and is not affiliated with any similarly named product.

For the project's full name-usage and trademark policy, see **[TRADEMARKS.md](TRADEMARKS.md)**.
