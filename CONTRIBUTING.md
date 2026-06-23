# Contributing to DedupCommando

Thank you for your interest. DedupCommando is a **data-safety-critical** tool — it deletes and relinks real
files — so changes on the write path (`src/actions/`, `src/zfs/`, scanning/hashing) receive extra review and
should come with tests.

## License and DCO (required)

- Contributions are accepted under **Apache-2.0** (the project's license).
- **Every commit must be signed off** under the Developer Certificate of Origin
  (DCO 1.1, <https://developercertificate.org>). Add the sign-off with `git commit -s`, which appends a
  `Signed-off-by: Your Name <you@example.com>` line. CI rejects pull-request commits that lack it. There is
  **no CLA**.

## Building and testing

DedupCommando is **Linux-only** (it uses `libc`/`renameat2` and ZFS). With a Rust toolchain on Linux
(MSRV **1.82**; see `rust-toolchain.toml`), the standard commands work:

```sh
cargo build --all-targets
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Maintainers also use a Docker wrapper (cross-platform PowerShell). It runs the `rust:1.95.0` image, but the
actual toolchain follows `rust-toolchain.toml` (`channel = "stable"`), so it tracks **current stable** rather
than being pinned to 1.95.0 — true pinning would require pinning `rust-toolchain.toml` itself:

```sh
pwsh scripts/build.ps1 check | test | clippy | release | docs-check
```

## Gates your PR must pass (same as CI)

- build + tests on **amd64 and arm64**
- `cargo fmt --all -- --check` — **rustfmt is enforced** (run `cargo fmt` before committing)
- `cargo clippy --all-targets -- -D warnings` — **zero warnings**
- `cargo deny check` — dependency licenses / advisories / bans / sources
- contamination scan + `gitleaks` secret scan
- DCO sign-off on every commit

## Style

- rustfmt is the formatter (canonical `rustfmt.toml`). A few stylistic clippy lints are documented as
  crate-level `#![allow]`s in `src/main.rs`; if you must allow a lint, keep it local and justify it.
- Match the surrounding code, and keep comments meaningful.

## Pull requests

- One logical change per PR; branch from the default branch.
- Explain *what* changed and *why*; link any related issues.
- For write-path / ZFS / safety changes: keep them focused, document the reasoning, and add tests.
- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Reporting security issues

Please **do not** open public issues for vulnerabilities — use the private channel described in
[SECURITY.md](SECURITY.md).
