# Build the Linux `dedcom` binary in Docker (no Rust toolchain needed on the Windows host).
#
# Usage:
#   .\scripts\build.ps1            # release build
#   .\scripts\build.ps1 check      # fast compile check
#   .\scripts\build.ps1 build      # debug build
#   .\scripts\build.ps1 test       # run unit tests
#   .\scripts\build.ps1 clippy     # clippy lints as a gate (-D warnings, zero warnings)
#   .\scripts\build.ps1 docs-check # docs anti-drift (keymap/version) + competitor-brand guard
#
# Resulting binary: target\release\dedcom (release mode)
# or target\debug\dedcom (debug).

param([string]$Mode = "release")

$ErrorActionPreference = "Stop"
$proj = (Resolve-Path "$PSScriptRoot\..").Path

# The Docker image tag is pinned (not rust:latest) for a stable base. NOTE: this does NOT pin the
# Rust compiler — rust-toolchain.toml (channel = stable) overrides the image, so the actual
# toolchain is whatever "stable" currently is (e.g. 1.96.x), not 1.95.0. Truly pinning the compiler
# would require pinning rust-toolchain.toml. Bump the image tag deliberately.
$image = "rust:1.95.0"

$cargoCmd = switch ($Mode) {
    "check"      { "cargo check" }
    "build"      { "cargo build" }
    "release"    { "cargo build --release" }
    "test"       { "cargo test" }
    # The stock rust image doesn't ship the clippy component — install it before running.
    "clippy"     { "rustup component add clippy >/dev/null 2>&1; cargo clippy --all-targets -- -D warnings" }
    "docs-check" { "if grep -rniE 'norton|midnight|rmlint|meld|winmerge|czkawka|fclones|fdupes' src Cargo.toml; then echo 'BRAND LEAK: competitor brand name in src/Cargo'; exit 1; fi; cargo test -- keymap_tests version_tests" }
    default      { throw "mode must be: check | build | release | test | clippy | docs-check" }
}

$ver = (Get-Content (Join-Path $proj "VERSION") -Raw).Trim()
Write-Host "[build.ps1] version $ver · $cargoCmd  (image $image, Docker)"

docker run --rm `
    -v "${proj}:/work" -w /work `
    -v dedcom-cargo-registry:/usr/local/cargo/registry `
    $image `
    sh -c $cargoCmd
