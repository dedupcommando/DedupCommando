#!/usr/bin/env bash
# scan-contamination.sh — pre-publication contamination scan for the public seed.
#
# Greps the whitelist-shippable set (code/config/scripts) for material that must
# NOT reach the public repository:
#   - AI-agent markers (Co-authored-by, Generated with Claude, claude.ai, ...)
#   - private RFC1918 host IPs (10/8, 172.16/12, 192.168/16 — full ranges)
#   - absolute / local developer paths and dev-server hosts
#   - deployment secrets (.deploy-target reference)
#
# Uses plain `grep -r` over an explicit pathspec — NO git dependency — so it runs
# identically on Linux/Docker (CI) and dev-native on Windows git-bash, where
# a worktree's gitdir can't always be resolved (that broke an earlier `git grep`
# version with a `fatal: not a git repository`). It scans the on-disk working tree,
# which is exactly what gets copied into the seed.
#
# SCOPE = the shippable code/config/scripts, MINUS files authored fresh at seed time
# (README.md, docs/manual/**, .gitignore, .gitleaks.toml) and this script itself (all
# legitimately contain these patterns). Non-shipped material is excluded from the
# public tree by the seed whitelist and is not scanned here.
#
# Pairs with .gitleaks.toml (entropy/secret scan over the source tree) in CI.
# Exit 0 = clean; 1 = unexpected hit (offending lines printed); 2 = scan error.
set -euo pipefail

# Repo root from this script's own location — no git call, robust everywhere.
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
cd -- "$SCRIPT_DIR/.."

# --- whitelist-shippable pathspec (dirs recursed; .gitignore/.gitleaks.toml/this script excluded) ---
SCOPE=(
  'src'
  'Cargo.toml' 'Cargo.lock' 'rust-toolchain.toml'
  'LICENSE' 'NOTICE' 'THIRD-PARTY-NOTICES'
  'deny.toml' 'about.toml' 'about.hbs'
  '.github'
  'scripts/build.ps1'
  'scripts/e2e-dir-completeness.sh' 'scripts/e2e-g5.sh' 'scripts/make-test-pool.sh'
  'scripts/teardown-test-pool.sh' 'scripts/test-teardown-guard.sh'
  'scripts/testpool-lib.sh'
)

# --- patterns that must NOT appear in the shippable set ---
MARKERS='Co-authored-by|Generated with Claude|claude\.ai|noreply@anthropic|🤖'
# RFC1918, full ranges (not just .0.0.x): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
PRIV_IP='10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}'
DEV_PATH='C:\\Users|localhost:3000|127\.0\.0\.1:3000'
DEPLOY='\.deploy-target'

# --- allowlisted benign matches (one ERE, '|'-joined; empty = none) ---
# safe_open.rs '/etc/secret' and the token/tokens identifiers are not matched by the
# patterns above, so the allowlist is currently empty. Add 'path:.*pattern' if a real
# false positive appears.
ALLOW=''

fail=0
scan() {
  local label="$1" pat="$2" hits rc
  set +e
  hits="$(grep -rnIiE "$pat" "${SCOPE[@]}")"
  rc=$?
  set -e
  # grep: 0 = matches, 1 = no matches, >1 = real error → fail loud (never a silent green).
  if [ "$rc" -gt 1 ]; then
    printf 'ERROR: grep failed (rc=%s) scanning "%s" — aborting (not a clean result).\n' "$rc" "$label" >&2
    exit 2
  fi
  if [ -n "$ALLOW" ] && [ -n "$hits" ]; then
    hits="$(printf '%s\n' "$hits" | { grep -vE "$ALLOW" || true; })"
  fi
  if [ -n "$hits" ]; then
    printf '\xE2\x9C\x97 %s — unexpected hits:\n' "$label"
    printf '%s\n' "$hits" | sed 's/^/    /'
    fail=1
  else
    printf '\xE2\x9C\x93 %s — clean\n' "$label"
  fi
}

echo "scan-contamination: whitelist-shippable scope"
scan "agent markers"         "$MARKERS"
scan "private IPs (RFC1918)" "$PRIV_IP"
scan "absolute/local paths"  "$DEV_PATH"
scan "deployment secrets"    "$DEPLOY"

if [ "$fail" -ne 0 ]; then
  echo "RESULT: contamination found — resolve or allowlist before public seed." >&2
  exit 1
fi
echo "RESULT: clean."
