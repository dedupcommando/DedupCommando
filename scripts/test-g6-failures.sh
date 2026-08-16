#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The directed failure suite: every scenario in the registry, run against the delivery as it
# stands.
#
# This suite answers one question per row — does the guard hold, and does it say why. The other
# half of the pair lives in test-g6-mutations.sh, which removes exactly that guard and requires
# the same scenario to notice. Neither half proves anything alone: a scenario that passes against
# a delivery with the guard cut out was never about the guard, and a mutation nobody exercised is
# a mutation nobody killed.
#
# Rehearsal scale, stubbed world. Not host calibration and not G6 evidence.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test-g6-stubs.sh"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
g6t_install_stubs "$WORK/bin"

. "$HERE/test-g6-scenarios.sh"
g6s_require_bin

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"
        [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }

echo "== G6 directed failure suite — publisher, S3, calibration, lifecycle, provenance =="
echo

# The rows are read in full before anything runs: the scenarios spawn routes and stand-ins that
# would otherwise be reading the same stream.
ROWS=()
while IFS= read -r line; do
  [ -n "$line" ] && ROWS+=("$line")
done < <(g6s_rows)

for line in "${ROWS[@]}"; do
  IFS=$'\t' read -r name fn pol cause alt rcpair <<< "$line"
  [ -n "${name:-}" ] || continue

  if ! declare -F "$fn" >/dev/null; then
    bad "[$name] the registry names '$fn', which does not exist"
    continue
  fi

  out=""; rc=0
  out="$("$fn" "$HERE" 2>&1)" || rc=$?
  tail="$(printf '%s' "$out" | tail -3)"

  case "$pol" in
    refuse)
      if [ "$rc" = 0 ]; then
        bad "[$name] refuse — it was accepted" "$tail"
      elif printf '%s' "$out" | grep -qF -- "$cause"; then
        ok "[$name] refused, naming '$cause'"
      else
        bad "[$name] refused without naming '$cause'" "$tail"
      fi ;;
    hold)
      if [ "$rc" = 0 ]; then
        ok "[$name] the guard holds"
      else
        bad "[$name] the guard did not hold" "$tail"
      fi ;;
    reclass)
      # Both copies refuse; the pristine one must refuse for THIS reason, with the status the
      # registry declares, and it must not already be producing the alternative the mutant is
      # expected to fall back to. The status is checked here and not only in the matrix: the
      # class is half of what a reclassification row claims, so a row whose pristine half has
      # quietly changed class should fail on the delivery as it stands.
      if [ "$rc" = 0 ]; then
        bad "[$name] reclass — the pristine copy did not refuse at all" "$tail"
      elif [ "$rc" != "${rcpair%%/*}" ]; then
        bad "[$name] refused with $rc, the registry declares ${rcpair%%/*}" "$tail"
      elif ! printf '%s' "$out" | grep -qF -- "$cause"; then
        bad "[$name] refused without naming '$cause'" "$tail"
      elif [ -n "${alt:-}" ] && [ "$alt" != "-" ] && printf '%s' "$out" | grep -qF -- "$alt"; then
        bad "[$name] the pristine copy already names the mutant's cause '$alt'" "$tail"
      else
        ok "[$name] names '$cause', and not '$alt'"
      fi ;;
    *)
      bad "[$name] unknown polarity '$pol'" ;;
  esac
done

echo
echo "== result: PASS=$PASS FAIL=$FAIL over ${#ROWS[@]} declared scenarios =="
[ "$FAIL" -eq 0 ]
