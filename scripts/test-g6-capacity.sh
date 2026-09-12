#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The capacity check at its exact boundaries, with the filesystem shrinking under it.
#
# Two questions, asked at two different moments, and the difference between them is the whole
# point. BEFORE generation the filesystem must be able to hold the fixture: actual total and
# actual free cover need + reserve, and the total is asked because mkfs cannot be told later to
# add inodes. BETWEEN batches, and once more AFTER the last one, the question is only whether
# the reserve is still there.
#
# The margin is MEASURED at each of those moments, never forecast. A batch spends more than its
# files — every directory it creates is an inode too, and the bytes are not files x block — so a
# harness-computed prediction of the next batch is a number nobody measured. That is P0 §4.2 and
# §6.3, and it is also why the earlier requirement of need + reserve between batches was not
# merely strict but impossible: after 2 200 000 files exist, no filesystem holding them can
# offer room for them a second time.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CTL="$HERE/g6-controller.sh"
. "$HERE/test-g6-stubs.sh"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
g6t_install_stubs "$WORK/bin"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"
        [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }

# The numbers the resource plan seals, written out as themselves: a change to the plan then shows
# up here as a failure instead of as a suite agreeing with itself.
NEED=2265900; RESERVE=226590
BYTE_NEED=9011200000; BYTE_RESERVE=1717986918
EXTERNAL=51539607552

# The hook the generator runs between batches. It takes no arguments by design, so everything it
# needs arrives in the environment — and nothing in the chain is ever a command line.
hook() {  # inside-inodes inside-bytes [extra env assignments...]
  local inodes="$1" bytes="$2"; shift 2
  env G6_EXTERNAL_REQUIREMENT="$EXTERNAL" G6_INODE_NEED="$NEED" G6_INODE_RESERVE="$RESERVE" \
      G6_INTERNAL_BYTE_NEED="$BYTE_NEED" G6_INTERNAL_BYTE_RESERVE="$BYTE_RESERVE" \
      G6T_INSIDE="$INSIDE" G6T_DF_INSIDE_INODES="$inodes" G6T_DF_INSIDE_BYTES="$bytes" \
      "$@" bash "$CTL" capacity-hook "$OUTSIDE" "$INSIDE" 2>&1
}

full() {  # inside-total-inodes inside-free-inodes inside-bytes
  env G6_EXTERNAL_REQUIREMENT="$EXTERNAL" G6_INODE_NEED="$NEED" G6_INODE_RESERVE="$RESERVE" \
      G6_INTERNAL_BYTE_NEED="$BYTE_NEED" G6_INTERNAL_BYTE_RESERVE="$BYTE_RESERVE" \
      G6T_INSIDE="$INSIDE" G6T_DF_INSIDE_INODES_TOTAL="$1" G6T_DF_INSIDE_INODES="$2" \
      G6T_DF_INSIDE_BYTES="$3" \
      bash "$CTL" capacity-full "$OUTSIDE" "$INSIDE" 2>&1
}

accepts() { local out; out="$("$@")" && ok "$LABEL" || bad "$LABEL" "$(printf '%s' "$out" | tail -2)"; }
refuses() {  # needle -- command...
  local needle="$1"; shift; [ "$1" = "--" ] && shift
  local out rc=0
  out="$("$@")" || rc=$?
  if [ "$rc" = 0 ]; then bad "$LABEL — it was accepted"; return; fi
  g6_has "$out" "$needle" && ok "$LABEL" \
    || bad "$LABEL — refused, but nothing named '$needle'" "$(printf '%s' "$out" | tail -2)"
}

g6t_new_world "$WORK"
OUTSIDE="$G6T_W/remote"
INSIDE="$G6T_W/remote/g6-fixture"; mkdir -p "$INSIDE"

echo "== G6 capacity — two questions, measured at their own moments =="
echo

echo "-- before generation: the fixture has to fit, and the geometry has to allow it --"
LABEL="the exact requirement is enough"
accepts full $(( NEED + RESERVE )) $(( NEED + RESERVE )) $(( BYTE_NEED + BYTE_RESERVE ))
LABEL="an inode total one below the requirement refuses, naming the geometry"
refuses "internal inode total" -- full $(( NEED + RESERVE - 1 )) $(( NEED + RESERVE )) \
        $(( BYTE_NEED + BYTE_RESERVE ))
LABEL="free inodes one below the requirement refuse"
refuses "internal inode margin" -- full $(( NEED + RESERVE )) $(( NEED + RESERVE - 1 )) \
        $(( BYTE_NEED + BYTE_RESERVE ))
LABEL="free bytes one below the requirement refuse"
refuses "internal byte margin" -- full $(( NEED + RESERVE )) $(( NEED + RESERVE )) \
        $(( BYTE_NEED + BYTE_RESERVE - 1 ))

echo
echo "-- between batches and after the last one: the reserve, and only the reserve --"
LABEL="exactly the reserve is enough"
accepts hook "$RESERVE" "$BYTE_RESERVE"
LABEL="one inode below the reserve refuses"
refuses "internal inode margin" -- hook $(( RESERVE - 1 )) "$BYTE_RESERVE"
LABEL="one byte below the reserve refuses"
refuses "internal byte margin" -- hook "$RESERVE" $(( BYTE_RESERVE - 1 ))
LABEL="the whole requirement is NOT asked again once the fixture exists"
accepts hook "$RESERVE" "$BYTE_RESERVE"

echo
echo "-- the external margin is not negotiable at either moment --"
LABEL="a starved host filesystem refuses between batches"
refuses "external requirement" -- hook "$RESERVE" "$BYTE_RESERVE" \
        G6T_DF_OUTSIDE_BYTES=$(( EXTERNAL - 1 ))

echo
echo "-- a filesystem that shrinks while the fixture grows is caught, not averaged --"
# The bench starves the inside axis after N answers. A margin that were sampled once at the start
# would never see this; the point of checking between batches is that the machine changes.
out="$(env G6_EXTERNAL_REQUIREMENT="$EXTERNAL" G6_INODE_NEED="$NEED" G6_INODE_RESERVE="$RESERVE" \
        G6_INTERNAL_BYTE_NEED="$BYTE_NEED" G6_INTERNAL_BYTE_RESERVE="$BYTE_RESERVE" \
        G6T_INSIDE="$INSIDE" G6T_DF_INSIDE_INODES="$RESERVE" G6T_DF_INSIDE_BYTES="$BYTE_RESERVE" \
        G6T_DF_STARVE_AFTER=0 \
        bash "$CTL" capacity-hook "$OUTSIDE" "$INSIDE" 2>&1)"
g6_has "$out" 'internal inode margin' \
  && ok "the first starved answer refuses" \
  || bad "the first starved answer refuses" "$(printf '%s' "$out" | tail -2)"

echo
echo "-- the generator must ask again after the last batch --"
# Without that final call the run that consumed the most is the only one nobody measured, and
# "it fitted while it was growing" is a different claim from "it fits".
calls="$WORK/hook-calls"; : > "$calls"
{ printf '#!/usr/bin/env bash\n'; printf 'echo call >> %q\n' "$calls"; printf 'exit 0\n'; } \
  > "$WORK/counting-hook"
chmod +x "$WORK/counting-hook"
env G6_G=2 G6_M=2 G6_U=1 G6_B=4096 G6_SEED=capacity-suite G6_BATCH=2 \
    G6_CAPACITY_HOOK="$WORK/counting-hook" \
    bash "$HERE/g6-make-fixture.sh" --mode rehearsal --root "$INSIDE" >/dev/null 2>&1
# Five files at two per batch is three batches: three checks before them, one after the last.
n="$(wc -l < "$calls")"
[ "$n" = 4 ] && ok "three batches produced four checks — one before each, one after the last" \
             || bad "three batches produced four checks" "saw $n"

echo
echo "== result: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
