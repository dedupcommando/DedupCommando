#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# G6 fixture generator — deterministic, batched, and silent about its own arithmetic.
#
# Builds the G6 directory tree and NOTHING else: it does not scan, does not open the
# checkpoint, and above all does not publish counts. Whatever this script believes it wrote is
# not evidence; the counts are asserted independently by g6-verify-counts.py, which derives
# them from the frozen parameters. A generator that certifies itself proves only that it agrees
# with itself.
#
# Frozen parameters (G6-P0-DESIGN.md section 2.1, redaction 4):
#   G = 645000 groups, M = 2 members each, U = 910000 singletons, B = 4096 bytes per file
#   files = G*M + U = 2 200 000
#
# B is NOT a free choice. ScanConfig::new (src/model/scan.rs:100) freezes min_size = 4096 and
# no CLI flag moves it, so a file below 4096 bytes never reaches the checkpoint at all — it is
# recorded as a dir_omission with reason `min_size`. B = 512, the redaction-3 value, produced a
# tree the product scanned to exactly zero files.
#
# Layout: data/<xx>/<yy>/ — a two-level hex fan, 65 536 leaves. Leaf directories are created
# only when they first receive a file, so a rehearsal does not materialise 65 536 empty ones.
#
# Capacity: the generator refuses to be one long loop. Every batch it hands control to the
# capacity hook, and a non-zero hook is BLOCKED with nothing half-written past that point.

set -uo pipefail

G6_G="${G6_G:-645000}"
G6_M="${G6_M:-2}"
G6_U="${G6_U:-910000}"
G6_B="${G6_B:-4096}"
G6_SEED="${G6_SEED:-g6-fixture-v1}"
G6_BATCH="${G6_BATCH:-10000}"
G6_CAPACITY_HOOK="${G6_CAPACITY_HOOK:-}"
G6_PYTHON="${G6_PYTHON:-python3}"

die() { printf 'REFUSED: %s\n' "$1" >&2; exit 1; }
blocked() { printf 'BLOCKED: %s\n' "$1" >&2; exit 2; }

# The frozen live scale, G6-P0-DESIGN.md section 2.1 redaction 4. Live means exactly these and
# nothing else.
LIVE_G=645000; LIVE_M=2; LIVE_U=910000; LIVE_B=4096; LIVE_SEED="g6-fixture-v1"

usage() {
  cat >&2 <<'USAGE'
usage: g6-make-fixture.sh --mode rehearsal|live --root <ABSOLUTE-DIR>

  --mode live        the frozen scale, and nothing but the frozen scale
  --mode rehearsal   a reduced scale for local proof; never calibration, never evidence
  --root <DIR>       absolute path of the fixture root; data/ is created under it

There is no default mode. A generator that picks one for you is a generator that can build the
wrong fixture in silence.

environment:
  G6_G G6_M G6_U G6_B G6_SEED   fixture parameters (live refuses any deviation)
  G6_BATCH                      files per batch between capacity checks
  G6_CAPACITY_HOOK              command run between batches AND after the last one
USAGE
  exit 1
}

ROOT=""; MODE=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) [ "$#" -ge 2 ] || usage; ROOT="$2"; shift 2 ;;
    --mode) [ "$#" -ge 2 ] || usage; MODE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument '$1'" ;;
  esac
done

[ -n "$ROOT" ] || usage
case "$MODE" in
  live|rehearsal) ;;
  '') die "--mode is required and has no default: say live or rehearsal" ;;
  *) die "--mode '$MODE' is neither live nor rehearsal" ;;
esac

if [ "$MODE" = live ]; then
  # Live is not "the defaults unless something was exported". Every parameter is compared, and
  # one deviation is enough to refuse: a live fixture that differs from the frozen scale is a
  # different experiment wearing the same name.
  for pair in "G6_G:$LIVE_G" "G6_M:$LIVE_M" "G6_U:$LIVE_U" "G6_B:$LIVE_B" "G6_SEED:$LIVE_SEED"; do
    name="${pair%%:*}"; want="${pair#*:}"
    eval "have=\${$name}"
    [ "$have" = "$want" ] || die "live refuses $name='$have'; the frozen value is '$want'"
  done
  [ -n "$G6_CAPACITY_HOOK" ] || die "live refuses to generate without a capacity hook"
fi
case "$ROOT" in
  /*) ;;
  *) die "--root '$ROOT' is not absolute" ;;
esac
case "$ROOT" in
  *//*|*/./*|*/../*|*/.|*/..) die "--root '$ROOT' contains an empty, '.' or '..' component" ;;
esac

for v in G6_G G6_M G6_U G6_B G6_BATCH; do
  eval "val=\${$v}"
  case "$val" in
    ''|*[!0-9]*) die "$v='$val' is not a decimal number" ;;
  esac
  [ "$val" -gt 0 ] || die "$v='$val' must be positive"
done

# The product cannot see a file below its own floor, so a fixture built under it is not a
# smaller fixture — it is an empty one. Refuse rather than produce a tree that scans to zero.
[ "$G6_B" -ge 4096 ] || die "G6_B=$G6_B is below the product's min_size floor of 4096 — \
every file would be omitted as min_size and the checkpoint would hold none of them"

# B must fill whole 32-byte digests: the payload is one digest repeated, which is what makes a
# pair byte-identical and every singleton distinct without hashing 128 times per file.
[ $(( G6_B % 32 )) -eq 0 ] || die "G6_B=$G6_B is not a multiple of 32"

command -v "$G6_PYTHON" >/dev/null 2>&1 || blocked "'$G6_PYTHON' not found"

# The hook is ONE executable, invoked with no arguments. A hook carrying its own arguments in a
# string would be word-split here, and a path with a space in it would silently become two
# programs neither of which exists — so a non-executable value is refused outright.
if [ -n "$G6_CAPACITY_HOOK" ] && [ ! -x "$G6_CAPACITY_HOOK" ]; then
  die "G6_CAPACITY_HOOK='$G6_CAPACITY_HOOK' is not an executable file; the hook takes no \
arguments and is never a command line"
fi

TOTAL=$(( G6_G * G6_M + G6_U ))

printf 'g6-make-fixture: root=%s\n' "$ROOT"
printf '  parameters: G=%s M=%s U=%s B=%s seed=%s\n' "$G6_G" "$G6_M" "$G6_U" "$G6_B" "$G6_SEED"
printf '  batch=%s, capacity hook=%s\n' "$G6_BATCH" "${G6_CAPACITY_HOOK:-<none>}"

mkdir -p "$ROOT/data" || die "cannot create '$ROOT/data'"

# One batch of the global index range [lo, hi). The index space is laid out as
#   [0, G*M)            group members, index = g*M + m
#   [G*M, G*M + U)      singletons,    index = G*M + u
# so a batch is a contiguous slice and the batch boundary carries no state of its own.
emit_batch() {  # lo hi
  "$G6_PYTHON" - "$ROOT" "$G6_SEED" "$G6_G" "$G6_M" "$G6_U" "$G6_B" "$1" "$2" <<'PY'
import hashlib, os, sys

root, seed = sys.argv[1], sys.argv[2]
G, M, U, B, lo, hi = (int(x) for x in sys.argv[3:9])
members = G * M
reps = B // 32

def key(kind, idx):
    return f"{seed}|{kind}|{idx}".encode()

def leaf(h):
    # The first two bytes of the placement digest pick the fan; the members of one pair land in
    # different leaves on purpose, so the fixture is a file-level duplicate set and not a pile
    # of directory twins.
    return f"{h[0]:02x}", f"{h[1]:02x}"

made = set()
for i in range(lo, hi):
    if i < members:
        g, m = divmod(i, M)
        content = hashlib.sha256(key("g", g)).digest()
        place = hashlib.sha256(key("gp", i)).digest()
        name = f"g{g:08d}-{m}.bin"
    else:
        u = i - members
        content = hashlib.sha256(key("u", u)).digest()
        place = hashlib.sha256(key("up", u)).digest()
        name = f"u{u:08d}.bin"
    xx, yy = leaf(place)
    d = os.path.join(root, "data", xx, yy)
    if d not in made:
        os.makedirs(d, exist_ok=True)
        made.add(d)
    path = os.path.join(d, name)
    tmp = path + ".part"
    with open(tmp, "wb") as fh:
        fh.write(content * reps)
    os.replace(tmp, path)
PY
}

lo=0
batches=0
while [ "$lo" -lt "$TOTAL" ]; do
  hi=$(( lo + G6_BATCH ))
  [ "$hi" -gt "$TOTAL" ] && hi="$TOTAL"

  # Capacity is checked BEFORE the batch that would consume it, so a refusal leaves the tree at
  # a batch boundary rather than somewhere inside one.
  if [ -n "$G6_CAPACITY_HOOK" ]; then
    if ! "$G6_CAPACITY_HOOK"; then
      blocked "capacity hook refused before batch [$lo,$hi) — fixture left at a batch boundary"
    fi
  fi

  if ! emit_batch "$lo" "$hi"; then
    blocked "batch [$lo,$hi) did not complete — an unfinished batch is not a fixture"
  fi

  lo="$hi"
  batches=$(( batches + 1 ))
done

# The margin is checked BETWEEN batches and once more AFTER the last one. Without this last
# check the run that consumed the most space is the only one nobody measured, and "it fitted
# while it was growing" is not the same claim as "it fits".
if [ -n "$G6_CAPACITY_HOOK" ]; then
  if ! "$G6_CAPACITY_HOOK"; then
    blocked "capacity hook refused after the final batch — the fixture is complete but the \
margin it left behind is not the one that was sanctioned"
  fi
fi

printf 'g6-make-fixture: mode=%s, %s batches over %s indices, done\n' "$MODE" "$batches" "$TOTAL"
printf 'g6-make-fixture: counts are NOT published here; assert them with g6-verify-counts.py\n'
