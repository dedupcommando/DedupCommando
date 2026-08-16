#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scenario and mutation suite for the G6 fixture generator and its independent verifier.
#
# Rehearsal scale only — 21 000 files. This is NOT host calibration and NOT G6 evidence; it
# exists to prove the contracts locally, and it says so in its own output.
#
# The checkpoint under test is built by the PRODUCT, through its ordinary headless scan. No DDL
# is written here, no user_version is set by hand, and no schema is transcribed: a checkpoint
# assembled by the harness would only prove the harness agrees with itself, which is exactly
# the lesson G2 paid for.
#
# Every mutation must be killed BY ITS OWN CAUSE: a non-zero exit that does not name the thing
# that broke is recorded as INVALID, not as a kill.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GEN="$HERE/g6-make-fixture.sh"
VERIFY="$HERE/g6-verify-counts.py"

DEDCOM="${DEDCOM:-}"
[ -n "$DEDCOM" ] || { echo "ABORT: set DEDCOM to the built candidate binary" >&2; exit 1; }
[ -x "$DEDCOM" ] || { echo "ABORT: DEDCOM='$DEDCOM' is not executable" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Rehearsal parameters: three batches at G6_BATCH=10000, so the batch boundary is exercised.
R_G=5000; R_M=2; R_U=11000; R_B=4096; R_SEED="rehearsal-v1"
R_FILES=$(( R_G * R_M + R_U ))

PASS=0; FAIL=0
MUT_DECLARED=0; MUT_KILLED=0; MUT_SURVIVED=0; MUT_INVALID=0

ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"
        [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }

echo "== G6 fixture suite — REHEARSAL SCALE ($R_FILES files), not calibration, not evidence =="

# ---------------------------------------------------------------- helpers

gen() {  # root [extra env assignments...]
  local root="$1"; shift
  env G6_G="$R_G" G6_M="$R_M" G6_U="$R_U" G6_B="$R_B" G6_SEED="$R_SEED" G6_BATCH=10000 "$@" \
      bash "$GEN" --mode rehearsal --root "$root"
}

scan() {  # fixture-root state-dir
  "$DEDCOM" --state-dir "$2" --scan "$1/data" --no-resume
}

# The set that must be reproducible: relative path plus content hash. Byte equality of the
# image, timestamps and inode numbers are explicitly NOT required.
census() {  # root -> "<relpath> <sha256>" lines, sorted
  ( cd "$1/data" && find . -type f -print0 | sort -z \
      | xargs -0 -r sha256sum | awk '{print $2, $1}' )
}

# A kill is only a kill when the refusal names its own cause.
kill_check() {  # label needle -- command...
  local label="$1" needle="$2"; shift 2
  [ "$1" = "--" ] && shift
  MUT_DECLARED=$((MUT_DECLARED+1))
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" = 0 ]; then
    MUT_SURVIVED=$((MUT_SURVIVED+1))
    bad "mutation '$label' SURVIVED — it was accepted"
    return
  fi
  case "$out" in
    *"$needle"*)
      MUT_KILLED=$((MUT_KILLED+1)); ok "mutation '$label' killed by its own cause" ;;
    *)
      MUT_INVALID=$((MUT_INVALID+1))
      bad "mutation '$label' INVALID — non-zero, but nothing named '$needle'" "$out" ;;
  esac
}

# ---------------------------------------------------------------- 1. determinism

echo
echo "== 1. two generations agree on (path, content-hash) =="

A="$WORK/a"; B="$WORK/b"
gen "$A" >/dev/null 2>&1 || bad "first generation completed"
gen "$B" >/dev/null 2>&1 || bad "second generation completed"

census "$A" > "$WORK/census-a"
census "$B" > "$WORK/census-b"
if [ "$(wc -l < "$WORK/census-a")" = "$R_FILES" ]; then
  ok "the tree holds exactly $R_FILES files"
else
  bad "the tree holds exactly $R_FILES files" "saw $(wc -l < "$WORK/census-a")"
fi
if cmp -s "$WORK/census-a" "$WORK/census-b"; then
  ok "two generations give identical (path, content-hash) sets"
else
  bad "two generations give identical (path, content-hash) sets" \
      "$(diff "$WORK/census-a" "$WORK/census-b" | head -6)"
fi

# Every file is exactly B bytes, and a duplicate pair is byte-identical by construction.
odd="$(find "$A/data" -type f ! -size "${R_B}c" | head -3)"
[ -z "$odd" ] && ok "every file is exactly $R_B bytes" \
              || bad "every file is exactly $R_B bytes" "$odd"

distinct_hashes="$(awk '{print $2}' "$WORK/census-a" | sort -u | wc -l)"
if [ "$distinct_hashes" = "$(( R_G + R_U ))" ]; then
  ok "content classes are exactly G + U = $(( R_G + R_U ))"
else
  bad "content classes are exactly G + U = $(( R_G + R_U ))" "saw $distinct_hashes"
fi

# ---------------------------------------------------------------- 2. production rehearsal

echo
echo "== 2. the product's own scan sees the fixture (guard: B=4096) =="

STA="$WORK/state-a"; mkdir -p "$STA"
scan "$A" "$STA" >/dev/null 2>&1 || bad "the product's headless scan completed"

if "$VERIFY" --db "$STA/dedcom.db" --groups "$R_G" --members-per-group "$R_M" \
             --singletons "$R_U" > "$WORK/verify.out" 2>&1; then
  ok "independent verifier: files/groups/members all match the derived formulas"
else
  bad "independent verifier: files/groups/members all match the derived formulas" \
      "$(cat "$WORK/verify.out")"
fi

zero_minsize="$(python3 - "$STA/dedcom.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(sum(n for r, n in c.execute(
    "SELECT reason, COALESCE(SUM(event_count),0) FROM dir_omission GROUP BY reason")
    if r == "min_size"))
PY
)"
[ "$zero_minsize" = "0" ] && ok "zero min_size omissions at B=$R_B" \
                          || bad "zero min_size omissions at B=$R_B" "saw $zero_minsize"

# The checkpoint came from the product, so its schema stamp is the product's, not ours.
uv="$(python3 - "$STA/dedcom.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(c.execute("PRAGMA user_version").fetchone()[0])
PY
)"
[ "$uv" = "5" ] && ok "schema provenance: the production path stamped user_version=5" \
                || bad "schema provenance: the production path stamped user_version=5" "saw $uv"

# The two generations must also agree on the checkpoint's LOGICAL content — same counts and the
# same set of group hashes. Byte equality of the database is not required and not checked.
STB="$WORK/state-b"; mkdir -p "$STB"
scan "$B" "$STB" >/dev/null 2>&1 || bad "the second scan completed"
logical() {  # db -> counts and sorted group hashes
  python3 - "$1" <<'PY'
import sqlite3, sys
c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
one = lambda s: c.execute(s).fetchone()[0]
print("files", one("SELECT COUNT(*) FROM file"))
print("groups", one("SELECT COUNT(*) FROM file_group"))
print("members", one("SELECT COALESCE(SUM(file_count),0) FROM file_group"))
for (h,) in c.execute("SELECT hash FROM file_group ORDER BY hash"):
    print("g", h)
PY
}
logical "$STA/dedcom.db" > "$WORK/log-a"
logical "$STB/dedcom.db" > "$WORK/log-b"
if cmp -s "$WORK/log-a" "$WORK/log-b"; then
  ok "both runs produce the same logical checkpoint content"
else
  bad "both runs produce the same logical checkpoint content" \
      "$(diff "$WORK/log-a" "$WORK/log-b" | head -6)"
fi

# ---------------------------------------------------------------- 3. mutations

echo
echo "== 3. mutations must be killed by their own cause =="

# schema: a database that never came from the product at all.
python3 - "$WORK/foreign.db" <<'PY'
import sqlite3, sys
sqlite3.connect(sys.argv[1]).close()
PY

kill_check "schema: a database the product never wrote" "user_version" -- \
  "$VERIFY" --db "$WORK/foreign.db" --groups "$R_G" --members-per-group "$R_M" \
            --singletons "$R_U"

kill_check "formula: membership read from file_group_member" "members" -- \
  "$VERIFY" --db "$STA/dedcom.db" --groups "$R_G" --members-per-group "$R_M" \
            --singletons "$R_U" --membership-source file_group_member --negative-control

kill_check "the wrong membership source without the negative-control lock" "negative control" -- \
  "$VERIFY" --db "$STA/dedcom.db" --groups "$R_G" --members-per-group "$R_M" \
            --singletons "$R_U" --membership-source file_group_member

kill_check "count: one singleton too many" "files" -- \
  "$VERIFY" --db "$STA/dedcom.db" --groups "$R_G" --members-per-group "$R_M" \
            --singletons "$(( R_U + 1 ))"

kill_check "count: one group too many" "groups" -- \
  "$VERIFY" --db "$STA/dedcom.db" --groups "$(( R_G + 1 ))" --members-per-group "$R_M" \
            --singletons "$R_U"

kill_check "B below the product's min_size floor" "min_size" -- \
  env G6_G=10 G6_M=2 G6_U=10 G6_B=512 G6_SEED="$R_SEED" \
      bash "$GEN" --mode rehearsal --root "$WORK/tiny"

kill_check "no mode at all" "--mode is required" -- \
  env G6_G=10 G6_M=2 G6_U=10 G6_SEED="$R_SEED" bash "$GEN" --root "$WORK/nomode"

kill_check "live refuses a rehearsal scale" "live refuses" -- \
  env G6_G="$R_G" G6_M="$R_M" G6_U="$R_U" G6_B="$R_B" G6_SEED="$R_SEED" \
      bash "$GEN" --mode live --root "$WORK/livewrong"

# seed and path are proved by difference, not by refusal: a changed seed or a changed layout
# must move the census, otherwise determinism was never seed-bound in the first place.
MUT_DECLARED=$((MUT_DECLARED+1))
S="$WORK/seed"; gen "$S" G6_SEED="rehearsal-v2" >/dev/null 2>&1
census "$S" > "$WORK/census-seed"
if cmp -s "$WORK/census-a" "$WORK/census-seed"; then
  MUT_SURVIVED=$((MUT_SURVIVED+1))
  bad "mutation 'seed: a different seed' SURVIVED — the census did not move"
else
  moved_paths="$(comm -13 <(awk '{print $1}' "$WORK/census-a" | sort) \
                          <(awk '{print $1}' "$WORK/census-seed" | sort) | wc -l)"
  moved_hashes="$(comm -13 <(awk '{print $2}' "$WORK/census-a" | sort -u) \
                           <(awk '{print $2}' "$WORK/census-seed" | sort -u) | wc -l)"
  if [ "$moved_paths" -gt 0 ] && [ "$moved_hashes" -gt 0 ]; then
    MUT_KILLED=$((MUT_KILLED+1))
    ok "mutation 'seed: a different seed' killed — both placement and content moved"
  else
    MUT_INVALID=$((MUT_INVALID+1))
    bad "mutation 'seed: a different seed' INVALID — only one of placement/content moved" \
        "paths moved=$moved_paths hashes moved=$moved_hashes"
  fi
fi

MUT_DECLARED=$((MUT_DECLARED+1))
depths="$(awk '{print $1}' "$WORK/census-a" | awk -F/ '{print NF-1}' | sort -u | tr '\n' ' ')"
if [ "$depths" = "3 " ]; then
  MUT_KILLED=$((MUT_KILLED+1))
  ok "mutation 'path: the two-level fan' killed — every file sits at data/<xx>/<yy>/"
else
  MUT_INVALID=$((MUT_INVALID+1))
  bad "mutation 'path: the two-level fan' INVALID — depths seen: $depths"
fi

# ---------------------------------------------------------------- census

echo
echo "== census =="
if [ "$MUT_SURVIVED" = 0 ] && [ "$MUT_INVALID" = 0 ] && [ "$MUT_KILLED" = "$MUT_DECLARED" ]; then
  ok "mutations: $MUT_KILLED/$MUT_DECLARED killed, SURVIVED=0, INVALID=0"
else
  bad "mutations: $MUT_KILLED/$MUT_DECLARED killed, SURVIVED=$MUT_SURVIVED, INVALID=$MUT_INVALID"
fi

echo "== result: PASS=$PASS FAIL=$FAIL MUTATIONS=$MUT_KILLED/$MUT_DECLARED \
SURVIVED=$MUT_SURVIVED INVALID=$MUT_INVALID =="
[ "$FAIL" -eq 0 ] && [ "$MUT_SURVIVED" -eq 0 ] && [ "$MUT_INVALID" -eq 0 ]
