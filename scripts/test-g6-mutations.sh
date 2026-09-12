#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One-to-one source-mutation matrix for the G6 delivery.
#
# Each row names ONE guard, removes exactly that guard from a COMPLETE COPY of the delivery, and
# runs the one scenario that exercises it. Which code ran is proved rather than assumed: the
# mutant's bundle hash must differ from the pristine one and the controller loaded from the
# mutant directory must report that directory.
#
#   KILLED    the pristine refuses naming this guard's cause, and the mutant does not
#   SURVIVED  the mutant still refuses with the same cause — the edit removed nothing real
#   INVALID   the scenario never exercised the guard, the mutant did not parse, the copy was not
#             what ran, or the mutant failed for a FOREIGN reason
#
# A foreign refusal is never a kill. It is evidence about some other guard, and counting it here
# would credit this row for work it did not do.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test-g6-stubs.sh"

DELIVERY="g6-controller.sh g6-supervisor.sh g6-image-lib.sh g6-make-fixture.sh \
g6-publish-record.py g6-verify-counts.py g6-observe-destination.py"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
g6t_install_stubs "$WORK/bin"

# The directed scenarios live next door, in the same registry the failure suite reads. A matrix
# that carried its own private copy of them would be a matrix proving things about code the other
# suite never ran.
. "$HERE/test-g6-scenarios.sh"
g6s_require_bin

PASS=0; FAIL=0
DECLARED=0; KILLED=0; SURVIVED=0; INVALID=0

ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"
        [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }

PRISTINE="$WORK/pristine"; mkdir -p "$PRISTINE"
for f in $DELIVERY; do cp "$HERE/$f" "$PRISTINE/"; done
PRISTINE_SHA="$(bash "$PRISTINE/g6-controller.sh" bundle \
                 | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')"

# Exactly one occurrence, or the edit is not a one-to-one mutation.
#
# `${src/from/to}` replaces the FIRST match and says nothing about the others, so an anchor that
# appears twice silently mutates one of them and leaves a row that looks fine and proves nothing
# about the guard it names. Counting here makes the matrix itself refuse, instead of leaving the
# ambiguity to be noticed by whoever happens to audit the anchors later.
literal_sub() {
  local file="$1" from="$2" to="$3" src rest count=0
  src="$(cat "$file")"
  rest="$src"
  while :; do
    case "$rest" in
      *"$from"*) count=$(( count + 1 )); rest="${rest#*"$from"}" ;;
      *) break ;;
    esac
  done
  [ "$count" = 1 ] || return $(( count == 0 ? 3 : 4 ))
  printf '%s\n' "${src/"$from"/"$to"}" > "$file"
}

# An exit that is not an answer. 124 is the bounded timeout firing, 128+n is a signal: in both
# cases the scenario STOPPED, it did not decide anything, and reading either as "the guard
# refused" would credit a row for an accident. Neither is ever a kill, in any polarity.
rc_accident() {  # rc -> 0 when this exit says nothing about the guard
  case "$1" in
    ''|*[!0-9]*) return 0 ;;
    124) return 0 ;;
  esac
  [ "$1" -lt 128 ] && return 1
  return 0
}

# ---------------------------------------------------------------- scenario bench

# The sealed world and the bare world both come from the shared bench, and both now carry the
# REAL candidate. A matrix that sealed a stand-in over the candidate could never reach the scan,
# so every row about the route would have been decided before the route began.
sealed_world() { g6s_sealed_world "$1"; }
lib_world()    { g6s_world; }

# --- lifecycle scenarios
sc_containment()   { lib_world; G6_IMAGE="$WORK/escape.img" bash "$1/g6-image-lib.sh" prepare 2>&1; }
sc_busy_device()   { lib_world
                     mkdir -p "$G6T_SYS/block/loop7/loop"
                     printf '/foreign.img\n' > "$G6T_SYS/block/loop7/loop/backing_file"
                     bash "$1/g6-image-lib.sh" prepare >/dev/null 2>&1
                     bash "$1/g6-image-lib.sh" attach 2>&1; }
sc_no_fields()     { lib_world
                     bash "$1/g6-image-lib.sh" prepare >/dev/null 2>&1
                     G6T_NO_LOSETUP_FIELDS=1 bash "$1/g6-image-lib.sh" attach 2>&1; }
sc_unpub_attach()  { lib_world
                     bash "$1/g6-image-lib.sh" prepare >/dev/null 2>&1
                     "$G6_LOSETUP" "$G6_LOOP_DEV" "$G6_IMAGE" >/dev/null 2>&1
                     bash "$1/g6-image-lib.sh" teardown 2>&1; }
sc_unpub_mount()   { lib_world
                     bash "$1/g6-image-lib.sh" prepare >/dev/null 2>&1
                     bash "$1/g6-image-lib.sh" attach >/dev/null 2>&1
                     bash "$1/g6-image-lib.sh" format >/dev/null 2>&1
                     mkdir -p "$G6_MOUNTPOINT"
                     "$G6_MOUNT" "$G6_LOOP_DEV" "$G6_MOUNTPOINT" >/dev/null 2>&1
                     bash "$1/g6-image-lib.sh" teardown 2>&1; }
sc_broken_seal_rec() { lib_world
                     bash "$1/g6-image-lib.sh" prepare >/dev/null 2>&1
                     printf 'tampered\n' >> "$G6_STATE_DIR/PREPARED"
                     bash "$1/g6-image-lib.sh" attach 2>&1; }
sc_stale_chain()   { lib_world
                     bash "$1/g6-image-lib.sh" prepare >/dev/null 2>&1
                     bash "$1/g6-image-lib.sh" attach >/dev/null 2>&1
                     printf '/moved.img\n' > "$G6T_SYS/block/loop7/loop/backing_file"
                     bash "$1/g6-image-lib.sh" format 2>&1; }
sc_blocksize()     { lib_world
                     bash "$1/g6-image-lib.sh" prepare >/dev/null 2>&1
                     bash "$1/g6-image-lib.sh" attach >/dev/null 2>&1
                     G6T_FAKE_BLOCKSIZE=1024 bash "$1/g6-image-lib.sh" format 2>&1; }

# --- controller scenarios
sc_contour_default() { sealed_world "$1"; G6_CONTOUR= bash "$1/g6-controller.sh" contour --mode rehearsal 2>&1; }
sc_contour_real()    { sealed_world "$1"; G6_MOUNT=/usr/bin/mount bash "$1/g6-controller.sh" contour --mode rehearsal 2>&1; }
sc_window()          { sealed_world "$1"
                       sed -i 's/^window-close\t9999999999/window-close\t4000/' "$SANC"
                       bash "$1/g6-controller.sh" check-sanctions --mode rehearsal 2>&1; }
sc_cal_seal()        { sealed_world "$1"; printf 'note\ttampered\n' >> "$CAL"
                       bash "$1/g6-controller.sh" check-sanctions --mode rehearsal 2>&1; }
sc_plan_incomplete() { sealed_world "$1"
                       grep -v '^work-dir	' "$PLAN" > "$PLAN.n" && mv "$PLAN.n" "$PLAN"
                       g6t_write_sanction rehearsal "$SANC" "$CAL" "$G6_BIN" \
                         "$(bash "$1/g6-controller.sh" bundle | awk -F'\t' '$1=="bundle-sha256"{print $2}')" "$PLAN"
                       bash "$1/g6-controller.sh" check-sanctions --mode rehearsal 2>&1; }
sc_plan_seal()       { sealed_world "$1"; printf 'note\tedited\n' >> "$PLAN"
                       bash "$1/g6-controller.sh" check-sanctions --mode rehearsal 2>&1; }
# The inside axis is the mounted image, so the mountpoint exists whenever it is measured —
# the lifecycle creates it in mount. These scenarios call the hook directly, without a
# lifecycle, so they have to make it themselves: df cannot measure what is not there, and a
# refusal about a missing path is a foreign cause, not this guard.
sc_internal_bytes()  { sealed_world "$1"; mkdir -p "$G6_FIXTURE_ROOT"
                       G6T_DF_INSIDE_BYTES=5 bash "$1/g6-controller.sh" capacity-hook \
                         "$G6_REMOTE_ROOT" "$G6_FIXTURE_ROOT" 2>&1; }
sc_internal_inodes() { sealed_world "$1"; mkdir -p "$G6_FIXTURE_ROOT"
                       G6T_DF_INSIDE_INODES=5 bash "$1/g6-controller.sh" capacity-hook \
                         "$G6_REMOTE_ROOT" "$G6_FIXTURE_ROOT" 2>&1; }
sc_external_bytes()  { sealed_world "$1"; mkdir -p "$G6_FIXTURE_ROOT"
                       G6T_DF_OUTSIDE_BYTES=1000 bash "$1/g6-controller.sh" capacity-hook \
                         "$G6_REMOTE_ROOT" "$G6_FIXTURE_ROOT" 2>&1; }

# Five files at two per batch is three batches, so the hook is asked four times: once before each
# batch and once after the last. This hook allows the first three and refuses the fourth, so the
# only thing that can fail is the check that happens AFTER the fixture is complete — the one the
# run consumed the most to reach and the only one a missing final call would skip.
sc_final_capacity()  { local d="$1" root="$WORK/fin$RANDOM" h="$WORK/fh$RANDOM" c="$WORK/fc$RANDOM"
                       mkdir -p "$root"; : > "$c"
                       { printf '#!/usr/bin/env bash\n'
                         printf 'echo x >> %q\n' "$c"
                         printf 'n=$(wc -l < %q)\n' "$c"
                         printf '[ "$n" -ge 4 ] && exit 1\n'
                         printf 'exit 0\n'; } > "$h"
                       chmod +x "$h"
                       env G6_G=2 G6_M=2 G6_U=1 G6_B=4096 G6_SEED=fin G6_BATCH=2 \
                           G6_CAPACITY_HOOK="$h" \
                         bash "$d/g6-make-fixture.sh" --mode rehearsal --root "$root" 2>&1; }

# --- generator and helper scenarios
sc_tiny_b()      { env G6_G=2 G6_M=2 G6_U=2 G6_B=512 G6_SEED=x \
                     bash "$1/g6-make-fixture.sh" --mode rehearsal --root "$WORK/tiny$RANDOM" 2>&1; }
sc_no_mode()     { env G6_G=2 G6_M=2 G6_U=2 G6_SEED=x \
                     bash "$1/g6-make-fixture.sh" --root "$WORK/nm$RANDOM" 2>&1; }
sc_live_scale()  { env G6_G=2 G6_M=2 G6_U=2 G6_B=4096 G6_SEED=x \
                     bash "$1/g6-make-fixture.sh" --mode live --root "$WORK/ls$RANDOM" 2>&1; }
sc_hook_argv()   { local h="$WORK/h$RANDOM"; printf '#!/usr/bin/env bash\nexit 0\n' > "$h"; chmod +x "$h"
                   env G6_G=2 G6_M=2 G6_U=2 G6_SEED=x G6_CAPACITY_HOOK="$h --extra" \
                     bash "$1/g6-make-fixture.sh" --mode rehearsal --root "$WORK/ha$RANDOM" 2>&1; }
sc_unsealed_rec() { local d="$WORK/pv$RANDOM"; mkdir -p "$d"
                    printf 'body\n' > "$d/REC"
                    "$1/g6-publish-record.py" --verify --dir "$d" --name REC 2>&1; }
sc_neg_control() { "$1/g6-verify-counts.py" --db /nonexistent --groups 1 --members-per-group 2 \
                     --singletons 1 --membership-source file_group_member 2>&1; }

# ---------------------------------------------------------------- the matrix

# A row filter, so a handful of rows can be re-run while they are being reconciled instead of the
# whole matrix. G6M_ONLY is a space-separated list of row names; unset — which is what a real pass
# leaves it — runs everything. A filtered row is not declared, so it cannot be counted as killed.
g6m_skip() {  # row-name -> 0 when this row is filtered out
  [ -n "${G6M_ONLY:-}" ] || return 1
  case " $G6M_ONLY " in *" $1 "*) return 1 ;; *) return 0 ;; esac
}

mutate() {  # label file FROM TO scenario cause
  g6m_skip "$1" && return
  DECLARED=$((DECLARED+1))
  local label="$1" file="$2" from="$3" to="$4" scenario="$5" cause="$6"
  local dir="$WORK/mut-$DECLARED"; mkdir -p "$dir"
  local f; for f in $DELIVERY; do cp "$PRISTINE/$f" "$dir/"; done

  if ! literal_sub "$dir/$file" "$from" "$to"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the anchor does not occur exactly once in $file"; return
  fi
  case "$file" in
    *.py) python3 -m py_compile "$dir/$file" 2>/dev/null \
            || { INVALID=$((INVALID+1)); bad "[$label] INVALID — the mutant does not compile"; return; } ;;
    *)    bash -n "$dir/$file" 2>/dev/null \
            || { INVALID=$((INVALID+1)); bad "[$label] INVALID — the mutant does not parse"; return; } ;;
  esac

  local mdir msha
  mdir="$(bash "$dir/g6-controller.sh" bundle | awk -F'\t' '$1 == "bundle-dir" { print $2 }')"
  msha="$(bash "$dir/g6-controller.sh" bundle | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')"
  if [ "$mdir" != "$dir" ] || [ "$msha" = "$PRISTINE_SHA" ]; then
    INVALID=$((INVALID+1)); bad "[$label] INVALID — the copy is not what ran" "dir=$mdir"; return
  fi

  local pout prc=0
  pout="$("$scenario" "$PRISTINE" 2>&1)" || prc=$?
  if rc_accident "$prc"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the pristine copy did not exit, it stopped (rc=$prc)"; return
  fi
  if [ "$prc" = 0 ] || ! g6_has "$pout" "$cause"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the scenario does not exercise this guard on the pristine copy" \
        "$(printf '%s' "$pout" | tail -3)"
    return
  fi

  local mout mrc=0
  mout="$("$scenario" "$dir" 2>&1)" || mrc=$?
  if rc_accident "$mrc"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the mutant did not exit, it stopped (rc=$mrc)"; return
  fi
  if g6_has "$mout" "$cause"; then
    SURVIVED=$((SURVIVED+1)); bad "[$label] SURVIVED — the same cause still refuses"; return
  fi
  if [ "$mrc" != 0 ]; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the mutant failed for a foreign reason" "$(printf '%s' "$mout" | tail -3)"
    return
  fi
  KILLED=$((KILLED+1)); ok "[$label] killed — this guard was what refused"
}

mutate_detect() {  # label file FROM TO scenario cause
  g6m_skip "$1" && return
  DECLARED=$((DECLARED+1))
  local label="$1" file="$2" from="$3" to="$4" scenario="$5" cause="$6"
  local dir="$WORK/mut-$DECLARED"; mkdir -p "$dir"
  local f; for f in $DELIVERY; do cp "$PRISTINE/$f" "$dir/"; done
  if ! literal_sub "$dir/$file" "$from" "$to"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the anchor does not occur exactly once in $file"; return
  fi
  case "$file" in
    *.py) python3 -m py_compile "$dir/$file" 2>/dev/null \
            || { INVALID=$((INVALID+1)); bad "[$label] INVALID — does not compile"; return; } ;;
    *)    bash -n "$dir/$file" 2>/dev/null \
            || { INVALID=$((INVALID+1)); bad "[$label] INVALID — does not parse"; return; } ;;
  esac
  local mdir msha
  mdir="$(bash "$dir/g6-controller.sh" bundle | awk -F'\t' '$1=="bundle-dir"{print $2}')"
  msha="$(bash "$dir/g6-controller.sh" bundle | awk -F'\t' '$1=="bundle-sha256"{print $2}')"
  if [ "$mdir" != "$dir" ] || [ "$msha" = "$PRISTINE_SHA" ]; then
    INVALID=$((INVALID+1)); bad "[$label] INVALID — the copy is not what ran"; return
  fi
  # The pristine must SUCCEED here, or the scenario is not a proof about this guard.
  local pout prc=0
  pout="$("$scenario" "$PRISTINE" 2>&1)" || prc=$?
  if [ "$prc" != 0 ]; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the pristine copy does not pass the scenario" "$(printf '%s' "$pout" | tail -3)"
    return
  fi
  local mout mrc=0
  mout="$("$scenario" "$dir" 2>&1)" || mrc=$?
  if rc_accident "$mrc"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the mutant did not exit, it stopped (rc=$mrc)"; return
  fi
  if [ "$mrc" = 0 ]; then
    SURVIVED=$((SURVIVED+1)); bad "[$label] SURVIVED — the mutant passes just as well"; return
  fi
  if g6_has "$mout" "$cause"; then
    KILLED=$((KILLED+1)); ok "[$label] killed — removing it breaks exactly this detection"
  else
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the mutant failed for a foreign reason" "$(printf '%s' "$mout" | tail -3)"
  fi
}

# A third polarity, for guards that decide the CLASS of a failure rather than whether it happens.
# Both copies fail the scenario; what the mutation destroys is the reason.
#
# The oracle is not "the phrase disappeared". A mutant that succeeds, that crashes, or that fails
# for some third reason also loses the phrase, and counting any of those as a kill credits this
# row for work it did not do — the same foreign-refusal mistake the other two polarities refuse
# by construction.
#
# A phrase is also not a class. These rows are about WHICH refusal happens, and the refusal a
# reader acts on is the exit status: BLOCKED=2 says the environment is wrong and FAIL=1 says the
# candidate is. So the class is declared in advance, both halves of it, and compared exactly —
# "it still failed somehow" is not the claim. A row that names 2 -> 1 and gets 2 -> 2 has not
# reclassified anything, and 124 or a signal is not a class at all.
#
# So a kill requires all six: the pristine refuses with the declared status naming the cause, the
# mutant refuses with the declared status, the mutant does NOT name the cause, and it DOES name
# the alternative this row declared in advance.
mutate_reclass() {  # label file FROM TO scenario cause alternative pristine-rc/mutant-rc
  g6m_skip "$1" && return
  DECLARED=$((DECLARED+1))
  local label="$1" file="$2" from="$3" to="$4" scenario="$5" cause="$6"
  local dir="$WORK/mut-$DECLARED"; mkdir -p "$dir"
  local f; for f in $DELIVERY; do cp "$PRISTINE/$f" "$dir/"; done
  if ! literal_sub "$dir/$file" "$from" "$to"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the anchor does not occur exactly once in $file"; return
  fi
  case "$file" in
    *.py) python3 -m py_compile "$dir/$file" 2>/dev/null \
            || { INVALID=$((INVALID+1)); bad "[$label] INVALID — does not compile"; return; } ;;
    *)    bash -n "$dir/$file" 2>/dev/null \
            || { INVALID=$((INVALID+1)); bad "[$label] INVALID — does not parse"; return; } ;;
  esac
  local mdir msha
  mdir="$(bash "$dir/g6-controller.sh" bundle | awk -F'\t' '$1=="bundle-dir"{print $2}')"
  msha="$(bash "$dir/g6-controller.sh" bundle | awk -F'\t' '$1=="bundle-sha256"{print $2}')"
  if [ "$mdir" != "$dir" ] || [ "$msha" = "$PRISTINE_SHA" ]; then
    INVALID=$((INVALID+1)); bad "[$label] INVALID — the copy is not what ran"; return
  fi
  local alt="${7:-}" rcpair="${8:-}" want_prc want_mrc
  if [ -z "$alt" ] || [ "$alt" = "-" ]; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — a reclass row must declare the cause the mutant falls back to"; return
  fi
  want_prc="${rcpair%%/*}"; want_mrc="${rcpair##*/}"
  case "$rcpair" in
    */*) ;;
    *) want_prc=""; want_mrc="" ;;
  esac
  case "$want_prc$want_mrc" in
    ''|*[!0-9]*)
      INVALID=$((INVALID+1))
      bad "[$label] INVALID — a reclass row must declare the exit status of both copies, as \
'pristine/mutant'; the registry says '$rcpair'"; return ;;
  esac
  if [ "$want_prc" = 0 ] || [ "$want_mrc" = 0 ]; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — a reclass row declares two REFUSALS; '$rcpair' declares a success"
    return
  fi

  # The pristine copy: it must refuse with exactly the declared status, name this cause, and NOT
  # already be producing the alternative — otherwise the alternative proves nothing about the
  # mutation.
  local pout prc=0; pout="$("$scenario" "$PRISTINE" 2>&1)" || prc=$?
  if [ "$prc" != "$want_prc" ]; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the pristine copy exited $prc, the row declares $want_prc" \
        "$(printf '%s' "$pout" | tail -3)"
    return
  fi
  if ! g6_has "$pout" "$cause"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the pristine copy does not name this cause" "$(printf '%s' "$pout" | tail -3)"
    return
  fi
  if g6_has "$pout" "$alt"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the pristine copy already names the fallback cause" \
        "$(printf '%s' "$pout" | tail -3)"
    return
  fi

  # The mutant: it must still refuse, with the declared status, it must lose this cause, and it
  # must fail for the declared alternative reason rather than for any reason at all.
  local mout mrc=0; mout="$("$scenario" "$dir" 2>&1)" || mrc=$?
  if g6_has "$mout" "$cause"; then
    SURVIVED=$((SURVIVED+1)); bad "[$label] SURVIVED — the mutant still names it"; return
  fi
  if [ "$mrc" != "$want_mrc" ]; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the mutant exited $mrc, the row declares $want_mrc: this is not the \
reclassification the row is about" "$(printf '%s' "$mout" | tail -3)"
    return
  fi
  if ! g6_has "$mout" "$alt"; then
    INVALID=$((INVALID+1))
    bad "[$label] INVALID — the mutant failed for a foreign reason, not '$alt'" \
        "$(printf '%s' "$mout" | tail -3)"
    return
  fi
  KILLED=$((KILLED+1)); ok "[$label] killed — the classification came from exactly this code"
}

echo "== G6 one-to-one source-mutation matrix — complete mutated copies =="
echo "   pristine bundle: $PRISTINE_SHA"
echo

# --- g6-image-lib.sh, one row per guard
mutate "lib/containment" g6-image-lib.sh \
  'g6_contained() {  # path -> 0 when it lies under REMOTE_ROOT by spelling and by canonical form
  local path="$1" p real' \
  'g6_contained() {  # mutant
  return 0
  local path="$1" p real' \
  sc_containment "not under REMOTE_ROOT"

mutate "lib/busy-device" g6-image-lib.sh \
  '  local pre; pre="$(g6_kernel_backing_file)"
  if [ -n "$pre" ]; then' \
  '  local pre; pre="$(g6_kernel_backing_file)"
  if false; then' \
  sc_busy_device "already backs"

mutate_reclass "lib/losetup-fields" g6-image-lib.sh \
  '  if [ -n "$unavailable" ]; then' \
  '  if false; then' \
  sc_no_fields "field is unavailable" "but the planned image" 2/2

mutate "lib/unpublished-attach" g6-image-lib.sh \
  '  if [ "$live_attach" = 1 ] && ! g6_has_record ATTACHED; then' \
  '  if false; then' \
  sc_unpub_attach "ATTACHED was never published"

mutate "lib/unpublished-mount" g6-image-lib.sh \
  '  if [ "$live_mount" = 1 ] && ! g6_has_record MOUNTED; then' \
  '  if false; then' \
  sc_unpub_mount "MOUNTED was never published"

mutate "lib/record-seal" g6-image-lib.sh \
  'g6_record_intact() {  # name -> 0 when the seal verifies
  "$G6_PUBLISH" --verify --dir "$G6_STATE_DIR" --name "$1" >/dev/null 2>&1' \
  'g6_record_intact() {  # mutant
  return 0
  "$G6_PUBLISH" --verify --dir "$G6_STATE_DIR" --name "$1" >/dev/null 2>&1' \
  sc_broken_seal_rec "own seal"

mutate "lib/chain-before-mutation" g6-image-lib.sh \
  '  g6_chain_ok_before format || return 2' \
  '  :' \
  sc_stale_chain "no longer describes the machine"

mutate "lib/frozen-block-size" g6-image-lib.sh \
  '  [ "$bs" = 4096 ] || { g6_blocked "block size is $bs, the frozen value is 4096"; return 2; }' \
  '  :' \
  sc_blocksize "the frozen value is 4096"

# --- g6-controller.sh, one row per guard
mutate "ctl/contour-required" g6-controller.sh \
  "    '') refused \"G6_CONTOUR is not set: say local or host, there is no default\"; return 1 ;;" \
  '    "") return 0 ;;' \
  sc_contour_default "G6_CONTOUR is not set"

mutate "ctl/local-contour-tools" g6-controller.sh \
  '    for t in "$G6_LOSETUP" "$G6_MKFS" "$G6_MOUNT" "$G6_UMOUNT"; do' \
  '    for t in ; do' \
  sc_contour_real "never reaches"

mutate "ctl/load-window" g6-controller.sh \
  '  if [ "$now" -lt "$open" ] || [ "$now" -gt "$close" ]; then' \
  '  if false; then' \
  sc_window "load window is not open"

mutate "ctl/calibration-seal" g6-controller.sh \
  '  [ "$want" = "$got" ] \
    || { refused "the calibration is not the sealed one: sanction pins $want, file is $got"; return 1; }' \
  '  :' \
  sc_cal_seal "not the sealed one"

mutate_reclass "ctl/plan-completeness" g6-controller.sh \
  '    [ -n "$(plan_field "$k")" ] || { refused "the resource plan names no '"'"'$k'"'"'"; return 1; }' \
  '    :' \
  sc_plan_incomplete "names no" "but the frozen plan says" 1/1

mutate "ctl/plan-seal" g6-controller.sh \
  '  [ "$want" = "$got" ] \
    || { refused "the resource plan is not the sealed one: sanction pins $want, file is $got"; return 1; }' \
  '  :' \
  sc_plan_seal "resource plan is not the sealed one"

mutate "ctl/internal-byte-margin" g6-controller.sh \
  '      byte_need=$G6_INTERNAL_BYTE_RESERVE' \
  '      byte_need=0' \
  sc_internal_bytes "internal byte margin"

mutate "ctl/internal-inode-margin" g6-controller.sh \
  '    have="$(avail_inodes "$inside_dir")"' \
  '    have="$inode_need"' \
  sc_internal_inodes "internal inode margin"

mutate "gen/final-capacity-check" g6-make-fixture.sh \
  'if [ -n "$G6_CAPACITY_HOOK" ]; then
  if ! "$G6_CAPACITY_HOOK"; then
    blocked "capacity hook refused after the final batch — the fixture is complete but the \
margin it left behind is not the one that was sanctioned"
  fi
fi' \
  ':' \
  sc_final_capacity "refused after the final batch"

mutate "ctl/external-margin" g6-controller.sh \
  '  [ "$have" -ge "$G6_EXTERNAL_REQUIREMENT" ] \' \
  '  [ 1 = 1 ] \' \
  sc_external_bytes "external requirement"

# --- g6-make-fixture.sh
mutate "gen/min-size-floor" g6-make-fixture.sh \
  '[ "$G6_B" -ge 4096 ] || die' \
  '[ "$G6_B" -ge 0 ] || die' \
  sc_tiny_b "min_size"

mutate "gen/mode-required" g6-make-fixture.sh \
  "  '') die \"--mode is required and has no default: say live or rehearsal\" ;;" \
  '  "") MODE=rehearsal ;;' \
  sc_no_mode "--mode is required"

mutate_reclass "gen/live-scale" g6-make-fixture.sh \
  '    [ "$have" = "$want" ] || die "live refuses $name='"'"'$have'"'"'; the frozen value is '"'"'$want'"'"'"' \
  '    :' \
  sc_live_scale "the frozen value is" "without a capacity hook" 1/1

mutate_reclass "gen/hook-argv" g6-make-fixture.sh \
  'if [ -n "$G6_CAPACITY_HOOK" ] && [ ! -x "$G6_CAPACITY_HOOK" ]; then' \
  'if false; then' \
  sc_hook_argv "never a command line" "capacity hook refused before batch" 1/2

# --- g6-publish-record.py
mutate "pub/seal-verify" g6-publish-record.py \
  '    if body is None:
        return f"'"'"'{path}'"'"' carries no {SIZE_KEY}/{SHA_KEY} seal"' \
  '    if body is None:
        return None' \
  sc_unsealed_rec "seal"

# --- g6-verify-counts.py
mutate_reclass "verify/negative-control-lock" g6-verify-counts.py \
  '    if args.membership_source != "file_group" and not args.negative_control:' \
  '    if False:' \
  sc_neg_control "negative control" "cannot open" 2/2

# ---------------------------------------------------------------- the eleven corrections
#
# Two polarities, both one-to-one. `mutate` is for a guard whose removal ACCEPTS something the
# pristine refuses. `mutate_detect` is for a guard whose removal breaks DETECTION: the pristine
# passes the scenario, and the mutant is caught failing it by the guard's own words. Either way
# a foreign refusal is INVALID.

# --- scenarios for the eleven
sc_state_tamper() { local d="$1" w="$WORK/st$RANDOM"; mkdir -p "$w"
                    printf 'PUBLISHED 0 TERMINAL 512 abc\nstate-sha256\tdeadbeef\n' > "$w/PUBSTATE"
                    "$d/g6-publish-record.py" --query-state --state-file "$w/PUBSTATE" 2>&1; }
sc_route_twice()  { local d="$1"; sealed_world "$d"
                    bash "$d/g6-controller.sh" route --mode rehearsal >/dev/null 2>&1
                    bash "$d/g6-controller.sh" route --mode rehearsal 2>&1; }
# A run refused on its window that had already left a lifecycle record behind. The zero-write
# state is recorded either way; what the downgrade decides is whether the VERDICT is allowed to
# stand as it was. So the assertion is on the reason the record carries, not on the presence of
# the zero-write line — which is there in both copies and proves nothing about the downgrade.
sc_zero_write()   { local d="$1" out; sealed_world "$d"
                    # C2-2 moved every read-only refusal BEFORE BEGIN, so a refusal over a
                    # leftover no longer writes a terminal record at all — it reports the
                    # violation in the prestart refusal itself. The claim this row now pins is
                    # the same one at its new address: a refusal over a dirty machine must SAY
                    # the machine is dirty, never "proved".
                    : > "$G6_STATE_DIR/PREPARED"
                    sed -i 's/^window-close\t9999999999/window-close\t4000/' "$SANC"
                    out="$(bash "$d/g6-controller.sh" route --mode rehearsal 2>&1)" || true
                    printf '%s' "$out" | grep -q 'nothing was touched (VIOLATED: PREPARED)' \
                      || { printf 'zero-write-downgrade -> the refusal did not name what was left: %s\n' \
                             "$(printf '%s' "$out" | tail -1)"
                           return 1; }
                    return 0; }
sc_pin_mountpoint() { local d="$1"; sealed_world "$d"
                      grep -v '^mountpoint	' "$SANC" > "$SANC.n" && mv "$SANC.n" "$SANC"
                      bash "$d/g6-controller.sh" check-sanctions --mode rehearsal 2>&1; }
# PREPARED re-published with the same facts and a different digest. Every field the later checks
# read still agrees with the machine, so the ONLY thing wrong with the chain is that ATTACHED
# links back to a record that no longer hashes that way. Republishing it with junk fields instead
# made the image checks fire too, and this row would have been credited for their refusals.
sc_crosslink()    { local d="$1"; lib_world
                    bash "$d/g6-image-lib.sh" prepare >/dev/null 2>&1
                    bash "$d/g6-image-lib.sh" attach >/dev/null 2>&1
                    rm -f "$G6_STATE_DIR/PREPARED"
                    { printf 'image\t%s\n'  "$G6_IMAGE"
                      printf 'devino\t%s\n' "$(stat -c '%d:%i' -- "$G6_IMAGE")"
                      printf 'size\t%s\n'   "$(stat -c '%s' -- "$G6_IMAGE")"
                      printf 'loop_dev\t%s\n' "$G6_LOOP_DEV"
                      printf 'reissued\tsame facts, another digest\n'
                      printf 'prev-sha256\tnone\n'; } \
                      | "$d/g6-publish-record.py" --dir "$G6_STATE_DIR" --name PREPARED >/dev/null 2>&1
                    bash "$d/g6-image-lib.sh" verify 2>&1; }
sc_cal_removed()  { local d="$1"; sealed_world "$d"
                    bash "$d/g6-controller.sh" calibrate --mode rehearsal "$G6T_W/c.txt" >/dev/null 2>&1
                    [ ! -e "$G6_REMOTE_ROOT/g6-calibration-image/calibration.img" ] \
                      || { echo "cal-image-still-there"; return 1; }; }
sc_cal_formula()  { local d="$1"; sealed_world "$d"
                    bash "$d/g6-controller.sh" calibrate --mode rehearsal "$G6T_W/c.txt" >/dev/null 2>&1
                    grep -q '^formula	max(4 \* 100 \* t, 900)' "$G6T_W/c.txt" \
                      || { printf 'cal-formula-manifest -> the manifest does not carry the frozen formula\n'
                           return 1; }
                    return 0; }

mutate "corr/strict-state-seal" g6-publish-record.py \
  '    if hashlib.sha256((head + "\n").encode()).hexdigest() != want:' \
  '    if False:' \
  sc_state_tamper "FAILED"

mutate_reclass "corr/rerun-gate" g6-controller.sh \
  '  if [ "$qstate" != NOT_STARTED ] || [ "$qrc" != 0 ] || [ -e "$G6_WORK/TERMINAL" ]; then' \
  '  if false; then' \
  sc_route_twice "already carries a finished run" "the run could not announce itself" 2/2

# The terminalize-side downgrade branch this row used to mutate is still in the delivery, but
# after C2-2 it is reachable only in the two-line window between BEGIN and the first mutation —
# no deterministic oracle can drive a run into it. What IS provable is the same claim at the
# prestart address: the refusal's zero-write report must come from looking, not from optimism.
mutate_detect "corr/zero-write-downgrade" g6-controller.sh \
  '  [ -z "$leftovers" ] && printf '"'"'proved'"'"' || printf '"'"'VIOLATED:%s'"'"' "$leftovers"' \
  '  printf '"'"'proved'"'"'' \
  sc_zero_write "zero-write-downgrade ->"

mutate_reclass "corr/full-resource-pins" g6-controller.sh \
  'image loop-device uuid mountpoint state-dir work-dir image-size"' \
  'image loop-device uuid"' \
  sc_pin_mountpoint "pins no 'mountpoint'" "disagree about 'mountpoint'" 1/1

mutate "corr/crosslink" g6-image-lib.sh \
  '  for r in PREPARED ATTACHED FORMATTED MOUNTED TORNDOWN; do
    g6_has_record "$r" || continue
    g6_check_crosslink "$r" || rc=2
  done' \
  '  :' \
  sc_crosslink "links back to PREPARED"

mutate_detect "corr/calibration-image-removed" g6-controller.sh \
  '  cal_lib teardown >/dev/null 2>&1 \' \
  '  true \' \
  sc_cal_removed "cal-image-still-there"

mutate_detect "corr/calibration-formula" g6-controller.sh \
  "    printf 'formula\\tmax(4 * %s * t, 900)\\n' \"\$CAL_DIVISOR\"" \
  "    printf 'formula\\tguessed\\n'" \
  sc_cal_formula "cal-formula-manifest ->"

# A verifier that was NEVER there is caught by the preflight now, before BEGIN, in both copies
# — which is exactly why this row makes it vanish AFTER the run began: the candidate stand-in
# deletes a COPY of the verifier during the scan, so the VERIFY-step guard is the only thing
# left between the run and a 127 read as "the counts disagreed".
sc_verifier_rc() { local d="$1"; g6s_world
                   cp "$d/g6-verify-counts.py" "$G6T_W/verify-copy.py"
                   { printf '#!/usr/bin/env bash\n'
                     printf 'for a in "$@"; do [ "$a" = --scan ] && rm -f %q; done\n' \
                       "$G6T_W/verify-copy.py"
                     printf 'exec %q "$@"\n' "$DEDCOM"
                   } > "$G6T_W/vergone"
                   chmod +x "$G6T_W/vergone"
                   g6s_seal "$d" "$G6T_W/vergone"
                   G6_VERIFY_COUNTS="$G6T_W/verify-copy.py" \
                     bash "$d/g6-controller.sh" route --mode rehearsal 2>&1; }
sc_failfast()    { local d="$1" got
                   g6s_world
                   g6s_badstats_candidate "$G6T_W/badstats"
                   g6s_seal "$d" "$G6T_W/badstats"
                   bash "$d/g6-controller.sh" route --mode rehearsal >/dev/null 2>&1
                   got="$(awk -F'\t' '$1 == "stopped-at" { print $2 }' \
                            "$G6_WORK/TERMINAL" 2>/dev/null)"
                   # Without the marker the record still carries a stopped-at — the stage name,
                   # not the step. "There is a line" is not the claim; naming the step is.
                   [ "$got" = S1 ] \
                     || { printf 'fail-fast-marker -> the run stopped at %s, not at S1\n' \
                            "${got:-nothing}"; return 1; }
                   return 0; }
sc_s3_observer() { local d="$1"; sealed_world "$d"
                   bash "$d/g6-controller.sh" route --mode rehearsal >/dev/null 2>&1
                   local w="$G6_WORK/scenarios/S3.witness"
                   local n; n="$(awk -F'\t' '$1=="observer-samples"{print $2}' "$w" 2>/dev/null)"
                   [ -n "$n" ] && [ "$n" -ge 1 ] || { echo "the observer took no sample"; return 1; }; }
sc_verifier_counts() { local d="$1"
                       g6s_world
                       g6s_row_deleter "$G6T_W/deleter"
                       g6s_seal "$d" "$G6T_W/deleter"
                       bash "$d/g6-controller.sh" route --mode rehearsal 2>&1; }

mutate_reclass "corr/verifier-rc" g6-controller.sh \
  '      > "$G6_WORK/verify.out" 2>&1 || vrc=$?' \
  '      > "$G6_WORK/verify.out" 2>&1; vrc=0' \
  sc_verifier_counts "the counts contradict the derived formulas" "S1-post" 1/1

mutate_reclass "corr/verifier-missing" g6-controller.sh \
  '  [ -x "$G6_VERIFY_COUNTS" ] \
    || terminalize BLOCKED "the independent verifier '"'"'$G6_VERIFY_COUNTS'"'"' is not executable"' \
  '  :' \
  sc_verifier_rc "is not executable" "the counts contradict the derived formulas" 2/1

mutate_detect "corr/fail-fast-marker" g6-controller.sh \
  '  note_step() { printf '"'"'%s\n'"'"' "$1" > "$outdir/STOPPED-AT"; }' \
  '  note_step() { :; }' \
  sc_failfast "fail-fast-marker ->"

mutate_detect "corr/s3-concurrent-observer" g6-controller.sh \
  '  local obs_pid=$!' \
  '  local obs_pid=$!; kill "$obs_pid" 2>/dev/null; : > "$obs_log"' \
  sc_s3_observer "the observer took no sample"

# ---------------------------------------------------------------- the directed scenarios
#
# One row per scenario in the shared registry, and the registry decides the polarity and the
# cause. The only thing declared here is the EDIT — which guard is being removed — so a row can
# never quietly test a different thing from the scenario it names.

MUTATED_ROWS=""

mutate_row() {  # registry-name file FROM TO
  local name="$1" file="$2" from="$3" to="$4" fn pol cause alt rcpair
  fn="$(g6s_row_field "$name" 2)"
  pol="$(g6s_row_field "$name" 3)"
  cause="$(g6s_row_field "$name" 4)"
  alt="$(g6s_row_field "$name" 5)"
  rcpair="$(g6s_row_field "$name" 6)"
  MUTATED_ROWS="$MUTATED_ROWS $name"
  if [ -z "$fn" ] || [ -z "$pol" ]; then
    DECLARED=$((DECLARED+1)); INVALID=$((INVALID+1))
    bad "[$name] INVALID — no such row in the scenario registry"; return
  fi
  case "$pol" in
    refuse)  mutate         "$name" "$file" "$from" "$to" "$fn" "$cause" ;;
    hold)    mutate_detect  "$name" "$file" "$from" "$to" "$fn" "$cause" ;;
    reclass) mutate_reclass "$name" "$file" "$from" "$to" "$fn" "$cause" "$alt" "$rcpair" ;;
    *) DECLARED=$((DECLARED+1)); INVALID=$((INVALID+1))
       bad "[$name] INVALID — the registry declares polarity '$pol'" ;;
  esac
}

# --- publisher
mutate_row "pub/partial-write" g6-publish-record.py \
  '    if not size.isdigit() or int(size) != len(body):' \
  '    if False:'

mutate_row "pub/zero-write" g6-publish-record.py \
  '    if not body:' \
  '    if False:'

mutate_row "pub/state-corrupt" g6-publish-record.py \
  '    if len(lines) != 2 or not lines[1].startswith("state-sha256\t"):' \
  '    if False:'

mutate_row "pub/state-unreadable" g6-publish-record.py \
  '        if exc.errno == errno.ENOENT:' \
  '        if True:'

mutate_row "pub/state-unknown" g6-publish-record.py \
  '    if state not in VALID_STATES or not code.strip().isdigit():' \
  '    if False:'

mutate_row "pub/terminal-deleted" g6-controller.sh \
  '    [ "$qrec" != missing ] || refuse_reentry "this evidence directory already carries a \
finished run (state $qstate, code $qcode) whose terminal record has been deleted"' \
  '    :'

mutate_row "pub/terminal-substituted" g6-controller.sh \
  '      case "$qrec" in
        sha-mismatch|size-mismatch|unsealed|unreadable)' \
  '      case nothing in
        sha-mismatch|size-mismatch|unsealed|unreadable)'

mutate_row "pub/reentry-0" g6-publish-record.py \
  '        if rc == 0:' \
  '        if False:'

mutate_row "pub/reentry-1" g6-publish-record.py \
  '            if not write_state(args.state_file, "PUBLISHED", args.code, args.name,' \
  '            if not write_state(args.state_file, "PUBLISHED", 0, args.name,'

mutate_row "pub/reentry-2" g6-controller.sh \
  '    exit $RC_BLOCKED
  }' \
  '    exit $RC_FAIL
  }'

# --- S3
mutate_row "s3/partial-destination" g6-controller.sh \
  '  [ "$odd" = 0 ] || {' \
  '  [ 0 = 0 ] || {'

# --- calibration
mutate_row "cal/no-sanction" g6-controller.sh \
  '  verify_sanction_core \
    || { refused "calibration refuses without a sanction for this contour, mode and root — \
nothing was created and no device was touched"; return 1; }' \
  '  :'

mutate_row "cal/formula" g6-controller.sh \
  '  g1=$(( 4 * CAL_DIVISOR * t1 )); [ "$g1" -lt 900 ] && g1=900' \
  '  g1=$(( 2 * CAL_DIVISOR * t1 )); [ "$g1" -lt 900 ] && g1=900'

# --- lifecycle
mutate_row "lc/loop-partition" g6-image-lib.sh \
  '  case "${G6_LOOP_DEV#/dev/loop}" in' \
  '  case 0 in'

mutate_row "lc/uuid-shape" g6-image-lib.sh \
  '  if ! [[ "$G6_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then' \
  '  if false; then'

mutate_row "lc/image-devino" g6-image-lib.sh \
  '    want="$(g6_record_field PREPARED devino)"; got="$(g6_stat_devino "$G6_IMAGE")"
    if [ -n "$got" ] && [ "$want" != "$got" ]; then' \
  '    want="$(g6_record_field PREPARED devino)"; got="$(g6_stat_devino "$G6_IMAGE")"
    if false; then'

mutate_row "lc/image-missing" g6-image-lib.sh \
  '    if [ "$live_image" = 0 ]; then' \
  '    if false; then'

mutate_row "lc/backing-dev" g6-image-lib.sh \
  '    want="$(g6_record_field ATTACHED backing_dev)"' \
  '    want="$bd"'

mutate_row "lc/mount-fstype" g6-image-lib.sh \
  '  if [ "$fstype" != ext4 ]; then' \
  '  if false; then'

mutate_row "lc/mount-devno" g6-image-lib.sh \
  '  if [ -n "$kdevno" ] && [ "$majmin" != "$kdevno" ]; then' \
  '  if false; then'

mutate_row "lc/resume-attach" g6-image-lib.sh \
  '    PREPARED)  next=attach ;;' \
  '    PREPARED)  next=prepare ;;'

mutate_row "lc/resume-format" g6-image-lib.sh \
  '    ATTACHED)  next=format ;;' \
  '    ATTACHED)  next=attach ;;'

mutate_row "lc/resume-mount" g6-image-lib.sh \
  '    FORMATTED) next=mount ;;' \
  '    FORMATTED) next=format ;;'

mutate_row "lc/resume-teardown" g6-image-lib.sh \
  '    MOUNTED)   next=teardown ;;' \
  '    MOUNTED)   next=mount ;;'

mutate_row "lc/crash-after-umount" g6-image-lib.sh \
  '  if g6_has_record MOUNTED && { [ "$scope" = strict ] || [ "$live_mount" = 1 ]; }; then' \
  '  if g6_has_record MOUNTED; then'

mutate_row "lc/crash-after-detach" g6-image-lib.sh \
  '  if g6_has_record ATTACHED && { [ "$scope" = strict ] || [ "$live_attach" = 1 ]; }; then' \
  '  if g6_has_record ATTACHED; then'

mutate_row "lc/crash-after-unlink" g6-image-lib.sh \
  '  if g6_has_record PREPARED && { [ "$scope" = strict ] || [ "$live_image" = 1 ]; }; then' \
  '  if g6_has_record PREPARED; then'

mutate_row "lc/dir-residue" g6-image-lib.sh \
  '  if [ -d "$(dirname "$G6_IMAGE")" ]; then' \
  '  if false; then'

# --- provenance
mutate_row "prov/pre-existing-state" g6-controller.sh \
  '  if [ -e "$st/dedcom.db" ]; then
    blocked "a checkpoint already exists at '"'"'$st/dedcom.db'"'"' before the scan — this run cannot \
claim the provenance of a database it did not create"
    return 2
  fi' \
  '  :'

mutate_row "prov/incomplete-schema" g6-controller.sh \
  '  for t in scan file file_group dir_omission; do
    case ",$tables," in *",$t,"*) ;; *) absent="$absent $t" ;; esac
  done' \
  '  :'

mutate_row "prov/candidate-swapped" g6-controller.sh \
  '  # unattested.
  want="$(sanction_field candidate-sha256)"; got="$(sha_of "$G6_BIN")"' \
  '  # unattested.
  want="$(sanction_field candidate-sha256)"; got="$want"'

mutate_row "prov/receipt-argv" g6-controller.sh \
  '    printf '"'"'scan-argv\t%s\n'"'"' "$argv"' \
  '    printf '"'"'scan-argv\tsomething-else\n'"'"''

# --- fail-fast and the verdict
mutate_row "ff/nothing-after" g6-controller.sh \
  'sc_end FAIL "S1-post: reported files=$rf, SQL=$files"; return; }' \
  'sc_end FAIL "S1-post: reported files=$rf, SQL=$files"; }'

mutate_row "verdict/multiline" g6-controller.sh \
  '  sverdict="$(read_scenario_verdict "$outdir")"' \
  '  sverdict="$(run_scenarios "$outdir")"'

# --- publisher, part two
mutate_row "pub/physical-no-overwrite" g6-publish-record.py \
  '    if os.path.exists(final):' \
  '    if False:'

mutate_row "pub/terminal-unsealed" g6-publish-record.py \
  '    problem = verify(final)
    if problem:
        return "unsealed", problem' \
  '    problem = None
    if problem:
        return "unsealed", problem'

# --- the route as a whole
mutate_row "route/signal" g6-controller.sh \
  "  trap 'G6_RAW_SIGNAL=TERM; guard_interrupt_now; terminalize BLOCKED \"the run was interrupted by SIGTERM\"' TERM" \
  '  :'

# The reap half alone: the record is still published and the exit is still 143, but the guarded
# workload is left to the distant scan deadline — the pre-§5 behaviour, and the scenario now
# has to notice the scan outliving the terminal record.
mutate_row "route/signal-reap" g6-controller.sh \
  "  trap 'G6_RAW_SIGNAL=TERM; guard_interrupt_now; terminalize BLOCKED \"the run was interrupted by SIGTERM\"' TERM" \
  "  trap 'G6_RAW_SIGNAL=TERM; terminalize BLOCKED \"the run was interrupted by SIGTERM\"' TERM"

# The anchor once carried the "# fresh | resume" signature comment; C2-6 removed resume and the
# comment with it, and the row was INVALID from that commit to the first full matrix.
mutate_row "route/contour-first" g6-controller.sh \
  'route_common() {' \
  'route_common() {
  mkdir -p "$G6_WORK" 2>/dev/null'

# --- calibration, part two
mutate_row "cal/candidate-pin" g6-controller.sh \
  '  verify_candidate >/dev/null \
    || { refused "calibration refuses a candidate the sanction does not pin"; return 1; }' \
  '  :'

mutate_row "cal/kit-separate" g6-controller.sh \
  '  for k in image mountpoint state-dir; do' \
  '  for k in ; do'

mutate_row "cal/manifest-sealed" g6-controller.sh \
  '  } | "$G6_PUBLISH" --dir "$(dirname "$out")" --name "$(basename "$out")" >/dev/null 2>&1 \' \
  '  } > "$out" \'

mutate_row "cal/fixture-verified" g6-controller.sh \
  '  "$G6_VERIFY_COUNTS" --db "$cal_mnt/state/dedcom.db" \
      --groups "$g" --members-per-group "$m" --singletons "$u" \
      > "$outdir/verify.out" 2>&1 \
    || { cat "$outdir/verify.out" >&2
         blocked "the calibration fixture does not match its own parameters"; return 2; }' \
  '  :'

mutate_row "cal/no-word-splitting" g6-controller.sh \
  '      G6_MOUNTPOINT="$(plan_field cal-mountpoint)" \' \
  '      $(echo G6_MOUNTPOINT=$(plan_field cal-mountpoint)) \'

# --- plan and capacity
mutate_row "plan/env-override" g6-controller.sh \
  '  for p in $G6_ENV_PINS; do' \
  '  for p in ; do'

mutate_row "plan/host" g6-controller.sh \
  '  local here_host; here_host="$(host_identity)"' \
  '  local here_host; here_host="$(plan_field host)"'

mutate_row "plan/work-contained" g6-controller.sh \
  '  for k in mountpoint image state-dir work-dir evidence-dir cal-image cal-mountpoint \
           cal-state-dir; do' \
  '  for k in ; do'

mutate_row "plan/inode-total" g6-controller.sh \
  '    have="$(total_inodes "$inside_dir")"' \
  '    have="$need"'

# The anchor here went stale TWICE unseen: C2-3 moved the measurement to the sanctioned root
# and C2-4 gave check_capacity its modes, and this row silently stopped mutating anything until
# a filtered run tripped over it. The route-side check is the one this scenario starves.
mutate_row "plan/capacity-before-create" g6-controller.sh \
  '  check_capacity full "$G6_REMOTE_ROOT" \
                          || prestart_refusal "capacity before the image was created"' \
  '  :'

# --- lifecycle, part two
mutate_row "lc/attach-inode-binding" g6-image-lib.sh \
  '  [ "$bi" = "$planned_ino" ] || {' \
  '  [ 1 = 1 ] || {'

mutate_row "lc/format-fstype" g6-image-lib.sh \
  '  if [ "$seen_type" != ext4 ]; then' \
  '  if false; then'

mutate_row "lc/format-inode-total" g6-image-lib.sh \
  '    [ "$ic" -ge "$G6_MIN_INODES" ] \
      || { g6_blocked "the filesystem has $ic inodes, the run needs $G6_MIN_INODES"; return 2; }' \
  '    :'

mutate_row "lc/state-contained" g6-image-lib.sh \
  '  g6_contained "$G6_STATE_DIR" || return 1' \
  '  :'

mutate_row "lc/torndown-seal" g6-image-lib.sh \
  '    g6_record_intact TORNDOWN \
      || { g6_blocked "TORNDOWN is present but does not verify against its own seal"; return 2; }' \
  '    :'

mutate_row "lc/detach-ineffective" g6-image-lib.sh \
  '    if [ -n "$(g6_kernel_backing_file)" ]; then
      g6_inventory >&2; g6_blocked "$G6_LOOP_DEV still reports a backing file after detach"
      return 2
    fi' \
  '    :'

# --- provenance, part two
mutate_row "prov/invocation-record" g6-controller.sh \
  '  publish_invocation || terminalize BLOCKED "provenance: the invocation could not be recorded"' \
  '  :'

mutate_row "prov/read-after-verify" g6-controller.sh \
  '    "$G6_PUBLISH" --verify --dir "$G6_WORK" --name INVOCATION >/dev/null 2>&1 \
      || { blocked "the invocation record does not verify against its own seal"; return 2; }' \
  '    :'

mutate_row "prov/structural-v5" g6-verify-counts.py \
  '    absent = [i for i in V5_INDEXES if i not in indexes]' \
  '    absent = []'

mutate_row "prov/receipt-in-verifier" g6-verify-counts.py \
  '    if args.receipt is not None:' \
  '    if False:'

mutate_row "prov/sqlite-blocked" g6-verify-counts.py \
  '        print(f"BLOCKED: the schema of {args.db} could not be read: {exc}", file=sys.stderr)
        return 2' \
  '        raise'

# --- the write path itself
mutate_row "pub/write-short" g6-publish-record.py \
  '        written += n' \
  '        written += len(data)'

mutate_row "pub/write-no-progress" g6-publish-record.py \
  '        if n <= 0:' \
  '        if n < 0:'

mutate_row "pub/write-publish-nothing-left" g6-publish-record.py \
  '        write_all(fd, sealed, tmp)' \
  '        os.write(fd, sealed)'

# --- the claim on an evidence directory
mutate_row "pub/begin-concurrent" g6-publish-record.py \
  '        # The scratch name goes before the directory is fsynced, so the claim and the removal of
        # the temporary land in one fsync — and a loser, like a winner, leaves nothing behind.
        os.unlink(tmp)' \
  '        # The scratch name goes before the directory is fsynced, so the claim and the removal of
        # the temporary land in one fsync — and a loser, like a winner, leaves nothing behind.
        pass'

mutate_row "pub/begin-create-only" g6-publish-record.py \
  '        try:
            os.link(tmp, path)
            outcome = "ok"' \
  '        try:
            os.replace(tmp, path)
            outcome = "ok"'

# --- durable run state and the two kinds of exit
mutate_row "route/begin-durable" g6-controller.sh \
  '    "$G6_PUBLISH" --begin --state-file "$G6_WORK/PUBSTATE" > "$G6_WORK/begin.out" 2>&1 \' \
  '    true \'

# Same story as route/contour-first: C2-2 rerouted the refusal through prestart_refusal and the
# old printf anchor stopped matching anything.
mutate_row "route/prestart-leaves-nothing" g6-controller.sh \
  '  verify_contour          || prestart_refusal "the contour was refused"' \
  '  verify_contour          || { mkdir -p "$G6_WORK" 2>/dev/null
    "$G6_PUBLISH" --begin --state-file "$G6_WORK/PUBSTATE" >/dev/null 2>&1
    prestart_refusal "the contour was refused"; }'

mutate_row "lc/interrupted-blocked" g6-controller.sh \
  '      [ "$qstate" != RUNNING ] \' \
  '      [ 1 = 1 ] \'

# --- S3
mutate_row "s3/ready-after-sample" g6-observe-destination.py \
  '        fh.write(sample(dest) + "\n")
        with open(ready, "w") as rh:' \
  '        with open(ready, "w") as rh:'

mutate_row "s3/hung-observer" g6-controller.sh \
  '  local reaped=0 spin=0' \
  '  local reaped=0 spin=0; wait "$obs_pid" 2>/dev/null'

# --- calibration
mutate_row "cal/own-numbers" g6-controller.sh \
  '  use_calibration_numbers' \
  '  :'

mutate_row "cal/guarded-scan" g6-controller.sh \
  '  guarded_run "$G6_CAL_BOOTSTRAP_GUARD" CALSCAN "$outdir" -- \
    "$G6_BIN" --state-dir "$cal_mnt/state" --scan "$cal_mnt/data" --no-resume \' \
  '  "$G6_BIN" --state-dir "$cal_mnt/state" --scan "$cal_mnt/data" --no-resume >/dev/null 2>&1 \'

# The bootstrap pin ignored: a hardwired hour in its place lets a starved calibration run to
# completion, and the scenario that pins the limit to one second has to see that.
mutate_row "cal/bootstrap-blocked" g6-controller.sh \
  '  guarded_run "$G6_CAL_BOOTSTRAP_GUARD" CALSCAN "$outdir" -- \' \
  '  guarded_run 3600 CALSCAN "$outdir" -- \'

# The sealed scan guard replaced by the old constant: the route still runs, but the guard its
# own meta records is 600 and not the number the manifest sealed.
mutate_row "route/scan-guard-used" g6-controller.sh \
  '  guarded_run "$(calibration_field guard-SCAN)" SCAN "$outdir" -- \' \
  '  guarded_run 600 SCAN "$outdir" -- \'

# The read-only probe removed: a candidate that corrupts its checkpoint after the S4 refusal
# sails through, and the scenario that breaks the checkpoint on purpose has to notice.
mutate_row "s4/still-opens" g6-controller.sh \
  '  checkpoint_opens_ro "$st/dedcom.db" || {' \
  '  true || {'

# --- preflight over the delivery's own parts

# The calibrate-side preflight removed: every tool question then waits until the tool is
# needed, which is after the lifecycle has already run and the candidate has already scanned.
mutate_row "cal/pf-publisher" g6-controller.sh \
  '  preflight_tools || return 2' \
  '  :'

# The supervisor dropped from the parts the preflight asks about. guarded_run still refuses on
# its own — but only with the lifecycle already run, which is exactly what the scenario counts.
mutate_row "cal/pf-supervisor" g6-controller.sh \
  '  for t in "$G6_SUPERVISOR" "$G6_PUBLISH" "$G6_VERIFY_COUNTS"; do' \
  '  for t in "$G6_PUBLISH" "$G6_VERIFY_COUNTS"; do'

# The verifier dropped from the same list: the question waits for the verify call, behind a
# built fixture and a completed calibration scan.
mutate_row "cal/pf-verifier" g6-controller.sh \
  '  for t in "$G6_SUPERVISOR" "$G6_PUBLISH" "$G6_VERIFY_COUNTS"; do' \
  '  for t in "$G6_SUPERVISOR" "$G6_PUBLISH"; do'

# The detachment probe removed: a setsid that exists but does not detach passes preflight, and
# the whole calibration then completes on a guard that would die with its controller.
mutate_row "cal/pf-setsid" g6-controller.sh \
  '  { [ -n "$there_sid" ] && [ "$there_sid" != "$here_sid" ]; } \' \
  '  { true; } \'

# The route-side twin of cal/pf-verifier: without the preflight entry the missing verifier is
# discovered at the VERIFY step, behind BEGIN, an image, a scan and a RUNNING record.
mutate_row "route/verifier-preflight" g6-controller.sh \
  '  for t in "$G6_SUPERVISOR" "$G6_PUBLISH" "$G6_VERIFY_COUNTS"; do' \
  '  for t in "$G6_SUPERVISOR" "$G6_PUBLISH"; do'

# --- the supervisor's critical branches

# The start time never read: READY announces an identity nobody captured, and everything
# downstream that verifies kills against it has nothing to verify.
mutate_row "wd/identity-before-ready" g6-supervisor.sh \
  'starttime="$(tail_field "$line" 20)"' \
  'starttime=""'

# The deadline never fires: the watch loop waits on the leader alone, and a TERM-proof
# workload knows no limit at all.
mutate_row "wd/deadline" g6-supervisor.sh \
  '  if [ "$waited" -ge "$deadline" ]; then fired=1; break; fi' \
  '  :'

# The escalation loses its first step: nothing polite is ever asked to leave, everything
# is KILLed outright.
mutate_row "wd/term-before-kill" g6-supervisor.sh \
  '  signal_guarded TERM' \
  '  :'

# The sweep looks and sees nothing: the leader's clean exit is reported as a cleared group
# over a living survivor.
mutate_row "wd/sweep" g6-supervisor.sh \
  '  survivors="$(group_survivors)"' \
  '  survivors=""'

# The start time dropped from the controller's identity check: a recycled number verifies by
# group alone, and the fallback shoots the decoy wearing it.
mutate_row "wd/starttime-recheck" g6-controller.sh \
  '  [ "$(tail_field "$l" 3)" = "$G6_LAST_PGID" ] && \
    [ "$(tail_field "$l" 20)" = "$G6_LAST_STARTTIME" ]' \
  '  [ "$(tail_field "$l" 3)" = "$G6_LAST_PGID" ]'

# The refusal branch removed outright: the fallback no longer declines an unverified identity,
# it signals it.
mutate_row "wd/fallback-refusal" g6-controller.sh \
  '  if ! guard_identity_holds; then
    [ -d "/proc/$G6_LAST_PID" ] && \
      say "pid $G6_LAST_PID no longer matches the recorded identity — refusing to signal it"
    return 0
  fi' \
  '  :'

mutate_row "cal/capacity-hook" g6-controller.sh \
      '      G6_BATCH="$G6_BATCH" G6_CAPACITY_HOOK="$cal_hook" \' \
      '      G6_BATCH="$G6_BATCH" \'

mutate_row "cal/geometry" g6-image-lib.sh \
  '  "$G6_MKFS" -b "$G6_BLOCK_SIZE" -N "$G6_REQUESTED_INODES" -m 0 -U "$G6_UUID" "$G6_LOOP_DEV" \' \
  '  "$G6_MKFS" -b 4096 -N 2500000 -m 0 -U "$G6_UUID" "$G6_LOOP_DEV" \'

# --- host identity
mutate_row "plan/host-live" g6-controller.sh \
  '  if [ "$MODE" = live ]; then
    hostname 2>/dev/null' \
  '  if false; then
    hostname 2>/dev/null'

# --- provenance
mutate_row "prov/receipt-seal" g6-verify-counts.py \
  '    if got != sha:
        raise ValueError(f"'"'"'{path}'"'"' records digest {sha}, body hashes to {got}")' \
  '    if False:
        raise ValueError(f"'"'"'{path}'"'"' records digest {sha}, body hashes to {got}")'

mutate_row "prov/invocation-binding" g6-verify-counts.py \
  '    elif claimed != inv_digest:' \
  '    elif False:'

mutate_row "prov/index-shape" g6-verify-counts.py \
  '        if got != keys:' \
  '        if False:'

mutate_row "prov/all-columns" g6-verify-counts.py \
  '    "hash_cache": ("device", "inode", "size", "mtime", "hash", "updated_at"),' \
  '    "hash_cache": (),'

# The C2-9 elements, one mutant per name — declared in C2-9's registry rows and never wired to
# a mutation until the first full matrix demanded them. Each mutant RENAMES the expected element
# instead of dropping it: dropping would let the run continue past the verifier onto a
# candidate-dependent path with an unpredictable exit, while a rename keeps the refusal on the
# same deterministic line — and still proves the NAME in the contract is the one that catches
# the defect: the pristine copy names the dropped element, the mutant names its stand-in and
# misses the drop.
mutate_row "prov/col-scan-trashed" g6-verify-counts.py \
  '    "scan": ("id", "created_at", "updated_at", "status", "config_json", "trashed"),' \
  '    "scan": ("id", "created_at", "updated_at", "status", "config_json", "zz_mutant"),'

mutate_row "prov/col-hash-failures" g6-verify-counts.py \
  '                   "reclaim_state", "hash_failures", "results_materialized",' \
  '                   "reclaim_state", "zz_mutant", "results_materialized",'

mutate_row "prov/col-materialized" g6-verify-counts.py \
  '                   "reclaim_state", "hash_failures", "results_materialized",' \
  '                   "reclaim_state", "hash_failures", "zz_mutant",'

mutate_row "prov/col-cand-files-total" g6-verify-counts.py \
  '                   "cand_files_total", "cand_bytes_total",' \
  '                   "zz_mutant", "cand_bytes_total",'

mutate_row "prov/col-cand-bytes-total" g6-verify-counts.py \
  '                   "cand_files_total", "cand_bytes_total",' \
  '                   "cand_files_total", "zz_mutant",'

mutate_row "prov/col-cand-files-hashed" g6-verify-counts.py \
  '                   "cand_files_hashed", "cand_bytes_hashed"),' \
  '                   "zz_mutant", "cand_bytes_hashed"),'

mutate_row "prov/col-cand-bytes-hashed" g6-verify-counts.py \
  '                   "cand_files_hashed", "cand_bytes_hashed"),' \
  '                   "cand_files_hashed", "zz_mutant"),'

mutate_row "prov/idx-reuse-identity" g6-verify-counts.py \
  '    "file_reuse_identity": ("file", 0, (("path", 0, "BINARY"), ("size", 0, "BINARY"),' \
  '    "zz_mutant_identity": ("file", 0, (("path", 0, "BINARY"), ("size", 0, "BINARY"),'

echo
echo "== census =="

# A scenario nobody mutated proves the guard fires. It does not prove the guard is what fires.
UNMUTATED=""
while IFS= read -r row; do
  n="${row%%	*}"
  [ -n "$n" ] || continue
  case " $MUTATED_ROWS " in *" $n "*) ;; *) UNMUTATED="$UNMUTATED $n" ;; esac
done < <(g6s_rows)
[ -z "$UNMUTATED" ] && ok "every directed scenario has a mutant of its own" \
                    || bad "directed scenarios with no mutant:$UNMUTATED"
if [ "$SURVIVED" = 0 ] && [ "$INVALID" = 0 ] && [ "$KILLED" = "$DECLARED" ]; then
  ok "matrix: $KILLED/$DECLARED killed, SURVIVED=0, INVALID=0"
else
  bad "matrix: $KILLED/$DECLARED killed, SURVIVED=$SURVIVED, INVALID=$INVALID"
fi
echo "== result: PASS=$PASS FAIL=$FAIL MUTATIONS=$KILLED/$DECLARED SURVIVED=$SURVIVED INVALID=$INVALID =="

# A filtered run is a diagnostic and can never be a pass, however green it looks: the rows it did
# not run are rows nobody ran. It ends non-zero on purpose, so no caller can mistake one for the
# matrix.
if [ -n "${G6M_ONLY:-}" ]; then
  printf '== FILTERED RUN (G6M_ONLY=%s) — this is not the matrix and does not pass ==\n' "$G6M_ONLY"
  exit 1
fi
[ "$FAIL" -eq 0 ] && [ "$SURVIVED" -eq 0 ] && [ "$INVALID" -eq 0 ]
