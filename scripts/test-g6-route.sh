#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Integrated rehearsal route, end to end, with fault injection at every transition.
#
# Driven exactly as it would be live — same controller, same order, same fail-closed rules —
# with the external world replaced by exact stubs. Rehearsal scale, 100 files. Not host
# calibration and not G6 evidence.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CTL="$HERE/g6-controller.sh"
PUB="$HERE/g6-publish-record.py"
. "$HERE/test-g6-stubs.sh"

DEDCOM="${DEDCOM:-}"
[ -x "${DEDCOM:-/nonexistent}" ] || { echo "ABORT: set DEDCOM to the built candidate" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
g6t_install_stubs "$WORK/bin"

# The stand-ins the directed suite uses are shared, so the route suite can drive the candidate
# into the same states without a second copy of them.
. "$HERE/test-g6-scenarios.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"
        [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }

export G6T_G=40 G6T_U=20
BUNDLE="$(bash "$CTL" bundle | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')"

setup() {  # [mode] [candidate]
  local mode="${1:-rehearsal}" bin="${2:-$DEDCOM}"
  g6t_new_world "$WORK"
  CAL="$G6T_W/calibration.txt"; SANC="$G6T_W/sanction.txt"; PLAN="$G6T_W/plan.txt"
  g6t_write_calibration "$mode" "$CAL"
  g6t_write_plan "$PLAN" "$mode"
  g6t_write_sanction "$mode" "$SANC" "$CAL" "$bin" "$BUNDLE" "$PLAN"
  export G6_CALIBRATION="$CAL" G6_SANCTION="$SANC" G6_RESOURCE_PLAN="$PLAN"
  export G6_BIN="$bin" G6_NOW=5000 G6_CONTOUR=local
}
reseal() { g6t_write_sanction "${1:-rehearsal}" "$SANC" "$CAL" "$G6_BIN" "$BUNDLE" "$PLAN"; }
route()  { bash "$CTL" route --mode "${1:-rehearsal}"; }

# A STARTED exit terminalizes: a durable, sealed TERMINAL record carrying the expected verdict
# and the expected exit code. This is the assertion for every exit from BEGIN onwards — which is
# not the same as every exit, and the difference is `refuses_prestart` below.
exits_as() {  # label verdict code -- command...
  local label="$1" verdict="$2" code="$3"; shift 3; [ "$1" = "--" ] && shift
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  local problems=""
  [ "$rc" = "$code" ] || problems="$problems exit=$rc(want $code)"
  g6_has_line "$out" "VERDICT	$verdict" || problems="$problems no-VERDICT-$verdict"
  [ -f "$G6_WORK/TERMINAL" ] || problems="$problems no-terminal-record"
  if [ -f "$G6_WORK/TERMINAL" ]; then
    "$PUB" --verify --dir "$G6_WORK" --name TERMINAL >/dev/null 2>&1 \
      || problems="$problems unsealed-record"
    grep -q "^verdict	$verdict" "$G6_WORK/TERMINAL" || problems="$problems record-verdict"
    grep -q "^code	$code" "$G6_WORK/TERMINAL" || problems="$problems record-code"
  fi
  [ -z "$problems" ] && ok "$label" \
    || bad "$label" "$problems"$'\n'"$(printf '%s' "$out" | tail -4)"
}

# A PRESTART exit is the other kind, and it is asserted as the other kind. The refusal happens
# before BEGIN, so there is no run to terminalize and no record to verify: what has to be true is
# that NOTHING was left behind — not a record saying so. `route/prestart-leaves-nothing` proves
# the general rule; these pin the individual refusals that take that exit.
refuses_prestart() {  # label code -- command...
  local label="$1" code="$2"; shift 2; [ "$1" = "--" ] && shift
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  local problems=""
  [ "$rc" = "$code" ] || problems="$problems exit=$rc(want $code)"
  g6_has_line "$out" "VERDICT	BLOCKED" || problems="$problems no-VERDICT-BLOCKED"
  [ ! -e "$G6_WORK/TERMINAL" ] || problems="$problems terminal-record-left"
  [ ! -e "$G6_WORK/PUBSTATE" ] || problems="$problems state-file-left"
  [ ! -e "$G6_IMAGE" ]        || problems="$problems image-left"
  [ -z "$problems" ] && ok "$label" \
    || bad "$label" "$problems"$'\n'"$(printf '%s' "$out" | tail -4)"
}

echo "== G6 route suite — REHEARSAL, 100 files, stubbed world, not calibration, not evidence =="

# ---------------------------------------------------------------- 1. the whole route

echo
echo "== 1. the integrated route terminalizes with PASS = 0 =="
setup
exits_as "route --mode rehearsal ends PASS with code 0" PASS 0 -- route rehearsal
grep -q '^bundle-sha256	' "$G6_WORK/TERMINAL" && ok "the record names the bundle that produced it" \
                                               || bad "the record names the bundle"
grep -q '^resource-plan-sha256	' "$G6_WORK/TERMINAL" && ok "and the frozen resource plan" \
                                                      || bad "and the frozen resource plan"
[ -f "$G6_WORK/RECEIPT" ] && ok "a production receipt is published" || bad "a production receipt"
grep -q '^user_version	5' "$G6_WORK/RECEIPT" 2>/dev/null \
  && ok "the receipt carries the product's own schema stamp" || bad "the receipt carries the stamp"
grep -q '^ddl-written-by-harness	none' "$G6_WORK/RECEIPT" 2>/dev/null \
  && ok "and states that no DDL came from the harness" || bad "and states no harness DDL"

for s in SCAN S1 S2 S3 S4; do
  m="$G6_WORK/scenarios/$s.meta"
  if [ -s "$m" ] && grep -q '^raw-exit	' "$m" && grep -q '^pgid	' "$m" \
     && [ -f "$G6_WORK/scenarios/$s.out" ] && [ -f "$G6_WORK/scenarios/$s.err" ]; then
    ok "$s ran guarded, with separate streams and a raw exit"
  else bad "$s ran guarded, with separate streams and a raw exit" "$(cat "$m" 2>/dev/null)"; fi
done

# The S3 witness is the real one: an atomic replacement renames a NEW file over the old.
W="$G6_WORK/scenarios/S3.witness"
if [ -s "$W" ]; then
  ib="$(awk -F'\t' '$1=="inode-before"{print $2}' "$W")"
  ia="$(awk -F'\t' '$1=="inode-after"{print $2}' "$W")"
  sb="$(awk -F'\t' '$1=="sha-before"{print $2}' "$W")"
  sa="$(awk -F'\t' '$1=="sha-after"{print $2}' "$W")"
  [ -n "$ib" ] && [ "$ib" != "$ia" ] && [ "$sb" = "$sa" ] \
    && ok "S3 atomicity witness: the inode changed, the bytes did not ($ib -> $ia)" \
    || bad "S3 atomicity witness" "$(cat "$W")"
else bad "S3 atomicity witness exists"; fi

[ -e "$G6_IMAGE" ] && ok "the route left the image for teardown to decide on" \
                   || bad "the route left the image for teardown"
bash "$CTL" teardown --mode rehearsal >/dev/null 2>&1 \
  && ok "the separate teardown completes" || bad "the separate teardown completes"
[ ! -e "$G6_IMAGE" ] && ok "and only then is the image gone" || bad "and only then is the image gone"

# ---------------------------------------------------------------- 2. contour, earliest of all

echo
echo "== 2. the contour is refused first =="
setup
refuses_prestart "no contour at all is BLOCKED, and nothing is touched" 2 -- \
  env G6_CONTOUR= bash "$CTL" route --mode rehearsal
setup
refuses_prestart "rehearsal in the host contour is BLOCKED, and nothing is touched" 2 -- \
  env G6_CONTOUR=host bash "$CTL" route --mode rehearsal
setup
refuses_prestart "a local contour reaching a real privileged tool is BLOCKED" 2 -- \
  env G6_MOUNT=/usr/bin/mount bash "$CTL" route --mode rehearsal

# ---------------------------------------------------------------- 3. modes and seals

echo
echo "== 3. modes and seals =="
setup
# The output is captured first and matched after. Under `set -o pipefail` a refusal on the left
# of a pipe decides the pipeline, so `refuses | grep -q` reads as a failure however well the
# message matched.
out="$(bash "$CTL" route 2>&1)" || true
g6_has "$out" '--mode is required' \
  && ok "the route refuses without a mode" || bad "the route refuses without a mode" "$out"

setup
printf 'note\ttampered\n' >> "$CAL"
# These ten refusals moved from a verdict to a refusal in C2-2, and the assertion moved with
# them. Each is a read-only check — sanction, calibration, candidate, bundle, plan, margin — and
# all of them now happen before BEGIN, so there is no run for a record to be about. Asserting a
# TERMINAL record here would be asserting that the harness wrote the very state its own refusal
# says it never made.
refuses_prestart "a calibration edited after sealing" 2 -- route rehearsal
setup
sed -i 's/^window-close\t9999999999/window-close\t4000/' "$SANC"
refuses_prestart "a closed load window" 2 -- route rehearsal
setup
sed -i "s/^candidate-sha256\t.*/candidate-sha256\t$(printf '0%.0s' $(seq 64))/" "$SANC"
refuses_prestart "a candidate that is not the pinned one" 2 -- route rehearsal
setup
sed -i "s/^bundle-sha256\t.*/bundle-sha256\t$(printf '1%.0s' $(seq 64))/" "$SANC"
refuses_prestart "a bundle that is not the pinned one" 2 -- route rehearsal

# ---------------------------------------------------------------- 4. the frozen resource plan

echo
echo "== 4. the resource plan is complete, frozen and agreed =="
setup
grep -v '^work-dir	' "$PLAN" > "$PLAN.n" && mv "$PLAN.n" "$PLAN"; reseal
refuses_prestart "a plan missing a resource" 2 -- route rehearsal
setup
printf 'note\tedited\n' >> "$PLAN"
refuses_prestart "a plan edited after sealing" 2 -- route rehearsal
setup
sed -i "s|^uuid\t.*|uuid\t00000000-0000-0000-0000-000000000000|" "$PLAN"; reseal
refuses_prestart "a plan that disagrees with the sanction" 2 -- route rehearsal

# ---------------------------------------------------------------- 5. capacity

echo
echo "== 5. both margins, at every check =="
setup
refuses_prestart "a starved external margin" 2 -- \
  env G6T_DF_OUTSIDE_BYTES=1000 bash "$CTL" route --mode rehearsal
setup
exits_as "a starved internal inode margin" BLOCKED 2 -- \
  env G6T_DF_INSIDE_INODES=5 bash "$CTL" route --mode rehearsal
setup
exits_as "a starved internal byte margin" BLOCKED 2 -- \
  env G6T_DF_INSIDE_BYTES=5 bash "$CTL" route --mode rehearsal

# The hook is one executable with no arguments, so a path with a space still works.
setup
hookdir="$G6T_W/hook dir"; mkdir -p "$hookdir"
printf '#!/usr/bin/env bash\nexit 0\n' > "$hookdir/h"; chmod +x "$hookdir/h"
env G6_G=5 G6_M=2 G6_U=5 G6_CAPACITY_HOOK="$hookdir/h" \
    bash "$HERE/g6-make-fixture.sh" --mode rehearsal --root "$G6T_W/spaced" >/dev/null 2>&1 \
  && ok "a capacity hook whose path contains a space is invoked exactly" \
  || bad "a capacity hook whose path contains a space is invoked exactly"
out="$(env G6_G=5 G6_M=2 G6_U=5 G6_CAPACITY_HOOK="$hookdir/h --extra" \
         bash "$HERE/g6-make-fixture.sh" --mode rehearsal --root "$G6T_W/spaced2" 2>&1)" || true
g6_has "$out" 'never a command line' \
  && ok "a hook carrying arguments in a string is refused" \
  || bad "a hook carrying arguments in a string is refused" "$out"

# ---------------------------------------------------------------- 6. classification, fail-fast

echo
echo "== 6. classification and fail-fast =="

# A candidate that fails the scan on valid input is the CANDIDATE failing: FAIL, not BLOCKED.
BADSCAN="$WORK/badscan"; cat > "$BADSCAN" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [ "\$a" = "--scan" ] && exit 7; done
exec "$DEDCOM" "\$@"
EOF
chmod +x "$BADSCAN"
setup rehearsal "$BADSCAN"
exits_as "a scan that fails on valid input is FAIL with code 1" FAIL 1 -- route rehearsal

# A postcondition contradicted stops everything below it.
BADSTATS="$WORK/badstats"; cat > "$BADSTATS" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
  if [ "\$a" = "--stats" ]; then
    "$DEDCOM" "\$@" | sed 's/files=[0-9]*/files=999999/'
    exit 0
  fi
done
exec "$DEDCOM" "\$@"
EOF
chmod +x "$BADSTATS"
setup rehearsal "$BADSTATS"
exits_as "a contradicted S1 postcondition is FAIL with code 1" FAIL 1 -- route rehearsal
if [ -f "$G6_WORK/scenarios/S1.meta" ] && [ ! -f "$G6_WORK/scenarios/S2.meta" ]; then
  ok "fail-fast: nothing after the first contradicted postcondition ran"
else bad "fail-fast: nothing after the first contradicted postcondition ran"; fi

# ---------------------------------------------------------------- 7. calibration, locally proved

echo
echo "== 7. the calibration route runs where it is proved =="
# Calibration comes BEFORE the run it measures for, and it uses the assigned device. A world
# where the run already holds that device is not a world calibration may start in — the lifecycle
# refuses it, which is the point of the assignment.
setup
if bash "$CTL" calibrate --mode rehearsal "$G6T_W/fresh-cal.txt" >/dev/null 2>&1; then
  ok "calibrate produces a manifest"
else bad "calibrate produces a manifest"; fi
if grep -q '^scale	rehearsal' "$G6T_W/fresh-cal.txt" 2>/dev/null \
   && grep -qE '^guard-S1	[0-9]+' "$G6T_W/fresh-cal.txt"; then
  ok "and it names the scale it was measured at, with numeric guards"
else bad "and it names the scale it was measured at" "$(cat "$G6T_W/fresh-cal.txt" 2>/dev/null)"; fi
grep -q '^measured-from	' "$G6T_W/fresh-cal.txt" 2>/dev/null \
  && ok "and points at the measurement it came from" || bad "and points at the measurement"

# ---------------------------------------------------------------- 8. publication

echo
echo "== 8. a PASS nobody recorded is not a PASS =="
# The publication is broken from underneath rather than by leaving a record in place: a record
# that is already there is now refused by the re-entry gate long before the run reaches a verdict,
# which is a different (and stronger) refusal. A stale temporary is what a publication that died
# halfway leaves behind, and it makes the LAST step fail — after a PASS has been earned.
setup
# The shape a dead publication actually leaves: the temporary carries the pid of the process
# that was writing it. `.TERMINAL.tmp` is a name this program never writes, and the stale-file
# check is right not to recognise it.
mkdir -p "$G6_WORK"; printf 'half a record\n' > "$G6_WORK/.TERMINAL.999999.tmp"
out="$(route rehearsal 2>&1)"; rc=$?
if [ "$rc" = 2 ] && g6_has "$out" 'a PASS nobody recorded is BLOCKED'; then
  ok "an unpublishable PASS becomes BLOCKED with code 2"
else bad "an unpublishable PASS becomes BLOCKED with code 2" "$(printf '%s' "$out" | tail -5)"; fi

# ---------------------------------------------------------------- 9. the eleven corrections

echo
echo "== 9. strict state and the re-run gate =="
setup
route rehearsal >/dev/null 2>&1
before="$(sha256sum < "$G6_WORK/TERMINAL")"
out="$(route rehearsal 2>&1)"; rc=$?
if [ "$rc" = 2 ] && g6_has "$out" 'already carries a finished run'; then
  ok "a second run is refused before it touches anything"
else bad "a second run is refused before it touches anything" "$(printf '%s' "$out" | tail -4)"; fi
[ "$(sha256sum < "$G6_WORK/TERMINAL")" = "$before" ] \
  && ok "and the first run's terminal record is untouched" || bad "the record is untouched"
printf 'PUBLISHED 0\nstate-sha256\tdeadbeef\n' > "$G6_WORK/PUBSTATE"
out="$("$PUB" --query-state --state-file "$G6_WORK/PUBSTATE" 2>&1)" || true
g6_has "$out" 'FAILED' \
  && ok "a tampered state reads as FAILED, never as a fresh start" \
  || bad "a tampered state reads as FAILED" "$out"

echo
echo "== 10. zero-write on an early refusal =="
setup
sed -i 's/^window-close\t9999999999/window-close\t4000/' "$SANC"
# The proof used to be read out of the TERMINAL record. After C2-2 there is no record here, and
# that is the point: an early refusal writes nothing, so it cannot leave a note certifying that
# it wrote nothing. The claim travels in the refusal itself, and the absence is then checked
# against the filesystem rather than against the harness's own account of it.
out="$(route rehearsal 2>&1)" || true
problems=""
g6_has "$out" 'nothing was touched (proved)' || problems="$problems no-zero-write-claim"
[ ! -e "$G6_WORK/TERMINAL" ] || problems="$problems terminal-record-left"
[ ! -e "$G6_WORK/PUBSTATE" ] || problems="$problems state-file-left"
[ ! -e "$G6_IMAGE" ]         || problems="$problems image-left"
[ -z "$problems" ] && ok "an early refusal proves it wrote nothing" \
                   || bad "an early refusal proves it wrote nothing" "$problems"
[ ! -e "$G6_IMAGE" ] && [ ! -e "$G6_STATE_DIR/PREPARED" ] \
  && ok "and no image or lifecycle record exists" || bad "and no image or record exists"

echo
echo "== 11. the verifier's own status decides its class =="
# Editing the scale in the sanction changes what the generator builds AND what the verifier
# expects, so it contradicts nothing. The contradiction has to come from the checkpoint: a
# candidate that scans correctly and then loses a row is the candidate producing a wrong answer,
# which is FAIL and not BLOCKED.
g6s_world
g6s_row_deleter "$G6T_W/deleter"
g6s_seal "$HERE" "$G6T_W/deleter"
exits_as "counts that contradict the formulas are FAIL" FAIL 1 -- route rehearsal
setup
exits_as "a verifier that cannot be executed is BLOCKED" BLOCKED 2 -- \
  env G6_VERIFY_COUNTS=/nonexistent/verify bash "$CTL" route --mode rehearsal

echo
echo "== 12. fail-fast records where it stopped =="
setup rehearsal "$BADSTATS"
route rehearsal >/dev/null 2>&1
grep -q '^stopped-at	S1' "$G6_WORK/TERMINAL" 2>/dev/null \
  && ok "the terminal record names the step it stopped at" \
  || bad "the terminal record names the step" "$(grep '^stopped-at' "$G6_WORK/TERMINAL" 2>/dev/null)"

echo
echo "== 13. the S3 observer runs at the same time =="
setup
route rehearsal >/dev/null 2>&1
W="$G6_WORK/scenarios/S3.witness"
s="$(awk -F'\t' '$1=="observer-samples"{print $2}' "$W" 2>/dev/null)"
u="$(awk -F'\t' '$1=="observer-unexpected"{print $2}' "$W" 2>/dev/null)"
{ [ -n "$s" ] && [ "$s" -ge 1 ] && [ "$u" = 0 ]; } \
  && ok "the observer took $s samples and saw no intermediate state" \
  || bad "the observer took samples and saw no intermediate state" "$(cat "$W" 2>/dev/null)"

echo
echo "== 14. calibration builds and removes its own fixture =="
setup
bash "$CTL" calibrate --mode rehearsal "$G6T_W/cal2.txt" >/dev/null 2>&1
if grep -q '^formula	max(4 \* 100 \* t, 900)' "$G6T_W/cal2.txt" 2>/dev/null \
   && grep -qE '^elapsed-S1	[0-9]+' "$G6T_W/cal2.txt" \
   && grep -qE '^guard-S1	[0-9]+' "$G6T_W/cal2.txt"; then
  ok "the guards are derived from a measurement by the frozen formula"
else bad "the guards are derived by the formula" "$(cat "$G6T_W/cal2.txt" 2>/dev/null)"; fi
grep -q '^calibration-image-removed	proved' "$G6T_W/cal2.txt" 2>/dev/null \
  && ok "and the calibration image is proved gone" || bad "the calibration image is proved gone"
[ ! -e "$G6_REMOTE_ROOT/g6-calibration-image" ] \
  && ok "the calibration image and its directory really are absent" \
  || bad "the calibration image and its directory really are absent"
[ ! -e "$G6_IMAGE" ] && ok "and it was never the run's own image" || bad "it was the run's image"

echo
echo "== 15. every resource is pinned in the sanction =="
setup
grep -v '^mountpoint	' "$SANC" > "$SANC.n" && mv "$SANC.n" "$SANC"
refuses_prestart "a sanction that pins no mountpoint" 2 -- route rehearsal
setup
sed -i "s|^state-dir\t.*|state-dir\t/elsewhere|" "$SANC"
refuses_prestart "a sanction whose state-dir disagrees with the plan" 2 -- route rehearsal

echo
echo "== 16. the lifecycle chain is cross-linked and resumable =="
setup
bash "$HERE/g6-image-lib.sh" prepare >/dev/null 2>&1
out="$(bash "$HERE/g6-image-lib.sh" resume 2>&1)"
g6_has "$out" 'next=attach' \
  && ok "resume reads the next step out of durable state" || bad "resume reads the next step"
bash "$HERE/g6-image-lib.sh" attach >/dev/null 2>&1
grep -qE '^prev-sha256	[0-9a-f]{64}' "$G6_STATE_DIR/ATTACHED" \
  && ok "ATTACHED links back to PREPARED by digest" || bad "ATTACHED links back to PREPARED"
setup
bash "$HERE/g6-image-lib.sh" prepare >/dev/null 2>&1
bash "$HERE/g6-image-lib.sh" attach >/dev/null 2>&1
# A PREPARED from another run cannot be slotted under an existing ATTACHED.
printf 'image\tx\ndevino\t1:1\nsize\t1\nloop_dev\t/dev/loop7\nremote_root\tx\nprev-sha256\tnone\n' \
  > "$WORK/foreign-body"
rm -f "$G6_STATE_DIR/PREPARED"
"$PUB" --dir "$G6_STATE_DIR" --name PREPARED < "$WORK/foreign-body" >/dev/null 2>&1
out="$(bash "$HERE/g6-image-lib.sh" verify 2>&1)"; rc=$?
if [ "$rc" != 0 ] && g6_has "$out" 'links back to PREPARED'; then
  ok "a swapped predecessor breaks the cross-link"
else bad "a swapped predecessor breaks the cross-link" "$(printf '%s' "$out" | tail -3)"; fi

echo
echo "== 17. the receipt quotes the argv that actually ran =="
setup
route rehearsal >/dev/null 2>&1
ra="$(awk -F'\t' '$1=="scan-argv"{print $2}' "$G6_WORK/RECEIPT" 2>/dev/null)"
sa="$(cat "$G6_WORK/scenarios/SCAN.argv" 2>/dev/null)"
[ -n "$ra" ] && [ "$ra" = "$sa" ] \
  && ok "the receipt's argv is the guard's own argv" \
  || bad "the receipt's argv is the guard's own argv" "receipt=$ra"$'\n'"guard=$sa"

echo
echo "== result: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
