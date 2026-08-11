#!/usr/bin/env bash
# test-e2e-g5-operator-contract.sh — what `scripts/e2e-g5.sh` TELLS the operator to do, and how
# it decides its own result.
#
# SCOPE, stated once so it is never mistaken for something bigger: this proves the printed
# operator contract, the harness's failure arithmetic and its finalization. It runs no TUI,
# creates no pool, touches no dataset and applies nothing, so it is NOT evidence that any
# scenario passed on real hardware. It exists because the earlier guided run failed on the
# instructions rather than on the product, and instructions are checkable without ZFS.
#
# It drives the harness's own offline modes, which re-use the production pause definitions,
# formatter, route generator, verdict and finalization — so what passes here is what runs.
#
# Usage: bash scripts/test-e2e-g5-operator-contract.sh
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
G5="$SCRIPT_DIR/e2e-g5.sh"
[ -r "$G5" ] || { printf 'ABORT: %s not found\n' "$G5" >&2; exit 1; }

FAILED=0
check() {  # description ; 0 = pass
    if [ "$2" -eq 0 ]; then
        printf '  [OK]   %s\n' "$1"
    else
        printf '  [FAIL] %s\n' "$1" >&2
        FAILED=1
    fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DUMP="$WORK/dump.txt"

bash "$G5" contract-dump >"$DUMP" 2>"$WORK/dump.err"
check "contract-dump exits zero" "$?"
[ -s "$DUMP" ]; check "contract-dump produced output" "$?"

# The record of one pause: everything between its BEGIN marker and the next one.
record() { awk -v idx="$1" '
        /^PAUSE [0-9][0-9] BEGIN /  { want = ($2 == idx) }
        want                        { print }
    ' "$DUMP"; }
has()     { record "$1" | grep -qF -- "$2"; }
hasre()   { record "$1" | grep -qE -- "$2"; }
countre() { record "$1" | grep -cE -- "$2"; }
# 1-based line of the first match inside a record; 0 when absent.
line_of() { record "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1 | grep . || echo 0; }

ALL="01 02 03 04 05 06 07 08 09 10"
# Every pause but 06 starts from a cold TUI; 06 continues the overlay 05 left open.
ROUTED="01 02 03 04 05 07 08 09 10"
# The pauses that open the confirmation themselves.
OPENS="01 02 03 04 05 07 08 09 10"
# The pauses that press Y. 06 applies the overlay it inherited and opens nothing.
APPLIES="01 02 03 04 06 08 09 10"
# The sample dataset list puts an unrelated pool and the pool root ahead of ds_a.
CYCLES=2

printf '\n== 1. ten pauses, unique and in order ==\n'
indices="$(grep -E '^PAUSE [0-9][0-9] BEGIN ' "$DUMP" | awk '{print $2}' | tr '\n' ' ')"
[ "$(printf '%s' "$indices" | tr -s ' ')" = "$ALL " ]
check "indices are exactly 01..10, once each, in order (saw: $indices)" "$?"

printf '\n== 2. every record names the run it belongs to ==\n'
for idx in $ALL; do
    grep -E "^PAUSE $idx BEGIN " "$DUMP" | grep -qE 'pool=[^ ]+ state=[^ ]+ fixture=[^ ]+ scan=[0-9]+$'
    check "pause $idx marker carries pool/state/fixture/scan" "$?"
    has "$idx" "  binary  :" && has "$idx" "  state   :" \
        && has "$idx" "  pool    :" && has "$idx" "  fixture :" && has "$idx" "  scan id :"
    check "pause $idx body restates binary/state/pool/fixture/scan id" "$?"
done

printf '\n== 3. launch, consent, files view and the installed scan ==\n'
for idx in $ROUTED; do
    has "$idx" "do NOT pass --classic";            check "pause $idx: Commander is the launch"       "$?"
    has "$idx" "Notice and consent";               check "pause $idx: consent screen named"          "$?"
    has "$idx" "I have read and agree (required)"; check "pause $idx: consent checkbox named"        "$?"
    has "$idx" "[Enter] continue";                 check "pause $idx: consent postcondition given"   "$?"
    has "$idx" "Don't show this at startup again"; check "pause $idx: suppress box explicitly left"  "$?"
    has "$idx" "loading…";                         check "pause $idx: directory-read wait is visible" "$?"
    has "$idx" "files view";                       check "pause $idx: files view required"           "$?"
    hasre "$idx" 'header «scan #[0-9]+ · <age>»';  check "pause $idx: installed scan is visible"     "$?"
    has "$idx" 'WITHOUT «(loading…)»';             check "pause $idx: scan must not be loading"      "$?"
done

printf '\n== 3b. the start route is GENERATED, not assumed ==\n'
for idx in $ROUTED; do
    has "$idx" "[0] /rpool/data"
    check "pause $idx: the real item [0] is named, unrelated pool and all" "$?"
    has "$idx" "Panel 1 is the ACTIVE panel and starts on item [0]"
    check "pause $idx: the active panel's actual start is stated" "$?"
    has "$idx" "ending with «/rpool/data»"
    check "pause $idx: the starting title is verified before moving" "$?"
    [ "$(countre "$idx" '^ +cycle [0-9]+ -> status must read «Panel 1 → ')" -eq "$CYCLES" ]
    check "pause $idx: exactly $CYCLES generated Root cycle(s), each with its status" "$?"
    has "$idx" "exactly $CYCLES"
    check "pause $idx: the cycle count is stated as a number" "$?"
    has "$idx" 'cycle 2 -> status must read «Panel 1 → /dedcom-g5-SAMPLE/ds_a»'
    check "pause $idx: the last cycle lands on the target dataset" "$?"
    has "$idx" "press the real F5 key"
    check "pause $idx: Root is the second-layer F5 key itself" "$?"
    has "$idx" "backtick followed by the DIGIT 5 is first-layer F5"
    check "pause $idx: the Hardlink mis-key is called out" "$?"
    has "$idx" 'Enter on «g5»'
    check "pause $idx: the fixture is entered by its visible name" "$?"
    hasre "$idx" 'title must end with «/g5/'
    check "pause $idx: the title is checked after Enter" "$?"
    # The dataset must be reached BEFORE g5 is entered.
    a="$(line_of "$idx" 'After the last cycle')"; b="$(line_of "$idx" 'Enter on «g5»')"
    [ "$a" -gt 0 ] && [ "$b" -gt 0 ] && [ "$a" -lt "$b" ]
    check "pause $idx: the dataset is reached before g5 is entered ($a < $b)" "$?"
done
! grep -qE '^ +Enter on «g5»' <(record 01 | head -20)
check "no record opens with «Enter on g5» straight after launch" "$?"

printf '\n== 3c. the settlement line has to fit the terminal ==\n'
for idx in $ALL; do
    need="$(record "$idx" | grep -oE 'needs [0-9]+ columns' | head -1 | tr -dc '0-9')"
    marks="$(countre "$idx" '«Mark saved: .* = ')"
    if [ "$marks" -eq 0 ]; then
        [ -z "$need" ]; check "pause $idx: no marks, so no width requirement" "$?"
        continue
    fi
    [ -n "$need" ]; check "pause $idx: states the required terminal width" "$?"
    worst=0
    while IFS= read -r line; do
        text="${line#«}"; text="${text%»}"
        [ "${#text}" -gt "$worst" ] && worst="${#text}"
    done < <(record "$idx" | grep -oE '«Mark saved: [^»]*»')
    [ -n "$need" ] && [ "$need" -ge "$((worst + 2))" ]
    check "pause $idx: required width $need covers the longest settlement line ($worst + 2)" "$?"
done

printf '\n== 4. one settlement checkpoint per durable mark ==\n'
for idx in $ALL; do
    marks="$(countre "$idx" '^ +F[5678] on «')"
    settled="$(countre "$idx" '«Mark saved: .* = ')"
    [ "$marks" -eq "$settled" ]
    check "pause $idx: $marks durable key(s), $settled «Mark saved» checkpoint(s)" "$?"
    if [ "$marks" -gt 1 ]; then
        has "$idx" "Mark still saving — wait for Mark saved before marking again"
        check "pause $idx: the in-flight refusal is spelled out" "$?"
    fi
done
total_marks="$(grep -cE '^ +F[5678] on «' "$DUMP")"
[ "$total_marks" -ge 10 ]; check "the contract marks through F5/F6/F7/F8 only ($total_marks keys)" "$?"

printf '\n== 5. exactly one x, exactly one Y, and Q last ==\n'
for idx in $OPENS; do
    [ "$(countre "$idx" '^ +x  \(F11')" -eq 1 ]
    check "pause $idx: exactly one x opens the confirmation" "$?"
done
[ "$(countre 06 '^ +x  \(F11')" -eq 0 ]
check "pause 06: no x — it inherits the open overlay" "$?"
for idx in $APPLIES; do
    [ "$(countre "$idx" 'Y +ONCE')" -eq 1 ]
    check "pause $idx: exactly one Y" "$?"
done
has 05 "do NOT press Y in this stage"; check "pause 05 presses no Y at all" "$?"
[ "$(countre 07 'Y +ONCE')" -eq 0 ]; check "pause 07 (ScanScript) presses no Y at all" "$?"
grep -qF 'F11 is the same command' "$DUMP"
check "F11 is offered only as the equivalent of x" "$?"
# Q is the last instruction of every pause that reaches the summary.
for idx in $APPLIES; do
    y="$(line_of "$idx" 'Y  ONCE')"; q="$(line_of "$idx" 'Q  from that summary')"
    [ "$y" -gt 0 ] && [ "$q" -gt 0 ] && [ "$y" -lt "$q" ]
    check "pause $idx: Y precedes Q ($y < $q)" "$?"
done

printf '\n== 6. scenario-specific reading happens before the key that leaves ==\n'
x03="$(line_of 03 'x  (F11')"; e03="$(line_of 03 'zero guaranteed reclaim')"
y03="$(line_of 03 'Y  ONCE')"; q03="$(line_of 03 'Q  from that summary')"
[ "$x03" -lt "$e03" ] && [ "$e03" -lt "$y03" ] && [ "$y03" -lt "$q03" ]
check "pause 03: x < zero-reclaim warning < Y < Q ($x03 < $e03 < $y03 < $q03)" "$?"
y06="$(line_of 06 'Y  ONCE')"; e06="$(line_of 06 'BATCH REFUSED before any change')"
q06="$(line_of 06 'Q  from that summary')"
[ "$y06" -lt "$e06" ] && [ "$e06" -lt "$q06" ]
check "pause 06: Y < BATCH REFUSED < Q ($y06 < $e06 < $q06)" "$?"
y09="$(line_of 09 'Y  ONCE')"; e09="$(line_of 09 'changed after the scan (content)')"
q09="$(line_of 09 'Q  from that summary')"
[ "$y09" -lt "$e09" ] && [ "$e09" -lt "$q09" ]
check "pause 09: Y < the cancelled-action line < Q ($y09 < $e09 < $q09)" "$?"
has 05 "LEAVE THE OVERLAY OPEN";          check "pause 05 stops with the overlay open"       "$?"
has 05 "stage 1 of 2";                    check "pause 05 names its stage"                   "$?"
has 06 "stage 2 of 2";                    check "pause 06 names its stage"                   "$?"
! has 06 "Notice and consent"
check "pause 06 continues the open TUI instead of restarting it" "$?"
has 07 "Script saved:";                   check "pause 07 requires the saved-script status"  "$?"
has 07 "with that overlay visibly open";  check "pause 07 presses Tab only inside the overlay" "$?"
has 07 "On the panels Tab switches the active panel"
check "pause 07 warns that Tab means something else on the panels" "$?"

printf '\n== 7. the acknowledgement fails closed ==\n'
printf '' | bash "$G5" ack-probe 01 >"$WORK/eof.out" 2>&1
[ "$?" -ne 0 ]; check "end of input fails the pause" "$?"
grep -qF 'PAUSE 01 ABORT reason=eof' "$WORK/eof.out"; check "and says the input ended" "$?"
printf '   \t \n' | bash "$G5" ack-probe 01 >"$WORK/blank.out" 2>&1
[ "$?" -ne 0 ]; check "whitespace-only initials fail the pause" "$?"
grep -qF 'PAUSE 01 ABORT reason=blank' "$WORK/blank.out"; check "and say it was blank" "$?"
printf 'dk\n' | bash "$G5" ack-probe 01 >"$WORK/ok.out" 2>&1
[ "$?" -eq 0 ]; check "real initials are accepted" "$?"
grep -qF 'PAUSE 01 HUMAN-ACK initials=dk' "$WORK/ok.out"; check "and are recorded verbatim" "$?"
! grep -qE 'read[^|]*\|\| *true' "$G5"
check "no acknowledgement read is swallowed with '|| true'" "$?"

printf '\n== 8. every scenario verdict describes only that scenario ==\n'
bash "$G5" scenario-seq-probe >"$WORK/seq.out" 2>&1
[ "$?" -ne 0 ]; check "two failing scenarios exit nonzero" "$?"
grep -qF 'SCENARIO seq-a FAIL' "$WORK/seq.out"; check "the first failure is reported" "$?"
grep -qF 'SCENARIO seq-b FAIL' "$WORK/seq.out"
check "the second failure is reported too — the total is a count, not a flag" "$?"
! grep -qF 'SCENARIO seq-b PASS' "$WORK/seq.out"; check "and is never reported as a pass" "$?"
grep -qF 'FINAL RESULT FAIL' "$WORK/seq.out"; check "the final verdict fails" "$?"
bash "$G5" verdict-probe hardlink 0 0 >"$WORK/vp.out" 2>&1
[ "$?" -eq 0 ]; check "a clean run exits zero" "$?"
grep -qF 'SCENARIO hardlink PASS' "$WORK/vp.out"; check "and emits SCENARIO ... PASS" "$?"
bash "$G5" verdict-probe probe 0 1 >"$WORK/vf2.out" 2>&1
[ "$?" -ne 0 ]; check "a failing FINAL verdict exits nonzero on its own" "$?"

printf '\n== 9. nothing is called PASS until the run has given back what it owns ==\n'
bash "$G5" finalize-probe "" 0 >"$WORK/f_ok.out" 2>&1
[ "$?" -eq 0 ]; check "a clean cleanup exits zero" "$?"
grep -qF 'FINAL RESULT PASS' "$WORK/f_ok.out"; check "and reaches PASS" "$?"
c="$(grep -n 'CLEANUP RUN 1' "$WORK/f_ok.out" | cut -d: -f1)"
p="$(grep -n 'FINAL RESULT PASS' "$WORK/f_ok.out" | cut -d: -f1)"
[ -n "$c" ] && [ -n "$p" ] && [ "$c" -lt "$p" ]
check "cleanup runs BEFORE the PASS is printed ($c < $p)" "$?"
for step in state teardown leftover; do
    bash "$G5" finalize-probe "$step" 0 present absent >"$WORK/f_$step.out" 2>&1
    [ "$?" -ne 0 ]; check "a failed '$step' cleanup exits nonzero" "$?"
    grep -qF 'FINAL RESULT FAIL' "$WORK/f_$step.out"; check "and the final verdict is FAIL" "$?"
    ! grep -qF 'FINAL RESULT PASS' "$WORK/f_$step.out"
    check "and no PASS was printed first" "$?"
    [ "$(grep -c 'FINAL RESULT' "$WORK/f_$step.out")" -eq 1 ]
    check "exactly one final marker for a failed '$step'" "$?"
    [ "$(grep -c 'CLEANUP RUN' "$WORK/f_$step.out")" -eq 1 ]
    check "cleanup ran exactly once for a failed '$step'" "$?"
done

printf '\n== 9b. absence has to be PROVED, not inferred from a failed query ==\n'
# present -> absent and already-absent are the only two shapes that may pass. Every other answer,
# including «the query could not tell us», is a failure.
presence_case() {  # label seq expect-rc
    local label="$1" seq="$2" want="$3" out rc
    out="$(bash "$G5" finalize-probe "" 0 $seq 2>&1)"; rc=$?
    [ "$rc" -eq "$want" ]
    check "$label: exit $want (got $rc)" "$?"
    if [ "$want" -eq 0 ]; then
        grep -qF 'FINAL RESULT PASS' <<<"$out"; check "$label: reaches PASS" "$?"
    else
        grep -qF 'FINAL RESULT FAIL' <<<"$out"; check "$label: the verdict is FAIL" "$?"
        ! grep -qF 'FINAL RESULT PASS' <<<"$out"; check "$label: and never a PASS" "$?"
        [ "$(grep -c 'FINAL RESULT' <<<"$out")" -eq 1 ]
        check "$label: exactly one final marker" "$?"
        # A denial of absence is the right output; a positive claim of it would be the bug.
        ! grep -qiE '(is|was) (gone|absent|destroyed|removed)' <<<"$out"
        check "$label: absence is never claimed" "$?"
        case "$seq" in
            *unknown*)
                grep -qiE 'could not (determine|verify)' <<<"$out"
                check "$label: the uncertainty is named rather than resolved" "$?" ;;
        esac
    fi
}
presence_case "present then absent"      "present absent"  0
presence_case "already absent"           "absent absent"   0
presence_case "the first query fails"    "unknown"         1
presence_case "the post-teardown query fails" "present unknown" 1
presence_case "teardown says ok, pool stays" "present present" 1
# Isolates the teardown gate from the absence gate. With both answers unknown the second check
# catches everything, so the two mask each other and a teardown that silently skips on an
# unanswerable query would never be noticed.
presence_case "the first query fails, the second says absent" "unknown absent" 1
# The fail-closed source of truth is an enumeration, not the status of `zpool list <name>`.
grep -qF 'zpool list -H -o name' "$G5"
check "presence comes from enumerating the imported pools" "$?"
! grep -qE 'zpool list "\$POOL" >/dev/null 2>&1 \|\| return 0' "$G5"
check "a failed pool query is no longer read as absence" "$?"

printf '\n== 10. signals at every materially different point of the ending ==\n'
# The owned steps, in the order cleanup_owned attempts them. «Entered cleanup» is not the same
# fact as «cleanup ran», so the trace is what the assertions read.
STEPS="remove_state teardown_pool assert_no_leftovers"
steps_of() { grep -oE '^CLEANUP STEP [a-z_]+' "$1" | awk '{print $3}' | tr '\n' ' '; }

for sig in INT TERM; do
    case "$sig" in INT) want_rc=130 ;; TERM) want_rc=143 ;; esac
    # Points 1-4: the run is interrupted, so it must fail — and it must still give back what it
    # owns before saying so.
    for when in before entry after-step1 precommit; do
        f="$WORK/sig_${sig}_$when.out"
        bash "$G5" signal-probe "$sig" "$when" >"$f" 2>&1
        got=$?
        [ "$got" -eq "$want_rc" ]
        check "SIG$sig @$when: exits $want_rc (got $got)" "$?"
        [ "$(grep -c 'CLEANUP RUN' "$f")" -eq 1 ]
        check "SIG$sig @$when: exactly one cleanup invocation" "$?"
        [ "$(steps_of "$f")" = "$STEPS " ]
        check "SIG$sig @$when: all three owned steps attempted once, in order" "$?"
        [ "$(grep -c 'FINAL RESULT FAIL' "$f")" -eq 1 ]
        check "SIG$sig @$when: exactly one FINAL RESULT FAIL" "$?"
        [ "$(grep -c 'FINAL RESULT PASS' "$f")" -eq 0 ]
        check "SIG$sig @$when: no PASS" "$?"
        c="$(grep -n 'CLEANUP RUN 1' "$f" | cut -d: -f1)"
        m="$(grep -n 'FINAL RESULT' "$f" | cut -d: -f1)"
        [ -n "$c" ] && [ -n "$m" ] && [ "$c" -lt "$m" ]
        check "SIG$sig @$when: the marker follows the cleanup it describes ($c < $m)" "$?"
    done
    # Point 5: past the commit point the pair is fixed. Signals are masked there, so a clean run
    # stays PASS/0 — never PASS with an interrupted status, never markerless, never two markers.
    f="$WORK/sig_${sig}_postcommit.out"
    bash "$G5" signal-probe "$sig" postcommit >"$f" 2>&1
    got=$?
    [ "$got" -eq 0 ]
    check "SIG$sig @postcommit: the decided status survives (got $got)" "$?"
    [ "$(grep -c 'FINAL RESULT' "$f")" -eq 1 ]
    check "SIG$sig @postcommit: exactly one marker" "$?"
    grep -qF 'FINAL RESULT PASS' "$f"
    check "SIG$sig @postcommit: marker and status agree" "$?"
done
# A second signal may neither overwrite the first latch nor start a second give-back.
bash "$G5" signal-probe X double >"$WORK/sig_double.out" 2>&1
[ "$?" -eq 143 ]; check "two signals: the FIRST latched status is the one that survives" "$?"
grep -qF 'LATCHED:TERM' "$WORK/sig_double.out"; check "and the first signal is the latched one" "$?"
[ "$(grep -c 'CLEANUP RUN' "$WORK/sig_double.out")" -eq 1 ]
check "and the second signal starts no second cleanup" "$?"
[ "$(grep -c 'FINAL RESULT' "$WORK/sig_double.out")" -eq 1 ]
check "and only one marker is emitted" "$?"

! grep -qE '^trap [a-z_]+ EXIT INT TERM' "$G5"
check "EXIT and the signals do not share one handler" "$?"
grep -qF 'G5_FINAL_STATE=cleaning' "$G5"
check "finalization has an explicit in-flight state" "$?"
# `done` may only be published once the marker exists, and the commit point must mask signals.
awk '/^emit_final\(\)/,/^}/' "$G5" >"$WORK/emit.txt"
[ "$(grep -n "trap '' INT TERM" "$WORK/emit.txt" | cut -d: -f1)" -lt \
  "$(grep -n 'FINAL RESULT PASS' "$WORK/emit.txt" | cut -d: -f1)" ]
check "signals are masked before the marker is printed" "$?"
[ "$(grep -n 'FINAL RESULT FAIL' "$WORK/emit.txt" | cut -d: -f1)" -lt \
  "$(grep -n 'G5_FINAL_STATE=done' "$WORK/emit.txt" | cut -d: -f1)" ]
check "«done» is published only after the marker exists" "$?"
! grep -qE 'finalize [^|]*\|\| exit 1' "$G5"
check "no caller replaces the finalized status with a hard-coded 1" "$?"

printf '\n== 10a. the signal and trace seams are offline-only ==\n'
awk '/^maybe_signal\(\)/,/^}/' "$G5" | grep -qF 'G5_OFFLINE" -eq 1 ] || return 0'
check "the signal injection is refused outside an offline mode" "$?"
awk '/^trace_step\(\)/,/^}/' "$G5" | grep -qF 'G5_OFFLINE" -eq 1 ] || return 0'
check "the cleanup trace is refused outside an offline mode" "$?"

printf '\n== 10b. the dataset list of a real run comes from zfs, not the environment ==\n'
mkdir -p "$WORK/bin"
cat >"$WORK/bin/zfs" <<'STUB'
#!/usr/bin/env bash
printf 'stub/one\t/STUB_ONE\tyes\nstub/skip\tnone\tyes\nstub/two\t/STUB_TWO\tyes\n'
STUB
chmod +x "$WORK/bin/zfs"
PATH="$WORK/bin:$PATH" bash "$G5" roots-probe >"$WORK/roots_ok.out" 2>&1
[ "$?" -eq 0 ]; check "real-source mode reads the list and succeeds" "$?"
[ "$(tr -d '\r' <"$WORK/roots_ok.out")" = "$(printf '/STUB_ONE\n/STUB_TWO')" ]
check "and the rendered list is exactly what the query returned" "$?"
PATH="$WORK/bin:$PATH" bash "$G5" roots-probe forge >"$WORK/roots_forge.out" 2>&1
[ "$?" -ne 0 ]; check "a forged override in real-source mode fails the run" "$?"
! grep -qF '/FORGED' "$WORK/roots_forge.out"
check "and the forged mountpoint never reaches the route" "$?"
grep -qF 'refusing to print a route from it' "$WORK/roots_forge.out"
check "and the refusal names what was wrong" "$?"
grep -qE 'roots_source\(\)' "$G5"
check "the list source is decided by the mode, never by a bare environment variable" "$?"

printf '\n== 11. no Browser key vocabulary in a Commander instruction ==\n'
! grep -qE '^ +(r|d|h|c|K|H|C|D) on «' "$DUMP"
check "nothing is marked with a Browser letter key" "$?"
! grep -qiE 'press (r|d|h|c) ' "$DUMP"
check "no Browser command key is pressed" "$?"
# Case-sensitive: the Browser applies with two Y keystrokes, and «only Y» in prose must not read
# as one.
! grep -qE '\bY\b[, ]+\bY\b|\bY\b twice|press \bY\b again' "$DUMP"
check "Y is never pressed twice" "$?"
! grep -qF 'Browser' "$DUMP"
check "the Browser screen is never named as the route" "$?"
! grep -qiE '\bpress .*until|try again|repeat the key|sleep' "$DUMP"
check "no step is satisfied by repeating a key or by waiting" "$?"

printf '\n'
if [ "$FAILED" -eq 0 ]; then
    printf 'OPERATOR CONTRACT: PASS (printed contract and harness verdicts only — not a runtime G4 result)\n'
    exit 0
fi
printf 'OPERATOR CONTRACT: FAIL\n' >&2
exit 1
