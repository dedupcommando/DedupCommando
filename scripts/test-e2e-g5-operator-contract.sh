#!/usr/bin/env bash
# test-e2e-g5-operator-contract.sh — what `scripts/e2e-g5.sh` TELLS the operator to do.
#
# SCOPE, stated once so it is never mistaken for something bigger: this proves the printed
# operator contract and the harness's own failure arithmetic. It runs no TUI, creates no pool,
# touches no dataset and applies nothing, so it is NOT evidence that any scenario passed on real
# hardware. It exists because the earlier guided run failed on the instructions rather than on the
# product, and instructions are checkable without ZFS.
#
# It drives the harness's own offline modes, which re-use the production pause definitions,
# formatter and verdict functions — so a contract that passes here is the contract that prints.
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
record() {  # index -> that pause's text on stdout
    awk -v idx="$1" '
        /^PAUSE [0-9][0-9] BEGIN /  { want = ($2 == idx) }
        want                        { print }
    ' "$DUMP"
}
has() { record "$1" | grep -qF -- "$2"; }
hasre() { record "$1" | grep -qE -- "$2"; }
countre() { record "$1" | grep -cE -- "$2"; }

ALL="01 02 03 04 05 06 07 08 09 10"
# Every pause but 06 starts from a cold TUI; 06 continues the overlay 05 left open.
ROUTED="01 02 03 04 05 07 08 09 10"
# The pauses that open the confirmation themselves and apply it. Pause 06 also applies, but it
# returns to the overlay pause 05 deliberately left open, so it must NOT press x again.
APPLYING="01 02 03 04 08 09 10"

printf '\n== 1. ten pauses, unique and in order ==\n'
indices="$(grep -E '^PAUSE [0-9][0-9] BEGIN ' "$DUMP" | awk '{print $2}' | tr '\n' ' ')"
[ "$(printf '%s' "$indices" | tr -s ' ')" = "$ALL " ]
check "indices are exactly 01..10, once each, in order (saw: $indices)" "$?"

printf '\n== 2. every record names the run it belongs to ==\n'
for idx in $ALL; do
    line="$(grep -E "^PAUSE $idx BEGIN " "$DUMP")"
    printf '%s' "$line" \
        | grep -qE 'pool=[^ ]+ state=[^ ]+ fixture=[^ ]+ scan=[0-9]+$'
    check "pause $idx marker carries pool/state/fixture/scan" "$?"
    has "$idx" "  binary  :" && has "$idx" "  state   :" \
        && has "$idx" "  pool    :" && has "$idx" "  fixture :" && has "$idx" "  scan id :"
    check "pause $idx body restates binary/state/pool/fixture/scan id" "$?"
done

printf '\n== 3. launch, consent, navigation, view and the installed scan ==\n'
for idx in $ROUTED; do
    has "$idx" "do NOT pass --classic";           check "pause $idx: Commander is the launch"        "$?"
    has "$idx" "Notice and consent";              check "pause $idx: consent screen named"           "$?"
    has "$idx" "I have read and agree (required)"; check "pause $idx: consent checkbox named"        "$?"
    has "$idx" "[Enter] continue";                check "pause $idx: consent postcondition given"    "$?"
    has "$idx" "Don't show this at startup again"; check "pause $idx: suppress box explicitly left"  "$?"
    has "$idx" 'Enter on «g5»';                   check "pause $idx: navigates by the visible name"  "$?"
    hasre "$idx" 'title must end with «/g5/';     check "pause $idx: header checked after Enter"     "$?"
    has "$idx" "loading…";                        check "pause $idx: directory-read wait is visible" "$?"
    has "$idx" "files view";                      check "pause $idx: files view required"            "$?"
    hasre "$idx" 'header «scan #[0-9]+ · <age>»'; check "pause $idx: installed scan is visible"      "$?"
    has "$idx" 'WITHOUT «(loading…)»';            check "pause $idx: scan must not be loading"       "$?"
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

printf '\n== 5. x into the confirmation, exactly one Y ==\n'
for idx in $APPLYING; do
    hasre "$idx" '(^| )x( |$)|x  \(F11'
    check "pause $idx: the confirmation is opened with x" "$?"
    ys="$(countre "$idx" 'Y +ONCE')"
    [ "$ys" -eq 1 ]
    check "pause $idx: exactly one Y ($ys)" "$?"
done
has 05 "do NOT press Y in this stage"; check "pause 05 presses no Y at all" "$?"
[ "$(countre 07 'Y +ONCE')" -eq 0 ]; check "pause 07 (ScanScript) presses no Y at all" "$?"
[ "$(countre 06 'Y +ONCE')" -eq 1 ]; check "pause 06 supplies the single Y" "$?"
! hasre 06 'x  \(F11'
check "pause 06 does not re-open a confirmation it was handed" "$?"
grep -qF 'F11 is the same command' "$DUMP"
check "F11 is offered only as the equivalent of x" "$?"

printf '\n== 6. the two-stage preflight and the no-Y script route ==\n'
has 05 "LEAVE THE OVERLAY OPEN";            check "pause 05 stops with the overlay open"        "$?"
has 05 "stage 1 of 2";                      check "pause 05 names its stage"                    "$?"
has 06 "stage 2 of 2";                      check "pause 06 names its stage"                    "$?"
has 06 "BATCH REFUSED before any change";   check "pause 06 expects the refusal, not an apply"  "$?"
! has 06 "Notice and consent"
check "pause 06 continues the open TUI instead of restarting it" "$?"
has 07 "Script saved:";                     check "pause 07 requires the saved-script status"   "$?"
has 07 "with that overlay visibly open";    check "pause 07 presses Tab only inside the overlay" "$?"
has 07 "On the panels Tab switches the active panel"
check "pause 07 warns that Tab means something else on the panels" "$?"
has 09 "changed after the scan (content)"
check "pause 09 expects a cancelled action, not a successful apply" "$?"

printf '\n== 7. the acknowledgement fails closed ==\n'
printf '' | bash "$G5" ack-probe 01 >"$WORK/eof.out" 2>&1
[ "$?" -ne 0 ]; check "end of input fails the pause" "$?"
grep -qF 'PAUSE 01 ABORT reason=eof' "$WORK/eof.out"; check "and says the input ended" "$?"
printf '   \t \n' | bash "$G5" ack-probe 01 >"$WORK/blank.out" 2>&1
[ "$?" -ne 0 ]; check "whitespace-only initials fail the pause" "$?"
grep -qF 'PAUSE 01 ABORT reason=blank' "$WORK/blank.out"; check "and say the acknowledgement was blank" "$?"
printf 'dk\n' | bash "$G5" ack-probe 01 >"$WORK/ok.out" 2>&1
[ "$?" -eq 0 ]; check "real initials are accepted" "$?"
grep -qF 'PAUSE 01 HUMAN-ACK initials=dk' "$WORK/ok.out"; check "and are recorded verbatim" "$?"
! grep -qE 'read[^|]*\|\| *true' "$G5"
check "no acknowledgement read is swallowed with '|| true'" "$?"

printf '\n== 8/9. verdicts decide the exit status, and cleanup cannot undo it ==\n'
bash "$G5" verdict-probe hardlink 0 0 >"$WORK/vp.out" 2>&1
[ "$?" -eq 0 ]; check "a clean run exits zero" "$?"
grep -qF 'SCENARIO hardlink PASS' "$WORK/vp.out"; check "and emits SCENARIO ... PASS" "$?"
grep -qF 'FINAL RESULT PASS' "$WORK/vp.out";      check "and emits FINAL RESULT PASS" "$?"
bash "$G5" verdict-probe hardlink 1 1 >"$WORK/vf.out" 2>&1
[ "$?" -ne 0 ]; check "a failed scenario exits nonzero" "$?"
grep -qF 'SCENARIO hardlink FAIL' "$WORK/vf.out"; check "and emits SCENARIO ... FAIL" "$?"
grep -qF 'FINAL RESULT FAIL' "$WORK/vf.out";      check "and emits FINAL RESULT FAIL" "$?"
! grep -qF 'FINAL RESULT PASS' "$WORK/vf.out"
check "a failing run never also claims a pass" "$?"
# Isolates the final verdict from the trap's fail-safe: here the scenario passed, so nothing but
# `final_verdict` itself can carry the failure out. Without this the two mask each other and a
# final verdict that stopped exiting nonzero would go unnoticed.
bash "$G5" verdict-probe probe 0 1 >"$WORK/vf2.out" 2>&1
[ "$?" -ne 0 ]; check "a failing FINAL verdict exits nonzero on its own" "$?"
grep -qF 'FINAL RESULT FAIL' "$WORK/vf2.out"; check "and still emits the final marker" "$?"
# The EXIT trap runs in the probe too: this is the assertion that it reports without deciding.
grep -qE 'exit "\$rc"' "$G5"; check "the EXIT trap re-raises the status it was entered with" "$?"

printf '\n== 10. no Browser key vocabulary in a Commander instruction ==\n'
! grep -qE '^ +(r|d|h|c|K|H|C|D) on «' "$DUMP"
check "nothing is marked with a Browser letter key" "$?"
! grep -qiE 'press (r|d|h|c) ' "$DUMP"
check "no Browser command key is pressed" "$?"
# Case-sensitive on purpose: the Browser applies with two Y keystrokes, and «only Y» in ordinary
# prose must not read as one.
! grep -qE '\bY\b[, ]+\bY\b|\bY\b twice|press \bY\b again' "$DUMP"
check "Y is never pressed twice" "$?"
! grep -qF 'Browser' "$DUMP"
check "the Browser screen is never named as the route" "$?"
! grep -qiE '\bpress .*until|try again|repeat the key|sleep' "$DUMP"
check "no step is satisfied by repeating a key or by waiting" "$?"

printf '\n'
if [ "$FAILED" -eq 0 ]; then
    printf 'OPERATOR CONTRACT: PASS (printed contract only — not a runtime G4 result)\n'
    exit 0
fi
printf 'OPERATOR CONTRACT: FAIL\n' >&2
exit 1
