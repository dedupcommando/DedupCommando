#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The kill guard, proved by what is left on the machine rather than by what was written down.
#
# A terminal record saying BLOCKED costs nothing to produce and proves nothing about the process
# it was written about. The questions this suite asks are the ones that matter on a shared host:
#
#   - is the candidate GONE — pid and group — after the deadline, after a TERM, and after the
#     controller itself was killed with the one signal it cannot trap;
#   - was there ever a moment when the candidate ran and its guard did not — including the
#     moment BEFORE the guard's identity was announced;
#   - and is a signal ever sent on the strength of a number alone, when the identity behind the
#     number no longer matches.
#
# The supervisor is the answer to all three at once: it is detached first, it is the thing that
# launches the candidate, and everything it or the controller ever kills is verified against
# pid + pgid + /proc starttime — or owned outright.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CTL="$HERE/g6-controller.sh"
SUP="$HERE/g6-supervisor.sh"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"
        [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }

# A workload that ignores TERM and would run for an hour: only a real KILL ends it, so "it went
# away" cannot be confused with "it finished".
cat > "$WORK/stubborn" <<'STUB'
#!/usr/bin/env bash
trap '' TERM INT HUP
echo "$$" > "$1"
sleep 3600
STUB
chmod +x "$WORK/stubborn"

# GNU time is not in the pinned image, and the delivery reaches it through a variable precisely
# so its absence is a preflight question rather than a 127 in the middle of a guarded run. Here
# it only has to hand the workload through unchanged: this suite is about processes, not about
# measurement.
cat > "$WORK/time" <<'TIME'
#!/usr/bin/env bash
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -v) shift ;;
    -o) out="$2"; shift 2 ;;
    *) break ;;
  esac
done
[ -n "$out" ] && : > "$out"
exec "$@"
TIME
chmod +x "$WORK/time"
export G6_TIME="$WORK/time"

gone() {  # pid — true when neither the process nor its group is left
  local pid="$1"
  kill -0 "$pid" 2>/dev/null && return 1
  kill -0 -- "-$pid" 2>/dev/null && return 1
  return 0
}

settle() {  # pid seconds — wait until it is gone, or give up
  local pid="$1" n="$2"
  while [ "$n" -gt 0 ]; do gone "$pid" && return 0; sleep 1; n=$(( n - 1 )); done
  return 1
}

field() { awk -F'\t' -v k="$2" '$1 == k { print $2 }' "$1" 2>/dev/null; }

sups_running() { pgrep -c -f g6-supervisor 2>/dev/null || true; }

echo "== G6 kill guard — what is left on the machine =="
echo

echo "-- the guard fires and the group does not survive it --"
pidfile="$WORK/p1"
G6_GRACE=1 bash "$CTL" guarded 2 g1 "$WORK/o1" -- "$WORK/stubborn" "$pidfile" >/dev/null 2>&1
rc=$?
child="$(cat "$pidfile" 2>/dev/null || echo 0)"
if [ "$child" = 0 ]; then
  bad "the guarded child recorded its pid"
else
  ok "the guarded child recorded its pid ($child)"
  settle "$child" 15 && ok "after the deadline neither the pid nor its group is left" \
                     || bad "after the deadline neither the pid nor its group is left" \
                            "$(ps -o pid,pgid,stat,cmd -p "$child" 2>&1 | tail -2)"
fi
[ "$(field "$WORK/o1/g1.status" fired)" = 1 ] \
  && ok "the supervisor's status says the deadline fired" \
  || bad "the supervisor's status says the deadline fired" "$(cat "$WORK/o1/g1.status" 2>/dev/null)"
[ "$(field "$WORK/o1/g1.meta" class)" = CANDIDATE_TIMEOUT ] && [ "$rc" != 0 ] \
  && ok "the run is classified CANDIDATE_TIMEOUT and does not pass" \
  || bad "the run is classified CANDIDATE_TIMEOUT" "$(cat "$WORK/o1/g1.meta" 2>/dev/null)"

echo
echo "-- a workload that finishes on its own: identity, status, and nothing left behind --"
before="$(sups_running)"
bash "$CTL" guarded 30 g3 "$WORK/o3" -- /bin/true >/dev/null 2>&1
rc=$?
{ [ "$rc" = 0 ] && [ "$(field "$WORK/o3/g3.meta" class)" = OK ]; } \
  && ok "a clean exit is classified OK" \
  || bad "a clean exit is classified OK" "rc=$rc $(cat "$WORK/o3/g3.meta" 2>/dev/null)"
{ [ -s "$WORK/o3/g3.ready" ] && [ "$(field "$WORK/o3/g3.status" group)" = cleared ]; } \
  && ok "identity was announced and the group is reported cleared" \
  || bad "identity was announced and the group is reported cleared"
sleep 1
after="$(sups_running)"
[ "$after" -le "$before" ] && ok "no supervisor is left running after its run" \
                           || bad "no supervisor is left running" "before=$before after=$after"

echo
echo "-- the controller is SIGKILLed AFTER the identity is announced: the deadline still arrives --"
# This is the case an in-shell loop cannot answer. The controller is killed a second into a run
# whose deadline is three, so anything living inside it is gone before the deadline fires — and
# the workload must still be swept away, and the status still written, by the detached owner.
pidfile="$WORK/p2"
setsid bash "$CTL" guarded 3 g2 "$WORK/o2" -- "$WORK/stubborn" "$pidfile" >/dev/null 2>&1 &
ctl=$!
child=0
for _ in 1 2 3 4 5; do
  child="$(cat "$pidfile" 2>/dev/null || echo 0)"
  [ "$child" != 0 ] && break
  sleep 1
done
kill -KILL "$ctl" 2>/dev/null
wait "$ctl" 2>/dev/null
if kill -0 "$ctl" 2>/dev/null; then
  bad "the controller was killed"
else
  ok "the controller was killed outright, with no chance to clean up"
fi
if [ "$child" = 0 ]; then
  bad "the workload started under the killed controller"
else
  ok "the workload was running under the killed controller ($child)"
  settle "$child" 20 \
    && ok "the detached supervisor outlived the controller and closed the group" \
    || bad "the detached supervisor outlived the controller and closed the group" \
           "$(ps -o pid,pgid,stat,cmd -p "$child" 2>&1 | tail -2)"
  # The group going away precedes the publication by a sweep and a reap; give the writer the
  # seconds it is entitled to before reading its record.
  for _ in 1 2 3 4 5 6; do [ -s "$WORK/o2/g2.status" ] && break; sleep 1; done
  [ "$(field "$WORK/o2/g2.status" fired)" = 1 ] \
    && ok "and still published the status of a run nobody was left to read" \
    || bad "and still published the status" "$(cat "$WORK/o2/g2.status" 2>/dev/null)"
fi

echo
echo "-- the controller is SIGKILLed BEFORE the identity is announced: still no unguarded run --"
# The old watchdog's launch-to-guard window, forced open on purpose: setsid is delayed three
# seconds, and the controller is killed inside the delay — before READY can possibly exist. If
# the candidate were launched by the controller, it would now run unguarded for an hour. It is
# launched by the supervisor instead, so it starts AFTER the controller is dead and dies by the
# supervisor's own deadline.
cat > "$WORK/slowsid" <<SLOW
#!/usr/bin/env bash
sleep 3
exec setsid "\$@"
SLOW
chmod +x "$WORK/slowsid"
pidfile="$WORK/p4"
G6_SETSID="$WORK/slowsid" G6_GRACE=1 setsid bash "$CTL" guarded 2 g4 "$WORK/o4" -- \
  "$WORK/stubborn" "$pidfile" >/dev/null 2>&1 &
ctl=$!
sleep 1
kill -KILL "$ctl" 2>/dev/null
wait "$ctl" 2>/dev/null
[ ! -e "$WORK/o4/g4.ready" ] \
  && ok "the controller died before any identity existed" \
  || bad "the controller died before any identity existed" "$(cat "$WORK/o4/g4.ready" 2>/dev/null)"
child=0
for _ in 1 2 3 4 5 6 7 8; do
  child="$(cat "$pidfile" 2>/dev/null || echo 0)"
  [ "$child" != 0 ] && break
  sleep 1
done
if [ "$child" = 0 ]; then
  bad "the candidate was still launched, by the guard itself"
else
  ok "the candidate was still launched, by the guard itself ($child)"
  settle "$child" 15 \
    && ok "and the guard that launched it also ended it, with nobody else alive" \
    || bad "and the guard that launched it also ended it" \
           "$(ps -o pid,pgid,stat,cmd -p "$child" 2>&1 | tail -2)"
fi

echo
echo "-- TERM while the candidate runs: the owner closes the group bounded, not at the deadline --"
# The supervisor's abort path, which is what the controller's own TERM/INT/HUP traps lean on:
# a signal to the supervisor must end the group within notice + grace + KILL — seconds — while
# the deadline here is an hour away. The stubborn workload ignores the TERM half on purpose.
pidfile="$WORK/p5"
mkdir -p "$WORK/o5"
setsid "$SUP" 3600 1 5 "$WORK/time" "$WORK/o5" g5 -- "$WORK/stubborn" "$pidfile" \
  > "$WORK/o5.sup.out" 2>&1 &
sup=$!
child=0
for _ in 1 2 3 4 5; do
  child="$(cat "$pidfile" 2>/dev/null || echo 0)"
  [ "$child" != 0 ] && break
  sleep 1
done
if [ "$child" = 0 ]; then
  bad "the supervised workload started"
else
  ok "the supervised workload started ($child)"
  kill -TERM "$sup" 2>/dev/null
  settle "$child" 8 \
    && ok "TERM to the owner ended the group in bounded seconds, 3594 early" \
    || bad "TERM to the owner ended the group in bounded seconds" \
           "$(ps -o pid,pgid,stat,cmd -p "$child" 2>&1 | tail -2)"
  wait "$sup" 2>/dev/null
  grep -q aborted "$WORK/o5/g5.status" 2>/dev/null \
    && ok "and the status says the run was aborted, not that it timed out" \
    || bad "and the status says the run was aborted" "$(cat "$WORK/o5/g5.status" 2>/dev/null)"
fi

echo
echo "-- no detachment, no guard, no run: the candidate is never released --"
# setsid missing or broken is settled in preflight; and even reached at run time, a guard that
# cannot come up means the candidate is never launched — the window is not narrowed, it does
# not exist.
out="$(G6_SETSID=/nonexistent-setsid G6_LOSETUP=true G6_MKFS=true G6_MOUNT=true G6_UMOUNT=true \
       G6_BLKID=true G6_DUMPE2FS=true G6_DF=true bash "$CTL" preflight 2>&1)"; rc=$?
{ [ "$rc" = 2 ] && printf '%s' "$out" | grep -q 'nonexistent-setsid'; } \
  && ok "preflight refuses a missing setsid by name" \
  || bad "preflight refuses a missing setsid by name" "rc=$rc $out"
cat > "$WORK/samesid" <<'SAME'
#!/usr/bin/env bash
exec "$@"
SAME
chmod +x "$WORK/samesid"
out="$(G6_SETSID="$WORK/samesid" G6_LOSETUP=true G6_MKFS=true G6_MOUNT=true G6_UMOUNT=true \
       G6_BLKID=true G6_DUMPE2FS=true G6_DF=true bash "$CTL" preflight 2>&1)"; rc=$?
{ [ "$rc" = 2 ] && printf '%s' "$out" | grep -q 'does not start a new session'; } \
  && ok "preflight refuses a setsid that does not detach" \
  || bad "preflight refuses a setsid that does not detach" "rc=$rc $out"
cat > "$WORK/deadsid" <<'DEAD'
#!/usr/bin/env bash
exit 7
DEAD
chmod +x "$WORK/deadsid"
pidfile="$WORK/p6"
out="$(G6_SETSID="$WORK/deadsid" G6_READY_GUARD=3 bash "$CTL" guarded 30 g6 "$WORK/o6" -- \
       "$WORK/stubborn" "$pidfile" 2>&1)"; rc=$?
{ [ "$rc" = 2 ] && printf '%s' "$out" | grep -q 'announced no identity'; } \
  && ok "a guard that cannot come up is BLOCKED, not worked around" \
  || bad "a guard that cannot come up is BLOCKED" "rc=$rc $out"
[ ! -e "$pidfile" ] \
  && ok "and the candidate was never released into the gap" \
  || bad "and the candidate was never released into the gap" "pid $(cat "$pidfile")"
out="$(G6_SUPERVISOR=/nonexistent-supervisor bash "$CTL" guarded 30 g7 "$WORK/o7" -- \
       "$WORK/stubborn" "$WORK/p7" 2>&1)"; rc=$?
{ [ "$rc" = 2 ] && [ ! -e "$WORK/p7" ]; } \
  && ok "a missing supervisor refuses before anything is launched" \
  || bad "a missing supervisor refuses before anything is launched" "rc=$rc $out"

echo
echo "-- a substituted identity is refused a signal; a verified one is acted on --"
# The controller's fallback path: a supervisor that died without a status. What remains is the
# recorded identity, and the rule is absolute — matches, act; does not match, refuse. The decoy
# is a live process whose recorded starttime is forged, which is exactly what a recycled pid
# looks like from the outside.
setsid bash -c 'echo "$$" > "$1"; exec sleep 300' _ "$WORK/decoy.pid" &
for _ in 1 2 3 4 5; do [ -s "$WORK/decoy.pid" ] && break; sleep 1; done
decoy="$(cat "$WORK/decoy.pid")"
dstart="$(sed 's/.*) //' "/proc/$decoy/stat" | awk '{ print $20 }')"
cat > "$WORK/forging-sup" <<FORGE
#!/usr/bin/env bash
outdir="\$5"; label="\$6"
{ printf 'pid\t%s\n' "$decoy"; printf 'pgid\t%s\n' "$decoy"
  printf 'starttime\t%s\n' "$(( dstart + 100000 ))"; printf 'supervisor\t%s\n' "\$\$"
} > "\$outdir/\$label.ready"
exit 0
FORGE
chmod +x "$WORK/forging-sup"
out="$(G6_SUPERVISOR="$WORK/forging-sup" G6_GRACE=1 bash "$CTL" guarded 30 g8 "$WORK/o8" -- \
       /bin/true 2>&1)"; rc=$?
{ [ "$rc" = 2 ] && printf '%s' "$out" | grep -q 'refusing to signal'; } \
  && ok "a starttime that does not match is refused a signal, and the run is BLOCKED" \
  || bad "a starttime that does not match is refused a signal" "rc=$rc $out"
kill -0 "$decoy" 2>/dev/null \
  && ok "the decoy wearing the number is still alive" \
  || bad "the decoy wearing the number is still alive"
kill -KILL "$decoy" 2>/dev/null; wait "$decoy" 2>/dev/null

cat > "$WORK/orphaning-sup" <<'ORPH'
#!/usr/bin/env bash
outdir="$5"; label="$6"
set -m
sleep 300 &
c=$!
set +m
st="$(sed 's/.*) //' "/proc/$c/stat" | awk '{ print $20 }')"
{ printf 'pid\t%s\n' "$c"; printf 'pgid\t%s\n' "$c"
  printf 'starttime\t%s\n' "$st"; printf 'supervisor\t%s\n' "$$"
} > "$outdir/$label.ready"
echo "$c" > "$outdir/$label.orphan"
exit 0
ORPH
chmod +x "$WORK/orphaning-sup"
out="$(G6_SUPERVISOR="$WORK/orphaning-sup" G6_GRACE=1 bash "$CTL" guarded 30 g9 "$WORK/o9" -- \
       /bin/true 2>&1)"; rc=$?
orphan="$(cat "$WORK/o9/g9.orphan" 2>/dev/null || echo 0)"
if [ "$orphan" = 0 ]; then
  bad "the orphaned workload existed"
else
  { [ "$rc" = 2 ] && settle "$orphan" 8; } \
    && ok "a verified identity is closed by the fallback, and the run is still BLOCKED" \
    || bad "a verified identity is closed by the fallback" \
           "rc=$rc $(ps -o pid,pgid,stat,cmd -p "$orphan" 2>&1 | tail -2)"
fi

echo
echo "-- an identity that no longer exists needs nothing and wedges nothing --"
sleep 0.1 & deadpid=$!
wait "$deadpid" 2>/dev/null
cat > "$WORK/ghost-sup" <<GHOST
#!/usr/bin/env bash
outdir="\$5"; label="\$6"
{ printf 'pid\t%s\n' "$deadpid"; printf 'pgid\t%s\n' "$deadpid"
  printf 'starttime\t12345\n'; printf 'supervisor\t\$\$\n'
} > "\$outdir/\$label.ready"
exit 0
GHOST
chmod +x "$WORK/ghost-sup"
out="$(G6_SUPERVISOR="$WORK/ghost-sup" bash "$CTL" guarded 30 g10 "$WORK/o10" -- /bin/true 2>&1)"
rc=$?
{ [ "$rc" = 2 ] && printf '%s' "$out" | grep -q 'settled by identity'; } \
  && ok "a gone identity is a clean BLOCKED, with nothing signalled and no wait" \
  || bad "a gone identity is a clean BLOCKED" "rc=$rc $out"

echo
echo "== result: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
