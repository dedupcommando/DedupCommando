#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The kill guard, proved by what is left on the machine rather than by what was written down.
#
# A terminal record saying BLOCKED costs nothing to produce and proves nothing about the process
# it was written about. The question this suite asks is the one that matters on a shared host: is
# the candidate GONE — pid and process group both — after the guard fired, after a TERM, and
# after the controller itself was killed with the one signal it cannot trap.
#
# That last case is the reason the watchdog is a detached process. A guard living inside the
# controller is only a guard while the controller lives; SIGKILL it and the deadline disappears
# while the workload keeps running, on somebody else's production storage, with nothing left to
# stop it.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CTL="$HERE/g6-controller.sh"

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

echo "== G6 kill guard — what is left on the machine =="
echo

echo "-- the guard fires and the group does not survive it --"
pidfile="$WORK/p1"
G6_GRACE=1 bash "$CTL" guarded 2 g1 "$WORK/o1" -- "$WORK/stubborn" "$pidfile" >/dev/null 2>&1
child="$(cat "$pidfile" 2>/dev/null || echo 0)"
if [ "$child" = 0 ]; then
  bad "the guarded child recorded its pid"
else
  ok "the guarded child recorded its pid ($child)"
  settle "$child" 15 && ok "after the deadline neither the pid nor its group is left" \
                     || bad "after the deadline neither the pid nor its group is left" \
                            "$(ps -o pid,pgid,stat,cmd -p "$child" 2>&1 | tail -2)"
fi

echo
echo "-- the controller is SIGKILLed: the deadline still arrives --"
# This is the case an in-shell loop cannot answer. The controller is killed a second into a run
# whose deadline is three, so the loop that used to enforce it is gone before it could fire.
pidfile="$WORK/p2"
setsid bash "$CTL" guarded 3 g2 "$WORK/o2" -- "$WORK/stubborn" "$pidfile" >/dev/null 2>&1 &
ctl=$!
sleep 1
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
    && ok "the detached watchdog outlived the controller and closed the group" \
    || bad "the detached watchdog outlived the controller and closed the group" \
           "$(ps -o pid,pgid,stat,cmd -p "$child" 2>&1 | tail -2)"
fi

echo
echo "-- a workload that finishes on its own leaves no watchdog behind --"
before="$(pgrep -c -f 'watchdog' 2>/dev/null || echo 0)"
bash "$CTL" guarded 30 g3 "$WORK/o3" -- /bin/true >/dev/null 2>&1
sleep 1
after="$(pgrep -c -f 'watchdog' 2>/dev/null || echo 0)"
[ "$after" -le "$before" ] && ok "the watchdog was reaped with the run it was watching" \
                           || bad "the watchdog was reaped" "before=$before after=$after"

echo
echo "== result: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
