#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The kill guard as the PARENT of what it guards.
#
# The previous watchdog was started after the candidate and knew it only as a process-group
# number. Both halves of that were holes. Between the launch and the watchdog there was a window
# in which the candidate ran and its guard did not — SIGKILL the controller there and the
# workload continues on somebody's production host with no deadline at all. And a number, on a
# host that recycles them, can come to mean somebody else's session: a guard that kills by bare
# PGID is one recycled number away from killing a stranger's work.
#
# So the order is reversed. This supervisor is detached FIRST — setsid, a session of its own,
# where neither the controller's death nor a signal aimed at the controller's group can reach
# it — and the candidate does not exist until the supervisor itself launches it. There is no
# launch-to-guard window, because the guard is the thing that launches. Ownership is also what
# makes every signal it sends verifiable. Nothing here is ever signalled on the strength of a
# number alone:
#
#   - while the leader it launched still answers to the identity recorded at launch — the pid
#     exists, in the recorded group, with the recorded start time — that existence pins the
#     number in the kernel, and a group signal cannot land on anyone else;
#   - once the leader stops answering to it, group signals stop with it. Survivors are found by
#     reading /proc, and each one is killed BY PID, re-checked against the start time the scan
#     saw immediately before the signal. A recycled pid carries a later start time, and gets
#     nothing.
#
# usage: g6-supervisor.sh deadline grace reap-limit time-tool outdir label -- command...
#
#   $outdir/$label.ready    pid, pgid, starttime, supervisor — written the moment the candidate
#                           exists; the identity the controller may verify a kill against
#   $outdir/$label.status   raw, fired, reap-attempts, group, note — written when it is over
#
# Both are written to a temp name and moved into place, so a reader sees a whole file or none.
# On TERM/INT/HUP the supervisor does not die where it stands: it terminates and reaps the
# group it owns, bounded by grace and reap-limit, publishes the status, and only then leaves.

set -u

deadline="$1"; grace="$2"; reap_limit="$3"; time_tool="$4"; outdir="$5"; label="$6"; shift 6
[ "${1:-}" = "--" ] && shift

ready="$outdir/$label.ready"
status="$outdir/$label.status"

publish_status() {  # raw fired reap-attempts group note
  { printf 'raw\t%s\n' "$1";           printf 'fired\t%s\n' "$2"
    printf 'reap-attempts\t%s\n' "$3"; printf 'group\t%s\n' "$4"
    printf 'note\t%s\n' "$5"
  } > "$status.tmp" && mv -f "$status.tmp" "$status"
}

# /proc/<pid>/stat past the command name, so the fields count from the state: $1 state, $3 pgrp,
# $20 starttime. The comm field can contain spaces and parentheses, which is why the line is cut
# at the LAST ')'.
stat_tail()  { sed 's/.*) //' "/proc/$1/stat" 2>/dev/null; }
tail_field() { printf '%s' "$1" | awk -v n="$2" '{ print $n }'; }

set -m
"$time_tool" -v -o "$outdir/$label.time" "$@" \
  > "$outdir/$label.out" 2> "$outdir/$label.err" &
child=$!
set +m

line="$(stat_tail "$child")"
pgid="$(tail_field "$line" 3)"
starttime="$(tail_field "$line" 20)"

# Job control put the child in a group of its own, with the child as leader. If /proc says
# otherwise, the ownership argument every later signal rests on is void, and the run does not
# proceed on a void argument.
if [ -n "$pgid" ] && [ "$pgid" != "$child" ]; then
  kill -KILL "$child" 2>/dev/null; wait "$child" 2>/dev/null
  publish_status '' 0 0 unknown "the guarded child is in group $pgid, not its own"
  exit 2
fi
# An empty line means the child was already gone before it could be read. set -m still made it
# the leader of its own group; the start time, though, was never seen, and an identity that was
# never seen is one nothing may later be killed against.
[ -n "$pgid" ] || pgid="$child"

{ printf 'pid\t%s\n' "$child";           printf 'pgid\t%s\n' "$pgid"
  printf 'starttime\t%s\n' "$starttime"; printf 'supervisor\t%s\n' "$$"
} > "$ready.tmp" && mv -f "$ready.tmp" "$ready"

# The leader still answers to the recorded identity. While this holds — and an unreaped zombie
# still holds the number — the kernel cannot hand it to anyone else, so a group signal is a
# signal to OUR group and nobody else's.
leader_pinned() {
  local l; l="$(stat_tail "$child")"
  [ -n "$l" ] || return 1
  [ "$(tail_field "$l" 3)" = "$pgid" ] && [ "$(tail_field "$l" 20)" = "$starttime" ]
}

# The leader is finished: gone, a zombie, or — the shell reaps in the background — a stranger
# already wearing the recycled number. Anything but "alive and provably ours" is finished,
# because waiting a deadline out on a stranger guards nothing.
leader_done() {
  local l; l="$(stat_tail "$child")"
  [ -z "$l" ] && return 0
  [ "$(tail_field "$l" 1)" = Z ] && return 0
  [ "$(tail_field "$l" 20)" != "$starttime" ] && return 0
  return 1
}

# Live members of the guarded group, found by reading /proc rather than by asking kill: a group
# whose only remnant is the unreaped leader would answer a signal-0 probe forever. Each line is
# "pid starttime", and the start time is the identity the per-pid kill below re-checks.
group_survivors() {
  local d p l
  for d in /proc/[0-9]*; do
    p="${d#/proc/}"
    [ "$p" = "$child" ] && continue
    l="$(stat_tail "$p")"
    [ -n "$l" ] || continue
    [ "$(tail_field "$l" 3)" = "$pgid" ] || continue
    [ "$(tail_field "$l" 1)" = Z ] && continue
    printf '%s %s\n' "$p" "$(tail_field "$l" 20)"
  done
}

# One signal to the guarded set, under the identity rules: the group form only while the leader
# pins the number; afterwards per pid, each re-read immediately before the signal and required
# to still carry the start time the scan saw.
signal_guarded() {  # sig
  local sig="$1" p st l
  if leader_pinned; then kill "-$sig" -- "-$pgid" 2>/dev/null; return 0; fi
  group_survivors | while read -r p st; do
    l="$(stat_tail "$p")"
    [ -n "$l" ] || continue
    [ "$(tail_field "$l" 3)" = "$pgid" ] || continue
    [ "$(tail_field "$l" 20)" = "$st" ] || continue
    kill "-$sig" "$p" 2>/dev/null
  done
  return 0
}

# A signal to the supervisor is an order to close the run early, not to abandon it: the watch
# loop notices, the group is terminated and reaped bounded, the status is still published.
aborted=""
trap 'aborted=yes' TERM INT HUP

fired=0; waited=0
while :; do
  leader_done && break
  [ -n "$aborted" ] && break
  if [ "$waited" -ge "$deadline" ]; then fired=1; break; fi
  sleep 1; waited=$(( waited + 1 ))
done

if ! leader_done; then
  [ "$fired" = 1 ] && printf 'supervisor: the guarded group %s outlived its %s second deadline\n' \
    "$pgid" "$deadline" >&2
  signal_guarded TERM
  g=0
  while ! leader_done && [ "$g" -lt "$grace" ]; do sleep 1; g=$(( g + 1 )); done
  leader_done || signal_guarded KILL
fi

# The leader has to be finished before the group can be swept out from under it. One that will
# not die even to KILL — uninterruptible I/O, usually — is a machine problem, and it is reported
# as one rather than waited on forever.
g=0
while ! leader_done && [ "$g" -lt "$reap_limit" ]; do
  signal_guarded KILL
  sleep 1; g=$(( g + 1 ))
done
if ! leader_done; then
  publish_status '' "$fired" "$g" leader-stuck \
    "the group leader ignored KILL for ${reap_limit}s"
  exit 2
fi

attempts=0; group=cleared
while :; do
  survivors="$(group_survivors)"
  [ -z "$survivors" ] && break
  if [ "$attempts" -ge "$reap_limit" ]; then
    group="survived:$(printf '%s\n' "$survivors" | awk '{ printf "%s%s", s, $1; s="," }')"
    break
  fi
  signal_guarded KILL
  attempts=$(( attempts + 1 )); sleep 1
done

wait "$child" 2>/dev/null; raw=$?

note=none
[ -n "$aborted" ] && note="aborted by signal before the deadline"
publish_status "$raw" "$fired" "$attempts" "$group" "$note"
exit 0
