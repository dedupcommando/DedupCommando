#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scenario suite for the G6 loopback lifecycle, with fault injection at every transition.
#
# The teardown contract under test is the strict one: nothing is removed on a chain that is not
# confirmed. An action that happened without its record is a PUBLICATION failure, and the remedy
# for that is a human reading an inventory — not the harness deciding the object is probably its
# own and cleaning it up.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$HERE/g6-image-lib.sh"
. "$HERE/test-g6-stubs.sh"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
g6t_install_stubs "$WORK/bin"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"
        [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }

lib() { bash "$LIB" "$@"; }
world() { g6t_new_world "$WORK"; }
chain() { lib prepare >/dev/null && lib attach >/dev/null \
            && lib format >/dev/null && lib mount >/dev/null; }

refuses() {  # label needle -- command...
  local label="$1" needle="$2"; shift 2; [ "$1" = "--" ] && shift
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" = 0 ]; then bad "$label — it was accepted"; return; fi
  case "$out" in
    *"$needle"*) ok "$label" ;;
    *) bad "$label — refused, but nothing named '$needle'" "$(printf '%s' "$out" | tail -6)" ;;
  esac
}

echo "== G6 lifecycle suite — synthetic kernel state, no real loop, mkfs or mount =="

echo
echo "== 1. the four states, in order =="
world
chain && ok "prepare -> attach -> format -> mount completes" \
      || bad "prepare -> attach -> format -> mount completes" "$(cat "$G6T_W/log")"
for r in PREPARED ATTACHED FORMATTED MOUNTED; do
  [ -f "$G6_STATE_DIR/$r" ] && ok "record $r published" || bad "record $r published"
done
lib verify >/dev/null 2>&1 && ok "the chain verifies against the kernel" \
                           || bad "the chain verifies against the kernel"

# The backing inode comes from a losetup point query, not from an invented sysfs file.
grep -q '^backing_ino	[0-9]' "$G6_STATE_DIR/ATTACHED" \
  && ok "the backing inode was recorded from the losetup point query" \
  || bad "the backing inode was recorded from the losetup point query"
[ ! -e "$G6T_SYS/block/loop7/loop/backing_ino" ] \
  && ok "no invented backing_ino file exists in the synthetic sysfs" \
  || bad "no invented backing_ino file exists in the synthetic sysfs"

world
lib prepare >/dev/null
refuses "an unavailable losetup field is BLOCKED, never recorded blank" "field is unavailable" -- \
  env G6T_NO_LOSETUP_FIELDS=1 bash "$LIB" attach

echo
echo "== 2. order and containment =="
world
refuses "attach before prepare" "before PREPARED" -- lib attach
lib prepare >/dev/null
refuses "format before attach" "before ATTACHED" -- lib format
lib attach >/dev/null
refuses "mount before format" "before FORMATTED" -- lib mount

world
refuses "an image outside REMOTE_ROOT" "not under REMOTE_ROOT" -- \
  env G6_IMAGE="/tmp/escape.img" bash "$LIB" prepare
refuses "a mountpoint outside REMOTE_ROOT" "not under REMOTE_ROOT" -- \
  env G6_MOUNTPOINT="/tmp/escape" bash "$LIB" prepare
refuses "a '..' in the image path" "'.' or '..'" -- \
  env G6_IMAGE="$G6_REMOTE_ROOT/../escape.img" bash "$LIB" prepare
ln -sfn /tmp "$G6_REMOTE_ROOT/linkdir" 2>/dev/null
refuses "a symlinked component in the chain" "symbolic link" -- \
  env G6_IMAGE="$G6_REMOTE_ROOT/linkdir/x.img" bash "$LIB" prepare

echo
echo "== 3. identity mismatches =="
world; lib prepare >/dev/null
refuses "the kernel reports a different backing file" "not '$G6_IMAGE'" -- \
  env G6T_FAKE_BACKING="/somebody/else.img" bash "$LIB" attach

world
mkdir -p "$G6T_SYS/block/loop7/loop"; printf '/foreign.img\n' > "$G6T_SYS/block/loop7/loop/backing_file"
lib prepare >/dev/null
refuses "the assigned device already backs someone else" "already backs" -- lib attach

world; lib prepare >/dev/null; lib attach >/dev/null
refuses "a different filesystem UUID" "not '$G6_UUID'" -- \
  env G6T_FAKE_UUID="00000000-0000-0000-0000-000000000000" bash "$LIB" format

world; lib prepare >/dev/null; lib attach >/dev/null; lib format >/dev/null
refuses "a mount from a different source" "not /dev/loop7" -- \
  env G6T_FAKE_SOURCE="/dev/loop9" bash "$LIB" mount

world; chain >/dev/null
printf '999\n' > /dev/null   # the backing inode now comes from losetup, so move the real one
refuses "a changed backing device breaks the chain" "backing device" -- \
  env G6T_FAKE_BACKING_DEV="9:9" bash "$LIB" verify

world; chain >/dev/null; : > "$G6T_MI"
refuses "a vanished mount breaks the chain" "nothing is mounted" -- lib verify

world; chain >/dev/null
printf 'deadbeef-0000-0000-0000-000000000000\n' > "$G6T_UUIDS/loop7"
refuses "a changed filesystem UUID breaks the chain" "UUID" -- lib verify

world; chain >/dev/null
rm -f "$G6_IMAGE"; : > "$G6_IMAGE"
refuses "the image replaced underneath" "recorded" -- lib verify

echo
echo "== 4. teardown removes nothing it cannot confirm =="

# attach happened, ATTACHED never published.
world; lib prepare >/dev/null
"$G6_LOSETUP" "$G6_LOOP_DEV" "$G6_IMAGE" >/dev/null 2>&1
out="$(lib teardown 2>&1)"; rc=$?
if [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'ATTACHED was never published' \
   && printf '%s' "$out" | grep -q 'INVENTORY:'; then
  ok "an unpublished attach is BLOCKED with an inventory"
else bad "an unpublished attach is BLOCKED with an inventory" "$(printf '%s' "$out" | tail -6)"; fi
[ -e "$G6_IMAGE" ] && ok "and the image is untouched" || bad "and the image is untouched"
grep -q '^losetup -d' "$G6T_W/log" && bad "and nothing was detached" || ok "and nothing was detached"

# mount happened, MOUNTED never published.
world; lib prepare >/dev/null; lib attach >/dev/null; lib format >/dev/null
mkdir -p "$G6_MOUNTPOINT"; "$G6_MOUNT" "$G6_LOOP_DEV" "$G6_MOUNTPOINT" >/dev/null 2>&1
out="$(lib teardown 2>&1)"; rc=$?
if [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'MOUNTED was never published'; then
  ok "an unpublished mount is BLOCKED with an inventory"
else bad "an unpublished mount is BLOCKED with an inventory" "$(printf '%s' "$out" | tail -6)"; fi
grep -q '^umount' "$G6T_W/log" && bad "and nothing was unmounted" || ok "and nothing was unmounted"

# a foreign image on the assigned device
world; lib prepare >/dev/null
mkdir -p "$G6T_SYS/block/loop7/loop"; printf '/foreign.img\n' > "$G6T_SYS/block/loop7/loop/backing_file"
out="$(lib teardown 2>&1)"; rc=$?
[ "$rc" != 0 ] && ok "a foreign image on the device blocks the teardown" \
               || bad "a foreign image on the device blocks the teardown" "$out"
[ -e "$G6_IMAGE" ] && ok "our image survives it" || bad "our image survives it"

# a foreign mount at our target
world; lib prepare >/dev/null
printf '36 35 8:1 / %s rw - ext4 /dev/sda1 rw\n' "$G6_MOUNTPOINT" > "$G6T_MI"
out="$(lib teardown 2>&1)"; rc=$?
[ "$rc" != 0 ] && ok "a foreign mount at our target blocks the teardown" \
               || bad "a foreign mount at our target blocks the teardown" "$out"
grep -q '/dev/sda1' "$G6T_MI" && ok "the foreign mount survives" || bad "the foreign mount survives"

# a chain that no longer matches: nothing is removed
world; chain >/dev/null
printf 'deadbeef-0000-0000-0000-000000000000\n' > "$G6T_UUIDS/loop7"
out="$(lib teardown 2>&1)"; rc=$?
if [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'does not match the machine'; then
  ok "a chain that no longer matches blocks before any removal"
else bad "a chain that no longer matches blocks before any removal" "$(printf '%s' "$out" | tail -5)"; fi
[ -e "$G6_IMAGE" ] && ok "and the image is still there" || bad "and the image is still there"

# a refused umount stops everything below it
world; chain >/dev/null
out="$(G6T_UMOUNT_FAIL=1 bash "$LIB" teardown 2>&1)"; rc=$?
[ "$rc" != 0 ] && ok "a refused umount is BLOCKED" || bad "a refused umount is BLOCKED" "$out"
grep -q '^losetup -d' "$G6T_W/log" && bad "and nothing below it ran" || ok "and nothing below it ran"

# A detach that reports success and leaves the device bound. The stub keeps the backing file
# exactly as the kernel would, so this is the real failure and not a rehearsal of it: teardown
# must refuse, and it must refuse BEFORE unlinking the image out from under a live device.
world; chain >/dev/null
out="$(G6T_KEEP_BACKING=1 bash "$LIB" teardown 2>&1)"; rc=$?
if [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'still reports a backing file after detach'; then
  ok "a detach that did not take effect is BLOCKED"
else bad "a detach that did not take effect is BLOCKED" "$(printf '%s' "$out" | tail -5)"; fi
[ -e "$G6_IMAGE" ] && ok "and the image was not unlinked under a live device" \
                   || bad "and the image was not unlinked under a live device"

# the clean case, for contrast
world; chain >/dev/null
out="$(bash "$LIB" teardown 2>&1)"
printf '%s' "$out" | grep -q 'teardown complete' && ok "a clean teardown says complete" \
                                                 || bad "a clean teardown says complete" "$out"

# the happy path, and a second run is a clean no-op
world; chain >/dev/null
lib teardown >/dev/null 2>&1 && ok "a confirmed chain tears down" || bad "a confirmed chain tears down"
[ ! -e "$G6_IMAGE" ] && ok "the image is gone" || bad "the image is gone"
lib teardown >/dev/null 2>&1 && ok "a second teardown is a clean no-op" \
                             || bad "a second teardown is a clean no-op"

echo
echo "== 5. the forbidden discovery forms are absent from the library =="
scan_lib() { sed 's/[[:space:]]*#.*$//' "$LIB"; }
for pat in 'losetup --find' 'losetup -f' 'losetup -a'; do
  scan_lib | grep -qE -- "$pat" && bad "no executable line uses '$pat'" \
                                || ok "no executable line uses '$pat'"
done
scan_lib | grep -qE '/dev/loop\*|\bls .*loop' \
  && bad "no executable line globs over loop devices" || ok "no executable line globs over loop devices"
# The invented fields were SYSFS files. The record still has backing_ino and backing_dev keys —
# it has to, they are the facts — so what must be absent is any line that reads them from
# /sys/block/<dev>/loop/, which is where the earlier draft imagined them.
scan_lib | grep -qE 'block/[^/]*/loop/backing_(ino|dev)|SYSFS[^ ]*backing_(ino|dev)' \
  && bad "no executable line reads an invented sysfs field" \
  || ok "no executable line reads an invented sysfs field"

echo
echo "== result: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
