#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Shared stub bench for the G6 suites. Sourced, never run.
#
# Every external command the delivery touches is replaced by an exact stub, and the kernel's
# answers come from a synthetic sysfs tree, a synthetic mountinfo and a synthetic df. No real
# losetup, mkfs, mount, umount or /usr/bin/time runs anywhere in these suites — the first three
# are forbidden in this round and the last one is not even installed in the pinned image, which
# is precisely why the delivery addresses all of them through variables and refuses when they
# are missing instead of assuming they are there.
#
# The stubs model only what the real interfaces really expose. In particular a loop device has
# ONE sysfs file for its backing path; the backing inode and backing major:minor come from a
# point query with losetup --list against that one device, because sysfs has no such files.

g6t_make_stub() {  # name body
  { printf '#!/usr/bin/env bash\n'
    printf 'echo "%s $*" >> "$G6T_LOG"\n' "$1"
    printf '%s\n' "$2"
  } > "$G6T_BIN/$1"
  chmod +x "$G6T_BIN/$1"
}

g6t_install_stubs() {  # bin-dir
  G6T_BIN="$1"; mkdir -p "$G6T_BIN"

  g6t_make_stub losetup '
case "${1:-}" in
  --list)
    dev=""; for a in "$@"; do case "$a" in /dev/*) dev="$a" ;; esac; done
    d="${dev#/dev/}"
    f="$G6T_SYS/block/$d/loop/backing_file"
    [ -r "$f" ] || exit 1
    img="$(cat "$f")"
    [ -n "${G6T_NO_LOSETUP_FIELDS:-}" ] && { printf "\n"; exit 0; }
    printf "%s %s\n" "${G6T_FAKE_BACKING_INO:-$(stat -c %i "$img" 2>/dev/null || echo 0)}" \
                     "${G6T_FAKE_BACKING_DEV:-0:42}"
    exit 0 ;;
  -d)
    d="${2#/dev/}"
    # A detach that reports success and leaves the device bound is a real failure mode, and the
    # bench has to be able to produce it: G6T_KEEP_BACKING keeps the backing file exactly as the
    # kernel would if the detach had not taken effect.
    [ -n "${G6T_KEEP_BACKING:-}" ] || rm -f "$G6T_SYS/block/$d/loop/backing_file"
    exit "${G6T_DETACH_RC:-0}" ;;
esac
[ -n "${G6T_LOSETUP_FAIL:-}" ] && exit 1
d="${1#/dev/}"; img="$2"
mkdir -p "$G6T_SYS/block/$d/loop"
printf "%s\n" "${G6T_FAKE_BACKING:-$img}" > "$G6T_SYS/block/$d/loop/backing_file"
printf "7:%s\n" "${d#loop}" > "$G6T_SYS/block/$d/dev"
exit 0'

  g6t_make_stub mkfs.ext4 '
u=""; dev=""
while [ "$#" -gt 0 ]; do
  case "$1" in -U) u="$2"; shift 2 ;; /dev/*) dev="$1"; shift ;; *) shift ;; esac
done
[ -n "${G6T_MKFS_FAIL:-}" ] && exit 1
mkdir -p "$G6T_UUIDS"
printf "%s\n" "${G6T_FAKE_UUID:-$u}" > "$G6T_UUIDS/${dev#/dev/}"
exit 0'

  # dumpe2fs answers with the numbers the filesystem really has. The inode count deliberately
  # differs from the -N request, because ext4 rounds by block-group geometry and the delivery
  # must record what exists rather than what was asked for.
  g6t_make_stub dumpe2fs '
dev=""; for a in "$@"; do case "$a" in /dev/*) dev="$a" ;; esac; done
[ -r "$G6T_UUIDS/${dev#/dev/}" ] || exit 1
[ -n "${G6T_NO_FS_FACTS:-}" ] && exit 0
printf "Filesystem volume name:   <none>\n"
printf "Block size:               %s\n" "${G6T_FAKE_BLOCKSIZE:-4096}"
printf "Inode count:              %s\n" "${G6T_FAKE_INODES:-2506752}"
exit 0'

  # blkid answers for whichever tag was asked. TYPE is a separate fact from UUID: a device can
  # carry the right uuid and the wrong filesystem.
  g6t_make_stub blkid '
dev=""; tag=UUID
prev=""
for a in "$@"; do
  [ "$prev" = "-s" ] && tag="$a"
  case "$a" in /dev/*) dev="$a" ;; esac
  prev="$a"
done
f="$G6T_UUIDS/${dev#/dev/}"
[ -r "$f" ] || exit 2
case "$tag" in
  TYPE) printf "%s\n" "${G6T_FAKE_FSTYPE:-ext4}" ;;
  *)    cat "$f" ;;
esac'

  g6t_make_stub mount '
[ -n "${G6T_MOUNT_FAIL:-}" ] && exit 1
src="$1"; tgt="$2"
# mountinfo is a whitespace-separated table and the kernel escapes whitespace in the path fields
# to keep it one. A bench that writes the raw path cannot describe a mountpoint with a space in
# it at all, so nothing that reads the table could ever be tested against one.
esc="${tgt//\\/\\134}"; esc="${esc// /\\040}"; esc="${esc//	/\\011}"
mm="$(cat "$G6T_SYS/block/${src#/dev/}/dev" 2>/dev/null || echo 7:7)"
printf "36 35 %s / %s rw,relatime shared:1 - %s %s rw\n" \
  "${G6T_FAKE_MOUNT_DEVNO:-$mm}" "$esc" "${G6T_FAKE_FSTYPE:-ext4}" "${G6T_FAKE_SOURCE:-$src}" \
  >> "$G6T_MI"
exit 0'

  # Unmounting takes the filesystem away with it. The stub models that: what was written "into
  # the mount" lived in the image, and after the umount the mountpoint is the empty directory it
  # was before. Without this the bench cannot tell an unmounted mountpoint from one that still
  # has a filesystem on it, and every claim about residue would be vacuous.
  g6t_make_stub umount '
[ -n "${G6T_UMOUNT_FAIL:-}" ] && exit 1
tgt="$1"
esc="${tgt//\\/\\134}"; esc="${esc// /\\040}"; esc="${esc//	/\\011}"
# The escaped path goes through the ENVIRONMENT, not through -v: awk processes escape sequences
# in a -v assignment, so the "\040" this stub just wrote would arrive back as a space and the
# line it is looking for could never be found.
T="$esc" awk "\$5 != ENVIRON[\"T\"]" "$G6T_MI" > "$G6T_MI.new" && mv "$G6T_MI.new" "$G6T_MI"
case "$tgt" in
  "${G6T_W:-/nonexistent}"/*) [ -z "${G6T_UMOUNT_KEEPS_DATA:-}" ] && rm -rf -- "$tgt"/* "$tgt"/.[!.]* 2>/dev/null ;;
esac
exit 0'

  # df answers for whichever axis was asked. The inside and outside numbers are separate so a
  # suite can starve one without touching the other.
  g6t_make_stub df '
inodes=0; for a in "$@"; do [ "$a" = "-i" ] && inodes=1; done
target=""; for a in "$@"; do case "$a" in -*) ;; *) target="$a" ;; esac; done
inside=0
case "$target" in ${G6T_INSIDE:-__none__}*) inside=1 ;; esac
if [ "$inodes" = 1 ]; then
  # A filesystem that runs out part-way through: after G6T_DF_STARVE_AFTER answers about the
  # inside, every later answer is starved. This is what a capacity check BETWEEN batches is for,
  # and a bench where free space never moves cannot tell whether one happens.
  if [ -n "${G6T_DF_STARVE_AFTER:-}" ] && [ "$inside" = 1 ]; then
    n=$(( $(cat "$G6T_W/df-inside-calls" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" > "$G6T_W/df-inside-calls"
    if [ "$n" -gt "$G6T_DF_STARVE_AFTER" ]; then
      printf "Filesystem Inodes IUsed IFree IUse%% Mounted\n"
      printf "stub 9999999 1 5 99%% /\n"
      exit 0
    fi
  fi
  printf "Filesystem Inodes IUsed IFree IUse%% Mounted\n"
  if [ "$inside" = 1 ]; then
    printf "stub %s 1 %s 1%% /\n" "${G6T_DF_INSIDE_INODES_TOTAL:-9999999}" "${G6T_DF_INSIDE_INODES:-9999999}"
  else
    printf "stub %s 1 %s 1%% /\n" "${G6T_DF_OUTSIDE_INODES_TOTAL:-9999999}" "${G6T_DF_OUTSIDE_INODES:-9999999}"
  fi
  exit 0
fi
printf "Filesystem 1B-blocks Used Available Capacity Mounted\n"
if [ "$inside" = 1 ]; then printf "stub 1 1 %s 1%% /\n" "${G6T_DF_INSIDE_BYTES:-99999999999999}"
else printf "stub 1 1 %s 1%% /\n" "${G6T_DF_OUTSIDE_BYTES:-99999999999999}"; fi'

  # GNU time is absent from the pinned image, so the report is synthesised. The only thing the
  # delivery asks of it is that the report goes to its own file and the command still runs.
  g6t_make_stub time '
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -v) shift ;;
    -o) out="$2"; shift 2 ;;
    *) break ;;
  esac
done
[ -n "$out" ] && printf "Command being timed: %s\n\tMaximum resident set size (kbytes): 1024\n\tElapsed (wall clock) time (h:mm:ss or m:ss): %s\n" "$1" "${G6T_FAKE_ELAPSED:-0:00.01}" > "$out"
exec "$@"'
}

# One isolated world: fresh remote root, state dir, synthetic kernel state and call log.
g6t_new_world() {  # base-dir
  G6T_W="$1/w$RANDOM$RANDOM"
  # The state and the work directory live UNDER the sanctioned root, because that is what the
  # plan pins and what containment requires: they are written on every step.
  mkdir -p "$G6T_W/sys" "$G6T_W/uuids" "$G6T_W/remote/g6-image" \
           "$G6T_W/remote/g6-state" "$G6T_W/remote/g6-work"
  : > "$G6T_W/mountinfo"; : > "$G6T_W/log"
  export G6T_W
  export G6T_SYS="$G6T_W/sys" G6T_MI="$G6T_W/mountinfo" G6T_LOG="$G6T_W/log" \
         G6T_UUIDS="$G6T_W/uuids"
  export G6_REMOTE_ROOT="$G6T_W/remote"
  export G6_IMAGE="$G6T_W/remote/g6-image/fixture.img"
  export G6_FIXTURE_ROOT="$G6T_W/remote/g6-fixture"
  export G6_MOUNTPOINT="$G6_FIXTURE_ROOT"
  export G6_STATE_DIR="$G6T_W/remote/g6-state"
  export G6_WORK="$G6T_W/remote/g6-work"
  export G6_LOOP_DEV="/dev/loop7"
  export G6_UUID="1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5061"
  export G6_IMAGE_SIZE="1M"
  export G6_SYSFS_ROOT="$G6T_SYS" G6_MOUNTINFO="$G6T_MI"
  export G6_LOSETUP="$G6T_BIN/losetup" G6_MKFS="$G6T_BIN/mkfs.ext4" G6_MOUNT="$G6T_BIN/mount"
  export G6_UMOUNT="$G6T_BIN/umount" G6_BLKID="$G6T_BIN/blkid" G6_DF="$G6T_BIN/df"
  export G6_TIME="$G6T_BIN/time" G6_DUMPE2FS="$G6T_BIN/dumpe2fs"
  export G6T_INSIDE="$G6_FIXTURE_ROOT"
  export PATH="$G6T_BIN:$PATH"
  unset G6T_FAKE_BACKING G6T_FAKE_UUID G6T_FAKE_SOURCE G6T_FAKE_FSTYPE G6T_FAKE_MOUNT_DEVNO
  unset G6T_LOSETUP_FAIL G6T_MKFS_FAIL G6T_MOUNT_FAIL G6T_UMOUNT_FAIL G6T_DETACH_RC
  unset G6T_NO_LOSETUP_FIELDS G6T_FAKE_BACKING_DEV G6T_FAKE_BACKING_INO
  unset G6T_NO_FS_FACTS G6T_FAKE_BLOCKSIZE G6T_FAKE_INODES G6T_FAKE_ELAPSED
  unset G6T_DF_OUTSIDE_BYTES G6T_DF_INSIDE_BYTES G6T_DF_OUTSIDE_INODES G6T_DF_INSIDE_INODES
  unset G6T_DF_INSIDE_INODES_TOTAL G6T_DF_OUTSIDE_INODES_TOTAL
  unset G6T_KEEP_BACKING G6T_UMOUNT_KEEPS_DATA G6T_DF_STARVE_AFTER
}

# A sanction sealed over the calibration that actually exists, plus the candidate and bundle
# hashes that are actually loaded. Tests that want a mismatch introduce it deliberately.
# The frozen resource plan: every resource BOTH contours may touch, and every number either of
# them measures itself against, named once.
g6t_write_plan() {  # plan-path [mode]
  local mode="${2:-rehearsal}" g m u b seed
  if [ "$mode" = live ]; then
    g=645000; m=2; u=910000; b=4096; seed="g6-fixture-v1"
  else
    g="${G6T_G:-40}"; m=2; u="${G6T_U:-20}"; b=4096; seed="rehearsal-v1"
  fi
  { printf 'host\t%s\n'        "$(hostname)"
    printf 'remote-root\t%s\n' "$G6_REMOTE_ROOT"
    printf 'image\t%s\n'       "$G6_IMAGE"
    printf 'loop-device\t%s\n' "$G6_LOOP_DEV"
    printf 'uuid\t%s\n'        "$G6_UUID"
    printf 'mountpoint\t%s\n'  "$G6_FIXTURE_ROOT"
    printf 'state-dir\t%s\n'   "$G6_STATE_DIR"
    printf 'work-dir\t%s\n'    "$G6_WORK"
    printf 'evidence-dir\t%s\n' "$G6_WORK"
    printf 'image-size\t%s\n'  "$G6_IMAGE_SIZE"
    # the sealed 1/100 kit, sharing nothing with the run but the device and the order of use
    printf 'cal-image\t%s\n'        "$G6_REMOTE_ROOT/g6-calibration-image/calibration.img"
    printf 'cal-image-bytes\t%s\n'  "1073741824"
    printf 'cal-mountpoint\t%s\n'   "$G6_REMOTE_ROOT/g6-calibration"
    printf 'cal-state-dir\t%s\n'    "$G6_REMOTE_ROOT/g6-calibration-state"
    printf 'cal-loop-device\t%s\n'  "$G6_LOOP_DEV"
    printf 'cal-uuid\t%s\n'         "9f8e7d6c-5b4a-3928-1706-a5b4c3d2e1f0"
    printf 'cal-image-size\t%s\n'   "1G"
    printf 'cal-order\t%s\n'        "calibration-releases-the-device-before-the-run"
    # the calibration contour's own requirements: one hundredth of the run's, and its own
    # geometry — a one-gigabyte image formatted for the run's inode table is not a hundredth
    # of anything.
    printf 'cal-external-requirement\t%s\n'  "3221225472"
    printf 'cal-inode-need\t%s\n'            "22659"
    printf 'cal-inode-reserve\t%s\n'         "2266"
    printf 'cal-internal-byte-need\t%s\n'    "90112000"
    printf 'cal-internal-byte-reserve\t%s\n' "17179869"
    printf 'cal-block-size\t%s\n'            "4096"
    printf 'cal-requested-inodes\t%s\n'      "25000"
    # the numbers, frozen
    printf 'image-bytes\t%s\n'            "17179869184"
    printf 'external-requirement\t%s\n'   "51539607552"
    printf 'inode-need\t%s\n'             "2265900"
    printf 'inode-reserve\t%s\n'          "226590"
    printf 'internal-byte-need\t%s\n'     "9011200000"
    printf 'internal-byte-reserve\t%s\n'  "1717986918"
    printf 'batch\t%s\n'                  "10000"
    printf 'block-size\t%s\n'             "4096"
    printf 'requested-inodes\t%s\n'       "2500000"
    printf 'scale-G\t%s\n' "$g"; printf 'scale-M\t%s\n' "$m"
    printf 'scale-U\t%s\n' "$u"; printf 'scale-B\t%s\n' "$b"
    printf 'scale-seed\t%s\n' "$seed"
  } > "$1"
}

g6t_write_sanction() {  # mode sanction-path calibration-path candidate bundle-sha plan-path
  local mode="$1" sp="$2" cp="$3" bin="$4" bundle="$5" plan="$6"
  local g m u b seed contour
  if [ "$mode" = live ]; then
    g=645000; m=2; u=910000; b=4096; seed="g6-fixture-v1"; contour=host
  else
    g="${G6T_G:-40}"; m=2; u="${G6T_U:-20}"; b=4096; seed="rehearsal-v1"; contour=local
  fi
  { printf 'G6 LOAD SANCTION\n'
    printf 'mode\t%s\n' "$mode"
    printf 'contour\t%s\n' "$contour"
    printf 'host\t%s\n' "$(hostname)"
    printf 'remote-root\t%s\n' "$G6_REMOTE_ROOT"
    printf 'candidate-sha256\t%s\n' "$(sha256sum -- "$bin" | cut -d' ' -f1)"
    printf 'bundle-sha256\t%s\n' "$bundle"
    printf 'calibration-sha256\t%s\n' "$(sha256sum -- "$cp" | cut -d' ' -f1)"
    printf 'resource-plan-sha256\t%s\n' "$(sha256sum -- "$plan" | cut -d' ' -f1)"
    printf 'scale-G\t%s\n' "$g"
    printf 'scale-M\t%s\n' "$m"
    printf 'scale-U\t%s\n' "$u"
    printf 'scale-B\t%s\n' "$b"
    printf 'scale-seed\t%s\n' "$seed"
    printf 'image\t%s\n' "$G6_IMAGE"
    printf 'loop-device\t%s\n' "$G6_LOOP_DEV"
    printf 'uuid\t%s\n' "$G6_UUID"
    printf 'mountpoint\t%s\n' "$G6_FIXTURE_ROOT"
    printf 'state-dir\t%s\n' "$G6_STATE_DIR"
    printf 'work-dir\t%s\n' "$G6_WORK"
    printf 'image-size\t%s\n' "$G6_IMAGE_SIZE"
    printf 'window-open\t1000\n'
    printf 'window-close\t9999999999\n'
    printf 'signed-by\tdk\n'
  } > "$sp"
}

# A calibration manifest that survives being recomputed: the guards here are what the frozen
# formula gives for the measurements here. A manifest with four arbitrary positive numbers is
# refused now, which is the point of the recomputation.
g6t_write_calibration() {  # scale path [t1] [t2]
  local t1="${3:-1}" t2="${4:-1}" g1 g2
  g1=$(( 4 * 100 * t1 )); [ "$g1" -lt 900 ] && g1=900
  g2=$(( 4 * 100 * t2 )); [ "$g2" -lt 900 ] && g2=900
  { printf 'scale\t%s\n' "$1"
    printf 'calibration-divisor\t100\n'
    printf 'elapsed-S1\t%s\n' "$t1"; printf 'elapsed-S2\t%s\n' "$t2"
    printf 'formula\tmax(4 * 100 * t, 900)\n'
    printf 'guard-S1\t%s\n' "$g1"; printf 'guard-S2\t%s\n' "$g2"
    printf 'guard-S3\t%s\n' "$g2"; printf 'guard-S4\t%s\n' "$g1"
  } > "$2"
}

# ---------------------------------------------------------------- matching, without a pipe
#
# `producer | grep -q needle` is a RACE, not a test. grep exits at the first match, the
# producer takes SIGPIPE, and under `set -o pipefail` the pipeline reports 141 — a match read
# as a miss. It is the same class that was removed from the G4/G5 harness, and it must never
# come back through the oracle that judges everything else: a flaky matcher turns a surviving
# mutant into a killed one at random.
#
# Both helpers work on a string already in memory and start no subprocess at all.

g6_has() {  # haystack needle — literal substring
  case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac
}

g6_has_line() {  # haystack line — one WHOLE line, literally
  local nl='
'
  case "$nl$1$nl" in *"$nl$2$nl"*) return 0 ;; *) return 1 ;; esac
}
