#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# G6 loopback lifecycle: PREPARED -> ATTACHED -> FORMATTED -> MOUNTED.
#
# A loop device is a GLOBAL kernel name. It cannot be held under <REMOTE_ROOT> the way a path
# can, so identity here is a chain of four durable records, each published only AFTER its fact
# became true and each carrying values that can be read back from the kernel later. The image's
# content is deliberately not part of that identity: it changes on every write, so a
# fingerprint of it stops matching during ordinary work.
#
# The device is ASSIGNED by the published resource plan and never discovered. Searching forms
# are absent from this file by construction and the suite greps for them.
#
# Two interfaces are read, and only for the ONE assigned device:
#   /sys/block/<dev>/loop/backing_file   the backing path
#   losetup --list --output ... <dev>    the backing inode and backing major:minor
# There is no backing_ino or backing_dev file in sysfs; an earlier draft of this library
# invented both and its tests then validated the invention. Whether this kernel's losetup
# offers those columns is a HOST PREFLIGHT question, not something to assume here: the library
# refuses when the fields it needs are unavailable rather than recording a blank as a fact.
#
# Teardown removes nothing on a chain it cannot confirm. A missing record does not license the
# action below it, and an attach or a mount that is present but unconfirmed is BLOCKED with an
# inventory for a human — not quietly cleaned up.

set -uo pipefail

G6_IMAGE="${G6_IMAGE:-}"
G6_LOOP_DEV="${G6_LOOP_DEV:-}"
G6_MOUNTPOINT="${G6_MOUNTPOINT:-}"
G6_UUID="${G6_UUID:-}"
G6_STATE_DIR="${G6_STATE_DIR:-}"
G6_IMAGE_SIZE="${G6_IMAGE_SIZE:-}"
G6_REMOTE_ROOT="${G6_REMOTE_ROOT:-}"

G6_LOSETUP="${G6_LOSETUP:-losetup}"
G6_MKFS="${G6_MKFS:-mkfs.ext4}"
G6_MOUNT="${G6_MOUNT:-mount}"
G6_UMOUNT="${G6_UMOUNT:-umount}"
G6_BLKID="${G6_BLKID:-blkid}"
G6_DUMPE2FS="${G6_DUMPE2FS:-dumpe2fs}"
G6_TRUNCATE="${G6_TRUNCATE:-truncate}"

G6_MIN_INODES="${G6_MIN_INODES:-0}"
G6_BLOCK_SIZE="${G6_BLOCK_SIZE:-4096}"
G6_REQUESTED_INODES="${G6_REQUESTED_INODES:-2500000}"

G6_SYSFS_ROOT="${G6_SYSFS_ROOT:-/sys}"
G6_MOUNTINFO="${G6_MOUNTINFO:-/proc/self/mountinfo}"

G6_PUBLISH="${G6_PUBLISH:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/g6-publish-record.py}"

g6_die()     { printf 'REFUSED: %s\n' "$1" >&2; return 1; }
g6_blocked() { printf 'BLOCKED: %s\n' "$1" >&2; return 2; }
g6_say()     { printf 'g6: %s\n' "$1"; }

# ------------------------------------------------------------------ containment

# Lexical containment under <REMOTE_ROOT>, then a realpath and lstat check of the whole parent
# chain. Applied to every path this library creates, writes or removes.
g6_contained() {  # path -> 0 when it lies under REMOTE_ROOT by spelling and by canonical form
  local path="$1" p real
  [ -n "$G6_REMOTE_ROOT" ] || { g6_die "G6_REMOTE_ROOT is not set"; return 1; }
  case "$path" in
    /*) ;; *) g6_die "path '$path' is not absolute"; return 1 ;;
  esac
  case "$path" in
    *//*|*/./*|*/../*|*/.|*/..)
      g6_die "path '$path' contains an empty, '.' or '..' component"; return 1 ;;
  esac
  case "$path" in
    "$G6_REMOTE_ROOT"/*) ;;
    *) g6_die "path '$path' is not under REMOTE_ROOT '$G6_REMOTE_ROOT'"; return 1 ;;
  esac
  if [ -e "$path" ]; then
    real="$(readlink -f -- "$path" 2>/dev/null)" || { g6_die "cannot canonicalize '$path'"; return 1; }
    [ "$real" = "$path" ] || { g6_die "'$path' canonicalizes to '$real'"; return 1; }
  fi
  # Every existing component of the chain must be a real directory, never a link.
  p="$(dirname "$path")"
  while [ "$p" != "/" ] && [ -n "$p" ]; do
    if [ -L "$p" ]; then g6_die "'$p' in the chain of '$path' is a symbolic link"; return 1; fi
    [ "$p" = "$G6_REMOTE_ROOT" ] && break
    p="$(dirname "$p")"
  done
  return 0
}

# ------------------------------------------------------------------ environment

g6_require_env() {
  local v val
  for v in G6_IMAGE G6_LOOP_DEV G6_MOUNTPOINT G6_UUID G6_STATE_DIR G6_REMOTE_ROOT; do
    eval "val=\${$v}"
    [ -n "$val" ] || { g6_die "$v is not set — this lifecycle never guesses one"; return 1; }
  done
  case "$G6_REMOTE_ROOT" in
    /*) ;; *) g6_die "G6_REMOTE_ROOT='$G6_REMOTE_ROOT' is not absolute"; return 1 ;;
  esac
  case "$G6_LOOP_DEV" in
    *[*?\[]*) g6_die "G6_LOOP_DEV='$G6_LOOP_DEV' contains a glob character — a pattern is a \
search, and the device is named by the plan"; return 1 ;;
  esac
  # Exact means exact. `/dev/loop[0-9]*` also accepts /dev/loop7p1 — a PARTITION of the device,
  # which is a different block device with a different lifetime, and detaching it does not detach
  # what the plan named.
  case "${G6_LOOP_DEV#/dev/loop}" in
    ''|*[!0-9]*) g6_die "G6_LOOP_DEV='$G6_LOOP_DEV' is not an exact /dev/loopN name"; return 1 ;;
  esac
  case "$G6_LOOP_DEV" in
    /dev/loop[0-9]*) ;;
    *) g6_die "G6_LOOP_DEV='$G6_LOOP_DEV' is not an exact /dev/loopN name"; return 1 ;;
  esac
  # And a uuid is 8-4-4-4-12 lowercase hex, not five groups of anything. A short one is accepted
  # by mkfs after padding, and the value blkid reads back is then not the value that was pinned.
  if ! [[ "$G6_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    g6_die "G6_UUID='$G6_UUID' is not a uuid"; return 1
  fi
  g6_contained "$G6_IMAGE" || return 1
  g6_contained "$G6_MOUNTPOINT" || return 1
  # The state is not exempt from containment. It is written on every step, and a state directory
  # outside the sanctioned root is a write outside the sanctioned root — the fact that it holds
  # bookkeeping rather than fixture data changes nothing about where it lands.
  g6_contained "$G6_STATE_DIR" || return 1
  [ -d "$G6_STATE_DIR" ] || { g6_die "G6_STATE_DIR='$G6_STATE_DIR' is not a directory"; return 1; }
  return 0
}

g6_loop_name() { printf '%s' "${G6_LOOP_DEV#/dev/}"; }

# ------------------------------------------------------------------ kernel facts

g6_stat_devino() { stat -c '%d:%i' -- "$1" 2>/dev/null || true; }
g6_stat_size()   { stat -c '%s'    -- "$1" 2>/dev/null || true; }

# The backing path, from the one sysfs file that really exists for a loop device.
g6_kernel_backing_file() {
  local f="$G6_SYSFS_ROOT/block/$(g6_loop_name)/loop/backing_file"
  [ -r "$f" ] || return 0
  head -n 1 -- "$f" 2>/dev/null || true
}

g6_kernel_devno() {
  local f="$G6_SYSFS_ROOT/block/$(g6_loop_name)/dev"
  [ -r "$f" ] || return 0
  head -n 1 -- "$f" 2>/dev/null || true
}

# The backing inode and backing device, from a point query against THIS device only. Never a
# listing, never a filter over every loop. An empty or malformed answer is an unavailable
# interface, and unavailable is refused rather than recorded as a value.
g6_losetup_fields() {  # -> "BACK-INO BACK-MAJ:MIN" or empty
  "$G6_LOSETUP" --list --noheadings --output BACK-INO,BACK-MAJ:MIN "$G6_LOOP_DEV" 2>/dev/null \
    | awk 'NR == 1 { print $1, $2 }'
}

# The filesystem's own numbers, read back from the filesystem rather than restated from the
# mkfs command line. `-N` is a REQUEST: ext4 rounds the inode count by block-group geometry, so
# what was asked for and what exists are different facts and only the second one is recorded.
g6_fs_facts() {  # -> "BLOCKSIZE INODECOUNT" or empty
  "$G6_DUMPE2FS" -h "$G6_LOOP_DEV" 2>/dev/null | awk -F: '
    /^Block size:/  { gsub(/ /, "", $2); bs = $2 }
    /^Inode count:/ { gsub(/ /, "", $2); ic = $2 }
    END { if (bs != "" && ic != "") print bs, ic }'
}

g6_mountinfo_for_target() {
  [ -r "$G6_MOUNTINFO" ] || return 0
  # The wanted path travels in the environment rather than through -v, because awk processes
  # escape sequences in a -v assignment: a mountpoint containing a backslash would arrive here as
  # something else entirely and quietly fail to match itself.
  G6_MI_WANT="$1" awk '
    {
      sep = 0
      for (i = 7; i <= NF; i++) if ($i == "-") { sep = i; break }
      # The kernel escapes space, tab, newline and backslash in the path fields of mountinfo, so
      # the field is decoded before it is compared. Compared raw it never matches a mountpoint
      # whose path contains a space: the run cannot find its own mount and refuses for a reason
      # that has nothing to do with the mount.
      target = $5
      gsub(/\\040/, " ",    target)
      gsub(/\\011/, "\t",   target)
      gsub(/\\012/, "\n",   target)
      gsub(/\\134/, "\\\\", target)
      if (sep && target == ENVIRON["G6_MI_WANT"]) print $3, $(sep + 1), $(sep + 2)
    }' "$G6_MOUNTINFO"
}

# ------------------------------------------------------------------ records

g6_record_path() { printf '%s/%s' "$G6_STATE_DIR" "$1"; }
g6_has_record()  { [ -f "$(g6_record_path "$1")" ]; }

# A record is trusted only after its own seal checks out. A truncated or edited record is not a
# weaker fact, it is not a fact at all, and every field read below goes through this gate.
g6_record_intact() {  # name -> 0 when the seal verifies
  "$G6_PUBLISH" --verify --dir "$G6_STATE_DIR" --name "$1" >/dev/null 2>&1
}

g6_record_field() {  # name key -> value
  local f; f="$(g6_record_path "$1")"
  [ -f "$f" ] || return 1
  g6_record_intact "$1" || { g6_blocked "record '$1' does not verify against its own seal"; return 1; }
  awk -F'\t' -v k="$2" '$1 == k { print $2; found = 1 } END { exit !found }' "$f"
}

# Every published record must be intact before any step acts on the chain.
g6_records_intact() {
  local r rc=0
  for r in PREPARED ATTACHED FORMATTED MOUNTED TORNDOWN; do
    g6_has_record "$r" || continue
    g6_record_intact "$r" || { g6_blocked "record '$r' does not verify against its own seal"; rc=2; }
  done
  return "$rc"
}

g6_publish_record() { "$G6_PUBLISH" --dir "$G6_STATE_DIR" --name "$1"; }

# The digest of a published record, used to cross-link the next one to it. Without the link the
# four records are four separate facts that happen to sit in one directory; with it they are a
# chain, and a record carried over from another run cannot be slotted into the middle of it.
g6_record_sha() {  # name -> sha256 of the record file, or 'none'
  local f; f="$(g6_record_path "$1")"
  [ -f "$f" ] || { printf 'none'; return 0; }
  sha256sum -- "$f" | cut -d' ' -f1
}

# The chain, in order, and the record each step must be linked to.
g6_prev_of() {  # record -> the record it links back to
  case "$1" in
    PREPARED)  printf 'none' ;;
    ATTACHED)  printf 'PREPARED' ;;
    FORMATTED) printf 'ATTACHED' ;;
    MOUNTED)   printf 'FORMATTED' ;;
    TORNDOWN)  printf 'MOUNTED' ;;
  esac
}

g6_check_crosslink() {  # record -> 0 when its prev-sha256 still matches the record before it
  local rec="$1" prev want got
  prev="$(g6_prev_of "$rec")"
  want="$(g6_record_field "$rec" prev-sha256)" || return 2
  if [ "$prev" = none ]; then
    [ "$want" = none ] && return 0
    g6_blocked "$rec links back to '$want' but nothing precedes it"; return 2
  fi
  got="$(g6_record_sha "$prev")"
  [ "$want" = "$got" ] && return 0
  g6_blocked "$rec links back to $prev as $want, but $prev now hashes to $got"
  return 2
}

# Where the chain stands, read from durable state alone. Safe to call any number of times and
# the basis for continuing after an interruption.
g6_resume() {
  g6_require_env || return $?
  g6_records_intact || return 2
  local r last=none
  for r in PREPARED ATTACHED FORMATTED MOUNTED TORNDOWN; do
    g6_has_record "$r" || break
    g6_check_crosslink "$r" || return 2
    last="$r"
  done
  local next
  case "$last" in
    none)      next=prepare ;;
    PREPARED)  next=attach ;;
    ATTACHED)  next=format ;;
    FORMATTED) next=mount ;;
    MOUNTED)   next=teardown ;;
    TORNDOWN)  next=done ;;
  esac
  printf 'resume\tlast=%s\tnext=%s\n' "$last" "$next"
  g6_say "chain resumes at '$next'"
}

# Before ANY lifecycle mutation the entire chain published so far must still describe the
# machine. Checking only the immediately preceding record would let a step build on a chain that
# quietly stopped being true two steps earlier.
g6_chain_ok_before() {  # step-name
  g6_records_intact || return 2
  g6_verify_chain >/dev/null 2>&1 && return 0
  g6_verify_chain >/dev/null
  g6_blocked "the published chain no longer describes the machine — refusing to $1 on top of it"
  return 2
}

# ------------------------------------------------------------------ steps

g6_prepare() {
  g6_require_env || return $?
  g6_has_record PREPARED && { g6_blocked "PREPARED is already published"; return 2; }
  [ -n "$G6_IMAGE_SIZE" ] || { g6_die "G6_IMAGE_SIZE is not set"; return 1; }
  [ -e "$G6_IMAGE" ] && { g6_blocked "'$G6_IMAGE' already exists — refusing to reuse it"; return 2; }

  mkdir -p "$(dirname "$G6_IMAGE")" || { g6_die "cannot create the image directory"; return 1; }
  g6_contained "$(dirname "$G6_IMAGE")" || return 1
  "$G6_TRUNCATE" -s "$G6_IMAGE_SIZE" "$G6_IMAGE" || { g6_die "cannot create the image"; return 1; }

  {
    printf 'image\t%s\n'    "$G6_IMAGE"
    printf 'devino\t%s\n'   "$(g6_stat_devino "$G6_IMAGE")"
    printf 'size\t%s\n'     "$(g6_stat_size "$G6_IMAGE")"
    printf 'loop_dev\t%s\n' "$G6_LOOP_DEV"
    printf 'remote_root\t%s\n' "$G6_REMOTE_ROOT"
    printf 'prev-sha256\tnone\n'
  } | g6_publish_record PREPARED || { g6_blocked "PREPARED publication failed"; return 2; }
  g6_say "PREPARED $G6_IMAGE -> $G6_LOOP_DEV"
}

g6_attach() {
  g6_require_env || return $?
  g6_has_record PREPARED || { g6_blocked "cannot attach before PREPARED"; return 2; }
  g6_has_record ATTACHED && { g6_blocked "ATTACHED is already published"; return 2; }
  g6_chain_ok_before attach || return 2

  local pre; pre="$(g6_kernel_backing_file)"
  if [ -n "$pre" ]; then
    g6_blocked "$G6_LOOP_DEV already backs '$pre' — the plan no longer describes reality"
    return 2
  fi

  "$G6_LOSETUP" "$G6_LOOP_DEV" "$G6_IMAGE" || { g6_die "losetup refused"; return 1; }

  local bf dn fields bi bd
  bf="$(g6_kernel_backing_file)"; dn="$(g6_kernel_devno)"
  if [ "$bf" != "$G6_IMAGE" ]; then
    g6_blocked "the kernel reports '$bf' behind $G6_LOOP_DEV, not '$G6_IMAGE'"
    return 2
  fi
  fields="$(g6_losetup_fields)"
  bi="$(printf '%s' "$fields" | awk '{print $1}')"
  bd="$(printf '%s' "$fields" | awk '{print $2}')"
  # Both fields are judged together and refused together: recording one of them and a blank for
  # the other would publish a record that is half fact and half nothing.
  local unavailable=""
  case "$bi" in
    ''|*[!0-9]*) unavailable="backing inode" ;;
  esac
  case "$bd" in
    *:*) ;;
    *) unavailable="${unavailable:+$unavailable and }backing major:minor" ;;
  esac
  if [ -n "$unavailable" ]; then
    g6_blocked "losetup did not report a numeric $unavailable for $G6_LOOP_DEV — the field is \
unavailable on this kernel and must be settled by the host preflight"
    return 2
  fi
  # The kernel's backing inode is compared with the inode of the image the PLAN named. Recording
  # both and comparing neither would leave the device bound to a file that merely has the same
  # path spelling — the case where an image was replaced between prepare and attach.
  local planned_ino planned_dev
  planned_ino="$(stat -c '%i' -- "$G6_IMAGE" 2>/dev/null)"
  planned_dev="$(stat -c '%d' -- "$G6_IMAGE" 2>/dev/null)"
  [ "$bi" = "$planned_ino" ] || {
    g6_blocked "$G6_LOOP_DEV backs inode $bi, but the planned image '$G6_IMAGE' is inode \
$planned_ino"
    return 2; }
  {
    printf 'loop_dev\t%s\n'     "$G6_LOOP_DEV"
    printf 'devno\t%s\n'        "$dn"
    printf 'backing_file\t%s\n' "$bf"
    printf 'backing_ino\t%s\n'  "$bi"
    printf 'backing_dev\t%s\n'  "$bd"
    printf 'prev-sha256\t%s\n'  "$(g6_record_sha PREPARED)"
  } | g6_publish_record ATTACHED || { g6_blocked "ATTACHED publication failed"; return 2; }
  g6_say "ATTACHED $G6_LOOP_DEV backing $bf (ino $bi, dev $bd)"
}

g6_format() {
  g6_require_env || return $?
  g6_has_record ATTACHED || { g6_blocked "cannot format before ATTACHED"; return 2; }
  g6_has_record FORMATTED && { g6_blocked "FORMATTED is already published"; return 2; }
  g6_chain_ok_before format || return 2

  # The geometry is the CONTOUR's, not a constant. A calibration image of one gigabyte formatted
  # for two and a half million inodes is not a one-hundredth of anything.
  "$G6_MKFS" -b "$G6_BLOCK_SIZE" -N "$G6_REQUESTED_INODES" -m 0 -U "$G6_UUID" "$G6_LOOP_DEV" \
    || { g6_die "mkfs refused"; return 1; }

  local seen; seen="$("$G6_BLKID" -s UUID -o value "$G6_LOOP_DEV" 2>/dev/null || true)"
  if [ "$seen" != "$G6_UUID" ]; then
    g6_blocked "the filesystem on $G6_LOOP_DEV reports UUID '$seen', not '$G6_UUID'"
    return 2
  fi
  # What mkfs was ASKED for and what is now on the device are two different facts, and the second
  # one is the only one that matters afterwards.
  local seen_type; seen_type="$("$G6_BLKID" -s TYPE -o value "$G6_LOOP_DEV" 2>/dev/null || true)"
  if [ "$seen_type" != ext4 ]; then
    g6_blocked "the filesystem on $G6_LOOP_DEV is '$seen_type', not the ext4 that was formatted"
    return 2
  fi
  local facts bs ic
  facts="$(g6_fs_facts)"
  bs="$(printf '%s' "$facts" | awk '{print $1}')"
  ic="$(printf '%s' "$facts" | awk '{print $2}')"
  case "$bs" in ''|*[!0-9]*) g6_blocked "the filesystem reports no block size — the fact is \
unavailable on this host and must be settled by the preflight"; return 2 ;; esac
  case "$ic" in ''|*[!0-9]*) g6_blocked "the filesystem reports no inode count"; return 2 ;; esac
  [ "$bs" = 4096 ] || { g6_blocked "block size is $bs, the frozen value is 4096"; return 2; }
  # An inode table is fixed at mkfs time and never grows. A filesystem that came out with fewer
  # inodes than the run needs is a filesystem the run cannot finish on, and finding that out at
  # file 2 200 000 is finding it out after eight hours.
  if [ -n "$G6_MIN_INODES" ] && [ "$G6_MIN_INODES" != 0 ]; then
    [ "$ic" -ge "$G6_MIN_INODES" ] \
      || { g6_blocked "the filesystem has $ic inodes, the run needs $G6_MIN_INODES"; return 2; }
  fi
  {
    printf 'uuid\t%s\n'        "$G6_UUID"
    printf 'block_size\t%s\n'  "$bs"
    printf 'inode_count\t%s\n' "$ic"
    printf 'devno\t%s\n'       "$(g6_kernel_devno)"
    printf 'prev-sha256\t%s\n' "$(g6_record_sha ATTACHED)"
  } | g6_publish_record FORMATTED \
    || { g6_blocked "FORMATTED publication failed"; return 2; }
  g6_say "FORMATTED $G6_LOOP_DEV uuid=$G6_UUID block=$bs inodes=$ic"
}

g6_mount() {
  g6_require_env || return $?
  g6_has_record FORMATTED || { g6_blocked "cannot mount before FORMATTED"; return 2; }
  g6_has_record MOUNTED && { g6_blocked "MOUNTED is already published"; return 2; }
  g6_chain_ok_before mount || return 2

  mkdir -p "$G6_MOUNTPOINT" || { g6_die "cannot create the mountpoint"; return 1; }
  g6_contained "$G6_MOUNTPOINT" || return 1
  "$G6_MOUNT" "$G6_LOOP_DEV" "$G6_MOUNTPOINT" || { g6_die "mount refused"; return 1; }

  local fields majmin fstype source
  fields="$(g6_mountinfo_for_target "$G6_MOUNTPOINT")"
  [ -n "$fields" ] || { g6_blocked "mountinfo shows nothing at '$G6_MOUNTPOINT'"; return 2; }
  majmin="$(printf '%s' "$fields" | awk '{print $1}')"
  fstype="$(printf '%s' "$fields" | awk '{print $2}')"
  source="$(printf '%s' "$fields" | awk '{print $3}')"
  if [ "$source" != "$G6_LOOP_DEV" ]; then
    g6_blocked "'$G6_MOUNTPOINT' is mounted from '$source', not $G6_LOOP_DEV"
    return 2
  fi
  # What is recorded must also be what was ASKED for. Recording whatever mountinfo happens to say
  # makes the record agree with the machine by construction and proves nothing: an ext4 image
  # that came back mounted as something else, or under a device number that is not the loop's, is
  # a different filesystem wearing our mountpoint.
  if [ "$fstype" != ext4 ]; then
    g6_blocked "'$G6_MOUNTPOINT' carries fstype '$fstype', not the ext4 that was formatted"
    return 2
  fi
  local kdevno; kdevno="$(g6_kernel_devno)"
  if [ -n "$kdevno" ] && [ "$majmin" != "$kdevno" ]; then
    g6_blocked "'$G6_MOUNTPOINT' reports device number '$majmin', but $G6_LOOP_DEV is '$kdevno'"
    return 2
  fi
  {
    printf 'source\t%s\n' "$source"
    printf 'target\t%s\n' "$G6_MOUNTPOINT"
    printf 'devno\t%s\n'  "$majmin"
    printf 'fstype\t%s\n' "$fstype"
    printf 'prev-sha256\t%s\n' "$(g6_record_sha FORMATTED)"
  } | g6_publish_record MOUNTED || { g6_blocked "MOUNTED publication failed"; return 2; }
  g6_say "MOUNTED $source at $G6_MOUNTPOINT ($fstype, $majmin)"
}

# ------------------------------------------------------------------ verification

# Two scopes, one body.
#
#   strict  every published record must describe the machine RIGHT NOW. This is what a step is
#           allowed to build on, and what `verify` answers.
#   live    a published record is checked only where its resource is still live. This is what
#           teardown may rely on, because teardown is the one operation that can legitimately be
#           re-entered halfway: an interrupted teardown leaves MOUNTED published with nothing
#           mounted, and demanding the mount back would strand the run forever with a record it
#           can never satisfy. A resource that is gone is a step already done, not a mismatch —
#           but a resource that is still live must still match, exactly as before.
g6_verify_chain() {  # [strict|live]
  g6_require_env || return $?
  local scope="${1:-strict}" rc=0 want got r
  local live_image=0 live_attach=0 live_mount=0
  [ -e "$G6_IMAGE" ] && live_image=1
  [ -n "$(g6_kernel_backing_file)" ] && live_attach=1
  g6_has_record MOUNTED && [ -n "$(g6_mountinfo_for_target "$(g6_record_field MOUNTED target)")" ] \
    && live_mount=1

  # The links first: a record that no longer points at the one before it turns four facts back
  # into four unrelated files, and nothing below is worth checking until that holds.
  for r in PREPARED ATTACHED FORMATTED MOUNTED TORNDOWN; do
    g6_has_record "$r" || continue
    g6_check_crosslink "$r" || rc=2
  done

  if g6_has_record PREPARED && { [ "$scope" = strict ] || [ "$live_image" = 1 ]; }; then
    want="$(g6_record_field PREPARED image)"
    [ "$want" = "$G6_IMAGE" ] || { g6_blocked "PREPARED names image '$want'"; rc=2; }
    # An absent image is not a missing measurement, it is a missing image. Skipping the
    # comparison because stat had nothing to say turned the strongest signal there is —
    # the file the whole chain is about is gone — into silence.
    if [ "$live_image" = 0 ]; then
      g6_blocked "the recorded image '$G6_IMAGE' is gone"; rc=2
    fi
    want="$(g6_record_field PREPARED devino)"; got="$(g6_stat_devino "$G6_IMAGE")"
    if [ -n "$got" ] && [ "$want" != "$got" ]; then
      g6_blocked "the image's dev:ino is $got, recorded $want"; rc=2
    fi
    # Size is part of the recorded identity, so it is part of the check: a file removed and
    # recreated commonly gets the very same inode number back, and dev:ino alone then reports a
    # match that is not one.
    want="$(g6_record_field PREPARED size)"; got="$(g6_stat_size "$G6_IMAGE")"
    if [ -n "$got" ] && [ "$want" != "$got" ]; then
      g6_blocked "the image's size is $got bytes, recorded $want"; rc=2
    fi
  fi

  if g6_has_record ATTACHED && { [ "$scope" = strict ] || [ "$live_attach" = 1 ]; }; then
    local fields bi bd
    want="$(g6_record_field ATTACHED backing_file)"; got="$(g6_kernel_backing_file)"
    [ "$want" = "$got" ] || { g6_blocked "kernel backs '$got', recorded '$want'"; rc=2; }
    want="$(g6_record_field ATTACHED devno)"; got="$(g6_kernel_devno)"
    [ "$want" = "$got" ] || { g6_blocked "loop devno is '$got', recorded '$want'"; rc=2; }
    fields="$(g6_losetup_fields)"
    bi="$(printf '%s' "$fields" | awk '{print $1}')"
    bd="$(printf '%s' "$fields" | awk '{print $2}')"
    want="$(g6_record_field ATTACHED backing_ino)"
    [ "$want" = "$bi" ] || { g6_blocked "backing inode is '$bi', recorded '$want'"; rc=2; }
    want="$(g6_record_field ATTACHED backing_dev)"
    [ "$want" = "$bd" ] || { g6_blocked "backing device is '$bd', recorded '$want'"; rc=2; }
  fi

  if g6_has_record FORMATTED && { [ "$scope" = strict ] || [ "$live_attach" = 1 ]; }; then
    local facts
    want="$(g6_record_field FORMATTED uuid)"
    got="$("$G6_BLKID" -s UUID -o value "$G6_LOOP_DEV" 2>/dev/null || true)"
    [ "$want" = "$got" ] || { g6_blocked "filesystem UUID is '$got', recorded '$want'"; rc=2; }
    facts="$(g6_fs_facts)"
    want="$(g6_record_field FORMATTED block_size)"
    got="$(printf '%s' "$facts" | awk '{print $1}')"
    [ "$want" = "$got" ] || { g6_blocked "block size is '$got', recorded '$want'"; rc=2; }
    want="$(g6_record_field FORMATTED inode_count)"
    got="$(printf '%s' "$facts" | awk '{print $2}')"
    [ "$want" = "$got" ] || { g6_blocked "inode count is '$got', recorded '$want'"; rc=2; }
    want="$(g6_record_field FORMATTED devno)"; got="$(g6_kernel_devno)"
    [ "$want" = "$got" ] || { g6_blocked "loop devno is '$got', recorded '$want'"; rc=2; }
  fi

  if g6_has_record MOUNTED && { [ "$scope" = strict ] || [ "$live_mount" = 1 ]; }; then
    local fields majmin fstype source
    fields="$(g6_mountinfo_for_target "$(g6_record_field MOUNTED target)")"
    if [ -z "$fields" ]; then
      g6_blocked "nothing is mounted at the recorded target"; rc=2
    else
      majmin="$(printf '%s' "$fields" | awk '{print $1}')"
      fstype="$(printf '%s' "$fields" | awk '{print $2}')"
      source="$(printf '%s' "$fields" | awk '{print $3}')"
      [ "$source" = "$(g6_record_field MOUNTED source)" ] \
        || { g6_blocked "mount source is '$source'"; rc=2; }
      [ "$majmin" = "$(g6_record_field MOUNTED devno)" ] \
        || { g6_blocked "mount devno is '$majmin'"; rc=2; }
      [ "$fstype" = "$(g6_record_field MOUNTED fstype)" ] \
        || { g6_blocked "mount fstype is '$fstype'"; rc=2; }
    fi
  fi

  [ "$rc" = 0 ] && g6_say "chain verified"
  return "$rc"
}

# ------------------------------------------------------------------ inventory

# What a human is asked to look at when the chain cannot be confirmed. Printed, never acted on.
g6_inventory() {
  printf 'INVENTORY:\n'
  printf '  assigned loop device : %s\n' "$G6_LOOP_DEV"
  printf '  kernel backing file  : %s\n' "$(g6_kernel_backing_file)"
  printf '  losetup fields       : %s\n' "$(g6_losetup_fields)"
  printf '  image path           : %s\n' "$G6_IMAGE"
  printf '  image present        : %s\n' "$( [ -e "$G6_IMAGE" ] && echo yes || echo no )"
  printf '  image dev:ino / size : %s / %s\n' \
    "$(g6_stat_devino "$G6_IMAGE")" "$(g6_stat_size "$G6_IMAGE")"
  printf '  mountpoint           : %s\n' "$G6_MOUNTPOINT"
  printf '  mountinfo at target  : %s\n' "$(g6_mountinfo_for_target "$G6_MOUNTPOINT")"
  local r
  for r in PREPARED ATTACHED FORMATTED MOUNTED; do
    printf '  record %-10s    : %s\n' "$r" "$( g6_has_record "$r" && echo published || echo absent )"
  done
}

# ------------------------------------------------------------------ teardown

# Nothing is removed on a chain that is not confirmed. A missing record does not license the
# step below it, and a present-but-unconfirmed attach or mount is BLOCKED with the inventory —
# an unpublished action is a publication failure, and the remedy for that is a human looking at
# the machine, not the harness deciding on its own that the object is probably its own.
g6_teardown() {
  g6_require_env || return $?

  local fields source live_mount live_attach
  fields="$(g6_mountinfo_for_target "$G6_MOUNTPOINT")"
  live_mount=0; [ -n "$fields" ] && live_mount=1
  live_attach=0; [ -n "$(g6_kernel_backing_file)" ] && live_attach=1

  # Re-entry after a completed teardown. The four chain records describe what WAS true, so
  # verifying them against a machine they no longer describe would block forever; the durable
  # TORNDOWN record is what says the chain is history. If anything is live again, that is not a
  # repeat run — something came back, and it is BLOCKED.
  if g6_has_record TORNDOWN; then
    # Present is not the same as valid. A TORNDOWN that does not verify against its own seal, or
    # that no longer links back to the MOUNTED it claims to close, is not a statement that this
    # chain is history — it is a file somebody left in the state directory.
    g6_record_intact TORNDOWN \
      || { g6_blocked "TORNDOWN is present but does not verify against its own seal"; return 2; }
    g6_check_crosslink TORNDOWN \
      || { g6_blocked "TORNDOWN does not link back to the mount it claims to have closed"; return 2; }
    if [ "$live_mount" = 1 ] || [ "$live_attach" = 1 ] || [ -e "$G6_IMAGE" ]; then
      g6_inventory >&2
      g6_blocked "TORNDOWN is published but the resources are present again"
      return 2
    fi
    g6_say "already torn down"
    return 0
  fi

  if [ "$live_mount" = 1 ] && ! g6_has_record MOUNTED; then
    g6_inventory >&2
    g6_blocked "'$G6_MOUNTPOINT' is mounted but MOUNTED was never published — unconfirmed, \
nothing unmounted and nothing removed"
    return 2
  fi
  if [ "$live_attach" = 1 ] && ! g6_has_record ATTACHED; then
    g6_inventory >&2
    g6_blocked "$G6_LOOP_DEV carries a backing file but ATTACHED was never published — \
unconfirmed, nothing detached and nothing removed"
    return 2
  fi

  # Whatever IS published and still LIVE must agree with the machine before a single removal. The
  # live scope is what makes an interrupted teardown finishable: the steps that already happened
  # are history, and the ones that have not must still be exactly what was recorded.
  if ! g6_verify_chain live >/dev/null; then
    g6_inventory >&2
    g6_blocked "the published chain does not match the machine — nothing removed"
    return 2
  fi

  if [ "$live_mount" = 1 ]; then
    source="$(printf '%s' "$fields" | awk '{print $3}')"
    if [ "$source" != "$G6_LOOP_DEV" ]; then
      g6_inventory >&2
      g6_blocked "'$G6_MOUNTPOINT' is mounted from '$source', which is not ours"
      return 2
    fi
    g6_contained "$G6_MOUNTPOINT" || { g6_inventory >&2; return 1; }
    "$G6_UMOUNT" "$G6_MOUNTPOINT" || { g6_inventory >&2; g6_blocked "umount refused"; return 2; }
    if [ -n "$(g6_mountinfo_for_target "$G6_MOUNTPOINT")" ]; then
      g6_inventory >&2; g6_blocked "still mounted after umount"; return 2
    fi
    g6_say "unmounted $G6_MOUNTPOINT"
  fi

  if [ "$live_attach" = 1 ]; then
    local backing; backing="$(g6_kernel_backing_file)"
    if [ "$backing" != "$G6_IMAGE" ]; then
      g6_inventory >&2
      g6_blocked "$G6_LOOP_DEV backs '$backing', not ours"
      return 2
    fi
    "$G6_LOSETUP" -d "$G6_LOOP_DEV" \
      || { g6_inventory >&2; g6_blocked "losetup -d refused"; return 2; }
    if [ -n "$(g6_kernel_backing_file)" ]; then
      g6_inventory >&2; g6_blocked "$G6_LOOP_DEV still reports a backing file after detach"
      return 2
    fi
    g6_say "detached $G6_LOOP_DEV"
  fi

  if [ -e "$G6_IMAGE" ]; then
    g6_has_record PREPARED || {
      g6_inventory >&2
      g6_blocked "the image exists but PREPARED was never published — unconfirmed, not removed"
      return 2; }
    if [ -n "$(g6_kernel_backing_file)" ]; then
      g6_inventory >&2
      g6_blocked "$G6_LOOP_DEV is not proven free — refusing to unlink the image"
      return 2
    fi
    g6_contained "$G6_IMAGE" || { g6_inventory >&2; return 1; }
    rm -f -- "$G6_IMAGE" || { g6_inventory >&2; g6_blocked "cannot remove the image"; return 2; }
    if [ -e "$G6_IMAGE" ]; then
      g6_inventory >&2; g6_blocked "'$G6_IMAGE' is still present after removal"; return 2
    fi
    g6_say "removed $G6_IMAGE"
  fi

  # The two directories this lifecycle created are removed, and a refusal to remove one is kept
  # rather than swallowed: `|| true` on an rmdir is how a teardown reports complete over a tree
  # that still has something in it.
  local undeleted=""
  if [ -d "$G6_MOUNTPOINT" ]; then
    rmdir "$G6_MOUNTPOINT" 2>/dev/null || undeleted="$undeleted $G6_MOUNTPOINT"
  fi
  if [ -d "$(dirname "$G6_IMAGE")" ]; then
    rmdir "$(dirname "$G6_IMAGE")" 2>/dev/null || undeleted="$undeleted $(dirname "$G6_IMAGE")"
  fi

  # Residue is a hard failure, never a warning, and it is checked before the word "complete" is
  # allowed to appear at all.
  local residue=""
  [ -e "$G6_IMAGE" ] && residue="$residue $G6_IMAGE"
  [ -n "$(g6_kernel_backing_file)" ] && residue="$residue $G6_LOOP_DEV"
  [ -n "$(g6_mountinfo_for_target "$G6_MOUNTPOINT")" ] && residue="$residue $G6_MOUNTPOINT"
  if [ -n "$residue" ]; then
    g6_inventory >&2
    g6_blocked "residue remains after teardown:$residue"
    return 2
  fi
  # A directory is residue too. The image directory belongs to this lifecycle and to nothing
  # else, so anything that keeps it alive after the image is gone is something we did not put
  # there and did not expect — and `rmdir || true` swallowing that was the whole problem: the
  # teardown reported complete while the tree still carried state nobody accounted for.
  if [ -n "$undeleted" ]; then
    g6_inventory >&2
    g6_blocked "directory residue remains after teardown:$undeleted — rmdir refused, so something \
other than what this lifecycle created is still in there"
    return 2
  fi
  # Only now, with the absence proved by re-reading, may the completion be recorded at all.
  {
    printf 'image\t%s\n'    "$G6_IMAGE"
    printf 'loop_dev\t%s\n' "$G6_LOOP_DEV"
    printf 'target\t%s\n'   "$G6_MOUNTPOINT"
    printf 'prev-sha256\t%s\n' "$(g6_record_sha MOUNTED)"
  } | g6_publish_record TORNDOWN || { g6_blocked "TORNDOWN publication failed"; return 2; }
  g6_say "teardown complete"
  return 0
}

# ------------------------------------------------------------------ dispatch

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    prepare)   g6_prepare ;;
    attach)    g6_attach ;;
    format)    g6_format ;;
    mount)     g6_mount ;;
    verify)    g6_verify_chain ;;
    resume)    g6_resume ;;
    inventory) g6_inventory ;;
    teardown)  g6_teardown ;;
    *) printf 'usage: %s prepare|attach|format|mount|verify|resume|inventory|teardown\n' "$0" >&2
       exit 1 ;;
  esac
  exit $?
fi
