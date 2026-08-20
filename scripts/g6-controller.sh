#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# G6 controller: one route, one terminalizer, three exit codes.
#
#   PASS = 0    FAIL = 1    BLOCKED = 2
#
# There are two kinds of exit, and conflating them was a lie worth removing.
#
#   PRESTART   the run has not begun. G6_WORK is unusable, the contour is wrong, or this evidence
#              directory already belongs to another run. Nothing has been touched and nothing
#              will be; there is no terminal record because there is no run to record. These
#              exits print REFUSED or BLOCKED and leave, and the suite proves that they leave
#              NOTHING behind — no state, no record, no image.
#   STARTED    the run announced itself durably (BEGIN, state RUNNING) and is from that moment
#              accountable. EVERY exit after that point — including a signal — goes through
#              terminalize(), because a run that ended without saying how it ended is a run whose
#              result somebody will later have to guess.
#
# The boundary is `begin_run`. Before it, refusals; after it, verdicts.
#
# A run killed between BEGIN and the terminal record leaves RUNNING behind on purpose. `route`
# refuses to start over one of those — it is not a fresh directory — and it stops with the
# inventory instead. What happens next is a human decision: there is no subcommand that starts
# the candidate again over the evidence of a run that did not finish.
#
# Order, and it is fail-fast at every step:
#
#   contour -> tools -> sealed sanction -> calibration sealed BY it -> candidate SHA
#   -> bundle SHA and load path -> frozen resource plan -> lifecycle -> real capacity
#   -> generation -> guarded production scan -> provenance receipt -> independent verifier
#   -> S1..S4 -> terminal record
#
# Teardown is deliberately outside the route: a pipeline that cleans up on its way out destroys
# the evidence of its own failure.
#
# Classification is per step, not blanket. Tooling, environment and publication trouble is
# BLOCKED. The candidate producing a wrong answer — a scan that fails on valid input, counts
# that disagree with the derived formulas, a postcondition contradicted — is FAIL.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
G6_PUBLISH="${G6_PUBLISH:-$HERE/g6-publish-record.py}"
G6_IMAGE_LIB="${G6_IMAGE_LIB:-$HERE/g6-image-lib.sh}"
G6_MAKE_FIXTURE="${G6_MAKE_FIXTURE:-$HERE/g6-make-fixture.sh}"
G6_VERIFY_COUNTS="${G6_VERIFY_COUNTS:-$HERE/g6-verify-counts.py}"
G6_OBSERVE="${G6_OBSERVE:-$HERE/g6-observe-destination.py}"

BUNDLE_FILES="g6-controller.sh g6-image-lib.sh g6-make-fixture.sh g6-publish-record.py \
g6-verify-counts.py g6-observe-destination.py"

G6_SANCTION="${G6_SANCTION:-}"
G6_CALIBRATION="${G6_CALIBRATION:-}"
G6_RESOURCE_PLAN="${G6_RESOURCE_PLAN:-}"
G6_BIN="${G6_BIN:-}"
G6_CONTOUR="${G6_CONTOUR:-}"
G6_REMOTE_ROOT="${G6_REMOTE_ROOT:-}"
G6_IMAGE="${G6_IMAGE:-}"
G6_LOOP_DEV="${G6_LOOP_DEV:-}"
G6_UUID="${G6_UUID:-}"
G6_STATE_DIR="${G6_STATE_DIR:-}"
G6_FIXTURE_ROOT="${G6_FIXTURE_ROOT:-}"
G6_IMAGE_SIZE="${G6_IMAGE_SIZE:-}"
G6_WORK="${G6_WORK:-}"

# Which of the frozen numbers were handed in by the ENVIRONMENT. Captured before the defaults are
# applied, because afterwards there is no way to tell a default from an override — and an
# override that quietly disagrees with the sealed plan is how a run ends up measuring itself
# against a margin nobody signed.
G6_ENV_PINS=""
for _v in G6_IMAGE_BYTES G6_EXTERNAL_REQUIREMENT G6_INODE_NEED G6_INODE_RESERVE \
          G6_INTERNAL_BYTE_NEED G6_INTERNAL_BYTE_RESERVE G6_BATCH G6_BLOCK_SIZE \
          G6_REQUESTED_INODES; do
  eval "[ -n \"\${$_v+set}\" ]" && G6_ENV_PINS="$G6_ENV_PINS $_v"
done
unset _v

# Defaults only. Every one of these is replaced by the sealed plan's value before it is used.
G6_IMAGE_BYTES="${G6_IMAGE_BYTES:-17179869184}"
G6_EXTERNAL_REQUIREMENT="${G6_EXTERNAL_REQUIREMENT:-51539607552}"
G6_INODE_NEED="${G6_INODE_NEED:-2265900}"
G6_INODE_RESERVE="${G6_INODE_RESERVE:-226590}"
G6_INTERNAL_BYTE_NEED="${G6_INTERNAL_BYTE_NEED:-9011200000}"
G6_INTERNAL_BYTE_RESERVE="${G6_INTERNAL_BYTE_RESERVE:-1717986918}"
G6_BATCH="${G6_BATCH:-10000}"
G6_BLOCK_SIZE="${G6_BLOCK_SIZE:-4096}"
G6_REQUESTED_INODES="${G6_REQUESTED_INODES:-2500000}"
G6_EVIDENCE_DIR="${G6_EVIDENCE_DIR:-}"
G6_HOST_ID="${G6_HOST_ID:-}"

G6_DF="${G6_DF:-df}"
G6_TIME="${G6_TIME:-/usr/bin/time}"
# The watchdog is detached with this, so its absence is a preflight question like any
# other tool the delivery depends on — not something discovered when a guard is needed.
G6_SETSID="${G6_SETSID:-setsid}"
G6_LOSETUP="${G6_LOSETUP:-losetup}"
G6_MKFS="${G6_MKFS:-mkfs.ext4}"
G6_MOUNT="${G6_MOUNT:-mount}"
G6_UMOUNT="${G6_UMOUNT:-umount}"
G6_BLKID="${G6_BLKID:-blkid}"
G6_DUMPE2FS="${G6_DUMPE2FS:-dumpe2fs}"
G6_GRACE="${G6_GRACE:-3}"
G6_REAP_LIMIT="${G6_REAP_LIMIT:-10}"
G6_SCAN_GUARD="${G6_SCAN_GUARD:-600}"
G6_NOW="${G6_NOW:-}"

LIVE_G=645000; LIVE_M=2; LIVE_U=910000; LIVE_B=4096; LIVE_SEED="g6-fixture-v1"

MODE=""
RC_PASS=0; RC_FAIL=1; RC_BLOCKED=2

# Set to 1 the instant the run is allowed to change anything. Everything before that point must
# leave the machine exactly as it found it.
G6_MUTATED=0
G6_STOPPED_AT=""

# Before the first mutation nothing of ours may exist. A refusal that still left an image, a
# record or a mountpoint behind was not a free refusal, and the terminal record says so instead
# of reporting a tidy BLOCKED over a dirty tree.
zero_write_state() {
  if [ "$G6_MUTATED" = 1 ]; then printf 'not-applicable'; return; fi
  local leftovers="" r
  [ -n "$G6_IMAGE" ] && [ -e "$G6_IMAGE" ] && leftovers="$leftovers image"
  [ -n "$G6_FIXTURE_ROOT" ] && [ -e "$G6_FIXTURE_ROOT" ] && leftovers="$leftovers mountpoint"
  for r in PREPARED ATTACHED FORMATTED MOUNTED TORNDOWN; do
    [ -n "$G6_STATE_DIR" ] && [ -e "$G6_STATE_DIR/$r" ] && leftovers="$leftovers $r"
  done
  [ -z "$leftovers" ] && printf 'proved' || printf 'VIOLATED:%s' "$leftovers"
}

say()     { printf 'g6ctl[%s]: %s\n' "${MODE:-?}" "$1"; }
sha_of()  { sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1; }

# ------------------------------------------------------------------ terminalizer

# The single exit of the route. Publishes the terminal record, then leaves with the code that
# belongs to the verdict. Publication trouble can only make a verdict worse, never better.
terminalize() {  # verdict reason
  local verdict="$1" reason="$2" code zw
  zw="$(zero_write_state)"
  case "$zw" in
    VIOLATED:*)
      # A run that refused early and still left something behind cannot report a clean outcome.
      verdict=BLOCKED
      reason="$reason; zero-write violated ($zw)" ;;
  esac
  case "$verdict" in
    PASS)    code=$RC_PASS ;;
    FAIL)    code=$RC_FAIL ;;
    BLOCKED) code=$RC_BLOCKED ;;
    *)       verdict=BLOCKED; code=$RC_BLOCKED; reason="unclassified outcome: $reason" ;;
  esac

  if [ -n "$G6_WORK" ] && [ -d "$G6_WORK" ]; then
    {
      printf 'mode\t%s\n'     "$MODE"
      printf 'contour\t%s\n'  "${G6_CONTOUR:-unset}"
      printf 'verdict\t%s\n'  "$verdict"
      printf 'code\t%s\n'     "$code"
      printf 'reason\t%s\n'   "$reason"
      printf 'zero-write\t%s\n' "$zw"
      printf 'stopped-at\t%s\n' "${G6_STOPPED_AT:-none}"
      printf 'scenarios-ran\t%s\n' "$(scenarios_ran "$G6_WORK/scenarios")"
      printf 'postconditions-met\t%s\n' "$(postconditions_met "$G6_WORK/scenarios")"
      printf 'bundle-sha256\t%s\n' "$(bundle_sha)"
      [ -n "$G6_BIN" ] && printf 'candidate-sha256\t%s\n' "$(sha_of "$G6_BIN")"
      [ -n "$G6_CALIBRATION" ] && printf 'calibration-sha256\t%s\n' "$(sha_of "$G6_CALIBRATION")"
      [ -n "$G6_RESOURCE_PLAN" ] && printf 'resource-plan-sha256\t%s\n' "$(sha_of "$G6_RESOURCE_PLAN")"
      cat "$G6_WORK"/scenarios/*.meta 2>/dev/null
    } > "$G6_WORK/terminal.body"

    if ! "$G6_PUBLISH" --dir "$G6_WORK" --name TERMINAL \
           --state-file "$G6_WORK/PUBSTATE" --code "$code" \
           < "$G6_WORK/terminal.body" >"$G6_WORK/publish.out" 2>&1; then
      cat "$G6_WORK/publish.out" >&2
      if [ "$verdict" = PASS ]; then
        printf 'BLOCKED: a PASS nobody recorded is BLOCKED\n' >&2
        printf 'VERDICT\tBLOCKED\n'
        exit $RC_BLOCKED
      fi
      printf 'BLOCKED: the terminal record could not be published; the %s stands\n' "$verdict" >&2
      printf 'VERDICT\t%s\n' "$verdict"
      exit $RC_BLOCKED
    fi
  else
    printf 'BLOCKED: no evidence directory, so no terminal record could be written\n' >&2
    printf 'VERDICT\tBLOCKED\n'
    exit $RC_BLOCKED
  fi

  [ "$verdict" = PASS ] || printf '%s: %s\n' "$verdict" "$reason" >&2
  printf 'VERDICT\t%s\n' "$verdict"

  # A run cut short by a signal proved nothing about the candidate, so the VERDICT is BLOCKED and
  # the record says so. The exit STATUS is a different question: whatever sent the signal reads
  # the wait status, and §5 of the runbook puts TERM=143 and INT=130 first in its exit precedence.
  # Reporting 2 there would make the harness disagree with its own document about what happened,
  # and would hide a signal behind the code that means "environment". The record is written
  # first; only then does this process die of the signal it was sent.
  if [ -n "${G6_RAW_SIGNAL:-}" ]; then
    trap - "$G6_RAW_SIGNAL"
    kill -"$G6_RAW_SIGNAL" $$
  fi
  exit "$code"
}

# A refusal taken before the run announces itself. It never publishes, because there is nothing
# to publish about: no record, no state, no evidence directory. The zero-write check is quoted
# here rather than asserted in prose — a refusal that says "nothing was touched" while something
# was is worse than no refusal at all.
prestart_refusal() {  # reason
  local zw; zw="$(zero_write_state)"
  printf 'REFUSED: %s; nothing was touched (%s)\n' "$1" "$zw" >&2
  printf 'VERDICT\tBLOCKED\n'
  exit $RC_BLOCKED
}

# Outside the route these two just report; inside, everything funnels into terminalize.
refused() { printf 'REFUSED: %s\n' "$1" >&2; return 1; }
blocked() { printf 'BLOCKED: %s\n' "$1" >&2; return 2; }

# ------------------------------------------------------------------ contour

# The earliest refusal there is, and it comes before the sanctions on purpose: if the contour is
# wrong, reading somebody's signed sanction is already the wrong thing to be doing.
verify_contour() {
  case "$G6_CONTOUR" in
    local|host) ;;
    '') refused "G6_CONTOUR is not set: say local or host, there is no default"; return 1 ;;
    *) refused "G6_CONTOUR='$G6_CONTOUR' is neither local nor host"; return 1 ;;
  esac
  if [ "$MODE" = live ] && [ "$G6_CONTOUR" != host ]; then
    refused "live runs only in the host contour"; return 1
  fi
  if [ "$MODE" = rehearsal ] && [ "$G6_CONTOUR" != local ]; then
    refused "rehearsal runs only in the local contour"; return 1
  fi
  if [ "$G6_CONTOUR" = local ]; then
    # A local contour that reaches a real privileged binary is not a local contour. Resolve each
    # one and refuse the system paths outright, before a single command is issued.
    local t r
    for t in "$G6_LOSETUP" "$G6_MKFS" "$G6_MOUNT" "$G6_UMOUNT"; do
      r="$(command -v "$t" 2>/dev/null)" || r=""
      case "$r" in
        /sbin/*|/usr/sbin/*|/bin/*|/usr/bin/*)
          refused "the local contour resolves '$t' to the real '$r' — a rehearsal never reaches \
the privileged tools"; return 1 ;;
      esac
    done
  fi
  say "contour verified: $G6_CONTOUR"
}

# ------------------------------------------------------------------ bundle

bundle_manifest() {
  local f
  printf 'bundle-dir\t%s\n' "$HERE"
  for f in $BUNDLE_FILES; do
    [ -r "$HERE/$f" ] || { printf 'bundle-missing\t%s\n' "$f"; continue; }
    printf 'bundle-file\t%s\t%s\n' "$f" "$(sha_of "$HERE/$f")"
  done
}
bundle_sha() { bundle_manifest | grep -v '^bundle-dir	' | sha256sum | cut -d' ' -f1; }

# ------------------------------------------------------------------ sealed inputs

sanction_field()    { awk -F'\t' -v k="$1" '$1 == k { print $2 }' "$G6_SANCTION"; }
calibration_field() { awk -F'\t' -v k="$1" '$1 == k { print $2 }' "$G6_CALIBRATION"; }
plan_field()        { awk -F'\t' -v k="$1" '$1 == k { print $2 }' "$G6_RESOURCE_PLAN"; }

# The half of the sanction that authorises WORK AT ALL: who signed it, for which mode, in which
# contour, over which root, at which scale, inside which window. Calibration needs exactly this
# half and cannot need the other one — the seals include the digest of the calibration manifest,
# which is the very file calibration is about to produce.
SANCTION_CORE="mode contour host remote-root scale-G scale-M scale-U scale-B scale-seed \
window-open window-close signed-by"
# The other half: every resource the run may touch, pinned HERE, in the human-signed document,
# not only in the plan the document seals. A sanction that names the pool but not the mountpoint
# has not agreed to the mountpoint.
SANCTION_SEALS="candidate-sha256 bundle-sha256 calibration-sha256 resource-plan-sha256 \
image loop-device uuid mountpoint state-dir work-dir image-size"

# Which machine this actually is.
#
# In LIVE there is no override at all: an environment variable that can rename the host is an
# environment variable that can point a live run at somebody else's machine and have every
# subsequent check agree with it. The rehearsal contour may name itself, because a rehearsal is
# allowed to pretend — and it says so out loud rather than through the same variable a live run
# would read.
host_identity() {
  if [ "$MODE" = live ]; then
    hostname 2>/dev/null
  else
    printf '%s' "${G6_HOST_ID:-$(hostname 2>/dev/null)}"
  fi
}

verify_sanction_core() {
  [ -n "$G6_SANCTION" ] || { refused "G6_SANCTION is not set"; return 1; }
  [ -r "$G6_SANCTION" ] || { refused "load sanction '$G6_SANCTION' is unreadable"; return 1; }
  head -n 1 "$G6_SANCTION" | grep -qx 'G6 LOAD SANCTION' \
    || { refused "'$G6_SANCTION' is not a G6 load sanction"; return 1; }
  local k
  for k in $SANCTION_CORE; do
    [ -n "$(sanction_field "$k")" ] || { refused "the sanction pins no '$k'"; return 1; }
  done
  [ "$(sanction_field mode)" = "$MODE" ] \
    || { refused "the sanction is for mode '$(sanction_field mode)', not '$MODE'"; return 1; }
  [ "$(sanction_field contour)" = "$G6_CONTOUR" ] \
    || { refused "the sanction is for contour '$(sanction_field contour)', not '$G6_CONTOUR'"; return 1; }
  [ "$(sanction_field remote-root)" = "$G6_REMOTE_ROOT" ] \
    || { refused "the sanction is for root '$(sanction_field remote-root)', not '$G6_REMOTE_ROOT'"
         return 1; }

  local now open close
  now="${G6_NOW:-$(date -u +%s)}"
  open="$(sanction_field window-open)"; close="$(sanction_field window-close)"
  case "$now$open$close" in *[!0-9]*) refused "the window is not numeric"; return 1 ;; esac
  if [ "$now" -lt "$open" ] || [ "$now" -gt "$close" ]; then
    refused "the load window is not open: now=$now, window is [$open, $close]"; return 1
  fi
  if [ "$MODE" = live ]; then
    local pair name want
    for pair in "scale-G:$LIVE_G" "scale-M:$LIVE_M" "scale-U:$LIVE_U" "scale-B:$LIVE_B" \
                "scale-seed:$LIVE_SEED"; do
      name="${pair%%:*}"; want="${pair#*:}"
      [ "$(sanction_field "$name")" = "$want" ] \
        || { refused "live sanction pins $name='$(sanction_field "$name")', frozen is '$want'"
             return 1; }
    done
  fi
  return 0
}

verify_sanction() {
  verify_sanction_core || return 1
  local k
  for k in $SANCTION_SEALS; do
    [ -n "$(sanction_field "$k")" ] || { refused "the sanction pins no '$k'"; return 1; }
  done
  say "sanction verified: host=$(sanction_field host) signed-by=$(sanction_field signed-by)"
}

verify_calibration() {
  [ -n "$G6_CALIBRATION" ] || { refused "G6_CALIBRATION is not set"; return 1; }
  [ -r "$G6_CALIBRATION" ] || { refused "calibration '$G6_CALIBRATION' is unreadable"; return 1; }
  local want got
  want="$(sanction_field calibration-sha256)"; got="$(sha_of "$G6_CALIBRATION")"
  [ "$want" = "$got" ] \
    || { refused "the calibration is not the sealed one: sanction pins $want, file is $got"; return 1; }
  local scale; scale="$(calibration_field scale)"
  [ -n "$scale" ] || { refused "the calibration names no scale"; return 1; }
  [ "$scale" = "$MODE" ] \
    || { refused "a '$scale' calibration is not a '$MODE' one — guard values measured at another \
scale are not guard values for this one"; return 1; }
  local s g
  for s in S1 S2 S3 S4; do
    g="$(calibration_field "guard-$s")"
    case "$g" in ''|*[!0-9]*) refused "no numeric guard for $s"; return 1 ;; esac
    [ "$g" -gt 0 ] || { refused "guard-$s is not positive"; return 1; }
  done

  # The guards are RECOMPUTED here from the manifest's own measurements. Accepting four positive
  # numbers is accepting whatever produced them; the formula is the frozen part, and a guard that
  # does not follow from the measurement next to it is not a guard, it is a number.
  local t1 t2 div w1 w2
  t1="$(calibration_field elapsed-S1)"; t2="$(calibration_field elapsed-S2)"
  div="$(calibration_field calibration-divisor)"
  case "$t1$t2$div" in ''|*[!0-9]*) refused "the calibration carries no measurement to \
recompute its guards from"; return 1 ;; esac
  [ "$div" = "$CAL_DIVISOR" ] \
    || { refused "the calibration was measured at 1/$div, the frozen divisor is 1/$CAL_DIVISOR"
         return 1; }
  w1=$(( 4 * CAL_DIVISOR * t1 )); [ "$w1" -lt 900 ] && w1=900
  w2=$(( 4 * CAL_DIVISOR * t2 )); [ "$w2" -lt 900 ] && w2=900
  for s in "S1:$w1" "S2:$w2" "S3:$w2" "S4:$w1"; do
    g="$(calibration_field "guard-${s%%:*}")"
    [ "$g" = "${s#*:}" ] \
      || { refused "guard-${s%%:*} is $g; max(4 * $CAL_DIVISOR * t, 900) over this manifest's \
own measurement gives ${s#*:}"; return 1; }
  done
  [ "$(calibration_field formula)" = "max(4 * $CAL_DIVISOR * t, 900)" ] \
    || { refused "the calibration states the formula '$(calibration_field formula)'"; return 1; }
  say "calibration verified, sealed by the sanction, guards recomputed, scale=$scale"
}

verify_candidate() {
  [ -n "$G6_BIN" ] || { refused "G6_BIN is not set"; return 1; }
  [ -x "$G6_BIN" ] || { refused "candidate '$G6_BIN' is not executable"; return 1; }
  local want got
  want="$(sanction_field candidate-sha256)"; got="$(sha_of "$G6_BIN")"
  [ "$want" = "$got" ] \
    || { refused "the candidate is not the sanctioned one: pinned $want, binary is $got"; return 1; }
  say "candidate verified: $G6_BIN"
}

verify_bundle() {
  local want got
  want="$(sanction_field bundle-sha256)"; got="$(bundle_sha)"
  if [ "$want" != "$got" ]; then
    bundle_manifest >&2
    refused "the running bundle is not the sanctioned one: pinned $want, loaded $got from $HERE"
    return 1
  fi
  say "bundle verified: $got loaded from $HERE"
}

# The plan is a frozen document, sealed by the sanction, and it must be COMPLETE: every resource
# the run will touch is named there, and every one of them is compared against what this process
# is actually configured with. A plan with a field missing is not a plan.
# Every path the run touches, on BOTH contours, and every number it measures itself against.
PLAN_PATHS="remote-root image mountpoint state-dir work-dir evidence-dir loop-device uuid \
image-size"
PLAN_CAL="cal-image cal-image-bytes cal-mountpoint cal-state-dir cal-loop-device cal-uuid \
cal-image-size cal-order cal-external-requirement cal-inode-need cal-inode-reserve \
cal-internal-byte-need cal-internal-byte-reserve cal-block-size cal-requested-inodes"
PLAN_NUMBERS="image-bytes external-requirement inode-need inode-reserve internal-byte-need \
internal-byte-reserve batch block-size requested-inodes scale-G scale-M scale-U scale-B"

verify_resource_plan() {
  [ -n "$G6_RESOURCE_PLAN" ] || { refused "G6_RESOURCE_PLAN is not set"; return 1; }
  [ -r "$G6_RESOURCE_PLAN" ] || { refused "resource plan '$G6_RESOURCE_PLAN' is unreadable"; return 1; }
  local want got
  want="$(sanction_field resource-plan-sha256)"; got="$(sha_of "$G6_RESOURCE_PLAN")"
  [ "$want" = "$got" ] \
    || { refused "the resource plan is not the sealed one: sanction pins $want, file is $got"; return 1; }

  local k v
  for k in $PLAN_PATHS $PLAN_CAL $PLAN_NUMBERS scale-seed host; do
    [ -n "$(plan_field "$k")" ] || { refused "the resource plan names no '$k'"; return 1; }
  done
  for k in $PLAN_PATHS; do
    case "$k" in
      remote-root)  v="$G6_REMOTE_ROOT" ;;
      image)        v="$G6_IMAGE" ;;
      loop-device)  v="$G6_LOOP_DEV" ;;
      uuid)         v="$G6_UUID" ;;
      mountpoint)   v="$G6_FIXTURE_ROOT" ;;
      state-dir)    v="$G6_STATE_DIR" ;;
      work-dir)     v="$G6_WORK" ;;
      evidence-dir) v="${G6_EVIDENCE_DIR:-$G6_WORK}" ;;
      image-size)   v="$G6_IMAGE_SIZE" ;;
    esac
    [ -n "$v" ] || { refused "the run has no value for '$k'"; return 1; }
    [ "$v" = "$(plan_field "$k")" ] \
      || { refused "'$k' is '$v' but the frozen plan says '$(plan_field "$k")'"; return 1; }
  done
  # The plan and the sanction must agree on every pinned resource, not merely overlap on a few.
  for k in remote-root image loop-device uuid mountpoint state-dir work-dir image-size \
           scale-G scale-M scale-U scale-B scale-seed host; do
    [ "$(plan_field "$k")" = "$(sanction_field "$k")" ] \
      || { refused "the plan and the sanction disagree about '$k'"; return 1; }
  done

  # An environment that hands in one of the frozen numbers may not disagree with the plan. This
  # is the whole difference between a default and an override: a default is what the plan says,
  # an override is somebody deciding otherwise at run time.
  local p pv
  for p in $G6_ENV_PINS; do
    case "$p" in
      G6_IMAGE_BYTES)           k=image-bytes ;;
      G6_EXTERNAL_REQUIREMENT)  k=external-requirement ;;
      G6_INODE_NEED)            k=inode-need ;;
      G6_INODE_RESERVE)         k=inode-reserve ;;
      G6_INTERNAL_BYTE_NEED)    k=internal-byte-need ;;
      G6_INTERNAL_BYTE_RESERVE) k=internal-byte-reserve ;;
      G6_BATCH)                 k=batch ;;
      G6_BLOCK_SIZE)            k=block-size ;;
      G6_REQUESTED_INODES)      k=requested-inodes ;;
      *) continue ;;
    esac
    eval "pv=\$$p"
    [ "$pv" = "$(plan_field "$k")" ] \
      || { refused "the environment sets $p='$pv' while the frozen plan pins $k='$(plan_field "$k")'"
           return 1; }
  done
  # From here the numbers come from the PLAN, not from this process's defaults.
  G6_IMAGE_BYTES="$(plan_field image-bytes)"
  G6_EXTERNAL_REQUIREMENT="$(plan_field external-requirement)"
  G6_INODE_NEED="$(plan_field inode-need)"
  G6_INODE_RESERVE="$(plan_field inode-reserve)"
  G6_INTERNAL_BYTE_NEED="$(plan_field internal-byte-need)"
  G6_INTERNAL_BYTE_RESERVE="$(plan_field internal-byte-reserve)"
  G6_BATCH="$(plan_field batch)"
  G6_BLOCK_SIZE="$(plan_field block-size)"
  G6_REQUESTED_INODES="$(plan_field requested-inodes)"

  # The host the plan was written for is the host this is running on. A plan is a statement about
  # a machine, and the cheapest way to run it against the wrong one is to never ask.
  local here_host; here_host="$(host_identity)"
  [ -n "$here_host" ] || { blocked "this host has no identity to compare with the plan"; return 2; }
  [ "$here_host" = "$(plan_field host)" ] \
    || { refused "the plan is for host '$(plan_field host)', this is '$here_host'"; return 1; }

  # Containment is not only about the fixture: the state, the work and the evidence live under
  # the sanctioned root too, or they live somewhere nobody agreed to.
  for k in mountpoint image state-dir work-dir evidence-dir cal-image cal-mountpoint \
           cal-state-dir; do
    case "$(plan_field "$k")" in
      "$G6_REMOTE_ROOT"/*) ;;
      *) refused "'$k' is not under REMOTE_ROOT"; return 1 ;;
    esac
  done
  # The two contours may not share a single object.
  for k in image mountpoint state-dir; do
    [ "$(plan_field "$k")" != "$(plan_field "cal-$k")" ] \
      || { refused "the calibration and the run share '$k'"; return 1; }
  done
  say "resource plan verified: complete, frozen, and about this host"
}

preflight_tools() {
  local t missing=""
  for t in "$G6_LOSETUP" "$G6_MKFS" "$G6_MOUNT" "$G6_UMOUNT" "$G6_BLKID" "$G6_DUMPE2FS" \
           "$G6_TIME" "$G6_DF" python3 sha256sum; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
  done
  [ -z "$missing" ] || { blocked "tools unavailable:$missing — a preflight question, not \
something to work around at run time"; return 2; }
  say "tool preflight ok"
}

# ------------------------------------------------------------------ capacity

avail_bytes()  { "$G6_DF" -P -B1 "$1" 2>/dev/null | awk 'NR == 2 { print $4 }'; }
avail_inodes() { "$G6_DF" -P -i  "$1" 2>/dev/null | awk 'NR == 2 { print $4 }'; }
total_inodes() { "$G6_DF" -P -i  "$1" 2>/dev/null | awk 'NR == 2 { print $2 }'; }

# Two modes, because the question changes as the fixture grows.
#
#   full     everything the whole fixture will need, plus the reserve. Asked once before
#            generation, of the inode TOTAL as well: mkfs cannot be asked afterwards to add
#            inodes, so a filesystem formatted too small is BLOCKED before a single file exists.
#   reserve  the margin, and only the margin. Between batches and after the last one, what has
#            to be true is that the reserve is still there.
#
# The reserve mode MEASURES; it does not predict. A batch spends more than its files: every
# directory it creates is an inode too, and the bytes are not files x block either. Anything the
# harness works out about what the next batch will cost is a forecast, and a forecast that is
# wrong in the safe direction still refuses a run that would have fitted, while one wrong in the
# other direction passes a run that will not. P0 §4.2 and §6.3 ask for the margin to be measured
# again between batches, which is what this does.
#
# And asking for `need + reserve` again after 2 200 000 files already exist asks the filesystem
# to hold the fixture twice: the full-scale run would refuse itself at the last batch boundary,
# every time, on arithmetic rather than on the machine.
check_capacity() {
  local mode="$1" outside_dir="$2" inside_dir="${3:-}"
  local have inode_need byte_need
  case "$mode" in full|reserve) ;;
    *) blocked "unknown capacity mode '$mode'"; return 2 ;;
  esac
  have="$(avail_bytes "$outside_dir")"
  case "$have" in ''|*[!0-9]*) blocked "cannot measure free bytes on '$outside_dir'"; return 2 ;; esac
  [ "$have" -ge "$G6_EXTERNAL_REQUIREMENT" ] \
    || { blocked "external requirement: $have bytes free under '$outside_dir', need $G6_EXTERNAL_REQUIREMENT"; return 2; }
  if [ -n "$inside_dir" ]; then
    if [ "$mode" = full ]; then
      inode_need=$(( G6_INODE_NEED + G6_INODE_RESERVE ))
      byte_need=$(( G6_INTERNAL_BYTE_NEED + G6_INTERNAL_BYTE_RESERVE ))
      # The total is a property of the geometry mkfs already chose, so it is asked once, here,
      # and never again: it does not shrink and it cannot grow.
      have="$(total_inodes "$inside_dir")"
      case "$have" in ''|*[!0-9]*) blocked "cannot measure the inode total in '$inside_dir'"; return 2 ;; esac
      [ "$have" -ge "$inode_need" ] \
        || { blocked "internal inode total: $have in '$inside_dir', need $inode_need — a filesystem that was formatted too small never grows one"; return 2; }
    else
      inode_need=$G6_INODE_RESERVE
      byte_need=$G6_INTERNAL_BYTE_RESERVE
    fi
    have="$(avail_inodes "$inside_dir")"
    case "$have" in ''|*[!0-9]*) blocked "cannot measure free inodes in '$inside_dir'"; return 2 ;; esac
    [ "$have" -ge "$inode_need" ] \
      || { blocked "internal inode margin: $have free in '$inside_dir', need $inode_need"; return 2; }
    have="$(avail_bytes "$inside_dir")"
    case "$have" in ''|*[!0-9]*) blocked "cannot measure free bytes in '$inside_dir'"; return 2 ;; esac
    [ "$have" -ge "$byte_need" ] \
      || { blocked "internal byte margin: $have free in '$inside_dir', need $byte_need"; return 2; }
  fi
  say "capacity ok, $mode (outside '$outside_dir'${inside_dir:+, inside '$inside_dir'})"
}

# ------------------------------------------------------------------ kill guard

G6_LAST_CLASS=""; G6_LAST_RAW=""; G6_LAST_SIGNAL=""; G6_LAST_PID=""; G6_LAST_PGID=""
G6_LAST_WATCHDOG=""

guarded_run() {  # timeout label outdir -- command...
  local timeout="$1" label="$2" outdir="$3"; shift 3; [ "$1" = "--" ] && shift
  G6_LAST_CLASS=""; G6_LAST_RAW=""; G6_LAST_SIGNAL=""; G6_LAST_PID=""; G6_LAST_PGID=""
  mkdir -p "$outdir" || { blocked "cannot create '$outdir'"; return 2; }

  # The argv that actually ran, recorded here rather than re-typed later: a receipt quoting a
  # command line somebody printed separately is a receipt for a command nobody watched.
  local argv_q="" a
  for a in "$@"; do argv_q="$argv_q $(printf '%q' "$a")"; done
  printf '%s\n' "${argv_q# }" > "$outdir/$label.argv"

  set -m
  "$G6_TIME" -v -o "$outdir/$label.time" "$@" \
    >"$outdir/$label.out" 2>"$outdir/$label.err" &
  local child=$!
  set +m

  local pgid=""
  [ -r "/proc/$child/stat" ] && \
    pgid="$(sed 's/.*) //' "/proc/$child/stat" 2>/dev/null | awk '{print $3}')"
  [ -n "$pgid" ] || pgid="$child"
  if [ "$pgid" != "$child" ]; then
    kill -KILL "$child" 2>/dev/null; wait "$child" 2>/dev/null
    G6_LAST_CLASS="TOOLING_FAILURE"
    blocked "the guarded child is in group $pgid, not its own"
    return 2
  fi
  G6_LAST_PID="$child"; G6_LAST_PGID="$pgid"

  # THE WATCHDOG IS ITS OWN PROCESS, IN ITS OWN SESSION.
  #
  # A guard that is a loop inside this shell is only a guard while this shell is alive. SIGKILL
  # the controller — the one signal nothing can trap — and the loop is gone while the candidate
  # keeps running: on the full-scale fixture that is an unbounded scan on somebody else's
  # production host, with nobody left to stop it and no record that it is still there. The same
  # hole opens more quietly if the controller is killed as part of a process group.
  #
  # So the deadline is enforced from outside: setsid detaches the watchdog into a session of its
  # own, where neither the controller's death nor a signal aimed at the controller's group can
  # reach it. It watches the child's group, not the controller, and it exits by itself the moment
  # that group is gone. The in-shell loop below stays, because it is what MEASURES and classifies
  # the outcome — but it is no longer what enforces it.
  local wd="$outdir/$label.watchdog"
  { printf '#!/usr/bin/env bash\n'
    printf 'pgid=%q; deadline=%q; grace=%q\n' "$pgid" "$timeout" "$G6_GRACE"
    printf 'waited=0\n'
    printf 'while kill -0 -- "-$pgid" 2>/dev/null; do\n'
    printf '  [ "$waited" -ge "$deadline" ] && break\n'
    printf '  sleep 1; waited=$(( waited + 1 ))\n'
    printf 'done\n'
    printf 'kill -0 -- "-$pgid" 2>/dev/null || exit 0\n'
    printf 'printf "watchdog: the guarded group %%s outlived its %%s second deadline\\n" "$pgid" "$deadline" >&2\n'
    printf 'kill -TERM -- "-$pgid" 2>/dev/null\n'
    printf 'g=0\n'
    printf 'while kill -0 -- "-$pgid" 2>/dev/null && [ "$g" -lt "$grace" ]; do sleep 1; g=$(( g + 1 )); done\n'
    printf 'kill -KILL -- "-$pgid" 2>/dev/null\n'
    printf 'exit 0\n'
  } > "$wd"
  chmod 0700 "$wd"
  "$G6_SETSID" "$wd" >"$outdir/$label.watchdog.out" 2>&1 &
  local watcher=$!
  G6_LAST_WATCHDOG="$watcher"

  local waited=0 fired=0
  while kill -0 "$child" 2>/dev/null; do
    [ "$waited" -ge "$timeout" ] && { fired=1; break; }
    sleep 1; waited=$(( waited + 1 ))
  done
  if [ "$fired" = 1 ]; then
    kill -TERM -- "-$pgid" 2>/dev/null
    local g=0
    while kill -0 "$child" 2>/dev/null && [ "$g" -lt "$G6_GRACE" ]; do sleep 1; g=$(( g + 1 )); done
    kill -KILL -- "-$pgid" 2>/dev/null
  fi

  # The child is done one way or the other, so the deadline no longer has anything to enforce.
  # Reaped here rather than left to exit on its own, because a watchdog still sleeping on a dead
  # group is a process nobody accounted for.
  kill -TERM "$watcher" 2>/dev/null
  wait "$watcher" 2>/dev/null

  wait "$child"; local raw=$?
  G6_LAST_RAW="$raw"
  [ "$raw" -gt 128 ] && G6_LAST_SIGNAL=$(( raw - 128 ))

  local attempt=0
  while kill -0 -- "-$pgid" 2>/dev/null; do
    if [ "$attempt" -ge "$G6_REAP_LIMIT" ]; then
      G6_LAST_CLASS="TOOLING_FAILURE"
      blocked "process group $pgid survived $G6_REAP_LIMIT kill attempts"
      return 2
    fi
    kill -KILL -- "-$pgid" 2>/dev/null
    attempt=$(( attempt + 1 )); sleep 1
  done

  if [ "$fired" = 1 ]; then G6_LAST_CLASS="CANDIDATE_TIMEOUT"
  elif [ -n "$G6_LAST_SIGNAL" ]; then G6_LAST_CLASS="EXTERNAL_INTERRUPT"
  elif [ "$raw" = 0 ]; then G6_LAST_CLASS="OK"
  else G6_LAST_CLASS="CANDIDATE_NONZERO"; fi

  {
    printf 'label\t%s\n' "$label";     printf 'class\t%s\n' "$G6_LAST_CLASS"
    printf 'raw-exit\t%s\n' "$raw";    printf 'signal\t%s\n' "${G6_LAST_SIGNAL:-none}"
    printf 'pid\t%s\n' "$child";       printf 'pgid\t%s\n' "$pgid"
    printf 'stdout\t%s\n' "$outdir/$label.out"
    printf 'stderr\t%s\n' "$outdir/$label.err"
    printf 'time\t%s\n' "$outdir/$label.time"
    printf 'argv\t%s\n' "$(cat "$outdir/$label.argv")"
  } > "$outdir/$label.meta"
  say "$label: class=$G6_LAST_CLASS raw=$raw pid=$child pgid=$pgid"
  [ "$G6_LAST_CLASS" = "OK" ]
}

# A guarded run's class, turned into a verdict. The candidate's own misbehaviour is FAIL;
# everything else is the environment, and that is BLOCKED.
class_verdict() {
  case "${1:-}" in
    OK)                                    printf 'PASS\n' ;;
    CANDIDATE_NONZERO|CANDIDATE_TIMEOUT)   printf 'FAIL\n' ;;
    *)                                     printf 'BLOCKED\n' ;;
  esac
}

# ------------------------------------------------------------------ calibration

# A calibration route that can be proved where it runs. It builds a reduced fixture, times the
# read-only scenarios on it, and writes a manifest that names the scale it was measured at, so a
# rehearsal manifest can never be mistaken for a live one.
# Wall-clock seconds from a GNU time report, rounded up, never below one.
elapsed_seconds() {  # time-report
  awk '
    /Elapsed \(wall clock\) time/ {
      n = split($NF, p, ":")
      s = (n == 3) ? p[1] * 3600 + p[2] * 60 + p[3] : p[1] * 60 + p[2]
      v = int(s); if (v < s) v = v + 1; if (v < 1) v = 1
      print v; found = 1
    }
    END { if (!found) print -1 }' "$1"
}

# The calibration route builds its OWN fixture on its OWN image, measures S1 and S2 there,
# derives the guards by the frozen formula and then proves its image is gone. It never borrows
# the run's fixture: a guard measured on the very artifact it is meant to guard is a guard
# measured after the fact, and an image left behind is a resource nobody sanctioned.
#
#   CAL_DIVISOR = 100, so the calibration fixture is 1/100 of the frozen scale
#   guard(S) = max( 4 * CAL_DIVISOR * t_S , 900 )
#
# Four is headroom for non-linearity and for somebody else's I/O; the floor stops a calibration
# on an idle machine from producing an absurdly short guard.
CAL_DIVISOR=100

# The calibration kit, all of it sealed in the plan: its own image, its own mountpoint, its own
# state, its own uuid, and the device it is allowed to use together with the ORDER in which the
# two contours use it. Nothing here is derived from the run's paths at run time, because a
# calibration that computes its own resources is a calibration nobody sanctioned.
cal_lib() {  # step
  env G6_IMAGE="$(plan_field cal-image)" \
      G6_MOUNTPOINT="$(plan_field cal-mountpoint)" \
      G6_STATE_DIR="$(plan_field cal-state-dir)" \
      G6_LOOP_DEV="$(plan_field cal-loop-device)" \
      G6_UUID="$(plan_field cal-uuid)" \
      G6_IMAGE_SIZE="$(plan_field cal-image-size)" \
      G6_REMOTE_ROOT="$G6_REMOTE_ROOT" \
      G6_MIN_INODES="$(( $(plan_field cal-inode-need) + $(plan_field cal-inode-reserve) ))" \
      G6_REQUESTED_INODES="$(plan_field cal-requested-inodes)" \
      bash "$G6_IMAGE_LIB" "$1"
}

# Nothing of the calibration may still exist when the run begins. Proved by looking, not by
# remembering that teardown returned zero.
assert_calibration_gone() {
  local img mnt left=""
  img="$(plan_field cal-image)"; mnt="$(plan_field cal-mountpoint)"
  [ -n "$img" ] || return 0
  [ -e "$img" ] && left="$left $img"
  [ -d "$(dirname "$img")" ] && left="$left $(dirname "$img")"
  [ -e "$mnt" ] && left="$left $mnt"
  [ -z "$left" ] && return 0
  blocked "the calibration left resources behind:$left"
  return 2
}

# The calibration measures itself against ITS OWN sealed requirements. Using the run's numbers
# would ask a one-gigabyte image to prove it can hold two million files; using none would ask
# nothing at all.
use_calibration_numbers() {
  G6_EXTERNAL_REQUIREMENT="$(plan_field cal-external-requirement)"
  G6_INODE_NEED="$(plan_field cal-inode-need)"
  G6_INODE_RESERVE="$(plan_field cal-inode-reserve)"
  G6_INTERNAL_BYTE_NEED="$(plan_field cal-internal-byte-need)"
  G6_INTERNAL_BYTE_RESERVE="$(plan_field cal-internal-byte-reserve)"
  G6_BLOCK_SIZE="$(plan_field cal-block-size)"
  G6_REQUESTED_INODES="$(plan_field cal-requested-inodes)"
}

# One executable, no arguments, carrying the frozen numbers it must measure against. The numbers
# travel in the environment of the child rather than in an argument list, so the hook stays a
# program with no command line to word split.
write_capacity_hook() {  # path outside inside
  { printf '#!/usr/bin/env bash\n'
    printf 'exec env G6_EXTERNAL_REQUIREMENT=%q G6_INODE_NEED=%q G6_INODE_RESERVE=%q \\\n' \
      "$G6_EXTERNAL_REQUIREMENT" "$G6_INODE_NEED" "$G6_INODE_RESERVE"
    printf '  G6_INTERNAL_BYTE_NEED=%q G6_INTERNAL_BYTE_RESERVE=%q \\\n' \
      "$G6_INTERNAL_BYTE_NEED" "$G6_INTERNAL_BYTE_RESERVE"
    printf '  %q %q %q %q\n' "$HERE/g6-controller.sh" capacity-hook "$2" "$3"
  } > "$1"
  chmod 0700 "$1"
}

calibrate() {  # out-manifest
  local out="${1:-}"
  [ -n "$out" ] || { refused "calibrate needs an output manifest path"; return 1; }
  [ -n "$G6_WORK" ] || { refused "G6_WORK is not set"; return 1; }

  # Calibration attaches a loop device, formats it and mounts it — the same privileged chain the
  # route runs, on the same machine, under the same root. So it answers the same questions first,
  # and answers them BEFORE it creates a directory, let alone a device: contour, sanction,
  # candidate, bundle and the frozen plan. The one thing it cannot check is the seal over its own
  # manifest, which does not exist yet.
  verify_contour >/dev/null \
    || { refused "calibration refuses outside a verified contour"; return 1; }
  verify_sanction_core \
    || { refused "calibration refuses without a sanction for this contour, mode and root — \
nothing was created and no device was touched"; return 1; }
  verify_candidate >/dev/null \
    || { refused "calibration refuses a candidate the sanction does not pin"; return 1; }
  verify_bundle >/dev/null \
    || { refused "calibration refuses a bundle the sanction does not pin"; return 1; }
  verify_resource_plan >/dev/null \
    || { refused "calibration refuses without the frozen resource plan"; return 1; }

  local cal_img cal_mnt cal_state
  cal_img="$(plan_field cal-image)"
  cal_mnt="$(plan_field cal-mountpoint)"
  cal_state="$(plan_field cal-state-dir)"

  local outdir="$G6_WORK/calibration"
  mkdir -p "$outdir" || { blocked "cannot create '$outdir'"; return 2; }
  mkdir -p "$cal_state" || { blocked "cannot create '$cal_state'"; return 2; }

  # From here the calibration contour measures itself against its own sealed requirements, and
  # formats its own geometry. It is a separate contour or it is a second name for the run's.
  use_calibration_numbers

  local g m u
  g=$(( LIVE_G / CAL_DIVISOR )); m=$LIVE_M; u=$(( LIVE_U / CAL_DIVISOR ))

# The margin is measured on the sanctioned root, not on the image directory: that directory does
# not exist yet — `prepare` creates it (g6-image-lib.sh mkdir before the image is made) — and df
# on a path that is not there measures nothing, which this function then reports as BLOCKED. The
# image lands on the root's filesystem anyway, so the root is both the measurable answer and the
# correct one. The stub bench used to create g6-image up front, which is why no scenario saw it.
  check_capacity full "$G6_REMOTE_ROOT" \
    || { blocked "capacity before the calibration image was created"; return 2; }

  cal_lib prepare >/dev/null 2>&1 || { blocked "calibration lifecycle: prepare"; return 2; }
  cal_lib attach  >/dev/null 2>&1 || { blocked "calibration lifecycle: attach"; return 2; }
  cal_lib format  >/dev/null 2>&1 || { blocked "calibration lifecycle: format"; return 2; }
  cal_lib mount   >/dev/null 2>&1 || { blocked "calibration lifecycle: mount"; return 2; }

  check_capacity full "$G6_REMOTE_ROOT" "$cal_mnt" \
    || { blocked "capacity after the calibration mkfs"; return 2; }

  # The generator gets a hook here too, so the calibration is measured between batches and after
  # the last one exactly as the run is. A contour that skips it is not the same contour.
  local cal_hook="$outdir/capacity-hook"
  write_capacity_hook "$cal_hook" "$G6_REMOTE_ROOT" "$cal_mnt" \
    || { blocked "cannot prepare the calibration capacity hook"; return 2; }

  env G6_G="$g" G6_M="$m" G6_U="$u" G6_B="$LIVE_B" G6_SEED="calibration-$LIVE_SEED" \
      G6_BATCH="$G6_BATCH" G6_CAPACITY_HOOK="$cal_hook" \
      bash "$G6_MAKE_FIXTURE" --mode rehearsal --root "$cal_mnt" >/dev/null 2>&1 \
    || { blocked "the calibration fixture did not build"; return 2; }

  # The calibration scan runs under the SAME kill guard as the run's, and leaves the same raw
  # evidence. An unguarded scan here is an unbounded scan on the machine the run is about to use.
  mkdir -p "$cal_mnt/state" "$cal_mnt/out"
  guarded_run "$G6_SCAN_GUARD" CALSCAN "$outdir" -- \
    "$G6_BIN" --state-dir "$cal_mnt/state" --scan "$cal_mnt/data" --no-resume \
    || { blocked "the calibration scan did not complete ($G6_LAST_CLASS)"; return 2; }

  # The calibration fixture is checked by the same independent verifier the run uses. Timing a
  # fixture that is not the fixture it was supposed to be produces guards for an experiment
  # nobody ran.
  "$G6_VERIFY_COUNTS" --db "$cal_mnt/state/dedcom.db" \
      --groups "$g" --members-per-group "$m" --singletons "$u" \
      > "$outdir/verify.out" 2>&1 \
    || { cat "$outdir/verify.out" >&2
         blocked "the calibration fixture does not match its own parameters"; return 2; }

  guarded_run 600 CAL1 "$outdir" -- "$G6_BIN" --state-dir "$cal_mnt/state" --stats \
    || { blocked "calibration S1 did not complete"; return 2; }
  guarded_run 600 CAL2 "$outdir" -- "$G6_BIN" --state-dir "$cal_mnt/state" \
      --export-csv "$cal_mnt/out/cal.csv" \
    || { blocked "calibration S2 did not complete"; return 2; }

  local t1 t2 g1 g2
  t1="$(elapsed_seconds "$outdir/CAL1.time")"
  t2="$(elapsed_seconds "$outdir/CAL2.time")"
  { [ "$t1" -ge 1 ] && [ "$t2" -ge 1 ]; } \
    || { blocked "the time report carries no elapsed line — the guards cannot be derived"; return 2; }
  g1=$(( 4 * CAL_DIVISOR * t1 )); [ "$g1" -lt 900 ] && g1=900
  g2=$(( 4 * CAL_DIVISOR * t2 )); [ "$g2" -lt 900 ] && g2=900

  # The calibration image is gone before the manifest is written, and its absence is re-read
  # rather than assumed — the image, the directory that held it and the mountpoint.
  cal_lib teardown >/dev/null 2>&1 \
    || { blocked "the calibration image could not be torn down"; return 2; }
  assert_calibration_gone || return 2

  # Fail-closed publication, like every other durable fact here: a manifest written with a plain
  # redirect can be half a manifest, and half a manifest still parses.
  { printf 'scale\t%s\n' "$MODE"
    printf 'measured-from\t%s\n' "$outdir"
    printf 'calibration-divisor\t%s\n' "$CAL_DIVISOR"
    printf 'calibration-fixture\tG=%s M=%s U=%s B=%s\n' "$g" "$m" "$u" "$LIVE_B"
    printf 'calibration-image\t%s\n' "$cal_img"
    printf 'elapsed-S1\t%s\n' "$t1"; printf 'elapsed-S2\t%s\n' "$t2"
    printf 'formula\tmax(4 * %s * t, 900)\n' "$CAL_DIVISOR"
    printf 'calibration-image-removed\tproved\n'
    printf 'guard-S1\t%s\n' "$g1"; printf 'guard-S2\t%s\n' "$g2"
    printf 'guard-S3\t%s\n' "$g2"; printf 'guard-S4\t%s\n' "$g1"
  } | "$G6_PUBLISH" --dir "$(dirname "$out")" --name "$(basename "$out")" >/dev/null 2>&1 \
    || { blocked "the calibration manifest could not be published"; return 2; }
  say "calibration published to $out (scale $MODE, t1=${t1}s t2=${t2}s)"
}

# ------------------------------------------------------------------ scenarios

dry_route() {
  local st="$G6_FIXTURE_ROOT/state" out="$G6_FIXTURE_ROOT/out"
  cat <<EOF
S1	$G6_BIN --state-dir $st --stats
S1-post	exit 0; reported group and file counts equal the SQL-asserted counts; no OOM, no panic
S2	$G6_BIN --state-dir $st --export-csv $out/full.csv
S2-post	exit 0; row count equals header + sum of members exactly; mode 0600; no .dedcom-export-* residue
S3	$G6_BIN --state-dir $st --export-csv $out/full.csv
S3-post	exit 0; atomic replacement — a NEW inode, identical bytes, no temporary left behind
S4	$G6_BIN --state-dir $st --export-csv $st/dedcom.db
S4-post	non-zero; refused as a protected name; the checkpoint still opens afterwards
EOF
}

sql_counts() {
  python3 - "$1" <<'PY'
import sqlite3, sys
c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
one = lambda s: c.execute(s).fetchone()[0]
print(one("SELECT COUNT(*) FROM file"), one("SELECT COUNT(*) FROM file_group"),
      one("SELECT COALESCE(SUM(file_count),0) FROM file_group"))
PY
}

# Which scenario steps actually ran, in order, read from the guards' own meta files. This is what
# proves fail-fast, and it is a different claim from a marker: a marker says where the run
# BELIEVES it stopped, while this says which steps left evidence of having run at all. A run that
# carried on past a contradicted postcondition is visible here and nowhere else.
scenarios_ran() {  # outdir
  local s out=""
  for s in SCAN S1 S2 S3 S4; do
    [ -f "$1/$s.meta" ] && out="$out $s"
  done
  printf '%s' "${out# }"
}

# The postconditions that were checked and HELD, in the order they were reached. A record that
# says only where a run stopped leaves everything before that point as an unexamined claim.
postconditions_met() {  # outdir
  [ -f "$1/POSTCONDITIONS" ] || { printf 'none'; return; }
  tr '\n' ' ' < "$1/POSTCONDITIONS" | sed 's/ $//'
}

# The scenario stage's verdict is a durable one-line fact, never a word fished out of the stage's
# own output. That output is a LOG: every guarded run prints a progress line to it, so a verdict
# read from the stream changes meaning the moment one more line is printed — and a
# multi-line answer reaching the terminalizer is an unclassified outcome, which is a BLOCKED
# nobody asked for. The stage writes VERDICT and REASON; the route reads those two files and
# nothing else.
read_scenario_verdict() {  # outdir -> exactly one of PASS FAIL BLOCKED
  local f="$1/VERDICT"
  [ -f "$f" ] || { printf 'BLOCKED'; return; }
  [ "$(wc -l < "$f")" = 1 ] || { printf 'BLOCKED'; return; }
  case "$(head -n 1 "$f")" in
    PASS)    printf 'PASS' ;;
    FAIL)    printf 'FAIL' ;;
    BLOCKED) printf 'BLOCKED' ;;
    *)       printf 'BLOCKED' ;;
  esac
}

read_scenario_reason() {  # outdir
  local f="$1/REASON"
  if [ -f "$f" ]; then head -n 1 "$f"; else printf 'the scenario stage recorded no reason'; fi
}

# Fail-fast: the first contradicted postcondition ends the stage. The verdict goes to VERDICT,
# the diagnosis to REASON, and everything printed here is log.
run_scenarios() {  # outdir
  local outdir="$1" st="$G6_FIXTURE_ROOT/state" out="$G6_FIXTURE_ROOT/out"
  local counts files groups members
  # Fail-fast leaves a mark: the step the run stopped at, readable from outside this subshell.
  note_step() { printf '%s\n' "$1" > "$outdir/STOPPED-AT"; }
  # The one channel the route reads. Written exactly once, at the single point the stage ends.
  sc_end() { printf '%s\n' "$1" > "$outdir/VERDICT"; printf '%s\n' "$2" > "$outdir/REASON"; }
  # Which postconditions were actually SATISFIED. A terminal record that says only where a run
  # stopped leaves everything before that point as a claim; this is the part that was checked and
  # held, and it is what a reader needs in order to know how far the evidence goes.
  sc_met() { printf '%s\n' "$1" >> "$outdir/POSTCONDITIONS"; }
  counts="$(sql_counts "$st/dedcom.db")" \
    || { sc_end BLOCKED "the checkpoint could not be read for the SQL oracle"; return; }
  files="$(echo "$counts" | awk '{print $1}')"
  groups="$(echo "$counts" | awk '{print $2}')"
  members="$(echo "$counts" | awk '{print $3}')"
  mkdir -p "$out"

  note_step S1
  guarded_run "$(calibration_field guard-S1)" S1 "$outdir" -- "$G6_BIN" --state-dir "$st" --stats
  [ "$G6_LAST_CLASS" = OK ] \
    || { sc_end "$(class_verdict "$G6_LAST_CLASS")" "S1 ended $G6_LAST_CLASS"; return; }
  local rf rg
  rf="$(sed -n 's/.*workload:.*files=\([0-9]*\).*/\1/p' "$outdir/S1.out" | head -1)"
  rg="$(sed -n 's/.*workload:.*groups=\([0-9]*\).*/\1/p' "$outdir/S1.out" | head -1)"
  [ "$rf" = "$files" ] || { printf 'S1-post: reported files=%s, SQL=%s\n' "$rf" "$files" >&2
                            sc_end FAIL "S1-post: reported files=$rf, SQL=$files"; return; }
  [ "$rg" = "$groups" ] || { printf 'S1-post: reported groups=%s, SQL=%s\n' "$rg" "$groups" >&2
                             sc_end FAIL "S1-post: reported groups=$rg, SQL=$groups"; return; }
  if grep -qiE 'panic|out of memory' "$outdir/S1.err"; then
    printf 'S1-post: the candidate panicked or ran out of memory\n' >&2
    sc_end FAIL "S1-post: the candidate panicked or ran out of memory"; return
  fi
  sc_met "S1-counts-match-sql S1-no-panic"

  note_step S2
  guarded_run "$(calibration_field guard-S2)" S2 "$outdir" -- \
    "$G6_BIN" --state-dir "$st" --export-csv "$out/full.csv"
  [ "$G6_LAST_CLASS" = OK ] \
    || { sc_end "$(class_verdict "$G6_LAST_CLASS")" "S2 ended $G6_LAST_CLASS"; return; }
  local rows mode residue
  rows="$(wc -l < "$out/full.csv")"
  [ "$rows" = "$(( 1 + members ))" ] || {
    printf 'S2-post: %s rows, expected %s\n' "$rows" "$(( 1 + members ))" >&2
    sc_end FAIL "S2-post: $rows rows, expected $(( 1 + members ))"; return; }
  mode="$(stat -c '%a' "$out/full.csv")"
  [ "$mode" = "600" ] || { printf 'S2-post: mode %s, expected 600\n' "$mode" >&2
                           sc_end FAIL "S2-post: mode $mode, expected 600"; return; }
  residue="$(find "$out" -maxdepth 1 -name '.dedcom-export-*' -print -quit)"
  [ -z "$residue" ] || { printf 'S2-post: residue %s\n' "$residue" >&2
                         sc_end FAIL "S2-post: export residue $residue"; return; }
  sc_met "S2-rows-match-members S2-mode-0600 S2-no-residue"

  # --- S3: a real atomicity witness. An atomic replacement renames a NEW file over the old one,
  # so the inode must CHANGE while the bytes stay identical. A writer that truncated the
  # destination and wrote in place would keep the inode and be visible here — and would also be
  # observable half-written, which is the thing the postcondition is really about.
  local ino_before ino_after sha_before sha_after sz_before sz_after
  ino_before="$(stat -c '%i' "$out/full.csv")"; sha_before="$(sha_of "$out/full.csv")"
  sz_before="$(stat -c '%s' "$out/full.csv")"

  # An INDEPENDENT observer, running at the same time as the export. The endpoints alone do not
  # settle atomicity: what the postcondition is really about is that a reader looking at the
  # destination at an unlucky moment can never see a half-written artifact. So one samples the
  # destination continuously while the writer works, and afterwards every single sample has to
  # be either the old file or the new one — nothing in between, and never absent.
  note_step S3
  local obs_log="$outdir/S3.observed" obs_stop="$outdir/S3.observer-stop"
  local obs_ready="$outdir/S3.observer-ready"
  rm -f "$obs_stop" "$obs_ready"; : > "$obs_log"
  python3 "$G6_OBSERVE" "$out/full.csv" "$obs_log" "$obs_stop" "$obs_ready" &
  local obs_pid=$! waited=0
  # The observer is proved to be RUNNING before the writer starts. Starting it and hoping is how
  # a witness ends up watching the second half of an event it was meant to see all of — and an
  # observer that never started at all would otherwise look exactly like a clean run.
  while [ ! -e "$obs_ready" ] && [ "$waited" -lt 50 ]; do sleep 0.1; waited=$(( waited + 1 )); done
  if [ ! -e "$obs_ready" ]; then
    kill -KILL "$obs_pid" 2>/dev/null; wait "$obs_pid" 2>/dev/null
    sc_end BLOCKED "the S3 observer never signalled it was ready, so nothing could witness S3"
    return
  fi
  # READY is a claim, and the claim is checked: by the time it is made there must already be a
  # sample of the old file in the log. An observer that announces itself before it has looked at
  # anything is an observer whose first sample can be of the NEW file.
  local at_ready; at_ready="$(wc -l < "$obs_log")"
  if [ "${at_ready:-0}" -lt 1 ]; then
    kill -KILL "$obs_pid" 2>/dev/null; wait "$obs_pid" 2>/dev/null
    sc_end BLOCKED "the S3 observer signalled ready before it had sampled anything"
    return
  fi

  guarded_run "$(calibration_field guard-S3)" S3 "$outdir" -- \
    "$G6_BIN" --state-dir "$st" --export-csv "$out/full.csv"
  # Reaped on a BOUNDED deadline: stop file, then poll for it to leave, then KILL, then wait.
  # Waiting first was the bug — an unbounded `wait` on an observer that ignores the stop file
  # never returns, so the kill that was meant to handle exactly that case is unreachable and the
  # whole run hangs behind a background process it started itself.
  : > "$obs_stop"
  local reaped=0 spin=0
  while [ "$spin" -lt "$G6_REAP_LIMIT" ]; do
    kill -0 "$obs_pid" 2>/dev/null || { reaped=1; break; }
    sleep 1; spin=$(( spin + 1 ))
  done
  [ "$reaped" = 1 ] || kill -KILL "$obs_pid" 2>/dev/null
  wait "$obs_pid" 2>/dev/null
  [ "$G6_LAST_CLASS" = OK ] \
    || { sc_end "$(class_verdict "$G6_LAST_CLASS")" "S3 ended $G6_LAST_CLASS"; return; }
  ino_after="$(stat -c '%i' "$out/full.csv")"; sha_after="$(sha_of "$out/full.csv")"
  sz_after="$(stat -c '%s' "$out/full.csv")"

  local samples odd
  samples="$(wc -l < "$obs_log")"
  odd="$(grep -vc -e "^$ino_before $sz_before $sha_before\$" -e "^$ino_after $sz_after $sha_after\$" \
           "$obs_log" || true)"
  {
    printf 'witness\tS3-atomicity\n'
    printf 'inode-before\t%s\n' "$ino_before"; printf 'inode-after\t%s\n' "$ino_after"
    printf 'sha-before\t%s\n' "$sha_before";   printf 'sha-after\t%s\n' "$sha_after"
    printf 'size-before\t%s\n' "$sz_before";   printf 'size-after\t%s\n' "$sz_after"
    printf 'observer-samples\t%s\n' "$samples"
    printf 'observer-samples-at-ready\t%s\n' "$at_ready"
    printf 'observer-unexpected\t%s\n' "$odd"
  } > "$outdir/S3.witness"
  [ "$samples" -ge 1 ] || {
    printf 'S3-post: the observer took no sample, so nothing was witnessed\n' >&2
    sc_end FAIL "S3-post: the observer took no sample, so nothing was witnessed"; return; }
  [ "$odd" = 0 ] || {
    printf 'S3-post: the observer saw %s state(s) that were neither the old file nor the new\n' \
      "$odd" >&2
    sc_end FAIL "S3-post: the observer saw $odd half-written state(s) at the destination"; return; }
  [ "$ino_after" != "$ino_before" ] || {
    printf 'S3-post: the inode did not change — the destination was rewritten in place\n' >&2
    sc_end FAIL "S3-post: the inode did not change, the destination was rewritten in place"; return; }
  [ "$sha_after" = "$sha_before" ] || {
    printf 'S3-post: the replacement changed the content\n' >&2
    sc_end FAIL "S3-post: the replacement changed the content"; return; }
  rows="$(wc -l < "$out/full.csv")"
  [ "$rows" = "$(( 1 + members ))" ] || {
    printf 'S3-post: %s rows after replacement\n' "$rows" >&2
    sc_end FAIL "S3-post: $rows rows after the replacement"; return; }
  residue="$(find "$out" -maxdepth 1 -name '.dedcom-export-*' -print -quit)"
  [ -z "$residue" ] || { printf 'S3-post: residue %s\n' "$residue" >&2
                         sc_end FAIL "S3-post: export residue $residue"; return; }
  sc_met "S3-observer-witnessed S3-no-partial-state S3-new-inode S3-identical-bytes S3-rows S3-no-residue"

  note_step S4
  guarded_run "$(calibration_field guard-S4)" S4 "$outdir" -- \
    "$G6_BIN" --state-dir "$st" --export-csv "$st/dedcom.db"
  case "$G6_LAST_CLASS" in
    CANDIDATE_NONZERO) ;;
    OK) printf 'S4-post: the export over the checkpoint was accepted\n' >&2
        sc_end FAIL "S4-post: the export over the checkpoint was accepted"; return ;;
    *)  sc_end "$(class_verdict "$G6_LAST_CLASS")" "S4 ended $G6_LAST_CLASS"; return ;;
  esac
  grep -q "is dedcom's own dedcom.db" "$outdir/S4.err" || {
    printf 'S4-post: the refusal does not name the protected checkpoint\n' >&2
    sc_end FAIL "S4-post: the refusal does not name the protected checkpoint"; return; }
  "$G6_BIN" --state-dir "$st" --stats >/dev/null 2>&1 || {
    printf 'S4-post: the checkpoint no longer opens\n' >&2
    sc_end FAIL "S4-post: the checkpoint no longer opens after the refusal"; return; }
  sc_met "S4-refused S4-names-the-checkpoint S4-checkpoint-still-opens"

  note_step none
  sc_end PASS "every postcondition held"
}

# ------------------------------------------------------------------ provenance

# Provenance starts BEFORE the scan. A checkpoint that was already sitting there would still read
# user_version 5 and the receipt would still quote our argv — and every word of it would be about
# somebody else's database. The claim "this run produced this checkpoint" is only available to a
# run that found nothing there.
assert_fresh_checkpoint() {
  local st="$G6_FIXTURE_ROOT/state" leftovers
  # Absent, or present and provably empty. Anything else — a checkpoint, a journal, somebody
  # else's files — belongs to a run that is not this one.
  [ ! -e "$st" ] || [ -d "$st" ] || { blocked "'$st' exists and is not a directory"; return 2; }

  # The checkpoint is looked for FIRST, and the general leftovers after it. A database is the one
  # thing in there that has to be named as what it is: with the order the other way round a
  # pre-existing dedcom.db was reported as "the directory is not empty", which is true and says
  # nothing, and the sentence written for exactly this case could never be reached at all.
  if [ -e "$st/dedcom.db" ]; then
    blocked "a checkpoint already exists at '$st/dedcom.db' before the scan — this run cannot \
claim the provenance of a database it did not create"
    return 2
  fi
  if [ -d "$st" ]; then
    leftovers="$(ls -A -- "$st" 2>/dev/null | head -5 | tr '\n' ' ')"
    [ -z "$leftovers" ] || {
      blocked "the state directory '$st' is not empty before the scan ($leftovers) — this run \
cannot claim the provenance of anything it finds there"
      return 2; }
  fi
  return 0
}

# The exact command line this route intends to launch, built once and used both to record the
# intention beforehand and to check what actually ran afterwards.
scan_argv_expected() {
  local a out=""
  for a in "$G6_BIN" --state-dir "$G6_FIXTURE_ROOT/state" --scan "$G6_FIXTURE_ROOT/data" \
           --no-resume; do
    out="$out $(printf '%q' "$a")"
  done
  printf '%s' "${out# }"
}

# The durable binding, published BEFORE the scan: this argv, this binary, this checkpoint. A
# receipt written afterwards can only ever say what happened; this says what was about to happen,
# and the two have to agree for the checkpoint to be attributable to this run at all.
publish_invocation() {
  local st="$G6_FIXTURE_ROOT/state"
  { printf 'invocation\tproduction-scan\n'
    printf 'candidate\t%s\n' "$G6_BIN"
    printf 'candidate-sha256\t%s\n' "$(sha_of "$G6_BIN")"
    printf 'scan-argv\t%s\n' "$(scan_argv_expected)"
    printf 'checkpoint\t%s\n' "$st/dedcom.db"
    printf 'checkpoint-absent-before\tproved\n'
  } | "$G6_PUBLISH" --dir "$G6_WORK" --name INVOCATION >/dev/null 2>&1 \
    || { blocked "the invocation record could not be published before the scan"; return 2; }
  say "invocation recorded before the scan"
}

# What proves the checkpoint came from the product's own schema-creation path, as one contract
# rather than one field: the argv the guard actually launched, the binary that ran it — still the
# sanctioned one at the moment it produced this result — and the schema stamp AND product tables
# read back out of what it wrote. Every part is published durably as the production receipt,
# including the parts that failed.
publish_receipt() {  # scan-argv-file
  local st="$G6_FIXTURE_ROOT/state" argv_file="$1"
  local uv tables problems="" argv expect a t want got
  uv="$(python3 - "$st/dedcom.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(c.execute("PRAGMA user_version").fetchone()[0])
PY
)" || { blocked "cannot read the checkpoint for the receipt"; return 2; }
  tables="$(python3 - "$st/dedcom.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(",".join(sorted(r[0] for r in c.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"))))
PY
)" || { blocked "cannot list the checkpoint's tables"; return 2; }

  # The argv is compared, not merely quoted: the receipt must carry the exact command line the
  # guard launched, and that line must be the one this route meant to launch. A receipt that
  # agrees with itself proves only that one string was copied into another.
  [ -s "$argv_file" ] || { blocked "the guarded scan recorded no argv to build a receipt from"; return 2; }
  argv="$(head -n 1 "$argv_file")"
  expect="$(scan_argv_expected)"
  [ "$argv" = "$expect" ] \
    || problems="$problems; the recorded scan argv is not the route's own scan command line"

  # And against the record published BEFORE the scan. Two documents written after the fact can
  # agree with each other about anything at all.
  #
  # The seal is checked HERE, before the first field is taken out of the record, and not left to
  # the verifier at the end. A receipt built out of a record that does not verify is a receipt
  # published from something nobody trusted: the later check would report the corruption, and the
  # untrusted receipt would already exist. An INVOCATION that is not there at all is a different
  # thing, and stays the provenance problem it always was.
  local inv_argv="" inv_sha=""
  if [ -e "$G6_WORK/INVOCATION" ]; then
    "$G6_PUBLISH" --verify --dir "$G6_WORK" --name INVOCATION >/dev/null 2>&1 \
      || { blocked "the invocation record does not verify against its own seal"; return 2; }
    inv_argv="$(awk -F'\t' '$1 == "scan-argv" { print $2 }' "$G6_WORK/INVOCATION" 2>/dev/null)"
    inv_sha="$(awk -F'\t' '$1 == "candidate-sha256" { print $2 }' "$G6_WORK/INVOCATION" 2>/dev/null)"
  fi
  [ -n "$inv_argv" ] \
    || problems="$problems; there is no invocation record from before the scan to check against"
  [ -z "$inv_argv" ] || [ "$inv_argv" = "$argv" ] \
    || problems="$problems; the scan that ran is not the scan the invocation record announced"

  # The candidate is re-hashed HERE, after it produced the result. Verifying it on the way in and
  # never again would leave the whole window in which the checkpoint was actually written
  # unattested.
  want="$(sanction_field candidate-sha256)"; got="$(sha_of "$G6_BIN")"
  [ "$want" = "$got" ] \
    || problems="$problems; the candidate changed under the run: it now hashes to $got, the sanction pins $want"
  [ -z "$inv_sha" ] || [ "$inv_sha" = "$got" ] \
    || problems="$problems; the binary that scanned is not the binary the invocation record named"

  [ "$uv" = 5 ] || problems="$problems; user_version=$uv, the product's schema stamp is 5"

  # A stamp without the tables is a stamp on an empty room. Both halves, or the schema is not the
  # product's.
  local absent=""
  for t in scan file file_group dir_omission; do
    case ",$tables," in *",$t,"*) ;; *) absent="$absent $t" ;; esac
  done
  [ -z "$absent" ] \
    || problems="$problems; the checkpoint carries the stamp but not the product tables:$absent"

  {
    printf 'provenance\tinvocation-record + guarded-argv + candidate-sha256\n'
    printf 'provenance-not-from\tthe shape of the schema, which any writer can reproduce\n'
    printf 'candidate\t%s\n' "$G6_BIN"
    printf 'candidate-sha256\t%s\n' "$got"
    printf 'candidate-sha256-sanctioned\t%s\n' "$want"
    printf 'invocation-sha256\t%s\n' "$(sha_of "$G6_WORK/INVOCATION")"
    printf 'scan-argv\t%s\n' "$argv"
    printf 'scan-argv-expected\t%s\n' "$expect"
    printf 'checkpoint\t%s\n' "$st/dedcom.db"
    printf 'user_version\t%s\n' "$uv"
    printf 'tables\t%s\n' "$tables"
    printf 'ddl-written-by-harness\tnone\n'
    printf 'provenance-problems\t%s\n' "$( [ -n "$problems" ] && printf '%s' "${problems#; }" || printf 'none' )"
  } | "$G6_PUBLISH" --dir "$G6_WORK" --name RECEIPT >/dev/null 2>&1 \
    || { blocked "the production receipt could not be published"; return 2; }
  [ -z "$problems" ] || { printf 'provenance:%s\n' "$problems" >&2; return 1; }
  say "production receipt published (user_version=$uv)"
}

# ------------------------------------------------------------------ lifecycle entry

# Where the lifecycle actually stands, and what is left to do about it.
#
# The chain is durable, so "start at prepare" is a guess, not a fact. The library reports where
# the chain got to, and a human uses that to continue or to tear down. The controller does not
# resume a run on its own: the lifecycle steps and teardown remain available, the automatic
# re-entry does not.
G6_LIFECYCLE_WHY=""

lifecycle_to_mounted() {
  local out next step started=0
  out="$(bash "$G6_IMAGE_LIB" resume 2>&1)" || {
    printf '%s\n' "$out" >&2
    bash "$G6_IMAGE_LIB" inventory >&2
    G6_LIFECYCLE_WHY="the durable chain does not describe this machine"
    return 2; }
  next="$(printf '%s' "$out" | awk -F'\t' '$1 == "resume" { print $3 }')"
  next="${next#next=}"
  case "$next" in
    prepare|attach|format|mount) ;;
    *) bash "$G6_IMAGE_LIB" inventory >&2
       G6_LIFECYCLE_WHY="the chain is at '$next', which is not a step that leads to a mount"
       return 2 ;;
  esac
  for step in prepare attach format mount; do
    if [ "$started" = 0 ]; then
      [ "$step" = "$next" ] || continue
      started=1
      [ "$step" = prepare ] || say "resuming the lifecycle at '$step'"
    fi
    bash "$G6_IMAGE_LIB" "$step" || { G6_LIFECYCLE_WHY="$step"; return 2; }
  done
  return 0
}

# ------------------------------------------------------------------ the route

route() { route_common; }

route_common() {
  # PRESTART. The contour is settled BEFORE anything at all — before a directory is created,
  # before a stream is redirected into one, before the lifecycle is touched and before the
  # candidate is invoked. A contour check that runs after the first mkdir has already acted in
  # the contour it was about to reject. These exits are refusals, not verdicts: there is no run
  # yet to write a terminal record about.
  # PRESTART. Every read-only check happens here, and NOTHING in this phase creates anything:
  # no evidence directory, no state file, no terminal record, no image, no mountpoint, and the
  # candidate is not invoked once. That is not tidiness. A refusal routed through terminalize
  # would CREATE the very state it claims was never made — it writes RUNNING and then TERMINAL —
  # so the harness would contradict its own contract in the act of reporting it. There is no run
  # yet for a verdict to be about; these exits are refusals.
  verify_contour          || prestart_refusal "the contour was refused"
  [ -n "$G6_WORK" ]       || prestart_refusal "G6_WORK is not set"
  preflight_tools         || prestart_refusal "tool preflight refused"
  verify_sanction         || prestart_refusal "sanction refused"
  verify_calibration      || prestart_refusal "calibration refused"
  verify_candidate        || prestart_refusal "candidate refused"
  verify_bundle           || prestart_refusal "bundle refused"
  verify_resource_plan    || prestart_refusal "resource plan refused"
  assert_calibration_gone || prestart_refusal "calibration resources are still present"
  check_capacity full "$G6_REMOTE_ROOT" \
                          || prestart_refusal "capacity before the image was created"

  local outdir="$G6_WORK/scenarios"

  # A finished run is finished. The terminal state is consulted here — before the first
  # mutation and before the candidate is invoked even once — so a second run cannot start by
  # walking over the evidence of the first. Nothing has been touched at this point, and nothing
  # will be if the answer is no.
  #
  # The state and the record are checked against EACH OTHER, because the two ways of erasing a
  # finished run erase different halves of it. Deleting the terminal record leaves a state file
  # saying PUBLISHED; replacing the record with a properly sealed one of somebody else's leaves
  # a state file whose recorded digest no longer matches. Either half alone would let one of the
  # two through, and both refusals name which half was wrong.
  # Read into a variable, not into a file under the evidence directory: a query that has to
  # create the directory in order to report that nothing is in it has already answered its own
  # question wrongly. g6-publish-record.py makes no directories, so this is a pure read.
  local qrc=0 qout qstate qcode qrec
  qout="$("$G6_PUBLISH" --query-state --state-file "$G6_WORK/PUBSTATE" --dir "$G6_WORK" 2>&1)" \
    || qrc=$?
  qstate="$(printf '%s\n' "$qout" | awk -F'\t' '$1 == "STATE" { print $2 }')"
  qcode="$(printf '%s\n' "$qout" | awk -F'\t' '$1 == "STATE" { print $3 }')"
  qrec="$(printf '%s\n' "$qout" | awk -F'\t' '$1 == "RECORD" { print $2 }')"
  refuse_reentry() {  # reason
    [ -n "$qout" ] && printf '%s\n' "$qout" >&2
    # The inventory is part of the refusal, not a follow-up somebody has to ask for: a human
    # deciding what to do with an interrupted run needs to see what is on the machine.
    [ -n "${G6_IMAGE_LIB:-}" ] && bash "$G6_IMAGE_LIB" inventory >&2 2>/dev/null
    printf 'BLOCKED: %s; nothing was touched\n' "$1" >&2
    printf 'VERDICT\tBLOCKED\n'
    exit $RC_BLOCKED
  }
  if true; then
    if [ "$qstate" != NOT_STARTED ] || [ "$qrc" != 0 ] || [ -e "$G6_WORK/TERMINAL" ]; then
      # An unfinished run is BLOCKED with an inventory, and the candidate is NOT started again.
      # There was a controller-level `recover` here; it resumed on RUNNING without checking
      # whether a TERMINAL record already existed, so a run whose record was published and whose
      # state update then failed could be re-entered and the candidate invoked a second time over
      # the evidence of the first. Continuing an interrupted run is a decision for a human
      # holding the inventory, not a subcommand.
      [ "$qstate" != RUNNING ] \
        || refuse_reentry "this evidence directory carries a run that started and did not \
finish — what happens next is decided by a human reading the inventory below, not by starting \
the candidate again"
      { [ "$qstate" != NOT_STARTED ] || [ "$qrc" != 0 ]; } \
        || refuse_reentry "a terminal record is present while the state file reports NOT_STARTED \
— one of the two was removed"
      [ "$qrec" != missing ] || refuse_reentry "this evidence directory already carries a \
finished run (state $qstate, code $qcode) whose terminal record has been deleted"
      case "$qrec" in
        sha-mismatch|size-mismatch|unsealed|unreadable)
          refuse_reentry "this evidence directory already carries a finished run whose terminal \
record has been substituted ($qrec)" ;;
      esac
      # The record status is named even when nothing was wrong with it. A refusal that says only
      # "there was a run here" leaves the reader to guess whether the record behind it was
      # examined at all, and the answer is that it was.
      refuse_reentry "this evidence directory already carries a finished run (state $qstate, \
code $qcode, record ${qrec:-none})"
    fi
  fi

  # What the filesystem must be able to hold, handed to the steps that format it. mkfs cannot be
  # asked afterwards to add inodes.
  export G6_MIN_INODES=$(( G6_INODE_NEED + G6_INODE_RESERVE ))
  export G6_REQUESTED_INODES

  # THE BOUNDARY. From here the run is accountable: the state says RUNNING durably, so a process
  # killed at any point after this line leaves a directory that says a run started and did not
  # finish — instead of one that looks untouched. On a fresh entry this is also the last moment
  # at which nothing has been changed.
  mkdir -p "$G6_WORK" || prestart_refusal "cannot create the evidence directory"
  if true; then
    "$G6_PUBLISH" --begin --state-file "$G6_WORK/PUBSTATE" > "$G6_WORK/begin.out" 2>&1 \
      || { cat "$G6_WORK/begin.out" >&2
           printf 'BLOCKED: the run could not announce itself; nothing was touched\n' >&2
           printf 'VERDICT\tBLOCKED\n'; exit $RC_BLOCKED; }
  fi

  # A signal is an outcome too, and from the boundary onwards it is a VERDICT rather than a
  # refusal. Without this the shell dies where it stands and the evidence directory is left
  # saying RUNNING for ever, which is the one state nobody can classify later.
  trap 'G6_RAW_SIGNAL=INT  terminalize BLOCKED "the run was interrupted by SIGINT"'  INT
  trap 'G6_RAW_SIGNAL=TERM terminalize BLOCKED "the run was interrupted by SIGTERM"' TERM
  trap 'G6_RAW_SIGNAL=HUP  terminalize BLOCKED "the run was interrupted by SIGHUP"'  HUP

  G6_MUTATED=1
  lifecycle_to_mounted || terminalize BLOCKED "lifecycle: $G6_LIFECYCLE_WHY"

  # And again the moment the filesystem exists, because what mkfs actually produced — not what it
  # was asked for — is the first time the inode total is a fact.
  check_capacity full "$G6_REMOTE_ROOT" "$G6_FIXTURE_ROOT" \
    || terminalize BLOCKED "capacity after mkfs, before generation"

  # The hook is a generated executable carrying the exact paths, so the generator invokes ONE
  # program with no arguments and there is no word splitting anywhere in the chain.
  local hook="$G6_WORK/capacity-hook"
  write_capacity_hook "$hook" "$G6_REMOTE_ROOT" "$G6_FIXTURE_ROOT" \
    || terminalize BLOCKED "cannot prepare the capacity hook"

  local g m u b seed
  g="$(sanction_field scale-G)"; m="$(sanction_field scale-M)"; u="$(sanction_field scale-U)"
  b="$(sanction_field scale-B)"; seed="$(sanction_field scale-seed)"
  env G6_G="$g" G6_M="$m" G6_U="$u" G6_B="$b" G6_SEED="$seed" G6_CAPACITY_HOOK="$hook" \
      G6_BATCH="$G6_BATCH" \
      bash "$G6_MAKE_FIXTURE" --mode "$MODE" --root "$G6_FIXTURE_ROOT" \
    || terminalize BLOCKED "generation did not complete"

  assert_fresh_checkpoint \
    || terminalize BLOCKED "provenance: a checkpoint predates this run's scan"
  mkdir -p "$G6_FIXTURE_ROOT/state"
  G6_STOPPED_AT=INVOCATION
  publish_invocation || terminalize BLOCKED "provenance: the invocation could not be recorded"
  G6_STOPPED_AT=SCAN
  guarded_run "$G6_SCAN_GUARD" SCAN "$outdir" -- \
    "$G6_BIN" --state-dir "$G6_FIXTURE_ROOT/state" --scan "$G6_FIXTURE_ROOT/data" --no-resume
  case "$G6_LAST_CLASS" in
    OK) say "production scan complete" ;;
    CANDIDATE_NONZERO|CANDIDATE_TIMEOUT)
       terminalize FAIL "the production scan failed on valid input ($G6_LAST_CLASS)" ;;
    *) terminalize BLOCKED "the production scan was interrupted ($G6_LAST_CLASS)" ;;
  esac

  # The receipt quotes the argv the guard actually launched, not a line printed alongside it.
  G6_STOPPED_AT=RECEIPT
  local prc=0
  publish_receipt "$outdir/SCAN.argv" || prc=$?
  case "$prc" in
    0) ;;
    1) terminalize FAIL "provenance: the checkpoint does not satisfy the production receipt's \
contract (see RECEIPT: provenance-problems)" ;;
    *) terminalize BLOCKED "the production receipt could not be published" ;;
  esac

  # The verifier's own status, captured before anything else can overwrite $?. Its absence is a
  # tooling question and is settled BEFORE it runs: a shell that cannot find the program exits
  # 127, and 127 read as "the verifier disagreed with the counts" would turn a missing file into
  # a verdict about the candidate.
  G6_STOPPED_AT=VERIFY
  [ -x "$G6_VERIFY_COUNTS" ] \
    || terminalize BLOCKED "the independent verifier '$G6_VERIFY_COUNTS' is not executable"
  local vrc=0
  "$G6_VERIFY_COUNTS" --db "$G6_FIXTURE_ROOT/state/dedcom.db" \
      --groups "$g" --members-per-group "$m" --singletons "$u" \
      --receipt "$G6_WORK/RECEIPT" --invocation "$G6_WORK/INVOCATION" \
      > "$G6_WORK/verify.out" 2>&1 || vrc=$?
  if [ "$vrc" != 0 ]; then
    cat "$G6_WORK/verify.out" >&2
    case "$vrc" in
      2) terminalize BLOCKED "the verifier could not read the checkpoint" ;;
      *) terminalize FAIL "the counts contradict the derived formulas" ;;
    esac
  fi
  say "independent verifier passed"

  # The stage's output is a log and goes to a log. Its verdict comes back from the durable file
  # it wrote, so however many lines the guards printed, the answer is the same one.
  G6_STOPPED_AT=SCENARIOS
  rm -f "$outdir/VERDICT" "$outdir/REASON" "$outdir/STOPPED-AT" "$outdir/POSTCONDITIONS"
  run_scenarios "$outdir" > "$G6_WORK/scenarios.log" 2>&1
  cat "$G6_WORK/scenarios.log"
  [ -f "$outdir/STOPPED-AT" ] && G6_STOPPED_AT="$(head -n 1 "$outdir/STOPPED-AT")"
  local sverdict sreason
  sverdict="$(read_scenario_verdict "$outdir")"
  sreason="$(read_scenario_reason "$outdir")"
  terminalize "$sverdict" "scenarios: $sreason"
}

# ------------------------------------------------------------------ dispatch

parse_mode() {
  case "${1:-}" in --mode) MODE="${2:-}" ;; *) MODE="" ;; esac
  case "$MODE" in
    live|rehearsal) return 0 ;;
    '') refused "--mode is required and has no default: say live or rehearsal"; return 1 ;;
    *) refused "--mode '$MODE' is neither live nor rehearsal"; return 1 ;;
  esac
}

cmd="${1:-}"; shift 2>/dev/null || true
case "$cmd" in
  bundle)          bundle_manifest; printf 'bundle-sha256\t%s\n' "$(bundle_sha)" ;;
  preflight)       preflight_tools ;;
  contour)         parse_mode "$@" || exit $RC_BLOCKED; verify_contour ;;
  check-sanctions) parse_mode "$@" || exit $RC_BLOCKED
                   verify_contour && verify_sanction && verify_calibration && verify_candidate \
                     && verify_bundle && verify_resource_plan ;;
  capacity-hook)   check_capacity reserve "${1:?outside dir}" "${2:-}" ;;
  capacity-full)   check_capacity full "${1:?outside dir}" "${2:-}" ;;
  dry-route)       parse_mode "$@" || exit $RC_BLOCKED
                   verify_sanction >/dev/null && verify_calibration >/dev/null \
                     || { refused "the dry route is not printed before the sanctions verify"; exit $RC_BLOCKED; }
                   dry_route ;;
  calibrate)       parse_mode "$@" || exit $RC_BLOCKED; shift 2; calibrate "${1:?out manifest}" ;;
  guarded)         guarded_run "$@" ;;
  classify)        class_verdict "${1:-}" ;;
  route)           parse_mode "$@" || exit $RC_BLOCKED; route ;;
  teardown)        parse_mode "$@" || exit $RC_BLOCKED
                   say "teardown is a separate decision, taken after the result was read"
                   bash "$G6_IMAGE_LIB" teardown ;;
  *) printf 'usage: %s bundle|preflight|contour|check-sanctions|capacity-hook|dry-route|calibrate|guarded|classify|route|teardown [--mode live|rehearsal]\n' "$0" >&2
     exit $RC_BLOCKED ;;
esac
