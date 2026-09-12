#!/usr/bin/env bash
# Regression tests for the safety-critical guard in teardown-test-pool.sh and the safety
# functions in testpool-lib.sh. Stubs `zpool` and `zfs` — real ZFS is NOT needed.
#
# Since the shared-host containment change the library refuses to be sourced without a valid
# DEDCOM_E2E_ROOT and DEDCOM_E2E_OWNER_UID, and teardown refuses to destroy a pool whose name,
# GUID, leaf-vdevs and dataset mountpoints do not still match the manifest written at create
# time. Both are exercised here: every scenario runs inside one disposable root, each with its
# own pool name, and the stubs answer the identity queries the guard now makes.
#
# Checks that depend on POSIX permission semantics and real symlinks are SKIPPED where that is
# unattainable (git-bash on Windows). On Linux — all of them run.
#
# Run:  bash scripts/test-teardown-guard.sh
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEARDOWN="$HERE/teardown-test-pool.sh"
LIB="$HERE/testpool-lib.sh"

PASS=0; FAIL=0; SKIP=0; N=0
ok()   { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }
skip() { SKIP=$((SKIP+1)); printf 'SKIP  %s (%s)\n' "$1" "$2"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK" "${E2E:-}"' EXIT
BIN="$WORK/bin"; mkdir -p "$BIN"
DLOG="$WORK/destroy.log"

# ---------------------------------------------------------------- stubs
# zpool stub. Behaviour via env: FIX_PRESENT + FIX_POOLNAME (the tri-state full enumeration
# prints FIX_POOLNAME when FIX_PRESENT=1 and nothing when 0), FIX_ENUM_RC (non-zero fails the
# enumeration itself), FIX_LIST_RC + FIX_VDEV (the verbose leaf-vdev query), FIX_DESTROY_RC,
# FIX_STATUS_RC + FIX_STATUS (the `zpool status -P` view the guard reads the untruncated
# path from), FIX_GUID / FIX_GUID_RC.
cat > "$BIN/zpool" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "list" ]; then
  shift
  verbose=0
  for a in "$@"; do case "$a" in -*v*) verbose=1;; esac; done
  if [ "$verbose" = "1" ]; then
    printf '%b' "${FIX_VDEV:-}"
    exit "${FIX_LIST_RC:-0}"
  fi
  [ "${FIX_ENUM_RC:-0}" = "0" ] || exit "${FIX_ENUM_RC}"
  if [ "${FIX_PRESENT:-1}" = "1" ] && [ -n "${FIX_POOLNAME:-}" ]; then
    printf '%s\n' "$FIX_POOLNAME"
  fi
  exit 0
elif [ "$1" = "status" ]; then
  [ "${FIX_STATUS_RC:-0}" = "0" ] || exit "${FIX_STATUS_RC}"
  printf '%b' "${FIX_STATUS:-}"
  exit 0
elif [ "$1" = "get" ]; then
  [ "${FIX_GUID_RC:-0}" = "0" ] || exit "${FIX_GUID_RC}"
  printf '%s\n' "${FIX_GUID:-1111111111111111111}"
  exit 0
elif [ "$1" = "destroy" ]; then
  echo "STUB-DESTROY $2" >> "${STUB_DESTROY_LOG:-/dev/null}"
  exit "${FIX_DESTROY_RC:-0}"
fi
exit 0
STUB
chmod +x "$BIN/zpool"

# zfs stub: only the dataset listing the guard needs.
cat > "$BIN/zfs" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "list" ]; then
  [ "${FIX_DS_RC:-0}" = "0" ] || exit "${FIX_DS_RC}"
  printf '%b' "${FIX_DS:-}"
  exit 0
fi
exit 0
STUB
chmod +x "$BIN/zfs"

# ---------------------------------------------------------------- probes
probe="$WORK/probe"; mkdir -p "$probe"; chmod 0707 "$probe" 2>/dev/null || true
posix_perms=no
if [ "$(stat -c '%a' "$probe" 2>/dev/null)" = "707" ]; then posix_perms=yes; fi

ln_ok=no
if ln -s "$probe" "$WORK/lnprobe" 2>/dev/null && [ -L "$WORK/lnprobe" ]; then ln_ok=yes; fi
rm -f "$WORK/lnprobe" 2>/dev/null || true

# The containment root needs a clean chain (no world-writable ancestor), which /tmp is not.
E2E=""
for cand in /var/lib /run /root "$HOME"; do
  if [ ! -d "$cand" ] || [ ! -w "$cand" ]; then continue; fi
  c="$(mktemp -d "$cand/dedcom-e2e-tg.XXXXXX" 2>/dev/null)" || continue
  chmod 0700 "$c" 2>/dev/null || true
  if [ "$posix_perms" = yes ] &&
     DEDCOM_E2E_ROOT="$c" DEDCOM_E2E_OWNER_UID="$(id -u)" \
       bash -c '. "$1"' _ "$LIB" >/dev/null 2>&1; then
    E2E="$c"; break
  fi
  rmdir "$c" 2>/dev/null || rm -rf "$c"
done

if [ -z "$E2E" ]; then
  skip "every teardown-guard scenario" "no clean-chain containment root available here"
  echo "== result: PASS=$PASS FAIL=$FAIL SKIP=$SKIP =="
  [ "$FAIL" -eq 0 ]; exit
fi

UID_NOW="$(id -u)"
export DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW"
mkdir -p -m 0700 "$E2E/pools"

lib_call() { DEDCOM_TESTPOOL_NAME="$1" bash -c '. "$1"; "$2"' _ "$LIB" "$2" >/dev/null 2>&1; }

GUID_OK=1111111111111111111

# Write the manifest teardown re-verifies. Fields mirror what the stubs will answer.
mkmanifest() {  # dir pool guid canon dsrows
  local dir="$1" pool="$2" guid="$3" canon="$4" ds="$5"
  {
    printf 'root\t%s\n'  "$E2E"
    printf 'pool\t%s\n'  "$pool"
    printf 'guid\t%s\n'  "$guid"
    printf 'image\t%s\n' "$canon"
    printf 'mount\t%s\n' "$dir/mount"
    printf 'vdev\t%s\n'  "$canon"
    printf '%b' "$ds"
  } > "$dir/manifest.txt"
}

# One `zpool status -P` config block in the shape the real command prints: a leading TAB on every
# config row, the pool at indent 0, each leaf at indent 2.
mkstatus() {  # pool leaf...
  local pool="$1"; shift
  printf '  pool: %s\n state: ONLINE\nconfig:\n\n' "$pool"
  printf '\tNAME                 STATE     READ WRITE CKSUM\n'
  printf '\t%s                 ONLINE       0     0     0\n' "$pool"
  local leaf
  for leaf in "$@"; do printf '\t  %s  ONLINE       0     0     0\n' "$leaf"; done
  printf '\nerrors: No known data errors\n'
}

# scenario LABEL PRESENT LISTRC DESTRC VDEV MKIMG WANT_EC WANT_DESTROY WANT_IMG [SYMLINK] [STATUS] [STATUSRC]
#
# STATUS defaults to the view that AGREES with a healthy single-image pool; a case that wants the
# two kernel views to disagree passes its own. @IMGCUT@ is the image path with its last four
# characters cut off — what `zpool list -v` does to a path longer than 63 characters.
scenario() {
  local label="$1" present="$2" listrc="$3" destrc="$4" vdev="$5" mkimg="$6"
  local wec="$7" wdes="$8" wimg="$9" symlink="${10:-no}" status="${11:-}" statusrc="${12:-0}"
  N=$((N+1))
  local pool="tp$N"
  local dir="$E2E/pools/$pool"; mkdir -p "$dir/mount"; chmod 0700 "$dir" "$dir/mount" 2>/dev/null || true
  local img="$dir/pool.img" canon target=""
  if [ "$symlink" = "yes" ]; then
    target="$dir/real-target"; : > "$target"; ln -s "$target" "$img"
    canon="$(readlink -f "$img")"
  else
    canon="$(readlink -f "$img" 2>/dev/null || echo "$img")"
    if [ "$mkimg" = "yes" ]; then : > "$img"; fi
  fi
  local cut="${canon%????}"
  local vd="${vdev//@IMG@/$canon}"
  vd="${vd//@SUM@/$pool}"; vd="${vd//@IMGCUT@/$cut}"
  local st="$status"
  if [ -z "$st" ]; then st="$(mkstatus "$pool" "$canon")"; fi
  st="${st//@IMG@/$canon}"; st="${st//@SUM@/$pool}"; st="${st//@IMGCUT@/$cut}"
  local ds; ds="$(printf 'dataset\t%s\t%s\ndataset\t%s\t%s\n' "$pool" "$dir/mount" "$pool/ds_a" "$dir/mount/ds_a")"
  mkmanifest "$dir" "$pool" "$GUID_OK" "$canon" "$ds"
  local dslist; dslist="$(printf '%s\t%s\n%s\t%s\n' "$pool" "$dir/mount" "$pool/ds_a" "$dir/mount/ds_a")"
  : > "$DLOG"
  local out ec
  out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_NAME="$pool" \
         FIX_PRESENT="$present" FIX_POOLNAME="$pool" \
         FIX_LIST_RC="$listrc" FIX_DESTROY_RC="$destrc" FIX_VDEV="$vd" \
         FIX_STATUS="$st" FIX_STATUS_RC="$statusrc" \
         FIX_GUID="$GUID_OK" FIX_DS="$dslist\n" \
         bash "$TEARDOWN" 2>&1)"; ec=$?
  local des=no
  if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then des=yes; fi
  local watch="$img"
  if [ "$symlink" = "yes" ]; then watch="$target"; fi
  local imgstate=gone
  if [ -e "$watch" ]; then imgstate=exists; fi
  local err=""
  if [ "$ec"  != "$wec"  ]; then err="$err ec=$ec(want $wec)"; fi
  if [ "$des" != "$wdes" ]; then err="$err destroy=$des(want $wdes)"; fi
  if [ "$wimg" != "na" ] && [ "$imgstate" != "$wimg" ]; then err="$err img=$imgstate(want $wimg)"; fi
  if [ -z "$err" ]; then ok "$label"; else fail "$label" "$err"$'\n'"$out"; fi
}

echo "== teardown guard scenarios =="
# Each scenario owns a pool named tp<N>; @SUM@ in a vdev fixture becomes that name, so adding
# or removing a scenario can never desynchronize the summary row from the pool under test.

scenario "legit single-image (name-only) -> destroy + remove" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  0 yes gone

scenario "mirror container -> refuse" \
  1 0 0 "@SUM@\n\tmirror-0\n\t@IMG@\n\t/dev/sdb\n" yes  1 no exists

scenario "real disk only (same name) -> refuse" \
  1 0 0 "@SUM@\n\t/dev/sdb\n" yes  1 no exists

scenario "our image + extra stripe disk -> refuse" \
  1 0 0 "@SUM@\n\t@IMG@\n\t/dev/sdb\n" yes  1 no exists

scenario "summary has extra TAB field -> refuse" \
  1 0 0 "@SUM@\tMALFORMED\n\t@IMG@\n" yes  1 no exists

# ZFS 2.3+: the detailed vdev row under -v carries property columns (SIZE … HEALTH) AFTER the
# name, ignoring -o name. We take the name from $2 and ignore the tail -> destroy.
scenario "ZFS 2.3 vdev row carries property columns -> destroy" \
  1 0 0 "@SUM@\n\t@IMG@\t2G\t252M\t1.63G\t-\t-\t3%\t13.1%\t-\tONLINE\n" yes  0 yes gone

# The image file is real (require_real_image passes), but the CANONICAL path of the actual vdev
# fails (the parent doesn't exist) -> refuse without destroy (no fallback to the raw path).
scenario "actual vdev canon fails -> refuse" \
  1 0 0 "@SUM@\n\t/nonexistent-dedcom-canon-probe/pool.img\n" yes  1 no exists

scenario "garbage row (no leading tab) -> refuse" \
  1 0 0 "@SUM@\nTHIS_IS_NOT_A_VDEV\n" yes  1 no exists

scenario "logs section header -> refuse" \
  1 0 0 "@SUM@\n\t@IMG@\nlogs\n\t/dev/sdb\n" yes  1 no exists

scenario "list exits 1 but prints path -> refuse (fail-closed)" \
  1 1 0 "@SUM@\n\t@IMG@\n" yes  1 no exists

# Since the tri-state change an absent pool WITH artifacts on disk is BLOCKED, not a noop:
# there is no pool left to verify the artifacts against, so nothing may be deleted by path.
scenario "pool absent + residue on disk -> BLOCKED, image untouched" \
  0 0 0 "" yes  1 no exists

# The clean noop needs its own setup: the pool is absent AND its directory never existed.
N=$((N+1)); np_pool="tp$N"
: > "$DLOG"
np_out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_NAME="$np_pool" \
          FIX_PRESENT=0 FIX_POOLNAME="$np_pool" \
          bash "$TEARDOWN" 2>&1)"; np_ec=$?
np_des=no; if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then np_des=yes; fi
if [ "$np_ec" = 0 ] && [ "$np_des" = no ] && [ ! -e "$E2E/pools/$np_pool" ]; then
  ok "pool absent + no artifacts -> clean noop 0"
else
  fail "pool absent + no artifacts -> clean noop 0" "ec=$np_ec destroy=$np_des"$'\n'"$np_out"
fi

# A failed enumeration is `unknown`, and unknown licenses NOTHING — not even the noop.
N=$((N+1)); uk_pool="tp$N"; uk_dir="$E2E/pools/$uk_pool"; mkdir -p "$uk_dir/mount"
chmod 0700 "$uk_dir" "$uk_dir/mount" 2>/dev/null || true
: > "$uk_dir/pool.img"
: > "$DLOG"
uk_out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_NAME="$uk_pool" \
          FIX_ENUM_RC=2 \
          bash "$TEARDOWN" 2>&1)"; uk_ec=$?
uk_des=no; if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then uk_des=yes; fi
if [ "$uk_ec" != 0 ] && [ "$uk_des" = no ] && [ -e "$uk_dir/pool.img" ]; then
  ok "pool enumeration fails -> BLOCKED, nothing destroyed, artifacts kept"
else
  fail "pool enumeration fails -> BLOCKED, nothing destroyed, artifacts kept" \
       "ec=$uk_ec destroy=$uk_des"$'\n'"$uk_out"
fi

scenario "failed destroy -> image preserved" \
  1 0 1 "@SUM@\n\t@IMG@\n" yes  1 yes exists

scenario "image missing (pool present) -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" no  1 no na

if [ "$ln_ok" = yes ]; then
  scenario "image is symlink (to file) -> REFUSE, no destroy" \
    1 0 0 "@SUM@\n\t@IMG@\n" no  1 no exists yes
else
  skip "image is symlink (to file) -> REFUSE, no destroy" "symlinks unsupported here"
fi

echo "== identity guard: GUID, datasets, containment =="

# One helper for the identity cases: a legitimate-looking pool whose manifest and stub answers
# are made to disagree in exactly one place.
identity_case() {  # label guid_stub ds_stub want_ec want_destroy
  local label="$1" guid="$2" ds="$3" wec="$4" wdes="$5"
  N=$((N+1))
  local pool="tp$N"
  local dir="$E2E/pools/$pool"; mkdir -p "$dir/mount"; chmod 0700 "$dir" "$dir/mount" 2>/dev/null || true
  local img="$dir/pool.img"; : > "$img"
  local canon; canon="$(readlink -f "$img")"
  local mds; mds="$(printf 'dataset\t%s\t%s\ndataset\t%s\t%s\n' "$pool" "$dir/mount" "$pool/ds_a" "$dir/mount/ds_a")"
  mkmanifest "$dir" "$pool" "$GUID_OK" "$canon" "$mds"
  : > "$DLOG"
  local out ec
  out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_NAME="$pool" \
         FIX_PRESENT=1 FIX_POOLNAME="$pool" \
         FIX_LIST_RC=0 FIX_DESTROY_RC=0 FIX_VDEV="$pool\n\t$canon\n" \
         FIX_STATUS="$(mkstatus "$pool" "$canon")" \
         FIX_GUID="$guid" FIX_DS="$(printf "$ds" "$pool" "$dir/mount" "$pool" "$dir/mount")\n" \
         bash "$TEARDOWN" 2>&1)"; ec=$?
  local des=no
  if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then des=yes; fi
  local err=""
  if [ "$ec"  != "$wec"  ]; then err="$err ec=$ec(want $wec)"; fi
  if [ "$des" != "$wdes" ]; then err="$err destroy=$des(want $wdes)"; fi
  if [ -z "$err" ]; then ok "$label"; else fail "$label" "$err"$'\n'"$out"; fi
}


echo "== the two kernel views of one leaf-vdev =="
# `zpool list -v` cuts a vdev path at 63 characters (measured on OpenZFS 2.4.3), so on a long
# image path the list view alone can never confirm the pool and teardown refused forever. The PATH
# now comes from `zpool status -P`; the list view still decides the TOPOLOGY, and the two views
# must agree — same leaf count, list name a prefix of the status path.

scenario "list truncates the path, status has it whole -> destroy" \
  1 0 0 "@SUM@\n\t@IMGCUT@\n" yes  0 yes gone

scenario "status names a different file -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  /root/not-our-image.img  ONLINE       0     0     0\n\nerrors: No known data errors\n"

scenario "status shows one leaf more than list -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  @IMG@  ONLINE       0     0     0\n\t  /root/second.img  ONLINE       0     0     0\n\nerrors: No known data errors\n"

scenario "status query fails -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no "" 1

scenario "status wraps the leaf in a mirror -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  mirror-0  ONLINE       0     0     0\n\t    @IMG@  ONLINE       0     0     0\n\nerrors: No known data errors\n"

scenario "status names another pool -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: someother\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\tsomeother  ONLINE       0     0     0\n\t  @IMG@  ONLINE       0     0     0\n\nerrors: No known data errors\n"

scenario "status carries a logs section -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  @IMG@  ONLINE       0     0     0\n\tlogs\t\n\t  /root/log.img  ONLINE       0     0     0\n\nerrors: No known data errors\n"

scenario "status has no config block -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\n"

scenario "status extends the truncated path into a sibling -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMGCUT@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  @IMG@.bak  ONLINE       0     0     0\n\nerrors: No known data errors\n"

scenario "status lists a leaf before the pool row -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t  /root/not-our-image.img  ONLINE       0     0     0\n\t@SUM@  ONLINE       0     0     0\n\nerrors: No known data errors\n"

scenario "status carries a second config block -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  @IMG@  ONLINE       0     0     0\n\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t  /root/second.img  ONLINE       0     0     0\n"

scenario "status repeats the header after a blank line -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  @IMG@  ONLINE       0     0     0\n\n\tNAME  STATE     READ WRITE CKSUM\n\t  /root/second.img  ONLINE       0     0     0\n"

scenario "status names a leaf with a space in it -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  /root/my pool/pool.img  ONLINE       0     0     0\n\nerrors: No known data errors\n"

scenario "status row without a STATE column -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  ONLINE       0     0     0\n\t  @IMG@\n\nerrors: No known data errors\n"

scenario "status names the missing device by GUID -> REFUSE, no destroy" \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  1 no exists no \
  "  pool: @SUM@\n state: DEGRADED\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\t@SUM@  DEGRADED     0     0     0\n\t  10806766978193310897  UNAVAIL      0     0     0  was @IMG@\n\nerrors: No known data errors\n"

echo "== mutations: the guards this change adds must each be a kill =="
# A guard no test can tell from its absence is not a guard. Each mutation below deletes exactly
# one rule in a COPY of testpool-lib.sh and re-runs the scenario that rule exists for, requiring
# the opposite outcome. Only rules whose removal actually changes what teardown DOES are listed:
# the parser's remaining shape rules are defence in depth behind the exact image compare, and
# they are proved one by one in the shape cases above instead of being given a fake kill here.
MUTN=0
line_sub() {  # file whole-line-from whole-line-to  -> 0 if exactly that line was replaced
  local file="$1" from="$2" to="$3" n
  n="$(grep -nxF -- "$from" "$file" | head -1 | cut -d: -f1)"
  [ -n "$n" ] || return 1
  TO="$to" awk -v n="$n" 'NR == n { print ENVIRON["TO"]; next } { print }' "$file" > "$file.mut" \
    && mv "$file.mut" "$file"
}
mut_scenario() {  # label from to  <the scenario args, with the expectations INVERTED>
  local label="$1" from="$2" to="$3"; shift 3
  MUTN=$((MUTN+1))
  local d="$WORK/mut-$MUTN"; rm -rf "$d"; mkdir -p "$d"
  cp "$HERE"/*.sh "$d/" 2>/dev/null
  if ! line_sub "$d/testpool-lib.sh" "$from" "$to"; then
    fail "$label" "the line this mutation targets is no longer in testpool-lib.sh"; return
  fi
  if ! bash -n "$d/testpool-lib.sh" 2>/dev/null; then
    fail "$label" "the mutant does not parse — the substitution broke the syntax"; return
  fi
  local saved="$TEARDOWN"; TEARDOWN="$d/teardown-test-pool.sh"
  scenario "$label" "$@"
  TEARDOWN="$saved"
}

# Without the status view the path comes back cut at 63 characters, and the long-path pool that
# this whole change exists to remove stops being removable again.
mut_scenario "mutation: status view replaced by the truncated list view -> the long path stops being confirmable" \
  '    full="$(tp_pool_status_vdevs "$pool")" || {' \
  '    full="$out" || {' \
  1 0 0 "@SUM@\n\t@IMGCUT@\n" yes  1 no exists

# Without the pool-name rule a config block that belongs to SOMEONE ELSE'S pool is read as ours,
# and because it names our image the destroy then goes through.
mut_scenario "mutation: the status pool-name rule removed -> another pool's config block licenses the destroy" \
  '                if (name != pool) { printf("REFUSED: status names pool «%s», expected «%s»\n", name, pool) > "/dev/stderr"; bail = 3; exit bail }' \
  '                if (0) { printf("REFUSED: status names pool «%s», expected «%s»\n", name, pool) > "/dev/stderr"; bail = 3; exit bail }' \
  1 0 0 "@SUM@\n\t@IMG@\n" yes  0 yes gone no \
  "  pool: someother\n state: ONLINE\nconfig:\n\n\tNAME  STATE     READ WRITE CKSUM\n\tsomeother  ONLINE       0     0     0\n\t  @IMG@  ONLINE       0     0     0\n\nerrors: No known data errors\n"

identity_case "matching identity -> destroy" \
  "$GUID_OK" '%s\t%s\n%s/ds_a\t%s/ds_a\n' 0 yes

identity_case "GUID changed since create -> REFUSE, no destroy" \
  2222222222222222222 '%s\t%s\n%s/ds_a\t%s/ds_a\n' 1 no

identity_case "dataset set changed since create -> REFUSE, no destroy" \
  "$GUID_OK" '%s\t%s\n%s/ds_a\t%s/ds_a\n%s/ds_c\t%s/ds_c\n' 1 no

N=$((N+1))
esc_pool="tp$N"; esc_dir="$E2E/pools/$esc_pool"; mkdir -p "$esc_dir/mount"
chmod 0700 "$esc_dir" "$esc_dir/mount" 2>/dev/null || true
: > "$esc_dir/pool.img"; esc_canon="$(readlink -f "$esc_dir/pool.img")"
mkmanifest "$esc_dir" "$esc_pool" "$GUID_OK" "$esc_canon" \
  "$(printf 'dataset\t%s\t%s\n' "$esc_pool" "/dedcom-escaped")"
: > "$DLOG"
esc_out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_NAME="$esc_pool" \
           FIX_PRESENT=1 FIX_POOLNAME="$esc_pool" \
           FIX_LIST_RC=0 FIX_DESTROY_RC=0 FIX_VDEV="$esc_pool\n\t$esc_canon\n" \
           FIX_STATUS="$(mkstatus "$esc_pool" "$esc_canon")" \
           FIX_GUID="$GUID_OK" FIX_DS="$(printf '%s\t/dedcom-escaped\n' "$esc_pool")" \
           bash "$TEARDOWN" 2>&1)"; esc_ec=$?
esc_des=no; if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then esc_des=yes; fi
# The status view has to be the agreeing one, or this case refuses at the two-view step and never
# reaches the mountpoint check it exists for: a test that refuses for the wrong reason is a dead
# test. That is also why the reason is asserted, not just the refusal.
if [ "$esc_ec" = 1 ] && [ "$esc_des" = no ] && grep -qi "is mounted at .*, outside" <<<"$esc_out"; then
  ok "dataset mounted outside the root -> REFUSE, no destroy"
else
  fail "dataset mounted outside the root -> REFUSE, no destroy" "ec=$esc_ec destroy=$esc_des"$'\n'"$esc_out"
fi

N=$((N+1))
ug_pool="tp$N"; ug_dir="$E2E/pools/$ug_pool"; mkdir -p "$ug_dir/mount"
chmod 0700 "$ug_dir" "$ug_dir/mount" 2>/dev/null || true
: > "$ug_dir/pool.img"; ug_canon="$(readlink -f "$ug_dir/pool.img")"
mkmanifest "$ug_dir" "$ug_pool" "$GUID_OK" "$ug_canon" \
  "$(printf 'dataset\t%s\t%s\n' "$ug_pool" "$ug_dir/mount")"
: > "$DLOG"
ug_out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_NAME="$ug_pool" \
          FIX_PRESENT=1 FIX_POOLNAME="$ug_pool" \
          FIX_LIST_RC=0 FIX_DESTROY_RC=0 FIX_VDEV="$ug_pool\n\t$ug_canon\n" \
          FIX_STATUS="$(mkstatus "$ug_pool" "$ug_canon")" \
          FIX_GUID_RC=1 FIX_DS="$(printf '%s\t%s\n' "$ug_pool" "$ug_dir/mount")" \
          bash "$TEARDOWN" 2>&1)"; ug_ec=$?
ug_des=no; if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then ug_des=yes; fi
# Same reasoning as above: with no status view this case proved only that an empty `zpool status`
# refuses, which another case already proves. The GUID query is what it is here to exercise.
if [ "$ug_ec" = 1 ] && [ "$ug_des" = no ] && grep -qi "GUID unreadable\|could not read the GUID" <<<"$ug_out"; then
  ok "GUID query fails -> REFUSE, no destroy (fail-closed)"
else
  fail "GUID query fails -> REFUSE, no destroy (fail-closed)" "ec=$ug_ec destroy=$ug_des"$'\n'"$ug_out"
fi

echo "== testpool-lib safety units =="

if lib_call ai_clean tp_assert_image_absent; then
  ok "tp_assert_image_absent: clean -> ok"
else
  fail "tp_assert_image_absent: clean -> ok"
fi

mkdir -p "$E2E/pools/ai_taken"; : > "$E2E/pools/ai_taken/pool.img"
if lib_call ai_taken tp_assert_image_absent; then
  fail "tp_assert_image_absent: existing image -> refuse"
else
  ok "tp_assert_image_absent: existing image -> refuse"
fi

if lib_call sd_ok tp_secure_dir && [ "$(stat -c '%a' "$E2E/pools/sd_ok" 2>/dev/null)" = 700 ]; then
  ok "tp_secure_dir: fresh -> created 0700"
else
  fail "tp_secure_dir: fresh -> created 0700" "mode=$(stat -c '%a' "$E2E/pools/sd_ok" 2>/dev/null)"
fi

ex="$E2E/pools/sd_exists"; mkdir -p "$ex"; chmod 0755 "$ex"
before="$(stat -c '%a' "$ex" 2>/dev/null)"
secured=yes
if ! lib_call sd_exists tp_secure_dir; then secured=no; fi
after="$(stat -c '%a' "$ex" 2>/dev/null)"
if [ "$secured" = no ] && [ "$before" = "$after" ]; then
  ok "tp_secure_dir: existing dir -> refuse, mode unchanged ($after)"
else
  fail "tp_secure_dir: existing dir -> refuse, mode unchanged" "secured=$secured before=$before after=$after"
fi

if [ "$ln_ok" = yes ]; then
  mkdir -p "$E2E/pools/sl_real_x"
  if ln -s "$E2E/pools/sl_real_x" "$E2E/pools/sl_link" 2>/dev/null; then
    if lib_call sl_link tp_secure_dir; then
      fail "tp_secure_dir: symlink leaf -> refuse"
    else
      ok "tp_secure_dir: symlink leaf -> refuse"
    fi
  else
    skip "tp_secure_dir: symlink leaf -> refuse" "ln -s unavailable"
  fi
else
  skip "tp_secure_dir: symlink leaf -> refuse" "symlinks unsupported here"
fi

echo "== result: PASS=$PASS FAIL=$FAIL SKIP=$SKIP =="
[ "$FAIL" -eq 0 ]
