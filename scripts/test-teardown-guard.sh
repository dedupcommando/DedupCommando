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
# zpool stub. Behaviour via env: FIX_PRESENT, FIX_LIST_RC, FIX_VDEV, FIX_DESTROY_RC, FIX_GUID.
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
  [ "${FIX_PRESENT:-1}" = "1" ] && exit 0 || exit 1
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

# scenario LABEL PRESENT LISTRC DESTRC VDEV MKIMG WANT_EC WANT_DESTROY WANT_IMG [SYMLINK]
scenario() {
  local label="$1" present="$2" listrc="$3" destrc="$4" vdev="$5" mkimg="$6"
  local wec="$7" wdes="$8" wimg="$9" symlink="${10:-no}"
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
  local vd="${vdev//@IMG@/$canon}"
  local ds; ds="$(printf 'dataset\t%s\t%s\ndataset\t%s\t%s\n' "$pool" "$dir/mount" "$pool/ds_a" "$dir/mount/ds_a")"
  mkmanifest "$dir" "$pool" "$GUID_OK" "$canon" "$ds"
  local dslist; dslist="$(printf '%s\t%s\n%s\t%s\n' "$pool" "$dir/mount" "$pool/ds_a" "$dir/mount/ds_a")"
  : > "$DLOG"
  local out ec
  out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_NAME="$pool" \
         FIX_PRESENT="$present" FIX_LIST_RC="$listrc" FIX_DESTROY_RC="$destrc" FIX_VDEV="$vd" \
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
# Each scenario owns a pool named tp<N>, so the stub's summary row carries that name literally.

scenario "legit single-image (name-only) -> destroy + remove" \
  1 0 0 "tp1\n\t@IMG@\n" yes  0 yes gone

scenario "mirror container -> refuse" \
  1 0 0 "tp2\n\tmirror-0\n\t@IMG@\n\t/dev/sdb\n" yes  1 no exists

scenario "real disk only (same name) -> refuse" \
  1 0 0 "tp3\n\t/dev/sdb\n" yes  1 no exists

scenario "our image + extra stripe disk -> refuse" \
  1 0 0 "tp4\n\t@IMG@\n\t/dev/sdb\n" yes  1 no exists

scenario "summary has extra TAB field -> refuse" \
  1 0 0 "tp5\tMALFORMED\n\t@IMG@\n" yes  1 no exists

# ZFS 2.3+: the detailed vdev row under -v carries property columns (SIZE … HEALTH) AFTER the
# name, ignoring -o name. We take the name from $2 and ignore the tail -> destroy.
scenario "ZFS 2.3 vdev row carries property columns -> destroy" \
  1 0 0 "tp6\n\t@IMG@\t2G\t252M\t1.63G\t-\t-\t3%\t13.1%\t-\tONLINE\n" yes  0 yes gone

# The image file is real (require_real_image passes), but the CANONICAL path of the actual vdev
# fails (the parent doesn't exist) -> refuse without destroy (no fallback to the raw path).
scenario "actual vdev canon fails -> refuse" \
  1 0 0 "tp7\n\t/nonexistent-dedcom-canon-probe/pool.img\n" yes  1 no exists

scenario "garbage row (no leading tab) -> refuse" \
  1 0 0 "tp8\nTHIS_IS_NOT_A_VDEV\n" yes  1 no exists

scenario "logs section header -> refuse" \
  1 0 0 "tp9\n\t@IMG@\nlogs\n\t/dev/sdb\n" yes  1 no exists

scenario "list exits 1 but prints path -> refuse (fail-closed)" \
  1 1 0 "tp10\n\t@IMG@\n" yes  1 no exists

scenario "pool absent -> noop, image untouched" \
  0 0 0 "" yes  0 no exists

scenario "failed destroy -> image preserved" \
  1 0 1 "tp12\n\t@IMG@\n" yes  1 yes exists

scenario "image missing (pool present) -> REFUSE, no destroy" \
  1 0 0 "tp13\n\t@IMG@\n" no  1 no na

if [ "$ln_ok" = yes ]; then
  scenario "image is symlink (to file) -> REFUSE, no destroy" \
    1 0 0 "tp14\n\t@IMG@\n" no  1 no exists yes
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
         FIX_PRESENT=1 FIX_LIST_RC=0 FIX_DESTROY_RC=0 FIX_VDEV="$pool\n\t$canon\n" \
         FIX_GUID="$guid" FIX_DS="$(printf "$ds" "$pool" "$dir/mount" "$pool" "$dir/mount")\n" \
         bash "$TEARDOWN" 2>&1)"; ec=$?
  local des=no
  if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then des=yes; fi
  local err=""
  if [ "$ec"  != "$wec"  ]; then err="$err ec=$ec(want $wec)"; fi
  if [ "$des" != "$wdes" ]; then err="$err destroy=$des(want $wdes)"; fi
  if [ -z "$err" ]; then ok "$label"; else fail "$label" "$err"$'\n'"$out"; fi
}

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
           FIX_PRESENT=1 FIX_LIST_RC=0 FIX_DESTROY_RC=0 FIX_VDEV="$esc_pool\n\t$esc_canon\n" \
           FIX_GUID="$GUID_OK" FIX_DS="$(printf '%s\t/dedcom-escaped\n' "$esc_pool")" \
           bash "$TEARDOWN" 2>&1)"; esc_ec=$?
esc_des=no; if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then esc_des=yes; fi
if [ "$esc_ec" = 1 ] && [ "$esc_des" = no ]; then
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
          FIX_PRESENT=1 FIX_LIST_RC=0 FIX_DESTROY_RC=0 FIX_VDEV="$ug_pool\n\t$ug_canon\n" \
          FIX_GUID_RC=1 FIX_DS="$(printf '%s\t%s\n' "$ug_pool" "$ug_dir/mount")" \
          bash "$TEARDOWN" 2>&1)"; ug_ec=$?
ug_des=no; if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then ug_des=yes; fi
if [ "$ug_ec" = 1 ] && [ "$ug_des" = no ]; then
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
