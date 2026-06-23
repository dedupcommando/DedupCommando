#!/usr/bin/env bash
# Regression tests for the safety-critical guard in teardown-test-pool.sh and the
# safety functions in testpool-lib.sh. Stubs `zpool` — real ZFS is NOT needed. Runs both on
# a Linux host and in git-bash on Windows.
#
# Checks that depend on POSIX permission semantics, a "clean" directory chain, and
# real symlinks are automatically SKIPPED where this is unattainable
# (git-bash; only /tmp is available). On Linux from a root environment — all of them run.
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

# Run a lib function in a separate bash process (env isolation, without the
# pitfalls of source-in-subshell). Returns its exit code.
lib_call() { DEDCOM_TESTPOOL_DIR="$1" bash -c '. "$1"; "$2"' _ "$LIB" "$2" >/dev/null 2>&1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK" "${CLEANBASE:-}"' EXIT
BIN="$WORK/bin"; mkdir -p "$BIN"
DLOG="$WORK/destroy.log"

# zpool stub. Behavior via env: FIX_PRESENT, FIX_LIST_RC, FIX_VDEV, FIX_DESTROY_RC.
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
elif [ "$1" = "destroy" ]; then
  echo "STUB-DESTROY $2" >> "${STUB_DESTROY_LOG:-/dev/null}"
  exit "${FIX_DESTROY_RC:-0}"
fi
exit 0
STUB
chmod +x "$BIN/zpool"

# Probe: POSIX file modes?
probe="$WORK/probe"; mkdir -p "$probe"; chmod 0707 "$probe" 2>/dev/null || true
posix_perms=no
if [ "$(stat -c '%a' "$probe" 2>/dev/null)" = "707" ]; then posix_perms=yes; fi

# Probe: real symlinks? (git-bash on Windows does not make them.)
ln_ok=no
if ln -s "$probe" "$WORK/lnprobe" 2>/dev/null && [ -L "$WORK/lnprobe" ]; then ln_ok=yes; fi
rm -f "$WORK/lnprobe" 2>/dev/null || true

# A base with a "clean" chain (no world-writable ancestors) — needed for the real
# image removal and tp_secure_dir. /tmp (1777) won't do.
CLEANBASE=""
for cand in /var/lib /run /root "$HOME"; do
  if [ ! -d "$cand" ] || [ ! -w "$cand" ]; then continue; fi
  c="$(mktemp -d "$cand/dedcom-sdtest.XXXXXX" 2>/dev/null)" || continue
  if [ "$posix_perms" = yes ] && bash -c '. "$1"; tp_verify_chain "$2"' _ "$LIB" "$c" >/dev/null 2>&1; then
    CLEANBASE="$c"; break
  fi
  rmdir "$c" 2>/dev/null || rm -rf "$c"
done
BASE="${CLEANBASE:-$WORK}"
gone_testable=no
if [ -n "$CLEANBASE" ]; then gone_testable=yes; fi

SUM='testpool'   # pool-summary line, name-only column

# scenario LABEL PRESENT LISTRC DESTRC VDEV MKIMG WANT_EC WANT_DESTROY WANT_IMG [SYMLINK]
scenario() {
  local label="$1" present="$2" listrc="$3" destrc="$4" vdev="$5" mkimg="$6"
  local wec="$7" wdes="$8" wimg="$9" symlink="${10:-no}"
  N=$((N+1))
  local dir="$BASE/d$N"; mkdir -p "$dir"; chmod 0700 "$dir" 2>/dev/null || true
  local img="$dir/pool.img" canon target=""
  if [ "$symlink" = "yes" ]; then
    target="$dir/real-target"; : > "$target"; ln -s "$target" "$img"
    canon="$(readlink -f "$img")"
  else
    canon="$(readlink -f "$img" 2>/dev/null || echo "$img")"
    if [ "$mkimg" = "yes" ]; then : > "$img"; fi
  fi
  local vd="${vdev//@IMG@/$canon}"
  : > "$DLOG"
  local out ec
  out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_DIR="$dir" \
         FIX_PRESENT="$present" FIX_LIST_RC="$listrc" FIX_DESTROY_RC="$destrc" FIX_VDEV="$vd" \
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
  if [ "$wimg" = "gone" ] && [ "$gone_testable" != yes ]; then
    : # removal is unattainable in this environment — skip the image-state check
  elif [ "$wimg" != "na" ] && [ "$imgstate" != "$wimg" ]; then
    err="$err img=$imgstate(want $wimg)"
  fi
  if [ -z "$err" ]; then ok "$label"; else fail "$label" "$err"$'\n'"$out"; fi
}

echo "== teardown guard scenarios =="

scenario "legit single-image (name-only) -> destroy + remove" \
  1 0 0 "$SUM\n\t@IMG@\n" yes  0 yes gone

scenario "mirror container -> refuse" \
  1 0 0 "$SUM\n\tmirror-0\n\t@IMG@\n\t/dev/sdb\n" yes  1 no exists

scenario "real disk only (same name) -> refuse" \
  1 0 0 "$SUM\n\t/dev/sdb\n" yes  1 no exists

scenario "our image + extra stripe disk -> refuse" \
  1 0 0 "$SUM\n\t@IMG@\n\t/dev/sdb\n" yes  1 no exists

scenario "summary has extra TAB field -> refuse" \
  1 0 0 "testpool\tMALFORMED\n\t@IMG@\n" yes  1 no exists

# ZFS 2.3+: the detailed vdev row under -v carries property columns (SIZE … HEALTH)
# AFTER the name, ignoring -o name. We take the name from $2 and ignore the tail -> destroy.
scenario "ZFS 2.3 vdev row carries property columns -> destroy" \
  1 0 0 "$SUM\n\t@IMG@\t2G\t252M\t1.63G\t-\t-\t3%\t13.1%\t-\tONLINE\n" yes  0 yes gone

# The image file is real (require_real_image passes), but the CANONICAL path of the actual vdev
# fails (the parent doesn't exist) -> refuse without destroy (no fallback to the raw path).
scenario "actual vdev canon fails -> refuse" \
  1 0 0 "$SUM\n\t/nonexistent-dedcom-canon-probe/pool.img\n" yes  1 no exists

scenario "garbage row (no leading tab) -> refuse" \
  1 0 0 "$SUM\nTHIS_IS_NOT_A_VDEV\n" yes  1 no exists

scenario "logs section header -> refuse" \
  1 0 0 "$SUM\n\t@IMG@\nlogs\n\t/dev/sdb\n" yes  1 no exists

scenario "list exits 1 but prints path -> refuse (fail-closed)" \
  1 1 0 "$SUM\n\t@IMG@\n" yes  1 no exists

scenario "pool absent -> noop, image untouched" \
  0 0 0 "" yes  0 no exists

scenario "failed destroy -> image preserved" \
  1 0 1 "$SUM\n\t@IMG@\n" yes  1 yes exists

scenario "image missing (pool present) -> REFUSE, no destroy" \
  1 0 0 "$SUM\n\t@IMG@\n" no  1 no na

if [ "$ln_ok" = yes ]; then
  scenario "image is symlink (to file) -> REFUSE, no destroy" \
    1 0 0 "$SUM\n\t@IMG@\n" no  1 no exists yes
else
  skip "image is symlink (to file) -> REFUSE, no destroy" "symlinks unsupported here"
fi

# Exact repro from the review: pool.img -> /dev/null. The canonical path would match the actual
# /dev/null, but the image symlink must be rejected BEFORE destroy.
if [ "$ln_ok" = yes ]; then
  N=$((N+1)); ddir="$BASE/d$N"; mkdir -p "$ddir"; chmod 0700 "$ddir" 2>/dev/null || true
  ln -s /dev/null "$ddir/pool.img"
  : > "$DLOG"
  dn_out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_DIR="$ddir" \
            FIX_PRESENT=1 FIX_LIST_RC=0 FIX_DESTROY_RC=0 FIX_VDEV="$SUM\n\t/dev/null\n" \
            bash "$TEARDOWN" 2>&1)"; dn_ec=$?
  dn_des=no
  if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then dn_des=yes; fi
  if [ "$dn_ec" = 1 ] && [ "$dn_des" = no ]; then
    ok "image symlink -> /dev/null -> REFUSE, no destroy"
  else
    fail "image symlink -> /dev/null -> REFUSE, no destroy" "ec=$dn_ec destroy=$dn_des"$'\n'"$dn_out"
  fi
else
  skip "image symlink -> /dev/null -> REFUSE, no destroy" "symlinks unsupported here"
fi

# path with spaces (dir name contains a space) -> destroy (+remove)
N=$((N+1)); sdir="$BASE/has space d$N"; mkdir -p "$sdir"; chmod 0700 "$sdir" 2>/dev/null || true
simg="$sdir/pool.img"; : > "$simg"
scanon="$(readlink -f "$simg" 2>/dev/null || echo "$simg")"
: > "$DLOG"
sp_out="$(PATH="$BIN:$PATH" STUB_DESTROY_LOG="$DLOG" DEDCOM_TESTPOOL_DIR="$sdir" \
          FIX_PRESENT=1 FIX_LIST_RC=0 FIX_DESTROY_RC=0 FIX_VDEV="$SUM\n\t$scanon\n" \
          bash "$TEARDOWN" 2>&1)"; sp_ec=$?
sp_des=no
if grep -q STUB-DESTROY "$DLOG" 2>/dev/null; then sp_des=yes; fi
sp_gone_ok=yes
if [ "$gone_testable" = yes ] && [ -e "$simg" ]; then sp_gone_ok=no; fi
if [ "$sp_ec" = 0 ] && [ "$sp_des" = yes ] && [ "$sp_gone_ok" = yes ]; then
  ok "path with spaces -> destroy (+remove)"
else
  sp_state=gone; if [ -e "$simg" ]; then sp_state=exists; fi
  fail "path with spaces -> destroy (+remove)" "ec=$sp_ec destroy=$sp_des img=$sp_state"$'\n'"$sp_out"
fi

echo "== testpool-lib safety units =="

mkdir -p "$WORK/ai_clean"
if lib_call "$WORK/ai_clean" tp_assert_image_absent; then
  ok "tp_assert_image_absent: clean -> ok"
else
  fail "tp_assert_image_absent: clean -> ok"
fi

mkdir -p "$WORK/ai_taken"; : > "$WORK/ai_taken/pool.img"
if lib_call "$WORK/ai_taken" tp_assert_image_absent; then
  fail "tp_assert_image_absent: existing image -> refuse"
else
  ok "tp_assert_image_absent: existing image -> refuse"
fi

if [ -n "$CLEANBASE" ]; then
  d="$CLEANBASE/sd_ok"
  if lib_call "$d" tp_secure_dir && [ "$(stat -c '%a' "$d" 2>/dev/null)" = 700 ]; then
    ok "tp_secure_dir: fresh -> created 0700"
  else
    fail "tp_secure_dir: fresh -> created 0700" "mode=$(stat -c '%a' "$d" 2>/dev/null)"
  fi

  # P1-2: an existing directory -> refuse AND mode NOT changed (we don't chmod the system).
  ex="$CLEANBASE/sd_exists"; mkdir -p "$ex"; chmod 0755 "$ex"
  before="$(stat -c '%a' "$ex" 2>/dev/null)"
  secured=yes
  if ! lib_call "$ex" tp_secure_dir; then secured=no; fi
  after="$(stat -c '%a' "$ex" 2>/dev/null)"
  if [ "$secured" = no ] && [ "$before" = "$after" ]; then
    ok "tp_secure_dir: existing dir -> refuse, mode unchanged ($after)"
  else
    fail "tp_secure_dir: existing dir -> refuse, mode unchanged" "secured=$secured before=$before after=$after"
  fi

  if ln -s "$CLEANBASE/sl_real_x" "$CLEANBASE/sl_link" 2>/dev/null; then
    mkdir -p "$CLEANBASE/sl_real_x"
    if lib_call "$CLEANBASE/sl_link" tp_secure_dir; then
      fail "tp_secure_dir: symlink leaf -> refuse"
    else
      ok "tp_secure_dir: symlink leaf -> refuse"
    fi
  else
    skip "tp_secure_dir: symlink leaf -> refuse" "ln -s unavailable"
  fi

  # finding #3: symlink-ANCESTOR -> refuse, directory NOT created through the link.
  mkdir -p "$CLEANBASE/anc_real"
  if ln -s "$CLEANBASE/anc_real" "$CLEANBASE/anc_link" 2>/dev/null; then
    if lib_call "$CLEANBASE/anc_link/sub" tp_secure_dir; then
      fail "tp_secure_dir: symlink ancestor -> refuse"
    else
      ok "tp_secure_dir: symlink ancestor -> refuse"
    fi
    if [ -e "$CLEANBASE/anc_real/sub" ]; then
      fail "tp_secure_dir: ancestor not created through link"
    else
      ok "tp_secure_dir: ancestor not created through link"
    fi
  else
    skip "tp_secure_dir: symlink ancestor -> refuse" "ln -s unavailable"
    skip "tp_secure_dir: ancestor not created through link" "ln -s unavailable"
  fi
else
  for t in "fresh -> created 0700" "existing dir -> refuse, mode unchanged" "symlink leaf -> refuse" \
           "symlink ancestor -> refuse" "ancestor not created through link"; do
    skip "tp_secure_dir: $t" "no clean-chain base / non-POSIX"
  done
fi

echo "== result: PASS=$PASS FAIL=$FAIL SKIP=$SKIP =="
[ "$FAIL" -eq 0 ]
