#!/usr/bin/env bash
# Contract test for shared-host containment.
#
# The harness in this directory is run on machines that are not sandboxes. This test pins the
# rules that keep it from touching anything it did not create:
#
#   * DEDCOM_E2E_ROOT is mandatory, absolute, symlink-free and never a system directory;
#   * DEDCOM_E2E_OWNER_UID is mandatory and numeric, and only root or that uid may own the chain;
#   * every backing file, mountpoint, state directory, capture, log and temporary file is inside
#     the root;
#   * `zpool create` carries an explicit mountpoint under the root and `cachefile=none`;
#   * destruction names one exact object from this run's manifest — never a prefix, a glob or a
#     listing — and re-verifies name, GUID, leaf-vdevs and dataset mountpoints first;
#   * anything uncertain refuses without destroying.
#
# NOTHING REAL RUNS. `zpool`, `zfs` and friends are PATH stubs that only record their arguments;
# no ZFS command, no mount, no sudo and no network call is made. The pool-creating cases need
# uid 0 (make-test-pool.sh requires it) and SKIP when the test is not run as root.
#
# The second half applies eight mutations to copies of the scripts and requires each one to be
# caught: a rule nothing fails on is not a rule.
#
# Run:  bash scripts/test-shared-host-containment.sh
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LIB="$HERE/testpool-lib.sh"

# The static scanners are scoped to the six harness scripts: the test files themselves carry
# the very strings under audit inside their heredocs and must not be read as violations.
HARNESS_FILES="testpool-lib.sh make-test-pool.sh teardown-test-pool.sh e2e-g5.sh e2e-root-guard.sh e2e-dir-completeness.sh"

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }
skip() { SKIP=$((SKIP+1)); printf 'SKIP  %s (%s)\n' "$1" "$2"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK" "${E2E:-}"' EXIT
BIN="$WORK/bin"; mkdir -p "$BIN"
CMDLOG="$WORK/cmds.log"; : > "$CMDLOG"

# ---------------------------------------------------------------- PATH stubs
# Each stub records its full argument vector and answers the minimum the harness needs. None of
# them touches a pool, a dataset or a mount.
make_stub() {  # name body
  cat > "$BIN/$1" <<STUBHEAD
#!/usr/bin/env bash
printf '%s' "$1" >> "\$STUB_CMDLOG"
for a in "\$@"; do printf ' %s' "\$a" >> "\$STUB_CMDLOG"; done
printf '\n' >> "\$STUB_CMDLOG"
STUBHEAD
  cat >> "$BIN/$1" <<STUBBODY
$2
STUBBODY
  chmod +x "$BIN/$1"
}

make_stub zpool '
case "$1" in
  list)
    shift
    for a in "$@"; do case "$a" in -*v*) exec printf "%b" "${STUB_VDEV:-}";; esac; done
    [ "${STUB_ENUM_RC:-0}" = "0" ] || exit "${STUB_ENUM_RC}"
    if [ "$#" -eq 1 ] && [ "${1#-}" = "$1" ]; then
      # Single-pool query, the pre-tristate form: succeed only when the name is enumerated.
      printf "%b" "${STUB_POOLNAMES:-}" | grep -qxF -- "$1"
      exit $?
    fi
    printf "%b" "${STUB_POOLNAMES:-}"
    exit 0 ;;
  get)     [ "${STUB_GUID_RC:-0}" = "0" ] || exit "${STUB_GUID_RC}"
           printf "%s\n" "${STUB_GUID-7777777777777777777}"; exit 0 ;;
  create)  exit 0 ;;
  destroy) exit "${STUB_DESTROY_RC:-0}" ;;
  sync)    exit 0 ;;
esac
exit 0'

# rm passthrough stub: fails exactly one marked path, so a removal error is injectable
# without touching permissions or capabilities.
make_stub rm '
for a in "$@"; do
  if [ -n "${STUB_RM_FAIL_PATH:-}" ] && [ "$a" = "$STUB_RM_FAIL_PATH" ]; then
    echo "stub rm: refusing $a" >&2
    exit 1
  fi
done
exec /bin/rm "$@"'

make_stub zfs '
case "$1" in
  list)     printf "%b" "${STUB_DS:-}"; exit 0 ;;
  create)   exit 0 ;;
  snapshot) exit 0 ;;
  destroy)  exit 0 ;;
esac
exit 0'

make_stub seq 'printf "1\n2\n3\n"'   # keeps the fixture loop to three files

export STUB_CMDLOG="$CMDLOG"

# ---------------------------------------------------------------- containment root
# The base is HANDED IN and never searched for. Probing system directories is how this suite
# used to build its containment root in /var/lib — the first writable candidate won, and that
# is outside <REMOTE_ROOT>, which the containment rules forbid. The caller names one base; the
# private subdirectory created below is the only thing this run makes and the only thing the
# exit trap removes. A base we cannot use is an abort with a reason, never a fallback.
CT_BASE="${DEDCOM_E2E_CT_ROOT-}"
if [ -z "$CT_BASE" ]; then
  {
    echo "ABORT: DEDCOM_E2E_CT_ROOT is not set — this suite never searches for a root."
    echo "       Pass an absolute path inside the tree this run owns, for example:"
    echo "         DEDCOM_E2E_CT_ROOT=<REMOTE_ROOT>/ct bash $0"
  } >&2
  exit 1
fi
case "$CT_BASE" in
  /*) ;;
  *) echo "ABORT: DEDCOM_E2E_CT_ROOT='$CT_BASE' is not absolute." >&2; exit 1;;
esac
if [ ! -d "$CT_BASE" ]; then
  echo "ABORT: DEDCOM_E2E_CT_ROOT='$CT_BASE' does not exist or is not a directory." >&2
  exit 1
fi
if ! CT_REAL="$(readlink -f -- "$CT_BASE" 2>/dev/null)"; then
  echo "ABORT: canonicalization of DEDCOM_E2E_CT_ROOT='$CT_BASE' failed." >&2; exit 1
fi
if [ "$CT_REAL" != "$CT_BASE" ]; then
  echo "ABORT: DEDCOM_E2E_CT_ROOT='$CT_BASE' canonicalizes to '$CT_REAL' — refusing an aliased base." >&2
  exit 1
fi

# The shared guard refuses a system directory as a root, but only when it IS one: a base
# UNDER /var/lib passes it, and that is exactly how the old search ended up there. Here the
# whole ancestry is refused, and the list is read out of the library so there is one source of
# truth. Failing to read it is an abort, never a silently empty list.
ct_forbidden_roots() {
  awk '/^tp_root_is_forbidden\(\)/,/^}/' "$LIB" \
    | sed -n 's/^[[:space:]]*\(\/|[^)]*\))$/\1/p' | tr '|' ' '
}
FORBIDDEN_ROOTS="$(ct_forbidden_roots)"
if [ -z "$FORBIDDEN_ROOTS" ]; then
  echo "ABORT: cannot read the forbidden-root list out of '$LIB' — refusing to guess it." >&2
  exit 1
fi
ct_refuse_base() {  # reason -> abort naming the base and why
  echo "ABORT: DEDCOM_E2E_CT_ROOT='$CT_BASE' $1." >&2
  exit 1
}
# The base itself is measured against the whole list, '/' included.
for ct_bad_root in $FORBIDDEN_ROOTS; do
  [ "$CT_BASE" = "$ct_bad_root" ] && ct_refuse_base "is the system directory '$ct_bad_root'"
done
[ -n "${HOME:-}" ] && [ "$CT_BASE" = "$HOME" ] && ct_refuse_base "is the user's home directory"
# Its ancestry is measured against the same list MINUS '/', because every path lies under '/'
# and refusing that would refuse every base there is.
ct_probe_path="$(dirname "$CT_BASE")"
while [ "$ct_probe_path" != "/" ]; do
  for ct_bad_root in $FORBIDDEN_ROOTS; do
    [ "$ct_bad_root" = "/" ] && continue
    [ "$ct_probe_path" = "$ct_bad_root" ] \
      && ct_refuse_base "lies under the system directory '$ct_bad_root'"
  done
  [ -n "${HOME:-}" ] && [ "$ct_probe_path" = "$HOME" ] \
    && ct_refuse_base "lies under the user's home directory"
  ct_probe_path="$(dirname "$ct_probe_path")"
done

E2E="$(mktemp -d "$CT_BASE/dedcom-e2e-ct.XXXXXX")" || {
  echo "ABORT: cannot create a private containment root under '$CT_BASE'." >&2; exit 1; }
chmod 0700 "$E2E" || { echo "ABORT: cannot set mode 0700 on '$E2E'." >&2; exit 1; }
UID_NOW="$(id -u)"
if ! ct_probe="$(DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
                 bash -c '. "$1"' _ "$LIB" 2>&1)"; then
  echo "ABORT: the guard refuses the handed-in containment root '$E2E':" >&2
  printf '%s\n' "$ct_probe" | sed 's/^/       /' >&2
  exit 1
fi

# Source the library in a subshell with a given environment; prints nothing, returns its status.
lib_env() { env "$@" bash -c '. "$1"' _ "$LIB" >/dev/null 2>&1; }

echo "== 1. the environment contract =="

lib_env DEDCOM_E2E_OWNER_UID="$UID_NOW" && bad "missing DEDCOM_E2E_ROOT -> refuse" \
  || ok "missing DEDCOM_E2E_ROOT -> refuse"

lib_env DEDCOM_E2E_ROOT="$E2E" && bad "missing DEDCOM_E2E_OWNER_UID -> refuse" \
  || ok "missing DEDCOM_E2E_OWNER_UID -> refuse"

lib_env DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="nobody" \
  && bad "non-numeric DEDCOM_E2E_OWNER_UID -> refuse" \
  || ok "non-numeric DEDCOM_E2E_OWNER_UID -> refuse"

lib_env DEDCOM_E2E_ROOT="relative/path" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
  && bad "relative DEDCOM_E2E_ROOT -> refuse" || ok "relative DEDCOM_E2E_ROOT -> refuse"

for forbidden in / /home /tmp /var/tmp /var/lib /root /run; do
  if lib_env DEDCOM_E2E_ROOT="$forbidden" DEDCOM_E2E_OWNER_UID="$UID_NOW"; then
    bad "forbidden root '$forbidden' -> refuse"
  else
    ok "forbidden root '$forbidden' -> refuse"
  fi
done

if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
  lib_env DEDCOM_E2E_ROOT="$HOME" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
    && bad "the user's home as root -> refuse" || ok "the user's home as root -> refuse"
else
  skip "the user's home as root -> refuse" "no HOME"
fi

lib_env DEDCOM_E2E_ROOT="$E2E/.." DEDCOM_E2E_OWNER_UID="$UID_NOW" \
  && bad "'..' in the root -> refuse" || ok "'..' in the root -> refuse"

lib_env DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
  && ok "a valid root and uid -> accepted" || bad "a valid root and uid -> accepted"

echo "== 2. ownership and symlink escape =="

# The ownership contract is proved WITHOUT chown, so it can never be skipped for a missing
# CAP_CHOWN: a stat stub reports a chosen owner for exactly one marked node, and tp_check_node
# is called against that node directly. Three assertions, three verdicts, no capability needed.
make_stub stat '
if [ -n "${STAT_FAKE_PATH:-}" ]; then
  for last; do :; done
  if [ "$last" = "$STAT_FAKE_PATH" ]; then
    case "$*" in
      *%u*) printf "%s\n" "${STAT_FAKE_UID:-0}"; exit 0 ;;
      *%a*) printf "%s\n" "${STAT_FAKE_MODE:-700}"; exit 0 ;;
    esac
  fi
fi
exec /usr/bin/stat "$@"'

own_probe="$E2E/ownprobe"; mkdir -p "$own_probe"; chmod 0700 "$own_probe" 2>/dev/null || true
owner_case() {  # fake-owner declared-uid -> exit status of tp_check_node
  env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" \
      STAT_FAKE_PATH="$own_probe" STAT_FAKE_UID="$1" \
      DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
      bash -c '. "$1" && tp_check_node "$2" "$3"' _ "$LIB" "$own_probe" "$2" >/dev/null 2>&1
}
if owner_case 0 1234; then
  ok "owner root(0) is accepted for a chain node"
else
  bad "owner root(0) is accepted for a chain node"
fi
if owner_case 1234 1234; then
  ok "the exact declared owner uid is accepted for a chain node"
else
  bad "the exact declared owner uid is accepted for a chain node"
fi
if owner_case 4242 1234; then
  bad "a third uid owning a chain node -> refuse"
else
  ok "a third uid owning a chain node -> refuse"
fi

ww="$E2E/worldwritable"; mkdir -p "$ww"; chmod 0777 "$ww" 2>/dev/null || true
if [ "$(stat -c '%a' "$ww" 2>/dev/null)" = "777" ]; then
  lib_env DEDCOM_E2E_ROOT="$ww" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
    && bad "a world-writable root -> refuse" || ok "a world-writable root -> refuse"
else
  skip "a world-writable root -> refuse" "no POSIX modes here"
fi

if ln -s "$E2E" "$WORK/rootlink" 2>/dev/null && [ -L "$WORK/rootlink" ]; then
  lib_env DEDCOM_E2E_ROOT="$WORK/rootlink" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
    && bad "a symlinked root -> refuse" || ok "a symlinked root -> refuse"

  # An escape one level down: pools/<name> is a link out of the root.
  mkdir -p "$E2E/pools" "$WORK/outside"
  ln -sfn "$WORK/outside" "$E2E/pools/escapee" 2>/dev/null
  if env DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME=escapee \
       bash -c '. "$1"; tp_contained "$TP_IMG"' _ "$LIB" >/dev/null 2>&1; then
    bad "a symlink out of the root -> refuse"
  else
    ok "a symlink out of the root -> refuse"
  fi
  rm -f "$E2E/pools/escapee"
else
  skip "a symlinked root -> refuse" "symlinks unavailable"
  skip "a symlink out of the root -> refuse" "symlinks unavailable"
fi

echo "== 3. every derived path is inside the root =="

paths="$(env DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME=probe \
         bash -c '. "$1"
                  printf "%s\n" "$TP_DIR" "$TP_IMG" "$TP_MNT" \
                                "$(tp_state_dir s)" "$(tp_tmp_dir s)" "$(tp_evidence_dir s)" \
                                "$(tp_manifest_path)"' _ "$LIB" 2>/dev/null)"
outside=0
while IFS= read -r p; do
  [ -n "$p" ] || continue
  case "$p" in "$E2E"/*) ;; *) outside=1; printf '        outside: %s\n' "$p" ;; esac
done <<< "$paths"
[ "$outside" -eq 0 ] && ok "backing file, mount, state, tmp, evidence and manifest are all under the root" \
                     || bad "backing file, mount, state, tmp, evidence and manifest are all under the root"

echo "== 4. the exact zpool create command =="

if [ "$UID_NOW" != "0" ]; then
  skip "zpool create carries -m under the root and cachefile=none" "not root"
  skip "the manifest records name, GUID, vdev and dataset mountpoints" "not root"
else
  POOL="ct-$$"
  PDIR="$E2E/pools/$POOL"
  : > "$CMDLOG"
  createlog="$WORK/create.out"
  env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" \
      DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID=0 \
      DEDCOM_TESTPOOL_NAME="$POOL" DEDCOM_TESTPOOL_SIZE=1M \
      STUB_VDEV="$POOL\n\t$PDIR/pool.img\n" \
      STUB_DS="$(printf '%s\t%s\n%s/ds_a\t%s/ds_a\n%s/ds_b\t%s/ds_b\n' \
                 "$POOL" "$PDIR/mount" "$POOL" "$PDIR/mount" "$POOL" "$PDIR/mount")" \
      bash "$HERE/make-test-pool.sh" > "$createlog" 2>&1
  mk_rc=$?

  create_line="$(grep -m1 '^zpool create ' "$CMDLOG" || true)"
  if [ -z "$create_line" ]; then
    bad "zpool create carries -m under the root and cachefile=none" \
        "no zpool create was issued (rc=$mk_rc)"$'\n'"$(tail -20 "$createlog")"
  else
    err=""
    case "$create_line" in *" -m $PDIR/mount "*) ;; *) err="$err no explicit -m under the root;";; esac
    case "$create_line" in *" -o cachefile=none "*) ;; *) err="$err no cachefile=none;";; esac
    case "$create_line" in *" /$POOL"*) err="$err mountpoint at the filesystem root;";; esac
    if [ -z "$err" ]; then
      ok "zpool create carries -m under the root and cachefile=none"
    else
      bad "zpool create carries -m under the root and cachefile=none" "$err"$'\n'"$create_line"
    fi
  fi

  man="$PDIR/manifest.txt"
  if [ -r "$man" ] &&
     grep -q "^pool	$POOL$" "$man" &&
     grep -q '^guid	[0-9][0-9]*$' "$man" &&
     grep -q "^vdev	$PDIR/pool.img$" "$man" &&
     grep -q "^dataset	$POOL	$PDIR/mount$" "$man"; then
    ok "the manifest records name, GUID, vdev and dataset mountpoints"
  else
    bad "the manifest records name, GUID, vdev and dataset mountpoints" \
        "$( [ -r "$man" ] && cat "$man" || echo 'no manifest written')"
  fi

  # Everything the run created stays inside the root.
  stray="$(grep -E '^(zpool|zfs) ' "$CMDLOG" | grep -oE ' /[A-Za-z0-9._/-]+' | tr -d ' ' \
           | grep -v "^$E2E" | grep -v '^/dev/' || true)"
  [ -z "$stray" ] && ok "no ZFS argument names a path outside the root" \
                  || bad "no ZFS argument names a path outside the root" "$stray"
fi

echo "== 5. a dataset mounted outside the root refuses =="

esc="$E2E/pools/escaped-mount"; mkdir -p "$esc/mount"
if env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" \
       DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
       DEDCOM_TESTPOOL_NAME=escaped-mount \
       STUB_DS="$(printf 'escaped-mount\t/dedcom-escaped-mount\n')" \
       bash -c '. "$1"; tp_assert_dataset_mounts_contained escaped-mount' _ "$LIB" >/dev/null 2>&1; then
  bad "a dataset mounted outside the root -> refuse"
else
  ok "a dataset mounted outside the root -> refuse"
fi

echo "== 6. clean-stale refuses prefix and listing forms =="

# The gate envs are supplied so the refusal under test is the ARGUMENT check itself, not the
# earlier destructive-E2E gate: with them present, a permissive clean-stale would sail through
# to the stubbed "pool not found" and exit 0.
G5="$HERE/e2e-g5.sh"
clean_stale() {  # args... -> exit status of clean-stale under gate envs and stubs
  env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" DEDCOM_G5_E2E=1 \
      DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
      DEDCOM="$BIN/zpool" \
      bash "$G5" clean-stale "$@" >/dev/null 2>&1
}
if [ "$UID_NOW" = "0" ]; then
  if clean_stale; then
    bad "clean-stale without an exact pool name -> refuse"
  else
    ok "clean-stale without an exact pool name -> refuse"
  fi
  if clean_stale 'dedcom-g5-*'; then
    bad "clean-stale with a glob -> refuse"
  else
    ok "clean-stale with a glob -> refuse"
  fi
  if clean_stale 'rpool'; then
    bad "clean-stale with a foreign pool name -> refuse"
  else
    ok "clean-stale with a foreign pool name -> refuse"
  fi
else
  skip "clean-stale without an exact pool name -> refuse" "not root"
  skip "clean-stale with a glob -> refuse" "not root"
  skip "clean-stale with a foreign pool name -> refuse" "not root"
fi
# The old form iterated every imported pool and matched a prefix; its loop message is the
# static fingerprint. The new form must refuse without a name and never print the old marker.
if grep -q 'tearing down stale pool:' "$G5"; then
  bad "clean-stale no longer iterates a pool listing"
elif grep -q 'clean-stale needs the EXACT pool name' "$G5"; then
  ok "clean-stale no longer iterates a pool listing"
else
  bad "clean-stale no longer iterates a pool listing" "the refusal message is gone too"
fi

echo "== 7. no executable path escapes the root, statically =="

# Comments may discuss /tmp; executable lines may not use it. The check looks at code only.
static_clean=1
for f in testpool-lib.sh make-test-pool.sh teardown-test-pool.sh e2e-g5.sh \
         e2e-root-guard.sh e2e-dir-completeness.sh; do
  hits="$(sed 's/[[:space:]]*#.*$//' "$HERE/$f" \
          | grep -nE '(^|[^A-Za-z0-9_])(/tmp/|/var/tmp/|/var/lib/|"/\$POOL|/dedcomdirtest)' || true)"
  if [ -n "$hits" ]; then
    static_clean=0
    printf '        %s:\n%s\n' "$f" "$(printf '%s' "$hits" | sed 's/^/          /')"
  fi
done
[ "$static_clean" -eq 1 ] && ok "no executable line names /tmp, /var/tmp, /var/lib or a pool at the filesystem root" \
                          || bad "no executable line names /tmp, /var/tmp, /var/lib or a pool at the filesystem root"

if grep -nE '(^|[[:space:]])--force([[:space:]]|$)' "$HERE"/*.sh | grep -v '^\s*#' | grep -q .; then
  bad "--force appears in no harness script"
else
  ok "--force appears in no harness script"
fi

echo "== 7b. execution-gap audits (FIX2A) =="

# Reused verbatim by the mutation kills below, so the live audit and the kill are one check.
audit_bare_zdb() {  # dir -> 0 = no executable bare `zdb`; the absolute path is the only form
  local dir="$1" hits
  hits="$(sed 's/[[:space:]]*#.*$//' "$dir/e2e-g5.sh" | sed 's|/usr/sbin/zdb||g' \
          | grep -E '(^|[^A-Za-z0-9_./-])zdb([^A-Za-z0-9_.-]|$)' || true)"
  [ -n "$hits" ] && return 1
  return 0
}
audit_no_nobody() {  # dir -> 0 = no harness script runs anything as `nobody`
  local dir="$1" f hits
  for f in $HARNESS_FILES; do
    hits="$(sed 's/[[:space:]]*#.*$//' "$dir/$f" | grep -F 'runuser -u nobody' || true)"
    [ -n "$hits" ] && return 1
  done
  return 0
}
audit_no_destroy_advice() {  # dir -> 0 = e2e-g5.sh neither runs nor prints `zpool destroy`
  local dir="$1" hits
  hits="$(sed 's/[[:space:]]*#.*$//' "$dir/e2e-g5.sh" | grep -F 'zpool destroy' || true)"
  [ -n "$hits" ] && return 1
  return 0
}
audit_rootguard_shared() {  # dir -> 0 = root-guard sources the shared guard, no private copy
  local dir="$1"
  grep -q 'testpool-lib\.sh' "$dir/e2e-root-guard.sh" || return 1
  grep -q 'is a system directory' "$dir/e2e-root-guard.sh" && return 1
  return 0
}

audit_bare_zdb "$HERE"          && ok "zdb is invoked only as /usr/sbin/zdb" \
                                || bad "zdb is invoked only as /usr/sbin/zdb"
audit_no_nobody "$HERE"         && ok "no harness script runs as nobody" \
                                || bad "no harness script runs as nobody"
audit_no_destroy_advice "$HERE" && ok "e2e-g5.sh prints no manual zpool-destroy bypass" \
                                || bad "e2e-g5.sh prints no manual zpool-destroy bypass"
audit_rootguard_shared "$HERE"  && ok "e2e-root-guard.sh uses the shared containment guard" \
                                || bad "e2e-root-guard.sh uses the shared containment guard"

hits="$(sed 's/[[:space:]]*#.*$//' "$HERE/e2e-dir-completeness.sh" | grep -F 'pwd.getpwuid' || true)"
[ -n "$hits" ] && ok "the unprivileged identity is derived from DEDCOM_E2E_OWNER_UID" \
              || bad "the unprivileged identity is derived from DEDCOM_E2E_OWNER_UID"

echo "== 7d. tri-state existence, verified closure, tmux isolation (FIX2B) =="

# --- make: a failed enumeration permits nothing --------------------------------------------
if [ "$UID_NOW" = "0" ]; then
  ts_pool="ts-make-$$"
  : > "$CMDLOG"
  env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" STUB_ENUM_RC=2 \
      DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID=0 DEDCOM_TESTPOOL_NAME="$ts_pool" \
      bash "$HERE/make-test-pool.sh" >/dev/null 2>&1
  ts_rc=$?
  created="$(grep -c '^zpool create' "$CMDLOG" || true)"
  if [ "$ts_rc" != 0 ] && [ "$created" = 0 ] && [ ! -e "$E2E/pools/$ts_pool" ]; then
    ok "make: enumeration error -> non-zero, zero creates, no directory provisioned"
  else
    bad "make: enumeration error -> non-zero, zero creates, no directory provisioned" \
        "rc=$ts_rc creates=$created dir=$( [ -e "$E2E/pools/$ts_pool" ] && echo exists || echo absent )"
  fi
else
  bad "make: enumeration error -> non-zero, zero creates, no directory provisioned" "needs uid 0"
fi

# --- teardown: the same error is unknown, and unknown licenses nothing ---------------------
td_pool="ts-td-$$"; td_dir="$E2E/pools/$td_pool"
mkdir -p "$td_dir/mount"; chmod 0700 "$td_dir" "$td_dir/mount" 2>/dev/null || true
printf 'payload' > "$td_dir/pool.img"
td_sum_before="$(cksum < "$td_dir/pool.img")"
: > "$CMDLOG"
env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" STUB_ENUM_RC=2 \
    DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="$td_pool" \
    bash "$HERE/teardown-test-pool.sh" >/dev/null 2>&1
td_rc=$?
td_destroys="$(grep -c '^zpool destroy' "$CMDLOG" || true)"
td_sum_after="$(cksum < "$td_dir/pool.img" 2>/dev/null || echo GONE)"
if [ "$td_rc" != 0 ] && [ "$td_destroys" = 0 ] && [ "$td_sum_after" = "$td_sum_before" ]; then
  ok "teardown: enumeration error -> non-zero, zero destroys, artifacts byte-unchanged"
else
  bad "teardown: enumeration error -> non-zero, zero destroys, artifacts byte-unchanged" \
      "rc=$td_rc destroys=$td_destroys"
fi

# The same error with NO artifacts present must still refuse: unknown is not absent, and the
# clean noop is licensed only by a proved absence.
env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" STUB_ENUM_RC=2 \
    DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="ts-none-$$" \
    bash "$HERE/teardown-test-pool.sh" >/dev/null 2>&1 \
  && bad "teardown: enumeration error with no artifacts -> still non-zero" \
  || ok "teardown: enumeration error with no artifacts -> still non-zero"

# --- absent: clean noop only when NOTHING remains ------------------------------------------
env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" \
    DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="ts-clean-$$" \
    bash "$HERE/teardown-test-pool.sh" >/dev/null 2>&1 \
  && ok "teardown: proved absent + no artifacts -> clean noop 0" \
  || bad "teardown: proved absent + no artifacts -> clean noop 0"

: > "$CMDLOG"
env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" \
    DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="$td_pool" \
    bash "$HERE/teardown-test-pool.sh" >/dev/null 2>&1
ab_rc=$?
ab_destroys="$(grep -c '^zpool destroy' "$CMDLOG" || true)"
ab_sum_after="$(cksum < "$td_dir/pool.img" 2>/dev/null || echo GONE)"
if [ "$ab_rc" != 0 ] && [ "$ab_destroys" = 0 ] && [ "$ab_sum_after" = "$td_sum_before" ]; then
  ok "teardown: absent + residue -> non-zero, artifacts byte-unchanged"
else
  bad "teardown: absent + residue -> non-zero, artifacts byte-unchanged" \
      "rc=$ab_rc destroys=$ab_destroys"
fi

# --- present: a removal error turns the whole teardown non-zero ----------------------------
cl_pool="ts-close-$$"; cl_dir="$E2E/pools/$cl_pool"
mkdir -p "$cl_dir/mount"; chmod 0700 "$cl_dir" "$cl_dir/mount" 2>/dev/null || true
: > "$cl_dir/pool.img"; cl_canon="$(readlink -f "$cl_dir/pool.img")"
{
  printf 'root\t%s\n'  "$E2E"
  printf 'pool\t%s\n'  "$cl_pool"
  printf 'guid\t%s\n'  7777777777777777777
  printf 'image\t%s\n' "$cl_canon"
  printf 'mount\t%s\n' "$cl_dir/mount"
  printf 'vdev\t%s\n'  "$cl_canon"
  printf 'dataset\t%s\t%s\n' "$cl_pool" "$cl_dir/mount"
} > "$cl_dir/manifest.txt"
: > "$CMDLOG"
env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" \
    STUB_POOLNAMES="$cl_pool\n" STUB_VDEV="$cl_pool\n\t$cl_canon\n" \
    STUB_DS="$(printf '%s\t%s\n' "$cl_pool" "$cl_dir/mount")" \
    STUB_RM_FAIL_PATH="$cl_dir/pool.img" \
    DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="$cl_pool" \
    bash "$HERE/teardown-test-pool.sh" >/dev/null 2>&1
cl_rc=$?
if [ "$cl_rc" != 0 ] && [ -e "$cl_dir/pool.img" ]; then
  ok "teardown: a failed artifact removal -> non-zero, never a green Done"
else
  bad "teardown: a failed artifact removal -> non-zero, never a green Done" "rc=$cl_rc"
fi

# The same pool with a working rm: destroy succeeds and the WHOLE directory must be gone.
{
  printf 'root\t%s\n'  "$E2E"
  printf 'pool\t%s\n'  "$cl_pool"
  printf 'guid\t%s\n'  7777777777777777777
  printf 'image\t%s\n' "$cl_canon"
  printf 'mount\t%s\n' "$cl_dir/mount"
  printf 'vdev\t%s\n'  "$cl_canon"
  printf 'dataset\t%s\t%s\n' "$cl_pool" "$cl_dir/mount"
} > "$cl_dir/manifest.txt"
env PATH="$BIN:$PATH" STUB_CMDLOG="$CMDLOG" \
    STUB_POOLNAMES="$cl_pool\n" STUB_VDEV="$cl_pool\n\t$cl_canon\n" \
    STUB_DS="$(printf '%s\t%s\n' "$cl_pool" "$cl_dir/mount")" \
    DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="$cl_pool" \
    bash "$HERE/teardown-test-pool.sh" >/dev/null 2>&1
cl2_rc=$?
if [ "$cl2_rc" = 0 ] && [ ! -e "$cl_dir" ] && [ ! -L "$cl_dir" ]; then
  ok "teardown: successful destroy -> the pool directory is gone entirely"
else
  bad "teardown: successful destroy -> the pool directory is gone entirely" \
      "rc=$cl2_rc dir=$( [ -e "$cl_dir" ] && echo exists || echo absent )"
fi

# --- tmux: private socket only, no default server, no global kill --------------------------
audit_tmux_private() {  # dir -> 0 = every tmux invocation is private and no global kill exists
  local dir="$1" src hits
  src="$(sed 's/[[:space:]]*#.*$//' "$dir/e2e-dir-completeness.sh")"
  # Invocation-position tmux calls that do NOT carry the private socket.
  hits="$(printf '%s\n' "$src" \
          | grep -E '(^[[:space:]]*|[;&|(][[:space:]]*|\{[[:space:]]+)tmux[[:space:]]' \
          | grep -Fv -- '-S "$TMUX_SOCKET"' || true)"
  [ -n "$hits" ] && return 1
  # The global form must not exist at all, socketed or bare spelling aside.
  hits="$(printf '%s\n' "$src" | grep -E '(^|[^-A-Za-z0-9_])tmux[[:space:]]+kill-server' \
          | grep -Fv -- '-S "$TMUX_SOCKET"' || true)"
  [ -n "$hits" ] && return 1
  return 0
}
audit_tmux_socket_contained() {  # dir -> 0 = the socket path is declared under DIRTMP
  grep -q 'TMUX_SOCKET="${DIRTMP}/' "$1/e2e-dir-completeness.sh"
}
audit_tmux_private "$HERE" && ok "every tmux call is addressed to the private socket" \
                          || bad "every tmux call is addressed to the private socket"
audit_tmux_socket_contained "$HERE" && ok "the tmux socket lives inside DIRTMP" \
                                    || bad "the tmux socket lives inside DIRTMP"
hits="$(sed 's/[[:space:]]*#.*$//' "$HERE/e2e-dir-completeness.sh" | grep -F 'command -v tmux' || true)"
[ -n "$hits" ] && ok "tmux availability is a preflight check" \
              || bad "tmux availability is a preflight check"

echo "== 7c. root-guard walks through the shared guard =="

# The guard must fire BEFORE the fixture exists. The banner «========== fixture» prints only
# after mktemp, so its absence plus a REFUSED line is «refused before mktemp/mount», and its
# presence is «containment accepted» — /bin/true stands in for the binary, which is never
# reached before the fixture stage.
rg_run() { env "$@" DEDCOM=/bin/true bash "$HERE/e2e-root-guard.sh" 2>&1 || true; }

mkdir -p "$WORK/rg-real/sub"; chmod 0700 "$WORK/rg-real/sub" 2>/dev/null || true
if ln -s "$WORK/rg-real" "$WORK/rg-link" 2>/dev/null && [ -L "$WORK/rg-link" ]; then
  out="$(rg_run DEDCOM_E2E_ROOT="$WORK/rg-link/sub" DEDCOM_E2E_OWNER_UID="$UID_NOW")"
  if printf '%s' "$out" | grep -q '========== fixture'; then
    bad "root-guard: a symlink parent in the root -> refused before any fixture" "$out"
  elif printf '%s' "$out" | grep -Eq 'REFUSED|containment guard refused'; then
    ok "root-guard: a symlink parent in the root -> refused before any fixture"
  else
    bad "root-guard: a symlink parent in the root -> refused before any fixture" "$out"
  fi
else
  bad "root-guard: a symlink parent in the root -> refused before any fixture" "ln -s unavailable"
fi

out="$(rg_run PATH="$BIN:$PATH" STAT_FAKE_PATH="$E2E" STAT_FAKE_UID=4242 \
              DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW")"
if printf '%s' "$out" | grep -q '========== fixture'; then
  bad "root-guard: a foreign-owned chain component -> refused before any fixture" "$out"
elif printf '%s' "$out" | grep -Eq 'REFUSED|containment guard refused'; then
  ok "root-guard: a foreign-owned chain component -> refused before any fixture"
else
  bad "root-guard: a foreign-owned chain component -> refused before any fixture" "$out"
fi

out="$(rg_run DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW")"
if printf '%s' "$out" | grep -q '========== fixture'; then
  ok "root-guard: a valid root passes the shared guard and reaches the fixture stage"
else
  bad "root-guard: a valid root passes the shared guard and reaches the fixture stage" "$out"
fi

echo "== 8. mutations must be caught =="

# Each mutation is applied to a private copy of the scripts and the named check is re-run there.
# The check MUST fail on the mutant: a guard nothing trips is not a guard.
#
# Replacement is literal — FROM and TO are plain strings, not patterns. A regex here would need
# escaping that quietly stops matching after an unrelated edit, and a mutation that silently
# matches nothing is a test that proves nothing.
literal_sub() {  # file from to  -> non-zero when FROM does not occur
  local file="$1" from="$2" to="$3" src
  src="$(cat "$file")"
  case "$src" in *"$from"*) ;; *) return 3;; esac
  printf '%s\n' "${src/"$from"/"$to"}" > "$file"
}

mutate() {  # label file from to check-fn
  local label="$1" file="$2" from="$3" to="$4" fn="$5"
  local dir="$WORK/mut-$MUTN"; MUTN=$((MUTN+1))
  mkdir -p "$dir"
  cp "$HERE"/*.sh "$dir/" 2>/dev/null
  if ! literal_sub "$dir/$file" "$from" "$to"; then
    bad "mutation '$label' changed nothing — the target text is no longer present in $file"; return
  fi
  # A mutant that does not parse proves nothing about the contract — it must be a valid
  # program that the checks then reject for its BEHAVIOUR.
  if ! bash -n "$dir/$file" 2>/dev/null; then
    bad "mutation '$label' does not parse — the substitution broke the syntax"; return
  fi
  if "$fn" "$dir"; then
    bad "mutation '$label' SURVIVED — the contract does not catch it"
  else
    ok "mutation '$label' is caught"
  fi
}
MUTN=0

# Every chk_* is THE CONTRACT CHECK for its guard, phrased positively: it returns 0 when the
# guard holds and non-zero when it does not. On a mutant the check must fail — that is the
# kill.

chk_create_opts() {  # 0 = zpool create still carries -m under the root and cachefile=none
  local dir="$1" line
  [ "$UID_NOW" = "0" ] || return 1     # make refuses as non-root: cannot prove, report caught
  local pool="mu-$$-$RANDOM" log="$dir/cmds.log"; : > "$log"
  local pdir="$E2E/pools/$pool"
  env PATH="$BIN:$PATH" STUB_CMDLOG="$log" \
      DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID=0 \
      DEDCOM_TESTPOOL_NAME="$pool" DEDCOM_TESTPOOL_SIZE=1M \
      STUB_VDEV="$pool\n\t$pdir/pool.img\n" \
      STUB_DS="$(printf '%s\t%s\n' "$pool" "$pdir/mount")" \
      bash "$dir/make-test-pool.sh" >/dev/null 2>&1
  line="$(grep -m1 '^zpool create ' "$log" || true)"
  rm -rf "$pdir"
  [ -n "$line" ] || return 1
  case "$line" in *" -m $pdir/mount "*) ;; *) return 1;; esac
  case "$line" in *" -o cachefile=none "*) ;; *) return 1;; esac
  return 0
}

# Both scanners CAPTURE grep's full output instead of using `grep -q` on the pipe: -q exits at
# the first match, sed catches SIGPIPE (141), and under pipefail that turns a FOUND violation
# into a not-found — a timing-dependent fail-open on exactly the files big enough to matter.
chk_no_root_mount() {  # 0 = no harness script places a pool at the filesystem root
  local dir="$1" f hits
  for f in $HARNESS_FILES; do
    hits="$(sed 's/[[:space:]]*#.*$//' "$dir/$f" | grep -E '"/\$POOL' || true)"
    [ -n "$hits" ] && return 1
  done
  return 0
}

chk_no_tmp() {  # 0 = no executable harness line names /tmp or /var/lib
  local dir="$1" f hits
  for f in $HARNESS_FILES; do
    hits="$(sed 's/[[:space:]]*#.*$//' "$dir/$f" | grep -E '(/tmp/|/var/lib/)' || true)"
    [ -n "$hits" ] && return 1
  done
  return 0
}

chk_uid_guard() {  # 0 = a non-numeric owner uid still refuses
  local dir="$1"
  if env DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="nobody" \
       bash -c '. "$1"' _ "$dir/testpool-lib.sh" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

chk_symlink_guard() {  # 0 = a symlinked root still refuses
  local dir="$1"
  [ -L "$WORK/rootlink" ] || return 1
  if env DEDCOM_E2E_ROOT="$WORK/rootlink" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
       bash -c '. "$1"' _ "$dir/testpool-lib.sh" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

chk_prefix_cleanup() {  # 0 = clean-stale without an exact name still refuses
  local dir="$1"
  [ "$UID_NOW" = "0" ] || return 1     # the gate needs root; cannot prove here, report caught
  # Every earlier gate is satisfied on purpose — env, root, stubs — so the only thing standing
  # between a defaulted pool name and a "pool not found" exit 0 is the argument check itself.
  if env PATH="$BIN:$PATH" STUB_CMDLOG="$WORK/mut.log" DEDCOM_G5_E2E=1 \
       DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
       DEDCOM="$BIN/zpool" \
       bash "$dir/e2e-g5.sh" clean-stale >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

chk_dataset_mounts() {  # 0 = a dataset mounted outside the root still refuses
  local dir="$1"
  if env PATH="$BIN:$PATH" STUB_CMDLOG="$WORK/mut.log" \
       DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME=escaped-mount \
       STUB_DS="$(printf 'escaped-mount\t/dedcom-escaped-mount\n')" \
       bash -c '. "$1"; tp_assert_dataset_mounts_contained escaped-mount' \
       _ "$dir/testpool-lib.sh" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

chk_guid_failopen() {  # 0 = an unreadable or empty GUID still refuses
  local dir="$1"
  if env PATH="$BIN:$PATH" STUB_CMDLOG="$WORK/mut.log" \
       DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME=guidprobe \
       STUB_GUID="" \
       bash -c '. "$1"; tp_pool_guid guidprobe' _ "$dir/testpool-lib.sh" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

# FROM/TO strings are assigned through quoted heredocs: the target lines carry every kind of
# quote themselves, and a heredoc reproduces them without any escaping to get subtly wrong.
setvar() { IFS= read -r "$1" || true; }

setvar M_FROM <<'EOT'
zpool create -o cachefile=none -m "$TP_MNT" "$TP_POOL" "$TP_IMG"
EOT
setvar M_TO <<'EOT'
zpool create "$TP_POOL" "$TP_IMG"
EOT
mutate "1. explicit mountpoint removed from zpool create" make-test-pool.sh \
  "$M_FROM" "$M_TO" chk_create_opts

setvar M_FROM <<'EOT'
G5ROOT="$PMNT/ds_a/g5"
EOT
setvar M_TO <<'EOT'
G5ROOT="/$POOL/ds_a/g5"
EOT
mutate "2. pool placed back at the filesystem root" e2e-g5.sh \
  "$M_FROM" "$M_TO" chk_no_root_mount

setvar M_FROM <<'EOT'
    STATE="$(tp_state_dir "$POOL")"
EOT
setvar M_TO <<'EOT'
    STATE="/tmp/$POOL-state"
EOT
mutate "3. state moved back to /tmp" e2e-g5.sh \
  "$M_FROM" "$M_TO" chk_no_tmp

setvar M_FROM <<'EOT'
    POOLDIR="$TP_DIR"
EOT
setvar M_TO <<'EOT'
    POOLDIR="/var/lib/$POOL"
EOT
mutate "3b. pool directory moved back to /var/lib" e2e-g5.sh \
  "$M_FROM" "$M_TO" chk_no_tmp

setvar M_FROM <<'EOT'
        ''|*[!0-9]*) tp_die "DEDCOM_E2E_OWNER_UID='$uid' is not a decimal uid"; return 1;;
EOT
setvar M_TO <<'EOT'
        '') tp_die "DEDCOM_E2E_OWNER_UID is empty"; return 1;;
EOT
mutate "4. arbitrary owner uid accepted" testpool-lib.sh \
  "$M_FROM" "$M_TO" chk_uid_guard

# Mutation 5 removes BOTH symlink layers — the lstat refusal and the canonical-spelling
# comparison. Removing only one is an equivalent mutant: the other layer still refuses, which
# is the defence working, not a hole. The kill therefore targets the composite.
mut5_dir="$WORK/mut-$MUTN"; MUTN=$((MUTN+1))
mkdir -p "$mut5_dir"
cp "$HERE"/*.sh "$mut5_dir/" 2>/dev/null
setvar M_FROM <<'EOT'
    if [ -L "$root" ]; then tp_die "DEDCOM_E2E_ROOT='$root' is a symbolic link"; return 1; fi
EOT
setvar M_TO <<'EOT'
    :
EOT
setvar M_FROM2 <<'EOT'
    if [ "$real" != "$root" ]; then
EOT
setvar M_TO2 <<'EOT'
    if false; then
EOT
if literal_sub "$mut5_dir/testpool-lib.sh" "$M_FROM" "$M_TO" &&
   literal_sub "$mut5_dir/testpool-lib.sh" "$M_FROM2" "$M_TO2"; then
  if chk_symlink_guard "$mut5_dir"; then
    bad "mutation '5. symlink guard removed (both layers)' SURVIVED — the contract does not catch it"
  else
    ok "mutation '5. symlink guard removed (both layers)' is caught"
  fi
else
  bad "mutation '5. symlink guard removed (both layers)' changed nothing — a target line is gone"
fi

setvar M_FROM <<'EOT'
    stale="${2:-}"
EOT
setvar M_TO <<'EOT'
    stale="${2:-dedcom-g5-any}"
EOT
mutate "6. prefix clean-stale restored" e2e-g5.sh \
  "$M_FROM" "$M_TO" chk_prefix_cleanup

setvar M_FROM <<'EOT'
            *) tp_die "dataset '$name' is mounted at '$mp', outside $TP_MNT"; return 1;;
EOT
setvar M_TO <<'EOT'
            *) ;;
EOT
mutate "7. dataset mountpoint check removed" testpool-lib.sh \
  "$M_FROM" "$M_TO" chk_dataset_mounts

setvar M_FROM <<'EOT'
        ''|*[!0-9]*) tp_die "unexpected GUID for pool '$pool': [$guid]"; return 1;;
EOT
setvar M_TO <<'EOT'
        *) ;;
EOT
mutate "8. GUID query fails open" testpool-lib.sh \
  "$M_FROM" "$M_TO" chk_guid_failopen

# ---- FIX2A mutations: each check above must also be a kill ----

chk_owner_comparison() {  # 0 = a third uid owning a chain node still refuses
  local dir="$1"
  if env PATH="$BIN:$PATH" STUB_CMDLOG="$WORK/mut.log" \
       STAT_FAKE_PATH="$own_probe" STAT_FAKE_UID=4242 \
       DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" \
       bash -c '. "$1" && tp_check_node "$2" 1234' _ "$dir/testpool-lib.sh" "$own_probe" \
       >/dev/null 2>&1; then
    return 1
  fi
  return 0
}
chk_bare_zdb()   { audit_bare_zdb "$1"; }
chk_no_nobody()  { audit_no_nobody "$1"; }
chk_no_advice()  { audit_no_destroy_advice "$1"; }

setvar M_FROM <<'EOT'
    if [ "$owner" != "0" ] && [ "$owner" != "$uid" ]; then
EOT
setvar M_TO <<'EOT'
    if false; then
EOT
mutate "9. owner comparison removed from tp_check_node" testpool-lib.sh \
  "$M_FROM" "$M_TO" chk_owner_comparison

setvar M_FROM <<'EOT'
    "$G5_ZDB" -dddd "$ds" "$obj" 2>/dev/null \
EOT
setvar M_TO <<'EOT'
    zdb -dddd "$ds" "$obj" 2>/dev/null \
EOT
mutate "10. bare zdb restored" e2e-g5.sh \
  "$M_FROM" "$M_TO" chk_bare_zdb

setvar M_FROM <<'EOT'
runuser -u "$OWNER_USER" -- "$DEDCOM" --state-dir "$STATE_FAIL" --scan "$FAILROOT" --no-resume
EOT
setvar M_TO <<'EOT'
runuser -u nobody -- "$DEDCOM" --state-dir "$STATE_FAIL" --scan "$FAILROOT" --no-resume
EOT
mutate "11. runuser nobody restored" e2e-dir-completeness.sh \
  "$M_FROM" "$M_TO" chk_no_nobody

setvar M_FROM <<'EOT'
    printf '       BLOCKED: pool %s is left in place, untouched.\n' "$POOL" >&2
EOT
setvar M_TO <<'EOT'
    printf '       recover manually: sudo zpool destroy %s && sudo rm -f %s/pool.img\n' "$POOL" "$POOLDIR" >&2
EOT
mutate "12. manual destroy advice restored" e2e-g5.sh \
  "$M_FROM" "$M_TO" chk_no_advice

# ---- FIX2B mutations: tri-state, verified closure, tmux isolation ----

chk_unknown_not_absent() {  # 0 = an enumeration error still refuses the clean noop
  local dir="$1"
  if env PATH="$BIN:$PATH" STUB_CMDLOG="$WORK/mut.log" STUB_ENUM_RC=2 \
       DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="mu-none-$$" \
       bash "$dir/teardown-test-pool.sh" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

chk_make_enum_gate() {  # 0 = make still refuses to create after an enumeration error
  local dir="$1"
  [ "$UID_NOW" = "0" ] || return 1
  local pool="mu-mk-$$-$RANDOM" log="$WORK/mut.log"; : > "$log"
  env PATH="$BIN:$PATH" STUB_CMDLOG="$log" STUB_ENUM_RC=2 \
      DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID=0 DEDCOM_TESTPOOL_NAME="$pool" \
      bash "$dir/make-test-pool.sh" >/dev/null 2>&1
  local rc=$?
  local created; created="$(grep -c '^zpool create' "$log" || true)"
  local dirstate=absent; [ -e "$E2E/pools/$pool" ] && dirstate=exists
  rm -rf "$E2E/pools/$pool" 2>/dev/null
  [ "$rc" != 0 ] && [ "$created" = 0 ] && [ "$dirstate" = absent ] && return 0
  return 1
}

chk_residue_blocked() {  # 0 = absent + residue still refuses with exit non-zero
  local dir="$1"
  local pool="mu-res-$$-$RANDOM"
  local pdir="$E2E/pools/$pool"
  mkdir -p "$pdir"; : > "$pdir/pool.img"
  local rc=0
  env PATH="$BIN:$PATH" STUB_CMDLOG="$WORK/mut.log" \
      DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="$pool" \
      bash "$dir/teardown-test-pool.sh" >/dev/null 2>&1 || rc=$?
  rm -rf "$pdir" 2>/dev/null
  [ "$rc" != 0 ] && return 0
  return 1
}

chk_removal_verified() {  # 0 = a failed artifact removal still turns teardown non-zero
  local dir="$1"
  local pool="mu-cl-$$-$RANDOM"
  local pdir="$E2E/pools/$pool"
  mkdir -p "$pdir/mount"; chmod 0700 "$pdir" "$pdir/mount" 2>/dev/null || true
  : > "$pdir/pool.img"
  local canon; canon="$(readlink -f "$pdir/pool.img")"
  {
    printf 'root\t%s\n'  "$E2E"
    printf 'pool\t%s\n'  "$pool"
    printf 'guid\t%s\n'  7777777777777777777
    printf 'image\t%s\n' "$canon"
    printf 'mount\t%s\n' "$pdir/mount"
    printf 'vdev\t%s\n'  "$canon"
    printf 'dataset\t%s\t%s\n' "$pool" "$pdir/mount"
  } > "$pdir/manifest.txt"
  local rc=0
  env PATH="$BIN:$PATH" STUB_CMDLOG="$WORK/mut.log" \
      STUB_POOLNAMES="$pool\n" STUB_VDEV="$pool\n\t$canon\n" \
      STUB_DS="$(printf '%s\t%s\n' "$pool" "$pdir/mount")" \
      STUB_RM_FAIL_PATH="$pdir/pool.img" \
      DEDCOM_E2E_ROOT="$E2E" DEDCOM_E2E_OWNER_UID="$UID_NOW" DEDCOM_TESTPOOL_NAME="$pool" \
      bash "$dir/teardown-test-pool.sh" >/dev/null 2>&1 || rc=$?
  rm -rf "$pdir" 2>/dev/null
  [ "$rc" != 0 ] && return 0
  return 1
}

chk_tmux_private() { audit_tmux_private "$1"; }

setvar M_FROM <<'EOT'
        printf 'unknown\n'; return 0
EOT
setvar M_TO <<'EOT'
        printf 'absent\n'; return 0
EOT
mutate "13. a failed enumeration reported as absent" testpool-lib.sh \
  "$M_FROM" "$M_TO" chk_unknown_not_absent

setvar M_FROM <<'EOT'
        exit 1 ;;   # an unproved absence creates nothing
EOT
setvar M_TO <<'EOT'
        ;;   # mutant: carry on after a failed enumeration
EOT
mutate "14. make continues past an enumeration error" make-test-pool.sh \
  "$M_FROM" "$M_TO" chk_make_enum_gate

setvar M_FROM <<'EOT'
        exit 1 ;;   # residue with no pool to verify against stays untouched
EOT
setvar M_TO <<'EOT'
        exit 0 ;;   # mutant: residue waved through
EOT
mutate "15. absent-plus-residue returns success" teardown-test-pool.sh \
  "$M_FROM" "$M_TO" chk_residue_blocked

setvar M_FROM <<'EOT'
    exit 1   # an unremoved artifact is a hard failure, never a warning
EOT
setvar M_TO <<'EOT'
    return 0   # mutant: residue reported but ignored
EOT
mutate "16. removal errors ignored by the closure" teardown-test-pool.sh \
  "$M_FROM" "$M_TO" chk_removal_verified

setvar M_FROM <<'EOT'
ptmux() { tmux -S "$TMUX_SOCKET" "$@"; }
EOT
setvar M_TO <<'EOT'
ptmux() { tmux "$@"; }
EOT
mutate "17. a tmux call loses the private socket" e2e-dir-completeness.sh \
  "$M_FROM" "$M_TO" chk_tmux_private

setvar M_FROM <<'EOT'
        ptmux kill-server 2>/dev/null \
EOT
setvar M_TO <<'EOT'
        tmux kill-server 2>/dev/null \
EOT
mutate "18. the global tmux kill-server returns" e2e-dir-completeness.sh \
  "$M_FROM" "$M_TO" chk_tmux_private

echo "== result: PASS=$PASS FAIL=$FAIL SKIP=$SKIP =="
[ "$FAIL" -eq 0 ]
