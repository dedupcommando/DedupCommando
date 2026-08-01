#!/usr/bin/env bash
# e2e-g5.sh — GUIDED destructive E2E on a disposable loopback-ZFS pool.
#
# AUTHORITATIVE ENVIRONMENT (owner-sanctioned): a local, human-controlled Linux
# host/VM with OpenZFS + root/sudo, using a freshly-created disposable loopback
# zpool owned by this harness. NEVER /tank or any production pool/dataset.
# GitHub-hosted runners are NOT authoritative for this destructive E2E (no stable ZFS module/root);
# this destructive E2E is validated only by a clean operator run on such a host.
#
# WHY GUIDED: dedcom has NO headless apply by design — destructive actions
# (hardlink / reflink / delete-to-quarantine) happen only in the TUI (F11) or via a
# ScanScript saved from the F11 overlay. So this harness automates everything that is
# deterministic and checkable (pool, fixtures, headless --scan, ZFS snapshot ops,
# post-apply verification) and pauses for ONE operator step per destructive scenario.
# It does NOT drive the TUI via expect/tmux — apply stays human-confirmed by design.
#
# Action keys (manual §08): Keeper=F7/K, Hardlink=F5/H, Reflink=F6/C, Delete=F8/D,
# apply overlay=F11, save ScanScript=S.
#
# Usage:
#   sudo DEDCOM_G5_E2E=1 DEDCOM=/path/to/dedcom scripts/e2e-g5.sh [scenario]
#     scenarios: hardlink reflink two-alias preflight script-preflight delete-restore
#                revalidate snapshot interrupt dir-dedup all   (default: all)
#   sudo DEDCOM_G5_E2E=1 scripts/e2e-g5.sh clean-stale   # tear down leftover dedcom-g5-* pools
#
# shellcheck disable=SC2015
#   `<cond> && ok ... || fail ...` below is intentional: ok/fail/info are printf-based
#   status reporters that always return 0, so the `|| fail` branch never fires on a true
#   condition. (File-level: applies to the verification one-liners in every scenario.)
set -euo pipefail

# --------------------------------------------------------------------- guardrails
g5_die() { printf '\nABORT: %s\n' "$*" >&2; exit 1; }

[ "${DEDCOM_G5_E2E:-}" = "1" ] \
    || g5_die "refusing to run the destructive E2E. Set DEDCOM_G5_E2E=1 explicitly."
[ "$(id -u)" = "0" ] || g5_die "must run as root (ZFS pool ops require root)."
command -v zpool >/dev/null 2>&1 || g5_die "'zpool' not found in PATH (OpenZFS not installed?)."
command -v zfs   >/dev/null 2>&1 || g5_die "'zfs' not found in PATH (OpenZFS not installed?)."

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${HARNESS:-$SCRIPT_DIR}"
DEDCOM="${DEDCOM:-/tmp/dedcom-e2e/dedcom}"
for s in make-test-pool.sh teardown-test-pool.sh testpool-lib.sh; do
    [ -e "$HARNESS/$s" ] || g5_die "harness script missing: $HARNESS/$s (set HARNESS=...)."
done

# --------------------------------- clean-stale: tear down leftover dedcom-g5-* pools only
if [ "${1:-}" = "clean-stale" ]; then
    found=0
    while IFS= read -r p; do
        case "$p" in
            dedcom-g5-*)
                found=1
                echo "tearing down stale pool: $p"
                DEDCOM_TESTPOOL_NAME="$p" DEDCOM_TESTPOOL_DIR="/var/lib/$p" \
                    "$HARNESS/teardown-test-pool.sh" \
                    || echo "  (teardown of $p reported an error; inspect manually)"
                ;;
        esac
    done < <(LC_ALL=C zpool list -H -o name 2>/dev/null || true)
    [ "$found" = 1 ] || echo "no dedcom-g5-* pools found."
    exit 0
fi

[ -x "$DEDCOM" ] || g5_die "dedcom binary not found/executable at '$DEDCOM' (set DEDCOM=...)."

# ----------------------------------------------------------- config / unique disposable pool
TS="$(date +%Y%m%d-%H%M%S)-$$"
POOL="dedcom-g5-$TS"
POOLDIR="/var/lib/$POOL"
export DEDCOM_TESTPOOL_NAME="$POOL"
export DEDCOM_TESTPOOL_DIR="$POOLDIR"
export DEDCOM_TESTPOOL_SIZE="${DEDCOM_G5_SIZE:-2G}"

G5ROOT="/$POOL/ds_a/g5"          # ds_a is created by make-test-pool.sh
STATE="/tmp/$POOL-state"

# never operate outside our own pool; never touch /tank
case "$POOL" in dedcom-g5-*) ;; *) g5_die "pool name '$POOL' is not dedcom-g5-* — refusing." ;; esac
case "$G5ROOT" in /tank/*|*/tank/*) g5_die "G5ROOT '$G5ROOT' touches /tank — refusing." ;; esac

# --------------------------------------------------------------------- logging / helpers
banner() { printf '\n========== %s ==========\n' "$*"; }
info()   { printf '  %s\n' "$*"; }
ok()     { printf '  [OK]   %s\n' "$*"; }
fail()   { printf '  [FAIL] %s\n' "$*" >&2; G5_FAILED=1; }
G5_FAILED=0

cleanup() {
    local rc=$?
    banner "cleanup"
    rm -rf "$STATE" 2>/dev/null || true
    if LC_ALL=C zpool list "$POOL" >/dev/null 2>&1; then
        info "destroying disposable pool $POOL (teardown-test-pool.sh, topology-verified)"
        if ! "$HARNESS/teardown-test-pool.sh"; then
            printf '\n  !! teardown of %s reported an error. Recover manually:\n' "$POOL" >&2
            printf '       sudo zpool destroy %s && sudo rm -f %s/pool.img && sudo rmdir %s\n' \
                   "$POOL" "$POOLDIR" "$POOLDIR" >&2
        fi
    fi
    if [ "$rc" -eq 0 ] && [ "$G5_FAILED" -eq 0 ]; then
        printf '\n========== RESULT: all checks passed ==========\n'
    else
        printf '\n========== RESULT: FAILURES (rc=%s, failed=%s) — see [FAIL] above ==========\n' \
               "$rc" "$G5_FAILED" >&2
    fi
}
trap cleanup EXIT INT TERM

# operator pause: print precise TUI steps, wait for the human, then continue to verify.
operator() {
    printf '\n  >>> OPERATOR STEP (apply is TUI-only by design) <<<\n'
    printf '%s\n' "$1" | sed 's/^/      /'
    printf '      Open the TUI on this scan:   %s --state-dir %s\n' "$DEDCOM" "$STATE"
    printf '      Apply (F11 → confirm) or save+run a ScanScript (S), exit the TUI,\n'
    printf '      then press ENTER here to run verification.\n'
    read -r _ || true
}

scan() { rm -rf "$STATE"; "$DEDCOM" --state-dir "$STATE" --scan "$1" --no-resume; }
inode() { stat -c '%i' -- "$1"; }

# xattr helpers (D-1): setfattr/getfattr come from the `attr` package and are not everywhere,
# python3 is. Returning non-zero means "could not do it" — the caller fails the scenario.
xattr_set() {  # path name value
    if command -v setfattr >/dev/null 2>&1; then
        setfattr -n "$2" -v "$3" -- "$1"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import os,sys; os.setxattr(sys.argv[1], sys.argv[2], sys.argv[3].encode())' \
                "$1" "$2" "$3"
    else
        return 127
    fi
}
xattr_get() {  # path name -> value on stdout, empty if absent
    if command -v getfattr >/dev/null 2>&1; then
        getfattr --only-values -n "$2" -- "$1" 2>/dev/null || true
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import os,sys
try: sys.stdout.write(os.getxattr(sys.argv[1], sys.argv[2]).decode())
except OSError: pass' "$1" "$2"
    else
        return 127
    fi
}
quarantined() { find "/$POOL" -path '*/.dedcom-quarantine/*' -name "$1" 2>/dev/null | grep -q .; }

# Data-block addresses of one file, sorted and de-duplicated (R2D-C5-2).
#
# `bcloneused` is a pool-wide counter and says nothing about WHICH blocks two files share, so it
# cannot tell a clone from a fresh copy written into free space. The DVAs can: a block clone makes
# the published file point at the keeper's own vdev offsets.
dvas_of() {  # dataset abspath -> "vdev:offset:size" per line
    local ds="$1" path="$2" obj
    obj="$(stat -c '%i' -- "$path")" || return 1
    sync; zpool sync "$POOL" 2>/dev/null || true
    zdb -dddd "$ds" "$obj" 2>/dev/null \
        | grep -oE 'DVA\[0\]=<[0-9]+:[0-9a-fA-F]+:[0-9a-fA-F]+>' \
        | sed 's/DVA\[0\]=<//; s/>//' | sort -u
}

# Allocated bytes of a dataset, for a before/after delta that can be compared with a claim.
used_of() { zfs get -Hp -o value used "$1"; }

# Both halves of the release the summary screen names: destroy the safety snapshots, then purge
# the quarantine.
#
# Purging alone releases nothing measurable, and that is not a bug in the tool: the safety snapshot
# taken before the batch still references the old blocks, which is the whole point of taking it. So
# a check that only removes the quarantine measures the snapshot, not the plan.
purge_and_release() {
    zfs list -H -t snapshot -o name -r "$POOL" 2>/dev/null \
        | grep '@dedcom-' \
        | while read -r snap; do zfs destroy "$snap"; done
    find "/$POOL" -type d -name '.dedcom-quarantine' -prune -print0 2>/dev/null \
        | xargs -0 -r rm -rf --
    sync; zpool sync "$POOL" 2>/dev/null || true
}

# 0 if the latest scan row is observably in-progress (walking/hashing); needs python3.
scan_in_progress() {
    [ -f "$STATE/dedcom.db" ] && command -v python3 >/dev/null 2>&1 || return 1
    python3 - "$STATE/dedcom.db" 2>/dev/null <<'PY'
import sqlite3, sys
r = sqlite3.connect(sys.argv[1]).execute("SELECT status FROM scan ORDER BY id DESC LIMIT 1").fetchone()
sys.exit(0 if r and r[0] in ("walking", "hashing") else 1)
PY
}

# --------------------------------------------------------------------- scenarios
scenario_hardlink() {
    banner "hardlink — same inode within one dataset"
    local d="$G5ROOT/hardlink"; rm -rf "$d"; mkdir -p "$d"
    head -c 256K /dev/urandom > "$d/keeper.bin"; cp "$d/keeper.bin" "$d/dup.bin"
    local i_keep; i_keep="$(inode "$d/keeper.bin")"
    info "fixture: keeper.bin, dup.bin (identical) in one dataset; keeper inode=$i_keep"
    scan "$d"
    operator "Group: keeper.bin + dup.bin.
Mark keeper.bin = Keeper (F7), dup.bin = Hardlink (F5), then F11.
Expected: dup.bin becomes a hardlink to keeper.bin; original dup.bin → quarantine."
    banner "verify hardlink"
    [ -f "$d/dup.bin" ] || { fail "dup.bin missing after apply"; return; }
    local i_dup; i_dup="$(inode "$d/dup.bin")"
    [ "$i_dup" = "$i_keep" ] && ok "dup.bin shares keeper inode ($i_keep)" \
                              || fail "dup.bin inode=$i_dup != keeper inode=$i_keep"
    cmp -s "$d/keeper.bin" "$d/dup.bin" && ok "content identical" || fail "content differs"
    quarantined "dup.bin" && ok "original dup.bin evacuated to quarantine" \
                          || info "note: original dup.bin not seen in quarantine — verify manually"
}

scenario_reflink() {
    banner "reflink — separate inode, shared blocks, and the target's own metadata (D-1)"
    local d="$G5ROOT/reflink"; rm -rf "$d"; mkdir -p "$d"
    head -c 512K /dev/urandom > "$d/keeper.bin"; cp "$d/keeper.bin" "$d/dup.bin"
    # D-1: the clone is a NEW inode, so it must come back with dup.bin's owner/mode/xattr —
    # not the keeper's, and not root's. Make all three differ, or the check proves nothing.
    chmod 0644 "$d/keeper.bin"
    chmod 0600 "$d/dup.bin"
    chown 12345:12345 "$d/dup.bin" || { fail "cannot chown dup.bin — D-1 cannot be checked"; return; }
    xattr_set "$d/dup.bin" user.dedcom_e2e "target-metadata" \
        || { fail "cannot set user.dedcom_e2e on dup.bin (install 'attr' or python3; ensure the dataset stores xattrs)"; return; }
    local i_keep; i_keep="$(inode "$d/keeper.bin")"
    info "fixture: keeper.bin 0644 root:root, dup.bin 0600 12345:12345 + user.dedcom_e2e; keeper inode=$i_keep"
    scan "$d"
    operator "Group: keeper.bin + dup.bin.
Mark keeper.bin = Keeper (F7), dup.bin = Reflink (F6), then F11.
Expected: dup.bin keeps a SEPARATE inode but shares blocks with keeper (ZFS block_cloning),
and keeps its own 0600 / 12345:12345 / user.dedcom_e2e."
    banner "verify reflink"
    [ -f "$d/dup.bin" ] || { fail "dup.bin missing after apply"; return; }
    local i_dup; i_dup="$(inode "$d/dup.bin")"
    [ "$i_dup" != "$i_keep" ] && ok "dup.bin keeps a separate inode ($i_dup)" \
                              || fail "dup.bin inode == keeper inode ($i_keep) — that's a hardlink, not reflink"
    cmp -s "$d/keeper.bin" "$d/dup.bin" && ok "content identical" || fail "content differs"
    # R2D-C5-2: the blocks, by address. A pool-wide `bcloneused` counter cannot say which file
    # shares which block, and a fresh copy written into free space would satisfy it just as well.
    local keeper_dvas dup_dvas shared
    keeper_dvas="$(dvas_of "$POOL/ds_a" "$d/keeper.bin")"
    dup_dvas="$(dvas_of "$POOL/ds_a" "$d/dup.bin")"
    if [ -z "$keeper_dvas" ] || [ -z "$dup_dvas" ]; then
        fail "zdb produced no DVAs — block sharing is UNPROVEN (do not call this scenario green)"
    else
        shared="$(comm -12 <(printf '%s\n' "$keeper_dvas") <(printf '%s\n' "$dup_dvas") | wc -l)"
        [ "$shared" -gt 0 ] && ok "published clone shares $shared block address(es) with the keeper" \
                            || fail "no DVA in common — the published file is a COPY, not a clone"
    fi
    quarantined "dup.bin" && ok "original dup.bin evacuated to quarantine" \
                          || info "note: original dup.bin not seen in quarantine — verify manually"
    # And the old target really was its own allocation before it was replaced: purging the
    # quarantine has to give the space back.
    local before after freed
    before="$(used_of "$POOL/ds_a")"
    purge_and_release
    after="$(used_of "$POOL/ds_a")"
    freed=$((before - after))
    info "post-purge allocation delta on $POOL/ds_a: $freed bytes (fixture is 512 KiB)"
    [ "$freed" -ge 262144 ] && ok "purging the quarantine released the old allocation" \
                            || fail "delta $freed is too small — the old target was not a separate allocation"
    # D-1 proper: on the filesystem the feature exists for.
    local mode owner xa
    mode="$(stat -c '%a' -- "$d/dup.bin")"
    owner="$(stat -c '%u:%g' -- "$d/dup.bin")"
    xa="$(xattr_get "$d/dup.bin" user.dedcom_e2e)"
    [ "$mode" = "600" ] && ok "mode preserved (0600)" \
                        || fail "mode is 0$mode, expected 0600 — D-1 regression (clone published with the umask's mode)"
    [ "$owner" = "12345:12345" ] && ok "owner preserved (12345:12345)" \
                                 || fail "owner is $owner, expected 12345:12345 — D-1 regression (clone published as the running user)"
    [ "$xa" = "target-metadata" ] && ok "xattr user.dedcom_e2e preserved" \
                                  || fail "user.dedcom_e2e is '$xa', expected 'target-metadata' — D-1 regression (xattrs/ACL lost)"
}

scenario_delete_restore() {
    banner "delete (quarantine) + restore"
    local d="$G5ROOT/delete"; rm -rf "$d"; mkdir -p "$d"
    head -c 256K /dev/urandom > "$d/keeper.bin"; cp "$d/keeper.bin" "$d/dup.bin"
    info "fixture: keeper.bin + dup.bin (identical)"
    scan "$d"
    operator "Group: keeper.bin + dup.bin.
Mark keeper.bin = Keeper (F7), dup.bin = Delete (F8), then F11.
Expected: dup.bin moved to .dedcom-quarantine/<ts>/...; keeper.bin untouched."
    banner "verify delete → quarantine"
    [ -f "$d/keeper.bin" ] && ok "keeper.bin intact" || fail "keeper.bin missing"
    [ -e "$d/dup.bin" ] && fail "dup.bin still at original path (expected moved to quarantine)" \
                        || ok "dup.bin removed from original path"
    local q; q="$(find "/$POOL" -path '*/.dedcom-quarantine/*' -name 'dup.bin' 2>/dev/null | head -1 || true)"
    [ -n "$q" ] && ok "dup.bin found in quarantine: $q" || { fail "dup.bin not found in quarantine"; return; }
    banner "restore from quarantine"
    info "restoring: mv '$q' '$d/dup.bin'"
    mv -n -- "$q" "$d/dup.bin"
    [ -f "$d/dup.bin" ] && cmp -s "$d/keeper.bin" "$d/dup.bin" \
        && ok "dup.bin restored and content matches keeper" || fail "restore failed / content mismatch"
}

scenario_revalidate() {
    banner "revalidate — file changed AFTER scan must cancel the destructive action"
    local d="$G5ROOT/reval"; rm -rf "$d"; mkdir -p "$d"
    head -c 256K /dev/urandom > "$d/keeper.bin"; cp "$d/keeper.bin" "$d/dup.bin"
    info "fixture: keeper.bin + dup.bin (identical)"
    scan "$d"
    info "MUTATING dup.bin AFTER the scan (overwrite with new random content of the same size)"
    head -c 256K /dev/urandom > "$d/dup.bin"
    local sum_before; sum_before="$(sha256sum "$d/dup.bin" | cut -d' ' -f1)"
    operator "Group from the scan still lists keeper.bin + dup.bin (as scanned).
Mark keeper.bin = Keeper (F7), dup.bin = Hardlink (F5) or Delete (F8), then F11.
Expected: revalidate detects dup.bin changed after the scan and CANCELS the action
(error like 'dup.bin changed after the scan — action cancelled'); dup.bin is preserved (auto-returned from quarantine if needed)."
    banner "verify revalidate protection"
    [ -f "$d/dup.bin" ] || { fail "dup.bin missing — revalidate did NOT protect the changed file"; return; }
    local sum_after; sum_after="$(sha256sum "$d/dup.bin" | cut -d' ' -f1)"
    [ "$sum_after" = "$sum_before" ] && ok "changed dup.bin preserved unchanged (revalidate blocked the action)" \
                                     || fail "dup.bin content changed — revalidate did not protect it"
    local i_dup i_keep; i_dup="$(inode "$d/dup.bin")"; i_keep="$(inode "$d/keeper.bin")"
    [ "$i_dup" != "$i_keep" ] && ok "dup.bin was NOT hardlinked to keeper (action correctly canceled)" \
                              || fail "dup.bin was hardlinked despite post-scan change"
}

scenario_snapshot() {
    banner "snapshot / recovery — dedcom @dedcom-<ts> snapshot + rollback"
    local d="$G5ROOT/snap"; rm -rf "$d"; mkdir -p "$d"
    head -c 256K /dev/urandom > "$d/keeper.bin"; cp "$d/keeper.bin" "$d/dup.bin"
    local before; before="$(find "$d" -type f | sort)"
    info "fixture: keeper.bin + dup.bin; pre-apply file set recorded"
    scan "$d"
    operator "Group: keeper.bin + dup.bin.
Mark keeper.bin = Keeper (F7), dup.bin = Delete (F8) or Hardlink (F5), then F11.
Expected: dedcom takes a ZFS snapshot ds_a@dedcom-<ts> before the destructive batch."
    banner "verify snapshot present"
    local snaps; snaps="$(LC_ALL=C zfs list -H -t snapshot -o name "$POOL/ds_a" 2>/dev/null | grep '@dedcom-' || true)"
    [ -n "$snaps" ] && ok "dedcom snapshot(s) present: $(printf '%s' "$snaps" | tr '\n' ' ')" \
                    || { fail "no @dedcom-<ts> snapshot found on $POOL/ds_a"; return; }
    banner "recovery — rollback to the dedcom snapshot restores pre-apply state"
    local snap; snap="$(printf '%s\n' "$snaps" | tail -1)"
    info "rolling back: zfs rollback -r $snap"
    zfs rollback -r "$snap"
    local after; after="$(find "$d" -type f | sort)"
    [ "$after" = "$before" ] && ok "post-rollback file set matches pre-apply state" \
                             || fail "file set differs after rollback (recovery incomplete)"
}

scenario_interrupt() {
    banner "interrupt — abort a headless scan mid-flight, DB stays resumable, resume completes"
    local d="$G5ROOT/interrupt"; rm -rf "$d"; mkdir -p "$d"
    local n="${DEDCOM_G5_INTERRUPT_FILES:-6000}"
    info "fixture: $n x 64K files so the hashing phase is long enough to catch in-progress"
    local i; for i in $(seq 1 "$n"); do head -c 64K /dev/urandom > "$d/f$i.bin"; done
    cp "$d/f1.bin" "$d/f1-copy.bin"
    rm -rf "$STATE"
    # We MUST observe the scan in-progress (walking/hashing) before aborting — otherwise we cannot
    # prove the interrupt landed mid-flight. And we abort with SIGTERM, NOT SIGINT: a non-interactive
    # shell sets SIGINT/SIGQUIT to SIG_IGN for `&` background jobs (job control off), and dedcom
    # installs no signal handler, so a SIGINT to the backgrounded scan is silently ignored and the
    # scan runs to completion — a false-green. SIGTERM is not masked and aborts the scan.
    info "starting headless scan in background; waiting until it is observably in-progress"
    "$DEDCOM" --state-dir "$STATE" --scan "$d" --no-resume & local pid=$!
    # Poll until the scan is walking/hashing while the process is still alive (max ~30s).
    local waited=0 inprogress=0
    while kill -0 "$pid" 2>/dev/null; do
        if scan_in_progress; then inprogress=1; break; fi
        sleep 1; waited=$((waited + 1)); [ "$waited" -ge 30 ] && break
    done
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        fail "scan finished before it could be interrupted — raise DEDCOM_G5_INTERRUPT_FILES (was $n)"
        rm -rf "$d"; return
    fi
    if [ "$inprogress" != 1 ]; then
        kill -KILL "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
        fail "could not observe the scan in-progress within ${waited}s (need python3 + a live walking/hashing scan) — cannot prove a mid-flight interrupt"
        rm -rf "$d"; return
    fi
    info "scan observed in-progress after ${waited}s — sending SIGTERM"
    kill -TERM "$pid" 2>/dev/null || true
    # Bounded wait for termination; escalate to SIGKILL and FAIL if it refuses to die.
    local t=0 dead=0
    while [ "$t" -lt 10 ]; do
        kill -0 "$pid" 2>/dev/null || { dead=1; break; }
        sleep 1; t=$((t + 1))
    done
    if [ "$dead" != 1 ]; then
        kill -KILL "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
        fail "scan did not terminate within ${t}s of SIGTERM — sent SIGKILL"
        rm -rf "$d"; return
    fi
    local sigrc=0; wait "$pid" 2>/dev/null || sigrc=$?
    ok "scan aborted by SIGTERM (terminated after ${t}s, exit=$sigrc)"
    banner "verify DB integrity ok AND scan left unfinished (resumable, NOT complete)"
    [ -f "$STATE/dedcom.db" ] || { fail "no scan DB after abort ($STATE/dedcom.db missing)"; rm -rf "$d"; return; }
    command -v python3 >/dev/null 2>&1 || { fail "python3 required to prove scan status/integrity"; rm -rf "$d"; return; }
    STATE_DB="$STATE/dedcom.db" python3 - <<'PY' && ok "integrity_check ok; latest scan is unfinished (resumable)" || { fail "DB corrupt, OR scan reached a terminal status before abort (not actually interrupted — raise DEDCOM_G5_INTERRUPT_FILES)"; rm -rf "$d"; return; }
import os, sqlite3, sys
con = sqlite3.connect(os.environ["STATE_DB"])
if con.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
    print("  integrity_check FAILED"); sys.exit(1)
row = con.execute("SELECT id, status FROM scan ORDER BY id DESC LIMIT 1").fetchone()
if row is None:
    print("  no scan row recorded"); sys.exit(1)
print(f"  latest scan after abort: id={row[0]} status={row[1]}")
sys.exit(1 if row[1] in ("complete", "complete_with_warnings") else 0)
PY
    banner "resume — the same scan continues from its checkpoint and reaches a terminal status"
    local rlog="$STATE/resume.out"
    if "$DEDCOM" --state-dir "$STATE" --scan "$d" >"$rlog" 2>&1; then
        grep -q "Resuming unfinished scan" "$rlog" \
            && ok "resume picked up the checkpoint (saw 'Resuming unfinished scan')" \
            || fail "resume did NOT report 'Resuming unfinished scan' — it re-scanned fresh instead of continuing"
    else
        sed 's/^/    /' "$rlog" >&2; fail "resume run exited non-zero"; rm -rf "$d"; return
    fi
    STATE_DB="$STATE/dedcom.db" python3 - <<'PY' && ok "after resume: latest scan is terminal (complete/complete_with_warnings)" || fail "after resume the scan is still not complete"
import os, sqlite3, sys
con = sqlite3.connect(os.environ["STATE_DB"])
row = con.execute("SELECT id, status FROM scan ORDER BY id DESC LIMIT 1").fetchone()
print(f"  latest scan after resume: id={row[0]} status={row[1]}")
sys.exit(0 if row and row[1] in ("complete", "complete_with_warnings") else 1)
PY
    rm -rf "$d"
}

# R2D-C5-2: two pathnames of ONE allocation. The whole point of the checkpoint is that they are
# one allocation's worth of space, and that covering only one of them is worth nothing at all.
scenario_two_alias() {
    banner "two aliases of one allocation — one allocation's worth, or nothing"
    local d="$G5ROOT/twoalias"; rm -rf "$d"; mkdir -p "$d"
    head -c 1M /dev/urandom > "$d/keeper.bin"
    cp "$d/keeper.bin" "$d/alias_a.bin"
    ln "$d/alias_a.bin" "$d/alias_b.bin"
    info "fixture: keeper.bin, plus alias_a.bin and alias_b.bin — two names, ONE inode"
    scan "$d"

    # Part 1: cover only one of the two names. The plan is allowed and it is worth zero.
    operator "Group: keeper.bin + alias_a.bin + alias_b.bin.
Mark keeper.bin = Keeper (F7) and alias_a.bin = Delete (F8). Leave alias_b.bin UNMARKED.
Before pressing F11, read the confirmation: it must say guaranteed 0 and explain that a
pathname of this allocation stays outside the plan. Then apply (F11 → Y)."
    banner "verify partial coverage realizes zero"
    [ -e "$d/alias_a.bin" ] && fail "alias_a.bin still at its original path" \
                            || ok "alias_a.bin removed from its original path"
    [ -f "$d/alias_b.bin" ] && ok "alias_b.bin still holds the allocation" \
                            || fail "alias_b.bin is gone — the fixture no longer proves anything"
    local before after freed
    before="$(used_of "$POOL/ds_a")"
    purge_and_release
    after="$(used_of "$POOL/ds_a")"
    freed=$((before - after))
    info "post-purge allocation delta: $freed bytes"
    [ "$freed" -lt 524288 ] && ok "partial coverage really did free (next to) nothing: $freed bytes" \
                            || fail "delta $freed — a half-covered allocation cannot release its blocks"

    # Part 2: cover the remaining name too. One allocation goes, once.
    scan "$d"
    operator "Group: keeper.bin + alias_b.bin (alias_a.bin is gone).
Mark keeper.bin = Keeper (F7), alias_b.bin = Delete (F8), then F11 → Y.
The confirmation must now claim ONE allocation's worth (about 1 MiB), not two."
    banner "verify full coverage releases exactly one allocation"
    before="$(used_of "$POOL/ds_a")"
    purge_and_release
    after="$(used_of "$POOL/ds_a")"
    freed=$((before - after))
    info "post-purge allocation delta: $freed bytes (one 1 MiB allocation)"
    [ "$freed" -ge 786432 ] && [ "$freed" -lt 1572864 ] \
        && ok "exactly one allocation was released: $freed bytes" \
        || fail "delta $freed is not one allocation's worth — the accounting counts pathnames"
    rm -rf "$d"
}

# R2D-C5-2: the second whole-plan preflight. Between the confirmation and the first change the
# plan is checked again — a covered pathname that moved in that window must stop the batch after
# the safety snapshot and before anything is touched.
scenario_preflight() {
    banner "second preflight — drift after the confirmation stops the batch"
    local d="$G5ROOT/preflight"; rm -rf "$d"; mkdir -p "$d"
    head -c 256K /dev/urandom > "$d/keeper.bin"
    cp "$d/keeper.bin" "$d/alias_a.bin"
    ln "$d/alias_a.bin" "$d/alias_b.bin"
    info "fixture: keeper.bin + alias_a.bin/alias_b.bin (one inode, two names)"
    scan "$d"
    local snaps_before; snaps_before="$(zfs list -H -t snapshot -o name -r "$POOL" | wc -l)"

    printf '\n  >>> OPERATOR STEP 1 of 2 <<<\n'
    printf '      Open the TUI: %s --state-dir %s\n' "$DEDCOM" "$STATE"
    printf '      Mark keeper.bin = Keeper (F7), alias_a.bin AND alias_b.bin = Delete (F8).\n'
    printf '      Press F11 to open the confirmation, then LEAVE IT OPEN and press ENTER here.\n'
    read -r _ || true
    # The drift: one covered pathname goes away while the operator is looking at the plan.
    rm -f -- "$d/alias_b.bin"
    info "drift injected: alias_b.bin removed while the confirmation was open"
    printf '\n  >>> OPERATOR STEP 2 of 2 <<<\n'
    printf '      Now press Y in the confirmation, then leave the TUI and press ENTER here.\n'
    read -r _ || true

    banner "verify the batch refused itself before touching anything"
    [ -f "$d/alias_a.bin" ] && ok "alias_a.bin untouched — no file was mutated" \
                            || fail "alias_a.bin moved: the batch ran past a plan that no longer held"
    quarantined "alias_a.bin" && fail "alias_a.bin reached the quarantine — a mutation happened" \
                              || ok "nothing was moved to quarantine"
    local snaps_after; snaps_after="$(zfs list -H -t snapshot -o name -r "$POOL" | wc -l)"
    info "snapshots before=$snaps_before after=$snaps_after (a safety snapshot may exist; it must be reported)"
    info "the summary screen must name every snapshot it created and say the batch was refused"
    rm -rf "$d"
}

# R2D-C5-2: the saved ScanScript is a real apply route, so it carries the same whole-plan
# preflight — twice, and the first one runs before the snapshot section.
scenario_script_preflight() {
    banner "saved ScanScript — structural preflight before the snapshot"
    local d="$G5ROOT/script"; rm -rf "$d"; mkdir -p "$d"
    head -c 256K /dev/urandom > "$d/keeper.bin"
    cp "$d/keeper.bin" "$d/alias_a.bin"
    ln "$d/alias_a.bin" "$d/alias_b.bin"
    info "fixture: keeper.bin + alias_a.bin/alias_b.bin (one inode, two names)"
    scan "$d"
    operator "Group: keeper.bin + alias_a.bin + alias_b.bin.
Mark keeper.bin = Keeper (F7), alias_a.bin AND alias_b.bin = Delete (F8), press F11,
switch to the Commands tab (Tab) and SAVE the script with S. Do NOT press Y. Exit the TUI."
    banner "verify the saved script"
    local sh; sh="$(find "$STATE/plans" -name '*.sh' 2>/dev/null | sort | tail -1 || true)"
    [ -n "$sh" ] || { fail "no saved script under $STATE/plans"; return; }
    info "script: $sh"
    grep -q 'dedcom_preflight' "$sh" && ok "the script carries a whole-plan preflight" \
                                     || { fail "no preflight in the saved script"; return; }
    local calls; calls="$(grep -c '^dedcom_preflight$' "$sh")"
    [ "$calls" -eq 2 ] && ok "it is called twice" || fail "preflight called $calls time(s), expected 2"
    local first_call snapshot_line
    first_call="$(grep -n '^dedcom_preflight$' "$sh" | head -1 | cut -d: -f1)"
    snapshot_line="$(grep -n 'zfs snapshot' "$sh" | head -1 | cut -d: -f1)"
    [ -n "$snapshot_line" ] && [ "$first_call" -lt "$snapshot_line" ] \
        && ok "the first call precedes the snapshot section" \
        || fail "preflight at line $first_call does not precede the snapshot at line ${snapshot_line:-none}"
    bash -n "$sh" && ok "the script parses" || fail "the generated script does not parse"

    # Now drift the plan and run it: it must exit non-zero before the snapshot and before any mv.
    rm -f -- "$d/alias_b.bin"
    local snaps_before; snaps_before="$(zfs list -H -t snapshot -o name -r "$POOL" | wc -l)"
    if bash "$sh" >/tmp/$POOL-script.out 2>/tmp/$POOL-script.err; then
        fail "the drifted script ran to completion"
    else
        ok "the drifted script exited non-zero"
    fi
    grep -q 'since the plan' /tmp/$POOL-script.err && ok "and said what moved" \
        || fail "no preflight message: $(head -2 /tmp/$POOL-script.err)"
    local snaps_after; snaps_after="$(zfs list -H -t snapshot -o name -r "$POOL" | wc -l)"
    [ "$snaps_after" -eq "$snaps_before" ] && ok "no snapshot was taken" \
                                           || fail "the script reached the snapshot section"
    [ -f "$d/alias_a.bin" ] && ok "no file was moved" || fail "alias_a.bin moved"
    rm -f "/tmp/$POOL-script.out" "/tmp/$POOL-script.err"
    rm -rf "$d"
}

scenario_dir_dedup() {
    banner "dir-dedup — identical directory trees grouped (Old and Merkle agree)"
    local d="$G5ROOT/dirdedup"; rm -rf "$d"; mkdir -p "$d/twinA" "$d/twinB" "$d/lone"
    head -c 128K /dev/urandom > "$d/twinA/a.bin"; head -c 64K /dev/urandom > "$d/twinA/b.bin"
    cp "$d/twinA/a.bin" "$d/twinB/a.bin"; cp "$d/twinA/b.bin" "$d/twinB/b.bin"
    head -c 32K /dev/urandom > "$d/lone/c.bin"
    info "fixture: twinA == twinB (identical trees), lone is unique"
    local so="/tmp/$POOL-old" sm="/tmp/$POOL-merkle"; rm -rf "$so" "$sm"
    "$DEDCOM" --state-dir "$so" --scan "$d" --no-resume
    "$DEDCOM" --state-dir "$sm" --scan "$d" --no-resume --merkle-dirs
    banner "verify dir_dedup groups twins, suppresses lone, Old==Merkle"
    if command -v python3 >/dev/null 2>&1; then
        STATE_OLD="$so" STATE_MERKLE="$sm" TWINA="$d/twinA" TWINB="$d/twinB" LONE="$d/lone" \
        python3 - <<'PY' && ok "dir_dedup: twins grouped, lone suppressed, Old==Merkle" || fail "dir_dedup mismatch (see above)"
import os, sqlite3, sys
def groups(state):
    con = sqlite3.connect(os.path.join(state, "dedcom.db"))
    sid = con.execute("SELECT MAX(id) FROM scan").fetchone()[0]
    rows = con.execute("SELECT signature, path FROM dir_dedup WHERE scan_id=? ORDER BY signature, path", (sid,)).fetchall()
    g = {}
    for sig, p in rows: g.setdefault(sig, set()).add(p)
    return sorted(tuple(sorted(s)) for s in g.values())
old = groups(os.environ["STATE_OLD"]); mer = groups(os.environ["STATE_MERKLE"])
twin = {os.environ["TWINA"], os.environ["TWINB"]}
if not any(twin <= set(g) for g in old): print("  twinA/twinB not grouped (Old)"); sys.exit(1)
for g in old:
    if os.environ["LONE"] in g and len(g) > 1: print(f"  lone wrongly grouped: {g}"); sys.exit(1)
if old != mer: print(f"  Old != Merkle:\n  Old={old}\n  Merkle={mer}"); sys.exit(1)
print(f"  dir groups (Old==Merkle): {len(old)}")
PY
    else
        info "python3 not available — inspect dir_dedup in $so/dedcom.db and $sm/dedcom.db manually"
    fi
    rm -rf "$so" "$sm"
}

# --------------------------------------------------------------------- main
SCENARIOS="hardlink reflink two-alias preflight script-preflight delete-restore revalidate snapshot interrupt dir-dedup"
want="${1:-all}"
# Validate the requested scenario BEFORE creating a pool — a typo must abort, not
# create a pool, run nothing, and report "all checks passed".
if [ "$want" != "all" ]; then
    case " $SCENARIOS " in
        *" $want "*) ;;
        *) g5_die "unknown scenario '$want' (valid: all | $SCENARIOS)" ;;
    esac
fi

banner "destructive E2E — disposable pool $POOL (size $DEDCOM_TESTPOOL_SIZE)"
info "dedcom: $DEDCOM ($("$DEDCOM" -V 2>/dev/null || echo '??'))"
info "scenarios: $want"
info "creating disposable loopback-ZFS pool via make-test-pool.sh"
"$HARNESS/make-test-pool.sh"
mkdir -p "$G5ROOT"

G5_RAN=0
run() { case "$want" in all|"$1") "scenario_${1//-/_}"; G5_RAN=$((G5_RAN + 1));; esac; }
run hardlink
run reflink
run two-alias
run preflight
run script-preflight
run delete-restore
run revalidate
run snapshot
run interrupt
run dir-dedup

# Fail (not false-green) if nothing actually ran.
[ "$G5_RAN" -gt 0 ] || fail "no scenarios ran (want='$want') — refusing to report success"
# cleanup + final RESULT printed by the EXIT trap.
[ "$G5_FAILED" -eq 0 ] || exit 1
