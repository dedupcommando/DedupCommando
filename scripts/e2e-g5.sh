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
# THE ROUTE IS THE COMMANDER, AND ONLY THE COMMANDER. Every operator step below runs on the
# multi-panel screen dedcom opens by default: marks are F7 keeper / F5 hardlink / F6 reflink /
# F8 delete, the confirmation is opened with `x` (F11 is the same command), and it is applied with
# ONE `Y` inside that overlay. The Wizard Browser has a different keymap for the same intentions
# (Enter/d/h/c to mark, `r` to build, two Y to apply); mixing the two is what invalidated the
# earlier guided run, so no Browser key appears in any instruction here.
#
# Usage:
#   sudo DEDCOM_G5_E2E=1 DEDCOM=/path/to/dedcom scripts/e2e-g5.sh [scenario]
#     scenarios: hardlink reflink two-alias preflight script-preflight delete-restore
#                revalidate snapshot interrupt dir-dedup all   (default: all)
#   sudo DEDCOM_G5_E2E=1 scripts/e2e-g5.sh clean-stale   # tear down leftover dedcom-g5-* pools
#
# Offline modes — no pool, no root, no ZFS, and NOT runtime evidence. They render or exercise the
# same pause definitions, formatter and verdict functions the real run uses, so they prove what
# this harness TELLS the operator, never that an apply happened:
#   scripts/e2e-g5.sh contract-dump              # print all ten operator records
#   scripts/e2e-g5.sh ack-probe [NN]             # run the acknowledgement reader on stdin
#   scripts/e2e-g5.sh verdict-probe NAME SF FF   # run the scenario marker and finalization
#   scripts/e2e-g5.sh scenario-seq-probe         # two scenarios, both failing, through run()
#   scripts/e2e-g5.sh finalize-probe STEP SF [PRESENCE...]
#                                                # finalization with injected cleanup outcomes
#   scripts/e2e-g5.sh signal-probe INT|TERM [before|during]
#                                                # the signal handlers and the single cleanup
#   scripts/e2e-g5.sh roots-probe [forge]        # the dataset list in real-source mode
#
# shellcheck disable=SC2015
#   `<cond> && ok ... || fail ...` below is intentional: ok/fail/info are printf-based
#   status reporters that always return 0, so the `|| fail` branch never fires on a true
#   condition. (File-level: applies to the verification one-liners in every scenario.)
set -euo pipefail

# --------------------------------------------------------------------- guardrails
g5_die() { printf '\nABORT: %s\n' "$*" >&2; exit 1; }

# Modes that only print or exercise the operator contract. They create no pool, touch no
# dataset and need neither root nor ZFS — and they are NOT runtime evidence: they prove what
# this harness TELLS the operator to do, never that a real apply happened.
G5_OFFLINE=0
case "${1:-}" in
    contract-dump|ack-probe|verdict-probe|scenario-seq-probe|finalize-probe|signal-probe|roots-probe)
        G5_OFFLINE=1 ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${HARNESS:-$SCRIPT_DIR}"
DEDCOM="${DEDCOM:-/tmp/dedcom-e2e/dedcom}"

if [ "$G5_OFFLINE" -eq 0 ]; then
    [ "${DEDCOM_G5_E2E:-}" = "1" ] \
        || g5_die "refusing to run the destructive E2E. Set DEDCOM_G5_E2E=1 explicitly."
    [ "$(id -u)" = "0" ] || g5_die "must run as root (ZFS pool ops require root)."
    command -v zpool >/dev/null 2>&1 || g5_die "'zpool' not found in PATH (OpenZFS not installed?)."
    command -v zfs   >/dev/null 2>&1 || g5_die "'zfs' not found in PATH (OpenZFS not installed?)."
    # Every pause has to print the exact scan id the operator must see installed, and that id is
    # read from this harness's own state database. Without it a pause could only say "some scan",
    # which is the class of vagueness this contract exists to remove.
    command -v python3 >/dev/null 2>&1 \
        || g5_die "'python3' not found in PATH — the operator contract needs it to read the exact scan id."
    for s in make-test-pool.sh teardown-test-pool.sh testpool-lib.sh; do
        [ -e "$HARNESS/$s" ] || g5_die "harness script missing: $HARNESS/$s (set HARNESS=...)."
    done
fi

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

[ "$G5_OFFLINE" -eq 1 ] || [ -x "$DEDCOM" ] \
    || g5_die "dedcom binary not found/executable at '$DEDCOM' (set DEDCOM=...)."

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
# A COUNT, not a flag. A boolean is sticky: once the first scenario has failed, a later one can
# raise its own [FAIL], leave the value at 1 -> 1, and be reported as a pass.
fail()   { printf '  [FAIL] %s\n' "$*" >&2; G5_FAILS=$((G5_FAILS + 1)); }
G5_FAILS=0

# ------------------------------------------------------------------ finalization
#
# One state machine owns the ending. The order is fixed and is the whole point: everything this
# run owns is given back FIRST, and only a clean give-back may be followed by a PASS. A teardown
# that fails after a printed PASS would leave an owned pool behind under a green verdict — the
# exact false green the final-gate driver has to reject.
G5_CLEANUP_RUNS=0
# The finalization state, explicit rather than a boolean raised before the work it describes.
# A signal that lands BETWEEN «cleaning» and «done» still owes exactly one marker; a boolean set
# ahead of cleanup made the EXIT handler believe the ending had already been printed.
G5_FINAL_STATE=pending      # pending -> cleaning -> done, and `done` means the marker EXISTS
G5_FINAL_RC=1
G5_SIGNAL_LATCHED=0
G5_SIGNAL_STATUS=0
G5_SIGNAL_NAME=""
G5_PRESENCE=unknown
G5_STEP_TRACE=""

# Probe-only injection, reachable ONLY when G5_OFFLINE=1. A real run never consults any of these,
# so nothing in the environment can fake a production path.
G5_FORCE_FAIL="${G5_FORCE_FAIL:-}"
G5_PRESENCE_SEQ="${G5_PRESENCE_SEQ:-}"
# A space-separated list of `<point>:<SIGNAL>` pairs, so more than one signal can be delivered in
# one run and the «first latch wins» rule is checkable.
G5_SIGNAL_AT="${G5_SIGNAL_AT:-}"
forced() {  # step -> 0 when this step must report failure
    [ "$G5_OFFLINE" -eq 1 ] || return 1
    case " $G5_FORCE_FAIL " in *" $1 "*) return 0 ;; esac
    return 1
}

# Which owned step was entered, in order. Probe evidence only — it records that a step was
# ATTEMPTED and says nothing about whether it succeeded; the return values still decide that.
trace_step() {  # name
    [ "$G5_OFFLINE" -eq 1 ] || return 0
    G5_STEP_TRACE="$G5_STEP_TRACE $1"
    printf 'CLEANUP STEP %s\n' "$1"
}

# Probe-only signal injection at a named point of the ending. Offline only.
maybe_signal() {  # point
    [ "$G5_OFFLINE" -eq 1 ] || return 0
    local spec sig=""
    for spec in $G5_SIGNAL_AT; do
        case "$spec" in "$1":*) sig="${spec#*:}" ;; esac
    done
    [ -n "$sig" ] || return 0
    kill -"$sig" $$
    # The handler runs between commands; this gives it that boundary.
    :
}

# Whether the disposable pool is imported: present | absent | unknown.
#
# «There is no such pool» and «the query failed» are different facts, and only the first is proof.
# `zpool list <name>` exits nonzero for both, so absence is decided by ENUMERATING the imported
# pools and looking for the exact name. Any failure of that enumeration is `unknown`, and unknown
# is a failure — never a green, and never a reason to skip teardown.
#
# Sets G5_PRESENCE instead of printing it: the offline sequence has to advance, and a command
# substitution would advance it inside a subshell that then disappears.
pool_presence() {  # name
    if [ "$G5_OFFLINE" -eq 1 ]; then
        G5_PRESENCE="${G5_PRESENCE_SEQ%% *}"
        case "$G5_PRESENCE_SEQ" in *" "*) G5_PRESENCE_SEQ="${G5_PRESENCE_SEQ#* }" ;; esac
        [ -n "$G5_PRESENCE" ] || G5_PRESENCE=absent
        return 0
    fi
    local out
    if ! out="$(LC_ALL=C zpool list -H -o name 2>&1)"; then
        G5_PRESENCE=unknown
        # The diagnostic is reported as a diagnostic. It is never allowed to become a pool name.
        printf '  the pool enumeration failed: %s\n' "$(printf '%s' "$out" | head -1)" >&2
        return 0
    fi
    if printf '%s\n' "$out" | grep -qxF -- "$1"; then
        G5_PRESENCE=present
    else
        G5_PRESENCE=absent
    fi
}

remove_state() {
    trace_step remove_state
    if [ "$G5_OFFLINE" -eq 1 ]; then
        forced state && { fail "harness state $STATE could not be removed"; return 1; }
        return 0
    fi
    rm -rf "$STATE" 2>/dev/null || true
    if [ -e "$STATE" ]; then
        fail "harness state $STATE is still present after cleanup"
        return 1
    fi
    return 0
}

teardown_pool() {
    trace_step teardown_pool
    pool_presence "$POOL"
    case "$G5_PRESENCE" in
        absent) return 0 ;;
        unknown)
            fail "could not determine whether $POOL is imported — refusing to treat it as gone"
            return 1 ;;
    esac
    if forced teardown; then
        fail "teardown of $POOL reported an error"
        return 1
    fi
    [ "$G5_OFFLINE" -eq 0 ] || return 0
    info "destroying disposable pool $POOL (teardown-test-pool.sh, topology-verified)"
    if "$HARNESS/teardown-test-pool.sh"; then
        return 0
    fi
    fail "teardown of $POOL reported an error"
    printf '       recover manually: sudo zpool destroy %s && sudo rm -f %s/pool.img && sudo rmdir %s\n' \
           "$POOL" "$POOLDIR" "$POOLDIR" >&2
    return 1
}

# Teardown reporting success is not the same as the pool being gone, and a query that could not
# answer is not an answer. This is the check that makes the verdict about the machine's state.
assert_no_leftovers() {
    trace_step assert_no_leftovers
    local rc=0
    pool_presence "$POOL"
    case "$G5_PRESENCE" in
        absent) ;;
        present)
            fail "disposable pool $POOL is still imported after teardown"
            rc=1 ;;
        unknown)
            fail "could not verify that $POOL was torn down — its absence was never proved"
            rc=1 ;;
    esac
    if [ "$G5_OFFLINE" -eq 1 ]; then
        forced leftover \
            && { fail "backing file $POOLDIR/pool.img is still present after teardown"; rc=1; }
        return $rc
    fi
    if [ -e "$POOLDIR/pool.img" ]; then
        fail "backing file $POOLDIR/pool.img is still present after teardown"
        rc=1
    fi
    return $rc
}

# The give-back, attempted exactly once. All three owned steps are attempted in order even when a
# signal arrives midway: a run that was interrupted before touching its pool has given nothing
# back, and «entered cleanup» is not the same fact as «cleanup ran».
cleanup_owned() {
    G5_CLEANUP_RUNS=$((G5_CLEANUP_RUNS + 1))
    printf '\nCLEANUP RUN %s\n' "$G5_CLEANUP_RUNS"
    maybe_signal entry
    local rc=0
    remove_state        || rc=1
    maybe_signal after-step1
    teardown_pool       || rc=1
    assert_no_leftovers || rc=1
    return $rc
}

# The single marker, and the one commit point of the whole run.
#
# Everything before the mask below is interruptible, and a signal there forces FAIL with the
# signal's own status. At the mask, cleanup is over and the process has nothing left to do but
# print and leave, so INT and TERM are ignored from here on and are never restored: a signal can
# no longer leave the run markerless, and it can no longer pair a PASS with an interrupted status.
# `done` is published only once the marker actually exists.
emit_final() {  # extra-failure-flag
    trap '' INT TERM
    local rc
    if [ "$G5_FAILS" -eq 0 ] && [ "$G5_SIGNAL_LATCHED" -eq 0 ] && [ "${1:-0}" -eq 0 ]; then
        printf '\nFINAL RESULT PASS\n'
        rc=0
    else
        printf '\nFINAL RESULT FAIL\n' >&2
        rc=1
        # A latched signal owns the status: 130/143 must survive to the caller.
        [ "$G5_SIGNAL_LATCHED" -eq 0 ] || rc="$G5_SIGNAL_STATUS"
    fi
    G5_FINAL_RC="$rc"
    G5_FINAL_STATE=done
    maybe_signal postcommit
    return "$rc"
}

# The one ending: give back what the run owns, then say what happened. Re-entering while the
# give-back is still in flight does NOT start a second one.
finalize() {  # extra-failure-flag
    case "$G5_FINAL_STATE" in
        done) return "$G5_FINAL_RC" ;;
        cleaning) return 1 ;;
    esac
    G5_FINAL_STATE=cleaning
    cleanup_owned || true
    maybe_signal precommit
    emit_final "${1:-0}"
}

# The modes that only PRINT or READ own nothing and decide nothing, so they must not emit a final
# verdict at all. Marking finalization done keeps EXIT from inventing one for them.
skip_finalization() { G5_FINAL_STATE=done; G5_FINAL_RC=0; }

# EXIT is the only place cleanup can happen. It preserves or strengthens a failure and can never
# weaken one.
on_exit() {
    local rc=$?
    case "$G5_FINAL_STATE" in
        done) ;;
        cleaning)
            # The give-back died mid-flight without reaching the commit point. It is not repeated
            # — that was the double teardown — but the run still owes exactly one marker.
            emit_final 1 || true ;;
        pending)
            finalize 1 || true ;;
    esac
    # A latched signal or a recorded failure owns the status; the trap can only strengthen it.
    if [ "$rc" -eq 0 ] && [ "$G5_FINAL_RC" -ne 0 ]; then rc="$G5_FINAL_RC"; fi
    if [ "$rc" -eq 0 ] && [ "$G5_FAILS" -ne 0 ]; then rc=1; fi
    exit "$rc"
}
# Signals latch the failure, its name and its status — once. A second signal cannot overwrite the
# first, and it cannot start a second give-back.
#
# While the give-back is in flight the handler RETURNS instead of exiting: the three owned steps
# still have to be attempted, exactly once, and the run still owes one marker afterwards. Exiting
# from here is what left a cleanup that had touched nothing looking like a cleanup that ran.
on_signal() {  # name status
    if [ "$G5_SIGNAL_LATCHED" -eq 0 ]; then
        G5_SIGNAL_LATCHED=1
        G5_SIGNAL_NAME="$1"
        G5_SIGNAL_STATUS="$2"
        fail "interrupted by SIG$1"
    fi
    [ "$G5_FINAL_STATE" != "cleaning" ] || return 0
    exit "$G5_SIGNAL_STATUS"
}
trap on_exit EXIT
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM

# ------------------------------------------------------------------ the operator contract
#
# Ten human pauses, fixed indices 01..10, in run order. ONE formatter builds the text, and the
# real run and `contract-dump` both go through it — so what is tested is what is printed.
#
# Every record states the candidate binary, state directory, pool, fixture path and scan id; the
# screen, view and focus it starts from; the key; the exact string production renders when that
# key lands; the settlement condition that must hold before the next durable key; and the way out.
# Nothing here is satisfied by elapsed time, a repeated keypress or an optimistic glyph.
#
# Route derived from the handlers on 06584c4: main.rs:412 (Commander is the default screen),
# app.rs:3020 (consent keys), app.rs:680 (panels open on dataset mountpoints), panel.rs:78 (the
# panel title carries the cwd), commander/mod.rs:252 (the header's scan line), commander/mod.rs:350
# (auto-switch installs the covering scan), commander/mod.rs:658 (`x` = F11), overlay.rs:160/166
# (the confirmation's title and its never-shed key line), actions.rs:100 (Y leaves the Commander),
# summary.rs:183 (the summary's own exit keys).
G5_PAUSE_SEEN=""
G5_FIXTURE=""
G5_SCAN=""

# The exact id of the newest scan in this harness's own state database. A pause may not say
# "the scan" — it has to name the number the operator must see in the header.
# Only a scan that actually reached a terminal status may be named: a pause that quotes the id of
# a half-finished scan would send the operator to look for a header the tool will never show.
latest_scan_id() {
    python3 - "$STATE/dedcom.db" <<'PY'
import sqlite3, sys
row = sqlite3.connect(sys.argv[1]).execute(
    "SELECT id, status FROM scan ORDER BY id DESC LIMIT 1").fetchone()
if row is None or row[1] not in ("complete", "complete_with_warnings"):
    raise SystemExit(1)
print(row[0])
PY
}

# The ordered panel roots the app will compute, reproduced exactly rather than assumed.
#
# `list_datasets()` keeps `zfs list` order and drops none/legacy/-/unmounted rows
# (src/zfs/datasets.rs:15-36); the datasets are grouped into pools in FIRST-APPEARANCE order of
# the pool name (src/zfs/mod.rs:69-79); `App::new` flattens pools in that order into
# `commander_dirs` (src/app.rs:680-687); and `CommanderState::new` puts panel 1 on item 0,
# panel 2 on item 1, with panel 1 active (src/tui/commander/state.rs:867-875).
#
# Nothing in that chain makes the active panel start at /$POOL/ds_a — the pool root, ds_b and any
# unrelated pool on the host all sit in the same list.
# Where the dataset list is allowed to come from. A real run has exactly one answer and the
# environment does not get a vote: `G5_FORCE_REAL_SOURCE` is a probe knob and is consulted only
# when the harness is already in an offline mode.
roots_source() {
    if [ "$G5_OFFLINE" -eq 1 ] && [ "${G5_FORCE_REAL_SOURCE:-0}" != "1" ]; then
        printf 'sample\n'
    else
        printf 'real\n'
    fi
}

commander_roots() {
    local raw
    if [ "$(roots_source)" = "sample" ]; then
        raw="${G5_DATASETS_OVERRIDE:-}"
        [ -n "$raw" ] || return 1
    else
        # A sample list reaching a real run means the launch environment was poisoned: the route
        # would be printed from something the TUI will never see. Refuse loudly rather than
        # silently ignore it — a run that prints the wrong route is worse than one that stops.
        if [ -n "${G5_DATASETS_OVERRIDE:-}" ]; then
            fail "G5_DATASETS_OVERRIDE is set where the dataset list must come from zfs — refusing to print a route from it"
            return 1
        fi
        raw="$(zfs list -H -p -o name,mountpoint,mounted -t filesystem)" || {
            fail "could not read the ZFS filesystem list the Commander will show"
            return 1
        }
    fi
    printf '%s\n' "$raw" | awk -F'\t' '
        $2 == "none" || $2 == "legacy" || $2 == "-" || $3 != "yes" { next }
        { split($1, p, "/"); pool = p[1]
          if (!(pool in seen)) { seen[pool] = 1; order[++n] = pool }
          list[pool] = list[pool] $2 "\n" }
        END { for (i = 1; i <= n; i++) printf "%s", list[order[i]] }
    '
}

# 0-based position of a mountpoint in that list, and only if it is there exactly once.
root_index() {  # mountpoint
    local want="$1" hits
    hits="$(printf '%s\n' "$G5_ROOTS" | grep -cxF -- "$want")" || hits=0
    [ "$hits" = "1" ] || return 2
    printf '%s\n' "$G5_ROOTS" | grep -nxF -- "$want" | head -1 | cut -d: -f1 \
        | awk '{ print $1 - 1 }'
}

# The durable keys of one pause: KEY, the meaning the database returns, and the pathname.
# The settlement lines, the width requirement and the mark instructions are all generated from
# this one list, so they cannot drift apart.
pause_marks() {  # index
    case "$1" in
    01) printf 'F7\tkeeper\t%s\nF5\thardlink\t%s\n' \
               "$G5_FIXTURE/keeper.bin" "$G5_FIXTURE/dup.bin" ;;
    02) printf 'F7\tkeeper\t%s\nF6\treflink\t%s\n' \
               "$G5_FIXTURE/keeper.bin" "$G5_FIXTURE/dup.bin" ;;
    03) printf 'F7\tkeeper\t%s\nF8\tdelete\t%s\n' \
               "$G5_FIXTURE/keeper.bin" "$G5_FIXTURE/alias_a.bin" ;;
    04) printf 'F7\tkeeper\t%s\nF8\tdelete\t%s\n' \
               "$G5_FIXTURE/keeper.bin" "$G5_FIXTURE/alias_b.bin" ;;
    05|07) printf 'F7\tkeeper\t%s\nF8\tdelete\t%s\nF8\tdelete\t%s\n' \
               "$G5_FIXTURE/keeper.bin" "$G5_FIXTURE/alias_a.bin" "$G5_FIXTURE/alias_b.bin" ;;
    06) ;;
    08) printf 'F7\tkeeper\t%s\nF8\tdelete\t%s\n' \
               "$G5_FIXTURE/keeper.bin" "$G5_FIXTURE/dup.bin" ;;
    09) printf 'F7\tkeeper\t%s\nF5\thardlink\t%s\n' \
               "$G5_FIXTURE/keeper.bin" "$G5_FIXTURE/dup.bin" ;;
    10) printf 'F7\tkeeper\t%s\nF8\tdelete\t%s\n' \
               "$G5_FIXTURE/keeper.bin" "$G5_FIXTURE/dup.bin" ;;
    esac
}

# The terminal width this pause's settlement lines need.
#
# C0A guarantees only that the «Mark saved» PREFIX survives a narrow terminal; the pathname and
# the meaning are what get clipped, and those are exactly what the operator has to read here. The
# status renders as « <status> » with no border and no wrapping (commander/mod.rs:418,428), so the
# whole verdict needs two columns more than the longest generated line.
settlement_cols() {  # index
    local key meaning path line longest=0
    while IFS="$(printf '\t')" read -r key meaning path; do
        [ -n "${key:-}" ] || continue
        line="Mark saved: $path = $meaning"
        [ "${#line}" -gt "$longest" ] && longest="${#line}"
    done <<MARKS
$(pause_marks "$1")
MARKS
    [ "$longest" -eq 0 ] && { printf '0\n'; return 0; }
    printf '%s\n' "$((longest + 2))"
}

# Launch, width, consent, the generated route to the fixture, view and scan installation — the
# part every destructive pause starts with, printed in full rather than referred to.
route_prologue() {  # index
    local leaf="${G5_FIXTURE##*/}" cols i cur next
    cols="$(settlement_cols "$1")"
    cat <<EOF
  binary  : $DEDCOM
  state   : $STATE
  pool    : $POOL
  fixture : $G5_FIXTURE
  scan id : $G5_SCAN

  1. Terminal width. This scenario's longest settlement line needs $cols columns; the status
     line does not wrap, so a narrower window clips the pathname and the meaning off the very
     verdict you are here to read. Size the window to at least $cols columns before starting.
  2. Start the tool. The Commander is the default screen — do NOT pass --classic:
       $DEDCOM --state-dir $STATE
  3. Consent gate. The box is titled « Notice » and its heading is «Notice and consent».
     The cursor is already on the required line: «▸ [ ] I have read and agree (required)».
       Space -> that line must read «▸ [x] I have read and agree (required)» and the
                hint must change from «[Enter] unavailable — check the consent box»
                to «[Enter] continue».
       Enter -> the box disappears and the Commander panels are on screen.
     Do NOT check «Don't show this at startup again»: every scenario re-creates the state
     directory, so this gate is expected again next time.
  4. Reach the dataset. The panels open on the mounted ZFS filesystems of this host, in this
     exact order — generated for this run, not assumed:
EOF
    i=0
    while IFS= read -r cur; do
        [ -n "$cur" ] || continue
        printf '       [%s] %s%s\n' "$i" "$cur" \
               "$(if [ "$i" = "$G5_ROOT_K" ]; then printf ' <- the target'; fi)"
        i=$((i + 1))
    done <<ROOTS
$G5_ROOTS
ROOTS
    cat <<EOF
     Panel 1 is the ACTIVE panel and starts on item [0]; panel 2 starts on item [1]. Verify
     that the active panel (cyan border) has a title of the form « 1 · <path> · <sort> »
     ending with «$(printf '%s\n' "$G5_ROOTS" | head -1)».
EOF
    if [ "$G5_ROOT_K" -eq 0 ]; then
        printf '%s\n' "     The target dataset is already item [0]: no Root cycle is needed."
    else
        cat <<EOF
     Now cycle the ACTIVE panel's root with the production Root command, exactly $G5_ROOT_K
     time(s). Root is the SECOND-layer F5: press the backtick \` to arm layer 2 (the status
     line shows «Layer 2: choose an F-key · Esc — cancel»), then press the real F5 key.
     Shift+F5 does the same where the terminal passes it.
     WARNING: backtick followed by the DIGIT 5 is first-layer F5 — that is the Hardlink mark,
     not Root. Use the F5 key itself.
EOF
        i=1
        while [ "$i" -le "$G5_ROOT_K" ]; do
            next="$(printf '%s\n' "$G5_ROOTS" | sed -n "$((i + 1))p")"
            printf '       cycle %s -> status must read «Panel 1 → %s»\n' "$i" "$next"
            i=$((i + 1))
        done
        printf '%s\n' "     After the last cycle the active panel title must end with «$G5_TARGET_ROOT»."
    fi
    cat <<EOF
  5. Enter the fixture by its VISIBLE name — never by a counted number of arrow presses:
       Enter on «g5»     -> the active panel title must end with «/g5»
       Enter on «$leaf»  -> the active panel title must end with «/g5/$leaf»
     While a directory is being read the panel shows «  loading…» in place of the rows; the
     step is done when the rows are listed, not after any amount of time.
  6. View. The active panel must be in the files view, which is where the Commander starts:
     its title carries the PATH (the group views replace the path with a caption such as
     «groups» or «duplicates») and the rows list this fixture's *.bin files. Do not press «v».
  7. The covering scan must be installed BEFORE any durable key:
       status «Scan #$G5_SCAN activated»
       header «scan #$G5_SCAN · <age>»  — and WITHOUT «(loading…)»
     «No scan for <path> · F12 — select» means it is not installed: stop and report that
     instead of marking anything.
EOF
}

# Every durable key of this pause, from the one list.
route_marks() {  # index
    local key meaning path
    while IFS="$(printf '\t')" read -r key meaning path; do
        [ -n "${key:-}" ] || continue
        route_mark "$key" "$meaning" "$path"
    done <<MARKS
$(pause_marks "$1")
MARKS
}

# One durable mark, with the settlement that has to be read before the next one.
route_mark() {  # key meaning path
    cat <<EOF
       $1 on «${3##*/}»
         -> status «Saving mark: $3»
         -> then   «Mark saved: $3 = $2»
       The next durable key may only be pressed once that «Mark saved» line is on screen.
       «Mark still saving — wait for Mark saved before marking again» means the previous
       write is not settled yet — wait for its «Mark saved», do not press the key again.
EOF
}

# The apply route in three separable steps, so a scenario can put its own reading between them.
# Each pause that opens a confirmation prints exactly ONE x, and Q is always last.
route_open_confirmation() {
    cat <<'EOF'
       x  (F11 is the same command; x is the terminal-independent way in)
         -> status «Building the plan…», then the overlay « Confirmation — F11 » with the
            tab strip «Summary  Commands» and the line
            «[Tab] tab  [S] save .sh  [Y] execute  [N]/[Esc] cancel».
EOF
}

route_apply_to_summary() {
    cat <<'EOF'
       Y  ONCE, inside that overlay. This is the only Y in the whole scenario.
         -> the Commander is left behind: the wizard «Applying» screen runs, then the
            « DedupCommando — summary » screen appears, ending with
            «[Esc] to configuration · [Q] quit».
EOF
}

# Always the last instruction of a pause: everything that has to be read on the summary is
# printed before the key that leaves it.
route_exit_summary() {
    cat <<'EOF'
       Q  from that summary screen, once everything above has been read.
EOF
}

# Cancelling instead of applying, and the screen that comes back.
route_cancel() {
    cat <<'EOF'
       N or Esc in the confirmation -> the overlay closes and the Commander panels are back.
       Leave the tool with F10 (or q) from the panels.
EOF
}

# The ten pause definitions. This case IS the contract: production and contract-dump both
# render the operator text from here and from nowhere else.
pause_record() {  # index -> operator text on stdout
    case "$1" in
    01)
        printf '%s\n' "hardlink — keeper.bin stays, dup.bin becomes a second name for its inode."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement:"
        route_marks "$1"
        printf '%s\n' "  9. Apply:"
        route_open_confirmation
        route_apply_to_summary
        route_exit_summary
        ;;
    02)
        printf '%s\n' "reflink — dup.bin keeps its own inode and its own 0600 / 12345:12345 / xattr,"
        printf '%s\n' "and shares the keeper's blocks."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement:"
        route_marks "$1"
        printf '%s\n' "  9. Apply:"
        route_open_confirmation
        route_apply_to_summary
        route_exit_summary
        ;;
    03)
        printf '%s\n' "two aliases, part 1 of 2 — cover ONE of the two names of a single allocation."
        printf '%s\n' "alias_a.bin and alias_b.bin are two names of ONE inode. Only alias_a.bin is"
        printf '%s\n' "marked here; alias_b.bin is deliberately LEFT UNMARKED, which is what makes the"
        printf '%s\n' "plan worth nothing."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement (alias_b.bin gets no key at all):"
        route_marks "$1"
        printf '%s\n' "  9. Open the confirmation and READ it before applying:"
        route_open_confirmation
        printf '%s\n' "         The Summary tab must carry the line"
        printf '%s\n' "            «guaranteed after quarantine purge: 0 B» and the warning"
        printf '%s\n' "            «zero guaranteed reclaim — 1 pathname(s) of this allocation stay"
        printf '%s\n' "            outside the plan». If that warning is absent, stop and report it."
        printf '%s\n' " 10. Only then apply:"
        route_apply_to_summary
        route_exit_summary
        ;;
    04)
        printf '%s\n' "two aliases, part 2 of 2 — cover the remaining name, on a FRESH scan."
        printf '%s\n' "alias_a.bin is gone; the group is keeper.bin + alias_b.bin. The confirmation"
        printf '%s\n' "must now claim one allocation's worth (about 1 MiB), not two."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement:"
        route_marks "$1"
        printf '%s\n' "  9. Apply:"
        route_open_confirmation
        route_apply_to_summary
        route_exit_summary
        ;;
    05)
        printf '%s\n' "second preflight, stage 1 of 2 — stop with the confirmation OPEN, before any Y."
        printf '%s\n' "Both names of the shared allocation are marked here."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement:"
        route_marks "$1"
        printf '%s\n' "  9. Open the confirmation and STOP there — do NOT press Y in this stage:"
        route_open_confirmation
        printf '%s\n' " 10. LEAVE THE OVERLAY OPEN, leave the TUI on screen, and acknowledge here."
        printf '%s\n' "     The harness then removes one covered pathname underneath the open plan."
        ;;
    06)
        printf '%s\n' "second preflight, stage 2 of 2 — the plan drifted while it was on screen."
        printf '%s\n' "alias_b.bin has just been removed by the harness. The confirmation from stage 1"
        printf '%s\n' "is still open in the same TUI; do not restart it and do not re-mark anything."
        cat <<EOF
  binary  : $DEDCOM
  state   : $STATE
  pool    : $POOL
  fixture : $G5_FIXTURE
  scan id : $G5_SCAN

  1. Return to the still-open « Confirmation — F11 » overlay. It is already open, so this
     stage opens nothing and marks nothing.
  2. Apply:
EOF
        route_apply_to_summary
        printf '%s\n' "  3. On that summary screen, BEFORE leaving it, the batch must have refused"
        printf '%s\n' "     itself: the screen carries «BATCH REFUSED before any change: <reason>»,"
        printf '%s\n' "     no file has been moved and nothing has reached the quarantine."
        printf '%s\n' "     A summary WITHOUT that line means the batch ran: stop and report it."
        printf '%s\n' "  4. Leave the summary:"
        route_exit_summary
        ;;
    07)
        printf '%s\n' "saved ScanScript — save the plan's .sh from the confirmation and apply NOTHING."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement:"
        route_marks "$1"
        printf '%s\n' "  9. Open the confirmation, switch tab, save — no Y anywhere in this scenario:"
        route_open_confirmation
        printf '%s\n' "       Tab -> ONLY now, with that overlay visibly open: the highlight moves to"
        printf '%s\n' "              «Commands» and the title gains «· lines <a>-<b> of <n>»."
        printf '%s\n' "              (On the panels Tab switches the active panel instead — that is"
        printf '%s\n' "              why this key is pressed inside the overlay and nowhere else.)"
        printf '%s\n' "       S   -> status «Script saved: $STATE/plans/<name>.sh». Read the path."
        printf '%s\n' " 10. Cancel instead of applying:"
        route_cancel
        ;;
    08)
        printf '%s\n' "delete to quarantine — dup.bin leaves its path, keeper.bin is untouched."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement:"
        route_marks "$1"
        printf '%s\n' "  9. Apply:"
        route_open_confirmation
        route_apply_to_summary
        route_exit_summary
        ;;
    09)
        printf '%s\n' "revalidation — dup.bin was overwritten AFTER the scan, so the action must be"
        printf '%s\n' "cancelled. This scenario expects a REFUSED action, not a successful apply."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement:"
        route_marks "$1"
        printf '%s\n' "  9. Apply, and expect the refusal:"
        route_open_confirmation
        route_apply_to_summary
        printf '%s\n' " 10. On that summary screen, BEFORE leaving it, the action must appear as a"
        printf '%s\n' "     failure line"
        printf '%s\n' "       «✗ Hardlink $G5_FIXTURE/dup.bin — … changed after the scan (content)"
        printf '%s\n' "        — action cancelled»"
        printf '%s\n' "     and dup.bin must still be at its own path with its new content. A summary"
        printf '%s\n' "     that reports the hardlink as done is a failure of this scenario."
        printf '%s\n' " 11. Only then leave the summary:"
        route_exit_summary
        ;;
    10)
        printf '%s\n' "snapshot — the safety snapshot taken before a destructive batch."
        route_prologue "$1"
        printf '%s\n' "  8. Mark, waiting for each settlement:"
        route_marks "$1"
        printf '%s\n' "  9. Apply:"
        route_open_confirmation
        route_apply_to_summary
        route_exit_summary
        ;;
    *)
        return 1
        ;;
    esac
}

# One human pause: markers, the record, and an acknowledgement that fails closed.
operator_pause() {  # index scenario
    local idx="$1" scen="$2" body ack
    case " $G5_PAUSE_SEEN " in
        *" $idx "*) fail "pause $idx was emitted twice"; return 1 ;;
    esac
    if ! body="$(pause_record "$idx")"; then
        fail "pause $idx has no definition"
        return 1
    fi
    G5_PAUSE_SEEN="$G5_PAUSE_SEEN $idx"
    printf '\nPAUSE %s BEGIN scenario=%s pool=%s state=%s fixture=%s scan=%s\n' \
           "$idx" "$scen" "$POOL" "$STATE" "$G5_FIXTURE" "$G5_SCAN"
    printf '%s\n' "$body" | sed 's/^/      /'
    printf '\n      Type your initials, then ENTER, to record the acknowledgement: '
    if ! IFS= read -r ack; then
        printf '\nPAUSE %s ABORT reason=eof\n' "$idx" >&2
        fail "pause $idx: end of input — no acknowledgement was ever given"
        return 1
    fi
    if [ -z "$(printf '%s' "$ack" | tr -d '[:space:]')" ]; then
        printf '\nPAUSE %s ABORT reason=blank\n' "$idx" >&2
        fail "pause $idx: blank acknowledgement"
        return 1
    fi
    printf 'PAUSE %s HUMAN-ACK initials=%s\n' "$idx" "$ack"
}

# Sets everything a pause prints about identity and route, and fails the scenario if any of it
# cannot be established. The route is REGENERATED per scenario, because a scenario may re-scan
# and because nothing lets this harness assume where the panels start.
pause_context() {  # fixture-dir
    G5_FIXTURE="$1"
    if ! G5_SCAN="$(latest_scan_id)"; then
        fail "no scan row in $STATE/dedcom.db — the pause cannot name the scan the operator must see"
        return 1
    fi
    if ! G5_ROOTS="$(commander_roots)" || [ -z "$G5_ROOTS" ]; then
        fail "could not enumerate the mounted ZFS filesystems the Commander will show"
        return 1
    fi
    G5_TARGET_ROOT="/$POOL/ds_a"
    if ! G5_ROOT_K="$(root_index "$G5_TARGET_ROOT")"; then
        fail "$G5_TARGET_ROOT is not exactly one entry of the Commander's root list — the route cannot be generated"
        return 1
    fi
}

# The per-scenario verdict. Both production and `verdict-probe` go through it.
scenario_verdict() {  # name failed
    if [ "$2" -eq 0 ]; then
        printf '\nSCENARIO %s PASS\n' "$1"
        return 0
    fi
    printf '\nSCENARIO %s FAIL\n' "$1" >&2
    return 1
}

G5_RAN=0
G5_SCENARIO_FAILS=0
# One scenario, one verdict marker describing only that scenario.
run() {
    case "$want" in all|"$1") ;; *) return 0 ;; esac
    local name="$1" before="$G5_FAILS" rc=0
    "scenario_${1//-/_}" || rc=1
    G5_RAN=$((G5_RAN + 1))
    # The COUNT is what makes this per-scenario: a sticky boolean already at 1 from an earlier
    # failure would be unchanged here, and this scenario would be reported as a pass.
    if [ "$G5_FAILS" -ne "$before" ]; then rc=1; fi
    scenario_verdict "$name" "$rc" || G5_SCENARIO_FAILS=$((G5_SCENARIO_FAILS + 1))
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
    pause_context "$d" || return 1
    operator_pause 01 hardlink || return 1
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
    pause_context "$d" || return 1
    operator_pause 02 reflink || return 1
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
    pause_context "$d" || return 1
    operator_pause 08 delete-restore || return 1
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
    pause_context "$d" || return 1
    operator_pause 09 revalidate || return 1
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
    pause_context "$d" || return 1
    operator_pause 10 snapshot || return 1
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
    pause_context "$d" || return 1
    operator_pause 03 two-alias || return 1
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
    pause_context "$d" || return 1
    operator_pause 04 two-alias || return 1
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

    pause_context "$d" || return 1
    operator_pause 05 preflight || return 1
    # The drift: one covered pathname goes away while the operator is looking at the plan.
    rm -f -- "$d/alias_b.bin"
    info "drift injected: alias_b.bin removed while the confirmation was open"
    operator_pause 06 preflight || return 1

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
    pause_context "$d" || return 1
    operator_pause 07 script-preflight || return 1
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
PAUSES="01 02 03 04 05 06 07 08 09 10"

# The offline modes. They render or exercise the SAME pause definitions, formatter and verdict
# functions production uses — and they set up no pool, touch no dataset and apply nothing, so
# they are a proof about the printed contract and never about a run.
# A sample dataset list for the offline modes. It deliberately puts an UNRELATED pool and the
# disposable pool's own root ahead of ds_a, so a route that assumes the active panel starts on
# the target cannot pass the contract test.
G5_SAMPLE_DATASETS="$(printf '%s\t%s\t%s\n' \
    rpool/data                /rpool/data                yes \
    rpool/swap                none                       no  \
    dedcom-g5-SAMPLE          /dedcom-g5-SAMPLE          yes \
    dedcom-g5-SAMPLE/ds_a     /dedcom-g5-SAMPLE/ds_a     yes \
    dedcom-g5-SAMPLE/ds_b     /dedcom-g5-SAMPLE/ds_b     yes)"

offline_sample_context() {
    POOL="dedcom-g5-SAMPLE"
    POOLDIR="/var/lib/$POOL"
    STATE="/tmp/dedcom-g5-SAMPLE-state"
    DEDCOM="/tmp/dedcom-e2e/dedcom"
    G5_DATASETS_OVERRIDE="$G5_SAMPLE_DATASETS"
    G5_ROOTS="$(commander_roots)"
    G5_TARGET_ROOT="/$POOL/ds_a"
    G5_ROOT_K="$(root_index "$G5_TARGET_ROOT")" \
        || { printf 'ABORT: the sample dataset list does not hold %s exactly once\n' \
                    "$G5_TARGET_ROOT" >&2; exit 1; }
}

case "${1:-}" in
contract-dump)
    offline_sample_context
    skip_finalization
    for idx in $PAUSES; do
        case "$idx" in
            01) scen=hardlink;        fixture="/$POOL/ds_a/g5/hardlink" ;;
            02) scen=reflink;         fixture="/$POOL/ds_a/g5/reflink" ;;
            03) scen=two-alias;       fixture="/$POOL/ds_a/g5/twoalias" ;;
            04) scen=two-alias;       fixture="/$POOL/ds_a/g5/twoalias" ;;
            05) scen=preflight;       fixture="/$POOL/ds_a/g5/preflight" ;;
            06) scen=preflight;       fixture="/$POOL/ds_a/g5/preflight" ;;
            07) scen=script-preflight; fixture="/$POOL/ds_a/g5/script" ;;
            08) scen=delete-restore;  fixture="/$POOL/ds_a/g5/delete" ;;
            09) scen=revalidate;      fixture="/$POOL/ds_a/g5/reval" ;;
            10) scen=snapshot;        fixture="/$POOL/ds_a/g5/snap" ;;
        esac
        G5_FIXTURE="$fixture"
        G5_SCAN="$((10#$idx))"
        printf '\nPAUSE %s BEGIN scenario=%s pool=%s state=%s fixture=%s scan=%s\n' \
               "$idx" "$scen" "$POOL" "$STATE" "$G5_FIXTURE" "$G5_SCAN"
        pause_record "$idx" | sed 's/^/      /'
    done
    exit 0
    ;;
ack-probe)
    # Runs the production acknowledgement reader once, on a real pause record, so EOF and blank
    # initials are proved against the code the operator meets — not against a copy of it.
    offline_sample_context
    skip_finalization
    G5_FIXTURE="/$POOL/ds_a/g5/hardlink"
    G5_SCAN=1
    operator_pause "${2:-01}" ack-probe
    exit $?
    ;;
verdict-probe)
    # The per-scenario marker on its own, plus the finalization, so the two can be told apart.
    offline_sample_context
    scenario_verdict "${2:-probe}" "${3:-0}" || fail "scenario ${2:-probe} failed"
    finalize "${4:-0}" || true
    exit "$G5_FINAL_RC"
    ;;
scenario-seq-probe)
    # Two sequential scenarios through the production `run()` bookkeeping. The first fails; the
    # second raises its own [FAIL] while its function returns zero. A sticky boolean would report
    # the second as a pass, because the total would already be non-zero.
    offline_sample_context
    scenario_seq_a() { fail "first scenario failed"; return 1; }
    scenario_seq_b() { fail "second scenario failed independently"; return 0; }
    want=all
    G5_RAN=0
    run seq-a
    run seq-b
    finalize 0 || true
    exit "$G5_FINAL_RC"
    ;;
finalize-probe)
    # The finalization state machine with chosen cleanup outcomes. No mount, no zpool, no rm: the
    # give-back steps report the injected result and do nothing else. Arguments 4+ are the
    # presence answers, consumed one per query — teardown first, then the absence check.
    offline_sample_context
    G5_FORCE_FAIL="${2:-}"
    [ "${3:-0}" -eq 0 ] || fail "a scenario failed before finalization"
    shift 3 2>/dev/null || true
    G5_PRESENCE_SEQ="${*:-absent}"
    finalize 0 || true
    printf 'STEP TRACE:%s\n' "$G5_STEP_TRACE"
    exit "$G5_FINAL_RC"
    ;;
signal-probe)
    # Sends itself the signal and lets the production handlers run, at each materially different
    # point of the ending: before cleanup, on entry to cleanup, after the first owned step, after
    # cleanup but before the commit point, and after it. Nothing destructive is reachable.
    offline_sample_context
    G5_PRESENCE_SEQ="present absent"
    case "${3:-before}" in
        before)
            kill -"${2:-INT}" $$
            sleep 5
            exit 0 ;;
        entry|after-step1|precommit|postcommit)
            G5_SIGNAL_AT="$3:${2:-INT}"
            finalize 0 || true
            printf 'STEP TRACE:%s\n' "$G5_STEP_TRACE"
            exit "$G5_FINAL_RC" ;;
        double)
            # Two different signals in one run: the first latch must own the status, and the
            # second must neither overwrite it nor start a second give-back.
            G5_SIGNAL_AT="entry:TERM precommit:INT"
            finalize 0 || true
            printf 'STEP TRACE:%s\n' "$G5_STEP_TRACE"
            printf 'LATCHED:%s\n' "$G5_SIGNAL_NAME"
            exit "$G5_FINAL_RC" ;;
        *)
            printf 'ABORT: unknown signal point %s\n' "$3" >&2
            exit 1 ;;
    esac
    ;;
roots-probe)
    # The dataset list with the source forced to REAL while the harness is offline, so a forged
    # override can be shown not to reach the rendered route. The caller supplies a `zfs` stub on
    # PATH; no ZFS command of this host is involved.
    G5_OFFLINE=1
    G5_FORCE_REAL_SOURCE=1
    skip_finalization
    POOL="dedcom-g5-SAMPLE"
    if [ "${2:-}" = "forge" ]; then
        G5_DATASETS_OVERRIDE="$(printf 'forged/ds\t/FORGED\tyes\n')"
    fi
    commander_roots || exit 1
    exit 0
    ;;
esac

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
# A full run owes all ten pauses. A missing one means an operator step was skipped, which is
# exactly the shape of failure this contract exists to catch.
if [ "$want" = "all" ]; then
    for idx in $PAUSES; do
        case " $G5_PAUSE_SEEN " in
            *" $idx "*) ;;
            *) fail "pause $idx never ran — the operator contract was not completed" ;;
        esac
    done
fi
# Finalization gives back everything this run owns BEFORE it says anything about the result, so
# a teardown that fails cannot arrive after a printed PASS. The status it computed is the status
# the process leaves with — a hard-coded 1 here would erase a latched 130/143.
finalize "$G5_SCENARIO_FAILS" || true
exit "$G5_FINAL_RC"
