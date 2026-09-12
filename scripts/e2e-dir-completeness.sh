#!/usr/bin/env bash
# E2E test: directory-completeness invariant on a disposable loopback-ZFS pool.
# Exercises the false-twin suppression case end-to-end.
#
# Run as ROOT on a ZFS host: root steps run directly; the unprivileged cases run as the OWNER
# of the containment root — the user DEDCOM_E2E_OWNER_UID names — via `runuser` (no sudo
# required). `nobody` is deliberately NOT used: on the accepted host the chain to the root
# passes through a 0700 home directory that only root and the owner can traverse, and the
# product's own path check accepts only root or the effective uid as component owners, so a
# `nobody` scan is unreachable there by construction.
#
# SHARED-HOST CONTAINMENT: operates ONLY on one disposable pool whose name is unique to this run
# (dedcomdir-<ts>), whose backing file and mountpoints live under $DEDCOM_E2E_ROOT, and whose
# state directories, captures and temporary files live there too. Nothing is placed in /tmp or
# /var/lib, and no pool name is reused between runs, so a leftover from an earlier run can never
# be mistaken for this one's. DEDCOM and HARNESS must be given explicitly. Does NOT tear down the
# pool -- run teardown-test-pool.sh with the same DEDCOM_TESTPOOL_NAME after observing the result.
set -euo pipefail

DEDCOM="${DEDCOM:-}"
HARNESS="${HARNESS:-}"

banner() { printf '\n========== %s ==========\n' "$*"; }

banner "preconditions"
[ -n "$DEDCOM" ]  || { echo "DEDCOM is not set — point it at the binary under test" >&2; exit 1; }
[ -n "$HARNESS" ] || { echo "HARNESS is not set — point it at the harness scripts dir" >&2; exit 1; }
[ -n "${DEDCOM_E2E_ROOT:-}" ] \
    || { echo "DEDCOM_E2E_ROOT is not set — this harness creates nothing outside a declared root" >&2; exit 1; }
[ -n "${DEDCOM_E2E_OWNER_UID:-}" ] \
    || { echo "DEDCOM_E2E_OWNER_UID is not set — refusing to guess who may own the tree" >&2; exit 1; }
[ "$DEDCOM_E2E_OWNER_UID" != "0" ] \
    || { echo "DEDCOM_E2E_OWNER_UID=0 cannot prove the unprivileged scenarios: root reads everything" >&2; exit 1; }
test -x "$DEDCOM"
test -x "$HARNESS/make-test-pool.sh"
test -x "$HARNESS/teardown-test-pool.sh"
"$DEDCOM" -V
python3 -c 'import sqlite3; print("python sqlite3", sqlite3.sqlite_version)'
command -v tmux >/dev/null 2>&1 \
    || { echo "tmux is required for the live-state scenario and was not found" >&2; exit 1; }

# The unprivileged identity is DERIVED from the owner uid, never guessed and never `nobody`.
# pwd.getpwuid is the same host python this script already requires; the round-trip through
# `id -u` proves the name still maps back to exactly the declared uid before it is trusted.
OWNER_USER="$(python3 -c 'import pwd, sys; print(pwd.getpwuid(int(sys.argv[1])).pw_name)' \
              "$DEDCOM_E2E_OWNER_UID")" \
    || { echo "uid $DEDCOM_E2E_OWNER_UID has no passwd entry on this host — cannot run the unprivileged cases" >&2; exit 1; }
[ -n "$OWNER_USER" ] \
    || { echo "uid $DEDCOM_E2E_OWNER_UID resolved to an empty user name" >&2; exit 1; }
[ "$(id -u -- "$OWNER_USER")" = "$DEDCOM_E2E_OWNER_UID" ] \
    || { echo "user '$OWNER_USER' does not map back to uid $DEDCOM_E2E_OWNER_UID" >&2; exit 1; }
echo "unprivileged identity: $OWNER_USER (uid $DEDCOM_E2E_OWNER_UID)"

banner "1. create disposable pool + fixtures"
# A unique name per run: `dedcomdirtest` was a fixed name, and a fixed name on a shared host is
# an invitation to adopt somebody else's leftover.
export DEDCOM_TESTPOOL_NAME="dedcomdir-$(date +%Y%m%d-%H%M%S)-$$"
export DEDCOM_TESTPOOL_SIZE=2G
# shellcheck source=testpool-lib.sh
. "$HARNESS/testpool-lib.sh"
STATEBASE="$(tp_state_dir "$DEDCOM_TESTPOOL_NAME")"
DIRTMP="$(tp_tmp_dir "$DEDCOM_TESTPOOL_NAME")"
tp_make_dir "$STATEBASE"
tp_make_dir "$DIRTMP"
cd "$DIRTMP"
"$HARNESS/make-test-pool.sh"

# Three scenarios scan as the owner user, which needs TRAVERSE (x) through the ROOT-created
# components down to the fixture and the state directory (owner-created components are already
# theirs). 0711 keeps every write bit closed — tp_check_node and the product's own chain check
# accept it (both test the 022 write bits, never x) — while letting the owner uid pass through.
# Nothing becomes listable or writable to others, and no human-owned directory outside the
# containment root is touched.
chmod 0711 "$DEDCOM_E2E_ROOT" "$DEDCOM_E2E_ROOT/pools" "$DEDCOM_E2E_ROOT/state" \
           "$STATEBASE" "$TP_DIR" "$TP_MNT"

export ROOT="$TP_MNT/ds_a/dir-completeness"
rm -rf "$ROOT"
mkdir -p "$ROOT/false/A" "$ROOT/false/B" "$ROOT/true/C" "$ROOT/true/D"
# false-twin case: unique.dat has a unique size -> scanned into manifest, NOT hashed
dd if=/dev/zero of="$ROOT/false/A/common.bin" bs=64K count=1 status=none
cp "$ROOT/false/A/common.bin" "$ROOT/false/B/common.bin"
dd if=/dev/zero of="$ROOT/false/A/unique.dat" bs=77777 count=1 status=none
# positive control: exact twin pair (every size collides -> all hashed -> both complete)
dd if=/dev/zero of="$ROOT/true/C/f1.bin" bs=64K count=1 status=none
dd if=/dev/zero of="$ROOT/true/C/f2.bin" bs=128K count=1 status=none
cp "$ROOT/true/C/f1.bin" "$ROOT/true/D/f1.bin"
cp "$ROOT/true/C/f2.bin" "$ROOT/true/D/f2.bin"
echo "--- fixture (size, path) ---"
find "$ROOT" -type f -printf '%s\t%p\n' | sort

banner "2. scan Old and Merkle (fresh state dirs)"
export STATE_OLD=${STATEBASE}/old-state
export STATE_MERKLE=${STATEBASE}/merkle-state
rm -rf "$STATE_OLD" "$STATE_MERKLE"
echo "--- OLD scan ---"
"$DEDCOM" --state-dir "$STATE_OLD" --scan "$ROOT" --no-resume
echo "--- MERKLE scan ---"
"$DEDCOM" --state-dir "$STATE_MERKLE" --scan "$ROOT" --no-resume --merkle-dirs

banner "2b. raw dir_dedup dump (diagnostic)"
python3 - <<'PY'
import os, sqlite3
for name, st in (("Old", os.environ["STATE_OLD"]), ("Merkle", os.environ["STATE_MERKLE"])):
    con = sqlite3.connect(os.path.join(st, "dedcom.db"))
    sid = con.execute("SELECT MAX(id) FROM scan").fetchone()[0]
    status = con.execute("SELECT status FROM scan WHERE id=?", (sid,)).fetchone()[0]
    hf = con.execute("SELECT hash_failures FROM scan_stats WHERE scan_id=?", (sid,)).fetchone()
    print(f"[{name}] scan_id={sid} status={status} hash_failures={hf[0] if hf else 'NA'}")
    rows = con.execute("SELECT signature,path FROM dir_dedup WHERE scan_id=? ORDER BY signature,path", (sid,)).fetchall()
    if not rows:
        print(f"  (dir_dedup empty for {name})")
    for sig, path in rows:
        print(f"  {sig[:16]}.. {path}")
PY

banner "3. assert false suppressed, true present, Old==Merkle"
python3 - <<'PY'
import os, sqlite3
cases = [("Old", os.environ["STATE_OLD"]), ("Merkle", os.environ["STATE_MERKLE"])]

def latest_scan(con):
    return con.execute("SELECT MAX(id) FROM scan").fetchone()[0]

def memberships(con, scan_id):
    rows = con.execute(
        "SELECT signature, path FROM dir_dedup WHERE scan_id = ? ORDER BY signature, path",
        (scan_id,),
    ).fetchall()
    groups = {}
    for sig, path in rows:
        groups.setdefault(sig, []).append(path)
    return sorted(tuple(paths) for paths in groups.values())

normalized = {}
for name, state in cases:
    con = sqlite3.connect(os.path.join(state, "dedcom.db"))
    scan_id = latest_scan(con)
    groups = memberships(con, scan_id)
    normalized[name] = groups
    false_pair = {os.environ["ROOT"] + "/false/A", os.environ["ROOT"] + "/false/B"}
    true_pair = {os.environ["ROOT"] + "/true/C", os.environ["ROOT"] + "/true/D"}
    for group in groups:
        if false_pair <= set(group):
            raise SystemExit(f"{name}: false twin was grouped: {group}")
    if not any(true_pair <= set(group) for group in groups):
        raise SystemExit(f"{name}: true twin pair missing")
    print(f"{name}: false pair suppressed, true pair present, dir groups={len(groups)}")

if normalized["Old"] != normalized["Merkle"]:
    raise SystemExit(
        "Old/Merkle group memberships differ:\n"
        f"Old={normalized['Old']!r}\nMerkle={normalized['Merkle']!r}"
    )
print("Old/Merkle memberships match")
PY

banner "4. hash-failure suppression (scan as $OWNER_USER)"
export FAILROOT="$TP_MNT/ds_a/dir-completeness-hashfail"
rm -rf "$FAILROOT"
mkdir -p "$FAILROOT/A" "$FAILROOT/B"
dd if=/dev/zero of="$FAILROOT/A/shared.bin" bs=64K count=1 status=none
cp "$FAILROOT/A/shared.bin" "$FAILROOT/B/shared.bin"
dd if=/dev/zero of="$FAILROOT/A/secret.bin" bs=64K count=1 status=none
chmod 000 "$FAILROOT/A/secret.bin"

export STATE_FAIL=${STATEBASE}/fail-state
rm -rf "$STATE_FAIL"
# Created by root INSIDE the contained state base, then handed to the owner user: the base is
# not world-writable (unlike the old /tmp), so the unprivileged uid cannot create it itself.
# The fixture stays root-owned: secret.bin at mode 000 is unreadable to the owner user, which
# is the hash failure this scenario exists to produce.
install -d -m 700 "$STATE_FAIL"
chown -- "$OWNER_USER" "$STATE_FAIL"
runuser -u "$OWNER_USER" -- "$DEDCOM" --state-dir "$STATE_FAIL" --scan "$FAILROOT" --no-resume

python3 - <<'PY'
import os, sqlite3
db = os.path.join(os.environ["STATE_FAIL"], "dedcom.db")
con = sqlite3.connect(db)
scan_id, status = con.execute("SELECT id, status FROM scan ORDER BY id DESC LIMIT 1").fetchone()
if status != "complete_with_warnings":
    raise SystemExit(f"expected complete_with_warnings, got {status}")
rows = con.execute(
    "SELECT signature, path FROM dir_dedup WHERE scan_id = ? ORDER BY signature, path",
    (scan_id,),
).fetchall()
groups = {}
for sig, path in rows:
    groups.setdefault(sig, set()).add(path)
failure_pair = {os.environ["FAILROOT"] + "/A", os.environ["FAILROOT"] + "/B"}
for sig, paths in groups.items():
    if failure_pair <= paths:
        raise SystemExit(f"hash-failure pair unexpectedly grouped under {sig}: {sorted(paths)}")
hf = con.execute("SELECT hash_failures FROM scan_stats WHERE scan_id = ?", (scan_id,)).fetchone()[0]
if hf != 1:
    raise SystemExit(f"expected hash_failures=1, got {hf}")
print("hash failure does not group A/B; hash_failures=1; status=complete_with_warnings")
PY

chmod 644 "$FAILROOT/A/secret.bin"

banner "5. ledger publication: registered roots vs real omission rows"
# The base fixture gains one sub-min file (2 bytes, under the default min_size of 4096), so the
# expected ledger is EXACTLY one min_size row — rows exist only for actual omissions, while
# scan_root holds one row per registered root.
echo x > "$ROOT/false/A/undersize.tiny"
export STATE_LEDGER=${STATEBASE}/ledger-state
rm -rf "$STATE_LEDGER"
"$DEDCOM" --state-dir "$STATE_LEDGER" --scan "$ROOT" --no-resume
python3 - <<'PY'
import os, sqlite3
db = os.path.join(os.environ["STATE_LEDGER"], "dedcom.db")
con = sqlite3.connect(db)
sid = con.execute("SELECT MAX(id) FROM scan").fetchone()[0]
roots = con.execute("SELECT root_key, generation FROM scan_root WHERE scan_id=?", (sid,)).fetchall()
if len(roots) != 1:
    raise SystemExit(f"expected ONE registered root row, got {roots}")
if roots[0][1] <= 0:
    raise SystemExit(f"the root generation must be positive after a completed walk: {roots}")
rows = con.execute(
    "SELECT dir_key, reason, event_count FROM dir_omission WHERE scan_id=?", (sid,)
).fetchall()
# Rows exist ONLY for actual omissions: exactly the one undersized file.
expected_dir = os.environ["ROOT"] + "/false/A"
if len(rows) != 1 or rows[0][0] != expected_dir or rows[0][1] != "min_size" or rows[0][2] != 1:
    raise SystemExit(f"expected exactly one min_size row at {expected_dir}, got {rows}")
status = con.execute("SELECT status FROM scan WHERE id=?", (sid,)).fetchone()[0]
if status != "complete":
    raise SystemExit(f"an intentional filter must not warn: {status}")
print(f"[ledger] one registered root gen>0; one real omission row; status={status}")
PY

banner "6. walk-error suppression + CompleteWithWarnings (scan as $OWNER_USER)"
export ERRROOT="$TP_MNT/ds_a/dir-completeness-walkerr"
rm -rf "$ERRROOT"
mkdir -p "$ERRROOT/E" "$ERRROOT/F" "$ERRROOT/E/locked"
dd if=/dev/zero of="$ERRROOT/E/same.bin" bs=64K count=1 status=none
cp "$ERRROOT/E/same.bin" "$ERRROOT/F/same.bin"
dd if=/dev/urandom of="$ERRROOT/E/locked/hidden.bin" bs=4K count=1 status=none
chmod 700 "$ERRROOT/E/locked"
chown root:root "$ERRROOT/E/locked"

export STATE_ERR=${STATEBASE}/err-state
rm -rf "$STATE_ERR"
install -d -m 700 "$STATE_ERR"
chown -- "$OWNER_USER" "$STATE_ERR"
runuser -u "$OWNER_USER" -- "$DEDCOM" --state-dir "$STATE_ERR" --scan "$ERRROOT" --no-resume | tee ${DIRTMP}/err-scan.out
grep -q "Scan left gaps:" ${DIRTMP}/err-scan.out || {
    echo "the aggregate omission notice is missing"; exit 1; }
grep -q "^Omissions:" ${DIRTMP}/err-scan.out || {
    echo "the omission summary line is missing"; exit 1; }
python3 - <<'PY'
import os, sqlite3
db = os.path.join(os.environ["STATE_ERR"], "dedcom.db")
con = sqlite3.connect(db)
sid, status = con.execute("SELECT id, status FROM scan ORDER BY id DESC LIMIT 1").fetchone()
if status != "complete_with_warnings":
    raise SystemExit(f"a walk error must warn: {status}")
reasons = dict(con.execute(
    "SELECT reason, SUM(event_count) FROM dir_omission WHERE scan_id=? GROUP BY reason", (sid,)
).fetchall())
if reasons.get("walk_error", 0) < 1:
    raise SystemExit(f"the unreadable directory must leave a walk_error row: {reasons}")
rows = con.execute(
    "SELECT signature, path FROM dir_dedup WHERE scan_id=? ORDER BY signature, path", (sid,)
).fetchall()
groups = {}
for sig, path in rows:
    groups.setdefault(sig, set()).add(path)
err_pair = {os.environ["ERRROOT"] + "/E", os.environ["ERRROOT"] + "/F"}
for sig, paths in groups.items():
    if err_pair <= paths:
        raise SystemExit(f"the walk-error side must be suppressed, got {sorted(paths)}")
print(f"[walk-error] status={status}; walk_error rows={reasons.get('walk_error')}; E/F not twins")
PY

banner "7. reopen: verdicts and groups are stable across a second process"
python3 - <<'PY'
import os, sqlite3
# The ledger and materialization written by phase 6 are re-read byte-stable by a fresh
# connection: same registered generation, same rows, same dir_dedup membership.
db = os.path.join(os.environ["STATE_ERR"], "dedcom.db")
first = sqlite3.connect(db)
sid = first.execute("SELECT MAX(id) FROM scan").fetchone()[0]
snap = lambda con: (
    con.execute("SELECT root_key, generation FROM scan_root WHERE scan_id=? ORDER BY root_key", (sid,)).fetchall(),
    con.execute("SELECT root_key, dir_key, reason, event_count, generation FROM dir_omission WHERE scan_id=? ORDER BY root_key, dir_key, reason", (sid,)).fetchall(),
    con.execute("SELECT signature, path FROM dir_dedup WHERE scan_id=? ORDER BY signature, path", (sid,)).fetchall(),
)
a = snap(first); first.close()
second = sqlite3.connect(db)
b = snap(second); second.close()
if a != b:
    raise SystemExit("reopen must see the identical ledger and groups")
print("[reopen] scan_root, dir_omission and dir_dedup identical across connections")
PY

banner "8. interrupted Hashing resume: authoritative = no re-walk; no authority = re-walk"
# Enough duplicate payload that SIGTERM lands inside the hashing phase.
export BIGROOT="$TP_MNT/ds_a/dir-completeness-resume"
rm -rf "$BIGROOT"
mkdir -p "$BIGROOT/one" "$BIGROOT/two"
for i in $(seq 1 24); do
    dd if=/dev/urandom of="$BIGROOT/one/f$i.bin" bs=1M count=8 status=none
    cp "$BIGROOT/one/f$i.bin" "$BIGROOT/two/f$i.bin"
done

interrupted_scan() { # $1 = state dir, $2... = scan args; SIGTERM at the first hashing line
    local state="$1"; shift
    rm -rf "$state"; mkdir -p "$state"
    "$DEDCOM" --state-dir "$state" "$@" > "$state/run1.out" 2>&1 &
    local pid=$!
    for _ in $(seq 1 300); do
        grep -q "\[phase\] Hashing" "$state/run1.out" 2>/dev/null && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    grep -q "Scan cancelled" "$state/run1.out" || {
        echo "run 1 must be cancelled mid-hashing:"; cat "$state/run1.out"; exit 1; }
}

walk_count() { # how many walks this state dir has performed (one log line per walk phase)
    grep -c "scan roots:" "$1/dedcom.log"
}

# 8a. Authoritative ledger (absolute root): the resume performs ZERO walks.
export STATE_RESUME_AUTH=${STATEBASE}/resume-auth
interrupted_scan "$STATE_RESUME_AUTH" --scan "$BIGROOT" --no-resume
[ "$(walk_count "$STATE_RESUME_AUTH")" = "1" ] || { echo "run 1 walks exactly once"; exit 1; }
"$DEDCOM" --state-dir "$STATE_RESUME_AUTH" --scan "$BIGROOT" > "$STATE_RESUME_AUTH/run2.out"
grep -q "Resuming unfinished scan" "$STATE_RESUME_AUTH/run2.out" || {
    echo "run 2 must resume, not start fresh"; exit 1; }
[ "$(walk_count "$STATE_RESUME_AUTH")" = "1" ] || {
    echo "an authoritative Hashing resume must not re-walk"; exit 1; }
grep -q "^Omissions:            0 files, 0 walk errors, 0 unsupported entries" \
    "$STATE_RESUME_AUTH/run2.out" || { echo "exact zero ledger totals expected"; exit 1; }

# Only NOW does the resume tree gain an omission: 8a above had to see a clean root and prove an
# exact zero, while 8b needs one real event whose account cannot outlive the interrupted process.
# A FIFO is the deterministic, privilege-free choice -- the walk classifies it by entry type, with
# no sleep, no permission race and no mocked counter. It lives in the disposable pool and dies
# with it.
mkfifo "$BIGROOT/one/resume-observed.pipe"
test -p "$BIGROOT/one/resume-observed.pipe" || {
    echo "the unsupported-entry fixture is not a FIFO"; exit 1; }

# 8b. Roots-unavailable (relative root spelling): the resume MUST re-walk and reconstruct
# the observed account before completing.
export STATE_RESUME_REL=${STATEBASE}/resume-rel
cd "$TP_MNT/ds_a"
interrupted_scan "$STATE_RESUME_REL" --scan ./dir-completeness-resume --no-resume
[ "$(walk_count "$STATE_RESUME_REL")" = "1" ] || { echo "run 1 walks exactly once"; exit 1; }
"$DEDCOM" --state-dir "$STATE_RESUME_REL" --scan ./dir-completeness-resume > "$STATE_RESUME_REL/run2.out"
grep -q "Resuming unfinished scan" "$STATE_RESUME_REL/run2.out" || {
    echo "run 2 must resume the relative-root scan"; exit 1; }
[ "$(walk_count "$STATE_RESUME_REL")" = "2" ] || {
    echo "a no-authority Hashing resume must re-walk"; exit 1; }
# The lost-session-account window: run 1 counted the FIFO and died with its count. Run 2 has to
# re-walk and arrive at the SAME number -- an exact account, not merely the session-only wording.
grep -qxF "Omissions:            0 files, 0 walk errors, 1 unsupported entries (session only — not persisted)" \
    "$STATE_RESUME_REL/run2.out" || {
    echo "the reconstructed account must be exactly one unsupported entry, session-only:"
    grep -n "^Omissions:" "$STATE_RESUME_REL/run2.out" || echo "(no Omissions line at all)"
    exit 1; }
# And the aggregate notice must name the same event AND its persistence truth.
grep -q "Scan left gaps: 1 unsupported entries" "$STATE_RESUME_REL/run2.out" || {
    echo "the notice must name the reconstructed event:"; cat "$STATE_RESUME_REL/run2.out"; exit 1; }
grep -qF "(details not persisted: no completeness authority)" "$STATE_RESUME_REL/run2.out" || {
    echo "the notice must say the account was not persisted:"; cat "$STATE_RESUME_REL/run2.out"; exit 1; }
cd "$DIRTMP"
python3 - <<'PY'
import os, sqlite3
# One expected status for both cases would hide the whole point: the authoritative root finishes
# clean, while the root that could never be registered finishes WITH warnings -- it saw a real
# omission it has nowhere to persist. Hence a per-case matrix, and a dir_omission count that
# proves the reconstructed account really is session-only rather than quietly stored.
for name, state, want_root, want_status in (
    ("auth", os.environ["STATE_RESUME_AUTH"], 1, "complete"),
    ("rel", os.environ["STATE_RESUME_REL"], 0, "complete_with_warnings"),
):
    con = sqlite3.connect(os.path.join(state, "dedcom.db"))
    sid, status = con.execute("SELECT id, status FROM scan ORDER BY id DESC LIMIT 1").fetchone()
    if status != want_status:
        raise SystemExit(f"[{name}] expected status {want_status}, got {status}")
    roots = con.execute("SELECT COUNT(*) FROM scan_root WHERE scan_id=?", (sid,)).fetchone()[0]
    if roots != want_root:
        raise SystemExit(f"[{name}] expected {want_root} scan_root rows, got {roots}")
    omissions = con.execute(
        "SELECT COUNT(*) FROM dir_omission WHERE scan_id=?", (sid,)
    ).fetchone()[0]
    if omissions != 0:
        raise SystemExit(f"[{name}] expected no persisted omission rows, got {omissions}")
    print(f"[resume/{name}] status={status}, scan_root rows={roots}, dir_omission rows={omissions}")
PY

banner "9. Old/Merkle parity holds for the walk-error fixture too"
export STATE_ERR_MERKLE=${STATEBASE}/err-merkle-state
rm -rf "$STATE_ERR_MERKLE"
install -d -m 700 "$STATE_ERR_MERKLE"
chown -- "$OWNER_USER" "$STATE_ERR_MERKLE"
runuser -u "$OWNER_USER" -- "$DEDCOM" --state-dir "$STATE_ERR_MERKLE" --scan "$ERRROOT" --no-resume --merkle-dirs
python3 - <<'PY'
import os, sqlite3
def memberships(state):
    con = sqlite3.connect(os.path.join(state, "dedcom.db"))
    sid = con.execute("SELECT MAX(id) FROM scan").fetchone()[0]
    rows = con.execute("SELECT signature, path FROM dir_dedup WHERE scan_id=? ORDER BY signature, path", (sid,)).fetchall()
    groups = {}
    for sig, path in rows:
        groups.setdefault(sig, []).append(path)
    return sorted(tuple(paths) for paths in groups.values())
old = memberships(os.environ["STATE_ERR"])
merkle = memberships(os.environ["STATE_ERR_MERKLE"])
if old != merkle:
    raise SystemExit(f"Old/Merkle memberships differ under a walk error:\n{old!r}\n{merkle!r}")
print(f"[parity] Old == Merkle under suppression: {len(old)} groups")
PY

banner "10. live states over tmux: Trusted highlights, Unknown shows rescan required"
# An Unknown copy: same data, generations zeroed — every stored group becomes an
# unverified candidate and the list must say so instead of claiming savings.
export STATE_UNKNOWN=${STATEBASE}/unknown-state
rm -rf "$STATE_UNKNOWN"
cp -a "$STATE_LEDGER" "$STATE_UNKNOWN"
python3 - <<'PY'
import os, sqlite3
con = sqlite3.connect(os.path.join(os.environ["STATE_UNKNOWN"], "dedcom.db"))
con.execute("UPDATE scan_root SET generation = 0")
con.commit()
print("[unknown] generations zeroed on the copy")
PY

# The TUI runs on a PRIVATE tmux server, addressed exclusively through a socket that lives
# inside this run's contained tmp directory. The default server — where a human or root
# session may be running on a shared host — is never probed, never joined and never killed;
# there is no bare `tmux` call and no global kill-server anywhere in this script. Failing to
# start, drive or shut down the private server is a scenario failure, not a shrug.
TMUX_SOCKET="${DIRTMP}/tmux-dircomp-$$.sock"
ptmux() { tmux -S "$TMUX_SOCKET" "$@"; }

capture_dir_groups() { # $1 = state dir, $2 = capture file: open commander, cycle to DirGroupList
    local state="$1" out="$2"
    ptmux new-session -d -s dircomp -x 120 -y 35 "\"$DEDCOM\" --state-dir \"$state\"" \
        || { echo "could not start the private tmux session on $TMUX_SOCKET" >&2; return 1; }
    sleep 3
    # Consent gate on a fresh state dir: Space checks the consent box, Enter continues. The
    # sends may land after the pane already advanced, so their status is not load-bearing —
    # the capture loop below is what decides.
    ptmux send-keys -t dircomp Space 2>/dev/null || true
    sleep 1
    ptmux send-keys -t dircomp Enter 2>/dev/null || true
    sleep 2
    for _ in 1 2 3 4 5 6 7; do
        ptmux send-keys -t dircomp v \
            || { echo "the private tmux session died under send-keys" >&2; return 1; }
        sleep 1
        ptmux capture-pane -t dircomp -p > "$out" \
            || { echo "could not capture the private tmux pane" >&2; return 1; }
        grep -q "directory groups" "$out" && break
    done
    ptmux kill-session -t dircomp \
        || { echo "could not close the private tmux session" >&2; return 1; }
}

# The private server must be gone at the end of the scenario — and proving that is part of
# the scenario, because a surviving server keeps the product process alive with it.
cleanup_private_tmux() {
    if [ -S "$TMUX_SOCKET" ] && ptmux has-session 2>/dev/null; then
        ptmux kill-server 2>/dev/null \
            || { echo "could not shut down the private tmux server on $TMUX_SOCKET" >&2; return 1; }
    fi
    rm -f -- "$TMUX_SOCKET"
    if [ -e "$TMUX_SOCKET" ]; then
        echo "private tmux socket $TMUX_SOCKET is still present" >&2; return 1
    fi
    return 0
}

capture_dir_groups "$STATE_LEDGER" ${DIRTMP}/dircomp-trusted.cap
grep -q "directory groups" ${DIRTMP}/dircomp-trusted.cap || {
    echo "the DirGroupList view was not reached:"; cat ${DIRTMP}/dircomp-trusted.cap; exit 1; }
grep -q "free" ${DIRTMP}/dircomp-trusted.cap || {
    echo "trusted groups must state their savings:"; cat ${DIRTMP}/dircomp-trusted.cap; exit 1; }
grep -q "rescan required" ${DIRTMP}/dircomp-trusted.cap && {
    echo "a trusted ledger must not demand a rescan:"; cat ${DIRTMP}/dircomp-trusted.cap; exit 1; }

capture_dir_groups "$STATE_UNKNOWN" ${DIRTMP}/dircomp-unknown.cap
grep -q "rescan required" ${DIRTMP}/dircomp-unknown.cap || {
    echo "unverified candidates must say rescan required:"; cat ${DIRTMP}/dircomp-unknown.cap; exit 1; }
grep -q "free" ${DIRTMP}/dircomp-unknown.cap && {
    echo "an unverified candidate must never claim savings:"; cat ${DIRTMP}/dircomp-unknown.cap; exit 1; }
cleanup_private_tmux || exit 1
echo "[live] trusted list claims savings; unknown list demands rescan and claims none"

banner "ALL ASSERTIONS PASSED"
