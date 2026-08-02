#!/usr/bin/env bash
# E2E test: directory-completeness invariant on a disposable loopback-ZFS pool.
# Exercises the false-twin suppression case end-to-end.
#
# Run as ROOT on a disposable ZFS host: root steps run directly; the unprivileged
# hash-failure case uses `runuser -u nobody` (no sudo required).
# SAFETY: operates ONLY on the disposable pool $DEDCOM_TESTPOOL_NAME (default
# dedcomdirtest) under $DEDCOM_TESTPOOL_DIR (default /var/lib/dedcom-dirtest) --
# never on production data. Override DEDCOM / HARNESS to point at the dedcom binary
# and the harness scripts dir. Does NOT tear down the pool -- run
# teardown-test-pool.sh separately after observing the result.
set -euo pipefail
cd /tmp

DEDCOM="${DEDCOM:-/tmp/dedcom-e2e/dedcom}"
HARNESS="${HARNESS:-/tmp/dedcom-e2e/scripts}"

banner() { printf '\n========== %s ==========\n' "$*"; }

banner "preconditions"
test -x "$DEDCOM"
test -x "$HARNESS/make-test-pool.sh"
test -x "$HARNESS/teardown-test-pool.sh"
"$DEDCOM" -V
python3 -c 'import sqlite3; print("python sqlite3", sqlite3.sqlite_version)'

banner "1. create disposable pool + fixtures"
export DEDCOM_TESTPOOL_NAME=dedcomdirtest
export DEDCOM_TESTPOOL_DIR=/var/lib/dedcom-dirtest
export DEDCOM_TESTPOOL_SIZE=2G
"$HARNESS/make-test-pool.sh"

export ROOT=/dedcomdirtest/ds_a/dir-completeness
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
export STATE_OLD=/tmp/dedcom-dir-old-state
export STATE_MERKLE=/tmp/dedcom-dir-merkle-state
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

banner "4. hash-failure suppression (scan as nobody)"
export FAILROOT=/dedcomdirtest/ds_a/dir-completeness-hashfail
rm -rf "$FAILROOT"
mkdir -p "$FAILROOT/A" "$FAILROOT/B"
dd if=/dev/zero of="$FAILROOT/A/shared.bin" bs=64K count=1 status=none
cp "$FAILROOT/A/shared.bin" "$FAILROOT/B/shared.bin"
dd if=/dev/zero of="$FAILROOT/A/secret.bin" bs=64K count=1 status=none
chmod 000 "$FAILROOT/A/secret.bin"

export STATE_FAIL=/tmp/dedcom-dir-fail-state
rm -rf "$STATE_FAIL"
runuser -u nobody -- install -d -m 700 "$STATE_FAIL"
runuser -u nobody -- "$DEDCOM" --state-dir "$STATE_FAIL" --scan "$FAILROOT" --no-resume

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
export STATE_LEDGER=/tmp/dedcom-dir-ledger-state
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

banner "6. walk-error suppression + CompleteWithWarnings (scan as nobody)"
export ERRROOT=/dedcomdirtest/ds_a/dir-completeness-walkerr
rm -rf "$ERRROOT"
mkdir -p "$ERRROOT/E" "$ERRROOT/F" "$ERRROOT/E/locked"
dd if=/dev/zero of="$ERRROOT/E/same.bin" bs=64K count=1 status=none
cp "$ERRROOT/E/same.bin" "$ERRROOT/F/same.bin"
dd if=/dev/urandom of="$ERRROOT/E/locked/hidden.bin" bs=4K count=1 status=none
chmod 700 "$ERRROOT/E/locked"
chown root:root "$ERRROOT/E/locked"

export STATE_ERR=/tmp/dedcom-dir-err-state
rm -rf "$STATE_ERR"
runuser -u nobody -- install -d -m 700 "$STATE_ERR"
runuser -u nobody -- "$DEDCOM" --state-dir "$STATE_ERR" --scan "$ERRROOT" --no-resume | tee /tmp/dedcom-err-scan.out
grep -q "Scan left gaps:" /tmp/dedcom-err-scan.out || {
    echo "the aggregate omission notice is missing"; exit 1; }
grep -q "^Omissions:" /tmp/dedcom-err-scan.out || {
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
export BIGROOT=/dedcomdirtest/ds_a/dir-completeness-resume
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
export STATE_RESUME_AUTH=/tmp/dedcom-dir-resume-auth
interrupted_scan "$STATE_RESUME_AUTH" --scan "$BIGROOT" --no-resume
[ "$(walk_count "$STATE_RESUME_AUTH")" = "1" ] || { echo "run 1 walks exactly once"; exit 1; }
"$DEDCOM" --state-dir "$STATE_RESUME_AUTH" --scan "$BIGROOT" > "$STATE_RESUME_AUTH/run2.out"
grep -q "Resuming unfinished scan" "$STATE_RESUME_AUTH/run2.out" || {
    echo "run 2 must resume, not start fresh"; exit 1; }
[ "$(walk_count "$STATE_RESUME_AUTH")" = "1" ] || {
    echo "an authoritative Hashing resume must not re-walk"; exit 1; }
grep -q "^Omissions:            0 files, 0 walk errors, 0 unsupported entries" \
    "$STATE_RESUME_AUTH/run2.out" || { echo "exact zero ledger totals expected"; exit 1; }

# 8b. Roots-unavailable (relative root spelling): the resume MUST re-walk and reconstruct
# the observed account before completing.
export STATE_RESUME_REL=/tmp/dedcom-dir-resume-rel
cd /dedcomdirtest/ds_a
interrupted_scan "$STATE_RESUME_REL" --scan ./dir-completeness-resume --no-resume
[ "$(walk_count "$STATE_RESUME_REL")" = "1" ] || { echo "run 1 walks exactly once"; exit 1; }
"$DEDCOM" --state-dir "$STATE_RESUME_REL" --scan ./dir-completeness-resume > "$STATE_RESUME_REL/run2.out"
grep -q "Resuming unfinished scan" "$STATE_RESUME_REL/run2.out" || {
    echo "run 2 must resume the relative-root scan"; exit 1; }
[ "$(walk_count "$STATE_RESUME_REL")" = "2" ] || {
    echo "a no-authority Hashing resume must re-walk"; exit 1; }
grep -q "(session only — not persisted)" "$STATE_RESUME_REL/run2.out" || {
    echo "the reconstructed observed account must be reported"; exit 1; }
cd /tmp
python3 - <<'PY'
import os, sqlite3
for name, state, want_root in (
    ("auth", os.environ["STATE_RESUME_AUTH"], 1),
    ("rel", os.environ["STATE_RESUME_REL"], 0),
):
    con = sqlite3.connect(os.path.join(state, "dedcom.db"))
    sid, status = con.execute("SELECT id, status FROM scan ORDER BY id DESC LIMIT 1").fetchone()
    if status != "complete":
        raise SystemExit(f"[{name}] the resumed scan must complete cleanly: {status}")
    roots = con.execute("SELECT COUNT(*) FROM scan_root WHERE scan_id=?", (sid,)).fetchone()[0]
    if roots != want_root:
        raise SystemExit(f"[{name}] expected {want_root} scan_root rows, got {roots}")
    print(f"[resume/{name}] status={status}, scan_root rows={roots}")
PY

banner "9. Old/Merkle parity holds for the walk-error fixture too"
export STATE_ERR_MERKLE=/tmp/dedcom-dir-err-merkle-state
rm -rf "$STATE_ERR_MERKLE"
runuser -u nobody -- install -d -m 700 "$STATE_ERR_MERKLE"
runuser -u nobody -- "$DEDCOM" --state-dir "$STATE_ERR_MERKLE" --scan "$ERRROOT" --no-resume --merkle-dirs
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
export STATE_UNKNOWN=/tmp/dedcom-dir-unknown-state
rm -rf "$STATE_UNKNOWN"
cp -a "$STATE_LEDGER" "$STATE_UNKNOWN"
python3 - <<'PY'
import os, sqlite3
con = sqlite3.connect(os.path.join(os.environ["STATE_UNKNOWN"], "dedcom.db"))
con.execute("UPDATE scan_root SET generation = 0")
con.commit()
print("[unknown] generations zeroed on the copy")
PY

tmux kill-server 2>/dev/null || true
capture_dir_groups() { # $1 = state dir, $2 = capture file: open commander, cycle to DirGroupList
    local state="$1" out="$2"
    tmux new-session -d -s dircomp -x 120 -y 35 "\"$DEDCOM\" --state-dir \"$state\""
    sleep 3
    # Consent gate on a fresh state dir: Space checks the consent box, Enter continues.
    tmux send-keys -t dircomp Space 2>/dev/null || true
    sleep 1
    tmux send-keys -t dircomp Enter 2>/dev/null || true
    sleep 2
    for _ in 1 2 3 4 5 6 7; do
        tmux send-keys -t dircomp v
        sleep 1
        tmux capture-pane -t dircomp -p > "$out"
        grep -q "directory groups" "$out" && break
    done
    tmux kill-session -t dircomp 2>/dev/null || true
}

capture_dir_groups "$STATE_LEDGER" /tmp/dircomp-trusted.cap
grep -q "directory groups" /tmp/dircomp-trusted.cap || {
    echo "the DirGroupList view was not reached:"; cat /tmp/dircomp-trusted.cap; exit 1; }
grep -q "free" /tmp/dircomp-trusted.cap || {
    echo "trusted groups must state their savings:"; cat /tmp/dircomp-trusted.cap; exit 1; }
grep -q "rescan required" /tmp/dircomp-trusted.cap && {
    echo "a trusted ledger must not demand a rescan:"; cat /tmp/dircomp-trusted.cap; exit 1; }

capture_dir_groups "$STATE_UNKNOWN" /tmp/dircomp-unknown.cap
grep -q "rescan required" /tmp/dircomp-unknown.cap || {
    echo "unverified candidates must say rescan required:"; cat /tmp/dircomp-unknown.cap; exit 1; }
grep -q "free" /tmp/dircomp-unknown.cap && {
    echo "an unverified candidate must never claim savings:"; cat /tmp/dircomp-unknown.cap; exit 1; }
tmux kill-server 2>/dev/null || true
echo "[live] trusted list claims savings; unknown list demands rescan and claims none"

banner "ALL ASSERTIONS PASSED"
