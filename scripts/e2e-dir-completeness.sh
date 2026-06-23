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

banner "ALL ASSERTIONS PASSED"
