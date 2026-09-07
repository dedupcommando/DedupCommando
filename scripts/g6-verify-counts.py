#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent count verifier for the G6 fixture.

Independent means three things, and all three are the point:

1. The expected numbers are DERIVED HERE from the frozen parameters. Nothing is imported from
   g6-make-fixture.sh, and the generator publishes no counts for this program to believe.
2. The observed numbers come from the checkpoint the PRODUCT wrote, read as plain SQL.
3. The membership source is named explicitly and is not guessed from a table name.

That third point is not pedantry. For a finished ordinary scan `file_group_member` holds ZERO
rows — it is not the scan's membership store — and `scan_membership` holds a single
(scan_id, mode, generation) marker. Membership lives in `file_group.file_count`. A verifier
written from the table names would assert COUNT(file_group_member) == G*M and fail forever.

Usage:
    g6-verify-counts.py --db <PATH> --groups G --members-per-group M --singletons U
                        [--csv <PATH>] [--membership-source file_group|file_group_member]
"""

import argparse
import hashlib
import sqlite3
import sys

EXPECTED_USER_VERSION = 6
PRODUCT_MIN_SIZE = 4096

# The v6 structural contract, transcribed from the product's own schema (src/state/schema.rs).
#
# A stamp and four table names are not a schema. `PRAGMA user_version = 6` is one integer any
# writer can set, and a database carrying that integer over three empty tables would satisfy a
# check that only counts names. What is checked here is the shape the product actually creates:
# every table, the columns of the tables this verifier reads, and the indexes those columns are
# useless without.
#
# This is a check of CONFORMANCE, not of origin. It cannot prove where a database came from —
# nothing about a schema can, because a schema is copyable — which is why provenance is settled
# by the invocation record and the receipt, and this only refuses a database that could not have
# come from the product at all.
V6_TABLES = (
    "scan", "file", "scan_stats", "file_mark", "dir_dedup", "file_group", "file_dedup",
    "scan_membership", "file_group_member", "hash_cache", "move_event", "scan_root",
    "dir_omission",
)

# Every table, not only the ones this program reads: a checkpoint missing a column of a table
# nobody queries here is still not a checkpoint the product would have created.
V6_COLUMNS = {
    # `trashed` is part of the v0 floor (schema.rs FLOOR_V0): a checkpoint without it is not
    # one this product wrote, and leaving it out of the contract left a real column unguarded.
    "scan": ("id", "created_at", "updated_at", "status", "config_json", "trashed"),
    "file": ("scan_id", "path", "size", "mtime", "mtime_nsec", "ctime_sec", "ctime_nsec",
             "identity_version", "device", "inode", "nlink", "hash"),
    # The four `cand_*` columns and `hash_failures` arrive through the migration ladder
    # (schema.rs, guarded ALTER ADD COLUMN), `results_materialized` through the v2 floor. They
    # are columns of a table this program already reads, so their absence has to refuse.
    "scan_stats": ("scan_id", "elapsed_seconds", "storage_type", "pool_layout", "zfs_version",
                   "files_scanned", "bytes_hashed", "groups_found", "reclaimable_bytes",
                   "reclaim_state", "hash_failures", "results_materialized",
                   "cand_files_total", "cand_bytes_total",
                   "cand_files_hashed", "cand_bytes_hashed"),
    "file_mark": ("scan_id", "path", "is_keeper", "action"),
    "dir_dedup": ("scan_id", "signature", "path", "file_count", "size_per_dir"),
    "file_group": ("scan_id", "rank", "hash", "file_count", "size", "reclaim", "object_count",
                   "reclaim_state"),
    "file_dedup": ("scan_id", "hash", "path", "size", "mtime", "device", "inode"),
    "scan_membership": ("scan_id", "mode", "generation"),
    "file_group_member": ("scan_id", "group_rank", "path", "generation"),
    "hash_cache": ("device", "inode", "size", "mtime", "hash", "updated_at"),
    # `path_fidelity` arrived with schema v6, when the two pathnames became raw bytes.
    "move_event": ("id", "created_at", "scan_id", "source_path", "target_path", "hash",
                   "duplicate", "path_fidelity"),
    "scan_root": ("scan_id", "root_key", "generation"),
    "dir_omission": ("scan_id", "root_key", "dir_key", "reason", "event_count", "generation"),
}

# The move journal's contract is more than its column names. Schema v6 stores both pathnames as
# BLOB — the raw bytes the move handled — and marks every row with `path_fidelity`, whose two
# CHECKs are the rule that a row may claim exactness only for BLOB pathnames. A database with the
# old TEXT columns plus a `path_fidelity` column carries every v6 name and none of the v6 meaning,
# and so does a copy of the table whose CHECKs live only in a comment. So this one table is sealed
# by its full `PRAGMA table_xinfo` — (cid, name, type, notnull, default, pk, hidden), generated and
# hidden columns included — AND by the exact text SQLite stores for it: the text is the only
# complete record of the constraints, and the product compares it the same way.
MOVE_EVENT_XINFO = (
    (0, "id", "INTEGER", 0, None, 1, 0),
    (1, "created_at", "TEXT", 1, None, 0, 0),
    (2, "scan_id", "INTEGER", 0, None, 0, 0),
    (3, "source_path", "BLOB", 1, None, 0, 0),
    (4, "target_path", "BLOB", 1, None, 0, 0),
    (5, "hash", "BLOB", 0, None, 0, 0),
    (6, "duplicate", "INTEGER", 1, None, 0, 0),
    (7, "path_fidelity", "INTEGER", 1, "0", 0, 0),
)
MOVE_EVENT_SQL = """CREATE TABLE move_event (
    id            INTEGER PRIMARY KEY,
    created_at    TEXT    NOT NULL,
    scan_id       INTEGER,
    source_path   BLOB    NOT NULL,
    target_path   BLOB    NOT NULL,
    hash          BLOB,
    duplicate     INTEGER NOT NULL,
    path_fidelity INTEGER NOT NULL DEFAULT 0,
    CHECK (path_fidelity IN (0, 1)),
    CHECK (path_fidelity = 0
           OR (typeof(source_path) = 'blob' AND typeof(target_path) = 'blob'))
)"""

# An index is not its name. Which table it belongs to, whether it is unique, whether it is
# partial, and the ORDER, direction and collation of its key columns are the index; a check that
# reads the name list would accept a one-column index wearing the name of a five-column one.
#   name -> (table, unique, ((column, desc, collation), ...), partial)
V6_INDEXES = {
    "file_size": ("file", 0, (("scan_id", 0, "BINARY"), ("size", 0, "BINARY")), 0),
    "file_hash": ("file", 0, (("scan_id", 0, "BINARY"), ("hash", 0, "BINARY")), 0),
    "file_content": ("file", 0, (("device", 0, "BINARY"), ("inode", 0, "BINARY"),
                                 ("size", 0, "BINARY"), ("mtime", 0, "BINARY")), 0),
    "file_scan_identity": ("file", 0, (("scan_id", 0, "BINARY"), ("device", 0, "BINARY"),
                                       ("inode", 0, "BINARY")), 0),
    "file_hash_identity": ("file", 0, (("scan_id", 0, "BINARY"), ("hash", 0, "BINARY"),
                                       ("device", 0, "BINARY"), ("inode", 0, "BINARY")), 0),
    "file_path_content": ("file", 0, (("path", 0, "BINARY"), ("size", 0, "BINARY"),
                                      ("mtime", 0, "BINARY")), 0),
    "file_hash_path": ("file", 0, (("scan_id", 0, "BINARY"), ("hash", 0, "BINARY"),
                                   ("path", 0, "BINARY")), 0),
    # The reuse identity: seven columns in this exact order. A shorter index wearing this name
    # would still let the hash cache answer for a file it never saw.
    "file_reuse_identity": ("file", 0, (("path", 0, "BINARY"), ("size", 0, "BINARY"),
                                        ("mtime", 0, "BINARY"), ("mtime_nsec", 0, "BINARY"),
                                        ("ctime_sec", 0, "BINARY"), ("ctime_nsec", 0, "BINARY"),
                                        ("identity_version", 0, "BINARY")), 0),
    "dir_dedup_by_scan_sig": ("dir_dedup", 0, (("scan_id", 0, "BINARY"),
                                               ("signature", 0, "BINARY")), 0),
    "file_group_hash": ("file_group", 0, (("scan_id", 0, "BINARY"), ("hash", 0, "BINARY")), 0),
    "file_dedup_by_scan_hash": ("file_dedup", 0, (("scan_id", 0, "BINARY"),
                                                  ("hash", 0, "BINARY")), 0),
    "file_group_member_by_path": ("file_group_member", 1, (("scan_id", 0, "BINARY"),
                                                           ("path", 0, "BINARY")), 0),
    "dir_omission_by_root": ("dir_omission", 0, (("scan_id", 0, "BINARY"),
                                                 ("root_key", 0, "BINARY"),
                                                 ("dir_key", 0, "BINARY")), 0),
}


def parse_args(argv):
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument("--db", required=True)
    p.add_argument("--groups", type=int, required=True)
    p.add_argument("--members-per-group", type=int, required=True)
    p.add_argument("--singletons", type=int, required=True)
    p.add_argument("--csv")
    # The production receipt, cross-checked HERE rather than believed where it was written. A
    # receipt that only its own author ever reads is a note, not evidence.
    p.add_argument("--receipt")
    # The record published BEFORE the scan. The receipt is bound to it by digest, and both
    # are checked here against their own seals.
    p.add_argument("--invocation")
    # The wrong source stays reachable so it can be PROVED wrong, but it is double-locked
    # behind an explicit negative-control flag. A verifier whose oracle can be pointed at the
    # wrong table by one ordinary-looking argument is a verifier waiting to be misconfigured on
    # the night it matters.
    p.add_argument("--membership-source",
                   choices=["file_group", "file_group_member"], default="file_group")
    p.add_argument("--negative-control", action="store_true")
    args = p.parse_args(argv)
    if args.membership_source != "file_group" and not args.negative_control:
        p.error("--membership-source file_group_member is a negative control and needs "
                "--negative-control; the production source is file_group.file_count")
    return args


SIZE_KEY = "record-size"
SHA_KEY = "record-sha256"


def read_sealed(path):
    """A published record, checked against its OWN seal before a single field is believed.

    Reading these as plain text was the gap: the receipt and the invocation record are durable
    records like any other, and a record whose seal nobody checks is a text file. Returns
    (fields, digest_of_the_whole_file) or raises ValueError with the reason."""
    with open(path, "rb") as fh:
        raw = fh.read()
    lines = raw.splitlines(keepends=True)
    if len(lines) < 3:
        raise ValueError(f"'{path}' is too short to carry a seal")
    size_line = lines[-2].decode(errors="replace")
    sha_line = lines[-1].decode(errors="replace")
    if not size_line.startswith(SIZE_KEY + "\t") or not sha_line.startswith(SHA_KEY + "\t"):
        raise ValueError(f"'{path}' carries no {SIZE_KEY}/{SHA_KEY} seal")
    body = b"".join(lines[:-2])
    size = size_line.split("\t", 1)[1].strip()
    sha = sha_line.split("\t", 1)[1].strip()
    if not size.isdigit() or int(size) != len(body):
        raise ValueError(f"'{path}' records size {size}, body is {len(body)} bytes")
    got = hashlib.sha256(body).hexdigest()
    if got != sha:
        raise ValueError(f"'{path}' records digest {sha}, body hashes to {got}")
    fields = {}
    for line in body.decode(errors="replace").splitlines():
        key, _, value = line.partition("\t")
        if key and key not in fields:
            fields[key] = value
    return fields, hashlib.sha256(raw).hexdigest()


def move_event_problems(conn):
    """The v6 move journal, by its full column list and its stored definition — not by names."""
    problems = []
    got = tuple(tuple(r) for r in conn.execute("PRAGMA table_xinfo(move_event)"))
    for index in range(max(len(got), len(MOVE_EVENT_XINFO))):
        have = got[index] if index < len(got) else None
        want = MOVE_EVENT_XINFO[index] if index < len(MOVE_EVENT_XINFO) else None
        if have != want:
            problems.append(f"move_event column {index}: {have}, expected {want}")
            break
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'move_event'").fetchone()
    sql = row[0] if row else ""
    if sql != MOVE_EVENT_SQL:
        common = 0
        for a, b in zip(sql, MOVE_EVENT_SQL):
            if a != b:
                break
            common += 1
        problems.append(
            f"move_event: the stored definition ({len(sql)} chars) is not the v6 text "
            f"({len(MOVE_EVENT_SQL)} chars): first difference at char {common} — BLOB pathnames, "
            f"path_fidelity and both CHECKs are required, as real constraints, not as names")
    return problems


def structural_problems(conn):
    """Every way this database fails to be the shape v6 creates."""
    problems = []
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != EXPECTED_USER_VERSION:
        problems.append(f"user_version={version}, expected {EXPECTED_USER_VERSION}")

    present = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    missing = [t for t in V6_TABLES if t not in present]
    if missing:
        problems.append(f"tables missing: {', '.join(missing)}")

    for table, columns in V6_COLUMNS.items():
        if table not in present:
            continue
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        absent = [c for c in columns if c not in have]
        if absent:
            problems.append(f"{table} is missing columns: {', '.join(absent)}")

    if "move_event" in present:
        problems.extend(move_event_problems(conn))

    indexes = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index'")}
    absent = [i for i in V6_INDEXES if i not in indexes]
    if absent:
        problems.append(f"indexes missing: {', '.join(absent)}")

    # The shape of every index that IS there: owner, uniqueness, partiality, and the key columns
    # in order with their direction and collation.
    for name, (table, unique, keys, partial) in V6_INDEXES.items():
        if name in absent or table not in present:
            continue
        listed = [r for r in conn.execute(f"PRAGMA index_list({table})") if r[1] == name]
        if not listed:
            problems.append(f"index {name} does not belong to {table}")
            continue
        _, _, is_unique, origin, is_partial = listed[0]
        if int(is_unique) != unique:
            problems.append(f"index {name}: unique={is_unique}, expected {unique}")
        if int(is_partial) != partial:
            problems.append(f"index {name}: partial={is_partial}, expected {partial}")
        if origin != "c":
            problems.append(f"index {name}: origin '{origin}', expected an explicit CREATE INDEX")
        got = tuple((r[2], int(r[3]), r[4])
                    for r in conn.execute(f"PRAGMA index_xinfo({name})") if r[5] == 1)
        if got != keys:
            problems.append(f"index {name}: keys {got}, expected {keys}")
    return problems


def receipt_problems(receipt, invocation, inv_digest, db_path, conn):
    """The chain, end to end: what was ANNOUNCED before the scan, what the receipt says happened,
    and what this program is actually looking at. Non-empty fields are not the check — exact
    equality is."""
    problems = []
    if not receipt:
        return ["the receipt is empty"]
    if receipt.get("checkpoint") != db_path:
        problems.append(f"the receipt is about '{receipt.get('checkpoint')}', "
                        f"this is '{db_path}'")
    stated = receipt.get("user_version")
    actual = str(conn.execute("PRAGMA user_version").fetchone()[0])
    if stated is not None and stated != actual:
        problems.append(f"the receipt states user_version={stated}, the checkpoint says {actual}")
    stated_problems = receipt.get("provenance-problems")
    if stated_problems and stated_problems != "none":
        problems.append(f"the receipt itself records: {stated_problems}")

    if invocation is None:
        problems.append("there is no invocation record to bind the receipt to")
        return problems

    # The receipt must name the sealed invocation it belongs to, by digest.
    claimed = receipt.get("invocation-sha256")
    if not claimed:
        problems.append("the receipt names no invocation digest")
    elif claimed != inv_digest:
        problems.append(f"the receipt names invocation {claimed}, the record hashes to "
                        f"{inv_digest}")

    for key in ("checkpoint", "scan-argv", "candidate-sha256"):
        r, i = receipt.get(key), invocation.get(key)
        if not r:
            problems.append(f"the receipt carries no {key}")
        elif not i:
            problems.append(f"the invocation record carries no {key}")
        elif r != i:
            problems.append(f"{key} differs: the invocation announced '{i}', "
                            f"the receipt reports '{r}'")
    return problems


def expected(groups, per_group, singletons):
    """The whole contract, derived from parameters alone."""
    members = groups * per_group
    return {
        "files": members + singletons,
        "groups": groups,
        "members": members,
        "csv_rows": 1 + members,
    }


def observed(conn, membership_source):
    one = lambda sql: conn.execute(sql).fetchone()[0]
    if membership_source == "file_group":
        members = one("SELECT COALESCE(SUM(file_count), 0) FROM file_group")
    else:
        members = one("SELECT COUNT(*) FROM file_group_member")
    return {
        "files": one("SELECT COUNT(*) FROM file"),
        "groups": one("SELECT COUNT(*) FROM file_group"),
        "members": members,
    }


def main(argv):
    args = parse_args(argv)
    for name, value in (("--groups", args.groups),
                        ("--members-per-group", args.members_per_group),
                        ("--singletons", args.singletons)):
        if value < 0:
            print(f"REFUSED: {name}={value} is negative", file=sys.stderr)
            return 2

    try:
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        print(f"BLOCKED: cannot open '{args.db}' read-only: {exc}", file=sys.stderr)
        return 2

    failures = []

    # The structural contract first, and it is fatal. Everything below reads product tables, so a
    # database that is not the shape the product creates must be refused here rather than crash
    # three queries later on a missing column — a traceback names Python, not the thing that is
    # actually wrong.
    try:
        structural = structural_problems(conn)
    except sqlite3.Error as exc:
        print(f"BLOCKED: the schema of {args.db} could not be read: {exc}", file=sys.stderr)
        return 2
    if structural:
        print("VERIFY: FAIL", file=sys.stderr)
        for problem in structural:
            print(f"  - v6 structure: {problem}", file=sys.stderr)
        print("  - this database is not the shape the product's schema-creation path produces",
              file=sys.stderr)
        return 1

    # The receipt is checked against the database it claims to be about, by the program that is
    # actually reading that database.
    if args.receipt is not None:
        try:
            receipt, _ = read_sealed(args.receipt)
        except (OSError, ValueError) as exc:
            print(f"BLOCKED: the receipt did not verify: {exc}", file=sys.stderr)
            return 2
        invocation, inv_digest = None, None
        if args.invocation is not None:
            try:
                invocation, inv_digest = read_sealed(args.invocation)
            except (OSError, ValueError) as exc:
                print(f"BLOCKED: the invocation record did not verify: {exc}", file=sys.stderr)
                return 2
        rp = receipt_problems(receipt, invocation, inv_digest, args.db, conn)
        if rp:
            print("VERIFY: FAIL", file=sys.stderr)
            for problem in rp:
                print(f"  - receipt: {problem}", file=sys.stderr)
            return 1
        print(f"receipt: agrees with this checkpoint ({args.receipt})")

    try:
        states = [r[0] for r in conn.execute("SELECT status FROM scan")]
        if states != ["complete"]:
            failures.append(f"scan status: {states!r}, expected exactly ['complete']")

        # A fixture the product silently declined to read is not a smaller fixture, it is a
        # different experiment. Any min_size omission means B was set below the product's floor.
        omitted = list(conn.execute(
            "SELECT reason, COALESCE(SUM(event_count), 0) FROM dir_omission GROUP BY reason"))
        min_size_events = sum(n for reason, n in omitted if reason == "min_size")
        if min_size_events:
            failures.append(
                f"min_size omissions: {min_size_events} events — files below the product's "
                f"floor of {PRODUCT_MIN_SIZE} bytes never enter the checkpoint")

        exp = expected(args.groups, args.members_per_group, args.singletons)
        obs = observed(conn, args.membership_source)
    except sqlite3.Error as exc:
        # A database that cannot be read is an environment problem, and it is reported as one
        # sentence rather than as a stack trace from a program nobody is debugging.
        print(f"BLOCKED: '{args.db}' could not be read: {exc}", file=sys.stderr)
        return 2

    print(f"membership source: {args.membership_source}")
    if args.membership_source == "file_group_member":
        print("  WARNING: file_group_member is not the membership store of a finished scan")
    for key in ("files", "groups", "members"):
        mark = "ok " if obs[key] == exp[key] else "BAD"
        print(f"  {mark} {key:8s} expected {exp[key]:>12} observed {obs[key]:>12}")
        if obs[key] != exp[key]:
            failures.append(f"{key}: expected {exp[key]}, observed {obs[key]}")

    if args.csv is not None:
        try:
            with open(args.csv, "rb") as fh:
                rows = sum(1 for _ in fh)
        except OSError as exc:
            failures.append(f"csv_rows: cannot read '{args.csv}': {exc}")
        else:
            mark = "ok " if rows == exp["csv_rows"] else "BAD"
            print(f"  {mark} {'csv_rows':8s} expected {exp['csv_rows']:>12} observed {rows:>12}")
            if rows != exp["csv_rows"]:
                failures.append(f"csv_rows: expected {exp['csv_rows']}, observed {rows}")

    if failures:
        print("VERIFY: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("VERIFY: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
