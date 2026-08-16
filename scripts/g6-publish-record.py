#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed publication and verification of one durable record.

Every record carries its own size and digest as the last two lines:

    <body lines>
    record-size\t<bytes of the body>
    record-sha256\t<sha256 of the body>

That is not the same mistake as a manifest vouching for its own trustworthiness. Nothing here
claims the CONTENT is right — the seal only proves the record on disk is the record that was
written, so a truncated write, a half-flushed page or a later edit is caught before any decision
is taken on the value inside. Authority over content lives outside, in the human-signed
sanction.

Publication: write into a UNIQUE absent sibling opened O_EXCL, check every write including the
short-write and no-progress cases, fsync the file, link it into place so the kernel refuses an
existing name PHYSICALLY rather than after a check, then fsync the directory. Anything short of
all of that is FAILED, and a FAILED publication can never end in PASS. A record is published
once; an existing final name is never overwritten and never restated.

The state file binds the run's outcome to the record that carries it — name, size and digest —
so a record that was deleted and a record that was replaced by a properly sealed one of somebody
else's are both detectable, and detectable as different things. Only ENOENT means NOT_STARTED;
unreadable, empty, malformed, incomplete or unknown all mean CORRUPT, and CORRUPT never licenses
a fresh run.

The FIRST state a run writes is a claim, and it is published create-only for the same reason the
record is: reading NOT_STARTED and then writing RUNNING is a check-then-act, and two runs can
both read an absent state file. Exactly one claim can win, and the losers are told they lost.

Usage:
    g6-publish-record.py --dir D --name N [--state-file S] [--code C]   # body on stdin
    g6-publish-record.py --verify --dir D --name N
    g6-publish-record.py --query-state --state-file S [--dir D]
"""

import argparse
import errno
import glob
import hashlib
import os
import sys

SIZE_KEY = "record-size"
SHA_KEY = "record-sha256"

# The exit status of a publication says whether THIS call published the record. 0 published it,
# 2 could not, 3 found it already published by an earlier run.
RC_RE_ENTRY = 3


def seal(body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return body + f"{SIZE_KEY}\t{len(body)}\n{SHA_KEY}\t{digest}\n".encode()


def split_sealed(raw: bytes):
    """Return (body, size, sha) or (None, None, None) when the seal is not well formed."""
    lines = raw.splitlines(keepends=True)
    if len(lines) < 2:
        return None, None, None
    try:
        size_line = lines[-2].decode()
        sha_line = lines[-1].decode()
    except UnicodeDecodeError:
        return None, None, None
    if not size_line.startswith(SIZE_KEY + "\t") or not sha_line.startswith(SHA_KEY + "\t"):
        return None, None, None
    body = b"".join(lines[:-2])
    return body, size_line.split("\t", 1)[1].strip(), sha_line.split("\t", 1)[1].strip()


def verify(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return f"cannot read '{path}': {exc}"
    body, size, sha = split_sealed(raw)
    if body is None:
        return f"'{path}' carries no {SIZE_KEY}/{SHA_KEY} seal"
    if not size.isdigit() or int(size) != len(body):
        return f"'{path}' records size {size}, body is {len(body)} bytes"
    got = hashlib.sha256(body).hexdigest()
    if got != sha:
        return f"'{path}' records digest {sha}, body hashes to {got}"
    return None


def write_all(fd, data, what):
    """Every write is checked, and a write that reports NO PROGRESS is an error rather than a
    reason to go round the loop again. os.write returning 0 on a regular file means something is
    wrong with the descriptor, and retrying it forever is how a publication hangs instead of
    failing."""
    written = 0
    while written < len(data):
        n = os.write(fd, data[written:])
        if n <= 0:
            raise OSError(errno.EIO, f"write to {what} made no progress at byte {written}")
        written += n
    if written != len(data):
        raise OSError(errno.EIO, f"write to {what} landed {written} of {len(data)} bytes")


VALID_STATES = ("NOT_STARTED", "RUNNING", "PUBLISHED", "FAILED")
STATE_FIELDS = 5  # STATE code record-name record-size record-sha256


def blank_state(state, code, why):
    return {"state": state, "code": code, "name": "-", "size": "-", "sha": "-", "why": why}


def read_state(path):
    """The state is sealed too, and only a file that is NOT THERE is a fresh start.

    An unreadable, empty, malformed, incomplete, tampered or unknown state is CORRUPT and reports
    FAILED with code 2: a run must not be able to start over by damaging the file that says it
    already ran. The head is `<STATE> <code> <record-name> <record-size> <record-sha256>`, and
    carrying the record's identity here is what makes a SUBSTITUTED record detectable — a
    properly sealed record of somebody else's verifies perfectly against its own seal and says
    nothing about being the record this state file is talking about."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return blank_state("NOT_STARTED", 2, "no state file")
        return blank_state("FAILED", 2, f"the state file is unreadable: {exc.strerror}")
    if not raw:
        return blank_state("FAILED", 2, "the state file is empty")
    lines = raw.decode(errors="replace").splitlines()
    if len(lines) != 2 or not lines[1].startswith("state-sha256\t"):
        return blank_state("FAILED", 2, "the state file is not two sealed lines")
    head = lines[0]
    want = lines[1].split("\t", 1)[1].strip()
    if hashlib.sha256((head + "\n").encode()).hexdigest() != want:
        return blank_state("FAILED", 2, "the state file does not match its own seal")
    fields = head.split(" ")
    if len(fields) != STATE_FIELDS:
        return blank_state("FAILED", 2, f"the state head carries {len(fields)} fields, not {STATE_FIELDS}")
    state, code, name, size, sha = fields
    if state not in VALID_STATES or not code.strip().isdigit():
        return blank_state("FAILED", 2, f"the state word '{state}' is not one this program writes")
    return {"state": state, "code": int(code), "name": name, "size": size, "sha": sha, "why": ""}


def state_record(state, code, name="-", size="-", sha="-"):
    head = f"{state} {code} {name} {size} {sha}\n"
    return (head + f"state-sha256\t{hashlib.sha256(head.encode()).hexdigest()}\n").encode()


def claim_state(path, state, code):
    """The first durable word of a run, published create-only.

    Two runs that both read NOT_STARTED must not both go on to write RUNNING, and os.replace
    closes that window on the wrong side: it overwrites whatever the other run had just put
    there, and both of them believe they started the run. So the claim is published the way a
    record is — a unique O_EXCL temporary, written, fsynced, then LINKED into place, so the
    kernel refuses an existing state file physically rather than after a check. Exactly one of
    any number of simultaneous claims can win; the losers learn they lost and leave nothing
    behind.

    Returns 'ok' when this call made the claim, 'taken' when somebody else already holds it, and
    'failed' when it could not be written at all."""
    body = state_record(state, code)
    tmp = f"{path}.{os.getpid()}.claim"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        return "failed"
    outcome = "failed"
    try:
        try:
            write_all(fd, body, tmp)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, path)
            outcome = "ok"
        except FileExistsError:
            outcome = "taken"
        # The scratch name goes before the directory is fsynced, so the claim and the removal of
        # the temporary land in one fsync — and a loser, like a winner, leaves nothing behind.
        os.unlink(tmp)
        dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return "failed"
    return outcome


def write_state(path, state, code, name="-", size="-", sha="-"):
    body = state_record(state, code, name, size, sha)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            write_all(fd, body, tmp)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
    return True


def check_published_record(directory, st):
    """What re-entry has to establish before it may report the earlier outcome: the record is
    still there, still seals, and is still the SAME record the state file recorded. Returns
    (status, detail)."""
    final = os.path.join(directory, st["name"])
    if not os.path.exists(final):
        return "missing", f"'{final}' is gone"
    problem = verify(final)
    if problem:
        return "unsealed", problem
    try:
        size = os.path.getsize(final)
        with open(final, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
    except OSError as exc:
        return "unreadable", str(exc)
    if st["size"] != "-" and str(size) != st["size"]:
        return "size-mismatch", f"{size} bytes, the state recorded {st['size']}"
    if st["sha"] != "-" and got != st["sha"]:
        return "sha-mismatch", f"hashes to {got}, the state recorded {st['sha']}"
    return "ok", f"{st['name']} {size} {got}"


def durable_write(args, body, sealed):
    if os.sep in args.name or args.name in (".", "..") or args.name.startswith("."):
        print(f"REFUSED: record name '{args.name}' is not a plain name", file=sys.stderr)
        return 2

    # A record with no body is not a record. It seals perfectly — the digest of nothing is a
    # valid digest — and it would be published, verified and believed, while the thing it was
    # supposed to carry never reached this program at all.
    if not body:
        print(f"REFUSED: record '{args.name}' has an empty body; a record that carries nothing "
              f"is not a record", file=sys.stderr)
        return 2

    final = os.path.join(args.dir, args.name)
    stale = sorted(glob.glob(os.path.join(args.dir, f".{args.name}.*.tmp")))

    if os.path.exists(final):
        print(f"BLOCKED: record '{args.name}' is already published — refusing to restate it",
              file=sys.stderr)
        return 2
    if stale:
        print(f"BLOCKED: stale temporary '{stale[0]}' — provisioning failure, not a fresh run",
              file=sys.stderr)
        return 2

    # A unique name, so two publications can never collide on the temporary itself, and O_EXCL so
    # the kernel — not a preceding existence check — is what guarantees it was absent.
    tmp = os.path.join(args.dir, f".{args.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        print(f"FAILED: cannot create '{tmp}': {exc}", file=sys.stderr)
        return 2
    try:
        write_all(fd, sealed, tmp)
        os.fsync(fd)
    except OSError as exc:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        print(f"FAILED: write or fsync of '{tmp}': {exc}", file=sys.stderr)
        return 2
    else:
        os.close(fd)

    # link() is the no-overwrite the KERNEL enforces. os.replace would silently overwrite, and
    # checking first and renaming second is a check-then-act with a window in it — the exact
    # shape this project refuses everywhere else on a write path.
    try:
        os.link(tmp, final)
    except FileExistsError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        print(f"BLOCKED: record '{args.name}' appeared while it was being written — refusing to "
              f"overwrite it", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"FAILED: link '{tmp}' -> '{final}': {exc}", file=sys.stderr)
        return 2
    try:
        os.unlink(tmp)
    except OSError as exc:
        print(f"FAILED: the record landed but '{tmp}' could not be removed: {exc}",
              file=sys.stderr)
        return 2

    try:
        dfd = os.open(args.dir, os.O_RDONLY)
    except OSError as exc:
        print(f"FAILED: cannot open '{args.dir}' to fsync it: {exc}", file=sys.stderr)
        return 2
    try:
        os.fsync(dfd)
    except OSError as exc:
        print(f"FAILED: fsync of '{args.dir}': {exc}", file=sys.stderr)
        return 2
    finally:
        os.close(dfd)

    # Read it back and check the seal before calling it published.
    problem = verify(final)
    if problem:
        print(f"FAILED: the record did not read back intact: {problem}", file=sys.stderr)
        return 2

    print(f"PUBLISHED {args.name}")
    return 0


def main(argv):
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument("--dir")
    p.add_argument("--name")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--query-state", action="store_true")
    p.add_argument("--begin", action="store_true")
    p.add_argument("--state-file")
    p.add_argument("--code", type=int, default=0)
    args = p.parse_args(argv)

    # The re-run gate asks this BEFORE anything is mutated: NOT_STARTED is the only answer that
    # licenses a fresh run, and any other one carries the code the earlier run ended with. When a
    # directory is given, re-entry also re-establishes that the record behind that outcome is
    # still present, still sealed and still the same one.
    if args.query_state:
        if not args.state_file:
            print("REFUSED: --query-state needs --state-file", file=sys.stderr)
            return 2
        st = read_state(args.state_file)
        print(f"STATE\t{st['state']}\t{st['code']}\t{st['name']}\t{st['size']}\t{st['sha']}")
        if st["why"]:
            print(f"WHY\t{st['why']}")
        if st["state"] == "PUBLISHED" and args.dir:
            status, detail = check_published_record(args.dir, st)
            print(f"RECORD\t{status}\t{detail}")
            if status != "ok":
                return 2
        if st["state"] == "NOT_STARTED":
            return 0
        return st["code"] if st["state"] == "PUBLISHED" else 2

    # A run says it has STARTED before it is allowed to change anything, and it says so durably.
    # Without this the only state a run ever writes is the one it writes at the END, so a process
    # killed halfway leaves NOT_STARTED behind and the next attempt is indistinguishable from a
    # first one — over a machine the first one had already begun to change.
    if args.begin:
        if not args.state_file:
            print("REFUSED: --begin needs --state-file", file=sys.stderr)
            return 2
        st = read_state(args.state_file)
        if st["state"] != "NOT_STARTED":
            print(f"BLOCKED: this evidence directory is {st['state']} (code {st['code']}), "
                  f"not a fresh start", file=sys.stderr)
            return 2
        outcome = claim_state(args.state_file, "RUNNING", 2)
        if outcome == "taken":
            print("BLOCKED: another run claimed this evidence directory between the check and "
                  "the write — this call did not start it", file=sys.stderr)
            return 2
        if outcome != "ok":
            print("FAILED: cannot record the RUNNING state", file=sys.stderr)
            return 2
        print("RUNNING")
        return 0

    if args.verify:
        if not args.dir or not args.name:
            print("REFUSED: --verify needs --dir and --name", file=sys.stderr)
            return 2
        problem = verify(os.path.join(args.dir, args.name))
        if problem:
            print(f"BLOCKED: {problem}", file=sys.stderr)
            return 2
        print(f"VERIFIED {args.name}")
        return 0

    if not args.dir or not args.name:
        print("REFUSED: publication needs --dir and --name", file=sys.stderr)
        return 2

    if args.state_file:
        st = read_state(args.state_file)
        if st["state"] == "PUBLISHED":
            # RE_ENTRY, never the stored code. This program's exit status answers "did THIS call
            # publish the record", and nothing else. Returning the outcome of the earlier run
            # here would report a fresh success for a run that did not happen — and returning the
            # verdict of the CURRENT run would make every recorded FAIL look like a publication
            # that failed. The verdict travels in the record and in --query-state.
            print(f"RE_ENTRY {args.name} (already published, code {st['code']})")
            return RC_RE_ENTRY
        if st["state"] == "FAILED":
            print(f"FAILED: refusing to report success on re-entry ({st['why']})",
                  file=sys.stderr)
            return 2
        # RUNNING is this run's own BEGIN, and publishing the terminal record is what a RUNNING
        # run does next. NOT_STARTED means nobody announced the run at all, so it is announced
        # here — a direct publication with no route around it.
        if st["state"] == "NOT_STARTED":
            outcome = claim_state(args.state_file, "RUNNING", 2)
            if outcome != "ok":
                print(f"FAILED: cannot record the RUNNING state ({outcome})", file=sys.stderr)
                return 2

    body = sys.stdin.buffer.read()
    sealed = seal(body)
    rc = durable_write(args, body, sealed)
    if args.state_file:
        if rc == 0:
            landed = hashlib.sha256(sealed).hexdigest()
            if not write_state(args.state_file, "PUBLISHED", args.code, args.name,
                               str(len(sealed)), landed):
                print("FAILED: the record landed but PUBLISHED could not be recorded",
                      file=sys.stderr)
                return 2
            return 0
        write_state(args.state_file, "FAILED", rc or 2)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
